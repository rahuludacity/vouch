"""Stripe backend abstraction (Phase 5, §4.8).

Two backends, one interface:

  MockStripeBackend  — default. Used when STRIPE_TEST_SECRET_KEY is unset.
                       Generates deterministic fake ids (cs_test_*, cus_test_*,
                       sub_test_*) and serves a local mock checkout page whose
                       "complete purchase" button fires a *synthetically signed*
                       checkout.session.completed event through the real
                       webhook path. No network, no keys, fully offline.

  RealStripeBackend  — live Stripe **test mode only**, via raw urllib calls to
                       api.stripe.com. Refuses to construct with anything but
                       an sk_test_* key, and refuses to run without an explicit
                       test webhook secret. Never touches live mode.

Webhook *signature verification* is backend-independent and lives in app.py.
"""
import base64
import json
import os
import secrets
import time
import urllib.parse
import urllib.request


class StripeBackend:
    name = "base"

    def ensure_customer(self, tenant_id, email=None):
        raise NotImplementedError

    def create_checkout_session(self, *, customer_id, tenant_id, plan,
                                success_url, cancel_url):
        """-> {"session_id", "url", "customer_id"}"""
        raise NotImplementedError

    def create_portal_session(self, *, customer_id, return_url):
        """-> {"url"}"""
        raise NotImplementedError

    # -- synthetic events (mock only) -------------------------------------
    def synth_checkout_completed(self, session_id):
        """Build a checkout.session.completed event dict for a session."""
        raise NotImplementedError("only the mock backend synthesizes events")


class MockStripeBackend(StripeBackend):
    """Clearly-labeled test double. All ids are prefixed test_ so a mock
    object can never be mistaken for a real Stripe object."""
    name = "mock"

    def __init__(self, billing_base_url):
        self.billing_base_url = billing_base_url.rstrip("/")
        self._sessions = {}   # session_id -> dict
        self._customers = {}  # customer_id -> tenant_id

    def ensure_customer(self, tenant_id, email=None):
        for cid, tid in self._customers.items():
            if tid == tenant_id:
                return cid
        cid = "cus_test_" + secrets.token_hex(8)
        self._customers[cid] = tenant_id
        return cid

    def create_checkout_session(self, *, customer_id, tenant_id, plan,
                                success_url, cancel_url):
        sid = "cs_test_" + secrets.token_hex(12)
        self._sessions[sid] = {
            "id": sid, "customer": customer_id, "tenant_id": tenant_id,
            "plan": plan, "success_url": success_url,
            "cancel_url": cancel_url, "status": "open",
        }
        return {
            "session_id": sid,
            "url": f"{self.billing_base_url}/v1/billing/mock-checkout/{sid}",
            "customer_id": customer_id,
        }

    def create_portal_session(self, *, customer_id, return_url):
        return {"url": f"{self.billing_base_url}/v1/billing/mock-portal"
                       f"?customer={customer_id}"}

    def session(self, session_id):
        return self._sessions.get(session_id)

    def complete_session(self, session_id):
        s = self._sessions.get(session_id)
        if s and s["status"] == "open":
            s["status"] = "complete"
        return s

    def synth_checkout_completed(self, session_id):
        s = self._sessions.get(session_id)
        if not s:
            raise KeyError(session_id)
        sub_id = "sub_test_" + secrets.token_hex(8)
        now = int(time.time())
        return {
            "id": "evt_test_" + secrets.token_hex(8),
            "type": "checkout.session.completed",
            "created": now,
            "data": {"object": {
                "id": session_id,
                "customer": s["customer"],
                "subscription": sub_id,
                "metadata": {"tenant_id": s["tenant_id"], "plan": s["plan"]},
                "current_period_end": now + 30 * 86400,
            }},
        }

    def synth_subscription_deleted(self, tenant_id, customer_id, sub_id, plan):
        return {
            "id": "evt_test_" + secrets.token_hex(8),
            "type": "customer.subscription.deleted",
            "created": int(time.time()),
            "data": {"object": {
                "id": sub_id, "customer": customer_id,
                "metadata": {"tenant_id": tenant_id, "plan": plan},
                "status": "canceled",
            }},
        }


class RealStripeBackend(StripeBackend):
    """Live Stripe API, test mode ONLY. stdlib urllib, HTTP basic auth."""
    name = "real-test"
    API = "https://api.stripe.com"

    def __init__(self, secret_key, price_map):
        if not secret_key.startswith("sk_test_"):
            raise ValueError(
                "refusing non-test Stripe key (must start with sk_test_)")
        self.secret_key = secret_key
        self.price_map = price_map  # {"pro": "price_...", "team": "price_..."}

    def _call(self, method, path, params):
        data = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(self.API + path, data=data, method=method)
        basic = base64.b64encode(f"{self.secret_key}:".encode()).decode()
        req.add_header("Authorization", f"Basic {basic}")
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def ensure_customer(self, tenant_id, email=None):
        # Idempotency via metadata lookup would need /v1/customers/search;
        # keep it simple: create (test mode; dedup by metadata on list).
        params = {"metadata[tenant_id]": tenant_id}
        if email:
            params["email"] = email
        return self._call("POST", "/v1/customers", params)["id"]

    def create_checkout_session(self, *, customer_id, tenant_id, plan,
                                success_url, cancel_url):
        price = self.price_map.get(plan)
        if not price:
            raise ValueError(f"no test price configured for plan '{plan}'")
        obj = self._call("POST", "/v1/checkout/sessions", {
            "customer": customer_id,
            "mode": "subscription",
            "line_items[0][price]": price,
            "line_items[0][quantity]": "1",
            "success_url": success_url,
            "cancel_url": cancel_url,
            "metadata[tenant_id]": tenant_id,
            "metadata[plan]": plan,
            "subscription_data[metadata][tenant_id]": tenant_id,
            "subscription_data[metadata][plan]": plan,
        })
        return {"session_id": obj["id"], "url": obj["url"],
                "customer_id": customer_id}

    def create_portal_session(self, *, customer_id, return_url):
        obj = self._call("POST", "/v1/billing_portal/sessions", {
            "customer": customer_id, "return_url": return_url})
        return {"url": obj["url"]}

    def synth_checkout_completed(self, session_id):
        raise NotImplementedError("real Stripe sends its own webhooks")


def build_backend(billing_base_url):
    """Mock unless STRIPE_TEST_SECRET_KEY is set (test mode only)."""
    key = os.environ.get("STRIPE_TEST_SECRET_KEY", "")
    if not key:
        return MockStripeBackend(billing_base_url)
    price_map = {
        "pro": os.environ.get("STRIPE_PRICE_PRO", ""),
        "team": os.environ.get("STRIPE_PRICE_TEAM", ""),
    }
    return RealStripeBackend(key, price_map)
