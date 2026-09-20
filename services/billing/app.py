"""Vouch billing service (:9004) — Phase 5, §2.7/§4.8.

Stripe **test mode only** (mock backend by default; real backend refuses
anything but sk_test_*). Frozen contracts implemented:

    POST /v1/billing/checkout   tenant API key   {"plan":"pro"|"team"}
                                -> {"checkout_url","session_id"} (test)
    GET  /v1/billing/portal      tenant API key   -> {"portal_url"} (test)
    POST /v1/stripe/webhook      Stripe-Signature -> 200 (idempotent)

Billing-local additions (documented in §2.7, not §4 cross-service changes):

    GET  /v1/billing/subscription  tenant API key -> plan, subscription,
                                current-month usage vs quota, over_quota
    POST /internal/billing/reconcile  BILLING_SVC_TOKEN -> usage check for
                                every billing-known tenant; over-quota ->
                                control-plane status 'suspended' (deny-all
                                via the gatekeeper key bundle, §4.3);
                                back-under-quota -> unsuspend, but ONLY when
                                billing did the suspending.

Auth model (§8): tenant endpoints resolve the tenant by introspecting the
presented vouch_sk_* key against control-plane GET /v1/tenants/me (cached
60s, fail closed — same pattern as the receipt service). The key IS the
tenant; cross-tenant access is impossible by construction. Webhooks are
authenticated by Stripe signature, not by bearer. /internal/* takes
Bearer BILLING_SVC_TOKEN.

Plan catalog (§2.7): free $0 — 10k actions/mo; pro $49/mo — 1M actions/mo;
team $199/mo — 10M actions/mo + SSO + audit export. Metered dimension:
actions = actions_allowed + actions_denied (current UTC month, read from
receipt-service /internal/usage with the shared RECEIPT_SVC_TOKEN).

Run:  python3 -m services.billing.app
Env:
    BILLING_PORT             (default 9004)
    BILLING_DB               (default <repo>/data/billing.db)
    BILLING_PUBLIC_URL       (default http://127.0.0.1:9004 — mock links)
    CONTROLPLANE_URL         (default http://127.0.0.1:9002)
    BILLING_SVC_TOKEN        service token for CP /internal/* + this
                             service's own /internal/* (required)
    RECEIPT_SVC_URL          (default http://127.0.0.1:9001)
    RECEIPT_SVC_TOKEN        shared internal token for receipt-service
                             /internal/usage (same value CP fan-in uses)
    STRIPE_TEST_SECRET_KEY   unset -> mock backend; sk_test_* -> real
                             test-mode backend (anything else: refuse boot)
    STRIPE_TEST_WEBHOOK_SECRET  required in real mode; mock default
                             "whsec_test_mock_do_not_use_in_prod"
    STRIPE_PRICE_PRO / _TEAM  test price ids for the real backend
    BILLING_QUOTA_FREE/PRO/TEAM  override monthly action quotas (tests/demo)
"""
import hashlib
import hmac
import html
import json
import os
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .models import BillingDB
from .stripe_backend import build_backend, MockStripeBackend

HERE = os.path.dirname(__file__)

PORT = int(os.environ.get("BILLING_PORT", "9004"))
PUBLIC_URL = os.environ.get("BILLING_PUBLIC_URL",
                            f"http://127.0.0.1:{PORT}").rstrip("/")
CONTROLPLANE_URL = os.environ.get("CONTROLPLANE_URL",
                                  "http://127.0.0.1:9002").rstrip("/")
RECEIPT_SVC_URL = os.environ.get("RECEIPT_SVC_URL",
                                 "http://127.0.0.1:9001").rstrip("/")
BILLING_SVC_TOKEN = os.environ.get("BILLING_SVC_TOKEN", "")
RECEIPT_SVC_TOKEN = os.environ.get("RECEIPT_SVC_TOKEN", "")
WEBHOOK_SECRET = os.environ.get("STRIPE_TEST_WEBHOOK_SECRET", "")
WEBHOOK_TOLERANCE = 300  # seconds — Stripe may redeliver with an old t=

# Plan catalog, §2.7. Quotas overridable for tests/demo.
PLANS = {
    "free": {"price_usd": 0, "quota": int(os.environ.get(
        "BILLING_QUOTA_FREE", "10000")), "label": "Free"},
    "pro": {"price_usd": 49, "quota": int(os.environ.get(
        "BILLING_QUOTA_PRO", "1000000")), "label": "Pro"},
    "team": {"price_usd": 199, "quota": int(os.environ.get(
        "BILLING_QUOTA_TEAM", "10000000")), "label": "Team"},
}
PURCHASABLE = ("pro", "team")  # free is the default; exit via cancel


def esc(s):
    return html.escape(str(s), quote=True)


class Handler(BaseHTTPRequestHandler):
    db = None
    backend = None
    webhook_secret = ""
    _tenant_key_cache = {}  # sha256(key) -> (tenant_id, expires_at)
    _tenant_key_lock = threading.Lock()
    _TENANT_KEY_TTL = 60

    # ------------------------------------------------------------ plumbing
    def log_message(self, *a):  # quieter logs
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, code, html_body):
        body = html_body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _err(self, code, error, message=""):
        self._send(code, {"error": error, "message": message})

    def _path(self):
        parsed = urllib.parse.urlparse(self.path)
        return parsed.path, urllib.parse.parse_qs(parsed.query)

    # Cap request bodies: Stripe webhooks and our JSON calls are small;
    # an unbounded read is a trivial memory-exhaustion vector.
    _MAX_BODY = 1_000_000

    def _read_raw(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n > self._MAX_BODY:
            return None  # sentinel: too large
        return self.rfile.read(max(n, 0)) if n > 0 else b""

    def _read_json(self):
        raw = self._read_raw()
        if raw is None:
            return "TOO_LARGE"
        if not raw:
            return {}
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return "INVALID"
        return obj if isinstance(obj, dict) else "INVALID"

    # ------------------------------------------------------ tenant identity
    @classmethod
    def _introspect_tenant_key(cls, token):
        """tenant_id for a vouch_sk_* key via CP /v1/tenants/me, or None.

        Cached 60s by key hash; failures fail closed and are never cached.
        """
        digest = hashlib.sha256(token.encode()).hexdigest()
        now = time.time()
        with cls._tenant_key_lock:
            hit = cls._tenant_key_cache.get(digest)
            if hit and hit[1] > now:
                return hit[0]
        url = CONTROLPLANE_URL + "/v1/tenants/me"
        req = urllib.request.Request(
            url, headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    return None
                data = json.loads(resp.read().decode("utf-8"))
                tid, plan = data.get("tenant_id"), data.get("plan", "free")
        except Exception:  # noqa: BLE001 - fail closed, don't cache
            return None
        if not tid:
            return None
        with cls._tenant_key_lock:
            cls._tenant_key_cache[digest] = ((tid, plan), now + cls._TENANT_KEY_TTL)
        return tid, plan

    def _require_tenant(self):
        """(tenant_id, cp_plan) or None (with 401 sent)."""
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or \
                not auth[len("Bearer "):].startswith("vouch_sk_"):
            self._err(401, "unauthorized", "Bearer vouch_sk_* required")
            return None
        token = auth[len("Bearer "):]
        ident = self._introspect_tenant_key(token)
        if not ident:
            self._err(401, "unauthorized", "unknown or invalid API key")
            return None
        tenant_id, cp_plan = ident
        # billing knows every tenant it has ever served (reconcile needs this)
        if not self.db.get_customer(tenant_id):
            try:
                cid = self.backend.ensure_customer(tenant_id)
            except Exception:  # noqa: BLE001 - backend down: still serve
                cid = f"cus_pending_{tenant_id}"
            self.db.upsert_customer(tenant_id, cid)
        return tenant_id, cp_plan

    def _require_service(self):
        presented = self.headers.get("Authorization", "")
        want = f"Bearer {BILLING_SVC_TOKEN}" if BILLING_SVC_TOKEN else ""
        if not want or not hmac.compare_digest(presented, want):
            self._err(401, "unauthorized", "bad or missing service token")
            return False
        return True

    # --------------------------------------------------- control-plane calls
    def _cp_post(self, path, body):
        """POST to control-plane /internal/* with the service token."""
        req = urllib.request.Request(
            CONTROLPLANE_URL + path,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {BILLING_SVC_TOKEN}"},
            method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status != 200:
                raise RuntimeError(f"control plane {path}: {resp.status}")
            return json.loads(resp.read().decode("utf-8"))

    def _cp_set_plan(self, tenant_id, plan):
        return self._cp_post(f"/internal/tenants/{tenant_id}/plan",
                             {"plan": plan})

    def _cp_set_status(self, tenant_id, status):
        return self._cp_post(f"/internal/tenants/{tenant_id}/status",
                             {"status": status})

    def _cp_tenant_status(self, tenant_id):
        """Current tenant status from the control plane's §4.3 key bundle.

        Returns the status string, or None when it can't be read (treated
        like unavailable usage: skip, never act).
        """
        try:
            req = urllib.request.Request(
                f"{CONTROLPLANE_URL}/internal/tenants/{tenant_id}/key-bundle",
                headers={"Authorization": f"Bearer {BILLING_SVC_TOKEN}"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8")).get("status")
        except Exception:
            return None

    # ---------------------------------------------------------- usage reads
    def _usage_for(self, tenant_id):
        """Current-month actions from the receipt service (§4.6-internal)."""
        month = time.strftime("%Y-%m", time.gmtime())
        usage = {"month": month, "actions_allowed": 0, "actions_denied": 0,
                 "unavailable": True}
        if not (RECEIPT_SVC_URL and RECEIPT_SVC_TOKEN):
            return usage
        try:
            req = urllib.request.Request(
                f"{RECEIPT_SVC_URL}/internal/usage/{tenant_id}?month={month}",
                headers={"Authorization": f"Bearer {RECEIPT_SVC_TOKEN}"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            usage["actions_allowed"] = int(data.get("actions_allowed", 0))
            usage["actions_denied"] = int(data.get("actions_denied", 0))
            usage["unavailable"] = False
        except Exception:  # noqa: BLE001 - display path fails open w/ flag
            pass
        return usage

    def _plan_for(self, tenant_id):
        sub = self.db.active_subscription(tenant_id)
        return sub["plan"] if sub else "free"

    # ----------------------------------------------------------------- GET
    def do_GET(self):
        path, _q = self._path()
        if path == "/v1/billing/portal":
            return self._portal()
        if path == "/v1/billing/subscription":
            return self._subscription()
        if path.startswith("/v1/billing/mock-checkout/"):
            return self._mock_checkout_page(path)
        if path == "/v1/billing/mock-portal":
            return self._mock_portal_page()
        return self._err(404, "not_found")

    def _portal(self):
        ident = self._require_tenant()
        if not ident:
            return
        tenant_id, _ = ident
        customer = self.db.get_customer(tenant_id)
        try:
            out = self.backend.create_portal_session(
                customer_id=customer["stripe_customer_id"],
                return_url=PUBLIC_URL + "/v1/billing/subscription")
        except Exception as e:  # noqa: BLE001
            return self._err(502, "stripe_error", str(e))
        return self._send(200, {"portal_url": out["url"]})

    def _subscription(self):
        ident = self._require_tenant()
        if not ident:
            return
        tenant_id, _ = ident
        plan = self._plan_for(tenant_id)
        sub = self.db.active_subscription(tenant_id)
        usage = self._usage_for(tenant_id)
        actions = usage["actions_allowed"] + usage["actions_denied"]
        quota = PLANS[plan]["quota"]
        return self._send(200, {
            "tenant_id": tenant_id,
            "plan": plan,
            "price_usd": PLANS[plan]["price_usd"],
            "quota_actions_per_month": quota,
            "subscription": ({
                "stripe_subscription_id": sub["stripe_sub_id"],
                "status": sub["status"],
                "current_period_end": sub["current_period_end"],
            } if sub else None),
            "usage": usage,
            "actions_this_month": actions,
            "over_quota": actions > quota,
        })

    def _mock_checkout_page(self, path):
        if not isinstance(self.backend, MockStripeBackend):
            return self._err(404, "not_found")
        sid = path[len("/v1/billing/mock-checkout/"):]
        s = self.backend.session(sid)
        if not s:
            return self._err(404, "not_found", "unknown session")
        self._send_html(200, f"""<html><body style="font-family:sans-serif">
<h2>Vouch test checkout (mock — no real charge)</h2>
<p>Plan: <b>{esc(s['plan'])}</b> —
${esc(PLANS[s['plan']]['price_usd'])}/mo, test mode.</p>
<form method="post"
      action="/v1/billing/mock-checkout/{esc(sid)}/complete">
<button type="submit">Complete test purchase</button></form>
<p style="color:#666">This fires a synthetically-signed
<code>checkout.session.completed</code> through the real webhook path.</p>
</body></html>""")

    def _mock_portal_page(self):
        if not isinstance(self.backend, MockStripeBackend):
            return self._err(404, "not_found")
        self._send_html(200, """<html><body style="font-family:sans-serif">
<h2>Vouch test billing portal (mock)</h2>
<p>No real subscription to manage — this is the mock backend.</p>
</body></html>""")

    # ---------------------------------------------------------------- POST
    def do_POST(self):
        path, _q = self._path()
        if path == "/v1/billing/checkout":
            return self._checkout()
        if path == "/v1/stripe/webhook":
            return self._webhook()
        if path == "/internal/billing/reconcile":
            return self._reconcile()
        if path.startswith("/v1/billing/mock-checkout/") and \
                path.endswith("/complete"):
            return self._mock_complete(path)
        return self._err(404, "not_found")

    def _checkout(self):
        ident = self._require_tenant()
        if not ident:
            return
        tenant_id, _ = ident
        body = self._read_json()
        if body == "TOO_LARGE":
            return self._err(413, "payload_too_large")
        if body == "INVALID":
            return self._err(400, "bad_request", "body must be JSON")
        plan = body.get("plan", "")
        if plan not in PURCHASABLE:
            return self._err(422, "invalid_plan",
                             f"plan must be one of {list(PURCHASABLE)}")
        customer = self.db.get_customer(tenant_id)
        try:
            out = self.backend.create_checkout_session(
                customer_id=customer["stripe_customer_id"],
                tenant_id=tenant_id, plan=plan,
                success_url=PUBLIC_URL + "/v1/billing/subscription?ok=1",
                cancel_url=PUBLIC_URL + "/v1/billing/subscription?canceled=1")
        except Exception as e:  # noqa: BLE001
            return self._err(502, "stripe_error", str(e))
        self.db.create_checkout_session(out["session_id"], tenant_id, plan)
        return self._send(200, {"checkout_url": out["url"],
                                "session_id": out["session_id"],
                                "test_mode": True})

    def _mock_complete(self, path):
        """Mock-only: complete a test purchase -> synthetic signed webhook.

        Tenant-authenticated: only the tenant that created the checkout
        session may complete it.
        """
        ident = self._require_tenant()
        if not ident:
            return
        tenant_id, _ = ident
        if not isinstance(self.backend, MockStripeBackend):
            return self._err(404, "not_found")
        sid = path[len("/v1/billing/mock-checkout/"):-len("/complete")]
        row = self.db.get_checkout_session(sid)
        if not row or row["tenant_id"] != tenant_id:
            return self._err(404, "not_found", "unknown or finished session")
        if not self.backend.complete_session(sid):
            return self._err(404, "not_found", "unknown or finished session")
        event = self.backend.synth_checkout_completed(sid)
        payload = json.dumps(event).encode()
        sig = self._sign_webhook(payload)
        req = urllib.request.Request(
            f"http://127.0.0.1:{PORT}/v1/stripe/webhook", data=payload,
            headers={"Content-Type": "application/json",
                     "Stripe-Signature": sig}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
        except Exception as e:  # noqa: BLE001
            return self._err(502, "webhook_delivery_failed", str(e))
        self._send(200, {"ok": True, "session_id": sid,
                         "webhook_event": event["id"]})

    # ---------------------------------------------------- webhook plumbing
    def _sign_webhook(self, payload):
        ts = str(int(time.time()))
        mac = hmac.new(self.webhook_secret.encode(),
                       f"{ts}.".encode() + payload,
                       hashlib.sha256).hexdigest()
        return f"t={ts},v1={mac}"

    @staticmethod
    def _parse_sig_header(value):
        parts = {}
        for chunk in value.split(","):
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                parts.setdefault(k.strip(), v.strip())
        return parts

    def _verify_webhook(self, payload):
        header = self.headers.get("Stripe-Signature", "")
        parts = self._parse_sig_header(header)
        ts, v1 = parts.get("t"), parts.get("v1")
        if not ts or not v1:
            return False
        try:
            age = abs(time.time() - int(ts))
        except ValueError:
            return False
        if age > WEBHOOK_TOLERANCE:
            return False
        expected = hmac.new(self.webhook_secret.encode(),
                            f"{ts}.".encode() + payload,
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, v1)

    def _webhook(self):
        payload = self._read_raw()
        if payload is None:
            return self._err(413, "payload_too_large")
        if not self._verify_webhook(payload):
            return self._err(401, "bad_signature",
                             "Stripe-Signature verification failed")
        try:
            event = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._err(400, "bad_request", "body must be JSON")
        event_id = event.get("id", "")
        event_type = event.get("type", "")
        if not event_id or not isinstance(event.get("data"), dict):
            return self._err(400, "bad_request", "not a Stripe event")
        if self.db.event_seen(event_id, event_type):
            return self._send(200, {"ok": True, "duplicate": True})
        try:
            result = self._dispatch_event(event_type, event["data"].get(
                "object", {}) or {})
        except Exception as e:  # noqa: BLE001 - 500 so Stripe redelivers;
            self.db.unclaim_event(event_id)  # ...and we don't double-apply
            return self._err(500, "handler_error", str(e))
        return self._send(200, {"ok": True, "type": event_type,
                                "applied": result})

    def _event_meta(self, obj):
        md = obj.get("metadata", {}) or {}
        return md.get("tenant_id", ""), md.get("plan", "")

    def _dispatch_event(self, event_type, obj):
        if event_type == "checkout.session.completed":
            return self._on_checkout_completed(obj)
        if event_type in ("customer.subscription.created",
                          "customer.subscription.updated"):
            return self._on_subscription_upsert(obj)
        if event_type == "customer.subscription.deleted":
            return self._on_subscription_deleted(obj)
        if event_type == "invoice.payment_failed":
            return self._on_payment_failed(obj)
        return "ignored"  # unhandled types are acked, not applied

    def _on_checkout_completed(self, obj):
        tenant_id, plan = self._event_meta(obj)
        session_id = obj.get("id", "")
        if not tenant_id or plan not in PLANS:
            # fall back to the stored session row (real Stripe always sends
            # metadata; this covers hand-built test events)
            row = self.db.get_checkout_session(session_id)
            if row:
                tenant_id, plan = row["tenant_id"], row["plan"]
        if not tenant_id or plan not in PLANS:
            raise ValueError("checkout.session.completed without tenant/plan")
        if plan not in PURCHASABLE:
            raise ValueError(f"unpurchaseable plan '{plan}'")
        sub_id = obj.get("subscription") or f"sub_mock_{session_id}"
        cpe = obj.get("current_period_end")
        customer_id = obj.get("customer", "")
        if customer_id:
            self.db.upsert_customer(tenant_id, customer_id)
        self.db.upsert_subscription(tenant_id, sub_id, plan, "active", cpe)
        self.db.complete_checkout_session(session_id)
        self._cp_set_plan(tenant_id, plan)  # dashboard sees it via /me fan-in
        return f"plan={plan}"

    def _on_subscription_upsert(self, obj):
        tenant_id, plan = self._event_meta(obj)
        sub_id = obj.get("id", "")
        if not tenant_id or not sub_id:
            raise ValueError("subscription event without tenant/subscription")
        status = obj.get("status", "active")
        cpe = obj.get("current_period_end")
        existing = self.db.get_subscription_by_stripe_id(sub_id)
        old_plan = existing["plan"] if existing else None
        plan = plan if plan in PLANS else (old_plan or "free")
        self.db.upsert_subscription(tenant_id, sub_id, plan, status, cpe)
        if plan != old_plan and plan in PURCHASABLE:
            self._cp_set_plan(tenant_id, plan)
        return f"plan={plan} status={status}"

    def _on_subscription_deleted(self, obj):
        tenant_id, plan = self._event_meta(obj)
        sub_id = obj.get("id", "")
        if not tenant_id or not sub_id:
            raise ValueError("subscription.deleted without tenant/subscription")
        self.db.upsert_subscription(tenant_id, sub_id,
                                    plan if plan in PLANS else "free",
                                    "canceled")
        self._cp_set_plan(tenant_id, "free")  # downgrade on cancel, §4.8
        return "plan=free"

    def _on_payment_failed(self, obj):
        sub_id = (obj.get("subscription") or "")
        if sub_id:
            existing = self.db.get_subscription_by_stripe_id(sub_id)
            if existing:
                self.db.upsert_subscription(
                    existing["tenant_id"], sub_id, existing["plan"],
                    "past_due", existing["current_period_end"])
                return "marked past_due (plan unchanged)"
        return "recorded (plan unchanged)"

    # ------------------------------------------------------------- reconcile
    def _reconcile(self):
        """Over-quota sweep. Service token only. Idempotent.

        Never suspends on missing data: tenants whose usage can't be read
        are skipped, not punished.
        """
        if not self._require_service():
            return
        results = []
        for tenant_id in self.db.all_tenant_ids():
            plan = self._plan_for(tenant_id)
            usage = self._usage_for(tenant_id)
            if usage["unavailable"]:
                results.append({"tenant_id": tenant_id, "action": "skipped",
                                "reason": "usage unavailable"})
                continue
            actions = usage["actions_allowed"] + usage["actions_denied"]
            quota = PLANS[plan]["quota"]
            state = self.db.get_quota_state(tenant_id) or {}
            suspended_by_us = bool(state.get("suspended_by_billing"))
            cp_status = self._cp_tenant_status(tenant_id)
            if cp_status is None:
                # Can't read current status: fail open, skip.
                results.append({"tenant_id": tenant_id, "action": "skipped",
                                "reason": "tenant status unavailable"})
                continue
            over = actions > quota
            if over and cp_status != "suspended":
                # Only claim suspensions billing itself makes; an operator's
                # suspension is never re-claimed here.
                self._cp_set_status(tenant_id, "suspended")
                self.db.set_suspended_by_billing(tenant_id, True, actions)
                results.append({"tenant_id": tenant_id, "action": "suspended",
                                "actions": actions, "quota": quota})
            elif not over and cp_status == "suspended" and suspended_by_us:
                # Auto-reverse ONLY billing-owned suspensions.
                self._cp_set_status(tenant_id, "active")
                self.db.set_suspended_by_billing(tenant_id, False, actions)
                results.append({"tenant_id": tenant_id, "action": "unsuspended",
                                "actions": actions, "quota": quota})
            else:
                self.db.set_suspended_by_billing(
                    tenant_id, suspended_by_us, actions)
                results.append({"tenant_id": tenant_id, "action": "ok",
                                "actions": actions, "quota": quota,
                                "status": cp_status})
        return self._send(200, {"ok": True, "tenants": results})


def main():
    if not BILLING_SVC_TOKEN:
        print("WARNING: BILLING_SVC_TOKEN not set — /internal/* will 401. "
              "Mint with: python3 -m services.controlplane.seed_tokens")
    backend = build_backend(PUBLIC_URL)
    secret = WEBHOOK_SECRET
    if isinstance(backend, MockStripeBackend):
        secret = secret or "whsec_test_mock_do_not_use_in_prod"
        print("billing backend: MOCK (no STRIPE_TEST_SECRET_KEY) — "
              "test double, offline")
    else:
        if not secret:
            raise SystemExit("STRIPE_TEST_WEBHOOK_SECRET is required "
                             "for the real test-mode backend")
        print("billing backend: STRIPE TEST MODE (sk_test_*)")
    Handler.db = BillingDB()
    Handler.backend = backend
    Handler.webhook_secret = secret
    print(f"vouch billing listening on :{PORT}")
    print(f"db:      {Handler.db.path}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
