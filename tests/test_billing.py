"""Phase 5 — billing (services/billing, :9004).

Covers ARCHITECTURE.md §2.7/§4.8: Stripe test-mode checkout, portal,
webhooks -> plan updates, quota display, and the over-quota reconcile loop
that suspends tenants (deny-all via the gatekeeper key bundle).

The control plane, receipt service, and billing run as real subprocesses
(mock Stripe backend — no network, no keys). Fixtures: tenants with
HMAC-signed receipts minted with the real signing scheme.

Auth under test:
  * tenant endpoints: vouch_sk_* introspected against the control plane
    (the key IS the tenant — cross-tenant access impossible by construction)
  * /v1/stripe/webhook: Stripe-Signature HMAC, timestamp tolerance,
    idempotent redelivery
  * /internal/billing/reconcile: BILLING_SVC_TOKEN only
"""
import hashlib
import hmac as hmac_mod
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
import urllib.request
import urllib.error

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
WEBHOOK_SECRET = "whsec_test_suite_only"


# ------------------------------------------------------------------ helpers
def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def http(method, url, body=None, headers=None, timeout=15):
    req = urllib.request.Request(url, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    data = None
    if body is not None:
        if isinstance(body, dict):
            data = json.dumps(body).encode()
            req.add_header("Content-Type", "application/json")
        else:
            data = body if isinstance(body, bytes) else body.encode()
    try:
        with urllib.request.urlopen(req, data=data, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw
    try:
        return resp.status, json.loads(raw)
    except json.JSONDecodeError:
        return resp.status, raw


def wait_up(url, timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3):
                return True
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"never came up: {url}")


def boot(module, env):
    e = dict(os.environ)
    e.update(env)
    return subprocess.Popen(
        [PY, "-m", module], env=e,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def probe(method, url, headers=None):
    """http() that returns None instead of raising on connection errors."""
    try:
        return http(method, url, headers=headers)
    except Exception:  # noqa: BLE001 - service not up yet
        return None


def wait_for_401(url, timeout=25):
    """A 401 from an authed route proves the service is up and parsing."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = probe("GET", url, {"Authorization": "Bearer <redacted>"})
        if r is not None and r[0] == 401:
            return
        time.sleep(0.2)
    raise RuntimeError(f"never came up: {url}")


def mint_receipt(tenant_id, kid, key_hex, seq, prev_hash, tool, decision,
                 task_id="bill-task", agent_id="agent-1"):
    key = bytes.fromhex(key_hex)
    body = {
        "seq": seq, "ts": round(time.time(), 3), "tenant_id": tenant_id,
        "kid": kid, "task_id": task_id, "agent_id": agent_id,
        "tool": tool,
        "args_sha256": hashlib.sha256(b"{}").hexdigest(),
        "decision": decision, "reason": None, "rule_id": None,
        "policy_version": 1, "prev_hash": prev_hash,
    }
    body["hash"] = hashlib.sha256(
        prev_hash.encode() + json.dumps(body, sort_keys=True).encode()
    ).hexdigest()
    body["sig"] = hmac_mod.new(
        key, json.dumps(body, sort_keys=True).encode(),
        hashlib.sha256).hexdigest()
    return body


def sign_webhook(payload_bytes, secret=WEBHOOK_SECRET, ts=None):
    ts = str(ts if ts is not None else int(time.time()))
    mac = hmac_mod.new(secret.encode(), ts.encode() + b"." + payload_bytes,
                       hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def _raw_oversized_status(base_url, path, headers=None):
    """Declare ``Content-Length: 1000001`` but send only a partial body;
    return the response status. urllib's full-body send races the server's
    early 413 and flakes with BrokenPipeError; the raw socket proves the
    server decides on the headers alone, before touching the body."""
    u = urllib.parse.urlparse(base_url)
    s = socket.create_connection((u.hostname, u.port or 80), timeout=15)
    try:
        lines = ["POST %s HTTP/1.1" % path, "Host: %s" % u.hostname,
                 "Content-Length: 1000001", "Connection: close"]
        for k, v in (headers or {}).items():
            lines.append("%s: %s" % (k, v))
        s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + b"x" * 1024)
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        return int(resp.split(b" ", 2)[1])
    finally:
        s.close()


class BillingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="vouch-bill-test-")
        cls.cp_port, cls.rc_port, cls.bill_port = (
            free_port(), free_port(), free_port())
        cls.cp_db = os.path.join(cls.tmp, "cp.db")
        cls.rc_db = os.path.join(cls.tmp, "rc.db")
        cls.bill_db = os.path.join(cls.tmp, "bill.db")

        out = subprocess.run(
            [PY, "-m", "services.controlplane.seed_tokens",
             "--db", cls.cp_db],
            capture_output=True, text=True, cwd=REPO)
        assert out.returncode == 0, out.stderr
        toks = {}
        for line in out.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                toks[k.strip()] = v.strip()
        cls.svc = toks["RECEIPT_SVC_TOKEN"]
        cls.bill_svc = toks["BILLING_SVC_TOKEN"]
        cls.cp = f"http://127.0.0.1:{cls.cp_port}"
        cls.rc = f"http://127.0.0.1:{cls.rc_port}"
        cls.bill = f"http://127.0.0.1:{cls.bill_port}"

        cls.procs = []
        cls.procs.append(boot("services.controlplane.app", {
            "CONTROLPLANE_PORT": str(cls.cp_port),
            "CONTROLPLANE_DB": cls.cp_db,
            "RECEIPT_SVC_URL": cls.rc,
            "RECEIPT_FANIN_TOKEN": cls.svc,
        }))
        cls.procs.append(boot("services.receipts.app", {
            "RECEIPT_PORT": str(cls.rc_port),
            "RECEIPT_DB": cls.rc_db,
            "RECEIPT_SVC_TOKEN": cls.svc,
            "CONTROLPLANE_URL": cls.cp,
            "CONTROLPLANE_SVC_TOKEN": cls.svc,
        }))
        cls.procs.append(boot("services.billing.app", {
            "BILLING_PORT": str(cls.bill_port),
            "BILLING_DB": cls.bill_db,
            "BILLING_PUBLIC_URL": cls.bill,
            "CONTROLPLANE_URL": cls.cp,
            "BILLING_SVC_TOKEN": cls.bill_svc,
            "RECEIPT_SVC_URL": cls.rc,
            "RECEIPT_SVC_TOKEN": cls.svc,
            "STRIPE_TEST_WEBHOOK_SECRET": WEBHOOK_SECRET,
            "BILLING_QUOTA_FREE": "3",   # tiny quota: over-quota is cheap
            "BILLING_QUOTA_PRO": "1000000",
            "BILLING_QUOTA_TEAM": "10000000",
        }))
        wait_up(cls.rc + "/v1/health")
        # a 401 from an authed route proves a service is up and parsing.
        wait_for_401(cls.cp + "/v1/tenants/me")
        wait_for_401(cls.bill + "/v1/billing/subscription")

        # two tenants: A (the payer) and B (isolation probe)
        cls.tenants = {}
        for name in ("Acme", "Beta"):
            s, data = http("POST", cls.cp + "/v1/tenants", {"name": name})
            assert s in (200, 201), data
            cls.tenants[name] = {
                "id": data["tenant_id"],
                "key": data["api_key"],
                "hdr": {"Authorization": f"Bearer {data['api_key']}"},
            }
        con = sqlite3.connect(cls.cp_db)
        cls.keys = {}
        for name, t in cls.tenants.items():
            kid, key_hex = con.execute(
                "SELECT kid, key_hex FROM tenant_keys "
                "WHERE tenant_id=? AND is_current=1",
                (t["id"],)).fetchone()
            cls.keys[name] = (kid, key_hex)
        con.close()

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            p.terminate()
        for p in cls.procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    # ------------------------------------------------------------- fixtures
    @classmethod
    def _ingest_raw(cls, tid, kid, key_hex, state, n, decision="allow",
                    tool="read_file"):
        for _ in range(n):
            state["seq"] += 1
            body = mint_receipt(tid, kid, key_hex, state["seq"],
                                state["prev"], tool, decision)
            state["prev"] = body["hash"]
            s, _ = http("POST", cls.rc + "/v1/ingest", body,
                        {"Authorization": f"Bearer {cls.svc}"})
            assert s == 201, s

    @classmethod
    def _ingest(cls, name, n, decision="allow", tool="read_file"):
        tid = cls.tenants[name]["id"]
        kid, key_hex = cls.keys[name]
        if name not in cls._ingest_state:
            cls._ingest_state[name] = {"seq": 0, "prev": "GENESIS"}
        cls._ingest_raw(tid, kid, key_hex, cls._ingest_state[name], n,
                        decision, tool)

    _ingest_state = {}

    def _webhook_post(self, event, secret=WEBHOOK_SECRET, ts=None):
        payload = json.dumps(event).encode()
        sig = sign_webhook(payload, secret, ts)
        return http("POST", self.bill + "/v1/stripe/webhook", payload, {
            "Content-Type": "application/json", "Stripe-Signature": sig})

    def _mock_event(self, etype, obj):
        return {"id": f"evt_test_{time.time_ns()}",
                "type": etype, "created": int(time.time()),
                "data": {"object": obj}}

    # ---------------------------------------------------------------- tests
    def test_01_checkout_requires_auth(self):
        s, _ = http("POST", self.bill + "/v1/billing/checkout",
                    {"plan": "pro"})
        self.assertEqual(s, 401)

    def test_02_checkout_invalid_plan(self):
        hdr = self.tenants["Acme"]["hdr"]
        s, data = http("POST", self.bill + "/v1/billing/checkout",
                       {"plan": "enterprise"}, hdr)
        self.assertEqual(s, 422)
        s, _ = http("POST", self.bill + "/v1/billing/checkout",
                    {"plan": "free"}, hdr)
        self.assertEqual(s, 422)

    def test_03_checkout_creates_mock_session(self):
        hdr = self.tenants["Acme"]["hdr"]
        s, data = http("POST", self.bill + "/v1/billing/checkout",
                       {"plan": "pro"}, hdr)
        self.assertEqual(s, 200, data)
        self.assertIn("/v1/billing/mock-checkout/cs_test_", data["checkout_url"])
        self.assertTrue(data["test_mode"])
        self.__class__.session_id = data["session_id"]

    def test_04_mock_complete_flips_plan_via_webhook(self):
        sid = self.__class__.session_id
        hdr = self.tenants["Acme"]["hdr"]
        # the mock checkout page exists (mock backend only)
        s, _ = http("GET", f"{self.bill}/v1/billing/mock-checkout/{sid}")
        self.assertEqual(s, 200)
        # complete -> synthetic checkout.session.completed through the
        # real webhook path (signed, verified). Mock-only, but still
        # tenant-gated: unauthenticated -> 401, wrong tenant -> 404.
        s, _ = http("POST",
                    f"{self.bill}/v1/billing/mock-checkout/{sid}/complete")
        self.assertEqual(s, 401)
        s, _ = http("POST",
                    f"{self.bill}/v1/billing/mock-checkout/{sid}/complete",
                    headers=self.tenants["Beta"]["hdr"])
        self.assertEqual(s, 404)
        s, data = http("POST",
                       f"{self.bill}/v1/billing/mock-checkout/{sid}/complete",
                       headers=hdr)
        self.assertEqual(s, 200, data)
        # control plane is the authority: plan flipped to pro
        s, me = http("GET", self.cp + "/v1/tenants/me", headers=hdr)
        self.assertEqual(s, 200, me)
        self.assertEqual(me["plan"], "pro")
        # and the tenant-facing subscription view agrees
        s, sub = http("GET", self.bill + "/v1/billing/subscription", headers=hdr)
        self.assertEqual(s, 200, sub)
        self.assertEqual(sub["plan"], "pro")
        self.assertEqual(sub["price_usd"], 49)
        self.assertIsNotNone(sub["subscription"])
        self.assertFalse(sub["over_quota"])

    def test_05_webhook_idempotent_redelivery(self):
        sub_id = "sub_test_redeliver"
        tid = self.tenants["Beta"]["id"]
        event = self._mock_event("customer.subscription.created", {
            "id": sub_id, "customer": "cus_test_x",
            "metadata": {"tenant_id": tid, "plan": "team"},
            "status": "active"})
        s, first = self._webhook_post(event)
        self.assertEqual(s, 200, first)
        self.assertTrue(first["applied"])
        s, second = self._webhook_post(event)  # Stripe redelivers
        self.assertEqual(s, 200, second)
        self.assertTrue(second.get("duplicate"))
        # applied exactly once: one subscription row for that stripe id
        con = sqlite3.connect(self.bill_db)
        n = con.execute(
            "SELECT COUNT(*) FROM subscriptions WHERE stripe_sub_id=?",
            (sub_id,)).fetchone()[0]
        con.close()
        self.assertEqual(n, 1)

    def test_06_webhook_bad_signature_rejected(self):
        event = self._mock_event("customer.subscription.created", {"id": "x"})
        s, _ = self._webhook_post(event, secret="whsec_wrong")
        self.assertEqual(s, 401)
        # missing header entirely
        payload = json.dumps(event).encode()
        s, _ = http("POST", self.bill + "/v1/stripe/webhook", payload,
                    {"Content-Type": "application/json"})
        self.assertEqual(s, 401)

    def test_07_webhook_stale_timestamp_rejected(self):
        event = self._mock_event("customer.subscription.created", {"id": "y"})
        payload = json.dumps(event).encode()
        sig = sign_webhook(payload, ts=int(time.time()) - 3600)
        s, _ = http("POST", self.bill + "/v1/stripe/webhook", payload, {
            "Content-Type": "application/json", "Stripe-Signature": sig})
        self.assertEqual(s, 401)

    def test_08_webhook_malformed_body(self):
        sig = sign_webhook(b"not json")
        s, _ = http("POST", self.bill + "/v1/stripe/webhook", b"not json", {
            "Content-Type": "application/json", "Stripe-Signature": sig})
        self.assertEqual(s, 400)

    def test_08b_webhook_oversized_body_rejected(self):
        # >1MB bodies are refused before any signature work (413, not 401).
        s = _raw_oversized_status(
            self.bill, "/v1/stripe/webhook",
            {"Content-Type": "application/json",
             "Stripe-Signature": "t=1,v1=nope"})
        self.assertEqual(s, 413)

    def test_09_subscription_deleted_downgrades_to_free(self):
        tid = self.tenants["Beta"]["id"]
        event = self._mock_event("customer.subscription.deleted", {
            "id": "sub_test_redeliver", "customer": "cus_test_x",
            "metadata": {"tenant_id": tid, "plan": "team"},
            "status": "canceled"})
        s, _ = self._webhook_post(event)
        self.assertEqual(s, 200)
        s, me = http("GET", self.cp + "/v1/tenants/me",
                     headers=self.tenants["Beta"]["hdr"])
        self.assertEqual(me["plan"], "free")

    def test_10_payment_failed_marks_past_due_keeps_plan(self):
        tid = self.tenants["Acme"]["id"]
        s, sub = http("GET", self.bill + "/v1/billing/subscription",
                      headers=self.tenants["Acme"]["hdr"])
        stripe_sub = sub["subscription"]["stripe_subscription_id"]
        event = self._mock_event("invoice.payment_failed", {
            "id": "in_test_1", "subscription": stripe_sub,
            "customer": "cus_test_y"})
        s, data = self._webhook_post(event)
        self.assertEqual(s, 200, data)
        s, sub = http("GET", self.bill + "/v1/billing/subscription",
                      headers=self.tenants["Acme"]["hdr"])
        self.assertEqual(sub["subscription"]["status"], "past_due")
        self.assertEqual(sub["plan"], "pro")  # plan untouched
        s, me = http("GET", self.cp + "/v1/tenants/me",
                     headers=self.tenants["Acme"]["hdr"])
        self.assertEqual(me["plan"], "pro")

    def test_11_tenant_isolation(self):
        # Beta sees only Beta's subscription — never Acme's
        s, sub = http("GET", self.bill + "/v1/billing/subscription",
                      headers=self.tenants["Beta"]["hdr"])
        self.assertEqual(s, 200, sub)
        self.assertEqual(sub["tenant_id"], self.tenants["Beta"]["id"])
        self.assertEqual(sub["plan"], "free")
        # Beta cannot complete Acme's checkout session (unknown to them —
        # the session page itself is unguessable, but the subscription
        # view must never leak across tenants)
        s, sub_a = http("GET", self.bill + "/v1/billing/subscription",
                        headers=self.tenants["Acme"]["hdr"])
        self.assertNotEqual(sub["subscription"], sub_a["subscription"])

    def test_12_subscription_view_shows_usage_and_quota(self):
        self._ingest("Beta", 2)  # free quota is 3 in this suite
        s, sub = http("GET", self.bill + "/v1/billing/subscription",
                      headers=self.tenants["Beta"]["hdr"])
        self.assertEqual(s, 200, sub)
        self.assertEqual(sub["quota_actions_per_month"], 3)
        self.assertEqual(sub["actions_this_month"], 2)
        self.assertFalse(sub["over_quota"])
        self.assertFalse(sub["usage"]["unavailable"])

    def test_13_reconcile_requires_service_token(self):
        s, _ = http("POST", self.bill + "/internal/billing/reconcile", {},
                    {"Authorization": "Bearer <redacted>"})
        self.assertEqual(s, 401)
        s, _ = http("POST", self.bill + "/internal/billing/reconcile")
        self.assertEqual(s, 401)

    def test_14_reconcile_suspends_over_quota(self):
        # Beta now has 2 actions; one more tips over the quota of 3
        self._ingest("Beta", 2)
        svc_hdr = {"Authorization": f"Bearer {self.bill_svc}"}
        s, data = http("POST", self.bill + "/internal/billing/reconcile",
                       {}, svc_hdr)
        self.assertEqual(s, 200, data)
        beta = [r for r in data["tenants"]
                if r["tenant_id"] == self.tenants["Beta"]["id"]][0]
        self.assertEqual(beta["action"], "suspended")
        self.assertEqual(beta["actions"], 4)
        # control plane is the authority: status flipped
        s, me = http("GET", self.cp + "/v1/tenants/me",
                     headers=self.tenants["Beta"]["hdr"])
        self.assertEqual(me["status"], "suspended")
        # reconcile is idempotent: second run reports ok, no double-suspend
        s, data = http("POST", self.bill + "/internal/billing/reconcile",
                       {}, svc_hdr)
        beta = [r for r in data["tenants"]
                if r["tenant_id"] == self.tenants["Beta"]["id"]][0]
        self.assertEqual(beta["action"], "ok")

    def test_14b_reconcile_unsuspends_own_suspension(self):
        svc_hdr = {"Authorization": f"Bearer {self.bill_svc}"}
        # new month: wipe Beta's usage -> billing lifts its own suspension
        con = sqlite3.connect(self.rc_db)
        con.execute("DELETE FROM usage_monthly WHERE tenant_id=?",
                    (self.tenants["Beta"]["id"],))
        con.commit()
        con.close()
        s, data = http("POST", self.bill + "/internal/billing/reconcile",
                       {}, svc_hdr)
        self.assertEqual(s, 200, data)
        beta = [r for r in data["tenants"]
                if r["tenant_id"] == self.tenants["Beta"]["id"]][0]
        self.assertEqual(beta["action"], "unsuspended")
        s, me = http("GET", self.cp + "/v1/tenants/me",
                     headers=self.tenants["Beta"]["hdr"])
        self.assertEqual(me["status"], "active")

    def test_15_reconcile_respects_operator_suspensions(self):
        svc_hdr = {"Authorization": f"Bearer {self.bill_svc}"}
        # Gamma: free tenant pushed over quota (quota=3), then suspended
        # by an OPERATOR (not billing).
        s, data = http("POST", self.cp + "/v1/tenants", {"name": "Gamma"})
        self.assertIn(s, (200, 201), data)
        gid, gkey = data["tenant_id"], data["api_key"]
        ghdr = {"Authorization": f"Bearer {gkey}"}
        con = sqlite3.connect(self.cp_db)
        gkid, gkey_hex = con.execute(
            "SELECT kid, key_hex FROM tenant_keys "
            "WHERE tenant_id=? AND is_current=1", (gid,)).fetchone()
        con.close()
        self._ingest_raw(gid, gkid, gkey_hex,
                         {"seq": 0, "prev": "GENESIS"}, 4)
        s, _ = http("POST", f"{self.cp}/internal/tenants/{gid}/status",
                    {"status": "suspended"}, svc_hdr)
        self.assertEqual(s, 200)
        # register Gamma with billing (any tenant-authed call upserts)
        s, _ = http("GET", self.bill + "/v1/billing/subscription", headers=ghdr)
        self.assertEqual(s, 200)
        # reconcile: over quota, but billing did NOT suspend -> hands off
        s, data = http("POST", self.bill + "/internal/billing/reconcile",
                       {}, svc_hdr)
        self.assertEqual(s, 200, data)
        gamma = [r for r in data["tenants"]
                 if r["tenant_id"] == gid][0]
        self.assertEqual(gamma["action"], "ok")
        con = sqlite3.connect(self.bill_db)
        con.row_factory = sqlite3.Row
        claimed = con.execute(
            "SELECT suspended_by_billing FROM quota_state WHERE tenant_id=?",
            (gid,)).fetchone()
        con.close()
        self.assertEqual(claimed["suspended_by_billing"], 0)
        # usage drops back under quota -> billing still must NOT unsuspend
        # a suspension it never made
        con = sqlite3.connect(self.rc_db)
        con.execute("DELETE FROM usage_monthly WHERE tenant_id=?", (gid,))
        con.commit()
        con.close()
        s, data = http("POST", self.bill + "/internal/billing/reconcile",
                       {}, svc_hdr)
        gamma = [r for r in data["tenants"]
                 if r["tenant_id"] == gid][0]
        self.assertEqual(gamma["action"], "ok")
        s, me = http("GET", self.cp + "/v1/tenants/me", headers=ghdr)
        self.assertEqual(me["status"], "suspended")

    def test_16_reconcile_skips_on_unavailable_usage(self):
        # a second billing pointed at a dead receipt service: usage reads
        # fail -> tenant is SKIPPED, never suspended on missing data
        dead_port = free_port()
        bill2 = free_port()
        bill2_db = os.path.join(self.tmp, "bill2.db")
        p = boot("services.billing.app", {
            "BILLING_PORT": str(bill2),
            "BILLING_DB": bill2_db,
            "BILLING_PUBLIC_URL": f"http://127.0.0.1:{bill2}",
            "CONTROLPLANE_URL": self.cp,
            "BILLING_SVC_TOKEN": self.bill_svc,
            "RECEIPT_SVC_URL": f"http://127.0.0.1:{dead_port}",
            "RECEIPT_SVC_TOKEN": self.svc,
            "STRIPE_TEST_WEBHOOK_SECRET": WEBHOOK_SECRET,
            "BILLING_QUOTA_FREE": "0",  # any usage would be "over"
        })
        self.procs.append(p)
        base = f"http://127.0.0.1:{bill2}"
        deadline = time.time() + 25
        while time.time() < deadline:
            r = probe("GET", base + "/v1/billing/subscription",
                      {"Authorization": "Bearer <redacted>"})
            if r is not None and r[0] == 401:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("billing2 never came up")
        # register a tenant with billing2 (any authed call upserts customer)
        s, _ = http("GET", base + "/v1/billing/subscription",
                    headers=self.tenants["Beta"]["hdr"])
        self.assertEqual(s, 200)
        svc_hdr = {"Authorization": f"Bearer {self.bill_svc}"}
        s, data = http("POST", base + "/internal/billing/reconcile", {},
                       svc_hdr)
        self.assertEqual(s, 200, data)
        self.assertEqual(data["tenants"][0]["action"], "skipped")
        # and Beta was NOT suspended by the blind reconcile
        s, me = http("GET", self.cp + "/v1/tenants/me",
                     headers=self.tenants["Beta"]["hdr"])
        self.assertEqual(me["status"], "active")

    def test_17_real_backend_refuses_live_keys(self):
        sys.path.insert(0, REPO)
        from services.billing.stripe_backend import RealStripeBackend
        with self.assertRaises(ValueError):
            RealStripeBackend("sk_live_abc", {})
        with self.assertRaises(ValueError):
            RealStripeBackend("rk_test_abc", {})
        # test keys are accepted (construction only — no network here)
        RealStripeBackend("sk_test_abc", {"pro": "price_test"})
        sys.path.remove(REPO)

    def test_18_checkout_without_metadata_falls_back_to_session_row(self):
        # hand-signed event with no metadata: the stored checkout row
        # still resolves tenant+plan
        hdr = self.tenants["Beta"]["hdr"]
        s, data = http("POST", self.bill + "/v1/billing/checkout",
                       {"plan": "team"}, hdr)
        self.assertEqual(s, 200, data)
        sid = data["session_id"]
        event = self._mock_event("checkout.session.completed", {
            "id": sid, "customer": "cus_test_z",
            "subscription": "sub_test_nometa"})
        s, data = self._webhook_post(event)
        self.assertEqual(s, 200, data)
        self.assertIn("team", data["applied"])
        s, me = http("GET", self.cp + "/v1/tenants/me", headers=hdr)
        self.assertEqual(me["plan"], "team")


if __name__ == "__main__":
    unittest.main(verbosity=2)
