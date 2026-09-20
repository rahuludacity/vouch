"""Phase 4 — dashboard (web/dashboard, :3000).

Covers ARCHITECTURE.md §2.6/§4: the dashboard talks only to the frozen
control-plane (§4.4/§4.5) and receipt-service (§4.6) contracts, using the
tenant API key as the single credential.

The control plane, receipt service, and dashboard run as real subprocesses
(they read env at import, so in-process booting would poison the shared test
process). Fixtures: one tenant, one v2 policy, one deployment, three
HMAC-signed receipts (2 allow, 1 deny) minted with the real signing scheme.

Auth under test:
  * operator mode (DASHBOARD_API_KEY set): no login required.
  * session mode: login validates the key against the control plane,
    HttpOnly session cookie, per-session CSRF on state-changing calls.
"""
import hashlib
import hmac as hmac_mod
from http import cookiejar as _cookiejar
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
import urllib.error

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


# ------------------------------------------------------------------ helpers
def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def http(method, url, body=None, headers=None, timeout=15, opener=None):
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
    call = (opener.open if opener else urllib.request.urlopen)
    try:
        resp = call(req, data=data, timeout=timeout)
        raw = resp.read().decode("utf-8", "replace")
        try:
            return resp.status, json.loads(raw), resp
        except json.JSONDecodeError:
            return resp.status, raw, resp
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw), e
        except json.JSONDecodeError:
            return e.code, raw, e


def wait_up(url, timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                if r.status < 500:
                    return True
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"never came up: {url}")


def boot(module, env):
    e = dict(os.environ)
    e.update(env)
    p = subprocess.Popen([PY, "-m", module], env=e,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    return p


def mint_receipt(tenant_id, kid, key_hex, seq, prev_hash, tool, decision,
                 task_id="demo-task", agent_id="agent-1", reason=None,
                 rule_id=None, policy_version=None, args=None):
    """A receipt signed exactly like gatekeeper/receipts.py signs them."""
    key = bytes.fromhex(key_hex)
    args = args or {}
    body = {
        "seq": seq,
        "ts": round(time.time(), 3),
        "tenant_id": tenant_id,
        "kid": kid,
        "task_id": task_id,
        "agent_id": agent_id,
        "tool": tool,
        "args_sha256": hashlib.sha256(
            json.dumps(args, sort_keys=True,
                       default=str).encode()).hexdigest(),
        "decision": decision,
        "reason": reason,
        "rule_id": rule_id,
        "policy_version": policy_version,
        "prev_hash": prev_hash,
    }
    body["hash"] = hashlib.sha256(
        prev_hash.encode() + json.dumps(body, sort_keys=True).encode()
    ).hexdigest()
    body["sig"] = hmac_mod.new(
        key, json.dumps(body, sort_keys=True).encode(),
        hashlib.sha256).hexdigest()
    return body


class DashboardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="vouch-dash-test-")
        cls.cp_port, cls.rc_port = free_port(), free_port()
        cls.dash_port, cls.dash2_port = free_port(), free_port()
        cls.cp_db = os.path.join(cls.tmp, "cp.db")
        cls.rc_db = os.path.join(cls.tmp, "rc.db")

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
        cls.cp = f"http://127.0.0.1:{cls.cp_port}"
        cls.rc = f"http://127.0.0.1:{cls.rc_port}"
        cls.dash = f"http://127.0.0.1:{cls.dash_port}"
        cls.dash2 = f"http://127.0.0.1:{cls.dash2_port}"

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
        wait_up(cls.rc + "/v1/health")
        # control plane has no public health endpoint; a 401 from a
        # tenant route proves it's up and parsing auth.
        deadline = time.time() + 25
        while time.time() < deadline:
            s, _, _ = http("GET", cls.cp + "/v1/tenants/me",
                           {"Authorization": "Bearer vouch_sk_bogus"})
            if s == 401:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("control plane never came up")

        # tenant
        s, data, _ = http("POST", cls.cp + "/v1/tenants", {"name": "Acme"})
        assert s in (200, 201), data
        cls.tenant_id = data["tenant_id"]
        cls.api_key = data["api_key"]
        cls.key_hdr = {"Authorization": f"Bearer {cls.api_key}"}

        # signing key for minting valid receipts
        con = sqlite3.connect(cls.cp_db)
        kid, key_hex = con.execute(
            "SELECT kid, key_hex FROM tenant_keys WHERE tenant_id=? "
            "AND is_current=1", (cls.tenant_id,)).fetchone()
        con.close()
        cls.kid = kid

        # three signed receipts: allow, deny, allow
        prev = "GENESIS"
        specs = [("read_file", "allow", None),
                 ("delete_database", "deny", "denied by rule 'no-destructive'"),
                 ("deploy_staging", "allow", None)]
        for i, (tool, dec, reason) in enumerate(specs, start=1):
            r = mint_receipt(cls.tenant_id, kid, key_hex, i, prev, tool, dec,
                             reason=reason,
                             rule_id="read-workspace" if dec == "allow" else
                             "no-destructive",
                             policy_version=1)
            prev = r["hash"]
            s, d, _ = http("POST", cls.rc + "/v1/ingest", r,
                           {"Authorization": f"Bearer {cls.svc}"})
            assert s == 201, (s, d)

        # policy (v2 schema), deployment
        s, d, _ = http("PUT", cls.cp + f"/v1/policies/{cls.tenant_id}",
                       {"rules": {"allow": [{"rule_id": "read-workspace",
                                             "tool": "read_file"}],
                                  "deny": [{"rule_id": "no-destructive",
                                            "tool": "delete_database"}]}},
                       cls.key_hdr)
        assert s == 200, d
        http("PUT", cls.cp + "/v1/policies/demo-task",
             {"rules": {"allow": [], "deny": []}}, cls.key_hdr)
        s, d, _ = http("POST", cls.cp + "/v1/deployments",
                       {"task_id": "demo-task",
                        "agent_image": "vouch/agent-demo:latest"}, cls.key_hdr)
        assert s in (200, 201), d
        cls.deployment_id = d["deployment_id"]

        # dashboard: operator mode (DASHBOARD_API_KEY skips login)
        cls.procs.append(boot("web.dashboard.app", {
            "DASHBOARD_PORT": str(cls.dash_port),
            "CONTROLPLANE_URL": cls.cp,
            "RECEIPT_SVC_URL": cls.rc,
            "DASHBOARD_API_KEY": cls.api_key,
        }))
        # dashboard: session mode (login required)
        cls.procs.append(boot("web.dashboard.app", {
            "DASHBOARD_PORT": str(cls.dash2_port),
            "CONTROLPLANE_URL": cls.cp,
            "RECEIPT_SVC_URL": cls.rc,
        }))
        wait_up(cls.dash + "/login")
        wait_up(cls.dash2 + "/login")

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            p.terminate()
        for p in cls.procs:
            try:
                p.wait(timeout=10)
            except Exception:
                p.kill()

    # ------------------------------------------------------- HTML pages (op)
    def test_pages_200(self):
        for path in ("/", "/overview", "/receipts", "/policies",
                     "/deployments", "/keys", "/login"):
            s, body, _ = http("GET", self.dash + path)
            self.assertIn(s, (200, 303), path)
            if s == 200:
                self.assertIn("Vouch", body, path)

    def test_overview_shows_tenant_and_usage(self):
        s, body, _ = http("GET", self.dash + "/overview")
        self.assertEqual(s, 200)
        self.assertIn("Acme", body)
        self.assertIn(self.tenant_id, body)
        self.assertIn("allowed", body.lower())
        self.assertIn("denied", body.lower())
        self.assertIn("Receipt chain:", body)
        self.assertIn("intact", body)  # verify banner on overview

    def test_receipts_page_filters_and_verify(self):
        s, body, _ = http("GET", self.dash + "/receipts?decision=deny")
        self.assertEqual(s, 200)
        self.assertIn("delete_database", body)
        self.assertNotIn("read_file", body.split("<table>")[1])
        s, body, _ = http("GET", self.dash + "/receipts?verify=1")
        self.assertEqual(s, 200)
        self.assertIn("Chain intact", body)

    def test_receipt_detail_page(self):
        s, body, _ = http("GET", self.dash + "/receipts/2")
        self.assertEqual(s, 200)
        self.assertIn("delete_database", body)
        self.assertIn("deny", body)

    def test_policies_page_lists_tasks(self):
        s, body, _ = http("GET", self.dash + "/policies")
        self.assertEqual(s, 200)
        self.assertIn("demo-task", body)
        self.assertIn("no-destructive", body)

    # ------------------------------------------------------------- JSON API
    def test_api_overview(self):
        s, data, _ = http("GET", self.dash + "/api/overview")
        self.assertEqual(s, 200)
        self.assertEqual(data["tenant"]["tenant_id"], self.tenant_id)
        self.assertEqual(data["tenant"]["plan"], "free")
        self.assertIn("actions_allowed", data["usage"])
        self.assertEqual(data["usage"]["actions_allowed"], 2)
        self.assertEqual(data["usage"]["actions_denied"], 1)
        self.assertIn("keys", data["api_keys"])
        self.assertIn("demo-task", data["policies"]["tasks"])
        self.assertTrue(any(
            d["id"] == self.deployment_id
            for d in data["deployments"]["deployments"]))

    def test_api_receipts_list_and_filters(self):
        s, data, _ = http("GET", self.dash + "/api/receipts")
        self.assertEqual(s, 200)
        seqs = [r["seq"] for r in data["items"]]
        self.assertEqual(seqs, [3, 2, 1])  # newest first
        s, data, _ = http("GET", self.dash + "/api/receipts?decision=deny")
        self.assertEqual(s, 200)
        self.assertEqual(len(data["items"]), 1)
        self.assertEqual(data["items"][0]["tool"], "delete_database")
        s, data, _ = http("GET", self.dash + "/api/receipts?limit=1")
        self.assertEqual(len(data["items"]), 1)

    def test_api_receipt_detail_and_404(self):
        s, data, _ = http("GET", self.dash + "/api/receipts/2")
        self.assertEqual(s, 200)
        self.assertEqual(data["seq"], 2)
        self.assertIn("sig", data)
        self.assertIn("hash", data)
        s, data, _ = http("GET", self.dash + "/api/receipts/9999")
        self.assertEqual(s, 404)

    def test_api_verify(self):
        s, data, _ = http("GET", self.dash + "/api/verify")
        self.assertEqual(s, 200)
        self.assertTrue(data["chain_ok"])
        self.assertEqual(data["receipts"], 3)
        self.assertEqual(data["failures"], [])

    def test_api_policies_crud(self):
        # version bump on PUT
        s, before, _ = http("GET", self.dash + "/api/policies")
        v0 = before["tasks"]["demo-task"]["version"]
        s, data, _ = http("PUT", self.dash + "/api/policies/demo-task",
                          {"rules": {"allow": [{"rule_id": "r1",
                                                "tool": "read_file"}],
                                     "deny": []}})
        self.assertEqual(s, 200)
        self.assertEqual(data["version"], v0 + 1)
        # invalid schema -> 422 relayed from the control plane
        s, data, _ = http("PUT", self.dash + "/api/policies/demo-task",
                          {"rules": {"allow": [{"rule_id": "bad",
                                                "tool": "read_file",
                                                "args": {"x": {"bogus": 1}}}],
                                     "deny": []}})
        self.assertEqual(s, 422)
        # malformed dashboard-side body -> 400
        s, data, _ = http("PUT", self.dash + "/api/policies/demo-task",
                          {"rules": "nope"})
        self.assertEqual(s, 400)
        # delete
        s, data, _ = http("DELETE", self.dash + "/api/policies/demo-task")
        self.assertEqual(s, 204)
        s, after, _ = http("GET", self.dash + "/api/policies")
        self.assertNotIn("demo-task", after["tasks"])
        # restore for other tests
        http("PUT", self.dash + "/api/policies/demo-task",
             {"rules": {"allow": [], "deny": []}})

    def test_api_deployments_crud(self):
        s, data, _ = http("POST", self.dash + "/api/deployments",
                          {"task_id": "demo-task",
                           "agent_image": "vouch/other:1"})
        self.assertIn(s, (200, 201))
        dep_id = data["deployment_id"]
        s, data, _ = http("GET", self.dash + f"/api/deployments/{dep_id}")
        self.assertEqual(s, 200)
        self.assertEqual(data["task_id"], "demo-task")
        s, data, _ = http("DELETE", self.dash + f"/api/deployments/{dep_id}")
        self.assertEqual(s, 200)
        self.assertEqual(data["status"], "stopped")

    def test_api_keys_lifecycle(self):
        s, data, _ = http("GET", self.dash + "/api/keys")
        self.assertEqual(s, 200)
        # metadata only: no plaintext, no hashes
        blob = json.dumps(data)
        self.assertNotIn("vouch_sk_", blob)
        self.assertNotIn("key_hash", blob)
        before = len(data["keys"])
        # create
        s, data, _ = http("POST", self.dash + "/api/keys", {"name": "ci"})
        self.assertIn(s, (200, 201))
        self.assertTrue(data["api_key"].startswith("vouch_sk_"))
        new_key, new_id = data["api_key"], data["id"]
        # the new key works against the upstream control plane
        s, d2, _ = http("GET", self.cp + "/v1/tenants/me",
                        headers={"Authorization": f"Bearer {new_key}"})
        self.assertEqual(s, 200)
        # revoke
        s, data, _ = http("DELETE", self.dash + f"/api/keys/{new_id}")
        self.assertEqual(s, 204)
        s, d2, _ = http("GET", self.cp + "/v1/tenants/me",
                        headers={"Authorization": f"Bearer {new_key}"})
        self.assertEqual(s, 401)
        s, data, _ = http("GET", self.dash + "/api/keys")
        self.assertEqual(len(data["keys"]), before + 1)  # revoked row kept

    def test_api_rotate_signing_keys(self):
        s, data, _ = http("POST", self.dash + "/api/keys/rotate-signing")
        self.assertEqual(s, 200)
        new_kid = data["new_kid"]
        self.assertNotEqual(new_kid, self.kid)
        # key material never appears
        self.assertNotIn("key_hex", json.dumps(data))
        # old receipts still verify against retired kids
        s, data, _ = http("GET", self.dash + "/api/verify")
        self.assertEqual(s, 200)
        self.assertTrue(data["chain_ok"])

    def test_sse_live_feed_relay(self):
        seen = []

        def reader():
            req = urllib.request.Request(self.dash + "/api/receipts/stream")
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    start = time.time()
                    while time.time() - start < 15:
                        line = r.readline().decode("utf-8", "replace")
                        if not line:
                            break
                        if "event: receipt" in line:
                            seen.append(line)
                            break
            except Exception:
                pass

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        t.join(timeout=18)
        self.assertTrue(seen, "expected at least one SSE receipt event "
                              "(backlog is replayed on connect)")

    # ------------------------------------------------- session mode (dash2)
    def _session_opener(self):
        jar = _cookiejar.CookieJar()
        return urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar))

    def test_login_required_without_key(self):
        # no session cookie -> HTML pages land on the login page
        s, body, _ = http("GET", self.dash2 + "/overview")
        self.assertEqual(s, 200)
        self.assertIn("Operator sign in", body)
        # JSON APIs fail closed with 401 instead of redirecting
        s, body, _ = http("GET", self.dash2 + "/api/overview")
        self.assertEqual(s, 401)

    def test_login_flow_html(self):
        op = self._session_opener()
        # bad key -> error page, no session
        form = urllib.parse.urlencode(
            {"api_key": "vouch_sk_nope"}).encode()
        s, body, _ = http("POST", self.dash2 + "/login", form,
                          {"Content-Type":
                           "application/x-www-form-urlencoded"}, opener=op)
        self.assertEqual(s, 200)
        self.assertIn("rejected", body)
        # good key -> session cookie set, lands on overview
        form = urllib.parse.urlencode({"api_key": self.api_key}).encode()
        s, body, resp = http("POST", self.dash2 + "/login", form,
                             {"Content-Type":
                              "application/x-www-form-urlencoded"}, opener=op)
        self.assertEqual(s, 200)
        self.assertIn("Acme", body)
        # the session persists across requests
        s, body, _ = http("GET", self.dash2 + "/overview", opener=op)
        self.assertEqual(s, 200)
        self.assertIn("Acme", body)
        # logout kills the session -> back to the login page
        s, body, _ = http("POST", self.dash2 + "/logout", b"",
                          {"Content-Type":
                           "application/x-www-form-urlencoded"}, opener=op)
        self.assertIn("Operator sign in", body)
        s, body, _ = http("GET", self.dash2 + "/overview", opener=op)
        self.assertIn("Operator sign in", body)

    def test_login_flow_json_and_csrf(self):
        op = self._session_opener()
        s, data, _ = http("POST", self.dash2 + "/api/session",
                          {"api_key": "vouch_sk_nope"}, opener=op)
        self.assertEqual(s, 200)
        self.assertIn("rejected", json.dumps(data).lower()
                      if isinstance(data, str) else "")
        s, data, _ = http("POST", self.dash2 + "/api/session",
                          {"api_key": self.api_key}, opener=op)
        self.assertEqual(s, 201)
        csrf = data["csrf_token"]
        self.assertTrue(csrf)
        # state-changing call without CSRF -> 403
        s, data, _ = http("POST", self.dash2 + "/api/keys",
                          {"name": "nope"}, opener=op)
        self.assertEqual(s, 403)
        # with CSRF header -> works
        s, data, _ = http("POST", self.dash2 + "/api/keys", {"name": "csrf-ok"},
                          {"X-CSRF-Token": csrf}, opener=op)
        self.assertIn(s, (200, 201))
        new_id = data["id"]
        # HTML form without CSRF field -> 403 page
        form = urllib.parse.urlencode({"name": "x"}).encode()
        s, body, _ = http("POST", self.dash2 + "/keys", form,
                          {"Content-Type":
                           "application/x-www-form-urlencoded"}, opener=op)
        self.assertEqual(s, 403)
        # session teardown
        s, data, _ = http("DELETE", self.dash2 + "/api/session", opener=op)
        self.assertEqual(s, 204)
        s, body, _ = http("GET", self.dash2 + "/api/overview", opener=op)
        self.assertEqual(s, 401)
        # cleanup: revoke the key created above (via operator dashboard)
        http("DELETE", self.dash + f"/api/keys/{new_id}")

    def test_key_plaintext_never_leaks(self):
        # HTML pages and JSON never render key material or plaintext.
        s, body, _ = http("GET", self.dash + "/keys")
        self.assertEqual(s, 200)
        self.assertNotIn("vouch_sk_", body)
        s, data, _ = http("GET", self.dash + "/api/keys")
        self.assertNotIn("key_hex", json.dumps(data))
        self.assertNotIn("BEGIN", json.dumps(data))


if __name__ == "__main__":
    unittest.main(verbosity=2)
