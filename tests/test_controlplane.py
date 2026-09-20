"""Phase 2 — control plane, key authority cutover, suspension, migration.

Covers ARCHITECTURE.md §4 (control plane API), §4.3 (gatekeeper key bundles),
§4.6 (receipt-service tenant-key APIs), §4.7 (receipt-service key source),
and the Phase 2 exit gate:

  create tenant via API -> PUT policy via API -> gated MCP calls ->
  receipts stored -> verify chain through the tenant-facing API
  (tenant vouch_sk_* key, per §4.6).

The gatekeeper, receipt service, and control plane run as real subprocesses
(they read env at import, so in-process booting would poison the shared test
process). Pure unit tests (models, caches, key loading) run in-process.

Control-plane contract under test is ARCHITECTURE.md §4.4/§4.5:
  POST /v1/tenants/me/rotate-keys -> {"new_kid"}
  POST /internal/tenants/{id}/status (service token) for suspension
  GET  /internal/desired-state -> {"deployments": [...]}
  DELETE /v1/deployments/{id} -> 200 {"status": "stopped"}
Task scope travels in the X-Task-Id header (§4.1, v1-stable).
"""
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


# ------------------------------------------------------------------ helpers
def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def http(method, url, body=None, headers=None, timeout=10):
    req = urllib.request.Request(url, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data=data, timeout=timeout) as resp:
            raw = resp.read().decode()
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw


def wait_up(check, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if check():
                return True
        except Exception:
            pass
        time.sleep(0.2)
    return False


# ------------------------------------------------- unit: models
class TestControlPlaneModels(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        sys.path.insert(0, REPO)
        from services.controlplane.models import ControlPlaneDB
        self.db = ControlPlaneDB(os.path.join(self.tmp, "cp.db"))

    def test_create_tenant_returns_one_time_key(self):
        t = self.db.create_tenant("Acme")
        self.assertEqual(t["tenant_id"], "acme")
        self.assertTrue(t["api_key"].startswith("vouch_sk_"))
        self.assertIsNotNone(self.db.get_tenant_by_api_key(t["api_key"]))
        self.assertIsNone(self.db.get_tenant_by_api_key("vouch_sk_nope"))
        self.assertIsNone(self.db.get_tenant_by_api_key("not-a-key"))

    def test_create_tenant_slug_collision(self):
        a = self.db.create_tenant("Acme")
        b = self.db.create_tenant("Acme!")
        self.assertEqual(a["tenant_id"], "acme")
        self.assertEqual(b["tenant_id"], "acme-2")

    def test_rotate_keeps_history_with_cap(self):
        t = self.db.create_tenant("Acme")
        tid = t["tenant_id"]
        self.assertEqual(self.db.get_keys(tid)["current_kid"], "k1")
        self.assertEqual(self.db.rotate_keys(tid), "k2")
        self.assertEqual(self.db.rotate_keys(tid), "k3")
        keys = self.db.get_keys(tid)
        self.assertEqual(keys["current_kid"], "k3")
        self.assertEqual(sorted(keys["keys"]), ["k1", "k2", "k3"])
        # cap: current + 3 retired -> 4th rotate prunes k1
        self.assertEqual(self.db.rotate_keys(tid), "k4")
        self.assertEqual(self.db.rotate_keys(tid), "k5")
        keys = self.db.get_keys(tid)
        self.assertEqual(keys["current_kid"], "k5")
        self.assertEqual(sorted(keys["keys"]), ["k2", "k3", "k4", "k5"])
        self.assertIsNone(self.db.rotate_keys("ghost"))

    def test_key_bundle_shape(self):
        t = self.db.create_tenant("Acme")
        b = self.db.key_bundle(t["tenant_id"])
        self.assertEqual(b["tenant_id"], "acme")
        self.assertEqual(b["status"], "active")
        self.assertEqual(b["policy_version"], 0)
        self.assertEqual(b["current_kid"], "k1")
        self.assertEqual(sorted(b["keys"]), ["k1"])
        self.assertIsNone(self.db.key_bundle("ghost"))

    def test_policy_put_validates_and_versions(self):
        t = self.db.create_tenant("Acme")
        tid = t["tenant_id"]
        good = {"allow": [{"rule_id": "r1", "tool": "read_file",
                           "args": {"path": {"prefix": "/data/"}}}],
                "deny": [{"rule_id": "d1", "tool": "delete_database"}]}
        self.assertEqual(self.db.put_policy(tid, "deploy", good), 1)
        self.assertEqual(self.db.put_policy(tid, "deploy", good), 2)
        # unknown constraint op -> ValueError (app maps to 422)
        bad = {"allow": [{"rule_id": "x", "tool": "t",
                          "args": {"a": {"bogus": 1}}}], "deny": []}
        with self.assertRaises(ValueError):
            self.db.put_policy(tid, "deploy", bad)
        with self.assertRaises(ValueError):
            self.db.put_policy(tid, "deploy", "not-a-dict")
        with self.assertRaises(ValueError):
            self.db.put_policy(tid, "deploy", {"allow": "nope", "deny": []})
        with self.assertRaises(KeyError):
            self.db.put_policy("ghost", "deploy", good)
        with self.assertRaises(ValueError):
            self.db.put_policy(tid, "  ", good)

    def test_policy_bundle_delta(self):
        t = self.db.create_tenant("Acme")
        tid = t["tenant_id"]
        rules = {"allow": [{"rule_id": "r1", "tool": "t"}], "deny": []}
        self.db.put_policy(tid, "a", rules)
        ver, tasks = self.db.policy_bundle(tid, 0)
        self.assertEqual(ver, 1)
        self.assertEqual(list(tasks), ["a"])
        self.assertIn("rules_json", tasks["a"])
        ver2, tasks2 = self.db.policy_bundle(tid, 1)
        self.assertEqual(ver2, 1)
        self.assertEqual(tasks2, {})  # nothing newer: empty delta
        self.assertIsNone(self.db.policy_bundle("ghost", 0))

    def test_migrate_preserves_kids_byte_for_byte(self):
        reg = {"tenants": {
            "acme": {"keys": {"k1": "aa" * 32, "k2": "bb" * 32},
                     "current_kid": "k2", "created_at": 1},
            "globex": {"keys": {"k1": "cc" * 32},
                       "current_kid": "k1", "created_at": 2},
        }}
        path = os.path.join(self.tmp, "tenants.json")
        with open(path, "w") as f:
            json.dump(reg, f)
        result = self.db.migrate_tenants_file(path)
        self.assertEqual(sorted(result["migrated"]), ["acme", "globex"])
        for tid, t in reg["tenants"].items():
            bundle = self.db.key_bundle(tid)
            self.assertEqual(bundle["keys"], t["keys"])
            self.assertEqual(bundle["current_kid"], t["current_kid"])
            # each migrated tenant got a working API key
            self.assertIsNotNone(
                self.db.get_tenant_by_api_key(result["api_keys"][tid]))
        # idempotent re-run: nothing migrated twice
        again = self.db.migrate_tenants_file(path)
        self.assertEqual(again["migrated"], [])
        self.assertEqual(sorted(again["skipped"]), ["acme", "globex"])

    def test_seed_tokens_once(self):
        tok1 = self.db.seed_service_token("gatekeeper")
        self.assertTrue(tok1.startswith("vouch_svc_"))
        self.assertIsNone(self.db.seed_service_token("gatekeeper"))
        self.assertEqual(self.db.validate_service_token(tok1), "gatekeeper")
        self.assertIsNone(self.db.validate_service_token("garbage"))
        self.assertIsNone(self.db.validate_service_token(""))

    def test_api_key_crud(self):
        t = self.db.create_tenant("Acme")
        tid = t["tenant_id"]
        # the creation key is listed
        keys = self.db.list_api_keys(tid)
        self.assertEqual(len(keys), 1)
        self.assertNotIn("key_hash", json.dumps(keys))
        created = self.db.create_api_key(tid, "ci")
        self.assertTrue(created["api_key"].startswith("vouch_sk_"))
        self.assertIsNotNone(self.db.get_tenant_by_api_key(created["api_key"]))
        self.assertEqual(len(self.db.list_api_keys(tid)), 2)
        # revoke kills it
        self.assertTrue(self.db.revoke_api_key(tid, created["id"]))
        self.assertIsNone(self.db.get_tenant_by_api_key(created["api_key"]))
        # revoking twice reports already_revoked; unknown id is False
        self.assertEqual(self.db.revoke_api_key(tid, created["id"]),
                         "already_revoked")
        self.assertFalse(self.db.revoke_api_key(tid, "ak_nope"))

    def test_plan_and_status_validation(self):
        t = self.db.create_tenant("Acme")
        tid = t["tenant_id"]
        self.assertTrue(self.db.set_plan(tid, "pro"))
        self.assertEqual(self.db.get_tenant(tid)["plan"], "pro")
        with self.assertRaises(ValueError):
            self.db.set_plan(tid, "ultra")
        self.assertTrue(self.db.set_status(tid, "suspended"))
        self.assertEqual(self.db.get_tenant(tid)["status"], "suspended")
        with self.assertRaises(ValueError):
            self.db.set_status(tid, "banned")
        self.assertFalse(self.db.set_status("ghost", "suspended"))

    def test_deployments(self):
        t = self.db.create_tenant("Acme")
        tid = t["tenant_id"]
        d = self.db.create_deployment(tid, "deploy-staging",
                                      "vouch/agent-demo:latest")
        self.assertEqual(d["status"], "pending")
        self.assertTrue(d["deployment_id"].startswith("dep_"))
        deps = self.db.list_deployments(tid)
        self.assertEqual(len(deps), 1)
        self.assertTrue(self.db.set_deployment_status(
            d["deployment_id"], "running", container_id="c1"))
        with self.assertRaises(ValueError):
            self.db.set_deployment_status(d["deployment_id"], "exploding")
        desired = self.db.desired_state()
        self.assertEqual(desired[0]["desired"], "running")
        self.assertTrue(self.db.stop_deployment(tid, d["deployment_id"]))
        self.assertEqual(self.db.desired_state()[0]["desired"], "stopped")
        with self.assertRaises(ValueError):
            self.db.create_deployment(tid, "x", "")


# ------------------------------------------------- unit: key bundle cache
class _BundleHandler(BaseHTTPRequestHandler):
    bundle = {"keys": {"k1": "aa" * 32}, "current_kid": "k1",
              "status": "active", "policy_version": 3, "tenant_id": "t1"}
    fail = False

    def do_GET(self):
        if self.fail:
            self.send_response(500)
            self.end_headers()
            return
        body = json.dumps(self.bundle).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class TestKeyBundleCache(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, REPO)
        from gatekeeper.controlplane import KeyBundleCache
        self.Cache = KeyBundleCache
        self.srv = HTTPServer(("127.0.0.1", 0), _BundleHandler)
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever,
                                       daemon=True)
        self.thread.start()
        _BundleHandler.fail = False

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def _cache(self, **kw):
        kw.setdefault("ttl", 60)
        return self.Cache(f"http://127.0.0.1:{self.port}", "tok", **kw)

    def test_fetch_and_interface(self):
        c = self._cache()
        kid, key = c.signing_key("t1")
        self.assertEqual(kid, "k1")
        self.assertEqual(key, bytes.fromhex("aa" * 32))
        self.assertEqual(c.status("t1"), "active")
        self.assertEqual(c.policy_version("t1"), 3)
        self.assertEqual(list(c.verification_keys("t1")), ["k1"])

    def test_server_error_without_stale_fails_closed(self):
        _BundleHandler.fail = True
        c = self._cache()
        with self.assertRaises(KeyError):
            c.signing_key("t1")

    def test_stale_served_while_down(self):
        c = self._cache(ttl=0.05, stale_max=600)
        c.signing_key("t1")  # prime the cache
        _BundleHandler.fail = True
        time.sleep(0.1)  # TTL expired, server failing
        kid, _ = c.signing_key("t1")  # stale entry keeps enforcement alive
        self.assertEqual(kid, "k1")

    def test_beyond_stale_max_fails_closed(self):
        c = self._cache(ttl=0.01, stale_max=0.02)
        c.signing_key("t1")
        _BundleHandler.fail = True
        time.sleep(0.05)
        with self.assertRaises(KeyError):
            c.signing_key("t1")

    def test_invalidate_drops_entry(self):
        c = self._cache()
        c.signing_key("t1")
        c.invalidate("t1")
        _BundleHandler.fail = True
        with self.assertRaises(KeyError):
            c.signing_key("t1")


# --------------------------------------------- unit: policy bundle cache
class _PolicyHandler(BaseHTTPRequestHandler):
    version = 1
    fail = False

    def do_GET(self):
        if self.fail:
            self.send_response(500)
            self.end_headers()
            return
        body = json.dumps({
            "version": self.version,
            "policies": {
                "deploy": {
                    "version": self.version,
                    "rules_json": json.dumps({
                        "allow": [{"rule_id": "r1", "tool": "read_file"}],
                        "deny": []}),
                }
            },
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class TestPolicyBundleCache(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, REPO)
        from gatekeeper.controlplane import PolicyBundleCache
        self.Cache = PolicyBundleCache
        self.srv = HTTPServer(("127.0.0.1", 0), _PolicyHandler)
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever,
                                       daemon=True)
        self.thread.start()
        _PolicyHandler.fail = False
        _PolicyHandler.version = 1

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_compile_and_enforce(self):
        c = self.Cache(f"http://127.0.0.1:{self.port}", "tok",
                       poll_interval=3600)
        try:
            p = c.policy_for("t1")
            self.assertIsNotNone(p)
            allowed, reason, rule = p.decide("deploy", "read_file", {})
            self.assertTrue(allowed)
            self.assertEqual(rule, "r1")
            allowed2, _, _ = p.decide("deploy", "exec_sql", {})
            self.assertFalse(allowed2)
        finally:
            c.close()

    def test_failure_keeps_last_good(self):
        c = self.Cache(f"http://127.0.0.1:{self.port}", "tok",
                       poll_interval=3600)
        try:
            p1 = c.policy_for("t1")
            _PolicyHandler.fail = True
            p2 = c.refresh_tenant("t1")
            self.assertIs(p1, p2)  # same object: never raises, never drops
        finally:
            c.close()


# ------------------------------------------------- unit: receipts key loading
class TestReceiptKeyLoading(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, REPO)
        from services.receipts import keys as kmod
        self.kmod = kmod
        self.tmp = tempfile.mkdtemp()
        self.tenants_path = os.path.join(self.tmp, "tenants.json")
        with open(self.tenants_path, "w") as f:
            json.dump({"tenants": {
                "fileonly": {"keys": {"k1": "dd" * 32},
                             "current_kid": "k1"}}}, f)

    def test_file_only_works_with_no_cp(self):
        keys = self.kmod.load_verification_keys(self.tenants_path, "fileonly")
        self.assertEqual(keys, {"k1": bytes.fromhex("dd" * 32)})

    def test_cp_down_falls_back_to_file(self):
        keys = self.kmod.load_verification_keys(
            self.tenants_path, "fileonly",
            controlplane_url="http://127.0.0.1:1", cp_token="x")
        self.assertEqual(keys, {"k1": bytes.fromhex("dd" * 32)})

    def test_cp_down_unknown_tenant_is_503_not_404(self):
        with self.assertRaises(self.kmod.KeyAuthorityUnavailable):
            self.kmod.load_verification_keys(
                self.tenants_path, "ghost",
                controlplane_url="http://127.0.0.1:1", cp_token="x")

    def test_no_cp_unknown_tenant_is_keyerror(self):
        with self.assertRaises(KeyError):
            self.kmod.load_verification_keys(self.tenants_path, "ghost")


# ------------------------------------------------- e2e: full control-plane path
class UpstreamStub(BaseHTTPRequestHandler):
    """Minimal upstream: answers initialize + tools/call, ignores the rest."""
    def _json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        req = json.loads(self.rfile.read(length) or b"{}")
        method = req.get("method", "")
        if method == "initialize":
            self._json({"jsonrpc": "2.0", "id": req.get("id"),
                        "result": {"protocolVersion": "2024-11-05",
                                   "capabilities": {}}})
        elif method == "tools/call":
            self._json({"jsonrpc": "2.0", "id": req.get("id"),
                        "result": {"content": [{"type": "text",
                                                "text": "stub-ok"}]}})
        else:
            self._json({"jsonrpc": "2.0", "id": req.get("id"), "result": {}})

    def log_message(self, *a):
        pass


class TestControlPlaneE2E(unittest.TestCase):
    """The Phase 2 exit gate, against real subprocesses."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.cp_port = free_port()
        cls.rc_port = free_port()
        cls.gk_port = free_port()
        cls.up_port = free_port()
        env_base = dict(os.environ)
        env_base["PYTHONPATH"] = REPO + os.pathsep + env_base.get("PYTHONPATH", "")

        # ---- control plane (with server-side push-invalidate + usage fan-in)
        cls.cp_db = os.path.join(cls.tmp, "cp.db")
        cp_env = dict(env_base, CONTROLPLANE_PORT=str(cls.cp_port),
                      CONTROLPLANE_DB=cls.cp_db)
        cls.cp = subprocess.Popen(
            [PY, "-m", "services.controlplane.app"], env=cp_env,
            cwd=REPO, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.cp_url = f"http://127.0.0.1:{cls.cp_port}"

        # seed service tokens into the SAME db the server uses
        seed_env = dict(env_base, CONTROLPLANE_DB=cls.cp_db)
        out = subprocess.run(
            [PY, "-m", "services.controlplane.seed_tokens"], env=seed_env,
            cwd=REPO, capture_output=True, text=True, check=True).stdout
        toks = dict(line.split("=", 1) for line in out.splitlines()
                    if "=" in line and not line.startswith("#"))
        cls.svc_token = toks["RECEIPT_SVC_TOKEN"]
        cls.gk_token = toks["GATEKEEPER_SVC_TOKEN"]
        cls.runner_token = toks["RUNNER_TOKEN"]

        ok = wait_up(lambda: http(
            "GET", cls.cp_url + "/internal/desired-state",
            headers={"Authorization": f"Bearer {cls.runner_token}"})[0] == 200)
        assert ok, "control plane did not start"

        # ---- receipt service, keyed by the control plane (file has NO tenants)
        empty_tenants = os.path.join(cls.tmp, "tenants.json")
        with open(empty_tenants, "w") as f:
            json.dump({"tenants": {}}, f)
        rc_env = dict(env_base, RECEIPT_PORT=str(cls.rc_port),
                      RECEIPT_DB=os.path.join(cls.tmp, "receipts.db"),
                      RECEIPT_SVC_TOKEN=cls.svc_token,
                      TENANTS_PATH=empty_tenants,
                      CONTROLPLANE_URL=cls.cp_url,
                      CONTROLPLANE_SVC_TOKEN=cls.svc_token)
        cls.rc = subprocess.Popen(
            [PY, "-m", "services.receipts.app"], env=rc_env,
            cwd=REPO, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.rc_url = f"http://127.0.0.1:{cls.rc_port}"
        ok = wait_up(lambda: http("GET", cls.rc_url + "/v1/health")[0] == 200)
        assert ok, "receipt service did not start"

        # now that both are up, restart the control plane with push + fan-in
        # (env is read at import; simplest is a restart here, once)
        cls.cp.terminate()
        cls.cp.wait(timeout=10)
        cp_env.update({
            "GATEKEEPER_URL": f"http://127.0.0.1:{cls.gk_port}",
            "CONTROLPLANE_INVALIDATE_TOKEN": cls.gk_token,
            "RECEIPT_SVC_URL": cls.rc_url,
            "RECEIPT_FANIN_TOKEN": cls.svc_token,
        })
        cls.cp = subprocess.Popen(
            [PY, "-m", "services.controlplane.app"], env=cp_env,
            cwd=REPO, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ok = wait_up(lambda: http(
            "GET", cls.cp_url + "/internal/desired-state",
            headers={"Authorization": f"Bearer {cls.runner_token}"})[0] == 200)
        assert ok, "control plane did not restart"

        # ---- upstream stub (in-process thread)
        cls.up = HTTPServer(("127.0.0.1", cls.up_port), UpstreamStub)
        threading.Thread(target=cls.up.serve_forever, daemon=True).start()

        # ---- gatekeeper, fully control-plane driven
        policy_file = os.path.join(cls.tmp, "policy.yaml")
        with open(policy_file, "w") as f:
            f.write('version: 1\ntasks: {}\n')
        gk_env = dict(env_base, GATEKEEPER_PORT=str(cls.gk_port),
                      GATEKEEPER_UPSTREAM=f"http://127.0.0.1:{cls.up_port}/mcp",
                      GATEKEEPER_TENANTS_PATH=os.path.join(cls.tmp, "gk-tenants.json"),
                      GATEKEEPER_RECEIPTS_PATH=os.path.join(cls.tmp, "spool.jsonl"),
                      GATEKEEPER_POLICY_PATH=policy_file,
                      RECEIPT_SVC_URL=cls.rc_url,
                      RECEIPT_SVC_TOKEN=cls.svc_token,
                      RECEIPT_FLUSH_INTERVAL="0.2",
                      CONTROLPLANE_URL=cls.cp_url,
                      GATEKEEPER_SVC_TOKEN=cls.gk_token,
                      POLICY_POLL_INTERVAL="3600")
        with open(gk_env["GATEKEEPER_TENANTS_PATH"], "w") as f:
            json.dump({"tenants": {}}, f)
        cls.gk = subprocess.Popen(
            [PY, "-m", "gatekeeper.proxy"], env=gk_env,
            cwd=REPO, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.gk_url = f"http://127.0.0.1:{cls.gk_port}"
        ok = wait_up(lambda: http(
            "POST", cls.gk_url + "/mcp",
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "x", "arguments": {}}},
            headers={"X-Tenant-Id": "ghost", "X-Task-Id": "t"})[0] == 403)
        assert ok, "gatekeeper did not start"

        # ---- provision the e2e tenant through the API only
        code, created = http("POST", cls.cp_url + "/v1/tenants",
                             {"name": "E2E Corp"})
        assert code == 201, created
        cls.tid = created["tenant_id"]
        cls.api_key = created["api_key"]

    @classmethod
    def tearDownClass(cls):
        for p in (cls.gk, cls.rc, cls.cp):
            p.terminate()
        for p in (cls.gk, cls.rc, cls.cp):
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        cls.up.shutdown()
        cls.up.server_close()

    # -- small helpers
    def _auth(self):
        return {"Authorization": f"Bearer {self.api_key}"}

    def _svc(self):
        return {"Authorization": f"Bearer {self.svc_token}"}

    def _tenant_headers(self, task_id):
        return {"X-Tenant-Id": self.tid, "X-Task-Id": task_id}

    def _invalidate(self):
        """Direct gatekeeper cache drop (deterministic; the CP also pushes)."""
        code, _ = http("POST", self.gk_url + "/internal/cache/invalidate",
                       {"tenant_id": self.tid},
                       headers={"Authorization": f"Bearer {self.gk_token}"})
        self.assertEqual(code, 200)

    def _put_policy(self, rules):
        code, body = http("PUT", self.cp_url + "/v1/policies/deploy-staging",
                          {"rules": rules}, headers=self._auth())
        self.assertEqual(code, 200, body)
        return body["version"]

    def _call(self, task_id, tool, args, req_id=1):
        return http("POST", self.gk_url + "/mcp",
                    {"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
                     "params": {"name": tool, "arguments": args}},
                    headers=self._tenant_headers(task_id))

    def _receipts(self, auth_headers, params=""):
        code, body = http("GET",
                          self.rc_url + f"/v1/receipts{params}",
                          headers=auth_headers)
        self.assertEqual(code, 200, body)
        return body["items"]

    # -- the gate
    def test_01_tenant_api_auth(self):
        code, me = http("GET", self.cp_url + "/v1/tenants/me",
                        headers=self._auth())
        self.assertEqual(code, 200)
        self.assertEqual(me["tenant_id"], self.tid)
        self.assertEqual(me["plan"], "free")
        self.assertEqual(me["status"], "active")
        self.assertIn("usage", me)
        self.assertNotIn("api_key", json.dumps(me))
        self.assertEqual(http("GET", self.cp_url + "/v1/tenants/me")[0], 401)
        self.assertEqual(http(
            "GET", self.cp_url + "/v1/tenants/me",
            headers={"Authorization": "Bearer vouch_sk_nope"})[0], 401)
        # internal endpoints reject the tenant API key...
        code, _ = http("GET",
                       self.cp_url + f"/internal/tenants/{self.tid}/key-bundle",
                       headers=self._auth())
        self.assertEqual(code, 401)
        # ...and accept the service token
        code, bundle = http(
            "GET", self.cp_url + f"/internal/tenants/{self.tid}/key-bundle",
            headers=self._svc())
        self.assertEqual(code, 200)
        self.assertEqual(bundle["current_kid"], "k1")
        self.assertNotIn("api_key", json.dumps(bundle))

    def test_02_policy_put_validates(self):
        bad = {"allow": [{"rule_id": "x", "tool": "t",
                          "args": {"a": {"bogus": 1}}}], "deny": []}
        code, body = http("PUT", self.cp_url + "/v1/policies/zzz",
                          {"rules": bad}, headers=self._auth())
        self.assertEqual(code, 422, body)
        code, body = http("PUT", self.cp_url + "/v1/policies/zzz",
                          {"rules": "nope"}, headers=self._auth())
        self.assertEqual(code, 422, body)
        # policy listing (dashboard reads this)
        code, listed = http("GET", self.cp_url + "/v1/policies",
                            headers=self._auth())
        self.assertEqual(code, 200)
        self.assertEqual(listed["tasks"], {})

    def test_03_gated_calls_allow_and_deny(self):
        self._put_policy({
            "allow": [{"rule_id": "read-ok", "tool": "read_file",
                       "args": {"path": {"prefix": "/data/"}}}],
            "deny": [{"rule_id": "no-sql", "tool": "exec_sql"}]})
        self._invalidate()
        code, resp = self._call("deploy-staging", "read_file",
                                {"path": "/data/report.csv"})
        self.assertEqual(code, 200, resp)
        self.assertIn("result", resp)
        code, resp = self._call("deploy-staging", "exec_sql",
                                {"q": "DROP TABLE t"}, req_id=2)
        self.assertEqual(code, 200, resp)
        self.assertIn("error", resp)
        self.assertIn("no-sql", resp["error"]["message"])
        self.assertIn("receipt #", resp["error"]["message"])

    def test_04_receipts_stored_and_chain_verifies_with_tenant_key(self):
        time.sleep(1.0)  # let the flusher deliver any spooled receipts
        # §4.6: the tenant API key is enough — no service token needed.
        items = self._receipts(self._auth())
        self.assertGreaterEqual(len(items), 2)
        decisions = {r["decision"] for r in items}
        self.assertEqual(decisions, {"allow", "deny"})
        # tenant-key verify, no ?tenant_id= (the key IS the tenant)
        code, v = http("GET", self.rc_url + "/v1/verify",
                       headers=self._auth())
        self.assertEqual(code, 200, v)
        self.assertEqual(v["tenant_id"], self.tid)
        self.assertTrue(v["chain_ok"], v)
        self.assertEqual(v["failures"], [])
        # ...and explicitly scoped
        code, v2 = http("GET",
                        self.rc_url + f"/v1/verify?tenant_id={self.tid}",
                        headers=self._auth())
        self.assertEqual(code, 200, v2)
        self.assertTrue(v2["chain_ok"])
        # a tenant key cannot read another tenant's receipts
        code, _ = http("GET", self.rc_url + "/v1/verify?tenant_id=someone-else",
                       headers=self._auth())
        self.assertEqual(code, 403)
        # garbage key -> 401
        code, _ = http("GET", self.rc_url + "/v1/verify",
                       headers={"Authorization": "Bearer vouch_sk_nope"})
        self.assertEqual(code, 401)
        # service token still works (ops path)
        code, v3 = http("GET",
                        self.rc_url + f"/v1/verify?tenant_id={self.tid}",
                        headers=self._svc())
        self.assertEqual(code, 200, v3)
        self.assertTrue(v3["chain_ok"])

    def test_05_rotation_pushes_invalidate_and_new_kid_signs(self):
        # rotate via the tenant API; the control plane pushes
        # /internal/cache/invalidate to the gatekeeper itself (§4.3) —
        # no manual invalidate needed.
        code, body = http("POST", self.cp_url + "/v1/tenants/me/rotate-keys",
                          headers=self._auth())
        self.assertEqual(code, 200, body)
        self.assertEqual(body["new_kid"], "k2")
        code, resp = self._call("deploy-staging", "read_file",
                                {"path": "/data/after-rotate.csv"}, req_id=3)
        self.assertEqual(code, 200, resp)
        self.assertIn("result", resp)
        time.sleep(1.0)
        items = self._receipts(self._svc(), f"?tenant_id={self.tid}")
        kids = {r["kid"] for r in items}
        self.assertIn("k2", kids)  # the pushed invalidate took effect
        self.assertIn("k1", kids)  # pre-rotation receipts kept
        # old receipts still verify against retired k1
        code, v = http("GET", self.rc_url + "/v1/verify",
                       headers=self._auth())
        self.assertEqual(code, 200, v)
        self.assertTrue(v["chain_ok"], v)

    def test_06_suspend_denies_everything(self):
        code, body = http("POST",
                          self.cp_url + f"/internal/tenants/{self.tid}/status",
                          {"status": "suspended"}, headers=self._svc())
        self.assertEqual(code, 200, body)
        # the control plane pushed the invalidate; no manual drop needed
        code, resp = self._call("deploy-staging", "read_file",
                                {"path": "/data/x.csv"}, req_id=4)
        self.assertEqual(code, 200, resp)
        self.assertIn("tenant suspended", resp["error"]["message"])
        # non-tool calls are blocked too
        code, _ = http("POST", self.gk_url + "/mcp",
                       {"jsonrpc": "2.0", "id": 5, "method": "tools/list",
                        "params": {}},
                       headers=self._tenant_headers("deploy-staging"))
        self.assertEqual(code, 403)
        # the blocked attempt is receipted with the suspension reason
        time.sleep(1.0)
        items = self._receipts(self._svc(), f"?tenant_id={self.tid}")
        reasons = {r["reason"] for r in items if r["decision"] == "deny"}
        self.assertIn("tenant suspended", reasons)
        # reactivate: the tenant works again
        code, _ = http("POST",
                       self.cp_url + f"/internal/tenants/{self.tid}/status",
                       {"status": "active"}, headers=self._svc())
        self.assertEqual(code, 200)
        code, resp = self._call("deploy-staging", "read_file",
                                {"path": "/data/back.csv"}, req_id=6)
        self.assertEqual(code, 200, resp)
        self.assertIn("result", resp)

    def test_07_policy_change_takes_effect(self):
        self._put_policy({"allow": [],
                          "deny": [{"rule_id": "lockdown",
                                    "tool": "read_file"}]})
        self._invalidate()
        code, resp = self._call("deploy-staging", "read_file",
                                {"path": "/data/x.csv"}, req_id=7)
        self.assertEqual(code, 200, resp)
        self.assertIn("lockdown", resp["error"]["message"])
        # deleting the policy removes the task -> default deny, unknown task
        code, _ = http("DELETE", self.cp_url + "/v1/policies/deploy-staging",
                       headers=self._auth())
        self.assertEqual(code, 204)
        self._invalidate()
        code, resp = self._call("deploy-staging", "read_file",
                                {"path": "/data/x.csv"}, req_id=8)
        self.assertIn("error", resp)

    def test_08_deployments_and_usage(self):
        self._put_policy({"allow": [{"rule_id": "r1", "tool": "read_file"}],
                          "deny": []})
        self._invalidate()
        code, dep = http("POST", self.cp_url + "/v1/deployments",
                         {"task_id": "deploy-staging",
                          "image": "vouch/agent-demo:latest",
                          "agent_image": "vouch/agent-demo:latest"},
                         headers=self._auth())
        self.assertEqual(code, 201, dep)
        dep_id = dep["deployment_id"]
        code, deps = http("GET", self.cp_url + "/v1/deployments",
                          headers=self._auth())
        self.assertEqual(code, 200)
        self.assertEqual(len(deps["deployments"]), 1)
        code, one = http("GET", self.cp_url + f"/v1/deployments/{dep_id}",
                         headers=self._auth())
        self.assertEqual(code, 200)
        # runner view of desired state (§4.5): pending -> desired running
        code, desired = http("GET", self.cp_url + "/internal/desired-state",
                             headers=self._svc())
        self.assertEqual(code, 200)
        self.assertEqual(desired["deployments"][0]["desired"], "running")
        # runner reports running
        code, _ = http("POST",
                       self.cp_url + f"/internal/deployments/{dep_id}/status",
                       {"status": "running", "container_id": "c1"},
                       headers=self._svc())
        self.assertEqual(code, 200)
        code, desired = http("GET", self.cp_url + "/internal/desired-state",
                             headers=self._svc())
        self.assertEqual(desired["deployments"][0]["desired"], "running")
        # usage fanned in from the receipt service via /v1/tenants/me
        code, me = http("GET", self.cp_url + "/v1/tenants/me",
                        headers=self._auth())
        self.assertEqual(code, 200)
        total = me["usage"]["actions_allowed"] + me["usage"]["actions_denied"]
        self.assertGreaterEqual(total, 1, me["usage"])
        # delete stops the deployment
        code, stopped = http("DELETE",
                             self.cp_url + f"/v1/deployments/{dep_id}",
                             headers=self._auth())
        self.assertEqual(code, 200)
        self.assertEqual(stopped["status"], "stopped")

    def test_09_api_keys_crud(self):
        code, created = http("POST", self.cp_url + "/v1/api-keys",
                             {"name": "ci"}, headers=self._auth())
        self.assertEqual(code, 201, created)
        self.assertTrue(created["api_key"].startswith("vouch_sk_"))
        ci_key = created["api_key"]
        # the new key authenticates
        code, me = http("GET", self.cp_url + "/v1/tenants/me",
                        headers={"Authorization": f"Bearer {ci_key}"})
        self.assertEqual(code, 200)
        self.assertEqual(me["tenant_id"], self.tid)
        code, listed = http("GET", self.cp_url + "/v1/api-keys",
                            headers=self._auth())
        self.assertEqual(len(listed["keys"]), 2)
        # revoke -> the key stops working
        code, _ = http("DELETE",
                       self.cp_url + f"/v1/api-keys/{created['id']}",
                       headers=self._auth())
        self.assertEqual(code, 204)
        code, _ = http("GET", self.cp_url + "/v1/tenants/me",
                       headers={"Authorization": f"Bearer {ci_key}"})
        self.assertEqual(code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
