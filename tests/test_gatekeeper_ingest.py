"""Gatekeeper <-> receipt service integration (Phase 1, §4.2).

Runs the REAL gatekeeper, receipt service, and demo upstream as
subprocesses on ephemeral ports (no in-process proxy import: that keeps
this file isolated from tests/test_transport.py's module-level import):

  - tools/call decisions flow through policy_v2.decide()
  - receipts land in the service with per-tenant seq + rule_id
  - service outage -> local file fallback; flusher replays in order
  - 409 duplicate_seq is success; 422 chain_break triggers tip re-sync
  - arg-constrained deny proven end to end
"""
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

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from gatekeeper.ingest import ReceiptEmitter  # noqa: E402 (no server import)
from gatekeeper.receipts import ReceiptLog, build_receipt  # noqa: E402

TMP = tempfile.mkdtemp(prefix="vouch-gk-ingest-")
TOKEN = "phase1-test-token"

V2_POLICY = """
tasks:
  deploy-staging:
    version: 2
    rules:
      allow:
        - rule_id: deploy-staging-build
          tool: deploy_staging
          args:
            build: {regex: "^[0-9a-f]{6,40}$"}
            env: {in: ["staging"]}
      deny:
        - rule_id: no-prod-deploy
          tool: deploy_staging
          args:
            env: {equals: "prod"}
        - rule_id: no-destructive
          tool: delete_database
"""


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_for(url, timeout=15, headers=None):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, headers=headers or {})
            urllib.request.urlopen(req, timeout=2).read()
            return True
        except Exception:
            time.sleep(0.2)
    raise AssertionError(f"never became ready: {url}")


class McpClient:
    """Minimal MCP client: initialize + tools/call (JSON accept)."""

    def __init__(self, gate_url, tenant, task, agent):
        self.url = gate_url
        self.tenant = tenant
        self.task = task
        self.agent = agent
        self.session = None
        self._id = 0

    def _post(self, msg):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, **msg}
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json",
                   "X-Tenant-Id": self.tenant, "X-Task-Id": self.task,
                   "X-Agent-Id": self.agent}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(self.url, data=json.dumps(msg).encode(),
                                     headers=headers)
        try:
            resp = urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")
        sid = resp.headers.get("Mcp-Session-Id")
        if sid:
            self.session = sid
        return resp.status, json.loads(resp.read() or b"{}")

    def initialize(self):
        code, msg = self._post(
            {"method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "t", "version": "0"}}})
        assert code == 200 and self.session, f"initialize failed: {msg}"

    def call_tool(self, tool, args):
        _, msg = self._post({"method": "tools/call",
                             "params": {"name": tool, "arguments": args}})
        return msg


def svc_request(port, method, path, body=None, token=TOKEN):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    if data:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                 headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw or b"{}")
        except ValueError:
            return e.code, {}


class GatekeeperIngestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tenants_path = os.path.join(TMP, "tenants.json")
        cls.policy_path = os.path.join(TMP, "policy_v2.yaml")
        with open(cls.policy_path, "w", encoding="utf-8") as f:
            f.write(V2_POLICY)
        cls.receipts_db = os.path.join(TMP, "receipts.db")
        cls.local_log = os.path.join(TMP, "receipts.jsonl")

        env = dict(os.environ, PYTHONPATH=REPO)
        # tenant registry (shared file: gatekeeper + receipt service).
        # EmitterUnitTest may have created it already (class order); only
        # create when acme is missing.
        needs_create = True
        if os.path.exists(cls.tenants_path):
            try:
                needs_create = "acme" not in json.load(
                    open(cls.tenants_path, encoding="utf-8"))["tenants"]
            except (ValueError, KeyError):
                needs_create = True
        if needs_create:
            subprocess.run(
                [sys.executable, "-m", "gatekeeper.tenants", "create", "acme"],
                cwd=REPO,
                env={**env, "GATEKEEPER_TENANTS_PATH": cls.tenants_path},
                check=True, capture_output=True)

        cls.rport = free_port()
        cls.uport = free_port()
        cls.gport = free_port()

        cls.receipts_proc = subprocess.Popen(
            [sys.executable, "-m", "services.receipts.app"], cwd=REPO,
            env={**env, "RECEIPT_PORT": str(cls.rport),
                 "RECEIPT_DB": cls.receipts_db,
                 "RECEIPT_SVC_TOKEN": TOKEN,
                 "TENANTS_PATH": cls.tenants_path},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.upstream_proc = subprocess.Popen(
            [sys.executable, "demo/upstream.py"], cwd=REPO,
            env={**env, "UPSTREAM_PORT": str(cls.uport)},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for(f"http://127.0.0.1:{cls.rport}/v1/health")

        cls.gate_env = {
            **env,
            "GATEKEEPER_PORT": str(cls.gport),
            "GATEKEEPER_UPSTREAM": f"http://127.0.0.1:{cls.uport}/mcp",
            "GATEKEEPER_TENANTS_PATH": cls.tenants_path,
            "GATEKEEPER_RECEIPTS_PATH": cls.local_log,
            "GATEKEEPER_POLICY_PATH": cls.policy_path,
            "RECEIPT_SVC_URL": f"http://127.0.0.1:{cls.rport}",
            "RECEIPT_SVC_TOKEN": TOKEN,
            "RECEIPT_FLUSH_INTERVAL": "0.2",
        }
        cls.gate_proc = subprocess.Popen(
            [sys.executable, "-m", "gatekeeper.proxy"], cwd=REPO,
            env=cls.gate_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # gatekeeper has no health endpoint: wait for TCP
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", cls.gport),
                                         timeout=1).close()
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise AssertionError("gatekeeper never listened")
        cls.gate_url = f"http://127.0.0.1:{cls.gport}/mcp"

    @classmethod
    def tearDownClass(cls):
        for p in ("gate_proc", "receipts_proc", "upstream_proc"):
            proc = getattr(cls, p, None)
            if proc:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()

    # ------------------------------------------------------------- helpers
    def svc(self, method, path, body=None):
        return svc_request(self.rport, method, path, body)

    def service_count(self, tenant="acme"):
        code, resp = self.svc("GET", f"/v1/verify?tenant_id={tenant}")
        self.assertEqual(code, 200)
        return resp["receipts"]

    def wait_for_receipt(self, seq, tenant="acme", timeout=15):
        """Poll until a receipt is visible in the service (allow-path emit
        runs after the MCP response bytes are written, so tests must not
        assume immediacy)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            code, resp = self.svc(
                "GET", f"/v1/receipts/{seq}?tenant_id={tenant}")
            if code == 200:
                return resp
            time.sleep(0.2)
        raise AssertionError(
            f"receipt seq={seq} never appeared in the service")

    # ---------------------------------------------------------------- tests
    def test_receipt_lands_in_service(self):
        local_before = (os.path.getsize(self.local_log)
                        if os.path.exists(self.local_log) else 0)
        code, tip = self.svc(
            "GET", "/v1/receipts?tenant_id=acme&limit=1&order=desc")
        seq_before = tip["items"][0]["seq"] if tip["items"] else 0
        client = McpClient(self.gate_url, "acme", "deploy-staging", "a1")
        client.initialize()
        msg = client.call_tool("deploy_staging",
                               {"build": "a1b2c3", "env": "staging"})
        self.assertNotIn("error", msg)
        # this test's receipt is the very next per-tenant seq (queue drained
        # in the previous test; nothing else writes here)
        r = self.wait_for_receipt(seq_before + 1)
        self.assertEqual(r["tool"], "deploy_staging")
        self.assertEqual(r["decision"], "allow")
        self.assertEqual(r["rule_id"], "deploy-staging-build")
        self.assertEqual(r["policy_version"], 2)
        # happy path: nothing spilled to the local fallback file
        local_after = (os.path.getsize(self.local_log)
                       if os.path.exists(self.local_log) else 0)
        self.assertEqual(local_after, local_before)

    def test_arg_constrained_deny(self):
        client = McpClient(self.gate_url, "acme", "deploy-staging", "a1")
        client.initialize()
        # env=prod matches the deny rule -> -32000, never upstream
        msg = client.call_tool("deploy_staging",
                               {"build": "a1b2c3", "env": "prod"})
        self.assertEqual(msg["error"]["code"], -32000)
        self.assertIn("denied by rule 'no-prod-deploy'",
                      msg["error"]["message"])
        # missing env fails the allow rule's constraints -> default deny
        msg = client.call_tool("deploy_staging", {"build": "a1b2c3"})
        self.assertEqual(msg["error"]["code"], -32000)
        self.assertIn("not granted tool", msg["error"]["message"])
        deadline = time.time() + 15
        items = []
        while time.time() < deadline:
            code, resp = self.svc(
                "GET", "/v1/receipts?tenant_id=acme&rule_id=no-prod-deploy"
                       "&decision=deny&limit=1&order=desc")
            items = resp.get("items", []) if code == 200 else []
            if items:
                break
            time.sleep(0.2)
        self.assertTrue(items, "deny receipt never landed")
        self.assertEqual(items[0]["decision"], "deny")
        self.assertEqual(items[0]["policy_version"], 2)

    def test_fallback_then_flusher_recovers(self):
        before = self.service_count()
        # kill the receipt service: gatekeeper must keep enforcing
        self.receipts_proc.terminate()
        self.receipts_proc.wait(timeout=10)
        try:
            client = McpClient(self.gate_url, "acme", "deploy-staging", "a1")
            client.initialize()
            msg = client.call_tool("deploy_staging",
                                   {"build": "deadbe", "env": "staging"})
            self.assertNotIn("error", msg)  # still allowed: enforcement is local
            # deny path also works with the service down
            msg = client.call_tool("delete_database", {})
            self.assertEqual(msg["error"]["code"], -32000)
            # both receipts fell back to the local v1 file
            log = ReceiptLog(self.local_log,
                             FakeRegistry(self.tenants_path))
            ok, failures = log.verify()
            self.assertTrue(ok, failures)
            self.assertGreaterEqual(log.seq, 2)
        finally:
            # service back: flusher replays the spool in order
            env = dict(os.environ, PYTHONPATH=REPO)
            self.receipts_proc = subprocess.Popen(
                [sys.executable, "-m", "services.receipts.app"], cwd=REPO,
                env={**env, "RECEIPT_PORT": str(self.rport),
                     "RECEIPT_DB": self.receipts_db,
                     "RECEIPT_SVC_TOKEN": TOKEN,
                     "TENANTS_PATH": self.tenants_path},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wait_for(f"http://127.0.0.1:{self.rport}/v1/health")
        deadline = time.time() + 15
        while time.time() < deadline:
            if self.service_count() >= before + 2:
                break
            time.sleep(0.3)
        self.assertGreaterEqual(self.service_count(), before + 2)
        code, resp = self.svc("GET", "/v1/verify?tenant_id=acme")
        self.assertTrue(resp["chain_ok"], resp["failures"])

    def test_422_resync(self):
        client = McpClient(self.gate_url, "acme", "deploy-staging", "a1")
        client.initialize()
        client.call_tool("deploy_staging", {"build": "aa11bb", "env": "staging"})
        # wait for that receipt to land before reading the tip
        deadline = time.time() + 15
        tip = None
        while time.time() < deadline:
            code, rows = self.svc(
                "GET", "/v1/receipts?tenant_id=acme&limit=1&order=desc")
            if code == 200 and rows["items"]:
                tip = rows["items"][0]
                break
            time.sleep(0.2)
        self.assertIsNotNone(tip, "first receipt never landed")
        # a "second gatekeeper" writes the next seq directly
        import hashlib
        key_hex = json.load(
            open(self.tenants_path, encoding="utf-8"))["tenants"]["acme"]["keys"]["k1"]
        foreign = build_receipt(
            seq=tip["seq"] + 1, prev_hash=tip["hash"], tenant_id="acme",
            kid="k1", key=bytes.fromhex(key_hex), task_id="deploy-staging",
            agent_id="rogue", tool="deploy_staging", args={},
            decision="allow", rule_id="x", policy_version=2)
        code, _ = self.svc("POST", "/v1/ingest", foreign)
        self.assertEqual(code, 201)
        # gatekeeper's cached tip is stale -> 422 -> re-sync -> success
        msg = client.call_tool("deploy_staging",
                               {"build": "bb22cc", "env": "staging"})
        self.assertNotIn("error", msg)
        code, resp = self.svc("GET", "/v1/verify?tenant_id=acme")
        # the resynced receipt may still be in flight; poll for the chain
        deadline = time.time() + 15
        while time.time() < deadline:
            code, resp = self.svc("GET", "/v1/verify?tenant_id=acme")
            if code == 200 and resp["chain_ok"] and \
                    resp["receipts"] >= tip["seq"] + 2:
                break
            time.sleep(0.2)
        self.assertTrue(resp["chain_ok"], resp["failures"])
        code, rows = self.svc(
            "GET", "/v1/receipts?tenant_id=acme&order=asc&limit=500")
        seqs = [r["seq"] for r in rows["items"]]
        self.assertEqual(seqs, list(range(1, seqs[-1] + 1)))  # contiguous


class FakeRegistry:
    """Minimal key resolver for ReceiptLog.verify (reads tenants.json)."""

    def __init__(self, path):
        self.path = path

    def _tenants(self):
        return json.load(open(self.path, encoding="utf-8"))["tenants"]

    def signing_key(self, tenant_id):
        t = self._tenants()[tenant_id]
        return t["current_kid"], bytes.fromhex(t["keys"][t["current_kid"]])

    def verification_keys(self, tenant_id):
        t = self._tenants()[tenant_id]
        return {k: bytes.fromhex(v) for k, v in t["keys"].items()}


class EmitterUnitTest(unittest.TestCase):
    """409/422/5xx mapping of ReceiptEmitter._try_ingest (no gatekeeper)."""

    @classmethod
    def setUpClass(cls):
        # FakeRegistry reads this; GatekeeperIngestTest also creates it, but
        # class order isn't guaranteed, so ensure it exists here too.
        tp = os.path.join(TMP, "tenants.json")
        if not os.path.exists(tp):
            env = dict(os.environ, PYTHONPATH=REPO,
                       GATEKEEPER_TENANTS_PATH=tp)
            subprocess.run(
                [sys.executable, "-m", "gatekeeper.tenants", "create", "acme"],
                cwd=REPO, env=env, check=True, capture_output=True)

    def _server(self, code, body=b"{}", get_hash=None):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class H(BaseHTTPRequestHandler):
            posted = {}

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0) or 0)
                raw = self.rfile.read(length)
                try:
                    H.posted = json.loads(raw or b"{}")
                except ValueError:
                    H.posted = {}
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                # GET /v1/receipts/<seq>?tenant_id= -> stored hash lookup
                payload = json.dumps(
                    {"hash": get_hash(H.posted)}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def _emitter(self, url, log_path):
        reg = FakeRegistry(os.path.join(TMP, "tenants.json"))
        log = ReceiptLog(log_path, reg)
        em = ReceiptEmitter(reg, log, svc_url=url, svc_token="t",
                            flush_interval=3600)
        em.close()  # no background flushing in unit tests
        return em, log

    def _fields(self):
        return dict(tenant_id="acme", task_id="t", agent_id="a", tool="x",
                    args={}, decision="allow")

    def test_409_reports_duplicate(self):
        srv = self._server(409, b'{"error":"duplicate_seq"}')
        try:
            em, _ = self._emitter(
                f"http://127.0.0.1:{srv.socket.getsockname()[1]}",
                os.path.join(TMP, "u1.jsonl"))
            self.assertEqual(em._try_ingest({"seq": 1}), "duplicate")
        finally:
            srv.shutdown()

    def test_duplicate_identical_is_success(self):
        # 409 + stored hash == ours -> retried success, no local fallback
        srv = self._server(409, b'{"error":"duplicate_seq"}',
                           get_hash=lambda posted: posted.get("hash"))
        try:
            em, log = self._emitter(
                f"http://127.0.0.1:{srv.socket.getsockname()[1]}",
                os.path.join(TMP, "u2.jsonl"))
            out = em.emit(**self._fields())
            self.assertNotIn("local_fallback", out)
            self.assertEqual(em.spooled("acme"), 0)
            self.assertFalse(os.path.exists(log.path))
        finally:
            srv.shutdown()

    def test_duplicate_other_writer_spools(self):
        # 409 + stored hash != ours -> another writer won the seq; the
        # decision is spooled for a fresh seq (local file has it)
        srv = self._server(409, b'{"error":"duplicate_seq"}',
                           get_hash=lambda posted: "not-our-hash")
        try:
            em, log = self._emitter(
                f"http://127.0.0.1:{srv.socket.getsockname()[1]}",
                os.path.join(TMP, "u3.jsonl"))
            out = em.emit(**self._fields())
            self.assertTrue(out.get("local_fallback"))
            self.assertEqual(em.spooled("acme"), 1)
            ok, failures = log.verify()
            self.assertTrue(ok, failures)
        finally:
            srv.shutdown()

    def test_422_chain_break(self):
        srv = self._server(422, json.dumps(
            {"error": "chain_break", "expected_prev_hash": "abc"}).encode())
        try:
            em, _ = self._emitter(
                f"http://127.0.0.1:{srv.socket.getsockname()[1]}",
                os.path.join(TMP, "u4.jsonl"))
            self.assertEqual(em._try_ingest({"seq": 1}), "chain_break")
        finally:
            srv.shutdown()

    def test_500_and_unreachable_are_failed(self):
        srv = self._server(500, b"{}")
        try:
            em, _ = self._emitter(
                f"http://127.0.0.1:{srv.socket.getsockname()[1]}",
                os.path.join(TMP, "u5.jsonl"))
            self.assertEqual(em._try_ingest({"seq": 1}), "failed")
        finally:
            srv.shutdown()
        em, _ = self._emitter("http://127.0.0.1:9",  # dead port
                              os.path.join(TMP, "u6.jsonl"))
        self.assertEqual(em._try_ingest({"seq": 1}), "failed")


if __name__ == "__main__":
    unittest.main()
