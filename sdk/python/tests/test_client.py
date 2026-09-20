"""Tests for vouch.client — request/response mapping against a stub server."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from vouch.client import VouchClient, VouchError


class Stub(BaseHTTPRequestHandler):
    """Minimal stub: records the request, replays canned JSON."""

    def _reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        Stub.last = {
            "method": self.command,
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "body": json.loads(raw) if raw else None,
        }
        path = self.path.split("?")[0]
        routes = {
            ("POST", "/v1/tenants"): (200, {"tenant_id": "acme",
                                           "api_key": "vouch_sk_abc",
                                           "plan": "free"}),
            ("GET", "/v1/tenants/me"): (200, {"tenant_id": "acme",
                                             "plan": "pro",
                                             "status": "active"}),
            ("PUT", "/v1/policies/t1"): (200, {"task_id": "t1", "version": 4}),
            ("GET", "/v1/receipts"): (200, {"items": [], "next_cursor": None}),
            ("GET", "/v1/verify"): (200, {"tenant_id": "acme", "receipts": 0,
                                         "chain_ok": True, "failures": []}),
            ("POST", "/v1/deployments"): (200, {"deployment_id": "dep_1",
                                              "status": "pending"}),
            ("POST", "/v1/billing/checkout"): (200, {"checkout_url": "https://x",
                                                   "session_id": "cs_1",
                                                   "test_mode": True}),
            ("PUT", "/v1/policies/bad"): (422, {"error": "invalid_policy",
                                              "message": "unknown op"}),
        }
        code, obj = routes.get((self.command, path),
                               (404, {"error": "not_found"}))
        self._reply(code, obj)

    do_GET = do_POST = do_PUT = do_DELETE = _handle

    def log_message(self, *a):
        pass


class TestClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Stub)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever,
                                      daemon=True)
        cls.thread.start()
        base = f"http://127.0.0.1:{cls.port}"
        cls.c = VouchClient("vouch_sk_test", control_plane_url=base,
                            receipt_service_url=base, billing_url=base)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_provision(self):
        base = f"http://127.0.0.1:{self.port}"
        client, tid, key = VouchClient.provision("acme",
                                                control_plane_url=base)
        self.assertEqual(tid, "acme")
        self.assertEqual(key, "vouch_sk_abc")
        self.assertEqual(Stub.last["body"], {"name": "acme"})
        self.assertIsNone(Stub.last["auth"])  # provisioning is unauthenticated

    def test_me_bearer(self):
        me = self.c.me()
        self.assertEqual(me["tenant_id"], "acme")
        self.assertEqual(Stub.last["auth"], "Bearer vouch_sk_test")

    def test_put_policy(self):
        out = self.c.put_policy("t1", {"allow": [], "deny": []})
        self.assertEqual(out["version"], 4)
        self.assertEqual(Stub.last["path"], "/v1/policies/t1")

    def test_error_mapping(self):
        with self.assertRaises(VouchError) as ctx:
            self.c.put_policy("bad", {"allow": [], "deny": []})
        self.assertEqual(ctx.exception.status, 422)
        self.assertEqual(ctx.exception.code, "invalid_policy")

    def test_receipts_go_to_receipt_service(self):
        self.c.receipts(limit=10)
        self.assertTrue(Stub.last["path"].startswith("/v1/receipts"))
        self.assertIn("limit=10", Stub.last["path"])

    def test_verify(self):
        out = self.c.verify()
        self.assertTrue(out["chain_ok"])

    def test_deploy_agent(self):
        dep = self.c.deploy_agent("t1", "vouch/agent-demo:latest")
        self.assertEqual(dep["deployment_id"], "dep_1")
        self.assertEqual(Stub.last["body"]["task_id"], "t1")

    def test_checkout_hits_billing(self):
        out = self.c.checkout("pro")
        self.assertTrue(out["test_mode"])
        self.assertEqual(Stub.last["body"], {"plan": "pro"})


if __name__ == "__main__":
    unittest.main()
