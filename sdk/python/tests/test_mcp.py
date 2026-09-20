"""Tests for vouch.mcp — header mapping against a stub gatekeeper."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from vouch.mcp import MCPClient


class Stub(BaseHTTPRequestHandler):
    """Minimal stub: records headers, replays a canned JSON-RPC result."""

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        Stub.last_headers = dict(self.headers)
        body = json.dumps({"jsonrpc": "2.0", "id": 1,
                           "result": {"ok": True}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = _handle

    def log_message(self, *a):
        pass


class TestMCPDeploymentToken(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Stub)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever,
                         daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_deployment_token_sent_as_header(self):
        url = f"http://127.0.0.1:{self.port}/mcp"
        mcp = MCPClient(url, tenant_id="acme", task_id="deploy-staging",
                        agent_id="agent-001",
                        deployment_token="dep_tok_123")
        out = mcp.call_tool("run_tests", {"suite": "unit"})
        self.assertEqual(out, {"ok": True})
        self.assertEqual(Stub.last_headers.get("X-Deployment-Token"),
                         "dep_tok_123")


if __name__ == "__main__":
    unittest.main()
