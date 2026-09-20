"""Tests for the v1 MCP Streamable HTTP transport.

Spins up the real demo upstream and the real gatekeeper on ephemeral
ports (in-process, threaded) and drives them as an MCP client would:
initialize handshake, session relay, SSE/JSON negotiation, tools/call
gating, GET streams, DELETE termination.
"""
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "demo"))

TMP = tempfile.mkdtemp(prefix="vouch-transport-")

import upstream as upmod  # noqa: E402  (demo/upstream.py, no env needed)

UP = ThreadingHTTPServer(("127.0.0.1", 0), upmod.Handler)
UP_PORT = UP.socket.getsockname()[1]
threading.Thread(target=UP.serve_forever, daemon=True).start()

os.environ["GATEKEEPER_UPSTREAM"] = f"http://127.0.0.1:{UP_PORT}/mcp"
os.environ["GATEKEEPER_TENANTS_PATH"] = os.path.join(TMP, "tenants.json")
os.environ["GATEKEEPER_RECEIPTS_PATH"] = os.path.join(TMP, "receipts.jsonl")

from gatekeeper import proxy  # noqa: E402  (reads env above at import)
from gatekeeper.receipts import ReceiptLog  # noqa: E402

GK = ThreadingHTTPServer(("127.0.0.1", 0), proxy.Handler)
GK_PORT = GK.socket.getsockname()[1]
GK_URL = f"http://127.0.0.1:{GK_PORT}/mcp"
threading.Thread(target=GK.serve_forever, daemon=True).start()

proxy.Handler.registry.create("acme")
proxy.Handler.registry.create("globex")


def parse_sse(raw):
    text = raw.decode("utf-8", errors="replace")
    out = []
    for block in text.split("\n\n"):
        data = "\n".join(
            ln[5:].strip() for ln in block.splitlines() if ln.startswith("data:")
        ).strip()
        if not data or data == "[DONE]":
            continue
        try:
            out.append(json.loads(data))
        except json.JSONDecodeError:
            pass
    return out


def raw_request(method, body=None, headers=None):
    req = urllib.request.Request(
        GK_URL, data=body, headers=headers or {}, method=method
    )
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def post(msg, tenant="acme", task="deploy-staging", agent="agent-001",
         session=None, accept="application/json, text/event-stream"):
    headers = {
        "Content-Type": "application/json",
        "Accept": accept,
        "X-Task-Id": task,
        "X-Agent-Id": agent,
    }
    if tenant is not None:
        headers["X-Tenant-Id"] = tenant
    if session:
        headers["Mcp-Session-Id"] = session
    status, rheaders, body = raw_request(
        "POST", json.dumps(msg).encode(), headers
    )
    ctype = rheaders.get("Content-Type", "")
    if "text/event-stream" in ctype:
        msgs = parse_sse(body)
    elif body:
        msgs = [json.loads(body)]
    else:
        msgs = []
    return status, rheaders, msgs


class TransportTest(unittest.TestCase):
    _ids = 0

    @classmethod
    def next_id(cls):
        cls._ids += 1
        return cls._ids

    def setUp(self):
        upmod.Handler.CALLS.clear()
        with proxy.Handler.sessions_lock:
            proxy.Handler.sessions.clear()

    def initialize(self, tenant="acme", accept="application/json, text/event-stream"):
        status, headers, msgs = post(
            {"jsonrpc": "2.0", "id": self.next_id(), "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "t", "version": "0"}}},
            tenant=tenant, accept=accept,
        )
        self.assertEqual(status, 200)
        session = headers.get("Mcp-Session-Id")
        self.assertTrue(session, "initialize must return Mcp-Session-Id")
        # initialized notification -> 202, empty
        notif_headers = {"Content-Type": "application/json",
                         "Accept": "application/json, text/event-stream",
                         "Mcp-Session-Id": session}
        if tenant is not None:
            notif_headers["X-Tenant-Id"] = tenant
        status, _, _ = raw_request(
            "POST",
            json.dumps({"jsonrpc": "2.0",
                        "method": "notifications/initialized"}).encode(),
            notif_headers,
        )
        self.assertEqual(status, 202)
        return session, msgs

    # ---- handshake & content negotiation ----
    def test_initialize_sse_handshake(self):
        session, msgs = self.initialize()
        self.assertTrue(session.startswith("sess-"))
        self.assertEqual(msgs[0]["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(msgs[0]["result"]["serverInfo"]["name"], "fake-mcp")

    def test_initialize_json_accept(self):
        session, msgs = self.initialize(accept="application/json")
        self.assertTrue(session)
        self.assertEqual(msgs[0]["result"]["protocolVersion"], "2025-06-18")

    def test_notification_returns_202_empty(self):
        session, _ = self.initialize()
        status, _, body = raw_request(
            "POST", json.dumps({"jsonrpc": "2.0", "method": "ping"}).encode(),
            {"Content-Type": "application/json",
             "Accept": "application/json, text/event-stream",
             "X-Tenant-Id": "acme", "Mcp-Session-Id": session},
        )
        self.assertEqual(status, 202)
        self.assertEqual(body, b"")

    # ---- tools ----
    def test_tools_list_passthrough(self):
        session, _ = self.initialize()
        status, _, msgs = post(
            {"jsonrpc": "2.0", "id": self.next_id(), "method": "tools/list"},
            session=session,
        )
        self.assertEqual(status, 200)
        names = [t["name"] for t in msgs[0]["result"]["tools"]]
        self.assertIn("delete_database", names)  # unfiltered: true passthrough

    def test_tools_call_allowed(self):
        session, _ = self.initialize()
        status, _, msgs = post(
            {"jsonrpc": "2.0", "id": self.next_id(), "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"path": "app.py"}}},
            session=session,
        )
        self.assertEqual(status, 200)
        self.assertIn("EXECUTED read_file", msgs[0]["result"]["content"][0]["text"])
        self.assertIn("read_file", upmod.Handler.CALLS)
        log = ReceiptLog(os.environ["GATEKEEPER_RECEIPTS_PATH"],
                         proxy.Handler.registry)
        ok, failures = log.verify()
        self.assertTrue(ok, failures)
        last = [json.loads(l) for l in
                open(os.environ["GATEKEEPER_RECEIPTS_PATH"])][-1]
        self.assertEqual(last["decision"], "allow")
        self.assertEqual(last["tenant_id"], "acme")
        self.assertEqual(last["tool"], "read_file")

    def test_tools_call_denied_never_reaches_upstream(self):
        session, _ = self.initialize()
        status, _, msgs = post(
            {"jsonrpc": "2.0", "id": self.next_id(), "method": "tools/call",
             "params": {"name": "delete_database", "arguments": {"target": "prod"}}},
            session=session,
        )
        self.assertEqual(status, 200)  # JSON-RPC error still rides HTTP 200
        self.assertEqual(msgs[0]["error"]["code"], -32000)
        self.assertIn("policy denied", msgs[0]["error"]["message"])
        self.assertNotIn("delete_database", upmod.Handler.CALLS)
        last = [json.loads(l) for l in
                open(os.environ["GATEKEEPER_RECEIPTS_PATH"])][-1]
        self.assertEqual(last["decision"], "deny")
        self.assertEqual(last["tenant_id"], "acme")

    def test_denied_over_json_accept(self):
        session, _ = self.initialize(accept="application/json")
        status, headers, msgs = post(
            {"jsonrpc": "2.0", "id": self.next_id(), "method": "tools/call",
             "params": {"name": "delete_database", "arguments": {}}},
            session=session, accept="application/json",
        )
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers.get("Content-Type", ""))
        self.assertIn("policy denied", msgs[0]["error"]["message"])

    # ---- tenants ----
    def test_unknown_tenant_rejected(self):
        status, _, body = raw_request(
            "POST", json.dumps({"jsonrpc": "2.0", "id": 1,
                                "method": "tools/list"}).encode(),
            {"Content-Type": "application/json",
             "Accept": "application/json, text/event-stream",
             "X-Tenant-Id": "nope"},
        )
        self.assertEqual(status, 403)
        self.assertIn("unknown tenant", body.decode())

    def test_session_binds_tenant(self):
        session, _ = self.initialize(tenant="globex")
        # no X-Tenant-Id on purpose: the session binding must attribute it
        status, _, msgs = post(
            {"jsonrpc": "2.0", "id": self.next_id(), "method": "tools/call",
             "params": {"name": "read_file", "arguments": {}}},
            tenant=None, session=session,
        )
        self.assertEqual(status, 200)
        last = [json.loads(l) for l in
                open(os.environ["GATEKEEPER_RECEIPTS_PATH"])][-1]
        self.assertEqual(last["tenant_id"], "globex")

    def test_default_tenant_when_no_header(self):
        session, _ = self.initialize(tenant=None)
        status, _, _ = post(
            {"jsonrpc": "2.0", "id": self.next_id(), "method": "tools/call",
             "params": {"name": "read_file", "arguments": {}}},
            tenant=None, session=session,
        )
        self.assertEqual(status, 200)
        last = [json.loads(l) for l in
                open(os.environ["GATEKEEPER_RECEIPTS_PATH"])][-1]
        self.assertEqual(last["tenant_id"], "default")

    # ---- GET / DELETE ----
    def test_get_sse_stream(self):
        session, _ = self.initialize()
        status, headers, body = raw_request(
            "GET", None,
            {"Accept": "text/event-stream", "X-Tenant-Id": "acme",
             "Mcp-Session-Id": session},
        )
        self.assertEqual(status, 200)
        self.assertIn("text/event-stream", headers.get("Content-Type", ""))
        self.assertIn(b"event: message", body)

    def test_get_without_session_is_400(self):
        status, _, _ = raw_request(
            "GET", None,
            {"Accept": "text/event-stream", "X-Tenant-Id": "acme"},
        )
        self.assertEqual(status, 400)

    def test_delete_terminates_session(self):
        session, _ = self.initialize()
        status, _, _ = raw_request(
            "DELETE", None,
            {"X-Tenant-Id": "acme", "Mcp-Session-Id": session},
        )
        self.assertEqual(status, 202)
        # session is gone upstream now: relayed 404
        status, _, _ = raw_request(
            "GET", None,
            {"Accept": "text/event-stream", "X-Tenant-Id": "acme",
             "Mcp-Session-Id": session},
        )
        self.assertEqual(status, 404)

    def test_unknown_path_404(self):
        req = urllib.request.Request(
            GK_URL.replace("/mcp", "/nope"), data=b"{}",
            headers={"Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(cm.exception.code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
