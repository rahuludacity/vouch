"""Fake upstream MCP tool server (the thing the agent WANTS to reach).

Now speaks MCP Streamable HTTP:
  - POST /mcp with JSON-RPC; answers SSE (`event: message`) when the
    client sends `Accept: text/event-stream`, else a single JSON object
  - `initialize` mints a Mcp-Session-Id, returned as a response header
  - GET /mcp opens a server-push SSE stream (session required)
  - DELETE /mcp terminates the session
  - notifications get 202 + empty body

Exposes: read_file, run_tests, deploy_staging, delete_database.
The gatekeeper sits in front of this; the agent never talks to it directly.

CALLS records every tools/call that actually arrived here — the demo and
tests use it to prove denied calls never reached this server.

Run: python3 demo/upstream.py  (listens on :9001, or $UPSTREAM_PORT)
"""
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("UPSTREAM_PORT", "9001"))

TOOLS = {
    "read_file": "read a file from the workspace",
    "run_tests": "run the test suite",
    "deploy_staging": "deploy the current build to staging",
    "delete_database": "DROP the production database (destructive!)",
}


class Handler(BaseHTTPRequestHandler):
    sessions = set()
    CALLS = []  # tool names that reached this server via tools/call

    server_version = "FakeMCP/1.0"

    # ---------- helpers ----------
    def _wants_sse(self):
        return "text/event-stream" in self.headers.get("Accept", "")

    def _send_json(self, obj, code=200, session_id=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if session_id:
            self.send_header("Mcp-Session-Id", session_id)
        self.end_headers()
        self.wfile.write(body)

    def _send_sse(self, messages, code=200, session_id=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        if session_id:
            self.send_header("Mcp-Session-Id", session_id)
        self.end_headers()
        for m in messages:
            self.wfile.write(f"event: message\ndata: {json.dumps(m)}\n\n".encode())
        self.wfile.flush()

    def _reply(self, msg, session_id=None):
        if self._wants_sse():
            self._send_sse([msg], session_id=session_id)
        else:
            self._send_json(msg, session_id=session_id)

    def _session_ok(self):
        sid = self.headers.get("Mcp-Session-Id")
        return sid if sid in self.sessions else None

    # ---------- verbs ----------
    def do_POST(self):
        if self.path != "/mcp":
            return self._send_json({"error": "not found"}, 404)
        length = int(self.headers.get("Content-Length", 0) or 0)
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self._send_json({"error": "invalid json"}, 400)

        method = req.get("method", "")
        req_id = req.get("id")

        if "method" in req and "id" not in req:
            # notification: 202, no body
            self.send_response(202)
            self.end_headers()
            return

        if method == "initialize":
            sid = "sess-" + secrets.token_hex(8)
            self.sessions.add(sid)
            print(f"[UPSTREAM] new session {sid}")
            return self._reply(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fake-mcp", "version": "0.1"},
                    },
                },
                session_id=sid,
            )

        sid = self._session_ok()
        if sid is None and method not in ("initialize",):
            return self._send_json(
                {"jsonrpc": "2.0", "id": req_id,
                 "error": {"code": -32001, "message": "unknown session"}},
                404,
            )

        if method == "tools/list":
            return self._reply(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": [
                            {"name": n, "description": d} for n, d in TOOLS.items()
                        ]
                    },
                },
                session_id=sid,
            )
        if method == "tools/call":
            name = (req.get("params") or {}).get("name", "")
            args = (req.get("params") or {}).get("arguments", {})
            self.CALLS.append(name)
            result = f"EXECUTED {name} with {json.dumps(args)}"
            print(f"[UPSTREAM] {result}")
            return self._reply(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": result}]},
                },
                session_id=sid,
            )
        return self._reply(
            {"jsonrpc": "2.0", "id": req_id,
             "result": {"ok": True, "server": "fake-mcp"}},
            session_id=sid,
        )

    def do_GET(self):
        if self.path != "/mcp":
            return self._send_json({"error": "not found"}, 404)
        sid = self._session_ok()
        if sid is None:
            return self._send_json({"error": "unknown session"}, 404)
        # Server-push stream: one heartbeat event, then close (demo).
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Mcp-Session-Id", sid)
        self.end_headers()
        self.wfile.write(b": stream open\n\n")
        self.wfile.write(
            b'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/ping"}\n\n'
        )
        self.wfile.flush()

    def do_DELETE(self):
        if self.path != "/mcp":
            return self._send_json({"error": "not found"}, 404)
        sid = self.headers.get("Mcp-Session-Id")
        if sid not in self.sessions:
            return self._send_json({"error": "unknown session"}, 404)
        self.sessions.discard(sid)
        print(f"[UPSTREAM] session {sid} terminated")
        self.send_response(202)
        self.end_headers()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"fake upstream MCP server (Streamable HTTP) on :{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
