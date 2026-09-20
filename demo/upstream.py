"""Fake upstream MCP tool server (the thing the agent WANTS to reach).

Exposes: read_file, run_tests, deploy_staging, delete_database.
The gatekeeper sits in front of this; the agent never talks to it directly.

Run: python3 demo/upstream.py  (listens on 9001)
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

TOOLS = {
    "read_file": "read a file from the workspace",
    "run_tests": "run the test suite",
    "deploy_staging": "deploy the current build to staging",
    "delete_database": "DROP the production database (destructive!)",
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(length) or b"{}")
        method = req.get("method", "")
        req_id = req.get("id")
        if method == "tools/list":
            return self._send(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": [{"name": n, "description": d} for n, d in TOOLS.items()]
                    },
                }
            )
        if method == "tools/call":
            name = (req.get("params") or {}).get("name", "")
            args = (req.get("params") or {}).get("arguments", {})
            # NOTE: this server trusts its caller completely.
            # In production the gatekeeper is the only caller.
            result = f"EXECUTED {name} with {json.dumps(args)}"
            print(f"[UPSTREAM] {result}")
            return self._send(
                {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": result}]}}
            )
        return self._send(
            {"jsonrpc": "2.0", "id": req_id, "result": {"ok": True, "server": "fake-mcp"}}
        )

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("fake upstream MCP server on :9001")
    HTTPServer(("127.0.0.1", 9001), Handler).serve_forever()
