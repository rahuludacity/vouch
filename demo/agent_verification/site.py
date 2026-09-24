"""Demo site: "Smallville Permit Office" — a small-business-style form page
fronted by the Vouch verified-agent gateway.

Three lanes:
  human lane          GET / serves the HTML form; POST /submit (a plain
                      browser form post, no credential) is processed
                      UNCHANGED — the verifier is never consulted.
  verified-agent lane POST /agent-submit with {credential, action, nonce,
                      ts, agent_signature} -> the site asks the verifier
                      (POST /v1/verify). allow -> the submission is
                      processed fast, and the decision lands in the
                      transparency log as a signed, hash-chained verification record.
  unverified lane     missing/invalid credential -> 429 + a challenge URL.
                      This is the status-quo path (CAPTCHA / proof-of-work
                      stand-in): bots get stuck here instead of eating the
                      form. Humans who complete the challenge get a
                      one-time pass.

The point of the demo: "verify the agent, don't detect the bot."

Env:
    SITE_PORT      default 9011
    VOUCH_BIND     default 127.0.0.1
    VERIFIER_URL   default http://127.0.0.1:9005
    SITE_SUBMISSIONS_PATH  where accepted submissions are appended (jsonl)

Run: python3 demo/agent_verification/site.py
"""
import html
import json
import os
import secrets
import sys
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, REPO)

BIND = os.environ.get("VOUCH_BIND", "127.0.0.1")
PORT = int(os.environ.get("SITE_PORT", "9011"))
VERIFIER_URL = os.environ.get("VERIFIER_URL",
                              "http://127.0.0.1:9005").rstrip("/")
SUBMISSIONS_PATH = os.environ.get("SITE_SUBMISSIONS_PATH", "")

FORM_HTML = """<!doctype html><html><head><title>Smallville Permit Office</title>
<style>body{{font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 16px}}
.lane{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px}}
.human{{background:#e6f4ea;color:#137333}}.agent{{background:#e8f0fe;color:#1a73e8}}
.unverified{{background:#fce8e6;color:#a50e0e}}</style></head>
<body>
<h1>Smallville Permit Office</h1>
<p>File a permit request. Humans use this form directly; <b>verified agents</b>
submit through the agent gateway with a signed credential.</p>
<form method="post" action="/submit">
<label>Name <input name="name" required></label><br><br>
<label>Permit type <input name="permit" required></label><br><br>
<button type="submit">File request (human lane)</button>
</form>
<p><small>Agent endpoint: <code>POST /agent-submit</code> (JSON)</small></p>
</body></html>"""

CHALLENGE_HTML = """<!doctype html><html><head><title>Challenge required</title></head>
<body style="font-family:sans-serif;max-width:640px;margin:40px auto">
<h1>Are you human?</h1>
<p>This is the status-quo challenge path (stand-in for CAPTCHA / proof of
work). Unverified automated traffic lands here instead of reaching the form.</p>
<form method="post" action="/challenge/{token}">
<input type="hidden" name="token" value="{token}">
<label><input type="checkbox" name="human" value="1" required>
I am a human filing this request myself</label><br><br>
<button type="submit">Verify and continue</button>
</form></body></html>"""


def _record_submission(entry):
    if SUBMISSIONS_PATH:
        with open(SUBMISSIONS_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")


class GatewayState:
    def __init__(self):
        self.challenges = {}   # token -> True (outstanding)
        self.passes = set()    # one-time challenge passes
        self.lane_counts = {"human": 0, "verified-agent": 0, "unverified": 0}


STATE = GatewayState()


def make_handler(verifier_url):
    class SiteHandler(BaseHTTPRequestHandler):
        server_version = "SmallvilleGateway/1.0"

        def log_message(self, *a):
            pass

        # -- helpers -------------------------------------------------
        def _send(self, code, body, ctype="text/html"):
            if isinstance(body, (dict, list)):
                body = json.dumps(body).encode()
                ctype = "application/json"
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self, limit=1 << 20):
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = 0
            if n <= 0 or n > limit:
                return b""
            return self.rfile.read(n)

        def _ask_verifier(self, payload):
            """POST /v1/verify. Returns (decision_dict | None)."""
            try:
                req = urllib.request.Request(
                    verifier_url + "/v1/verify",
                    data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=10) as r:
                    return json.loads(r.read().decode())
            except Exception:
                return None

        # -- routes --------------------------------------------------
        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._send(200, FORM_HTML)
            elif parsed.path.startswith("/challenge/"):
                token = parsed.path.rsplit("/", 1)[-1]
                if token in STATE.challenges:
                    self._send(200, CHALLENGE_HTML.format(token=token))
                else:
                    self._send(404, "unknown or expired challenge")
            elif parsed.path == "/stats":
                self._send(200, {"lanes": STATE.lane_counts,
                                 "outstanding_challenges":
                                     len(STATE.challenges)})
            else:
                self._send(404, "not found")

        def do_POST(self):
            parsed = urlparse(self.path)
            if parsed.path == "/submit":
                self._human_lane()
            elif parsed.path == "/agent-submit":
                self._agent_lane()
            elif parsed.path.startswith("/challenge/"):
                self._solve_challenge(parsed.path.rsplit("/", 1)[-1])
            else:
                self._send(404, "not found")

        # -- lane 1: human (unchanged, no verification) --------------
        def _human_lane(self):
            fields = parse_qs(self._read_body().decode("utf-8", "replace"))
            name = fields.get("name", ["?"])[0][:80]
            permit = fields.get("permit", ["?"])[0][:80]
            STATE.lane_counts["human"] += 1
            _record_submission({"lane": "human", "name": name,
                                "permit": permit})
            self._send(200, f"""<!doctype html><html><body style="font-family:
sans-serif;max-width:640px;margin:40px auto">
<h1>Request filed</h1>
<p><span class="lane human">human lane</span></p>
<p>Thanks {html.escape(name)} — your <b>{html.escape(permit)}</b> permit
request was accepted. (Humans pass through unchanged; no credential needed.)</p>
</body></html>""")

        # -- lane 2/3: agent gateway --------------------------------
        def _agent_lane(self):
            raw = self._read_body()
            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception:
                payload = {}
            if not isinstance(payload, dict) or "credential" not in payload:
                self._challenge("no agent credential presented")
                return
            payload.setdefault("tenant_id", "smallville")
            decision = self._ask_verifier(payload)
            if decision is None:
                self._send(503, {"error": "verifier_unavailable"})
                return
            if decision.get("decision") == "allow":
                STATE.lane_counts["verified-agent"] += 1
                action = payload.get("action", {})
                _record_submission({
                    "lane": "verified-agent",
                    "agent_id": payload["credential"].get("agent_id"),
                    "action": action.get("type"),
                    "target": action.get("target"),
                    "receipt_seq": decision.get("receipt_seq"),
                    "receipt_hash": decision.get("receipt_hash")})
                self._send(200, {
                    "status": "accepted",
                    "lane": "verified-agent",
                    "receipt_seq": decision.get("receipt_seq"),
                    "receipt_hash": decision.get("receipt_hash"),
                    "message": "verified agent: fast passage — verified action recorded"})
            else:
                self._challenge(
                    f"credential rejected: {decision.get('reason')}")

        def _challenge(self, why):
            STATE.lane_counts["unverified"] += 1
            token = secrets.token_hex(8)
            STATE.challenges[token] = True
            self._send(429, {
                "status": "challenged",
                "lane": "unverified",
                "reason": why,
                "challenge_url": f"/challenge/{token}",
                "message": "unverified traffic must complete the "
                           "status-quo challenge before reaching the form"})

        def _solve_challenge(self, token):
            fields = parse_qs(self._read_body().decode("utf-8", "replace"))
            if (token in STATE.challenges
                    and fields.get("token", [""])[0] == token
                    and fields.get("human", [""])[0] == "1"):
                del STATE.challenges[token]
                STATE.passes.add(token)
                self._send(200, """<!doctype html><html><body style="font-family:
sans-serif;max-width:640px;margin:40px auto">
<h1>Challenge passed</h1>
<p>You may now file your request through the human form.</p>
</body></html>""")
            else:
                self._send(400, "challenge failed")

    return SiteHandler


def main():
    handler = make_handler(VERIFIER_URL)
    server = ThreadingHTTPServer((BIND, PORT), handler)
    print(f"demo site listening on {BIND}:{PORT} "
          f"(verifier: {VERIFIER_URL})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
