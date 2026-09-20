"""Vouch dashboard (:3000) — web UI + JSON APIs (Phase 4, §2.6).

Talks ONLY to the control plane and receipt service REST APIs, using the
tenant API key (`vouch_sk_*`, §8) as the single credential. No new upstream
endpoints are invented: every screen below maps onto a frozen §4 contract.

Auth scheme (simplest secure option consistent with §8):
  * The tenant API key is the credential. The browser never holds it in
    JS-accessible state: on login the dashboard validates the key against
    control-plane `GET /v1/tenants/me`, then mints a random 256-bit session
    id stored in an HttpOnly, SameSite=Lax cookie. The key itself lives
    only in the dashboard's in-memory session map (12h TTL).
  * If `DASHBOARD_API_KEY` is set, the dashboard runs in single-operator
    mode and skips login entirely (local/dev + tests).
  * State-changing requests (HTML forms and JSON) carry a per-session CSRF
    token (hidden form field / `X-CSRF-Token` header).
  * Key plaintext is never rendered: key creation shows the new key once
    on the confirmation screen (the frozen `POST /v1/api-keys` contract),
    and it is never stored server-side beyond that response.
  * Signing keys (HMAC key material) never appear anywhere — `rotate-keys`
    returns only the new `kid`, per §4.5 and hard constraint §10.5.

Pages (server-rendered HTML, no JS framework):
  GET /                 -> redirect to /overview (or /login)
  GET /login            login form            POST /login  (api_key=)
  POST /logout
  GET /overview         tenant card + usage fan-in + counts
  GET /receipts         chain explorer: filters + table + verify banner
  GET /receipts/<seq>   receipt detail
  GET /policies         viewer + editor (writes v2 schema, §5)
  GET /deployments      list + create + stop
  GET /keys             named keys: list/create/revoke + signing-key rotation

JSON APIs (same session auth; state-changing needs X-CSRF-Token):
  GET  /api/overview
  GET  /api/receipts[?task_id=&tool=&decision=&agent_id=&limit=&cursor=]
  GET  /api/receipts/<seq>
  GET  /api/verify                       -> receipt-service GET /v1/verify
  GET  /api/receipts/stream              -> SSE relay of /v1/receipts/stream
  GET  /api/policies                     PUT /api/policies/<task>
  DELETE /api/policies/<task>
  GET  /api/deployments  POST /api/deployments
  GET  /api/deployments/<id>  DELETE /api/deployments/<id>
  GET  /api/keys  POST /api/keys  DELETE /api/keys/<id>
  POST /api/keys/rotate-signing          -> control-plane rotate-keys
  POST /api/session {"api_key": ...}      DELETE /api/session
  GET  /api/csrf

Contract gaps (documented, worked around — no frozen contract changed):
  G1. No tenant-facing monthly usage HISTORY endpoint exists (§4.5 has only
      the current-month fan-in on GET /v1/tenants/me; /internal/usage is
      service-token-only). The usage view shows the current month only.
  G2. No tenant-facing deployment LOGS endpoint exists. The deployments page
      shows status/heartbeat/container_id only.

Run:  python3 -m web.dashboard.app
Env:  DASHBOARD_PORT   (default 3000)
      CONTROLPLANE_URL (default http://127.0.0.1:9002)
      RECEIPT_SVC_URL  (default http://127.0.0.1:9001)
      DASHBOARD_API_KEY (optional: single-operator mode, skips login)
      DASHBOARD_SESSION_TTL (seconds, default 43200 = 12h)
"""
import html
import json
import os
import secrets
import threading
import time
import urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .upstream import fwd, UpstreamError

PORT = int(os.environ.get("DASHBOARD_PORT", "3000"))
CONTROLPLANE_URL = os.environ.get("CONTROLPLANE_URL",
                                  "http://127.0.0.1:9002").rstrip("/")
RECEIPT_SVC_URL = os.environ.get("RECEIPT_SVC_URL",
                                 "http://127.0.0.1:9001").rstrip("/")
OPERATOR_KEY = os.environ.get("DASHBOARD_API_KEY", "")
SESSION_TTL = int(os.environ.get("DASHBOARD_SESSION_TTL", "43200"))
SESSION_COOKIE = "vouch_dash_session"
# Secure-cookie policy: "1" forces the Secure attribute, "0" disables it,
# "auto" (default) adds Secure only when the request arrives over TLS
# (X-Forwarded-Proto: https behind a reverse proxy). Set to "1" whenever
# the dashboard is served over HTTPS.
SECURE_COOKIE = os.environ.get("VOUCH_SECURE_COOKIE", "auto")

_sessions = {}          # session_id -> {"api_key": str, "csrf": str, "exp": float}
_sessions_lock = threading.Lock()


def _new_session(api_key):
    sid = secrets.token_hex(32)
    with _sessions_lock:
        _sessions[sid] = {"api_key": api_key,
                          "csrf": secrets.token_hex(16),
                          "exp": time.time() + SESSION_TTL}
    return sid


def _get_session(sid):
    if not sid:
        return None
    with _sessions_lock:
        s = _sessions.get(sid)
        if s is None:
            return None
        if s["exp"] < time.time():
            del _sessions[sid]
            return None
        return s


def _drop_session(sid):
    with _sessions_lock:
        _sessions.pop(sid, None)


def _sweep_expired_sessions():
    """Remove expired sessions so abandoned logins never accumulate."""
    now = time.time()
    with _sessions_lock:
        dead = [sid for sid, s in _sessions.items() if s["exp"] < now]
        for sid in dead:
            del _sessions[sid]
    return len(dead)


def _session_sweeper(interval=600.0):
    """Background sweep for expired dashboard sessions (L-2)."""
    while True:
        time.sleep(interval)
        try:
            _sweep_expired_sessions()
        except Exception:
            pass


def esc(v):
    return html.escape("" if v is None else str(v), quote=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "VouchDashboard/1.0"

    # ------------------------------------------------------------ plumbing
    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _err(self, code, error, message=""):
        self._send(code, {"error": error, "message": message or error})

    def _send_html(self, code, body, headers=None):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _redirect(self, where, cookie=None):
        self.send_response(303)
        self.send_header("Location", where)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _path(self):
        u = urlparse(self.path)
        return u.path, {k: v[0] for k, v in parse_qs(u.query).items()}

    # M-2: single cap helper — every caller gets 400/413 before allocating.
    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            return "BAD_LENGTH"
        if length > 1_000_000:
            return "TOO_LARGE"
        return self.rfile.read(length) if length else b""

    def _read_json(self):
        raw = self._read_body()
        if raw in ("BAD_LENGTH", "TOO_LARGE"):
            return raw
        if not raw:
            return {}
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return "INVALID"
        return body if isinstance(body, dict) else "INVALID"

    def _read_form(self):
        raw = self._read_body()
        if raw in ("BAD_LENGTH", "TOO_LARGE"):
            return raw
        raw = raw.decode("utf-8", "replace") if raw else ""
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def log_message(self, *a):  # quieter logs
        pass

    # ---------------------------------------------------------------- auth
    def _cookie_sid(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        m = c.get(SESSION_COOKIE)
        return m.value if m else ""

    def _api_key(self):
        """Operator's tenant key for this request, or None (needs login)."""
        if OPERATOR_KEY:
            return OPERATOR_KEY
        s = _get_session(self._cookie_sid())
        return s["api_key"] if s else None

    def _session(self):
        if OPERATOR_KEY:
            return {"api_key": OPERATOR_KEY, "csrf": "operator-mode", "exp": 0}
        return _get_session(self._cookie_sid())

    def _csrf_ok(self):
        """State-changing requests need the per-session CSRF token."""
        s = self._session()
        if s is None:
            return False
        if OPERATOR_KEY:
            return True  # single-operator local mode: cookie auth absent
        if self.headers.get("X-CSRF-Token", "") == s["csrf"]:
            return True
        # HTML forms carry it as a field instead
        return False

    def _require_key_html(self):
        key = self._api_key()
        if key is None:
            self._redirect("/login")
            return None
        return key

    def _require_key_json(self):
        key = self._api_key()
        if key is None:
            self._err(401, "unauthorized", "login required")
            return None
        return key

    def _validate_key(self, key):
        """Check a candidate API key against the control plane. Returns
        (tenant_id, name) or None. Never raises."""
        try:
            status, data = fwd("GET", CONTROLPLANE_URL, "/v1/tenants/me",
                               key, timeout=10)
        except UpstreamError:
            return None
        if status == 200 and isinstance(data, dict) and data.get("tenant_id"):
            return data["tenant_id"], data.get("name", "")
        return None

    # ------------------------------------------------------------- chrome
    def _secure_cookie_suffix(self):
        # TLS-controlled Secure flag: force with VOUCH_SECURE_COOKIE=1, or
        # auto-add when the request arrived over TLS (behind a proxy).
        if SECURE_COOKIE == "1":
            return "; Secure"
        if SECURE_COOKIE == "auto" and \
                self.headers.get("X-Forwarded-Proto", "") == "https":
            return "; Secure"
        return ""

    def _nav(self, active, csrf=""):
        items = [("overview", "Overview"), ("receipts", "Receipts"),
                 ("policies", "Policies"), ("deployments", "Deployments"),
                 ("keys", "API Keys")]
        links = " ".join(
            f'<a href="/{p}" class="{ "on" if p == active else ""}">{t}</a>'
            for p, t in items)
        # L-2: logout is a state-changing POST — carry the CSRF token so a
        # cross-site form cannot log the operator out (logout CSRF).
        csrf_field = (f'<input type="hidden" name="csrf_token" value="{csrf}">'
                      if csrf else "")
        return (f'<nav>{links}'
                f'<form method="post" action="/logout" style="display:inline">'
                f'{csrf_field}'
                f'<button type="submit" class="linklike">log out</button>'
                f"</form></nav>")

    def _page_csrf(self):
        """CSRF token for forms rendered in the page chrome (L-2 logout)."""
        if OPERATOR_KEY:
            return ""
        s = _get_session(self._cookie_sid())
        return s["csrf"] if s else ""

    def _page(self, title, active, inner):
        return f"""<!doctype html><html><head><meta charset="utf-8">
<title>{esc(title)} — Vouch</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1100px;margin:24px auto;
padding:0 16px;color:#1a1a1a}}
nav{{margin-bottom:20px;border-bottom:1px solid #ddd;padding-bottom:10px}}
nav a{{margin-right:14px;text-decoration:none;color:#444}}
nav a.on{{font-weight:700;color:#000}}
table{{border-collapse:collapse;width:100%;margin:12px 0}}
th,td{{border:1px solid #ddd;padding:6px 10px;text-align:left;font-size:14px}}
th{{background:#f5f5f5}}
.allow{{color:#0a7d2c;font-weight:600}} .deny{{color:#c00;font-weight:600}}
.card{{border:1px solid #ddd;border-radius:8px;padding:14px 18px;margin:12px 0;
background:#fafafa}}
.ok{{background:#e8f7ee;border-color:#0a7d2c}} .bad{{background:#fdecec;
border-color:#c00}}
form.inline{{display:inline}}
button,.btn{{padding:6px 12px;margin:4px 2px;cursor:pointer}}
.linklike{{background:none;border:none;color:#444;text-decoration:underline;
cursor:pointer;font-size:14px;padding:0;margin-left:14px}}
input,select,textarea{{padding:6px;margin:4px 2px;font-size:14px}}
textarea{{width:100%;font-family:monospace}}
code{{background:#f0f0f0;padding:1px 5px;border-radius:3px;font-size:13px}}
pre{{background:#f6f6f6;padding:10px;border-radius:6px;overflow-x:auto;
font-size:13px}}
.muted{{color:#777;font-size:13px}}
.banner{{border:1px solid;border-radius:8px;padding:10px 14px;margin:12px 0}}
</style></head><body>
<h1>Vouch <span class="muted">governed agent deployment, with proof</span></h1>
{self._nav(active, csrf=self._page_csrf()) if active else ""}
{inner}
</body></html>"""

    # ------------------------------------------------------- upstream glue
    def _up(self, method, base, path, key, body=None, params=None):
        """Forward to an upstream service; returns (status, data).

        Renders 502 upstream_unavailable as an HTML banner instead of
        raising — the dashboard is observability, never the enforcement
        path (§1 trust boundary).
        """
        try:
            return fwd(method, base, path, key, body=body, params=params)
        except UpstreamError as e:
            return e.status, e.payload

    def _up_err_html(self, data):
        msg = (data.get("message") or data.get("error")
               if isinstance(data, dict) else str(data))
        return f'<div class="banner bad"><b>Upstream error:</b> {esc(msg)}</div>'

    # ---------------------------------------------------------------- login
    def _login_page(self, error=""):
        err = f'<div class="banner bad">{esc(error)}</div>' if error else ""
        if OPERATOR_KEY:
            return self._page("Login", None,
                              '<div class="card">Single-operator mode: '
                              '<code>DASHBOARD_API_KEY</code> is set, no login '
                              'needed. <a href="/overview">Continue</a></div>')
        return self._page("Login", None, f"""{err}
<div class="card" style="max-width:420px">
<h2>Operator sign in</h2>
<p class="muted">Paste a tenant API key (<code>vouch_sk_…</code>). It is
validated against the control plane and kept server-side only, never in the
page.</p>
<form method="post" action="/login">
<input type="password" name="api_key" placeholder="vouch_sk_…" size="40"
       autocomplete="off"><br>
<button type="submit">Sign in</button>
</form></div>""")

    def _do_login(self):
        ctype = self.headers.get("Content-Type", "")
        form = self._read_form() if "urlencoded" in ctype else {}
        body = self._read_json() if not form else {}
        if "TOO_LARGE" in (form, body):
            return self._err(413, "payload_too_large",
                             "request body exceeds 1MB")
        if form == "BAD_LENGTH" or body == "BAD_LENGTH":
            return self._err(400, "bad_request", "bad Content-Length")
        key = (form.get("api_key") or body.get("api_key") or "").strip()
        if not key.startswith("vouch_sk_"):
            return self._send_html(200, self._login_page(
                "That doesn't look like a vouch_sk_* API key."))
        ident = self._validate_key(key)
        if ident is None:
            return self._send_html(200, self._login_page(
                "Key rejected by the control plane (or it's unreachable)."))
        tenant_id, name = ident
        sid = _new_session(key)
        secure = self._secure_cookie_suffix()
        cookie = (f"{SESSION_COOKIE}={sid}; HttpOnly; SameSite=Lax;{secure} "
                  f"Path=/; Max-Age={SESSION_TTL}")
        if "application/json" in ctype:
            s = _get_session(sid)
            self.send_response(201)
            self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(
                {"tenant_id": tenant_id, "name": name,
                 "csrf_token": s["csrf"]}).encode())
            return
        self._redirect("/overview", cookie=cookie)

    def _do_logout(self):
        # L-2: logout is state-changing — require the CSRF token so a
        # cross-site POST cannot log the operator out from under them.
        # M-2: an oversized body is rejected (413) BEFORE any session
        # handling — the TOO_LARGE sentinel must not fall through the
        # isinstance(form, dict) check and skip CSRF validation.
        if not OPERATOR_KEY:
            form = self._read_form()
            if form == "TOO_LARGE":
                return self._err(413, "payload_too_large",
                                 "request body exceeds 1MB")
            if form == "BAD_LENGTH":
                return self._err(400, "bad_content_length",
                                 "invalid Content-Length")
            if isinstance(form, dict) and not self._csrf_form_ok(form):
                return self._send_html(403, self._page(
                    "Forbidden", None, "<p>Bad CSRF token.</p>"))
            _drop_session(self._cookie_sid())
        expired = (f"{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; "
                   "Path=/; Max-Age=0")
        self._redirect("/login", cookie=expired)

    # -------------------------------------------------------------- overview
    def _overview(self):
        key = self._require_key_html()
        if key is None:
            return
        status, me = self._up("GET", CONTROLPLANE_URL, "/v1/tenants/me", key)
        if status != 200:
            return self._send_html(502, self._page(
                "Overview", "overview", self._up_err_html(me)))
        usage = me.get("usage", {}) or {}
        s_keys, keys = self._up("GET", CONTROLPLANE_URL, "/v1/api-keys", key)
        s_pol, pols = self._up("GET", CONTROLPLANE_URL, "/v1/policies", key)
        s_dep, deps = self._up("GET", CONTROLPLANE_URL, "/v1/deployments", key)
        s_rc, rc = self._up("GET", RECEIPT_SVC_URL, "/v1/receipts", key,
                            params={"limit": 1})
        s_vf, vf = self._up("GET", RECEIPT_SVC_URL, "/v1/verify", key)
        st = me.get("status", "")
        status_badge = ("<b>active</b>" if st == "active"
                        else f'<b class="deny">{esc(st)}</b>')
        vf_banner = ""
        if s_vf == 200 and isinstance(vf, dict):
            if vf.get("chain_ok"):
                vf_banner = (f'<div class="banner ok">Receipt chain: '
                             f'<b>intact</b> — {esc(vf.get("receipts", 0))} '
                             f'receipts, all signatures valid.</div>')
            else:
                fails = vf.get("failures", [])
                vf_banner = (f'<div class="banner bad">Receipt chain: '
                             f'<b>BROKEN</b> — {len(fails)} failure(s). '
                             f'See <a href="/receipts">Receipts</a>.</div>')
        elif s_vf != 200:
            vf_banner = self._up_err_html(vf)
        n_keys = len(keys.get("keys", [])) if isinstance(keys, dict) else "?"
        n_pol = len(pols.get("tasks", {})) if isinstance(pols, dict) else "?"
        n_dep = (len(deps.get("deployments", []))
                 if isinstance(deps, dict) else "?")
        n_rc = (len(rc.get("items", [])) and "≥1" if isinstance(rc, dict)
                else "?")
        inner = f"""{vf_banner}
<div class="card"><h2>{esc(me.get("name", ""))}
<span class="muted">(<code>{esc(me.get("tenant_id", ""))}</code>)</span></h2>
<p>Status: {status_badge} &nbsp; Plan: <b>{esc(me.get("plan", ""))}</b></p>
<h3>Usage — {esc(usage.get("month", ""))}</h3>
<p>Allowed: <b class="allow">{esc(usage.get("actions_allowed", 0))}</b>
&nbsp; Denied: <b class="deny">{esc(usage.get("actions_denied", 0))}</b>
<span class="muted">(fanned in from the receipt service via
<code>GET /v1/tenants/me</code> — §4.5)</span></p>
<h3>Inventory</h3>
<p>API keys: <b>{n_keys}</b> · Policies: <b>{n_pol}</b> ·
Deployments: <b>{n_dep}</b> · Receipts: <b>{n_rc}</b></p>
<p class="muted">Keys are HMAC-signing identities plus named
<code>vouch_sk_*</code> API keys; key material never leaves the server.</p>
</div>"""
        self._send_html(200, self._page("Overview", "overview", inner))

    # -------------------------------------------------------------- receipts
    def _receipts(self, q):
        key = self._require_key_html()
        if key is None:
            return
        banner = ""
        if q.get("verify") == "1":
            s_vf, vf = self._up("GET", RECEIPT_SVC_URL, "/v1/verify", key)
            if s_vf == 200 and isinstance(vf, dict):
                if vf.get("chain_ok"):
                    banner = (f'<div class="banner ok"><b>Chain intact</b> — '
                              f'{esc(vf.get("receipts", 0))} receipts replayed, '
                              f'all signatures valid.</div>')
                else:
                    rows = "".join(
                        f"<li>seq {esc(f.get('seq'))}: "
                        f"{esc(f.get('error'))}</li>"
                        for f in vf.get("failures", []))
                    banner = (f'<div class="banner bad"><b>Chain broken</b>'
                              f"<ul>{rows}</ul></div>")
            else:
                banner = self._up_err_html(vf)
        params = {k: q.get(k) for k in
                  ("task_id", "tool", "decision", "agent_id", "limit", "cursor")
                  if q.get(k)}
        params.setdefault("limit", "50")
        s_rc, rc = self._up("GET", RECEIPT_SVC_URL, "/v1/receipts", key,
                            params=params)
        if s_rc != 200 or not isinstance(rc, dict):
            return self._send_html(502, self._page(
                "Receipts", "receipts", banner + self._up_err_html(rc)))
        rows = ""
        for r in rc.get("items", []):
            dec = esc(r.get("decision", ""))
            cls = "allow" if r.get("decision") == "allow" else "deny"
            rows += (f"<tr><td><a href=\"/receipts/{esc(r.get('seq'))}\">"
                     f"{esc(r.get('seq'))}</a></td>"
                     f"<td>{esc(r.get('task_id'))}</td>"
                     f"<td>{esc(r.get('agent_id'))}</td>"
                     f"<td><code>{esc(r.get('tool'))}</code></td>"
                     f'<td class="{cls}">{dec}</td>'
                     f"<td>{esc(r.get('rule_id') or '—')}</td>"
                     f"<td>{esc(r.get('kid'))}</td>"
                     f"<td class=\"muted\">{esc(r.get('hash', '')[:12])}…</td>"
                     "</tr>")
        nxt = rc.get("next_cursor")
        more = (f'<a class="btn" href="/receipts?{self._qs(q, cursor=nxt)}">'
                f'older →</a>' if nxt else "")
        f = {k: esc(q.get(k, "")) for k in ("task_id", "tool", "agent_id")}
        inner = f"""{banner}
<form method="get" action="/receipts" class="inline">
task <input name="task_id" value="{f['task_id']}" size="14">
tool <input name="tool" value="{f['tool']}" size="14">
agent <input name="agent_id" value="{f['agent_id']}" size="12">
decision <select name="decision">
<option value="">any</option>
<option value="allow"{" selected" if q.get("decision")=="allow" else ""}>allow</option>
<option value="deny"{" selected" if q.get("decision")=="deny" else ""}>deny</option>
</select>
<button type="submit">filter</button>
<a class="btn" href="/receipts?verify=1">verify chain</a>
</form>
<table><tr><th>seq</th><th>task</th><th>agent</th><th>tool</th><th>decision</th>
<th>rule</th><th>kid</th><th>hash</th></tr>{rows or
'<tr><td colspan="8" class="muted">no receipts yet</td></tr>'}</table>
{more}
<p class="muted">Newest first. Every allow <em>and</em> deny is receipted;
signatures are checked server-side against control-plane keys (§4.6/§4.7).</p>"""
        self._send_html(200, self._page("Receipts", "receipts", inner))

    @staticmethod
    def _qs(q, **over):
        from urllib.parse import urlencode
        merged = {**q, **{k: v for k, v in over.items() if v}}
        return urlencode(merged)

    def _receipt_detail(self, seq):
        key = self._require_key_html()
        if key is None:
            return
        s_rc, r = self._up("GET", RECEIPT_SVC_URL, f"/v1/receipts/{seq}", key)
        if s_rc != 200 or not isinstance(r, dict):
            inner = self._up_err_html(r) if s_rc != 404 else \
                '<div class="banner bad">Receipt not found.</div>'
            return self._send_html(s_rc if s_rc != 502 else 404,
                                   self._page("Receipt", "receipts", inner))
        rows = "".join(f"<tr><th>{esc(k)}</th><td><code>{esc(v)}</code></td></tr>"
                       for k, v in r.items())
        inner = (f'<p><a href="/receipts">← back to chain</a></p>'
                 f"<table>{rows}</table>")
        self._send_html(200, self._page(f"Receipt #{esc(seq)}",
                                        "receipts", inner))

    # -------------------------------------------------------------- policies
    def _policies(self, q):
        key = self._require_key_html()
        if key is None:
            return
        s = _get_session(self._cookie_sid()) if not OPERATOR_KEY else None
        csrf = s["csrf"] if s else "operator-mode"
        notice = ""
        if q.get("saved"):
            notice = (f'<div class="banner ok">Policy for '
                      f'<code>{esc(q["saved"])}</code> saved.</div>')
        if q.get("deleted"):
            notice = (f'<div class="banner ok">Policy for '
                      f'<code>{esc(q["deleted"])}</code> deleted.</div>')
        if q.get("error"):
            notice = f'<div class="banner bad">{esc(q["error"])}</div>'
        s_pol, pols = self._up("GET", CONTROLPLANE_URL, "/v1/policies", key)
        if s_pol != 200 or not isinstance(pols, dict):
            return self._send_html(502, self._page(
                "Policies", "policies", notice + self._up_err_html(pols)))
        tasks = pols.get("tasks", {})
        cards = ""
        for task_id in sorted(tasks):
            t = tasks[task_id]
            rules = json.dumps(t.get("rules", {}), indent=2, sort_keys=True)
            cards += f"""<div class="card"><h3><code>{esc(task_id)}</code>
<span class="muted">v{esc(t.get("version"))}</span></h3>
<form method="post" action="/policies/{esc(task_id)}">
<input type="hidden" name="csrf_token" value="{esc(csrf)}">
<textarea name="rules" rows="12">{esc(rules)}</textarea><br>
<button type="submit">save (v2 schema)</button>
</form>
<form method="post" action="/policies/{esc(task_id)}/delete" class="inline">
<input type="hidden" name="csrf_token" value="{esc(csrf)}">
<button type="submit" onclick="return confirm('Delete policy {esc(task_id)}?')">
delete</button></form></div>"""
        inner = f"""{notice}
<p class="muted">Policies are argument-aware (§5): <code>allow</code>/<code>deny</code>
rules with <code>equals</code>, <code>prefix</code>, <code>regex</code>,
<code>in</code>, <code>range</code>, <code>required</code> constraints.
Deny rules win. Invalid schema → <code>422</code> from the control plane.</p>
{cards or '<p class="muted">no policies yet</p>'}
<div class="card"><h3>New task policy</h3>
<form method="post" action="/policies/__new__">
<input type="hidden" name="csrf_token" value="{esc(csrf)}">
task_id <input name="task_id" size="24" required><br>
<textarea name="rules" rows="8">{{"allow": [], "deny": []}}</textarea><br>
<button type="submit">create</button></form></div>"""
        self._send_html(200, self._page("Policies", "policies", inner))

    def _save_policy(self, task_id, form):
        key = self._require_key_html()
        if key is None:
            return
        if task_id == "__new__":
            task_id = (form.get("task_id") or "").strip()
            if not task_id:
                return self._redirect("/policies?error=" +
                                      "task_id+is+required")
        try:
            rules = json.loads(form.get("rules", ""))
        except (ValueError, TypeError):
            return self._redirect(f"/policies?error=invalid+JSON+in+rules")
        if not isinstance(rules, dict):
            return self._redirect("/policies?error=rules+must+be+an+object")
        from urllib.parse import quote
        s, data = self._up("PUT", CONTROLPLANE_URL,
                           f"/v1/policies/{quote(task_id, safe='')}",
                           key, body={"rules": rules})
        if s not in (200, 201):
            msg = (data.get("message") or data.get("error")
                   if isinstance(data, dict) else str(data))
            return self._redirect("/policies?error=" +
                                  quote(str(msg))[:200])
        self._redirect(f"/policies?saved={quote(task_id)}")

    def _delete_policy(self, task_id):
        key = self._require_key_html()
        if key is None:
            return
        from urllib.parse import quote
        s, data = self._up("DELETE", CONTROLPLANE_URL,
                           f"/v1/policies/{quote(task_id, safe='')}", key)
        if s not in (200, 204):
            msg = (data.get("message") or data.get("error")
                   if isinstance(data, dict) else str(data))
            return self._redirect("/policies?error=" + quote(str(msg))[:200])
        self._redirect(f"/policies?deleted={quote(task_id)}")

    # ------------------------------------------------------------ deployments
    def _deployments(self, q):
        key = self._require_key_html()
        if key is None:
            return
        csrf = self._csrf_field()
        notice = ""
        if q.get("created"):
            notice = (f'<div class="banner ok">Deployment '
                      f'<code>{esc(q["created"])}</code> created.</div>')
        if q.get("stopped"):
            notice = (f'<div class="banner ok">Deployment '
                      f'<code>{esc(q["stopped"])}</code> stopped.</div>')
        if q.get("error"):
            notice = f'<div class="banner bad">{esc(q["error"])}</div>'
        s_dep, deps = self._up("GET", CONTROLPLANE_URL, "/v1/deployments", key)
        if s_dep != 200 or not isinstance(deps, dict):
            return self._send_html(502, self._page(
                "Deployments", "deployments", notice + self._up_err_html(deps)))
        rows = ""
        for d in deps.get("deployments", []):
            stop = (f'<form method="post" class="inline" '
                    f'action="/deployments/{esc(d.get("id"))}/stop">{csrf}'
                    f'<button type="submit">stop</button></form>'
                    if d.get("status") in ("pending", "running") else "")
            rows += (f"<tr><td><code>{esc(d.get('id'))}</code></td>"
                     f"<td><code>{esc(d.get('task_id'))}</code></td>"
                     f"<td><code>{esc(d.get('agent_image'))}</code></td>"
                     f"<td><b>{esc(d.get('status'))}</b></td>"
                     f"<td class=\"muted\">{esc(d.get('container_id') or '—')}</td>"
                     f"<td>{stop}</td></tr>")
        inner = f"""{notice}
<table><tr><th>id</th><th>task</th><th>image</th><th>status</th>
<th>container</th><th></th></tr>{rows or
'<tr><td colspan="6" class="muted">no deployments yet</td></tr>'}</table>
<div class="card"><h3>New deployment</h3>
<form method="post" action="/deployments">{csrf}
task_id <input name="task_id" size="24" required>
agent_image <input name="agent_image" size="32"
value="vouch/agent-demo:latest" required>
<button type="submit">deploy</button></form>
<p class="muted">The runner polls desired state and launches one sandboxed
container per deployment (§2.5). Agent logs are not exposed here yet (G2).</p>
</div>"""
        self._send_html(200, self._page("Deployments", "deployments", inner))

    def _create_deployment(self, form):
        key = self._require_key_html()
        if key is None:
            return
        s, data = self._up("POST", CONTROLPLANE_URL, "/v1/deployments", key,
                           body={"task_id": form.get("task_id", "").strip(),
                                 "agent_image": form.get("agent_image",
                                                         "").strip()})
        if s not in (200, 201) or not isinstance(data, dict):
            msg = (data.get("message") or data.get("error")
                   if isinstance(data, dict) else str(data))
            from urllib.parse import quote
            return self._redirect("/deployments?error=" + quote(str(msg))[:200])
        from urllib.parse import quote
        self._redirect(f"/deployments?created={quote(str(data.get('deployment_id')))}")

    def _stop_deployment(self, dep_id):
        key = self._require_key_html()
        if key is None:
            return
        from urllib.parse import quote
        s, data = self._up("DELETE", CONTROLPLANE_URL,
                           f"/v1/deployments/{quote(dep_id, safe='')}", key)
        if s not in (200, 204):
            msg = (data.get("message") or data.get("error")
                   if isinstance(data, dict) else str(data))
            return self._redirect("/deployments?error=" + quote(str(msg))[:200])
        self._redirect(f"/deployments?stopped={quote(dep_id)}")

    def _csrf_field(self):
        s = self._session()
        token = s["csrf"] if s else ""
        return (f'<input type="hidden" name="csrf_token" '
                f'value="{esc(token)}">')

    # ------------------------------------------------------------------ keys
    def _keys(self, q, new_key_plaintext=None):
        key = self._require_key_html()
        if key is None:
            return
        csrf = self._csrf_field()
        notice = ""
        if q.get("created"):
            notice = (f'<div class="banner ok">API key '
                      f'<b>{esc(q.get("name", ""))}</b> created.</div>')
        if q.get("revoked"):
            notice = '<div class="banner ok">API key revoked.</div>'
        if q.get("rotated"):
            notice = (f'<div class="banner ok">Signing keys rotated — new '
                      f'<code>kid</code>: <code>{esc(q["rotated"])}</code>. '
                      f'Old kids stay verifiable.</div>')
        if q.get("error"):
            notice = f'<div class="banner bad">{esc(q["error"])}</div>'
        if new_key_plaintext:
            notice += (f'<div class="banner"><b>Copy this key now — it is '
                       f'shown once:</b><br><code style="font-size:16px">'
                       f'{esc(new_key_plaintext)}</code></div>')
        s_k, keys = self._up("GET", CONTROLPLANE_URL, "/v1/api-keys", key)
        if s_k != 200 or not isinstance(keys, dict):
            return self._send_html(502, self._page(
                "API Keys", "keys", notice + self._up_err_html(keys)))
        rows = ""
        for k in keys.get("keys", []):
            rev = k.get("revoked_at")
            action = ("<span class=\"muted\">revoked</span>" if rev else
                      f'<form method="post" class="inline" '
                      f'action="/keys/{esc(k.get("id"))}/revoke">{csrf}'
                      f'<button type="submit">revoke</button></form>')
            rows += (f"<tr><td><code>{esc(k.get('id'))}</code></td>"
                     f"<td><b>{esc(k.get('name'))}</b></td>"
                     f"<td class=\"muted\">{esc(k.get('created_at'))}</td>"
                     f"<td>{action}</td></tr>")
        inner = f"""{notice}
<table><tr><th>id</th><th>name</th><th>created</th><th></th></tr>
{rows or '<tr><td colspan="4" class="muted">no keys yet</td></tr>'}</table>
<div class="card"><h3>New named API key</h3>
<form method="post" action="/keys">{csrf}
name <input name="name" size="24" required
placeholder="ci / human / per-service">
<button type="submit">create</button></form>
<p class="muted">Only the sha256 hash is stored; plaintext is shown once.</p>
</div>
<div class="card"><h3>Signing keys</h3>
<form method="post" action="/keys/rotate-signing">{csrf}
<button type="submit">rotate signing keys</button></form>
<p class="muted">Tenant HMAC keys (the receipt-signing identities) rotate;
the response carries only the new <code>kid</code> — key material never
leaves the server (§10.5).</p></div>"""
        self._send_html(200, self._page("API Keys", "keys", inner))

    def _create_key(self, form):
        key = self._require_key_html()
        if key is None:
            return
        name = (form.get("name") or "").strip() or "unnamed"
        s, data = self._up("POST", CONTROLPLANE_URL, "/v1/api-keys", key,
                           body={"name": name})
        if s not in (200, 201) or not isinstance(data, dict):
            msg = (data.get("message") or data.get("error")
                   if isinstance(data, dict) else str(data))
            from urllib.parse import quote
            return self._redirect("/keys?error=" + quote(str(msg))[:200])
        from urllib.parse import quote
        # Plaintext shown once, per the frozen contract — never stored.
        self._keys({"created": "1", "name": data.get("name", "")},
                   new_key_plaintext=data.get("api_key"))

    def _revoke_key(self, key_id):
        key = self._require_key_html()
        if key is None:
            return
        from urllib.parse import quote
        s, data = self._up("DELETE", CONTROLPLANE_URL,
                           f"/v1/api-keys/{quote(key_id, safe='')}", key)
        if s not in (200, 204):
            msg = (data.get("message") or data.get("error")
                   if isinstance(data, dict) else str(data))
            return self._redirect("/keys?error=" + quote(str(msg))[:200])
        self._redirect("/keys?revoked=1")

    def _rotate_signing(self):
        key = self._require_key_html()
        if key is None:
            return
        from urllib.parse import quote
        s, data = self._up("POST", CONTROLPLANE_URL,
                           "/v1/tenants/me/rotate-keys", key)
        if s != 200 or not isinstance(data, dict):
            msg = (data.get("message") or data.get("error")
                   if isinstance(data, dict) else str(data))
            return self._redirect("/keys?error=" + quote(str(msg))[:200])
        self._redirect(f"/keys?rotated={quote(str(data.get('new_kid')))}")

    # --------------------------------------------------------------- JSON API
    def _api_overview(self, key):
        out = {}
        s, me = self._up("GET", CONTROLPLANE_URL, "/v1/tenants/me", key)
        if s != 200:
            return self._send(s, me if isinstance(me, dict) else
                              {"error": "upstream_error"})
        out["tenant"] = {k: me.get(k) for k in
                         ("tenant_id", "name", "plan", "status")}
        out["usage"] = me.get("usage", {})
        for name, base, path, params in (
                ("api_keys", CONTROLPLANE_URL, "/v1/api-keys", None),
                ("policies", CONTROLPLANE_URL, "/v1/policies", None),
                ("deployments", CONTROLPLANE_URL, "/v1/deployments", None)):
            s2, d2 = self._up("GET", base, path, key, params=params)
            out[name] = d2 if s2 == 200 else {"error": "upstream_error"}
        s3, rc = self._up("GET", RECEIPT_SVC_URL, "/v1/receipts", key,
                          params={"limit": 1})
        out["receipts_sample"] = rc if s3 == 200 else {"error":
                                                      "upstream_error"}
        self._send(200, out)

    def _api(self, method, path, q, key):
        """Route /api/* onto the frozen upstream contracts."""
        parts = [p for p in path[len("/api/"):].split("/") if p]
        if not parts:
            return self._err(404, "not_found")

        def relay(base, up_path, body=None, params=None, ok=(200,)):
            s, data = self._up(method, base, up_path, key, body=body,
                               params=params)
            if s == 204:
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if s not in ok and s not in (200, 201, 204):
                self._send(s, data if isinstance(data, dict) else
                           {"error": "upstream_error",
                            "message": str(data)[:200]})
                return
            self._send(s if s in (200, 201) else 200, data)

        from urllib.parse import quote
        r = parts[0]
        if r == "overview" and method == "GET" and len(parts) == 1:
            return self._api_overview(key)
        if r == "verify" and method == "GET" and len(parts) == 1:
            return relay(RECEIPT_SVC_URL, "/v1/verify")
        if r == "csrf" and method == "GET" and len(parts) == 1:
            s = self._session()
            return self._send(200, {"csrf_token": s["csrf"] if s else ""})
        if r == "receipts":
            if len(parts) == 1 and method == "GET":
                return relay(RECEIPT_SVC_URL, "/v1/receipts", params={
                    k: q.get(k) for k in
                    ("task_id", "tool", "decision", "agent_id", "limit",
                     "cursor") if q.get(k)})
            if len(parts) == 2 and method == "GET" and parts[1] != "stream":
                return relay(RECEIPT_SVC_URL,
                             f"/v1/receipts/{quote(parts[1], safe='')}")
            if parts[1:] == ["stream"] and method == "GET":
                return self._sse_relay(key, q)
        if r == "policies":
            if len(parts) == 1 and method == "GET":
                return relay(CONTROLPLANE_URL, "/v1/policies")
            if len(parts) == 2:
                task = quote(parts[1], safe="")
                if method == "PUT":
                    body = self._read_json()
                    if body == "TOO_LARGE":
                        return self._err(413, "payload_too_large",
                                         "request body exceeds 1MB")
                    if body in ("INVALID", "BAD_LENGTH") or not isinstance(
                            body.get("rules"), dict):
                        return self._err(400, "bad_request",
                                         "body.rules must be an object")
                    return relay(CONTROLPLANE_URL, f"/v1/policies/{task}",
                                 body={"rules": body["rules"]}, ok=(200, 201))
                if method == "DELETE":
                    return relay(CONTROLPLANE_URL, f"/v1/policies/{task}")
        if r == "deployments":
            if len(parts) == 1 and method == "GET":
                return relay(CONTROLPLANE_URL, "/v1/deployments")
            if len(parts) == 1 and method == "POST":
                body = self._read_json()
                if body == "TOO_LARGE":
                    return self._err(413, "payload_too_large",
                                     "request body exceeds 1MB")
                if body in ("INVALID", "BAD_LENGTH"):
                    return self._err(400, "bad_request", "invalid JSON")
                return relay(CONTROLPLANE_URL, "/v1/deployments",
                             body={"task_id": body.get("task_id"),
                                   "agent_image": body.get("agent_image")},
                             ok=(200, 201))
            if len(parts) == 2:
                dep = quote(parts[1], safe="")
                return relay(CONTROLPLANE_URL, f"/v1/deployments/{dep}")
        if r == "keys":
            if len(parts) == 1 and method == "GET":
                return relay(CONTROLPLANE_URL, "/v1/api-keys")
            if len(parts) == 1 and method == "POST":
                body = self._read_json()
                if body == "TOO_LARGE":
                    return self._err(413, "payload_too_large",
                                     "request body exceeds 1MB")
                if body in ("INVALID", "BAD_LENGTH"):
                    return self._err(400, "bad_request", "invalid JSON")
                return relay(CONTROLPLANE_URL, "/v1/api-keys",
                             body={"name": body.get("name", "unnamed")},
                             ok=(200, 201))
            if len(parts) == 2 and parts[1] == "rotate-signing" and \
                    method == "POST":
                return relay(CONTROLPLANE_URL, "/v1/tenants/me/rotate-keys")
            if len(parts) == 2 and method == "DELETE":
                return relay(CONTROLPLANE_URL,
                             f"/v1/api-keys/{quote(parts[1], safe='')}")
        return self._err(404, "not_found")

    def _sse_relay(self, key, q):
        """Relay the receipt-service SSE live feed (§4.6) to the browser.

        The dashboard holds the tenant key server-side; the browser never
        sees it. Bytes pass through untouched.
        """
        from urllib.parse import urlencode
        params = {k: q.get(k) for k in ("task_id",) if q.get(k)}
        url = RECEIPT_SVC_URL + "/v1/receipts/stream"
        if params:
            url += "?" + urlencode(params)
        req = urllib.request.Request(
            url, headers={"Authorization": f"Bearer {key}",
                          "Accept": "text/event-stream"})
        try:
            upstream = urllib.request.urlopen(req, timeout=60)
        except Exception as e:  # noqa: BLE001
            return self._err(502, "upstream_unavailable", str(e)[:200])
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            while True:
                line = upstream.readline()
                if not line:
                    break
                self.wfile.write(line)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass  # browser navigated away — normal
        finally:
            upstream.close()

    # ---------------------------------------------------------------- routing
    def do_GET(self):
        path, q = self._path()
        if path == "/login":
            return self._send_html(200, self._login_page())
        if path == "/":
            return self._redirect("/overview")
        if path.startswith("/api/"):
            key = self._require_key_json()
            if key is None:
                return
            if path == "/api/receipts/stream":
                return self._sse_relay(key, q)
            return self._api("GET", path, q, key)
        key = self._require_key_html()
        if key is None:
            return
        if path == "/overview":
            return self._overview()
        if path == "/receipts":
            return self._receipts(q)
        if path.startswith("/receipts/") and path.count("/") == 2:
            return self._receipt_detail(path[len("/receipts/"):])
        if path == "/policies":
            return self._policies(q)
        if path == "/deployments":
            return self._deployments(q)
        if path == "/keys":
            return self._keys(q)
        self._send_html(404, self._page("Not found", None,
                                       "<p>Unknown page.</p>"))

    def _csrf_form_ok(self, form):
        s = self._session()
        if s is None:
            return False
        if OPERATOR_KEY:
            return True
        return form.get("csrf_token") == s["csrf"]

    def do_POST(self):
        path, q = self._path()
        if path == "/login":
            return self._do_login()
        if path == "/logout":
            return self._do_logout()
        if path == "/api/session":
            return self._do_login()
        if path.startswith("/api/"):
            key = self._require_key_json()
            if key is None:
                return
            if not self._csrf_ok():
                return self._err(403, "forbidden", "bad CSRF token")
            return self._api("POST", path, q, key)
        # HTML form posts
        form = self._read_form()
        if form == "TOO_LARGE":
            return self._err(413, "payload_too_large",
                             "request body exceeds 1MB")
        if form == "BAD_LENGTH":
            return self._err(400, "bad_request", "bad Content-Length")
        if path.startswith("/policies/") and path.endswith("/delete"):
            task = path[len("/policies/"):-len("/delete")]
            if not self._csrf_form_ok(form):
                return self._send_html(403, self._page(
                    "Forbidden", None, "<p>Bad CSRF token.</p>"))
            return self._delete_policy(task)
        if path.startswith("/policies/"):
            if not self._csrf_form_ok(form):
                return self._send_html(403, self._page(
                    "Forbidden", None, "<p>Bad CSRF token.</p>"))
            return self._save_policy(path[len("/policies/"):], form)
        if path == "/deployments":
            if not self._csrf_form_ok(form):
                return self._send_html(403, self._page(
                    "Forbidden", None, "<p>Bad CSRF token.</p>"))
            return self._create_deployment(form)
        if path.startswith("/deployments/") and path.endswith("/stop"):
            if not self._csrf_form_ok(form):
                return self._send_html(403, self._page(
                    "Forbidden", None, "<p>Bad CSRF token.</p>"))
            return self._stop_deployment(path[len("/deployments/"):
                                              -len("/stop")])
        if path == "/keys":
            if not self._csrf_form_ok(form):
                return self._send_html(403, self._page(
                    "Forbidden", None, "<p>Bad CSRF token.</p>"))
            return self._create_key(form)
        if path == "/keys/rotate-signing":
            if not self._csrf_form_ok(form):
                return self._send_html(403, self._page(
                    "Forbidden", None, "<p>Bad CSRF token.</p>"))
            return self._rotate_signing()
        if path.startswith("/keys/") and path.endswith("/revoke"):
            if not self._csrf_form_ok(form):
                return self._send_html(403, self._page(
                    "Forbidden", None, "<p>Bad CSRF token.</p>"))
            return self._revoke_key(path[len("/keys/"):-len("/revoke")])
        self._send_html(404, self._page("Not found", None,
                                       "<p>Unknown action.</p>"))

    def do_PUT(self):
        path, q = self._path()
        if not path.startswith("/api/"):
            return self._err(404, "not_found")
        key = self._require_key_json()
        if key is None:
            return
        if not self._csrf_ok():
            return self._err(403, "forbidden", "bad CSRF token")
        return self._api("PUT", path, q, key)

    def do_DELETE(self):
        path, q = self._path()
        if path == "/api/session":
            if not OPERATOR_KEY:
                _drop_session(self._cookie_sid())
            return self._send(204, {})
        if not path.startswith("/api/"):
            return self._err(404, "not_found")
        key = self._require_key_json()
        if key is None:
            return
        if not self._csrf_ok():
            return self._err(403, "forbidden", "bad CSRF token")
        return self._api("DELETE", path, q, key)


def main():
    import os as _os
    bind = _os.environ.get("VOUCH_BIND", "127.0.0.1")
    # L-2: expired sessions are lazily evicted on access; the sweeper makes
    # sure abandoned logins never accumulate in memory.
    threading.Thread(target=_session_sweeper, daemon=True).start()
    server = ThreadingHTTPServer((bind, PORT), Handler)
    print(f"vouch dashboard on {bind}:{PORT} "
          f"(control plane {CONTROLPLANE_URL}, receipts {RECEIPT_SVC_URL})",
          flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
