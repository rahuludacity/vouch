"""End-to-end test for the dashboard live demo (/demo + /api/demo/*).

Boots the REAL demo stack (verifier + Smallville site as subprocesses,
same as demo/agent_verification/run_demo.sh) and drives the dashboard's
demo APIs against it. Every asserted number comes from a live call.

Env is configured inside the test (not at module import): pytest imports
all test modules at collection time, and ambient env changes here would
leak into sibling test modules that boot the dashboard as a subprocess.

Slow (~2s): key generation + two subprocess boots. Run explicitly:
    python3 -m pytest tests/test_demo_page.py -q
"""
import json
import os
import socket
import sys
import tempfile
import threading
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer

_ENV_KEYS = ("DASHBOARD_API_KEY", "VOUCH_DEMO_STATE_DIR",
             "DEMO_VERIFIER_PORT", "DEMO_SITE_PORT", "DEMO_SWARM_SIZE",
             "DEMO_PROVISION_COOLDOWN_S")


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _req(base, method, path, body=None):
    req = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json",
                 "X-CSRF-Token": "operator-mode"},
        method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read().decode()
            ctype = r.headers.get("Content-Type", "")
            return r.status, (json.loads(raw) if "json" in ctype else raw)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_live_demo_end_to_end():
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    tmp = tempfile.mkdtemp(prefix="vouch-demo-test-")
    os.environ["DASHBOARD_API_KEY"] = "test-operator-key"   # single-op mode
    os.environ["VOUCH_DEMO_STATE_DIR"] = os.path.join(tmp, "demo_state")
    os.environ["DEMO_VERIFIER_PORT"] = str(_free_port())
    os.environ["DEMO_SITE_PORT"] = str(_free_port())
    os.environ["DEMO_SWARM_SIZE"] = "12"
    os.environ["DEMO_PROVISION_COOLDOWN_S"] = "0"
    # Fresh import under the test env (no other test module imports the
    # dashboard in-process; the dashboard tests use subprocesses).
    for mod in ("web.dashboard.demo_backend", "web.dashboard.app"):
        sys.modules.pop(mod, None)
    from web.dashboard.app import Handler
    from web.dashboard.demo_backend import get_demo_backend

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        # 1. status before provisioning: healthy endpoint, nothing booted.
        st, s = _req(base, "GET", "/api/demo/status")
        assert st == 200 and s["ok"] is True
        assert s["provisioned"] is False

        # 2. provision boots the real backend.
        st, p = _req(base, "POST", "/api/demo/provision", {})
        assert st == 200 and p["ok"] is True, p

        st, s = _req(base, "GET", "/api/demo/status")
        assert s["provisioned"] is True
        assert s["verifier_up"] is True and s["site_up"] is True

        # 3. the good agent: live 200 + live receipt seq/hash.
        st, g = _req(base, "POST", "/api/demo/run/good", {})
        assert st == 200 and g["ok"] is True, g
        assert g["http_status"] == 200
        assert g["lane"] == "verified-agent"
        assert isinstance(g["receipt_seq"], int) and g["receipt_seq"] >= 1
        assert isinstance(g["receipt_hash"], str) and len(g["receipt_hash"]) > 8

        # 4. the human: passes through unchanged.
        st, h = _req(base, "POST", "/api/demo/run/human", {})
        assert st == 200 and h["ok"] is True and h["lane"] == "human", h

        # 5. the forger: live 429 with the visible reason.
        st, f = _req(base, "POST", "/api/demo/run/forged", {})
        assert st == 200 and f["ok"] is True, f
        assert f["http_status"] == 429 and f["lane"] == "unverified"
        assert isinstance(f["reason"], str) and len(f["reason"]) > 0

        # 6. the swarm: every bot challenged, counted from live responses.
        st, w = _req(base, "POST", "/api/demo/run/swarm", {})
        assert st == 200 and w["ok"] is True, w
        assert w["challenged"] == w["total"] == 12

        # 7. lane counters moved, live from the site.
        st, s = _req(base, "GET", "/api/demo/status")
        assert s["lanes"]["verified-agent"] >= 1
        assert s["lanes"]["human"] >= 1
        assert s["lanes"]["unverified"] >= 13  # forger + 12 bots
        assert s["receipts"] >= 2  # allow + deny both receipted

        # 8. transparency log verifies intact, live.
        st, v = _req(base, "POST", "/api/demo/run/verify-log", {})
        assert st == 200 and v["ok"] is True and v["chain_ok"] is True, v
        assert v["receipts"] == s["receipts"]
        assert "chain intact" in v["output"]

        # 9. the page renders, in the proof-layer register.
        st, html = _req(base, "GET", "/demo")
        assert st == 200
        assert "Live demo" in html
        assert "Proof layer for AI agents" in html
        assert "Plaid for agents" not in html

        # 10. existing dashboard surfaces still work.
        st, _ = _req(base, "GET", "/login")
        assert st == 200
        st, _ = _req(base, "GET", "/api/csrf")
        assert st == 200
        st, _ = _req(base, "GET", "/overview")
        assert st in (200, 502)  # 502 = graceful upstream-unreachable page

        # 11. graceful degradation: backend killed -> no fake numbers.
        get_demo_backend().shutdown()
        st, s = _req(base, "GET", "/api/demo/status")
        assert st == 200 and s["ok"] is True
        assert s["provisioned"] is False
        assert s["verifier_up"] is False and s["site_up"] is False
        st, g = _req(base, "POST", "/api/demo/run/good", {})
        assert st == 200 and g["ok"] is False
        assert g["error"] == "demo backend unreachable"
        st, v = _req(base, "POST", "/api/demo/run/verify-log", {})
        assert st == 200 and v["ok"] is False
        assert v["error"] == "demo backend unreachable"
    finally:
        try:
            get_demo_backend().shutdown()
        except Exception:  # noqa: BLE001
            pass
        server.shutdown()
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
