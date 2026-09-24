"""Live demo backend for the dashboard's /demo page (three-lane gateway).

The dashboard drives a REAL demo stack — the same pieces as
demo/agent_verification/run_demo.sh, orchestrated from the dashboard
process so the /demo page can trigger each lane live:

  * verifier  (services.verifier.app) on 127.0.0.1:$DEMO_VERIFIER_PORT
  * demo site (demo/agent_verification/site.py, "Smallville Permit Office")
    on 127.0.0.1:$DEMO_SITE_PORT

Every number the /demo page shows comes from a live call: verification-record seq/hash
from the site's real /agent-submit response, deny reasons from the real 429
body, challenged counts from real bot responses, lane counters from the
site's live /stats, and chain verification from running gatekeeper.verify
against the live transparency log. Nothing is hardcoded or simulated.

Env:
    VOUCH_DEMO_STATE_DIR        where demo keys/log live
                                (default: ./demo_state under the cwd)
    DEMO_VERIFIER_PORT          default 9005
    DEMO_SITE_PORT              default 9011
    DEMO_SWARM_SIZE             bots per swarm run (default 12)
    DEMO_PROVISION_COOLDOWN_S   min seconds between provisions (default 30)

Safety: every subprocess is a fixed argv list — no shell, no visitor input
ever reaches a command line. Demo procs bind 127.0.0.1 only. All calls have
timeouts; one demo op runs at a time (lock) plus a provision cooldown.

Stdlib only — the dashboard has no build step.
"""
import atexit
import copy
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode

REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

SETUP_SCRIPT = os.path.join(REPO, "demo", "agent_verification", "setup.py")
SITE_SCRIPT = os.path.join(REPO, "demo", "agent_verification", "site.py")

# Files setup.py writes into the state dir; wiped on every provision so the
# demo always starts from a clean backend.
_STATE_FILES = ("tenants.json", "keys.json", "credential.json", "env.sh",
                "transparency.jsonl", "submissions.jsonl")
_STATE_DIRS = ("verifier-state",)

_HTTP_TIMEOUT = 10


def _post_json(url, payload, timeout=_HTTP_TIMEOUT):
    """POST JSON; returns (status, body_dict_or_None). Never raises."""
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode() or "{}")
        except Exception:  # noqa: BLE001
            body = None
        return e.code, body
    except Exception:  # noqa: BLE001 - unreachable backend, timeouts, ...
        return None, None


def _get_json(url, timeout=3):
    """GET JSON; returns (status, body) or (None, None). Never raises."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:  # noqa: BLE001
        return None, None


def _http_status(url, timeout=3):
    """GET status code only (for non-JSON endpoints). Never raises."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:  # noqa: BLE001
        return None


class DemoBackend:
    """Owns the demo verifier + site subprocesses and drives the story."""

    def __init__(self):
        self._lock = threading.Lock()     # one demo op at a time
        self._last_provision = 0.0
        self._verifier_proc = None
        self._site_proc = None
        self._keys = None
        self._credential = None

    # ------------------------------------------------------------ config
    def _cfg(self):
        # Read env lazily so tests / operators can override per process.
        return {
            "state_dir": os.environ.get("VOUCH_DEMO_STATE_DIR",
                                        os.path.join(os.getcwd(),
                                                     "demo_state")),
            "verifier_port": int(os.environ.get("DEMO_VERIFIER_PORT",
                                                "9005")),
            "site_port": int(os.environ.get("DEMO_SITE_PORT", "9011")),
            "swarm_size": int(os.environ.get("DEMO_SWARM_SIZE", "12")),
            "cooldown_s": float(os.environ.get("DEMO_PROVISION_COOLDOWN_S",
                                               "30")),
        }

    def _paths(self, cfg):
        d = cfg["state_dir"]
        return {
            "tenants": os.path.join(d, "tenants.json"),
            "keys": os.path.join(d, "keys.json"),
            "credential": os.path.join(d, "credential.json"),
            "log": os.path.join(d, "transparency.jsonl"),
            "verifier_state": os.path.join(d, "verifier-state"),
            "verifier_log": os.path.join(d, "verifier.log"),
            "site_log": os.path.join(d, "site.log"),
        }

    # ------------------------------------------------------------ procs
    @staticmethod
    def _alive(proc):
        return proc is not None and proc.poll() is None

    def _terminate(self, proc, name):
        if not self._alive(proc):
            return
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass

    def _stop_all(self):
        self._terminate(self._verifier_proc, "verifier")
        self._terminate(self._site_proc, "site")
        self._verifier_proc = None
        self._site_proc = None
        self._keys = None
        self._credential = None

    def _boot(self, cfg, paths):
        """Start verifier + site. Returns (ok, error)."""
        vport, sport = cfg["verifier_port"], cfg["site_port"]
        with open(paths["keys"], encoding="utf-8") as f:
            keys = json.load(f)
        principal_pub = keys["principal"]["pub"]

        venv = dict(os.environ)
        venv.update({
            "VERIFIER_PORT": str(vport),
            "VOUCH_BIND": "127.0.0.1",
            "VERIFIER_TENANTS_PATH": paths["tenants"],
            "VERIFIER_STATE_DIR": paths["verifier_state"],
            "VERIFIER_RECEIPTS_PATH": paths["log"],
            "VERIFIER_TRUSTED_ISSUERS": principal_pub,
            # Empty -> local transparency log (same as run_demo.sh).
            "RECEIPT_SVC_URL": "",
        })
        senv = dict(os.environ)
        senv.update({
            "SITE_PORT": str(sport),
            "VOUCH_BIND": "127.0.0.1",
            "VERIFIER_URL": f"http://127.0.0.1:{vport}",
            "SITE_SUBMISSIONS_PATH": os.path.join(cfg["state_dir"],
                                                  "submissions.jsonl"),
        })
        try:
            vlog = open(paths["verifier_log"], "ab")
            slog = open(paths["site_log"], "ab")
        except OSError as e:
            return False, f"cannot open demo logs: {e}"
        try:
            self._verifier_proc = subprocess.Popen(
                [sys.executable, "-m", "services.verifier.app"],
                cwd=REPO, env=venv, stdout=vlog, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL)
            self._site_proc = subprocess.Popen(
                [sys.executable, SITE_SCRIPT],
                cwd=REPO, env=senv, stdout=slog, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL)
        except OSError as e:
            return False, f"cannot start demo backend: {e}"
        finally:
            vlog.close()
            slog.close()

        deadline = time.time() + 30
        v_up = s_up = False
        while time.time() < deadline:
            if not v_up:
                st, _ = _get_json(f"http://127.0.0.1:{vport}/v1/health")
                v_up = st == 200
            if not s_up:
                # The site root serves HTML — status check only.
                s_up = _http_status(f"http://127.0.0.1:{sport}/") == 200
            if v_up and s_up:
                break
            if not self._alive(self._verifier_proc):
                tail = self._tail(paths["verifier_log"])
                self._stop_all()
                return False, ("demo verifier exited during boot "
                               f"(port {vport} in use?): {tail}")
            if not self._alive(self._site_proc):
                tail = self._tail(paths["site_log"])
                self._stop_all()
                return False, ("demo site exited during boot "
                               f"(port {sport} in use?): {tail}")
            time.sleep(0.25)
        if not (v_up and s_up):
            self._stop_all()
            return False, "demo backend unreachable after boot (health timeout)"
        self._keys = keys
        with open(paths["credential"], encoding="utf-8") as f:
            self._credential = json.load(f)
        return True, ""

    @staticmethod
    def _tail(path, n=5):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return " | ".join(f.read().splitlines()[-n:])
        except OSError:
            return ""

    # ------------------------------------------------------------ ops
    def provision(self):
        """Fresh demo backend: wipe state, mint keys, boot verifier + site."""
        with self._lock:
            cfg = self._cfg()
            now = time.time()
            wait = cfg["cooldown_s"] - (now - self._last_provision)
            if wait > 0:
                return {"ok": False,
                        "error": f"provision cooldown: try again in "
                                 f"{int(wait) + 1}s"}
            paths = self._paths(cfg)
            os.makedirs(cfg["state_dir"], exist_ok=True)
            self._stop_all()
            for name in _STATE_FILES:
                try:
                    os.remove(os.path.join(cfg["state_dir"], name))
                except FileNotFoundError:
                    pass
            for name in _STATE_DIRS:
                shutil.rmtree(os.path.join(cfg["state_dir"], name),
                              ignore_errors=True)

            env = dict(os.environ, DEMO_TMP=cfg["state_dir"])
            try:
                proc = subprocess.run(
                    [sys.executable, SETUP_SCRIPT],
                    cwd=REPO, env=env, capture_output=True, text=True,
                    timeout=120)
            except subprocess.TimeoutExpired:
                return {"ok": False,
                        "error": "demo setup timed out (key generation)"}
            if proc.returncode != 0:
                return {"ok": False,
                        "error": "demo setup failed: "
                                 f"{proc.stderr.strip()[-300:]}"}

            ok, err = self._boot(cfg, paths)
            if not ok:
                return {"ok": False, "error": err}
            self._last_provision = time.time()
            return {"ok": True,
                    "message": "demo backend ready: verifier + permit-office "
                               "site booted with fresh keys",
                    "verifier_port": cfg["verifier_port"],
                    "site_port": cfg["site_port"]}

    def _require_backend(self, cfg):
        if not (self._alive(self._verifier_proc)
                and self._alive(self._site_proc)
                and self._keys and self._credential):
            return {"ok": False, "error": "demo backend unreachable"}
        return None

    def status(self):
        """Live backend health + lane counters. Never raises."""
        cfg = self._cfg()
        paths = self._paths(cfg)
        vport, sport = cfg["verifier_port"], cfg["site_port"]
        st, _ = _get_json(f"http://127.0.0.1:{vport}/v1/health")
        verifier_up = st == 200
        # The site root serves HTML — status check only.
        site_up = _http_status(f"http://127.0.0.1:{sport}/") == 200
        lanes = {"human": 0, "verified-agent": 0, "unverified": 0}
        outstanding = 0
        if site_up:
            st, body = _get_json(f"http://127.0.0.1:{sport}/stats")
            if st == 200 and isinstance(body, dict):
                for k in lanes:
                    try:
                        lanes[k] = int(body.get("lanes", {}).get(k, 0))
                    except (TypeError, ValueError):
                        pass
                try:
                    outstanding = int(body.get("outstanding_challenges", 0))
                except (TypeError, ValueError):
                    pass
        receipts = 0
        try:
            with open(paths["log"], encoding="utf-8") as f:
                receipts = sum(1 for _ in f)
        except OSError:
            pass
        provisioned = bool(self._keys and self._credential
                           and self._alive(self._verifier_proc)
                           and self._alive(self._site_proc))
        return {"ok": True,
                "provisioned": provisioned,
                "verifier_up": verifier_up,
                "site_up": site_up,
                "lanes": lanes,
                "outstanding_challenges": outstanding,
                "receipts": receipts}

    def _envelope(self, priv_hex, credential, action):
        # Same signing path as demo/agent_verification/agents.py.
        from services.verifier.credentials import sign_action_request
        env = sign_action_request(agent_priv_hex=priv_hex,
                                  credential_id=credential["credential_id"],
                                  action=action)
        return {"tenant_id": "smallville",
                "credential": credential,
                "action": env["action"], "nonce": env["nonce"],
                "ts": env["ts"],
                "agent_signature": env["agent_signature"]}

    def run_good(self):
        """The legitimate agent: signed credential chain -> fast passage."""
        with self._lock:
            cfg = self._cfg()
            missing = self._require_backend(cfg)
            if missing:
                return missing
            action = {"type": "form.submit", "target": "/permits/apply",
                      "args": {"name": "R. Rao", "permit": "deck-extension"}}
            payload = self._envelope(self._keys["subagent"]["priv"],
                                     self._credential, action)
            url = f"http://127.0.0.1:{cfg['site_port']}/agent-submit"
            status, body = _post_json(url, payload)
            if status is None:
                return {"ok": False, "error": "demo backend unreachable"}
            if status == 200 and isinstance(body, dict) \
                    and body.get("status") == "accepted":
                return {"ok": True, "http_status": 200,
                        "lane": "verified-agent",
                        "receipt_seq": body.get("receipt_seq"),
                        "receipt_hash": body.get("receipt_hash"),
                        "message": body.get("message", "")}
            return {"ok": False,
                    "error": f"unexpected demo response: HTTP {status} "
                             f"{json.dumps(body)[:200]}"}

    def run_human(self):
        """Plain form post, no credential — passes through unchanged."""
        with self._lock:
            cfg = self._cfg()
            missing = self._require_backend(cfg)
            if missing:
                return missing
            url = f"http://127.0.0.1:{cfg['site_port']}/submit"
            body = urlencode({"name": "Ada Lovelace",
                              "permit": "shed"}).encode()
            req = urllib.request.Request(
                url, data=body,
                headers={"Content-Type":
                         "application/x-www-form-urlencoded"})
            try:
                with urllib.request.urlopen(req,
                                            timeout=_HTTP_TIMEOUT) as r:
                    html = r.read().decode("utf-8", "replace")
                    ok = r.status == 200 and "human lane" in html
            except Exception:  # noqa: BLE001
                return {"ok": False, "error": "demo backend unreachable"}
            if ok:
                return {"ok": True, "http_status": 200, "lane": "human",
                        "message": "accepted via human lane — the verifier "
                                   "was never consulted"}
            return {"ok": False,
                    "error": "unexpected demo response from human lane"}

    def run_forged(self):
        """Tampered credential -> denied with a visible reason."""
        with self._lock:
            cfg = self._cfg()
            missing = self._require_backend(cfg)
            if missing:
                return missing
            bad_cred = copy.deepcopy(self._credential)
            # Tamper: widen scope; the issuer signature is now stale.
            bad_cred["scope"] = {"allow": ["*"]}
            action = {"type": "form.submit", "target": "/permits/apply",
                      "args": {"name": "Mallory", "permit": "everything"}}
            payload = self._envelope(self._keys["attacker"]["priv"],
                                     bad_cred, action)
            url = f"http://127.0.0.1:{cfg['site_port']}/agent-submit"
            status, body = _post_json(url, payload)
            if status is None:
                return {"ok": False, "error": "demo backend unreachable"}
            if status == 429 and isinstance(body, dict) \
                    and body.get("lane") == "unverified":
                return {"ok": True, "http_status": 429,
                        "lane": "unverified",
                        "reason": body.get("reason", ""),
                        "challenge_url": body.get("challenge_url", "")}
            return {"ok": False,
                    "error": f"expected a 429 challenge, got HTTP {status} "
                             f"{json.dumps(body)[:200]}"}

    def run_swarm(self):
        """Credential-less bot swarm -> every bot challenged."""
        with self._lock:
            cfg = self._cfg()
            missing = self._require_backend(cfg)
            if missing:
                return missing
            n = cfg["swarm_size"]
            url = f"http://127.0.0.1:{cfg['site_port']}/agent-submit"
            challenged = 0
            for i in range(n):
                status, body = _post_json(
                    url, {"action": {"type": "form.submit",
                                    "target": "/permits/apply",
                                    "args": {"spam": i}}},
                    timeout=5)
                if status == 429 and isinstance(body, dict) \
                        and body.get("lane") == "unverified":
                    challenged += 1
            return {"ok": challenged == n,
                    "challenged": challenged, "total": n,
                    "lane": "unverified",
                    "message": (f"{challenged}/{n} bots challenged — none "
                                "reached the form") if challenged == n
                    else f"only {challenged}/{n} challenged (unexpected)"}

    def verify_log(self):
        """Run gatekeeper.verify against the live transparency log."""
        with self._lock:
            cfg = self._cfg()
            paths = self._paths(cfg)
            missing = self._require_backend(cfg)
            if missing:
                return missing
            env = dict(os.environ,
                       GATEKEEPER_TENANTS_PATH=paths["tenants"],
                       GATEKEEPER_RECEIPTS_PATH=paths["log"])
            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "gatekeeper.verify"],
                    cwd=REPO, env=env, capture_output=True, text=True,
                    timeout=60)
            except subprocess.TimeoutExpired:
                return {"ok": False,
                        "error": "transparency-log verification timed out"}
            receipts = 0
            try:
                with open(paths["log"], encoding="utf-8") as f:
                    receipts = sum(1 for _ in f)
            except OSError:
                pass
            output = (proc.stdout or "").strip()
            if proc.returncode == 0:
                return {"ok": True, "chain_ok": True, "receipts": receipts,
                        "output": output}
            return {"ok": False, "chain_ok": False, "receipts": receipts,
                    "output": output or proc.stderr.strip()[-300:]}

    def shutdown(self):
        with self._lock:
            self._stop_all()


_backend = None
_backend_lock = threading.Lock()


def get_demo_backend():
    """Process-wide demo backend (inert until provision() is called)."""
    global _backend
    with _backend_lock:
        if _backend is None:
            _backend = DemoBackend()
            atexit.register(_backend.shutdown)
        return _backend
