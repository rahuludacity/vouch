"""Vouch agent runner (:9003) — desired-state poll loop + sandboxed execution.

Polls the control plane ``GET /internal/desired-state`` every
``RUNNER_POLL_INTERVAL`` seconds (default 10), converges local docker
containers to it, and reports status back via
``POST /internal/deployments/{id}/status``. (§4.5, §2.5, ARCHITECTURE.md
Phase 3.)

Control-plane outage: the runner keeps the last known desired state, keeps
containers running, logs once, and retries. It never mass-restarts on a
failed poll — the runner is management plane; enforcement lives in the
gatekeeper and never depends on this service.

Endpoints:
    GET  /v1/health        no auth — {"ok": true, "managed": N}
    POST /v1/reconcile     service token — run one reconcile pass now,
                           returns the summary (runner-local; not in §4).

Run:  python3 -m services.runner.app [--once] [--check]
      --once: single reconcile pass, print the summary JSON, exit.
      --check: validate config + control-plane reachability, exit 0/1.
Env:  RUNNER_PORT            (default 9003)
      CONTROLPLANE_URL       control plane base (default http://127.0.0.1:9002)
      RUNNER_TOKEN           bearer token for /v1/reconcile
                             (default ""; empty = open, local dev only)
      GATEKEEPER_AGENT_URL   gatekeeper MCP endpoint as seen by agent
                             containers (default http://gatekeeper:9000/mcp)
      RUNNER_POLL_INTERVAL   seconds between polls (default 10)
      RUNNER_SANDBOX_NETWORK (default vouch-sandbox)
      RUNNER_DOCKER_FAKE=1   demo/test mode: in-process fake docker client
                             instead of the docker SDK. The fake "starts" the
                             demo agent (demo/agent_sim.py) as a subprocess
                             with the exact env the sandbox spec injects —
                             everything below the docker call is real.
"""
import json
import hmac
import os
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .sandbox import (
    SANDBOX_NETWORK,
    RUNNER_LABEL,
    RUNNER_VALUE,
    build_container_spec,
    validate_spec,
    ensure_sandbox_network,
)

HERE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIND = os.environ.get("VOUCH_BIND", "127.0.0.1")
PORT = int(os.environ.get("RUNNER_PORT", "9003"))
CONTROLPLANE_URL = os.environ.get("CONTROLPLANE_URL", "http://127.0.0.1:9002").rstrip("/")
SVC_TOKEN = os.environ.get("RUNNER_TOKEN", "")
GATEKEEPER_AGENT_URL = os.environ.get(
    "GATEKEEPER_AGENT_URL", "http://gatekeeper:9000/mcp")
POLL_INTERVAL = float(os.environ.get("RUNNER_POLL_INTERVAL", "10"))
SANDBOX_NET = os.environ.get("RUNNER_SANDBOX_NETWORK", SANDBOX_NETWORK)


class ControlPlaneError(Exception):
    """The control plane could not be reached or answered badly."""


class ControlPlaneClient:
    """Thin client for the control plane's internal runner surface (§4.5)."""

    def __init__(self, base_url, svc_token, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.svc_token = svc_token
        self.timeout = timeout

    def _request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base_url + path, data=data, method=method,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.svc_token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raise ControlPlaneError(f"HTTP {e.code} on {method} {path}")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise ControlPlaneError(str(e))
        try:
            return json.loads(raw) if raw else {}
        except ValueError:
            raise ControlPlaneError(f"bad JSON from {method} {path}")

    def get_desired_state(self):
        """-> list of {id, tenant_id, task_id, agent_image, desired}."""
        body = self._request("GET", "/internal/desired-state")
        deployments = body.get("deployments")
        if not isinstance(deployments, list):
            raise ControlPlaneError("desired-state missing deployments list")
        return deployments

    def get_deployment_credential(self, dep_id):
        """Fetch the deployment's gatekeeper credential (H-1).

        The control plane mints one per deployment at creation; the runner
        injects it into the agent container as VOUCH_DEPLOYMENT_TOKEN so the
        agent can authenticate to the gatekeeper. Never logged, never
        exposed beyond the container env.
        """
        body = self._request("GET", f"/internal/deployments/{dep_id}/credential")
        token = body.get("deployment_token")
        if not token:
            raise ControlPlaneError(
                f"no deployment credential for {dep_id}")
        if body.get("tenant_id") is None:
            raise ControlPlaneError(
                f"credential response missing tenant for {dep_id}")
        return token

    def report_status(self, dep_id, status, container_id=None):
        """POST the runner-observed status; True if the control plane took it."""
        try:
            self._request("POST", f"/internal/deployments/{dep_id}/status",
                          {"status": status, "container_id": container_id})
            return True
        except ControlPlaneError:
            return False


class DockerBackend:
    """Real docker backend. The SDK is imported lazily so the module loads
    (and unit tests run) on hosts without docker installed."""

    def __init__(self, sandbox_network=SANDBOX_NET):
        try:
            import docker  # noqa: F401
        except ImportError as e:
            raise RuntimeError(
                "the docker SDK is not installed; set RUNNER_DOCKER_FAKE=1 "
                "for demo/test mode") from e
        import docker as _docker
        self._docker = _docker
        self.client = _docker.from_env()
        self.sandbox_network = sandbox_network

    def ensure_network(self):
        # Adopt the real network name (ensure_sandbox_network may adopt the
        # compose-created vouch_vouch-sandbox); the spec builder must use
        # THIS name, not the bare SANDBOX_NETWORK default.
        self.sandbox_network = ensure_sandbox_network(self.client)
        return self.sandbox_network

    def list_managed(self):
        """{dep_id: {"id", "running", "exit_code"}} for our containers.

        exit_code is None while running or when unknown; for exited
        containers it is the container's exit status (0 = clean exit).
        """
        out = {}
        try:
            containers = self.client.containers.list(
                all=True, filters={"label": f"{RUNNER_LABEL}={RUNNER_VALUE}"})
        except Exception:
            return out
        for c in containers:
            dep_id = (c.labels or {}).get("vouch.deployment")
            if not dep_id:
                continue
            try:
                running = c.status == "running"
            except Exception:
                running = False
            exit_code = None
            if not running:
                try:
                    c.reload()
                    exit_code = (c.attrs.get("State") or {}).get("ExitCode")
                except Exception:
                    exit_code = None
            out[dep_id] = {"id": c.id, "running": running,
                           "exit_code": exit_code}
        return out

    def start(self, spec):
        validate_spec(spec, sandbox_network=self.sandbox_network)
        kwargs = dict(spec)
        image = kwargs.pop("image")
        container = self.client.containers.run(image, **kwargs)
        return container.id

    def stop(self, container_id):
        try:
            self.client.containers.get(container_id).stop(timeout=10)
        except self._docker.errors.NotFound:
            pass

    def remove(self, container_id):
        try:
            self.client.containers.get(container_id).remove(force=True)
        except self._docker.errors.NotFound:
            pass


class FakeDockerBackend:
    """In-process stand-in for docker (demo/tests on hosts without a daemon).

    ``agent_cmd`` is an optional callable ``(env: dict) -> Popen-like`` used
    to *execute* the agent when a "container" starts — the demo wires this to
    ``demo/agent_sim.py`` as a subprocess, so everything below the docker call
    is real. Every spec passed to ``start`` is validated and recorded in
    ``started_specs`` for assertions.
    """

    def __init__(self, agent_cmd=None, sandbox_network=SANDBOX_NET):
        self.agent_cmd = agent_cmd
        self.sandbox_network = sandbox_network
        self.containers = {}      # dep_id -> {"id", "proc", "spec"}
        self.started_specs = []   # every spec ever "created", in order
        self.networks_created = []
        self._n = 0

    def ensure_network(self):
        self.networks_created.append(self.sandbox_network)
        return self.sandbox_network

    def _alive(self, info):
        proc = info.get("proc")
        if proc is None:
            return True  # plain fake container: assumed running
        return proc.poll() is None

    def list_managed(self):
        return {dep_id: {"id": info["id"], "running": self._alive(info),
                         "exit_code": self._exit_code(info)}
                for dep_id, info in self.containers.items()}

    def _exit_code(self, info):
        """Exit status of an exited "container", else None."""
        proc = info.get("proc")
        if proc is None:
            return None
        try:
            return proc.poll()  # None while still running
        except Exception:
            return None

    def start(self, spec):
        validate_spec(spec, sandbox_network=self.sandbox_network)
        dep_id = spec["labels"]["vouch.deployment"]
        self._n += 1
        cid = f"fake-{dep_id}-{self._n}"
        proc = self.agent_cmd(dict(spec["environment"])) if self.agent_cmd else None
        self.containers[dep_id] = {"id": cid, "proc": proc, "spec": dict(spec)}
        self.started_specs.append(dict(spec))
        return cid

    def _find(self, container_id):
        for dep_id, info in self.containers.items():
            if info["id"] == container_id:
                return dep_id, info
        return None, None

    def stop(self, container_id):
        _, info = self._find(container_id)
        if info and info.get("proc") is not None:
            try:
                info["proc"].terminate()
            except Exception:
                pass

    def remove(self, container_id):
        dep_id, _ = self._find(container_id)
        if dep_id:
            del self.containers[dep_id]


class Runner:
    """Converge local containers to the control plane's desired state."""

    def __init__(self, cp, docker, gatekeeper_agent_url=GATEKEEPER_AGENT_URL,
                 poll_interval=POLL_INTERVAL, log=None):
        self.cp = cp
        self.docker = docker
        self.gatekeeper_agent_url = gatekeeper_agent_url
        self.poll_interval = poll_interval
        self._log = log or (lambda *a: print("[runner]", *a, flush=True))
        self._outage = False

    def _report(self, dep_id, status, container_id):
        ok = self.cp.report_status(dep_id, status, container_id)
        if not ok:
            self._log(f"status callback failed for {dep_id} ({status})")
        return ok

    def _remove_container(self, dep_id, container_id):
        try:
            self.docker.stop(container_id)
        except Exception as e:
            self._log(f"stop {container_id} ({dep_id}): {e}")
        try:
            self.docker.remove(container_id)
        except Exception as e:
            self._log(f"remove {container_id} ({dep_id}): {e}")

    def reconcile_once(self):
        """One converge pass. Returns a summary dict; never raises.

        Lifecycle: "service" deployments are supervisors — an exited
        container is replaced. "one-shot" deployments run exactly once:
        when their container exits, a clean exit (code 0) transitions the
        deployment to the terminal "succeeded" state, any other exit to
        "failed"; the container is removed and never restarted.
        """
        summary = {"started": [], "stopped": [], "heartbeats": 0,
                   "succeeded": [], "failed": [], "errors": []}
        try:
            desired = self.cp.get_desired_state()
        except ControlPlaneError as e:
            if not self._outage:
                self._log(f"control plane unreachable ({e}); "
                          "keeping containers as-is, will retry")
                self._outage = True
            summary["outage"] = True
            return summary
        self._outage = False
        try:
            managed = self.docker.list_managed()
        except Exception as e:
            summary["errors"].append(f"docker list failed: {e}")
            return summary

        want = {d["id"]: d for d in desired if d.get("id")}

        # 1. desired running -> ensure a live container
        #    (start / restart / heartbeat / one-shot terminal)
        for dep_id, dep in want.items():
            if dep.get("desired") != "running":
                continue
            cur = managed.get(dep_id)
            if cur and cur["running"]:
                self._report(dep_id, "running", cur["id"])  # heartbeat
                summary["heartbeats"] += 1
                continue
            if cur and not cur["running"]:
                if dep.get("mode") == "one-shot":
                    # Terminal: a one-shot runs exactly once. Clean exit
                    # (code 0) -> "succeeded"; anything else (crash, unknown
                    # exit code) -> "failed". Never restart — restarting a
                    # completed one-shot is the receipt-chain inflation bug.
                    exit_code = cur.get("exit_code")
                    terminal = ("succeeded"
                                if exit_code == 0 else "failed")
                    self._log(f"{dep_id}: one-shot exited"
                              f" (code {exit_code}), terminal -> {terminal}")
                    self._remove_container(dep_id, cur["id"])
                    self._report(dep_id, terminal, cur["id"])
                    summary[terminal].append(dep_id)
                    continue
                self._log(f"{dep_id}: previous container exited, replacing")
                self._remove_container(dep_id, cur["id"])
            try:
                # H-1: fetch the deployment's gatekeeper credential and inject
                # it into the container env — this is the only way the agent
                # can authenticate to the gatekeeper.
                dep_token = self.cp.get_deployment_credential(dep_id)
                spec = build_container_spec(
                    dep, gatekeeper_url=self.gatekeeper_agent_url,
                    deployment_token=dep_token,
                    sandbox_network=getattr(self.docker, "sandbox_network",
                                            SANDBOX_NETWORK))
                cid = self.docker.start(spec)
            except Exception as e:
                summary["failed"].append(dep_id)
                summary["errors"].append(f"start {dep_id}: {e}")
                self._report(dep_id, "failed", None)
                continue
            self._log(f"{dep_id}: started {cid} ({spec['name']})")
            summary["started"].append(dep_id)
            self._report(dep_id, "running", cid)

        # 2. desired stopped -> stop + remove
        for dep_id, dep in want.items():
            if dep.get("desired") == "running":
                continue
            cur = managed.get(dep_id)
            if cur:
                self._log(f"{dep_id}: desired stopped, removing {cur['id']}")
                self._remove_container(dep_id, cur["id"])
                self._report(dep_id, "stopped", cur["id"])
                summary["stopped"].append(dep_id)

        # 3. orphans: managed locally but unknown to the control plane
        for dep_id, cur in managed.items():
            if dep_id not in want:
                self._log(f"{dep_id}: orphan container, removing {cur['id']}")
                self._remove_container(dep_id, cur["id"])
                summary["errors"].append(f"orphan {dep_id} removed")
        return summary

    def run_forever(self):
        while True:
            try:
                self.reconcile_once()
            except Exception as e:  # never let the loop die
                self._log(f"reconcile crashed: {e}")
            time.sleep(self.poll_interval)


class Handler(BaseHTTPRequestHandler):
    runner = None
    svc_token = None
    server_version = "VouchRunner/1.0"

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _require_auth(self):
        if self.svc_token in (None, ""):
            return True  # no token configured: open (local dev only)
        # L-1: constant-time bearer comparison.
        return hmac.compare_digest(
            self.headers.get("Authorization", ""),
            f"Bearer {self.svc_token}")

    def do_GET(self):
        if self.path != "/v1/health":
            return self._send(404, {"error": "not_found"})
        try:
            managed = self.runner.docker.list_managed()
        except Exception:
            managed = {}
        self._send(200, {"ok": True, "managed": len(managed)})

    def do_POST(self):
        if self.path != "/v1/reconcile":
            return self._send(404, {"error": "not_found"})
        # M-2: 1MB body cap (this endpoint ignores the body, but a
        # client-controlled Content-Length must not drive an unbounded read).
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            return self._send(400, {"error": "bad Content-Length"})
        if length > 1_000_000:
            return self._send(413, {"error": "payload_too_large"})
        if length:
            self.rfile.read(length)  # drain so the connection stays usable
        if not self._require_auth():
            return self._send(401, {"error": "unauthorized"})
        self._send(200, self.runner.reconcile_once())

    def log_message(self, *a):
        pass


def demo_agent_cmd(env):
    """Run the demo agent as a subprocess with the sandbox spec's env.

    Demo/test wiring for RUNNER_DOCKER_FAKE=1: the "container" is
    ``demo/agent_sim.py`` executed with exactly the identity env the real
    container would get. Returns the Popen handle.
    """
    merged = dict(os.environ)
    merged.update(env)
    return subprocess.Popen(
        [sys.executable, os.path.join(HERE, "demo", "agent_sim.py")],
        env=merged, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True,
    )


def build_runner():
    cp = ControlPlaneClient(CONTROLPLANE_URL, SVC_TOKEN)
    if os.environ.get("RUNNER_DOCKER_FAKE") == "1":
        docker = FakeDockerBackend(agent_cmd=demo_agent_cmd)
    else:
        docker = DockerBackend()
    docker.ensure_network()
    return Runner(cp, docker,
                  gatekeeper_agent_url=GATEKEEPER_AGENT_URL,
                  poll_interval=POLL_INTERVAL)


def main(argv):
    if "--check" in argv:
        cp = ControlPlaneClient(CONTROLPLANE_URL, SVC_TOKEN)
        try:
            deps = cp.get_desired_state()
        except ControlPlaneError as e:
            print(f"control plane unreachable: {e}")
            return 1
        print(f"control plane ok at {CONTROLPLANE_URL} "
              f"({len(deps)} deployments desired)")
        return 0
    runner = build_runner()
    if "--once" in argv:
        print(json.dumps(runner.reconcile_once(), indent=2))
        return 0
    Handler.runner = runner
    Handler.svc_token = SVC_TOKEN
    if SVC_TOKEN == "":
        print("WARNING: RUNNER_TOKEN not set; /v1/reconcile is unauthenticated. "
              "Set it in production.")
    t = threading.Thread(
        target=ThreadingHTTPServer((BIND, PORT), Handler).serve_forever,
        daemon=True)
    t.start()
    print(f"vouch runner listening on :{PORT}, polling {CONTROLPLANE_URL} "
          f"every {POLL_INTERVAL}s")
    runner.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
