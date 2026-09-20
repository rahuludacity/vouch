"""Tests for the Vouch agent runner (Phase 3, ARCHITECTURE.md §2.5/§4.5/§4.9).

Covers: the sandbox spec contract (no host net, egress allowlist, env
injection, resource limits), the reconcile loop (start/stop/heartbeat/
orphan/failure/outage), the control-plane client, and the runner HTTP
surface. Docker itself is faked — the SDK calls are thin wrappers around
the validated spec.
"""
import json
import os
import socket
import sys
import threading
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from services.runner.sandbox import (
    SANDBOX_NETWORK,
    ALLOWED_EGRESS,
    RUNNER_LABEL,
    RUNNER_VALUE,
    build_container_spec,
    validate_spec,
    ensure_sandbox_network,
    container_name,
    agent_id_for,
)
from services.runner.app import (
    ControlPlaneClient,
    ControlPlaneError,
    FakeDockerBackend,
    Runner,
    Handler,
)


def dep(**kw):
    d = {"id": "dep_ab12cd34", "tenant_id": "acme",
         "task_id": "deploy-staging", "agent_image": "vouch/agent-demo:latest"}
    d.update(kw)
    return d


# H-1: every container spec carries the deployment's gatekeeper credential.
_TEST_DEP_TOKEN = "vouch_dep_dep_ab12cd34_acme_1700000000_" + "ab" * 16


def makespec(**kw):
    """build_container_spec with the mandatory H-1 deployment token."""
    return build_container_spec(dep(), deployment_token=_TEST_DEP_TOKEN, **kw)


# ------------------------------------------------------------------ sandbox
class TestSandboxSpec(unittest.TestCase):
    def test_spec_encodes_sandbox_contract(self):
        spec = makespec()
        # no host networking, ever: dedicated internal network only
        self.assertEqual(spec["network"], SANDBOX_NETWORK)
        self.assertNotEqual(spec.get("network_mode"), "host")
        # egress allowlist is the network membership (gatekeeper only)
        self.assertEqual(ALLOWED_EGRESS, ("http://gatekeeper:9000",))
        # read-only root, one writable scratch dir
        self.assertTrue(spec["read_only"])
        self.assertIn("/scratch", spec["tmpfs"])
        # resource limits
        self.assertTrue(spec["mem_limit"])
        self.assertTrue(spec["nano_cpus"])
        # no privileged, all caps dropped, non-root user
        self.assertFalse(spec["privileged"])
        self.assertIn("ALL", spec["cap_drop"])
        self.assertEqual(spec["user"], "65534:65534")
        # identity env injection (§4.9)
        env = spec["environment"]
        self.assertEqual(env["VOUCH_TENANT_ID"], "acme")
        self.assertEqual(env["VOUCH_TASK_ID"], "deploy-staging")
        self.assertEqual(env["VOUCH_AGENT_ID"], agent_id_for("dep_ab12cd34"))
        self.assertTrue(env["GATEKEEPER_URL"].endswith("/mcp"))
        # traceability labels + deterministic name
        self.assertEqual(spec["labels"][RUNNER_LABEL], RUNNER_VALUE)
        self.assertEqual(spec["labels"]["vouch.deployment"], "dep_ab12cd34")
        self.assertEqual(spec["name"], container_name("dep_ab12cd34"))
        self.assertTrue(spec["name"].startswith("vouch-dep_ab12cd34"))

    def test_spec_rejects_bad_deployments(self):
        for key in ("id", "tenant_id", "task_id", "agent_image"):
            bad = dep()
            bad[key] = ""
            with self.assertRaises(ValueError):
                build_container_spec(bad, deployment_token=_TEST_DEP_TOKEN)

    def test_validate_rejects_host_network(self):
        spec = makespec()
        spec["network"] = "host"
        with self.assertRaises(ValueError):
            validate_spec(spec)
        spec = makespec()
        spec["network_mode"] = "host"
        with self.assertRaises(ValueError):
            validate_spec(spec)

    def test_validate_rejects_wrong_network(self):
        spec = makespec()
        spec["network"] = "bridge"
        with self.assertRaises(ValueError):
            validate_spec(spec)

    def test_validate_rejects_privileged_and_caps(self):
        spec = makespec()
        spec["privileged"] = True
        with self.assertRaises(ValueError):
            validate_spec(spec)
        spec = makespec()
        spec["cap_drop"] = []
        with self.assertRaises(ValueError):
            validate_spec(spec)

    def test_validate_rejects_root_user(self):
        for bad_user in (None, "", "0", "0:0", "root", "root:root"):
            spec = makespec()
            spec["user"] = bad_user
            with self.assertRaises(ValueError, msg=f"user={bad_user!r}"):
                validate_spec(spec)
        spec = makespec()
        spec["user"] = "65534:65534"
        self.assertTrue(validate_spec(spec))

    def test_validate_rejects_writable_root_and_missing_limits(self):
        spec = makespec()
        spec["read_only"] = False
        with self.assertRaises(ValueError):
            validate_spec(spec)
        spec = makespec()
        del spec["mem_limit"]
        with self.assertRaises(ValueError):
            validate_spec(spec)

    def test_validate_rejects_missing_identity_env(self):
        spec = makespec()
        del spec["environment"]["VOUCH_TASK_ID"]
        with self.assertRaises(ValueError):
            validate_spec(spec)

    def test_container_name_is_docker_safe(self):
        self.assertEqual(container_name("dep_abc123"), "vouch-dep_abc123")
        self.assertNotIn(" ", container_name("dep a/b:c"))

    def test_ensure_sandbox_network_is_internal_and_idempotent(self):
        created = []

        class FakeNet:
            name = SANDBOX_NETWORK
            attrs = {"Internal": True}

        class FakeNetworks:
            def list(self, names=None):
                return []
            def create(self, name, internal=False, labels=None):
                created.append((name, internal, labels))
                return FakeNet()

        class FakeClient:
            networks = FakeNetworks()

        self.assertEqual(ensure_sandbox_network(FakeClient()), SANDBOX_NETWORK)
        self.assertEqual(created[0][0], SANDBOX_NETWORK)
        self.assertTrue(created[0][1], "sandbox network must be internal")

        class FakeNetworks2(FakeNetworks):
            def list(self, names=None):
                return [FakeNet()]

        class FakeClient2:
            networks = FakeNetworks2()

        created.clear()
        self.assertEqual(ensure_sandbox_network(FakeClient2()), SANDBOX_NETWORK)
        self.assertEqual(created, [], "existing network must not be recreated")

    def test_ensure_sandbox_network_rejects_non_internal(self):
        # L-5: a pre-existing vouch-sandbox WITHOUT internal=true is a
        # poisoned network — fail closed instead of granting egress.
        class PoisonedNet:
            name = SANDBOX_NETWORK
            attrs = {"Internal": False}

        class FakeNetworks:
            def list(self, names=None):
                return [PoisonedNet()]

        class FakeClient:
            networks = FakeNetworks()

        with self.assertRaises(RuntimeError):
            ensure_sandbox_network(FakeClient())

    def test_spec_requires_deployment_token(self):
        # H-1: a container spec without its gatekeeper credential is
        # rejected — agents must never start unauthenticated.
        with self.assertRaises(ValueError):
            build_container_spec(dep())
        s = makespec()
        self.assertEqual(s["environment"]["VOUCH_DEPLOYMENT_TOKEN"],
                         _TEST_DEP_TOKEN)
        # L-5 hardening is part of the validated contract.
        self.assertIn("no-new-privileges:true", s["security_opt"])
        self.assertIn("noexec", s["tmpfs"]["/scratch"])


# ------------------------------------------------------------------ runner
class StubCP:
    """Scripted control-plane client for reconcile tests."""

    def __init__(self, desired=None, fail=False):
        self.desired = desired or []
        self.fail = fail
        self.reports = []  # (dep_id, status, container_id)

    def get_desired_state(self):
        if self.fail:
            raise ControlPlaneError("boom")
        return [dict(d) for d in self.desired]

    def report_status(self, dep_id, status, container_id=None):
        self.reports.append((dep_id, status, container_id))
        return True

    def get_deployment_credential(self, dep_id):
        # H-1: the runner fetches each deployment's gatekeeper credential.
        return _TEST_DEP_TOKEN


def desired_running(**kw):
    d = dep(**kw)
    d["desired"] = "running"
    return d


def desired_stopped(**kw):
    d = dep(**kw)
    d["desired"] = "stopped"
    return d


class TestRunnerReconcile(unittest.TestCase):
    def make(self, desired, fail=False):
        cp = StubCP(desired, fail=fail)
        docker = FakeDockerBackend()
        runner = Runner(cp, docker, gatekeeper_agent_url="http://gk:9000/mcp",
                        poll_interval=0.01, log=lambda *a: None)
        return cp, docker, runner

    def test_start_desired_running(self):
        cp, docker, runner = self.make([desired_running()])
        summary = runner.reconcile_once()
        self.assertEqual(summary["started"], ["dep_ab12cd34"])
        self.assertEqual(len(docker.started_specs), 1)
        spec = docker.started_specs[0]
        self.assertEqual(spec["network"], SANDBOX_NETWORK)  # spec validated
        # H-1: the runner injected the deployment's gatekeeper credential.
        self.assertEqual(spec["environment"]["VOUCH_DEPLOYMENT_TOKEN"],
                         _TEST_DEP_TOKEN)
        cid = docker.containers["dep_ab12cd34"]["id"]
        self.assertIn(("dep_ab12cd34", "running", cid), cp.reports)

    def test_heartbeat_for_already_running(self):
        cp, docker, runner = self.make([desired_running()])
        runner.reconcile_once()
        n_specs = len(docker.started_specs)
        cp.reports.clear()
        summary = runner.reconcile_once()
        self.assertEqual(summary["started"], [])
        self.assertEqual(len(docker.started_specs), n_specs,
                         "no new container on heartbeat")
        self.assertEqual(summary["heartbeats"], 1)
        self.assertEqual(cp.reports[0][1], "running")

    def test_exited_container_is_replaced(self):
        cp, docker, runner = self.make([desired_running()])
        runner.reconcile_once()
        # simulate a crash: the fake tracks a dead proc
        class Dead:
            def poll(self):
                return 1
            def terminate(self):
                pass
        docker.containers["dep_ab12cd34"]["proc"] = Dead()
        cp.reports.clear()
        summary = runner.reconcile_once()
        self.assertEqual(summary["started"], ["dep_ab12cd34"])
        self.assertEqual(len(docker.started_specs), 2)

    def test_stop_desired_stopped(self):
        cp, docker, runner = self.make([desired_running()])
        runner.reconcile_once()
        cid = docker.containers["dep_ab12cd34"]["id"]
        cp2 = StubCP([desired_stopped()])
        runner.cp = cp2
        summary = runner.reconcile_once()
        self.assertEqual(summary["stopped"], ["dep_ab12cd34"])
        self.assertNotIn("dep_ab12cd34", docker.containers)
        self.assertIn(("dep_ab12cd34", "stopped", cid), cp2.reports)

    def test_orphan_containers_are_removed(self):
        cp, docker, runner = self.make([desired_running(id="dep_other")])
        # orphan not known to the control plane
        docker.containers["dep_gone"] = {"id": "fake-dep_gone-9",
                                        "proc": None, "spec": {}}
        summary = runner.reconcile_once()
        self.assertNotIn("dep_gone", docker.containers)
        self.assertTrue(any("orphan" in e for e in summary["errors"]))

    def test_start_failure_reports_failed(self):
        cp, docker, runner = self.make([desired_running()])

        def boom(spec):
            raise RuntimeError("no such image")
        docker.start = boom
        summary = runner.reconcile_once()
        self.assertEqual(summary["failed"], ["dep_ab12cd34"])
        self.assertIn(("dep_ab12cd34", "failed", None), cp.reports)

    def test_outage_keeps_containers_and_does_not_flail(self):
        cp, docker, runner = self.make([desired_running()])
        runner.reconcile_once()
        before = dict(docker.containers)
        runner.cp = StubCP(fail=True)
        summary = runner.reconcile_once()
        self.assertTrue(summary.get("outage"))
        self.assertEqual(docker.containers.keys(), before.keys())
        self.assertEqual(summary["started"], [])
        self.assertEqual(summary["stopped"], [])


# ------------------------------------------------------- control-plane client
class StubCPHandler(BaseHTTPRequestHandler):
    token = "tok"
    desired = []
    statuses = []

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        return self.headers.get("Authorization") == f"Bearer {self.token}"

    def do_GET(self):
        if self.path == "/internal/desired-state" and self._authed():
            return self._send(200, {"deployments": self.desired})
        return self._send(401 if not self._authed() else 404,
                          {"error": "x"})

    def do_POST(self):
        if self.path.startswith("/internal/deployments/") and self._authed():
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            self.statuses.append((self.path, body))
            return self._send(200, {"ok": True})
        return self._send(401, {"error": "x"})

    def log_message(self, *a):
        pass


class TestControlPlaneClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        cls.port = s.getsockname()[1]
        s.close()
        cls.server = ThreadingHTTPServer(("127.0.0.1", cls.port), StubCPHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        StubCPHandler.desired = [dict(dep(), desired="running")]
        StubCPHandler.statuses = []

    def test_desired_state(self):
        cp = ControlPlaneClient(self.base, "tok")
        deps = cp.get_desired_state()
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0]["desired"], "running")

    def test_report_status(self):
        cp = ControlPlaneClient(self.base, "tok")
        self.assertTrue(cp.report_status("dep_1", "running", "cid-9"))
        path, body = StubCPHandler.statuses[0]
        self.assertIn("dep_1", path)
        self.assertEqual(body["status"], "running")
        self.assertEqual(body["container_id"], "cid-9")

    def test_bad_token_raises(self):
        cp = ControlPlaneClient(self.base, "wrong")
        with self.assertRaises(ControlPlaneError):
            cp.get_desired_state()

    def test_unreachable_raises_not_hangs(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        cp = ControlPlaneClient(f"http://127.0.0.1:{port}", "tok", timeout=2)
        with self.assertRaises(ControlPlaneError):
            cp.get_desired_state()
        self.assertFalse(cp.report_status("dep_1", "running"))


# ------------------------------------------------------------- runner HTTP
def _raw_oversized_status(base_url, path, headers=None):
    """Declare ``Content-Length: 1000001`` but send only a partial body;
    return the response status. urllib's full-body send races the server's
    early 413 and flakes with BrokenPipeError; the raw socket proves the
    server decides on the headers alone, before touching the body."""
    u = urllib.parse.urlparse(base_url)
    s = socket.create_connection((u.hostname, u.port or 80), timeout=15)
    try:
        lines = ["POST %s HTTP/1.1" % path, "Host: %s" % u.hostname,
                 "Content-Length: 1000001", "Connection: close"]
        for k, v in (headers or {}).items():
            lines.append("%s: %s" % (k, v))
        s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + b"x" * 1024)
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        return int(resp.split(b" ", 2)[1])
    finally:
        s.close()


class TestRunnerHttp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        cls.port = s.getsockname()[1]
        s.close()
        cp = StubCP([dict(dep(), desired="running")])
        cls.docker = FakeDockerBackend()
        cls.runner = Runner(cp, cls.docker, poll_interval=0.01,
                            log=lambda *a: None)
        Handler.runner = cls.runner
        Handler.svc_token = "rtok"
        cls.server = ThreadingHTTPServer(("127.0.0.1", cls.port), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _get(self, path, token=None):
        req = urllib.request.Request(self.base + path)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())

    def test_health(self):
        code, body = self._get("/v1/health")
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])
        self.assertIn("managed", body)

    def test_reconcile_requires_token(self):
        req = urllib.request.Request(self.base + "/v1/reconcile", data=b"",
                                     method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
            self.fail("expected 401")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 401)

    def test_reconcile_with_token(self):
        req = urllib.request.Request(self.base + "/v1/reconcile", data=b"",
                                     method="POST",
                                     headers={"Authorization": "Bearer rtok"})
        with urllib.request.urlopen(req, timeout=10) as r:
            body = json.loads(r.read())
        self.assertIn("dep_ab12cd34", body["started"])

    def test_reconcile_oversized_body_rejected(self):
        # M-2: >1MB reconcile bodies are refused before any more work.
        code = _raw_oversized_status(
            self.base, "/v1/reconcile",
            {"Authorization": "Bearer rtok"})
        self.assertEqual(code, 413)


if __name__ == "__main__":
    unittest.main()
