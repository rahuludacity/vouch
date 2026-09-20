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


# ------------------------------------------------------------------ sandbox
class TestSandboxSpec(unittest.TestCase):
    def test_spec_encodes_sandbox_contract(self):
        spec = build_container_spec(dep())
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
        # no privileged, all caps dropped
        self.assertFalse(spec["privileged"])
        self.assertIn("ALL", spec["cap_drop"])
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
                build_container_spec(bad)

    def test_validate_rejects_host_network(self):
        spec = build_container_spec(dep())
        spec["network"] = "host"
        with self.assertRaises(ValueError):
            validate_spec(spec)
        spec = build_container_spec(dep())
        spec["network_mode"] = "host"
        with self.assertRaises(ValueError):
            validate_spec(spec)

    def test_validate_rejects_wrong_network(self):
        spec = build_container_spec(dep())
        spec["network"] = "bridge"
        with self.assertRaises(ValueError):
            validate_spec(spec)

    def test_validate_rejects_privileged_and_caps(self):
        spec = build_container_spec(dep())
        spec["privileged"] = True
        with self.assertRaises(ValueError):
            validate_spec(spec)
        spec = build_container_spec(dep())
        spec["cap_drop"] = []
        with self.assertRaises(ValueError):
            validate_spec(spec)

    def test_validate_rejects_writable_root_and_missing_limits(self):
        spec = build_container_spec(dep())
        spec["read_only"] = False
        with self.assertRaises(ValueError):
            validate_spec(spec)
        spec = build_container_spec(dep())
        del spec["mem_limit"]
        with self.assertRaises(ValueError):
            validate_spec(spec)

    def test_validate_rejects_missing_identity_env(self):
        spec = build_container_spec(dep())
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


if __name__ == "__main__":
    unittest.main()
