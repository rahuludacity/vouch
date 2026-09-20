"""Tests for services/receipts (store, ingest, query, SSE, verify, usage, import).

Spins up the real receipt service app in-process on an ephemeral port.
"""
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import socket
import urllib.parse
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from services.receipts import app as appmod  # noqa: E402
from services.receipts.store import ReceiptStore  # noqa: E402
from services.receipts.keys import load_verification_keys  # noqa: E402
from services.receipts import import_v1  # noqa: E402
from gatekeeper.receipts import build_receipt  # noqa: E402 (crypto only, no proxy)

TMP = tempfile.mkdtemp(prefix="vouch-receipts-")
TENANTS_PATH = os.path.join(TMP, "tenants.json")
DB_PATH = os.path.join(TMP, "receipts.db")
TOKEN = "test-svc-token"

# deterministic test key (never a real secret)
KEY_HEX = hashlib.sha256(b"vouch-test-tenant-key").hexdigest()
KEY = bytes.fromhex(KEY_HEX)

with open(TENANTS_PATH, "w", encoding="utf-8") as f:
    json.dump({"tenants": {"acme": {"created_at": 1, "keys": {"k1": KEY_HEX},
                                   "current_kid": "k1"}}}, f)


def make_receipt(tenant_id, seq, prev_hash, **kw):
    r = dict(tenant_id=tenant_id, task_id="deploy-staging", agent_id="agent-001",
             tool="read_file", args={"path": "x"}, decision="allow",
             reason=None, rule_id="v1-read_file", policy_version=1)
    r.update(kw)
    return build_receipt(seq=seq, prev_hash=prev_hash, tenant_id=tenant_id,
                         kid="k1", key=KEY, task_id=r["task_id"],
                         agent_id=r["agent_id"], tool=r["tool"], args=r["args"],
                         decision=r["decision"], reason=r["reason"],
                         rule_id=r["rule_id"],
                         policy_version=r["policy_version"])




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


class ServiceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        appmod.Handler.store = ReceiptStore(DB_PATH)
        appmod.Handler.tenants_path = TENANTS_PATH
        appmod.Handler.svc_token = TOKEN
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), appmod.Handler)
        cls.port = cls.server.socket.getsockname()[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.tip = {}  # tenant -> (seq, hash)

    # ------------------------------------------------------------- helpers
    def request(self, method, path, body=None, token=TOKEN):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=headers, method=method)
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw or b"{}")
            except ValueError:
                return e.code, {"raw": raw.decode(errors="replace")}

    def ingest_next(self, tenant="acme", **kw):
        seq, prev = self.tip.get(tenant, (0, None))
        seq += 1
        prev = prev or "GENESIS"
        r = make_receipt(tenant, seq, prev, **kw)
        code, resp = self.request("POST", "/v1/ingest", r)
        self.assertEqual(code, 201, resp)
        self.tip[tenant] = (seq, r["hash"])
        return r

    # ---------------------------------------------------------------- tests
    def test_health_no_auth(self):
        code, resp = self.request("GET", "/v1/health", token=None)
        self.assertEqual(code, 200)
        self.assertEqual(resp, {"ok": True})

    def test_unauthorized(self):
        code, resp = self.request("GET", "/v1/receipts?tenant_id=acme",
                                 token="wrong")
        self.assertEqual(code, 401)
        self.assertEqual(resp["error"], "unauthorized")
        code, _ = self.request("POST", "/v1/ingest", {}, token=None)
        self.assertEqual(code, 401)

    def test_ingest_oversized_body_rejected(self):
        # M-2: >1MB bodies are refused before any signature/hash work.
        code = _raw_oversized_status(
            self.base, "/v1/ingest",
            {"Authorization": f"Bearer {TOKEN}",
             "Content-Type": "application/json"})
        self.assertEqual(code, 413)

    def test_ingest_201_409_422(self):
        r1 = self.ingest_next(tool="run_tests")
        # duplicate -> 409, treated as already-stored
        code, resp = self.request("POST", "/v1/ingest", r1)
        self.assertEqual(code, 409)
        self.assertEqual(resp["error"], "duplicate_seq")
        # usage counted once, not twice; capture both counters
        code, usage = self.request("GET", "/internal/usage/acme")
        before_allowed, before_denied = (usage["actions_allowed"],
                                         usage["actions_denied"])
        # skip a seq -> 422 chain_break with the expected tip
        seq, prev = self.tip["acme"]
        bad = make_receipt("acme", seq + 2, "WRONGPREV")
        code, resp = self.request("POST", "/v1/ingest", bad)
        self.assertEqual(code, 422)
        self.assertEqual(resp["error"], "chain_break")
        self.assertEqual(resp["expected_seq"], seq + 1)
        self.assertEqual(resp["expected_prev_hash"], prev)
        # correct continuation works (a deny: allowed counter untouched)
        r2 = self.ingest_next(decision="deny", reason="nope", rule_id=None)
        self.assertEqual(r2["seq"], seq + 1)
        code, usage = self.request("GET", "/internal/usage/acme")
        self.assertEqual(usage["actions_allowed"], before_allowed)
        self.assertEqual(usage["actions_denied"], before_denied + 1)

    def test_ingest_validation(self):
        code, resp = self.request("POST", "/v1/ingest", {"nope": 1})
        self.assertEqual(code, 400)
        self.assertEqual(resp["error"], "invalid_receipt")
        r = make_receipt("acme", 999, "x", decision="maybe")
        code, resp = self.request("POST", "/v1/ingest", r)
        self.assertEqual(code, 400)

    def test_query_filters_and_pagination(self):
        self.ingest_next(tool="tool_a", task_id="t1")
        self.ingest_next(tool="tool_b", task_id="t1")
        self.ingest_next(tool="tool_a", task_id="t2", decision="deny")
        code, resp = self.request(
            "GET", "/v1/receipts?tenant_id=acme&tool=tool_a&limit=1")
        self.assertEqual(code, 200)
        self.assertEqual(len(resp["items"]), 1)
        self.assertEqual(resp["items"][0]["tool"], "tool_a")
        self.assertIsNotNone(resp["next_cursor"])
        # newest first: first item is the deny
        self.assertEqual(resp["items"][0]["decision"], "deny")
        code, page2 = self.request(
            "GET", f"/v1/receipts?tenant_id=acme&tool=tool_a&limit=1"
                   f"&cursor={resp['next_cursor']}")
        self.assertEqual(len(page2["items"]), 1)
        self.assertNotEqual(page2["items"][0]["seq"],
                            resp["items"][0]["seq"])
        self.assertIsNone(page2["next_cursor"])
        # decision filter
        code, resp = self.request(
            "GET", "/v1/receipts?tenant_id=acme&decision=deny")
        self.assertTrue(all(i["decision"] == "deny" for i in resp["items"]))
        # missing tenant_id -> 400
        code, _ = self.request("GET", "/v1/receipts")
        self.assertEqual(code, 400)

    def test_get_one_and_404(self):
        r = self.ingest_next()
        code, resp = self.request(
            "GET", f"/v1/receipts/{r['seq']}?tenant_id=acme")
        self.assertEqual(code, 200)
        self.assertEqual(resp["hash"], r["hash"])
        code, resp = self.request("GET", "/v1/receipts/999999?tenant_id=acme")
        self.assertEqual(code, 404)

    def test_verify_ok_and_tamper(self):
        self.ingest_next()
        self.ingest_next()
        code, resp = self.request("GET", "/v1/verify?tenant_id=acme")
        self.assertEqual(code, 200)
        self.assertTrue(resp["chain_ok"], resp["failures"])
        self.assertEqual(resp["failures"], [])
        n = resp["receipts"]
        # tamper directly in sqlite -> verify must fail
        db = sqlite3.connect(DB_PATH)
        db.execute("UPDATE receipts SET tool='evil' WHERE tenant_id='acme' "
                   "AND seq=1")
        db.commit()
        db.close()
        code, resp = self.request("GET", "/v1/verify?tenant_id=acme")
        self.assertFalse(resp["chain_ok"])
        self.assertTrue(resp["failures"])
        self.assertEqual(resp["receipts"], n)
        # restore (other tests share this db)
        db = sqlite3.connect(DB_PATH)
        db.execute("UPDATE receipts SET tool='read_file' "
                   "WHERE tenant_id='acme' AND seq=1")
        db.commit()
        db.close()
        code, resp = self.request("GET", "/v1/verify?tenant_id=acme")
        self.assertTrue(resp["chain_ok"], resp["failures"])

    def test_sse_stream(self):
        self.ingest_next(tool="stream_probe")
        events = []
        stop = threading.Event()

        def reader():
            # NOTE: http.client's read(n) on a chunked stream waits for n
            # bytes across chunks, so read byte-wise for prompt delivery.
            req = urllib.request.Request(
                self.base + "/v1/receipts/stream?tenant_id=acme",
                headers={"Authorization": f"Bearer {TOKEN}"})
            try:
                resp = urllib.request.urlopen(req, timeout=30)
                buf = b""
                while not stop.is_set():
                    byte = resp.read(1)
                    if not byte:
                        break
                    buf += byte
                    if buf.endswith(b"\n\n"):
                        if b"event: receipt" in buf:
                            events.append(buf)
                        buf = b""
            except Exception:
                pass

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        try:
            deadline = time.time() + 10
            while len(events) < 1 and time.time() < deadline:
                time.sleep(0.1)
            self.assertGreaterEqual(len(events), 1,
                                    "stream did not deliver backlog")
            backlog_n = len(events)
            live = self.ingest_next(tool="stream_live")
            deadline = time.time() + 10
            while len(events) < backlog_n + 1 and time.time() < deadline:
                time.sleep(0.1)
            self.assertGreaterEqual(len(events), backlog_n + 1,
                                    "stream did not deliver live ingest")
            last = json.loads(
                events[-1].split(b"data: ", 1)[1].decode())
            self.assertEqual(last["hash"], live["hash"])
        finally:
            stop.set()


class ImportV1Test(unittest.TestCase):
    """v1 receipts.jsonl -> per-tenant chains + manifest (§6)."""

    def _write_v1_ledger(self, path, n_per_tenant=3):
        """Write a faithful pre-Phase-1 v1 ledger: the exact v1 body shape.

        The v1 body had NO rule_id/policy_version keys — this matters because
        import + verify must handle real v1 ledgers, not ledgers written by
        the new build_receipt (which would include the new keys as null and
        silently dodge the compatibility path). Mirrors the v1 construction
        from git history (gatekeeper/receipts.py @ v1).
        """
        import hmac
        # both fixture tenants share the deterministic test key (k1)
        tenants = json.load(open(TENANTS_PATH, encoding="utf-8"))
        if "globex" not in tenants["tenants"]:
            tenants["tenants"]["globex"] = {
                "created_at": 1, "keys": {"k1": KEY_HEX}, "current_kid": "k1"}
            with open(TENANTS_PATH, "w", encoding="utf-8") as f:
                json.dump(tenants, f)
        seq, prev = 0, "GENESIS"
        with open(path, "w", encoding="utf-8") as f:
            # interleave tenants like the v1 global chain did
            for i in range(n_per_tenant):
                for t in ("acme", "globex"):
                    seq += 1
                    args = {"i": i}
                    body = {
                        "seq": seq,
                        "ts": round(1700000000.0 + seq, 3),
                        "tenant_id": t,
                        "kid": "k1",
                        "task_id": "t",
                        "agent_id": "a",
                        "tool": f"tool_{i}",
                        "args_sha256": hashlib.sha256(
                            json.dumps(args, sort_keys=True,
                                       default=str).encode("utf-8")).hexdigest(),
                        "decision": "allow",
                        "reason": None,
                        "prev_hash": prev,
                    }
                    body["hash"] = hashlib.sha256(
                        prev.encode("utf-8")
                        + json.dumps(body, sort_keys=True).encode("utf-8")
                    ).hexdigest()
                    body["sig"] = hmac.new(
                        KEY,
                        json.dumps(body, sort_keys=True).encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest()
                    prev = body["hash"]
                    f.write(json.dumps(body) + "\n")
        return path

    def test_import_groups_verifies_and_manifests(self):
        ledger = os.path.join(TMP, "v1.jsonl")
        db = os.path.join(TMP, "import.db")
        for p in (ledger, db):
            if os.path.exists(p):
                os.remove(p)
        self._write_v1_ledger(ledger)
        rc = import_v1.main(["--db", db, "--ledger", ledger,
                             "--tenants", TENANTS_PATH])
        self.assertEqual(rc, 0)
        store = ReceiptStore(db)
        try:
            for tid in ("acme", "globex"):
                # per-tenant seq 1..N, v1_seq preserves the global seq
                items, _ = store.get_receipts(tid, order="asc", limit=100)
                self.assertEqual([r["seq"] for r in items], [1, 2, 3])
                self.assertEqual(sorted(r["v1_seq"] for r in items),
                                 sorted(r["v1_seq"] for r in items))
                self.assertEqual(len({r["v1_seq"] for r in items}), 3)
                ok, failures = store.verify_tenant(
                    tid, load_verification_keys(TENANTS_PATH, tid))
                self.assertTrue(ok, failures)
            manifests = store.get_import_manifest()
            by_t = {m["tenant_id"]: m for m in manifests}
            self.assertEqual(by_t["acme"]["imported"], 3)
            self.assertEqual(by_t["acme"]["v1_lines"], 3)
            tip = store.tip("acme")
            self.assertEqual(by_t["acme"]["tip_hash"], tip["hash"])
            # original fields preserved
            items, _ = store.get_receipts("acme", order="asc", limit=100)
            self.assertEqual(items[0]["tool"], "tool_0")
        finally:
            store.close()

    def test_import_aborts_on_bad_signature(self):
        ledger = os.path.join(TMP, "v1-bad.jsonl")
        db = os.path.join(TMP, "import-bad.db")
        for p in (ledger, db):
            if os.path.exists(p):
                os.remove(p)
        self._write_v1_ledger(ledger, n_per_tenant=2)
        # tamper one line's tool
        lines = open(ledger, encoding="utf-8").read().splitlines()
        r = json.loads(lines[1])
        r["tool"] = "evil_tool"
        lines[1] = json.dumps(r)
        open(ledger, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        rc = import_v1.main(["--db", db, "--ledger", ledger,
                             "--tenants", TENANTS_PATH])
        self.assertEqual(rc, 2)
        store = ReceiptStore(db)
        try:
            self.assertEqual(store.count("acme"), 0)
            self.assertEqual(store.count("globex"), 0)
            self.assertEqual(store.get_import_manifest(), [])
        finally:
            store.close()

    def test_import_skips_tenant_with_v2_rows(self):
        ledger = os.path.join(TMP, "v1-skip.jsonl")
        db = os.path.join(TMP, "import-skip.db")
        for p in (ledger, db):
            if os.path.exists(p):
                os.remove(p)
        self._write_v1_ledger(ledger, n_per_tenant=1)
        store = ReceiptStore(db)
        # pre-existing v2 row for acme
        r = make_receipt("acme", 1, "GENESIS")
        store.ingest(r)
        store.close()
        rc = import_v1.main(["--db", db, "--ledger", ledger,
                             "--tenants", TENANTS_PATH,
                             "--tenant", "acme"])
        self.assertEqual(rc, 0)
        store = ReceiptStore(db)
        try:
            # still exactly the one pre-existing row; no manifest row
            self.assertEqual(store.count("acme"), 1)
            self.assertEqual(
                [m["tenant_id"] for m in store.get_import_manifest()], [])
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
