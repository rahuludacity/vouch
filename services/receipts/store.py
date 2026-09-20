"""Durable per-tenant receipt store (SQLite) — §3 data models.

Tables:
  receipts        per-tenant hash chains. PK (tenant_id, seq).
                  v1_seq: original global seq for rows imported from a v1
                  receipts.jsonl (audit continuity); NULL for native v2 rows.
  usage_monthly   per-tenant monthly action counters (feeds billing quotas).
                  PK (tenant_id, month). Incremented on every accepted ingest.
  import_manifest one row per tenant imported from v1 (§6).

SQLite locally; UTC epoch timestamps as REAL, JSON columns as TEXT, no
SQLite-isms that block a later Postgres move (plain INTEGER PKs, no
AUTOINCREMENT reliance).
"""
import hashlib
import hmac
import json
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts (
    tenant_id      TEXT NOT NULL,
    seq            INTEGER NOT NULL,
    v1_seq         INTEGER NULL,
    ts             REAL NOT NULL,
    kid            TEXT NOT NULL,
    task_id        TEXT NOT NULL,
    agent_id       TEXT NOT NULL,
    tool           TEXT NOT NULL,
    args_sha256    TEXT NOT NULL,
    decision       TEXT NOT NULL,           -- 'allow' | 'deny'
    reason         TEXT NULL,
    rule_id        TEXT NULL,
    policy_version INTEGER NULL,
    prev_hash      TEXT NOT NULL,
    hash           TEXT NOT NULL,
    sig            TEXT NOT NULL,
    ingested_at    REAL NOT NULL,
    PRIMARY KEY (tenant_id, seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_tenant_hash
    ON receipts (tenant_id, hash);
CREATE INDEX IF NOT EXISTS idx_receipts_tenant_task
    ON receipts (tenant_id, task_id, seq);
CREATE INDEX IF NOT EXISTS idx_receipts_tenant_tool
    ON receipts (tenant_id, tool, seq);

CREATE TABLE IF NOT EXISTS usage_monthly (
    tenant_id      TEXT NOT NULL,
    month          TEXT NOT NULL,           -- 'YYYY-MM' (UTC)
    actions_allowed INTEGER NOT NULL DEFAULT 0,
    actions_denied  INTEGER NOT NULL DEFAULT 0,
    updated_at     REAL NOT NULL,
    PRIMARY KEY (tenant_id, month)
);

CREATE TABLE IF NOT EXISTS import_manifest (
    tenant_id   TEXT PRIMARY KEY,
    v1_lines    INTEGER NOT NULL,
    imported    INTEGER NOT NULL,
    tip_hash    TEXT NOT NULL,
    imported_at REAL NOT NULL
);
"""

RECEIPT_FIELDS = (
    "tenant_id", "seq", "v1_seq", "ts", "kid", "task_id", "agent_id",
    "tool", "args_sha256", "decision", "reason", "rule_id",
    "policy_version", "prev_hash", "hash", "sig", "ingested_at",
)


class ChainBreak(Exception):
    def __init__(self, expected_seq, expected_prev_hash):
        super().__init__("chain break")
        self.expected_seq = expected_seq
        self.expected_prev_hash = expected_prev_hash


class DuplicateSeq(Exception):
    pass


class ReceiptStore:
    """Thread-safe SQLite receipt store."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        # check_same_thread=False: guarded by self._lock everywhere.
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(SCHEMA)
            self._db.commit()

    # ------------------------------------------------------------ ingest
    def ingest(self, receipt):
        """Store one gatekeeper-signed receipt.

        Returns the stored row dict. Raises DuplicateSeq if (tenant_id, seq)
        already exists, ChainBreak(expected_seq, expected_prev_hash) if the
        receipt does not continue the tenant tip.
        """
        tenant_id = receipt["tenant_id"]
        seq = receipt["seq"]
        with self._lock:
            cur = self._db.execute(
                "SELECT hash FROM receipts WHERE tenant_id=? AND seq=?",
                (tenant_id, seq),
            )
            if cur.fetchone():
                raise DuplicateSeq()
            tip = self._db.execute(
                "SELECT seq, hash FROM receipts WHERE tenant_id=? "
                "ORDER BY seq DESC LIMIT 1",
                (tenant_id,),
            ).fetchone()
            if tip is None:
                exp_seq, exp_prev = 1, "GENESIS"
            else:
                exp_seq, exp_prev = tip["seq"] + 1, tip["hash"]
            if seq != exp_seq or receipt["prev_hash"] != exp_prev:
                raise ChainBreak(exp_seq, exp_prev)
            now = time.time()
            self._db.execute(
                """INSERT INTO receipts
                   (tenant_id, seq, v1_seq, ts, kid, task_id, agent_id, tool,
                    args_sha256, decision, reason, rule_id, policy_version,
                    prev_hash, hash, sig, ingested_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (tenant_id, seq, receipt.get("v1_seq"), receipt["ts"],
                 receipt["kid"], receipt["task_id"], receipt["agent_id"],
                 receipt["tool"], receipt["args_sha256"], receipt["decision"],
                 receipt.get("reason"), receipt.get("rule_id"),
                 receipt.get("policy_version"), receipt["prev_hash"],
                 receipt["hash"], receipt["sig"], now),
            )
            month = time.strftime("%Y-%m", time.gmtime(now))
            col = ("actions_allowed" if receipt["decision"] == "allow"
                   else "actions_denied")
            self._db.execute(
                f"""INSERT INTO usage_monthly
                    (tenant_id, month, actions_allowed, actions_denied, updated_at)
                    VALUES (?,?,0,0,?)
                    ON CONFLICT(tenant_id, month) DO NOTHING""",
                (tenant_id, month, now),
            )
            self._db.execute(
                f"UPDATE usage_monthly SET {col}={col}+1, updated_at=? "
                "WHERE tenant_id=? AND month=?",
                (now, tenant_id, month),
            )
            self._db.commit()
            row = self._db.execute(
                "SELECT * FROM receipts WHERE tenant_id=? AND seq=?",
                (tenant_id, seq),
            ).fetchone()
            return dict(row)

    # ------------------------------------------------------------- queries
    def get_receipts(self, tenant_id, *, task_id=None, tool=None,
                     decision=None, agent_id=None, limit=50, cursor=None,
                     order="desc"):
        """Newest-first page. cursor = seq; next page continues below it."""
        limit = max(1, min(int(limit or 50), 500))
        order = "DESC" if str(order).lower() != "asc" else "ASC"
        where = ["tenant_id=?"]
        params = [tenant_id]
        for col, val in (("task_id", task_id), ("tool", tool),
                         ("decision", decision), ("agent_id", agent_id)):
            if val is not None:
                where.append(f"{col}=?")
                params.append(val)
        if cursor is not None:
            where.append("seq < ?" if order == "DESC" else "seq > ?")
            params.append(int(cursor))
        with self._lock:
            rows = self._db.execute(
                f"SELECT * FROM receipts WHERE {' AND '.join(where)} "
                f"ORDER BY seq {order} LIMIT ?",
                (*params, limit + 1),
            ).fetchall()
        items = [dict(r) for r in rows[:limit]]
        next_cursor = str(items[-1]["seq"]) if len(rows) > limit else None
        return items, next_cursor

    def get_receipt(self, tenant_id, seq):
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM receipts WHERE tenant_id=? AND seq=?",
                (tenant_id, int(seq)),
            ).fetchone()
        return dict(row) if row else None

    def tip(self, tenant_id):
        with self._lock:
            row = self._db.execute(
                "SELECT seq, hash FROM receipts WHERE tenant_id=? "
                "ORDER BY seq DESC LIMIT 1",
                (tenant_id,),
            ).fetchone()
        return dict(row) if row else None

    def count(self, tenant_id):
        with self._lock:
            row = self._db.execute(
                "SELECT COUNT(*) AS n FROM receipts WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
        return row["n"]

    # -------------------------------------------------------------- verify
    # The exact key set the pre-Phase-1 v1 code signed. Imported v1 rows
    # re-verify against this body (with the global v1 seq): rule_id and
    # policy_version are v2 additions that never were part of a v1 body,
    # so they must be excluded even though the columns store NULL.
    _V1_BODY_KEYS = ("seq", "ts", "tenant_id", "kid", "task_id", "agent_id",
                     "tool", "args_sha256", "decision", "reason", "prev_hash")

    def verify_tenant(self, tenant_id, keys):
        """Replay the tenant chain like v1 ReceiptLog.verify.

        keys: {kid: key_bytes} for signature checks (server-side only).
        Imported v1 rows (v1_seq NOT NULL) keep their original prev_hash /
        hash / sig: their tamper-evidence rests on the HMAC (verified here
        and at import time); we additionally require v1_seq strictly
        increasing so imported history cannot be reordered silently.
        Returns (ok, failures); failures are {"seq", "error"} dicts.
        """
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM receipts WHERE tenant_id=? ORDER BY seq ASC",
                (tenant_id,),
            ).fetchall()
        rows = [dict(r) for r in rows]
        failures = []
        prev_hash, prev_v1_seq = "GENESIS", None
        for want_seq, r in enumerate(rows, start=1):
            seq = r["seq"]
            if seq != want_seq:
                failures.append({"seq": seq,
                                 "error": f"seq break (want {want_seq})"})
            imported = r["v1_seq"] is not None
            if imported:
                if prev_v1_seq is not None and r["v1_seq"] <= prev_v1_seq:
                    failures.append({"seq": seq,
                                     "error": "imported v1_seq out of order"})
                prev_v1_seq = r["v1_seq"]
            else:
                if seq == 1:
                    if r["prev_hash"] != "GENESIS":
                        failures.append({"seq": seq,
                                         "error": "chain break at genesis"})
                elif r["prev_hash"] != prev_hash:
                    failures.append({"seq": seq, "error": "chain break"})
            # v1_seq / ingested_at are store-side bookkeeping, never signed.
            # Imported v1 rows re-verify against their ORIGINAL v1 body
            # (global seq), which is what their preserved hash/sig cover.
            if r["v1_seq"] is not None:
                body = {k: r[k] for k in self._V1_BODY_KEYS}
                body["seq"] = r["v1_seq"]
            else:
                body = {k: v for k, v in r.items()
                        if k not in ("hash", "sig", "ingested_at", "v1_seq")}
            want_hash = hashlib.sha256(
                r["prev_hash"].encode("utf-8")
                + json.dumps(body, sort_keys=True).encode("utf-8")
            ).hexdigest()
            if r["hash"] != want_hash:
                failures.append({"seq": seq,
                                 "error": "hash mismatch (tampered body?)"})
            kid = r.get("kid")
            key = keys.get(kid) if kid else None
            if key is None:
                failures.append({"seq": seq,
                                 "error": f"unknown key id '{kid}'"})
            else:
                want_sig = hmac.new(
                    key,
                    json.dumps({**body, "hash": r["hash"]},
                               sort_keys=True).encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                if not hmac.compare_digest(want_sig, r["sig"]):
                    failures.append({"seq": seq, "error": "bad signature"})
            prev_hash = r["hash"]
        return (len(failures) == 0), failures

    # --------------------------------------------------------------- usage
    def get_usage(self, tenant_id, month=None):
        if month is None:
            month = time.strftime("%Y-%m", time.gmtime())
        with self._lock:
            row = self._db.execute(
                "SELECT actions_allowed, actions_denied FROM usage_monthly "
                "WHERE tenant_id=? AND month=?",
                (tenant_id, month),
            ).fetchone()
        if row:
            return {"tenant_id": tenant_id, "month": month,
                    "actions_allowed": row["actions_allowed"],
                    "actions_denied": row["actions_denied"]}
        return {"tenant_id": tenant_id, "month": month,
                "actions_allowed": 0, "actions_denied": 0}

    # ------------------------------------------------------ v1 migration
    # (insert_imported: v1-migration row writer; manifest methods below)
    def has_receipts(self, tenant_id):
        return self.count(tenant_id) > 0

    def insert_imported(self, receipt, v1_seq):
        """Insert one v1-migrated row: all original fields preserved
        (prev_hash/hash/sig/ts), v2 seq assigned per tenant, v1_seq kept
        for audit continuity. No chain checks (the v1 chain values are
        historical); signatures MUST be verified by the caller first.
        Imported rows do not count toward usage_monthly (historical)."""
        with self._lock:
            self._db.execute(
                """INSERT INTO receipts
                   (tenant_id, seq, v1_seq, ts, kid, task_id, agent_id, tool,
                    args_sha256, decision, reason, rule_id, policy_version,
                    prev_hash, hash, sig, ingested_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (receipt["tenant_id"], receipt["seq"], v1_seq, receipt["ts"],
                 receipt["kid"], receipt["task_id"], receipt["agent_id"],
                 receipt["tool"], receipt["args_sha256"], receipt["decision"],
                 receipt.get("reason"), receipt.get("rule_id"),
                 receipt.get("policy_version"), receipt["prev_hash"],
                 receipt["hash"], receipt["sig"], time.time()),
            )
            self._db.commit()
    def record_import_manifest(self, tenant_id, v1_lines, imported, tip_hash):
        with self._lock:
            self._db.execute(
                """INSERT INTO import_manifest
                   (tenant_id, v1_lines, imported, tip_hash, imported_at)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(tenant_id) DO UPDATE SET
                     v1_lines=excluded.v1_lines, imported=excluded.imported,
                     tip_hash=excluded.tip_hash,
                     imported_at=excluded.imported_at""",
                (tenant_id, v1_lines, imported, tip_hash, time.time()),
            )
            self._db.commit()

    def get_import_manifest(self, tenant_id=None):
        with self._lock:
            if tenant_id:
                rows = self._db.execute(
                    "SELECT * FROM import_manifest WHERE tenant_id=?",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = self._db.execute("SELECT * FROM import_manifest").fetchall()
        return [dict(r) for r in rows]

    def close(self):
        with self._lock:
            self._db.close()
