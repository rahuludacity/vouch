"""Vouch control plane data model (Phase 2, ARCHITECTURE.md §3).

SQLite locally, Postgres-ready: no SQLite-isms (UTC epoch REAL timestamps,
JSON columns as TEXT, no AUTOINCREMENT reliance). The DB file is chmod 0600
— it holds tenant HMAC key material. Thread-safe via a single RLock.

Tables: tenants, tenant_keys, api_keys, policies, deployments,
usage_monthly, service_tokens.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time

from gatekeeper import policy_v2

PLANS = ("free", "pro", "team")
STATUSES = ("active", "suspended")
DEPLOYMENT_STATUSES = ("pending", "running", "stopped", "failed")

API_KEY_PREFIX = "vouch_sk_"
SVC_TOKEN_PREFIX = "vouch_svc_"
MAX_KEYS_PER_TENANT = 4  # current + 3 retired, mirrors v1 tenants.json

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'free',
  status TEXT NOT NULL DEFAULT 'active',
  stripe_customer_id TEXT,
  policy_bundle_version INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tenant_keys (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  kid TEXT NOT NULL,
  key_hex TEXT NOT NULL,
  is_current INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL,
  retired_at REAL,
  PRIMARY KEY (tenant_id, kid)
);
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  key_hash TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  created_at REAL NOT NULL,
  revoked_at REAL
);
CREATE TABLE IF NOT EXISTS policies (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  task_id TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  rules_json TEXT NOT NULL,
  updated_at REAL NOT NULL,
  updated_by TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, task_id)
);
CREATE TABLE IF NOT EXISTS deployments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  task_id TEXT NOT NULL,
  agent_image TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  container_id TEXT,
  last_heartbeat REAL,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS usage_monthly (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  month TEXT NOT NULL,
  actions_allowed INTEGER NOT NULL DEFAULT 0,
  actions_denied INTEGER NOT NULL DEFAULT 0,
  updated_at REAL NOT NULL,
  PRIMARY KEY (tenant_id, month)
);
CREATE TABLE IF NOT EXISTS service_tokens (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  token_hash TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL DEFAULT 'internal',
  created_at REAL NOT NULL
);
"""


def _utcnow():
    return time.time()


def _sha256_hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def slugify(name):
    """'Acme Corp!' -> 'acme-corp'. Used for tenant ids."""
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return slug or "tenant"


def _validate_rules(rules):
    """Raise ValueError unless rules is a valid v2 policy rules mapping.

    Unknown constraint ops, bad rule shapes, etc. are rejected here —
    the app maps this to HTTP 422.
    """
    if not isinstance(rules, dict):
        raise ValueError("rules must be a mapping with 'allow'/'deny' lists")
    for side in ("allow", "deny"):
        items = rules.get(side, [])
        if not isinstance(items, list):
            raise ValueError(f"rules.{side} must be a list")
    try:
        # Full compile check: unknown ops, bad regexes, bad rule shapes
        # all raise policy_v2.PolicyError (a ValueError).
        policy_v2.Policy.from_dict(
            {"version": 1, "tasks": {"__validate__": {"version": 1, "rules": rules}}}
        )
    except policy_v2.PolicyError as e:
        raise ValueError(str(e))
    return {"allow": rules.get("allow", []), "deny": rules.get("deny", [])}


class ControlPlaneDB:
    def __init__(self, path):
        self.path = os.path.abspath(path)
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()
        os.chmod(self.path, 0o600)

    # ------------------------------------------------------------ internals
    def _one(self, sql, params=()):
        cur = self._conn.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row else None

    def _all(self, sql, params=()):
        return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def _write(self, sql, params=()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    # ---------------------------------------------------------------- tenants
    def create_tenant(self, name):
        """Create tenant + first HMAC key + first API key.

        Returns {"tenant_id", "api_key", "plan"}. The api_key plaintext is
        shown once — only its sha256 is stored.
        """
        if not isinstance(name, str) or not name.strip():
            raise ValueError("tenant name must be a non-empty string")
        base = slugify(name)
        with self._lock:
            tenant_id = base
            n = 2
            while self._one("SELECT id FROM tenants WHERE id = ?", (tenant_id,)):
                tenant_id = f"{base}-{n}"
                n += 1
            now = _utcnow()
            self._conn.execute(
                "INSERT INTO tenants (id, name, plan, status, created_at)"
                " VALUES (?, ?, 'free', 'active', ?)",
                (tenant_id, name.strip(), now),
            )
            key_hex = secrets.token_hex(32)  # 256-bit HMAC key
            self._conn.execute(
                "INSERT INTO tenant_keys (tenant_id, kid, key_hex, is_current,"
                " created_at) VALUES (?, 'k1', ?, 1, ?)",
                (tenant_id, key_hex, now),
            )
            self._conn.commit()
        api = self.create_api_key(tenant_id, "default")
        return {"tenant_id": tenant_id, "api_key": api["api_key"], "plan": "free"}

    def get_tenant(self, tenant_id):
        """Public tenant fields (never key material)."""
        t = self._one(
            "SELECT id, name, plan, status, stripe_customer_id,"
            " policy_bundle_version, created_at FROM tenants WHERE id = ?",
            (tenant_id,),
        )
        return t

    def get_tenant_by_api_key(self, plaintext):
        """Tenant row for a presented vouch_sk_* key, or None."""
        if not plaintext.startswith(API_KEY_PREFIX):
            return None
        row = self._one(
            "SELECT t.id, t.name, t.plan, t.status, t.stripe_customer_id,"
            " t.policy_bundle_version, t.created_at"
            " FROM api_keys k JOIN tenants t ON t.id = k.tenant_id"
            " WHERE k.key_hash = ? AND k.revoked_at IS NULL",
            (_sha256_hex(plaintext),),
        )
        return row

    def set_plan(self, tenant_id, plan):
        if plan not in PLANS:
            raise ValueError(f"unknown plan '{plan}' (allowed: {', '.join(PLANS)})")
        cur = self._write(
            "UPDATE tenants SET plan = ? WHERE id = ?", (plan, tenant_id)
        )
        return cur.rowcount > 0

    def set_status(self, tenant_id, status):
        if status not in STATUSES:
            raise ValueError(
                f"unknown status '{status}' (allowed: {', '.join(STATUSES)})"
            )
        cur = self._write(
            "UPDATE tenants SET status = ? WHERE id = ?", (status, tenant_id)
        )
        return cur.rowcount > 0

    # ------------------------------------------------------------------ keys
    def rotate_keys(self, tenant_id):
        """Mint a new current HMAC key; retired keys stay verifiable.

        Keeps at most MAX_KEYS_PER_TENANT (current + 3 retired), mirroring v1.
        Returns the new kid, or None for unknown tenant.
        """
        with self._lock:
            t = self._one("SELECT id FROM tenants WHERE id = ?", (tenant_id,))
            if not t:
                return None
            rows = self._all(
                "SELECT kid FROM tenant_keys WHERE tenant_id = ? ORDER BY"
                " CAST(SUBSTR(kid, 2) AS INTEGER)",
                (tenant_id,),
            )
            n = 1
            have = {r["kid"] for r in rows}
            while f"k{n}" in have:
                n += 1
            new_kid = f"k{n}"
            now = _utcnow()
            self._conn.execute(
                "UPDATE tenant_keys SET is_current = 0, retired_at = ?"
                " WHERE tenant_id = ? AND is_current = 1",
                (now, tenant_id),
            )
            self._conn.execute(
                "INSERT INTO tenant_keys (tenant_id, kid, key_hex, is_current,"
                " created_at) VALUES (?, ?, ?, 1, ?)",
                (tenant_id, new_kid, secrets.token_hex(32), now),
            )
            # prune oldest retired beyond the keep window
            rows = self._all(
                "SELECT kid, is_current FROM tenant_keys WHERE tenant_id = ?"
                " ORDER BY CAST(SUBSTR(kid, 2) AS INTEGER)",
                (tenant_id,),
            )
            retired = [r["kid"] for r in rows if not r["is_current"]]
            for kid in retired[: max(0, len(retired) - (MAX_KEYS_PER_TENANT - 1))]:
                self._conn.execute(
                    "DELETE FROM tenant_keys WHERE tenant_id = ? AND kid = ?",
                    (tenant_id, kid),
                )
            self._conn.commit()
            return new_kid

    def get_keys(self, tenant_id):
        """{"current_kid", "keys": {kid: key_hex}} — key material, server-side only."""
        rows = self._all(
            "SELECT kid, key_hex, is_current FROM tenant_keys WHERE tenant_id = ?",
            (tenant_id,),
        )
        if not rows:
            return None
        current = next((r["kid"] for r in rows if r["is_current"]), None)
        return {
            "current_kid": current,
            "keys": {r["kid"]: r["key_hex"] for r in rows},
        }

    def key_bundle(self, tenant_id):
        """The §4.3 key bundle (key material included — service-token only)."""
        t = self.get_tenant(tenant_id)
        if not t:
            return None
        keys = self.get_keys(tenant_id)
        return {
            "tenant_id": tenant_id,
            "status": t["status"],
            "policy_version": t["policy_bundle_version"],
            "current_kid": keys["current_kid"],
            "keys": keys["keys"],
        }

    # -------------------------------------------------------------- api keys
    def create_api_key(self, tenant_id, name):
        """Returns {"id", "api_key"} — plaintext shown once, hash stored."""
        if not isinstance(name, str) or not name.strip():
            raise ValueError("api key name must be a non-empty string")
        if not self.get_tenant(tenant_id):
            raise KeyError(f"unknown tenant '{tenant_id}'")
        key_id = "ak_" + secrets.token_hex(8)
        plaintext = API_KEY_PREFIX + secrets.token_hex(16)
        self._write(
            "INSERT INTO api_keys (id, tenant_id, key_hash, name, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (key_id, tenant_id, _sha256_hex(plaintext), name.strip(), _utcnow()),
        )
        return {"id": key_id, "api_key": plaintext}

    def list_api_keys(self, tenant_id):
        return self._all(
            "SELECT id, name, created_at, revoked_at FROM api_keys"
            " WHERE tenant_id = ? ORDER BY created_at",
            (tenant_id,),
        )

    def revoke_api_key(self, tenant_id, key_id):
        cur = self._write(
            "UPDATE api_keys SET revoked_at = ?"
            " WHERE id = ? AND tenant_id = ? AND revoked_at IS NULL",
            (_utcnow(), key_id, tenant_id),
        )
        if cur.rowcount:
            return True
        # already revoked or foreign: distinguish for 404 fidelity
        row = self._one(
            "SELECT id FROM api_keys WHERE id = ? AND tenant_id = ?",
            (key_id, tenant_id),
        )
        return "already_revoked" if row else False

    # --------------------------------------------------------------- policies
    def put_policy(self, tenant_id, task_id, rules, updated_by=""):
        """Store a v2 policy for (tenant, task). Returns the new task version.

        Raises KeyError (unknown tenant) or ValueError (bad rules -> 422).
        """
        if not isinstance(task_id, str) or not task_id.strip():
            raise ValueError("task_id must be a non-empty string")
        if not self.get_tenant(tenant_id):
            raise KeyError(f"unknown tenant '{tenant_id}'")
        rules = _validate_rules(rules)
        rules_json = json.dumps(rules, sort_keys=True)
        with self._lock:
            row = self._one(
                "SELECT version FROM policies WHERE tenant_id = ? AND task_id = ?",
                (tenant_id, task_id),
            )
            version = (row["version"] + 1) if row else 1
            now = _utcnow()
            if row:
                self._conn.execute(
                    "UPDATE policies SET version = ?, rules_json = ?,"
                    " updated_at = ?, updated_by = ?"
                    " WHERE tenant_id = ? AND task_id = ?",
                    (version, rules_json, now, updated_by, tenant_id, task_id),
                )
            else:
                self._conn.execute(
                    "INSERT INTO policies (tenant_id, task_id, version,"
                    " rules_json, updated_at, updated_by)"
                    " VALUES (?, ?, 1, ?, ?, ?)",
                    (tenant_id, task_id, rules_json, now, updated_by),
                )
            self._conn.execute(
                "UPDATE tenants SET policy_bundle_version ="
                " policy_bundle_version + 1 WHERE id = ?",
                (tenant_id,),
            )
            self._conn.commit()
            return version

    def get_policies(self, tenant_id):
        """{task_id: {"version", "rules"}} with rules as parsed dicts."""
        rows = self._all(
            "SELECT task_id, version, rules_json FROM policies WHERE tenant_id = ?",
            (tenant_id,),
        )
        return {
            r["task_id"]: {"version": r["version"], "rules": json.loads(r["rules_json"])}
            for r in rows
        }

    def delete_policy(self, tenant_id, task_id):
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM policies WHERE tenant_id = ? AND task_id = ?",
                (tenant_id, task_id),
            )
            if cur.rowcount:
                self._conn.execute(
                    "UPDATE tenants SET policy_bundle_version ="
                    " policy_bundle_version + 1 WHERE id = ?",
                    (tenant_id,),
                )
                self._conn.commit()
                return True
            return False

    def policy_bundle(self, tenant_id, since_version=0):
        """(bundle_version, {task_id: {"version", "rules_json"}}).

        When the bundle hasn't advanced past since_version, the task map is
        empty — the gatekeeper applies a bundle only if the version advances.
        """
        t = self.get_tenant(tenant_id)
        if not t:
            return None
        version = t["policy_bundle_version"]
        if version <= since_version:
            return version, {}
        rows = self._all(
            "SELECT task_id, version, rules_json FROM policies WHERE tenant_id = ?",
            (tenant_id,),
        )
        return version, {
            r["task_id"]: {"version": r["version"], "rules_json": r["rules_json"]}
            for r in rows
        }

    # ------------------------------------------------------------ deployments
    def create_deployment(self, tenant_id, task_id, agent_image):
        if not isinstance(task_id, str) or not task_id.strip():
            raise ValueError("task_id must be a non-empty string")
        if not isinstance(agent_image, str) or not agent_image.strip():
            raise ValueError("agent_image must be a non-empty string")
        if not self.get_tenant(tenant_id):
            raise KeyError(f"unknown tenant '{tenant_id}'")
        dep_id = "dep_" + secrets.token_hex(8)
        self._write(
            "INSERT INTO deployments (id, tenant_id, task_id, agent_image,"
            " status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)",
            (dep_id, tenant_id, task_id.strip(), agent_image.strip(), _utcnow()),
        )
        return {"deployment_id": dep_id, "status": "pending"}

    def list_deployments(self, tenant_id):
        return self._all(
            "SELECT id, task_id, agent_image, status, container_id,"
            " last_heartbeat, created_at FROM deployments WHERE tenant_id = ?"
            " ORDER BY created_at",
            (tenant_id,),
        )

    def get_deployment(self, tenant_id, dep_id):
        return self._one(
            "SELECT id, task_id, agent_image, status, container_id,"
            " last_heartbeat, created_at FROM deployments"
            " WHERE id = ? AND tenant_id = ?",
            (dep_id, tenant_id),
        )

    def stop_deployment(self, tenant_id, dep_id):
        cur = self._write(
            "UPDATE deployments SET status = 'stopped' WHERE id = ? AND tenant_id = ?",
            (dep_id, tenant_id),
        )
        return cur.rowcount > 0

    def set_deployment_status(self, dep_id, status, container_id=None):
        if status not in DEPLOYMENT_STATUSES:
            raise ValueError(f"unknown deployment status '{status}'")
        cur = self._write(
            "UPDATE deployments SET status = ?, container_id = COALESCE(?, container_id),"
            " last_heartbeat = ? WHERE id = ?",
            (status, container_id, _utcnow(), dep_id),
        )
        return cur.rowcount > 0

    def desired_state(self):
        """What the runner should converge to (§4.5 internal)."""
        rows = self._all(
            "SELECT id, tenant_id, task_id, agent_image, status FROM deployments"
        )
        return [
            {
                "id": r["id"],
                "tenant_id": r["tenant_id"],
                "task_id": r["task_id"],
                "agent_image": r["agent_image"],
                "desired": "running"
                if r["status"] in ("pending", "running")
                else "stopped",
            }
            for r in rows
        ]

    # ---------------------------------------------------------- service tokens
    def seed_service_token(self, name, scope="internal"):
        """Mint a token; returns plaintext (shown once) or None if name taken."""
        if not isinstance(name, str) or not name.strip():
            raise ValueError("service token name must be a non-empty string")
        token_id = "st_" + secrets.token_hex(8)
        plaintext = SVC_TOKEN_PREFIX + secrets.token_hex(32)
        try:
            self._write(
                "INSERT INTO service_tokens (id, name, token_hash, scope, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (token_id, name.strip(), _sha256_hex(plaintext), scope, _utcnow()),
            )
        except sqlite3.IntegrityError:
            return None
        return plaintext

    def validate_service_token(self, plaintext):
        """-> token name, or None. Constant-time comparison."""
        if not plaintext:
            return None
        digest = _sha256_hex(plaintext)
        rows = self._all("SELECT name, token_hash FROM service_tokens")
        for r in rows:
            if hmac.compare_digest(r["token_hash"], digest):
                return r["name"]
        return None

    # ------------------------------------------------------------------ usage
    def get_usage(self, tenant_id, month):
        row = self._one(
            "SELECT actions_allowed, actions_denied FROM usage_monthly"
            " WHERE tenant_id = ? AND month = ?",
            (tenant_id, month),
        )
        if row:
            return dict(row)
        return {"actions_allowed": 0, "actions_denied": 0}

    # -------------------------------------------------------------- migration
    def migrate_tenants_file(self, tenants_path):
        """Import a v1 tenants.json registry, preserving kids and key history.

        Returns {"migrated": [tenant_id...], "skipped": [...],
                 "api_keys": {tenant_id: plaintext}} — one fresh API key per
        migrated tenant (printed by the CLI, shown once).
        """
        with open(os.path.abspath(tenants_path), "r", encoding="utf-8") as f:
            data = json.load(f).get("tenants", {})
        migrated, skipped, api_keys = [], [], {}
        for tid, t in data.items():
            if self.get_tenant(tid):
                skipped.append(tid)
                continue
            kids = t.get("keys", {})
            if not kids:
                skipped.append(tid)
                continue
            current_kid = t.get("current_kid") or sorted(kids)[0]
            created = t.get("created_at", _utcnow())
            with self._lock:
                self._conn.execute(
                    "INSERT INTO tenants (id, name, plan, status, created_at)"
                    " VALUES (?, ?, 'free', 'active', ?)",
                    (tid, tid, created),
                )
                for kid, key_hex in kids.items():
                    self._conn.execute(
                        "INSERT INTO tenant_keys (tenant_id, kid, key_hex,"
                        " is_current, created_at) VALUES (?, ?, ?, ?, ?)",
                        (tid, kid, key_hex, 1 if kid == current_kid else 0,
                         created),
                    )
                self._conn.commit()
            api = self.create_api_key(tid, "migrated")
            api_keys[tid] = api["api_key"]
            migrated.append(tid)
        return {"migrated": migrated, "skipped": skipped, "api_keys": api_keys}
