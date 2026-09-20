"""Billing persistence (Phase 5, §2.7/§4.8).

SQLite tables — every row carries created_at REAL (UTC epoch), per §3:

  customers          tenant_id PK, stripe_customer_id, email
  subscriptions      one row per Stripe subscription: tenant, stripe_sub_id,
                     plan, status, current_period_end
  checkout_sessions  stripe checkout session id -> tenant/plan, lifecycle
  webhook_events     processed Stripe event ids (idempotency — Stripe
                     redelivers; every event is applied at most once)
  quota_state        per-tenant reconcile watermark: whether *billing*
                     suspended the tenant (so we only ever unsuspend our own
                     suspensions — never a human operator's)
"""
import os
import sqlite3
import threading
import time

HERE = os.path.dirname(__file__)
DEFAULT_DB = os.environ.get("BILLING_DB") or os.path.join(
    HERE, "..", "..", "data", "billing.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS customers (
    tenant_id          TEXT PRIMARY KEY,
    stripe_customer_id TEXT NOT NULL UNIQUE,
    email              TEXT,
    created_at         REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS subscriptions (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id          TEXT NOT NULL,
    stripe_sub_id      TEXT NOT NULL UNIQUE,
    plan               TEXT NOT NULL,
    status             TEXT NOT NULL,
    current_period_end REAL,
    created_at         REAL NOT NULL,
    updated_at         REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS checkout_sessions (
    stripe_session_id  TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL,
    plan               TEXT NOT NULL,
    status             TEXT NOT NULL,   -- open | completed | expired
    created_at         REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS webhook_events (
    event_id           TEXT PRIMARY KEY,
    type               TEXT NOT NULL,
    received_at        REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS quota_state (
    tenant_id            TEXT PRIMARY KEY,
    suspended_by_billing INTEGER NOT NULL DEFAULT 0,
    last_actions         INTEGER NOT NULL DEFAULT 0,
    last_check           REAL
);
"""


class BillingDB:
    def __init__(self, path=None):
        self.path = path or DEFAULT_DB
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(SCHEMA)
            self._db.commit()

    # ------------------------------------------------------------ customers
    def upsert_customer(self, tenant_id, stripe_customer_id, email=None):
        with self._lock:
            self._db.execute(
                """INSERT INTO customers (tenant_id, stripe_customer_id,
                                          email, created_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(tenant_id) DO UPDATE SET
                     stripe_customer_id=excluded.stripe_customer_id,
                     email=COALESCE(excluded.email, customers.email)""",
                (tenant_id, stripe_customer_id, email, time.time()))
            self._db.commit()

    def get_customer(self, tenant_id):
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM customers WHERE tenant_id=?",
                (tenant_id,)).fetchone()
        return dict(row) if row else None

    def all_tenant_ids(self):
        with self._lock:
            rows = self._db.execute(
                "SELECT tenant_id FROM customers").fetchall()
        return [r["tenant_id"] for r in rows]

    # -------------------------------------------------------- subscriptions
    def upsert_subscription(self, tenant_id, stripe_sub_id, plan, status,
                            current_period_end=None):
        now = time.time()
        with self._lock:
            self._db.execute(
                """INSERT INTO subscriptions
                     (tenant_id, stripe_sub_id, plan, status,
                      current_period_end, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(stripe_sub_id) DO UPDATE SET
                     plan=excluded.plan, status=excluded.status,
                     current_period_end=excluded.current_period_end,
                     updated_at=excluded.updated_at""",
                (tenant_id, stripe_sub_id, plan, status,
                 current_period_end, now, now))
            self._db.commit()

    def active_subscription(self, tenant_id):
        """Newest non-canceled subscription for the tenant, or None."""
        with self._lock:
            row = self._db.execute(
                """SELECT * FROM subscriptions
                   WHERE tenant_id=? AND status NOT IN ('canceled')
                   ORDER BY id DESC LIMIT 1""",
                (tenant_id,)).fetchone()
        return dict(row) if row else None

    def get_subscription_by_stripe_id(self, stripe_sub_id):
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM subscriptions WHERE stripe_sub_id=?",
                (stripe_sub_id,)).fetchone()
        return dict(row) if row else None

    # ---------------------------------------------------- checkout sessions
    def create_checkout_session(self, stripe_session_id, tenant_id, plan):
        with self._lock:
            self._db.execute(
                """INSERT INTO checkout_sessions
                     (stripe_session_id, tenant_id, plan, status, created_at)
                   VALUES (?, ?, ?, 'open', ?)""",
                (stripe_session_id, tenant_id, plan, time.time()))
            self._db.commit()

    def get_checkout_session(self, stripe_session_id):
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM checkout_sessions WHERE stripe_session_id=?",
                (stripe_session_id,)).fetchone()
        return dict(row) if row else None

    def complete_checkout_session(self, stripe_session_id):
        with self._lock:
            cur = self._db.execute(
                """UPDATE checkout_sessions SET status='completed'
                   WHERE stripe_session_id=? AND status='open'""",
                (stripe_session_id,))
            self._db.commit()
            return cur.rowcount > 0

    # ------------------------------------------------------ webhook events
    def event_seen(self, event_id, event_type):
        """True if already processed (idempotency guard)."""
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM webhook_events WHERE event_id=?",
                (event_id,)).fetchone()
            if row:
                return True
            self._db.execute(
                "INSERT INTO webhook_events (event_id, type, received_at)"
                " VALUES (?, ?, ?)",
                (event_id, event_type, time.time()))
            self._db.commit()
            return False

    def unclaim_event(self, event_id):
        """Release an idempotency claim so a failed handler can be retried
        on Stripe redelivery (the claim is only re-inserted on success)."""
        with self._lock:
            self._db.execute(
                "DELETE FROM webhook_events WHERE event_id=?", (event_id,))
            self._db.commit()

    # ---------------------------------------------------------- quota state
    def set_suspended_by_billing(self, tenant_id, suspended, actions):
        with self._lock:
            self._db.execute(
                """INSERT INTO quota_state
                     (tenant_id, suspended_by_billing, last_actions, last_check)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(tenant_id) DO UPDATE SET
                     suspended_by_billing=excluded.suspended_by_billing,
                     last_actions=excluded.last_actions,
                     last_check=excluded.last_check""",
                (tenant_id, 1 if suspended else 0, actions, time.time()))
            self._db.commit()

    def get_quota_state(self, tenant_id):
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM quota_state WHERE tenant_id=?",
                (tenant_id,)).fetchone()
        return dict(row) if row else None
