"""Gatekeeper -> receipt service emitter (§4.2).

Every policy decision is emitted to the receipt service as a per-tenant
chained, tenant-key-signed receipt via POST /v1/ingest.

Trust boundary (non-negotiable): the enforcement path never depends on the
network. On ANY ingest failure the receipt falls back to the existing local
ReceiptLog file append (v1 behavior), and the service-bound receipt is
spooled for a background flusher that retries in per-tenant seq order.

Semantics:
  - 201: stored. 409 duplicate_seq: the seq is taken — if the stored receipt
    is byte-identical to ours it is a retried success; otherwise we lost a
    seq race (another writer) and the decision is spooled for a fresh seq.
  - 422 chain_break: re-sync the tenant tip
    (GET /v1/receipts?tenant_id=&limit=1&order=desc), rebuild the receipt
    off the fresh tip, retry once; still failing -> spool.
  - While a tenant has spooled receipts, new ones skip the live attempt
    (head-of-line blocking) so per-tenant seq order can never invert.
  - While a flush is in flight for a tenant, new emits spool instead of
    fast-pathing, so the flusher's batch and a live emit can never assign
    the same seq.
  - The local v1 file is the durable spool of record; the in-memory queue
    holds the service-bound fields and is rebuilt off the service tip at
    flush time, so a restart re-syncs instead of guessing seqs.

Env:
    RECEIPT_SVC_URL       receipt service base (default http://127.0.0.1:9001)
                          empty string disables remote ingest entirely
                          (local file only — used by the v1 demo path)
    RECEIPT_SVC_TOKEN     bearer token for /v1/ingest (default "")
    RECEIPT_FLUSH_INTERVAL seconds between flusher passes (default 5.0)
"""
import json
import os
import threading
import time
import urllib.request
import urllib.error
from collections import deque

from .receipts import build_receipt

SVC_URL = os.environ.get("RECEIPT_SVC_URL", "http://127.0.0.1:9001")
SVC_TOKEN = os.environ.get("RECEIPT_SVC_TOKEN", "")
FLUSH_INTERVAL = float(os.environ.get("RECEIPT_FLUSH_INTERVAL", "5.0"))
_HTTP_TIMEOUT = 5


class ReceiptEmitter:
    """Emits per-tenant receipts to the receipt service with file fallback."""

    def __init__(self, registry, local_log, svc_url=SVC_URL, svc_token=SVC_TOKEN,
                 flush_interval=FLUSH_INTERVAL):
        self.registry = registry
        self.local_log = local_log
        self.svc_url = (svc_url or "").rstrip("/")
        self.svc_token = svc_token
        self.flush_interval = flush_interval
        self._lock = threading.Lock()
        # tenant_id -> {"next_seq": int, "tip": str|None}; None tip = unknown
        self._state = {}
        # tenant_id -> deque of field-dicts awaiting ingest (seq assigned at flush)
        self._spool = {}
        # tenants with a flush batch in flight: emit() spools instead of
        # fast-pathing for these, so a live emit and the flusher can never
        # build receipts off the same tip state (duplicate seq race)
        self._flushing = set()
        self._stop = threading.Event()
        self._flusher = threading.Thread(
            target=self._flush_loop, name="receipt-flusher", daemon=True
        )
        self._flusher.start()

    # ------------------------------------------------------------------ api
    def emit(self, *, tenant_id, task_id, agent_id, tool, args, decision,
             reason=None, rule_id=None, policy_version=None):
        """Emit one decision. Returns a receipt-like dict with a 'seq' key.

        Fast path ingests to the service; any failure (or a non-empty spool
        for the tenant) falls back to the local v1 file append + spooling.
        The returned seq is the service seq on success, else the local seq.
        """
        fields = dict(
            tenant_id=tenant_id, task_id=task_id, agent_id=agent_id,
            tool=tool, args=args, decision=decision, reason=reason,
            rule_id=rule_id, policy_version=policy_version,
        )
        with self._lock:
            if (self.svc_url and not self._spool.get(tenant_id)
                    and tenant_id not in self._flushing):
                receipt = self._build(fields)
                outcome = self._try_ingest(receipt)
                if outcome == "ok":
                    self._commit(receipt)
                    return receipt
                if outcome == "duplicate" and \
                        self._resolve_duplicate(receipt):
                    # retried success: the stored bytes are ours
                    self._commit(receipt)
                    return receipt
                if outcome == "chain_break":
                    if self._resync_locked(tenant_id):
                        receipt = self._build(fields)
                        if self._try_ingest(receipt) == "ok":
                            self._commit(receipt)
                            return receipt
            # fallback: durable local v1 append + spool for later flush.
            # ("duplicate" that is not ours also lands here: the decision
            # still needs its own receipt, with a fresh seq next pass.)
            local = self.local_log.record(**fields)
            self._spool.setdefault(tenant_id, deque()).append(fields)
            return {"seq": local["seq"], "local_fallback": True, **local}

    def spooled(self, tenant_id=None):
        """How many receipts are waiting for flush (test/debug hook)."""
        with self._lock:
            if tenant_id is not None:
                return len(self._spool.get(tenant_id, ()))
            return sum(len(q) for q in self._spool.values())

    def flush_now(self):
        """Run one flush pass synchronously (tests)."""
        self._flush_pass()

    def close(self):
        self._stop.set()

    # ------------------------------------------------------- receipt crypto
    def _build(self, fields):
        """Build the service-bound receipt off cached tip state (lock held)."""
        tenant_id = fields["tenant_id"]
        st = self._state.get(tenant_id)
        seq = st["next_seq"] if st else 1
        prev = st["tip"] if st and st["tip"] else "GENESIS"
        kid, key = self.registry.signing_key(tenant_id)
        return build_receipt(
            seq=seq, prev_hash=prev, tenant_id=tenant_id, kid=kid, key=key,
            task_id=fields["task_id"], agent_id=fields["agent_id"],
            tool=fields["tool"], args=fields["args"],
            decision=fields["decision"], reason=fields["reason"],
            rule_id=fields["rule_id"], policy_version=fields["policy_version"],
        )

    def _commit(self, receipt):
        """Record a successful ingest in tip state (lock held)."""
        self._state[receipt["tenant_id"]] = {
            "next_seq": receipt["seq"] + 1,
            "tip": receipt["hash"],
        }

    # ------------------------------------------------------------- http io
    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.svc_token:
            h["Authorization"] = f"Bearer {self.svc_token}"
        return h

    def _try_ingest(self, receipt):
        """POST one receipt. Returns 'ok' | 'duplicate' | 'chain_break' | 'failed'.

        409 duplicate_seq means the seq is taken — the caller must check
        whether the stored bytes are ours (_resolve_duplicate). Never raises."""
        if not self.svc_url:
            return "failed"
        body = {k: v for k, v in receipt.items()}
        req = urllib.request.Request(
            self.svc_url + "/v1/ingest",
            data=json.dumps(body).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                code = resp.status
        except urllib.error.HTTPError as e:
            code = e.code
            try:
                err_body = json.loads(e.read().decode("utf-8") or "{}")
            except (ValueError, UnicodeDecodeError):
                err_body = {}
            if code == 409:
                return "duplicate"
            if code == 422 and err_body.get("error") == "chain_break":
                return "chain_break"
            return "failed"
        except Exception:  # noqa: BLE001 - any transport failure -> fallback
            return "failed"
        return "ok" if 200 <= code < 300 else "failed"

    def _resolve_duplicate(self, receipt):
        """409 follow-up: is the stored receipt byte-identical to ours?

        Compares the service's stored hash at (tenant_id, seq) with ours.
        True -> retried success, safe to commit tip. False -> another writer
        won the seq; our decision still needs its own receipt (spool it).
        Touches no shared state; safe under or outside the lock."""
        url = (self.svc_url +
               f"/v1/receipts/{receipt['seq']}?tenant_id={receipt['tenant_id']}")
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                stored = json.loads(resp.read().decode("utf-8"))
        except Exception:  # noqa: BLE001 - can't tell; spool and retry later
            return False
        return stored.get("hash") == receipt["hash"]

    def _query_tip(self, tenant_id):
        """(seq, hash) of the tenant's tip, or (0, None) if none. None on error."""
        if not self.svc_url:
            return None
        url = (self.svc_url +
               f"/v1/receipts?tenant_id={tenant_id}&limit=1&order=desc")
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception:  # noqa: BLE001
            return None
        items = data.get("items", [])
        if not items:
            return (0, None)
        return (items[0]["seq"], items[0]["hash"])

    def _resync_locked(self, tenant_id):
        """Refresh tip state from the service (lock held). False on error."""
        tip = self._query_tip(tenant_id)
        if tip is None:
            return False
        seq, h = tip
        self._state[tenant_id] = {"next_seq": seq + 1, "tip": h}
        return True

    # -------------------------------------------------------------- flusher
    def _flush_loop(self):
        while not self._stop.wait(self.flush_interval):
            try:
                self._flush_pass()
            except Exception:  # noqa: BLE001 - flusher must never die
                pass

    def _flush_pass(self):
        with self._lock:
            tenants = [t for t, q in self._spool.items() if q]
        for tenant_id in tenants:
            self._flush_tenant(tenant_id)

    def _flush_tenant(self, tenant_id):
        # Pop the whole tenant queue, then ingest outside the lock.
        # Field dicts (with raw args) are re-queued untouched on failure,
        # so args_sha256 stays byte-identical across retries. The _flushing
        # flag keeps live emit()s on the spool path while this batch is in
        # flight, so the flusher and a fast-path emit can never build two
        # receipts off the same tip state.
        with self._lock:
            queue = self._spool.get(tenant_id)
            if not queue or tenant_id in self._flushing:
                return
            self._flushing.add(tenant_id)
            if not self._resync_locked(tenant_id):
                self._flushing.discard(tenant_id)
                return  # service unreachable; try next pass
            batch = [queue.popleft() for _ in range(len(queue))]
        failed_at = None
        try:
            for i, fields in enumerate(batch):
                with self._lock:
                    receipt = self._build(fields)
                outcome = self._try_ingest(receipt)
                if outcome == "ok":
                    with self._lock:
                        self._commit(receipt)
                    continue
                if outcome == "duplicate" and \
                        self._resolve_duplicate(receipt):
                    with self._lock:
                        self._commit(receipt)
                    continue
                failed_at = i
                break
        finally:
            with self._lock:
                self._flushing.discard(tenant_id)
                if failed_at is not None:
                    # failure, chain_break, or a lost duplicate race: put
                    # this and the rest back at the FRONT, in order, and
                    # re-sync next pass
                    q = self._spool.setdefault(tenant_id, deque())
                    for fields in reversed(batch[failed_at:]):
                        q.appendleft(fields)
                    self._state.pop(tenant_id, None)  # force re-sync
