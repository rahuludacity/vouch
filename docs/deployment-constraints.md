# Verifier deployment constraints (M-1)

The verifier keeps nonce, rate-limit, and spend state in process memory.
This document is the explicit deployment contract for that state: what is
durable, what resets, how single-instance is enforced, and the exact
restart procedure. It is normative — violating it silently weakens
replay protection and spending controls.

## 1. The contract

1. **Exactly one verifier instance** per `VERIFIER_STATE_DIR`.
   Enforced at startup with an `flock(LOCK_EX|LOCK_NB)` on
   `<state_dir>/verifier.lock`. A second instance exits 2 immediately
   with `error: another verifier instance holds ...` on stderr. There
   is no active/standby, no rolling pair: the nonce/rate/spend tables
   live in one process and two writers would silently diverge them.
2. **State directory** (`VERIFIER_STATE_DIR`, default
   `<repo>/verifier-state`, mode 0700) holds:
   - `verifier.lock` — the instance lock (flock, held for process life).
   - `verifier-boot.json` — the durable boot floor:
     `{"boot_ts", "instance_id", "started_at"}`. Written atomically
     (tmp + rename) BEFORE the first request is served.
3. **Receipts, the transparency log, and the manifest are durable**
   (append-only files); they are unaffected by restarts.

## 2. What survives a restart and what does not

| State | Survives restart? | Consequence of reset |
|---|---|---|
| Nonce table | No (in-memory) | Closed by the boot floor (§3) — no replay window |
| Per-principal / per-agent rate counters | No (in-memory) | Limits restart from zero for the current day bucket (fail-open, bounded: one daily bucket) |
| Spend counters | No (in-memory) | Daily ceilings restart from zero (fail-open, bounded: one daily ceiling per credential+action) |
| Boot floor (`verifier-boot.json`) | Yes | Monotonic; never moves backward |
| Instance lock | Released by the OS on process death | A crashed holder never wedges the lock |
| Receipts / transparency log / manifest | Yes (files) | None |

The fail-open resets (rate, spend) are accepted prototype behavior:
each is bounded to a single day bucket/ceiling, and the alternative —
durable counters — is the production hardening step (§6). What is NOT
accepted is a replay window, which is why the boot floor exists.

## 3. The boot floor (replay-on-restart guard)

Threat: the nonce table is wiped by a restart. A request captured
before the restart has a still-fresh `ts` (inside `CLOCK_SKEW`) and a
now-unknown nonce, so without a guard it would verify after the
restart — a genuine replay.

Guard: on every boot the verifier records `boot_ts =
max(wall_clock, previous boot_ts)` and denies any request with `ts <
boot_ts` (`replay: request predates verifier boot`). `ts` is part of
the signed envelope, so a captured request's `ts` cannot be bumped
past the floor. The `max()` makes the floor monotonic: a backward
clock step (NTP) can never reopen the window — requests just fail
closed until the clock catches up.

Operational cost: legitimate requests sent just before a crash are
rejected after the restart. Clients must retry with a fresh `ts` and
a fresh `nonce` (they already must on any nonce rejection).

## 4. Restart procedure

1. Stop the verifier (SIGTERM). The OS releases the instance lock;
   nothing needs draining — receipts are already in the append-only
   file and the nonce/rate/spend tables are intentionally ephemeral.
2. Start exactly one new instance pointing at the same
   `VERIFIER_STATE_DIR`. It will:
   - take the instance lock (fails fast with exit 2 if one is held),
   - write a new `verifier-boot.json` with a monotonic `boot_ts`,
   - print `verifier boot instance_id=... boot_ts=... state_dir=...`.
3. Verify: `GET /v1/health` responds, and the boot line is in the log.
4. Expect `replay: request predates verifier boot` denies for a few
   minutes from clients holding pre-restart requests; they retry.

Do NOT: run two instances against one state dir (the second exits 2 —
treat that as an alarm, not a retry loop); delete `verifier-boot.json`
(it would reset the floor and reopen the replay window); share one
state dir across hosts (flock is local — one dir per host).

## 5. Detecting violations

- **Second instance started**: exit code 2 + the stderr line
  `error: another verifier instance holds <path>`. Alert on it.
- **Clock stepped backward**: a run of `replay: request predates
  verifier boot` denies with no recent restart in the log means the
  floor is ahead of the clock — check NTP; the verifier is failing
  closed, which is the safe direction.
- **Boot floor file tampered/deleted**: the next boot starts the floor
  at the current wall clock. Deletion is equivalent to a manual floor
  reset — restrict write access to the state dir (0700) to the
  verifier's own user.

## 6. Gatekeeper outbox (known limitation)

The gatekeeper's `ReceiptEmitter` spools receipts bound for the central
receipt service in memory when ingest fails; the local append-only file
is the durable record of every decision. The in-memory spool does NOT
survive a restart: receipts that were spooled but not yet flushed are
never retried to the central service after a reboot (they remain in the
local file). Restart procedure for the gatekeeper: after a restart,
reconcile the local receipt file against the central service and
re-submit any decision receipts the service is missing. Making the
outbox itself durable (persistent queue with per-receipt ingest
tracking) is the production hardening step, alongside SQLite-backed
nonce/rate/spend state for the verifier.
