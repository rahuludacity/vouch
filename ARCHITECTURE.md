# Vouch — End-to-End Architecture

**Status:** spec. v1 (gatekeeper + per-tenant receipts) is shipped and stable; this document
defines everything built on top of it. Two crews build against the contracts below in parallel.

**Non-goals for this spec:** marketing copy, pricing page design, production hardening
(KMS, Postgres, multi-region). Local-first; see §10.

---

## 1. Service map

| Service | Path | Port | Owner | State |
|---|---|---|---|---|
| gatekeeper | `gatekeeper/` | 9000 | Crew A | **STABLE — extend, never rewrite** |
| policy engine v2 | `gatekeeper/policy_v2.py` (in-process lib) + policy store in control plane | — (lib) | Crew A | to build |
| receipt service | `services/receipts/` | 9001 | Crew A | to build |
| control plane | `services/controlplane/` | 9002 | Crew A | to build |
| agent runner | `services/runner/` | 9003 | Crew A | to build |
| dashboard | `web/dashboard/` | 3000 | Crew B | to build |
| billing | `services/billing/` | 9004 | Crew B | to build |

All services speak HTTP+JSON. Inter-service auth: bearer service tokens (see §8).
External tenants authenticate with `vouch_sk_*` API keys (see §8).

```
                       ┌──────────────┐
                       │   dashboard  │ :3000  (Crew B)
                       └──────┬───────┘
                              │ tenant API key
              ┌───────────────┼────────────────┐
              ▼               ▼                ▼
      ┌──────────────┐ ┌─────────────┐ ┌──────────────┐
      │ control plane│ │   receipt   │ │   billing    │
      │     :9002    │ │ service :9001│ │    :9004     │ (billing: Crew B)
      └──────┬───────┘ └──────▲──────┘ └──────┬───────┘
             │                │               │ Stripe test mode
             │ keys/policies  │ ingest        │ webhooks → control plane
             ▼                │
      ┌──────────────┐        │
      │  gatekeeper  │────────┘
      │     :9000    │  POST /v1/ingest (receipts)
      └──────┬───────┘
             │ MCP Streamable HTTP (unchanged v1 contract)
             ▼
      ┌──────────────┐      ┌──────────────┐
      │ agent runner │─────▶│  MCP tools   │
      │     :9003    │      │  (customer)  │
      └──────────────┘      └──────────────┘
```

**Trust boundary (non-negotiable):** the enforcement path — agent → gatekeeper policy
check → receipt signing — never depends on the network. Policy evaluation is an
in-process library call; receipt signing uses in-memory cached keys. The receipt
service, control plane, and billing are *observability and management*; if they are
down, the gatekeeper keeps enforcing with cached policy/keys and spools receipts
to its local file fallback.

---

## 2. Service boundaries

### 2.1 gatekeeper — STABLE (v1, commit `bd4a840`)

Unchanged external contract: `POST/GET/DELETE /mcp`, MCP Streamable HTTP, SSE/JSON
negotiation, `Mcp-Session-Id` relay, tenant via `X-Tenant-Id` → session binding →
`default`. Denials return JSON-RPC `-32000` and never reach upstream.

**v2 extensions only** (no rewrites, no signature changes to existing behavior):
1. Policy check for `tools/call` moves from inline `tool in allow[]` to
   `policy_v2.decide(task_id, tool, args)` (§5). Same deny-before-upstream guarantee.
2. Receipts are emitted to the receipt service via `POST /v1/ingest`. On any ingest
   failure, fall back to the existing local `ReceiptLog` file append (current behavior).
   A background flusher retries spooled receipts; order per tenant is preserved
   (flush in seq order).
3. Tenant keys: keep working exactly as today (file-backed `TenantRegistry`), but the
   **key authority moves to the control plane** in Phase 2. Gatekeeper caches keys in
   memory, refreshed from the control plane (§4.3). Until Phase 2 ships, the file
   registry is the authority — no behavior change.
4. New receipt fields `rule_id`, `policy_version` (§6). Nullable; v1 receipts verify
   without them.

### 2.2 policy engine v2

A **pure, deterministic, in-process library**: `gatekeeper/policy_v2.py`.
No network, no LLM, no exceptions-as-control-flow on the hot path.
The control plane owns the policy *store* (CRUD); the gatekeeper holds a cached
*copy* and evaluates locally. Language and migration: §5.

### 2.3 receipt service (`services/receipts/`, :9001)

Durable, per-tenant, tamper-evident receipt store + public verify API.
- Accepts already-signed receipts from gatekeepers (it never signs).
- Stores per-tenant hash chains (migration from the v1 global chain: §6).
- Serves queries, SSE live stream, and chain/signature verification.
- Tracks per-tenant monthly usage counters (feeds billing quotas).

### 2.4 control plane (`services/controlplane/`, :9002)

Tenant provisioning, key authority, policy CRUD, deployment CRUD, API key issuance,
quota/suspension state. SQLite locally (`data/controlplane.db`), schema migrates
cleanly to Postgres later (no SQLite-isms: no `AUTOINCREMENT` reliance, UTC epoch
timestamps as REAL, JSON columns as TEXT).

### 2.5 agent runner (`services/runner/`, :9003)

Runs customer agents sandboxed (local: Docker, one container per deployment,
no host network; only egress to `http://gatekeeper:9000`). Polls the control plane
for desired state; reports status back. Injects `GATEKEEPER_URL`, `VOUCH_TENANT_ID`,
`VOUCH_TASK_ID`, `VOUCH_AGENT_ID` into the agent environment so the agent's MCP
client routes through the gatekeeper with correct identity headers.

### 2.6 dashboard (`web/dashboard/`, :3000) — Crew B

Live action feed, audit trail search, policy editor, tenant/key management,
deployment controls, usage/billing views. Talks **only** to the control plane and
receipt service REST APIs with the tenant API key. Must run against stub servers
implementing §4 until Crew A ships — stubs are Crew B's responsibility.

### 2.7 billing (`services/billing/`, :9004) — Crew B

Stripe **test mode only**. Plan catalog (configurable, defaults):
`free` $0 — 10k actions/mo; `pro` $49/mo — 1M actions/mo; `team` $199/mo —
10M actions/mo + SSO + audit export. Metered dimension: **actions** =
`actions_allowed + actions_denied` from `usage_monthly`. Webhooks update
`tenants.plan`; over-quota → control plane sets `tenants.status='suspended'`,
which the gatekeeper enforces as deny-all (see §4.3 key-bundle `status` field).

---

## 3. Data models

SQLite locally; every table carries `created_at REAL` (UTC epoch). JSON columns are TEXT.

### receipts
Per-tenant chain. PK `(tenant_id, seq)`.
```
tenant_id TEXT, seq INTEGER, ts REAL, kid TEXT, task_id TEXT, agent_id TEXT,
tool TEXT, args_sha256 TEXT, decision TEXT ('allow'|'deny'), reason TEXT NULL,
rule_id TEXT NULL, policy_version INTEGER NULL,
prev_hash TEXT, hash TEXT, sig TEXT, ingested_at REAL
```
`prev_hash` chains **within tenant** (`GENESIS` for seq 1). Unique `(tenant_id, hash)`.

### policies
One row per `(tenant_id, task_id)`. PK `(tenant_id, task_id)`.
```
tenant_id TEXT, task_id TEXT, version INTEGER, rules_json TEXT,
updated_at REAL, updated_by TEXT
```
`rules_json`: `{"allow": [...], "deny": [...]}` per §5. Version increments on every
write; gatekeeper caches by version and the receipt records `policy_version`.

### tenants
```
id TEXT PK, name TEXT, plan TEXT ('free'|'pro'|'team'),
status TEXT ('active'|'suspended'), stripe_customer_id TEXT NULL, created_at REAL
```

### tenant_keys
```
tenant_id TEXT, kid TEXT, key_hex TEXT, is_current INTEGER (0/1),
created_at REAL, retired_at REAL NULL
```
PK `(tenant_id, kid)`. Invariant: exactly one `is_current=1` per tenant; at most
4 rows per tenant (current + 3 retired, mirrors v1 `MAX_PREVIOUS_KEYS`). Local file
perms equivalent: DB file `0600`. (Production later: KMS — not this spec.)

### api_keys
```
id TEXT PK, tenant_id TEXT, key_hash TEXT UNIQUE, name TEXT,
created_at REAL, revoked_at REAL NULL
```
Presented key format `vouch_sk_<32 hex chars>`; only `sha256(presented)` is stored.

### deployments
```
id TEXT PK, tenant_id TEXT, task_id TEXT, agent_image TEXT,
status TEXT ('pending'|'running'|'stopped'|'failed'),
container_id TEXT NULL, last_heartbeat REAL NULL, created_at REAL
```

### usage_monthly
```
tenant_id TEXT, month TEXT ('YYYY-MM'), actions_allowed INTEGER,
actions_denied INTEGER, updated_at REAL
```
PK `(tenant_id, month)`. Incremented by the receipt service on every accepted ingest.

### service_tokens (control plane only)
```
id TEXT PK, name TEXT, token_hash TEXT UNIQUE, scope TEXT, created_at REAL
```
Seeds one token per internal consumer (`receipt-service`, `runner`, `gatekeeper`,
`billing`) via `controlplane seed-tokens` CLI; distributed as env vars in compose.

---

## 4. API contracts

Conventions: JSON; errors `{"error": "<code>", "message": "<human>"}` with HTTP
status; pagination `?limit=&cursor=` → `{"items": [...], "next_cursor": "..."}`;
timestamps are UTC epoch seconds (REAL).

### 4.1 agent → gatekeeper (STABLE, v1 — do not change)

MCP Streamable HTTP on `:9000/mcp` exactly as v1: `POST` (JSON-RPC, SSE or JSON
response per `Accept`), `GET` (server-push stream), `DELETE` (session teardown).
Identity headers: `X-Tenant-Id`, `X-Agent-Id`, `X-Task-Id`. Denied `tools/call`
→ JSON-RPC error `-32000` with `receipt #<seq>` in the message.

### 4.2 gatekeeper → receipt service

`POST /v1/ingest` — service-token bearer.
Request: one receipt object (§3 `receipts`, minus `ingested_at`).
Responses: `201 {"tenant_id","seq","hash"}`; `409 {"error":"duplicate_seq"}` (gatekeeper
treats as success — already stored); `422 {"error":"chain_break","expected_prev_hash"}`
(gatekeeper re-syncs: queries `GET /v1/receipts?tenant_id=&limit=1&order=desc` for the
tip and replays its spool from there).
`GET /v1/health` → `{"ok": true}` (gatekeeper uses for circuit-breaking to file fallback).

### 4.3 control plane → gatekeeper (internal)

`GET /internal/tenants/{id}/key-bundle` — service-token bearer.
Response:
```json
{"tenant_id":"acme","status":"active","policy_version":7,
 "current_kid":"k3","keys":{"k1":"hex…","k2":"hex…","k3":"hex…"}}
```
Gatekeeper caches per tenant, TTL 60s, and treats `status != "active"` as deny-all
with reason `tenant suspended`. `policy_version` lets the gatekeeper detect policy
drift (see 4.4).
`POST /internal/cache/invalidate` `{"tenant_id":"acme"}` — control plane calls on
rotate/suspend/plan-change; best-effort (TTL is the backstop).

### 4.4 control plane ↔ policy store (gatekeeper pulls)

`GET /internal/policies/bundle?since_version=6` — service-token bearer.
Response: `{"version":7,"policies":{"deploy-staging":{"version":3,"rules_json":"…"},…}}`
Gatekeeper polls every 15s; applies only if `version` advances; evaluates with
`policy_v2`. Until Phase 2, gatekeeper uses `policy.yaml` (unchanged v1 behavior).
Receipts record the `policy_version` that decided them.

**Tenant-facing policy CRUD** (dashboard uses these, tenant API key bearer):
- `GET /v1/policies` → `{"tasks":{"deploy-staging":{"version":3,"rules":{…}},…}}`
- `PUT /v1/policies/{task_id}` body `{"rules":{"allow":[…],"deny":[…]}}`
  → `{"task_id","version":4}` (validates against §5 schema; rejects unknown constraint ops with `422`)
- `DELETE /v1/policies/{task_id}` → `204`

### 4.5 control plane — tenants, keys, API keys, deployments (tenant API key bearer unless noted)

- `POST /v1/tenants` `{"name":"Acme"}` → `{"tenant_id":"acme","api_key":"vouch_sk_…","plan":"free"}`
  (api_key shown once; only the hash is stored)
- `GET /v1/tenants/me` → `{"tenant_id","name","plan","status","usage":{"month":"2026-09","actions_allowed":…,"actions_denied":…}}`
- `POST /v1/tenants/me/rotate-keys` → `{"new_kid":"k4"}` (old keys stay verifiable; gatekeeper cache invalidated)
- `POST /v1/api-keys` `{"name":"ci"}` → `{"id","api_key":"vouch_sk_…"}`
- `DELETE /v1/api-keys/{id}` → `204`
- `POST /v1/deployments` `{"task_id":"deploy-staging","agent_image":"vouch/agent-demo:latest"}`
  → `{"deployment_id":"dep_…","status":"pending"}`
- `GET /v1/deployments` / `GET /v1/deployments/{id}` / `DELETE /v1/deployments/{id}` (→ stops container)
- Internal, service-token: `GET /internal/desired-state` → `{"deployments":[{"id","tenant_id","task_id","agent_image","desired":"running|stopped"}]}` (runner polls 10s)
- Internal, service-token: `POST /internal/deployments/{id}/status` `{"status":"running","container_id":"abc"}` → `200`

### 4.6 receipt service — tenant APIs (tenant API key bearer)

- `GET /v1/receipts?task_id=&tool=&decision=&agent_id=&limit=&cursor=` (cursor = `seq`)
  → `{"items":[receipt…],"next_cursor":"120"}` (newest first)
- `GET /v1/receipts/{seq}` → receipt or `404`
- `GET /v1/receipts/stream?task_id=` — **SSE**, `event: receipt` per new ingest for the tenant. Dashboard live feed subscribes here.
- `GET /v1/verify` → `{"tenant_id","receipts":N,"chain_ok":true,"failures":[]}`
  Chain verification is public-with-key: needs the tenant API key (keys stay server-side).
  Signature verification runs server-side against control-plane keys (4.7); failures listed per seq.
- Internal, service-token: `GET /internal/usage/{tenant_id}?month=YYYY-MM` → `{"actions_allowed":…,"actions_denied":…}` (billing reads this)

### 4.7 receipt service → control plane (internal)

`GET /internal/tenants/{id}/keys` — service-token bearer → `{"current_kid":"k3","keys":{"k1":"hex…",…}}`.
Receipt service never stores key material; it fetches on verify and caches 5 min.
(Consolidates key authority in the control plane; gatekeeper's 4.3 bundle is the
hot-path-optimized twin of this endpoint.)

### 4.8 billing ↔ control plane / Stripe

- Stripe webhook `POST /v1/stripe/webhook` (billing, raw body + signature check with test webhook secret) handles `checkout.session.completed`, `customer.subscription.updated|deleted` → billing calls control plane internal `POST /internal/tenants/{id}/plan` `{"plan":"pro"}` (service-token) → `200`.
- `POST /v1/billing/checkout` (tenant API key) `{"plan":"pro"}` → `{"checkout_url":"https://checkout.stripe.com/…(test)"}`.
- `GET /v1/billing/portal` → `{"portal_url":"…test…"}`.
- Billing reads quotas from receipt service 4.6-internal; dashboard shows usage from control plane `GET /v1/tenants/me` (which fans in to the receipt service — dashboard never calls billing for usage).

### 4.9 runner → gatekeeper (unchanged v1 agent contract)

The agent process inside the runner container is just an MCP client: it uses
`GATEKEEPER_URL` + identity env vars (§2.5) and speaks §4.1. No new contract.

---

## 5. Policy engine v2 — argument-aware policies

### 5.1 Language

```yaml
# stored as rules_json per (tenant_id, task_id); YAML shown for readability
version: 3
allow:
  - rule_id: "read-workspace"
    tool: read_file
    args:
      path: {prefix: "/workspace/"}
  - rule_id: "deploy-staging-build"
    tool: deploy_staging
    args:
      build: {regex: "^[0-9a-f]{6,40}$"}
      env:   {in: ["staging"]}
deny:
  - rule_id: "no-destructive"
    tool: delete_database
  - rule_id: "no-rm-rf"
    tool: exec
    args:
      cmd: {regex: "rm\\s+-rf"}
```

Constraint ops (closed set — unknown op → `422` on PUT, never evaluated):
`equals`, `prefix`, `regex` (RE2-style, no backtracking; compiled once at load),
`in` (list), `range` (`{min,max}`, numeric), `required` (arg must be present).
An `args` block matches iff **every** listed constraint matches (AND); a rule
matches iff tool matches AND args block matches (empty/missing `args` = tool-only,
v1 semantics). Omitted `args` key ≡ `{}`.

### 5.2 Evaluation (`policy_v2.decide(task_id, tool, args) -> (bool, reason|None, rule_id|None)`)

1. Unknown task → `(False, "unknown task '<id>'", None)` (v1 behavior preserved).
2. Any matching **deny** rule → `(False, "denied by rule '<rule_id>'", rule_id)`.
3. Any matching **allow** rule → `(True, None, rule_id)`.
4. Else → `(False, "task '<id>' is not granted tool '<tool>'", None)` (v1 message preserved).
Deterministic, no I/O, <1ms. `rule_id` and the policy `version` are recorded on the
receipt (§6).

### 5.3 Migration note — `policy.yaml` schema change (REQUIRED reading for Crew A)

v1 schema: `tasks.<id>.allow: ["tool_a", "tool_b"]`.
v2 schema: `tasks.<id>.rules: {allow: [{rule_id, tool, args?}…], deny: […]}`.

`gatekeeper/policy_v2.py` **must** ship `upgrade_v1_policy(v1_dict) -> v2_dict`:
every `- "tool"` becomes `- {rule_id: "v1-<tool>", tool: "<tool>"}` with no args
constraint and an empty `deny: []`. The gatekeeper loads v1 files through this
converter, so **existing `policy.yaml` files keep working byte-for-byte**; authors
can then add `args` constraints incrementally. `PUT /v1/policies/{task}` accepts
only v2 schema (the dashboard policy editor writes v2). The demo `policy.yaml`
stays v1-format as a permanent compatibility fixture — `tests/test_policy_v2.py`
must cover: v1 upgrade equivalence, deny-wins, arg constraints, unknown-op rejection.

---

## 6. Receipts v2 — durable per-tenant chains

v1 stored one global chain in `receipts.jsonl` (all tenants interleaved).
v2 chains **per tenant** in the receipt service DB (§3 `receipts`).

**Import migration** (`services/receipts/import_v1.py`, Crew A, Phase 1):
replays a v1 `receipts.jsonl`, groups by `tenant_id`, re-chains each tenant from
`GENESIS` preserving original `seq→(tenant_seq)`, `ts`, `hash`, `sig`, and
verifying every signature against the tenant's keys before import. Emits an
import manifest row per tenant: `{tenant_id, v1_lines, imported, tip_hash}`.
v1 `seq` is kept in a `v1_seq` side column for audit continuity; the v2 `seq`
is the per-tenant sequence. The original file is never modified.

New v2 receipt fields: `rule_id TEXT NULL`, `policy_version INTEGER NULL`
(recorded by the gatekeeper at decision time). v1 receipts verify without them.

**Verify semantics** (receipt service `GET /v1/verify`): replays the tenant chain
exactly like v1 `ReceiptLog.verify` (seq continuity, `prev_hash` linkage, body
hash, HMAC via `(tenant_id, kid)`), but keys come from the control plane (§4.7).
Chain check needs no secrets; signature check is server-side only.

---

## 7. Repo layout (target)

```
gatekeeper/            # STABLE core. v2 adds policy_v2.py + ingest client only.
  proxy.py             # v1, untouched except: decide() call, ingest emit, key-bundle cache
  policy_v2.py         # NEW (Crew A): language, decide(), upgrade_v1_policy()
  receipts.py          # v1, untouched (local fallback path)
  tenants.py           # v1; Phase 2: control plane imports registry logic for DB migration
  verify.py            # v1 CLI, untouched
services/
  receipts/            # NEW (Crew A, Phase 1)
    app.py             # HTTP: /v1/ingest, /v1/receipts*, /v1/verify, /internal/usage
    store.py           # SQLite schema + queries (§3)
    import_v1.py       # v1 receipts.jsonl → per-tenant chains (§6)
  controlplane/        # NEW (Crew A, Phase 2)
    app.py             # tenant/policy/deployment/API-key REST + internal endpoints
    models.py          # §3 tables: tenants, tenant_keys, api_keys, deployments, usage, service_tokens
    migrate_tenants.py # tenants.json → DB (keys preserved, kids preserved)
  runner/              # NEW (Crew A, Phase 3)
    app.py             # desired-state poll loop, docker lifecycle, status callbacks
    sandbox.py         # container spec: no host net, egress allowlist {gatekeeper}
  billing/             # NEW (Crew B, Phase 5)
    app.py             # checkout, portal, Stripe webhook (TEST MODE)
    plans.py           # plan catalog: free/pro/team quotas
web/
  dashboard/           # NEW (Crew B, Phase 4): feed, audit, policies, keys, deployments, usage
docs/                  # NEW (Crew B, Phase 6)
sdks/
  python/  js/         # NEW (Crew B, Phase 6): MCP client wrappers injecting identity headers
demo/                  # v1 demo stays; Phase 3 adds e2e demo via runner
docker-compose.yml     # NEW (Phase 1): all services, ports §1, named volumes
ARCHITECTURE.md        # this file
```

---

## 8. Auth model (three credential types — do not mix)

1. **Tenant API keys** `vouch_sk_*` — what customers put in dashboards/SDKs. Scope: their
   tenant only, on control-plane and receipt-service tenant endpoints.
2. **Service tokens** — long random bearers, one per internal consumer, minted by
   `controlplane seed-tokens`, injected as env (`RECEIPT_SVC_TOKEN`, `RUNNER_TOKEN`,
   `GATEKEEPER_SVC_TOKEN`, `BILLING_SVC_TOKEN`). Scope: `/internal/*` and `/v1/ingest` only.
3. **Stripe test keys** — billing only, `sk_test_*` / test webhook secret. Never leave test mode
   without Rahul's explicit approval (and never in this build phase at all).

Gatekeeper request identity stays header-based (`X-Tenant-Id` etc.) exactly as v1 —
the runner injects them from env; that path is unchanged.

---

## 9. Phased build plan + crew split

**Contract freeze:** §4 is frozen as of this document. Crew B builds dashboard/billing
against these contracts using local stubs from day one; Crew A must not break them
without a versioned `/v2` and a note here.

### Phase 1 — durable receipts + argument-aware policy (Crew A)
1. `services/receipts/`: store, ingest, query, SSE stream, verify, usage counters, v1 import.
2. `gatekeeper/policy_v2.py`: language (§5), `decide()`, `upgrade_v1_policy()`, tests.
3. Gatekeeper integration: `decide()` in `_handle_tools_call`; emit to receipt service
   with file fallback + ordered flusher; record `rule_id`/`policy_version`.
4. `docker-compose.yml`: gatekeeper + receipt service + demo upstream.
**Exit:** demo runs end-to-end with receipts in the service; `GET /v1/verify` green;
arg-constrained deny proven (e.g. `deploy_staging` with `env=prod` denied).

### Phase 2 — control plane (Crew A)
Tenant API, key authority (migrate `tenants.json` → DB, kids preserved), policy CRUD
+ bundle endpoint, API keys, deployments CRUD, service tokens, suspension state.
Gatekeeper switches to key-bundle cache (§4.3) with 60s TTL + invalidate hook.
**Exit:** `POST /v1/tenants` → deploy policy → gated calls → receipts, all via API.

### Phase 3 — agent runner (Crew A)
Docker sandbox, desired-state poll, status callbacks, env injection. E2E demo:
`POST /v1/deployments` → container runs agent → MCP through gatekeeper → receipts →
dashboard-visible. **Exit:** one-command e2e (`compose up` + deploy + verify).

### Phase 4 — dashboard (Crew B; starts as soon as this doc lands, against stubs)
Live feed (SSE), audit search, policy editor (writes v2 schema), key rotation UI,
deployment controls, usage view. **Exit:** click-through of the Phase 3 e2e entirely
in the UI.

### Phase 5 — billing (Crew B; needs Phase 1 usage API — stub it until then)
Stripe test mode: checkout, portal, webhooks → plan updates; quota display.
Crew A (small): wire `tenants.status='suspended'` → gatekeeper deny-all via key bundle.
**Exit:** test-mode subscribe → plan flips → over-quota tenant gets deny-all receipts.

### Phase 6 — docs, SDKs, quickstart (Crew B)
`docs/` (concepts, API reference from §4, self-host guide), `sdks/python|js`
(MCP client wrapper: `VouchClient(tenant_key, task_id)` injecting identity headers),
5-minute quickstart: `docker-compose up` → deploy demo agent → watch live feed →
export audit proof.

**Dependency order:** 1 → 2 → 3, then 4/5/6. Crew B phases 4–6 run **in parallel**
with Crew A phases 1–3 against the frozen contracts + stubs.

---

## 10. Hard constraints

1. **No AWS provisioning.** Everything runs on this VM via `docker-compose`. AWS enters
   only with Rahul's explicit spending approval — never implied, never "to unblock".
2. **Stripe test mode only.** No live keys, no real charges, ever, in this build.
3. **Trust core is stable.** `gatekeeper/proxy.py`, `receipts.py`, `tenants.py`,
   `verify.py` keep their v1 semantics; v2 extends via `policy_v2.py` and the ingest
   client. A change that alters a v1 receipt field's meaning or breaks `verify.py`
   on old ledgers is a spec violation — escalate, don't improvise.
4. **policy.yaml migration** is §5.3: v1 files load through `upgrade_v1_policy()`;
   byte-for-byte compatibility is a release gate.
5. **Keys stay server-side.** Tenant HMAC keys never appear in dashboard responses,
   logs, or the receipt stream. `rotate-keys` returns only the new `kid`.
6. **Deny before execute, always.** No async policy checks on the enforcement path;
   no "allow then audit". The receipt is written before the upstream call returns.
7. **Two-crew rule:** Crew A never blocks on Crew B's UI; Crew B never waits on
   Crew A's services (stubs). Integration happens at phase exits, against §4.
