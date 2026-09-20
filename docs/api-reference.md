# API reference

The frozen contracts (`ARCHITECTURE.md` §4) in one page. All services speak
HTTP+JSON; errors are `{"error": "<code>", "message": "<human>"}` with an
HTTP status; timestamps are UTC epoch seconds.

Three credential types — do not mix (§8):

| credential | shape | scope |
|---|---|---|
| tenant API key | `vouch_sk_<32 hex>` | tenant endpoints on control plane, receipt service, billing |
| service token | long random bearer (env) | `/internal/*` and `/v1/ingest` only |
| Stripe test keys | `sk_test_*` | billing only — never leaves test mode |

Ports: gatekeeper `:9000`, receipts `:9001`, control plane `:9002`,
dashboard `:3000`, billing `:9004`.

---

## Agent → gatekeeper (`:9000`, unchanged v1)

MCP Streamable HTTP at `POST/GET/DELETE /mcp`. Identity headers:

- `X-Tenant-Id` (unknown tenant → `403`)
- `X-Agent-Id`
- `X-Task-Id` — the policy scope; unknown task → deny

Only `tools/call` is policy-gated. Denied calls return JSON-RPC error
`-32000` with `receipt #<seq>` in the message and never reach upstream.
`initialize` returns a real `Mcp-Session-Id` (relayed from upstream);
`Accept: application/json, text/event-stream` gets SSE, `Accept:
application/json` gets a single JSON object.

---

## Control plane (`:9002`)

### Tenants (tenant API key, except provisioning)

- `POST /v1/tenants` — body `{"name":"Acme"}` →
  `{"tenant_id":"acme","api_key":"vouch_sk_…","plan":"free"}`.
  No auth. Key plaintext shown **once**; only its sha256 is stored.
- `GET /v1/tenants/me` →
  `{"tenant_id","name","plan","status","usage":{"month":"2026-09","actions_allowed":…,"actions_denied":…}}`.
  `usage` is fanned in from the receipt service — this is the one place to
  read usage; never ask billing.
- `POST /v1/tenants/me/rotate-keys` → `{"new_kid":"k4"}`. Key material never
  leaves the server; old kids keep verifying (current + 3 retired).

### Policies (tenant API key)

- `GET /v1/policies` → `{"tasks":{"deploy-staging":{"version":3,"rules":{…}},…}}`
- `PUT /v1/policies/{task_id}` — body `{"rules":{"allow":[…],"deny":[…]}}` →
  `{"task_id","version":4}`. v2 schema only (§5); unknown constraint ops →
  `422 invalid_policy`.
- `DELETE /v1/policies/{task_id}` → `204`

### API keys (tenant API key)

- `POST /v1/api-keys` — body `{"name":"ci"}` →
  `{"id","api_key":"vouch_sk_…","name":"ci"}` (plaintext shown once)
- `GET /v1/api-keys` → `{"keys":[{"id","name","created_at","revoked_at"},…]}`
  (metadata only — no hashes, no plaintext)
- `DELETE /v1/api-keys/{id}` → `204` (revokes; that key → `401` afterwards)

### Deployments (tenant API key)

- `POST /v1/deployments` — `{"task_id":"deploy-staging","agent_image":"vouch/agent-demo:latest"}`
  → `{"deployment_id":"dep_…","status":"pending"}`. The runner polls and
  sandboxes the agent.
- `GET /v1/deployments` / `GET /v1/deployments/{id}` / `DELETE /v1/deployments/{id}`
  (delete stops the container)

### Internal (service token)

- `GET /internal/tenants/{id}/key-bundle` → `{"tenant_id","status","policy_version","current_kid","keys":{kid:hex…}}`
  (gatekeeper hot path; 60s TTL, stale up to 10 min on outage, fail-closed)
- `GET /internal/tenants/{id}/keys` → `{"current_kid","keys":{…}}`
  (receipt service verify path)
- `GET /internal/policies/bundle?tenant_id=…&since_version=…` — `tenant_id`
  **required** (`400` if missing, `404` on unknown tenant)
- `POST /internal/cache/invalidate` — body `{"tenant_id":"…"}`
- `GET /internal/desired-state` → runner's poll target
- `POST /internal/deployments/{id}/status` — runner callbacks
- `POST /internal/tenants/{id}/plan` — body `{"plan":"pro"}` (billing webhook hook; `422 invalid_plan`)
- `POST /internal/tenants/{id}/status` — body `{"status":"suspended"}` (suspend/unsuspend; `422 invalid_status`)

---

## Receipt service (`:9001`)

Tenant endpoints derive the tenant from the API key; an explicit
`?tenant_id=` must match the key's tenant (`403` otherwise). Service tokens
pass `?tenant_id=` and it is required.

- `GET /v1/receipts?task_id=&tool=&decision=&agent_id=&limit=&cursor=` →
  `{"items":[receipt…],"next_cursor":"120"}` (newest first; cursor = seq)
- `GET /v1/receipts/{seq}` → receipt or `404`
- `GET /v1/receipts/stream?task_id=` — SSE, `event: receipt` per new ingest
- `GET /v1/verify` → `{"tenant_id","receipts":N,"chain_ok":true,"failures":[]}`
  (chain + signature check; keys stay server-side; rotation-race retry built in)
- `POST /v1/ingest` (service token) — one signed receipt → `201
  {"tenant_id","seq","hash"}`; `409 duplicate_seq` = success (already stored);
  `422 chain_break` (gatekeeper re-syncs from the tip and replays)
- `GET /internal/usage/{tenant_id}?month=YYYY-MM` (service token) →
  `{"actions_allowed":…,"actions_denied":…}`

---

## Runner (`:9003`)

No public HTTP API of its own — deployments are created on the control plane
(`POST /v1/deployments`) and the runner polls `GET /internal/desired-state`,
sandboxes one container per deployment (no host network, egress only to the
gatekeeper), and injects `GATEKEEPER_URL`, `VOUCH_TENANT_ID`, `VOUCH_TASK_ID`,
`VOUCH_AGENT_ID` into the agent environment.

---

## Dashboard (`:3000`)

Server-rendered pages + `/api/*` JSON mirrors of the frozen contracts above.
Auth: the tenant API key (paste once on `/login`, kept server-side in a
session; or set `DASHBOARD_API_KEY` for single-operator mode). State-changing
calls need the per-session CSRF token (`GET /api/csrf`).

- Pages: `/overview`, `/receipts` (+ `/receipts/{seq}`), `/policies`,
  `/deployments`, `/keys`
- JSON: `GET /api/overview`, `GET /api/verify`, `GET /api/receipts?…`,
  `GET /api/receipts/{seq}`, `GET /api/receipts/stream` (SSE),
  `GET/PUT/DELETE /api/policies[/{task}]`, `GET/POST /api/deployments[/{id}]`,
  `GET/POST /api/keys`, `POST /api/keys/rotate-signing`

---

## Billing (`:9004`, Stripe test mode only)

- `POST /v1/billing/checkout` — body `{"plan":"pro"}` →
  `{"checkout_url":"https://checkout.stripe.com/…(test)","session_id":"…","test_mode":true}`
- `GET /v1/billing/subscription` → current subscription view
- `GET /v1/billing/portal` → `{"portal_url":"…test…"}`
- `POST /v1/stripe/webhook` — Stripe-signed; handles
  `checkout.session.completed`, `customer.subscription.updated|deleted` →
  flips the tenant plan via the control plane
- `POST /internal/billing/reconcile` (service token) — over-quota tenants get
  suspended through the control plane; only billing-owned suspensions
  auto-reverse

Plans: `free` $0 — 10k actions/mo; `pro` $49/mo — 1M actions/mo; `team`
$199/mo — 10M actions/mo. Metered dimension: actions = allowed + denied,
from the receipt service.
