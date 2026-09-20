# Vouch concepts

Vouch is the deployment layer for AI agents that need to be **governed**.
The whole company is one loop:

```
policy  →  enforcement  →  proof
```

1. **Policy** — you declare, per task, which tools an agent may call and under
   what argument constraints. Deny rules always win. Unknown tools and unknown
   tasks are denied by default.
2. **Enforcement** — the gatekeeper sits between your agent and its tools as a
   real MCP server. Every `tools/call` is checked against the cached policy
   *before* it can reach upstream. A denied call never leaves the proxy.
3. **Proof** — every decision, allow **and** deny, is written as a signed,
   hash-chained receipt. Anyone can replay the chain later and prove exactly
   what the agent did (or tried to do).

Signed receipts alone are a feature. The policy → enforcement → proof loop,
run by a neutral party across model and tool vendors, is the company.

## Tenants

Everything in Vouch is scoped to a **tenant**. A tenant has:

- an **API key** (`vouch_sk_…`) — the only credential customers use. The key
  *is* the tenant on every tenant endpoint; only its sha256 is stored, and
  the plaintext is shown exactly once at creation. Keys are **named** so CI,
  human, and per-service keys can be told apart and revoked individually.
- its **own HMAC signing key** (`kid` pins which key signed what). Keys rotate
  via `POST /v1/tenants/me/rotate-keys` — the response carries only the new
  `kid`; key material never leaves the server. Old kids stay verifiable, so
  historical receipts keep checking out after rotation.
- **policies** per task (v2 schema: `allow`/`deny` rules with argument
  constraints — see `ARCHITECTURE.md` §5).
- **deployments** — agent runs the runner sandboxes.

Tenant isolation is enforced at the key: every tenant endpoint derives the
tenant from the API key. An explicit `?tenant_id=` that doesn't match the
key's tenant is `403`. Cross-tenant forgery is impossible by construction —
receipts are HMAC-signed with the calling tenant's own key.

## The trust boundary

The enforcement path — agent → gatekeeper policy check → receipt signing —
**never depends on the network**:

- Policy evaluation is an in-process library call (`gatekeeper/policy_v2.py`).
- Receipt signing uses in-memory cached keys (control-plane key bundles,
  60s TTL).
- If the receipt service is unreachable, the gatekeeper spools receipts to a
  local file and a background flusher replays them in seq order. If the
  control plane is down, the gatekeeper serves the last key bundle/policy
  stale for up to 10 minutes, then fails closed (unknown tenant → deny).

The receipt service, control plane, dashboard, and billing are *observability
and management*. The gatekeeper keeps enforcing without them.

## Receipt chains

Each tenant has its own chain. A receipt is:

```json
{
  "seq": 7, "ts": 1758442800.123, "tenant_id": "acme", "kid": "k3",
  "task_id": "deploy-staging", "agent_id": "agent-001",
  "tool": "deploy_staging", "args_sha256": "9f2c…",
  "decision": "allow", "reason": null,
  "rule_id": "deploy-staging-build", "policy_version": 3,
  "prev_hash": "ab12…", "hash": "cd34…", "sig": "ef56…"
}
```

- `seq` is per-tenant, strictly increasing; `prev_hash` links to the previous
  receipt (`"GENESIS"` for seq 1). Insertion, deletion, or reordering breaks
  the chain.
- `hash = sha256(prev_hash ‖ canonical_json(body))`.
- `sig = HMAC-SHA256(tenant_key, canonical_json(body + hash))`.
- `args` are never stored raw — only their sha256 — so receipts are safe to
  hand to auditors.
- `rule_id` + `policy_version` record *which rule, of which policy version*
  made the decision.

Verification (`GET /v1/verify`, or the SDKs' `verify_chain`) replays all of
the above. Chain checks need no secrets; signature checks are server-side
only (keys stay server-side).

## Suspension is auditable

A suspended tenant's key bundle carries `status: "suspended"`; the gatekeeper
denies everything for that tenant — and **still writes receipts** for the
denials. Suspension itself leaves a paper trail.
