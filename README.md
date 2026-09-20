# Trust Plane — Prototype v0 ("Gatekeeper")

A working prototype of the Autonomous Systems Trust Plane thesis:
a neutral enforcement layer that intercepts agent tool calls, grants
**task-scoped capabilities**, and emits **tamper-evident signed receipts**
for every decision — including denials.

## The three primitives (this is the whole company in miniature)

1. **Interception** — the agent talks to the gatekeeper, not the tools.
   (`gatekeeper/proxy.py`, an MCP/JSON-RPC proxy on :9000)
2. **Task-scoped capabilities** — each task gets only the tools it needs.
   (`policy.yaml` — anything unlisted is denied)
3. **Verifiable receipts** — every allow AND deny gets a hash-chained,
   HMAC-signed receipt. (`gatekeeper/receipts.py`, `receipts.jsonl`)

## Run it

```bash
pip install pyyaml
bash demo/run_demo.sh
```

Watch for: the `delete_database` call is **blocked at the proxy** —
it never reaches the tool server — and the denial itself is receipted.
Then `verify.py` replays the chain to prove nothing was tampered with.

## What this proves (and what it doesn't)

Proves: the interception + policy + receipt loop works end-to-end,
and a compromised agent can be contained without touching the agent.

Doesn't prove (yet): real MCP transport (this speaks JSON-RPC, which is
what MCP is built on), multi-tenant keys, the policy language, or the
compliance/audit surface. Those are v1.

## Next steps toward v1

- Speak real MCP Streamable HTTP end-to-end against a live MCP server.
- Per-customer signing keys (KMS) instead of a shared dev key.
- A policy language with arguments constraints (e.g. `deploy_staging`
  only with `env=staging`, never `env=prod`).
- An auditor view: "show me everything agent-001 did on Tuesday,
  and prove it's complete."
