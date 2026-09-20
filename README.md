# Vouch — governed agent deployment, with proof (v1)

Vouch is the deployment layer for AI agents that need to be **governed**:
a neutral enforcement point that intercepts agent tool calls, grants
**task-scoped capabilities**, and emits **tamper-evident signed receipts**
for every decision — including denials. Deploy the agent anywhere; prove
everything it did.

## The three primitives (this is the whole company in miniature)

1. **Interception** — the agent talks to the gatekeeper, not the tools.
   (`gatekeeper/proxy.py`, an MCP Streamable HTTP proxy on :9000)
2. **Task-scoped capabilities** — each task gets only the tools it needs.
   (`policy.yaml` — anything unlisted is denied)
3. **Verifiable receipts** — every allow AND deny gets a hash-chained
   receipt, HMAC-signed with the calling **tenant's own key**.
   (`gatekeeper/receipts.py`, `receipts.jsonl`, `gatekeeper/tenants.py`)

## Run it

**Fastest path — the whole platform in one command:**

```bash
pip install pyyaml
bash quickstart.sh
```

That boots the gatekeeper, receipt service, control plane, dashboard, and
billing (mock test mode), provisions a tenant, deploys an agent, and verifies
the signed receipt chain. Start here: **[docs/quickstart.md](docs/quickstart.md)**.

Then read the [concepts](docs/concepts.md), the
[API reference](docs/api-reference.md), and grab an SDK —
[`sdk/python`](sdk/python) or [`sdk/js`](sdk/js).

The original v1 demo still works:

```bash
bash demo/run_demo.sh
```

Watch for: the `delete_database` call is **blocked at the proxy** —
it never reaches the tool server — and the denial itself is receipted
under the tenant's key. Then `verify.py` replays the chain to prove
nothing was tampered with.

Run the test suite:

```bash
python3 -m unittest discover -s tests
```

## v1: real MCP Streamable HTTP

The gatekeeper is a genuine MCP
[Streamable HTTP](https://spec.modelcontextprotocol.io) endpoint now,
not a JSON-RPC lookalike:

- `POST /mcp` carries JSON-RPC messages. Send
  `Accept: application/json, text/event-stream` and you get an SSE stream
  (`event: message` frames); send `Accept: application/json` and you get
  a single JSON object.
- `initialize` returns a real `Mcp-Session-Id`, relayed from the upstream
  MCP server; the client's session header is forwarded upstream on every
  call, so the gatekeeper stays transparent to session-aware clients.
- `GET /mcp` opens the server-push SSE stream (relayed upstream).
- `DELETE /mcp` terminates the session (relayed upstream, binding dropped).
- Notifications get `202` + empty body, per spec. JSON-RPC batches are
  rejected in v1 (`400`).

Only `tools/call` is policy-gated; discovery and capability calls pass
through untouched. Denied calls return a JSON-RPC `-32000` error naming
the receipt number — the destructive call never leaves the proxy.

## v1: per-tenant signing keys

One shared HMAC key was the v0 shortcut. v1 gives every tenant its own
256-bit key in a file-backed registry (`tenants.json`, git-ignored):

```bash
python3 -m gatekeeper.tenants create acme     # new tenant + key
python3 -m gatekeeper.tenants rotate acme     # rotate; old receipts still verify
python3 -m gatekeeper.tenants list
```

- The tenant is identified per request by the `X-Tenant-Id` header, falling
  back to the tenant bound to the `Mcp-Session-Id`, falling back to an
  auto-created `default` tenant. Unknown tenant ids get `403`.
- Each receipt stores `tenant_id` + `kid` and is HMAC-signed with that
  tenant's key — one tenant cannot forge another's audit trail.
- `python3 -m gatekeeper.verify` checks every receipt against the key its
  own `(tenant_id, kid)` points at, so verification survives rotation and
  cross-tenant tampering fails loudly.

## What this proves (and what it doesn't)

Proves: real MCP transport interop, per-tenant cryptographic isolation of
the audit trail, and the interception + policy + receipt loop end-to-end —
a compromised agent is contained without touching the agent.

Doesn't prove (yet): containerized agent deployment, the hosted control
plane / dashboard / proof verifier UI, billing, or the argument-aware
policy language (e.g. `deploy_staging` only with `env=staging`). Those are
next.
