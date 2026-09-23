# Agent verification demo — the three-lane verified-agent gateway

The demand-side half of Vouch: instead of guessing bot-vs-human, the site
**verifies the agent** — a signed credential plus its delegation chain —
before serving it.

## The three lanes

| Lane | Who | What happens |
|------|-----|--------------|
| verified-agent | requests presenting a signed agent credential + delegation chain | verifier checks signatures, chain integrity, scope, replay, and rate limits; **fast passage** with per-principal daily rate limits; every decision emits a signed, hash-chained receipt into the append-only transparency log |
| human | normal browser form traffic (no credential) | passes through **unchanged** — the verifier is never consulted |
| unverified | everything else (missing/forged credential, bot swarm) | the status-quo **challenge path** (stand-in for CAPTCHA / proof-of-work); bots get stuck here instead of eating the form |

## Run it

```bash
cd ~/workspace/trust-plane-prototype   # repo root
bash demo/agent_verification/run_demo.sh
```

One command, no Docker, no network beyond localhost, no cloud spend. It:

1. generates Ed25519 identities (principal, agent, sub-agent, attacker),
   issues the principal → agent → sub-agent credential chain, and creates
   the `smallville` tenant;
2. boots the verifier (`:9005`) and the demo site, "Smallville Permit
   Office" (`:9011`);
3. **human lane** — plain form POST, accepted unchanged;
4. **verified-agent lane** — the good agent's signed request sails through
   (HTTP 200) with a receipt seq/hash;
5. **unverified lane** — a forged credential is denied *with a visible
   reason* and challenged; a 12-bot credential-less swarm is 12/12
   challenged;
6. prints lane counters and verifies the transparency log
   (`RECEIPTS VERIFIED: chain intact, all signatures valid`).

## Interactive version (dashboard)

The same story, clickable: the dashboard's **Live demo** page (`/demo`,
`web/dashboard/demo_backend.py`) provisions a fresh demo backend on demand
and lets a visitor trigger each lane against the real verifier + site —
every number shown comes from a live call. See `tests/test_demo_page.py`
for the end-to-end proof.

## Pieces

- `site.py` — the gateway: form page, agent endpoint, challenge path.
- `agents.py` — `good` / `forged` / `swarm` demo clients.
- `setup.py` — keygen + credential issuance.
- `run_demo.sh` — the whole story in one command.

## The verifier service

`services/verifier/app.py` (`:9005`) is the reusable piece any site would
run or call:

- `POST /v1/verify` — `{tenant_id, credential, action, nonce, ts,
  agent_signature}` → `{decision, reason, lane, receipt_seq, receipt_hash}`
- `GET /v1/health`

Every allow **and** deny emits a receipt via the existing
`gatekeeper.ingest.ReceiptEmitter` pipeline (receipt service when
reachable, local append-only file otherwise — the prototype's
transparency log, verifiable with `python3 -m gatekeeper.verify`).

Trust is explicit: `VERIFIER_TRUSTED_ISSUERS` lists the principal
pubkeys the site accepts credentials from. A delegate can never widen
its delegator's scope; replay nonces, expiries, and per-principal daily
rate limits are enforced.

See `tests/test_agent_verification.py` (31 tests) and the Phase 8
section of `ARCHITECTURE.md`.
