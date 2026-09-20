# Troubleshooting

## "I lost my API key"

The plaintext is shown exactly once at creation — only its sha256 is stored,
so it cannot be recovered. Create a new named key and revoke the old one:

```bash
curl -s -X POST localhost:9002/v1/api-keys -H "Authorization: Bearer $OLD_KEY" \
  -H 'Content-Type: application/json' -d '{"name":"ci-2"}'
curl -s -X DELETE localhost:9002/v1/api-keys/<old-id> \
  -H "Authorization: Bearer $NEW_KEY"
```

## `403 unknown tenant` on every gatekeeper call

The tenant has no key bundle cached at the gatekeeper. Either the tenant
doesn't exist yet (create it via `POST /v1/tenants`), or the control plane is
down and the 10-minute stale window expired — the gatekeeper fails closed by
design. Bring the control plane back or re-create the tenant.

## Calls denied with "unknown task"

The `X-Task-Id` header names a task with no policy. Write one:
`PUT /v1/policies/{task_id}`. Note the demo `policy.yaml` is v1-format and
loads through `upgrade_v1_policy()` — control-plane policies must be v2.

## `PUT /v1/policies` → `422 invalid_policy`

Your rules use an unknown constraint op. The closed set is `equals`,
`prefix`, `regex`, `in`, `range`, `required` (`ARCHITECTURE.md` §5). Regexes
are RE2-style (no backtracking) and compiled once at load.

## `409 duplicate_seq` from `/v1/ingest`

Not an error — the receipt is already stored. The gatekeeper treats it as
success. If you see `422 chain_break`, the gatekeeper re-syncs: it fetches
the tip (`GET /v1/receipts?limit=1`) and replays its spool from there.

## `GET /v1/verify` → `chain_ok: false`

Look at `failures` — each entry names the seq and the reason:

- `seq break` / `chain break` — receipts inserted, deleted, or reordered.
  Check for two writers or a restored-from-backup DB mixed with a live spool.
- `hash mismatch` — a receipt body was tampered with after signing.
- `bad signature` — wrong key for the `kid`, or the receipt was forged.
- `unknown key id` — the signing key rotated and the receipt service's
  5-minute key cache is stale; it invalidates and retries once automatically.
  If it persists, check the control plane's `tenant_keys`.

## Policy changes not taking effect

The gatekeeper polls the control plane every 15s per active tenant and caches
key bundles for 60s. For immediate effect:

```bash
curl -s -X POST localhost:9000/internal/cache/invalidate \
  -H "Authorization: Bearer $GATEKEEPER_SVC_TOKEN" \
  -H 'Content-Type: application/json' -d '{"tenant_id":"acme"}'
```

Tenant create, key rotation, plan changes, and suspend/unsuspend already push
invalidations automatically.

## Billing shows the wrong plan after a Stripe test webhook

Webhooks are verified (HMAC, 300s tolerance) and idempotent — replays are
safe. Check: (1) the webhook reached `POST /v1/stripe/webhook` with the
**test** webhook secret, (2) `STRIPE_TEST_WEBHOOK_SECRET` is set on the
billing service, (3) the tenant's plan via `GET /v1/tenants/me`. In mock
mode there are no real webhooks — complete the mock checkout page instead.

## Port already in use

Default ports: gatekeeper `9000`, receipts `9001`, control plane `9002`,
dashboard `3000`, billing `9004`. Every service takes a `*_PORT` env override
(`GATEKEEPER_PORT`, `RECEIPT_PORT`, `CONTROLPLANE_PORT`, `DASHBOARD_PORT`,
`BILLING_PORT`).

## quickstart.sh hangs on "port never came up"

Check `$TMP/*.log` — the script prints the temp dir in the error. The usual
cause is a stale service still holding the port (`lsof -i :9002` / `kill`),
or `pyyaml` not installed (`pip install pyyaml`).
