# Revocation design: credential/key-granular AND per-link (2026-09-23)

## Decision

**ENFORCE per-link revocation handles** (option (a) from the CTO review
addendum). The handles were minted and signed into every delegation link
but never checked; they are now enforced fail-closed in the verification
path, with a registry and an operator console command. They were NOT
removed.

## Rationale

- The design intent was already surgical revocation: `issue_delegation`'s
  docstring promises "the operator can revoke this grant via the
  manifest's revoked_credentials list". The code minted the handles and
  then never wired them up — removing them would have deleted a
  designed security property to match an implementation gap, which is
  backwards.
- Threat-model fit: the H-2 finding is a *compromised intermediate
  delegator*. Credential-level revocation is a blunt instrument — it
  kills the whole credential, including legitimate sub-delegations the
  principal still wants. Per-link revocation is the surgical response:
  revoke exactly the compromised grant, leave the rest of the chain
  working.
- Cost is small and coherent: the plumbing (transparency-log fold,
  signed manifest, console revoke flow) already existed for credential
  handles; links reuse it with a parallel list.

## Mechanics

Three revocation granularities, finest last:

1. **Key revocation** — `revoke-key`: the principal's key is dead; every
   credential it issued fails verification (v2 check order step 2).
2. **Credential revocation** — `revoke-credential <handle>`: the
   credential's `revocation_handle` lands in the manifest's
   `revoked_credentials`; v2 denies the credential (check order step 2).
3. **Delegation-link revocation** — `revoke-delegation-link <handle>`:
   the link's `revocation_handle` (minted by `issue_delegation`,
   `"rh-" + 12 hex chars`, part of the signed link) lands in the
   manifest's `revoked_delegation_handles`; `_verify_chain` denies any
   chain containing that link (v2 check order step 4), even when every
   signature verifies.

Operator flow:

```
vouch-operator revoke-delegation-link --principal acme \
    --revocation-handle rh-abc123... --reason "intermediate compromised" --yes
vouch-operator manifest   # rebuild folds the handle into the manifest
```

Takes effect on the next manifest rebuild; verifiers reload the manifest
per request, so no verifier restart is needed.

## Deliberate edge cases

- **A link with no `revocation_handle` cannot be revoked by handle**
  (there is nothing to match) and is treated as not revoked — not
  denied. Denying handle-less links would break older credentials and
  hand-minted test credentials; the enforced property is "a revoked
  handle is denied", not "every link must carry a handle".
  `issue_delegation` always mints one, so in practice every real link
  is revocable.
- **Revocation is monotonic**: handles are only ever appended to the
  manifest lists (deduplicated at fold). There is no "unrevoke".
- **The v1 verification path** (`verify_credential` without a manifest)
  does not enforce link revocation — there is no registry to consult.
  The v2 manifest path is the enforced path; v1 is the legacy fallback.
- **Manifests predating this change** (no `revoked_delegation_handles`
  field) fail `verify_manifest` closed — "manifest missing field" — so a
  verifier can never silently run with link revocation unavailable. The
  operator rebuilds the manifest with the current console.

## What is NOT covered

Link revocation does not retroactively invalidate receipts already
emitted for actions the link authorized — the audit trail is
append-only by design. It stops *future* verifications using that link.
