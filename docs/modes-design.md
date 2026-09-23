# Delegation modes + principal approval + scope catalog — design

Date: 2026-09-23 · Author: fix-implementation worker (CTO remediation pass, H-3)
Status: design approved by construction — implements PRD-2026-09-23 §3
("Delegation issuance", "Verification", scope catalog) and §3.7.

## 1. Problem

The built prototype is pre-mode: credentials carry allow/deny/limits but no
notion of *how* the agent may act. The PRD's core product promise — three
delegation modes with verifier-enforced principal approval — has zero
presence in code (CTO verdict H-3). This design adds it to the verifier core
(`services/verifier/credentials.py`, `services/verifier/app.py`) without
changing any check the verdict called solid.

## 2. Modes

Three modes, strict rank `read < prepare < execute`:

- `read` — read-only authority within scopes. The agent may observe, never
  mutate. (PRD: "inbox read, calendar read, financial-data read".)
- `prepare` — the agent may *build* actions (draft the message, construct the
  payment instruction, assemble the publish payload) and may read, but any
  action with external effect verifies **only** with a signed principal
  approval attached. This turns the prompt guardrail ("nothing sends without
  my approval") into a verifier-enforced artifact.
- `execute` — the agent may act within its scopes subject to ceilings and
  limits, no per-action approval.

Capability lattice: `execute ⊇ prepare ⊇ read`. A higher mode can do
everything a lower mode can.

### Where mode lives

Mode is a property of every **grant**: each delegation link AND the
credential carry a `mode` field (signed, part of the canonical bytes).
Rationale: a delegator must be able to *de-escalate* for a sub-delegate
(principal grants the agent `execute`; the agent re-delegates `prepare` to a
sub-agent — least privilege), and the chain must visibly never escalate.

### Allowed transitions (the chain rule)

Mode is **non-increasing** along the whole chain, credential included:

```
rank(link_0.mode) >= rank(link_1.mode) >= ... >= rank(credential.mode)
```

- `issue_delegation(..., mode, parent_mode)`: `parent_mode` is advisory
  (caller-supplied); issuance rejects `rank(mode) > rank(parent_mode)`.
  The authoritative check is at verification (below) — a compromised
  intermediate cannot lie its way past a signed chain.
- `issue_credential(..., mode)`: with delegations present, every link must
  carry a known mode and the sequence must be non-increasing, ending at or
  above the credential's mode. A mode-carrying credential over a modeless
  (legacy) link is rejected at issuance — re-issue the chain with modes.
- Verification (`_verify_chain`): if *any* link or the credential carries a
  mode, the chain is mode-carrying and then *every* link plus the credential
  must carry a **known** mode, non-increasing. Mixed chains (some modeless)
  and unknown modes are denied (fail closed). A fully modeless chain is the
  legacy pre-mode path and skips mode checks entirely.

**Escalation requires principal re-approval.** There is no in-band "upgrade"
operation: the only way to hold a higher mode is a fresh principal-signed
root grant (new link 0 / new credential). The principal's fresh signature
*is* the re-approval. Test: `read → execute` without a new principal grant
is denied at issuance and at verification.

### Legacy (modeless) credentials

`mode=None` (the default) means pre-mode: no mode checks, no catalog
checks, exactly today's behavior. This grandfathers the prototype's
existing flows and its 421+ test contract. Mode is opt-in per credential;
the PRD-mode path is the going-forward contract. A future migration can
default issuance to modes — deliberately not done here.

## 3. Principal approval (for `prepare`)

When a `prepare`-mode credential is used for an **effect-class** action
(§5), the request must carry a principal approval object:

```json
{
  "credential_id": "cred-...",
  "action":        {<the EXACT action dict from the request>},
  "nonce":         "<hex, single-use>",
  "issued_at":     1234.5,
  "expires_at":    1234.5,
  "signature":     "<principal Ed25519 over canonical(unsigned approval)>"
}
```

- **Who signs:** the principal — verified against the credential's
  `issuer_pubkey` (the key that signed the credential). Not the agent, not
  the site.
- **What is bound:** the exact action payload (canonical bytes of the full
  action dict — type, target, args, amount_cents, everything), the
  `credential_id` it may be used with, a fresh nonce, and an expiry.
  Canonical encoding is the same `canonical()` (sorted keys, no whitespace)
  used everywhere in the verifier.
- **Replay protection (three layers):**
  1. Single-use nonce: the verifier keeps a seen-approval-nonce set
     (separate namespace from request nonces); reuse is denied.
  2. Expiry: default TTL 900s (15 min); `now < expires_at` is strict —
     no clock-skew extension on the expiry side (fail closed).
  3. Binding: the approval cannot move to a different action (canonical
     action bytes are signed) or a different credential (`credential_id`
     is signed). Stealing an approval buys nothing without the agent's
     private key for proof-of-possession anyway.
- **Transport:** `principal_approval` rides alongside the action request as
  `req["principal_approval"]` — *outside* the agent-signed envelope (the
  agent cannot mint it, only attach it). The verifier checks it during the
  mode step; on allow, the service reserves its nonce (race-safe
  check-and-reserve, mirroring request nonces).
- **Liveness note:** an approval consumed by a denied request is NOT burned
  (reservation happens only on allow), except under a true race where the
  second concurrent use is denied — fail closed, correct.

## 4. Verifier mode check (v2 check order)

Inserted as the new step 6, exactly where the PRD puts it — after scope,
before replay/nonce:

```
1. manifest freshness
2. principal/key status
3. credential signature
4. delegation chain        (now includes the mode-chain rule)
5. scope, then tier policy
6. MODE                    <-- new: unknown mode = deny; prepare+effect
                               without a valid principal approval = deny
7. timestamp skew, then replay
8. proof-of-possession
9. limits                  (now includes the H-2 chain-required-keys check)
```

(The PRD lists the tier hook after mode textually; in this codebase the tier
hook evaluates as part of the scope step — unchanged. Nothing solid moves.)

Mode check logic for a mode-carrying credential (`mode=None` skips):

1. `mode` not in `{"read","prepare","execute"}` → deny, fail closed.
2. `action.type` not in the scope catalog (§5) → deny "unknown scope".
   (Issuance already rejects unknown scopes; this is the verification-time
   backstop for hand-minted credentials.)
3. Effect-class rules (§5):
   - `read` effect → allowed in all modes.
   - `draft` effect → allowed in `prepare`/`execute`; denied in `read`.
   - `effect` effect → allowed in `execute`; in `prepare` **only** with a
     valid principal approval (bound, fresh, unexpired, principal-signed);
     denied in `read`.
4. Deny reasons are plain words ("delegation mode 'read' does not authorize
   'messaging.send'"), per the PRD's 2-AM-debugging UX rule.

The v1 path (`verify_action_request`) runs the same check right after its
scope check, via the shared helper. Unknown mode = deny in both paths.

## 5. Scope catalog → modes

The PRD's demand-driven catalog is the canonical scope vocabulary
(13 namespaces). Each maps to an effect class:

| scope | effect | notes |
|---|---|---|
| `inbox.read` | read | |
| `calendar.read` | read | |
| `payments.read` | read | balances/txns for forecasts & audits |
| `research.web` | read | no external mutation |
| `crm.read` | read | |
| `travel.recommend` | read | recommendations only, no booking |
| `messaging.draft` | draft | compose; no send |
| `publish.draft` | draft | assemble payload; no publish |
| `payments.initiate` | draft | PRD marks it "(prepare)": construct the instruction, no movement |
| `messaging.send` | effect | |
| `calendar.write` | effect | creates events / sends invites — external mutation |
| `crm.write` | effect | mutates shared records |
| `payments.execute` | effect | moves money |

Resulting matrix (mode × effect):

|  | read | draft | effect |
|---|---|---|---|
| `read` | allow | deny | deny |
| `prepare` | allow | allow (no approval — building is the job) | allow **iff** valid principal approval |
| `execute` | allow | allow | allow (ceilings/limits still apply) |

**Issuance:** a mode-carrying grant's scope is catalog-validated — every
allow/deny entry must be a catalog scope or a pattern matching ≥1 catalog
scope (e.g. `payments.*` is fine; `pay.*` is rejected as unknown).
Otherwise `ValueError`. Modeless grants skip this (legacy).

**Verification:** for a mode-carrying credential the *action type itself*
must be a catalog scope, else deny. This is what makes `allow: ["*"]`
harmless — it can only ever authorize catalog actions.

## 6. Interaction with agent-differentiated serving (PRD §3.7)

- The mode check is *inside* verification, so the verdict the middleware
  branches on already reflects it: a `prepare`-mode agent attempting an
  effect action without approval lands in the **unverified lane**
  (challenged), exactly like any other deny. No middleware change needed
  for the branching itself.
- The allow path exposes the credential (which now carries `mode`), so a
  site can serve *per-mode* optimized paths (e.g. read-mode agents get
  cached structured reads; execute-mode agents get the action API) — the
  site owns that branching; Vouch supplies the trusted verdict. The 7
  frozen receipt-evidence fields are untouched; mode is read from the
  credential in the verifier response.
- **Known integration gap (out of scope for this pass):** the reference
  middleware's verifier client (`middleware.py::_VerifierClient.verify`)
  rebuilds the POST body from the 6 core envelope fields and drops
  `principal_approval`. Prepare-mode flows through the reference
  middleware need that field forwarded (one-line follow-up). Flagged for
  the reviewer; not changed here per the verifier-core-only scope.

## 7. Ambiguities resolved (judgment calls)

1. `calendar.write` → **effect** (sends invites; external mutation), not
   draft. The PRD lists no `calendar.draft`, and the catalog's universal
   finding gates real-world effects behind approval.
2. `payments.initiate` → **draft**, per the PRD's explicit "(prepare)"
   annotation; `payments.execute` → effect.
3. `travel.recommend` / `research.web` → **read** (no external mutation).
4. Mode rank `read < prepare < execute`; de-escalation-only along chains;
   escalation = fresh principal-signed root grant (the re-approval).
5. `parent_mode` at `issue_delegation` is **advisory**; verification of the
   signed chain is authoritative (a compromised intermediate can't lie
   past it).
6. Legacy modeless credentials are grandfathered (no mode/catalog checks)
   — preserves the prototype's existing behavior and test contract.
7. Approval TTL default **900s**; expiry enforced strictly (no positive
   clock-skew grace); approval nonces live in a separate namespace from
   request nonces; reservation on allow only (race → second use denied).
8. In `prepare` mode, read/draft actions need **no** approval; only
   effect-class actions do. In `read` mode, draft actions are denied
   (drafting is not reading).
9. The 7 frozen v2 evidence fields are unchanged; mode travels in the
   credential itself.

## 8. Test plan

- Issuance: unknown mode rejected; escalation rejected at delegation and
  credential issuance; modeless-chain + mode-credential rejected; unknown
  scope rejected; catalog patterns (`payments.*`) accepted.
- Verification: unknown mode denied (fail closed); legacy credential
  unaffected; read-mode denies send/draft; prepare-mode allows draft
  without approval; prepare+effect without approval denied; forged
  approval (wrong key) denied; tampered action denied; cross-credential
  approval denied; replayed approval denied; expired approval denied;
  execute allows effect actions; mode escalation in a hand-minted chain
  denied.
- Key security tests fail-without-fix via the stash method (tests use
  stable primitives + hand-minted dicts so the property failure is
  visible, not just an ImportError).
