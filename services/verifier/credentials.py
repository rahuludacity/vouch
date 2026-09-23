"""Agent credential issuance and verification — the demand-side "passport".

A credential binds together:
  (a) agent identity      — the agent's Ed25519 keypair (pubkey in credential)
  (b) principal           — the human/org the agent acts for (id + pubkey)
  (c) delegation chain    — principal -> agent -> sub-agent ...; every link is
                            signed by the *delegator's* private key, so anyone
                            holding the pubkeys can verify the whole chain
  (d) authorization scope — what the agent may do (allow/deny action patterns
                            plus per-action rate limits)

The site (verifier) never needs a secret: it checks signatures against
pubkeys, chain continuity, scope narrowing (a delegate can never grant more
than it was granted), expiries, and the agent's proof-of-possession
signature over the attempted action.

Canonical encoding for everything signed: JSON with sorted keys and no
whitespace (see canonical()). Timestamps are epoch seconds (floats are
rounded to millis at issuance so signatures stay stable).

Scope model:
    {"allow": ["form.submit", "permit.*"],   # action-type patterns (fnmatch)
     "deny":  ["form.delete"],              # deny always wins
     "limits": {"form.submit": {"max_per_day": 50}}}
A child scope narrows a parent scope: every allow pattern must appear
verbatim in the parent's allow list, denies can only be added, and numeric
limits can only tighten. Simple, sound, and auditable.
"""
import copy
import fnmatch
import json
import secrets
import time
import uuid

from . import ed25519

CLOCK_SKEW = 300  # seconds of timestamp tolerance on action requests


def canonical(obj):
    """Canonical bytes for signing: sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _ts(ts=None):
    return round(time.time(), 3) if ts is None else round(float(ts), 3)


# ---------------------------------------------------------------- keypairs
def generate_keypair():
    """(priv_hex, pub_hex) — fresh Ed25519 identity."""
    sk, pk = ed25519.keypair_hex()
    return sk, pk


# ---------------------------------------------------------------- scopes
def _norm_scope(scope):
    scope = scope or {}
    return {
        "allow": sorted(scope.get("allow", [])),
        "deny": sorted(scope.get("deny", [])),
        "limits": {k: dict(v) for k, v in scope.get("limits", {}).items()},
    }


_PATTERN_CHARS = frozenset("*?[]!")


def _looks_like_pattern(key):
    """True if a scope key contains fnmatch metacharacters."""
    return any(ch in _PATTERN_CHARS for ch in str(key))


def _reject_pattern_limit_keys(scope):
    """Limit keys must be literal action types, never fnmatch patterns.

    allow/deny are matched with fnmatch, but limits are enforced with an
    exact dict lookup — a pattern key like "form.*" would silently match
    nothing and leave the action unthrottled (fail-open). Fail loudly at
    issuance instead of silently at enforcement.
    """
    for key in (scope or {}).get("limits", {}):
        if _looks_like_pattern(key):
            raise ValueError(
                f"limit key {key!r} looks like a pattern; limit keys must be "
                "literal action types (e.g. 'form.submit'). Expand patterns "
                "into their literal action types.")


def _validate_limit_values(scope):
    """Limit values must be non-negative ints — reject junk at issuance.

    A negative max_per_day / max_spend_per_day is nonsense; a float/str
    limit would compare weirdly at enforcement (fail-open). Fail loudly
    at issuance instead of silently at enforcement.
    """
    for action, lim in (scope or {}).get("limits", {}).items():
        if not isinstance(lim, dict):
            raise ValueError(f"limits[{action!r}] must be an object")
        for k, v in lim.items():
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise ValueError(
                    f"limit {action}.{k} must be a non-negative integer, "
                    f"got {v!r}")


def _new_revocation_handle():
    """Fresh revocation handle: "rh-" + 12 hex chars (48 bits, secrets)."""
    return "rh-" + secrets.token_hex(6)


def scope_allows(scope, action_type):
    """True iff action_type passes the scope's allow/deny patterns."""
    scope = _norm_scope(scope)
    allowed = any(fnmatch.fnmatchcase(action_type, pat)
                  for pat in scope["allow"])
    denied = any(fnmatch.fnmatchcase(action_type, pat)
                 for pat in scope["deny"])
    return allowed and not denied


def scope_narrows(child, parent):
    """True iff child grants no more than parent (for delegation links).

    Limits are monotonic over *missing* keys too (H-2): a child that still
    allows an action must carry every limit key the parent carries for it,
    with value <= the parent's. Dropping a key (e.g. a spending cap) while
    keeping the action allowed is a widening, not a narrowing — enforcement
    must never read an absent key as "unlimited".
    """
    c, p = _norm_scope(child), _norm_scope(parent)
    if any(pat not in p["allow"] for pat in c["allow"]):
        return False, "allow list wider than delegator's"
    if any(pat not in c["deny"] for pat in p["deny"]):
        return False, "cannot drop a delegator's deny"
    for action, plim in p["limits"].items():
        if _looks_like_pattern(action):
            # Not a valid limit key shape; issuance and verification reject
            # pattern limit keys elsewhere — narrowing must not hinge on
            # them.
            continue
        if not scope_allows(c, action):
            continue  # child dropped the action: no limit to carry
        clim = c["limits"].get(action, {})
        for k, pv in plim.items():
            cv = clim.get(k)
            if cv is None:
                return False, (
                    f"limit {action}.{k} missing: delegator caps it at "
                    f"{pv} and the child still allows '{action}'")
            if cv > pv:
                return False, (
                    f"limit {action}.{k} looser than delegator's "
                    f"({cv} > {pv})")
    return True, ""


def chain_required_limits(cred):
    """Limit keys the delegation chain requires, per action.

    Returns {action: {key: min_value}} — the union of limit keys across
    every delegation link's scope (the credential's own scope excluded:
    this is what the chain *requires*, used to fail closed when the
    credential omits a key). The minimum value across links is reported;
    under sound narrowing the credential's own value is the minimum.
    Pattern-looking action keys are skipped (invalid; rejected elsewhere).
    Never raises on malformed input.
    """
    required = {}
    try:
        links = cred.get("delegations") if isinstance(cred, dict) else None
    except Exception:
        return required
    for link in links or []:
        if not isinstance(link, dict):
            continue
        try:
            limits = _norm_scope(link.get("scope"))["limits"]
        except Exception:
            continue
        for action, lim in limits.items():
            if _looks_like_pattern(action) or not isinstance(lim, dict):
                continue
            slot = required.setdefault(action, {})
            for k, v in lim.items():
                if isinstance(v, bool) or not isinstance(v, int):
                    continue
                slot[k] = v if k not in slot else min(slot[k], v)
    return required


def check_chain_limits_present(cred, atype):
    """Enforcement-time fail-closed check (H-2).

    If the delegation chain implies a limit key for `atype` (some ancestor
    link caps it) but the credential's own scope omits that key, the
    credential is malformed relative to the chain: deny. An absent key is
    never "unlimited". Returns (ok, reasons). Defense in depth — the chain
    check already enforces this for well-formed chains; this guards the
    enforcement points themselves.
    """
    scope = cred.get("scope") if isinstance(cred, dict) else None
    normed = _norm_scope(scope)
    if not scope_allows(normed, atype):
        return True, []  # scope denial happens at the scope check
    have = normed["limits"].get(atype, {})
    missing = sorted(k for k in chain_required_limits(cred).get(atype, {})
                     if k not in have)
    if missing:
        return False, [
            f"limit key(s) {', '.join(missing)} for '{atype}' required by "
            f"the delegation chain but missing from the credential; "
            f"failing closed"]
    return True, ""


# ---------------------------------------------------------------- modes
# PRD §3: delegation modes read < prepare < execute, the demand-driven
# scope catalog, and signed principal approval for prepare-mode effect
# actions. Design: docs/modes-design.md. A credential/link without a mode
# (mode=None) is the legacy pre-mode path: no mode or catalog checks.

_MODES = ("read", "prepare", "execute")
_MODE_RANK = {"read": 0, "prepare": 1, "execute": 2}

# Canonical scope vocabulary (PRD "Delegation scope catalog"). The effect
# class drives the mode check: read = observable only; draft = buildable
# with no external effect; effect = external effect (principal approval
# required in prepare mode, allowed outright in execute, denied in read).
SCOPE_CATALOG = {
    "inbox.read":        ("read",   "Read inbox messages."),
    "calendar.read":     ("read",   "Read calendar events."),
    "payments.read":     ("read",   "Read balances/transactions (forecasts, audits)."),
    "research.web":      ("read",   "Web research; no external mutation."),
    "crm.read":          ("read",   "Read CRM records."),
    "travel.recommend":  ("read",   "Recommend travel options; no booking."),
    "messaging.draft":   ("draft",  "Compose a message; no send."),
    "publish.draft":     ("draft",  "Assemble a publish payload; no publish."),
    "payments.initiate": ("draft",  "Construct a payment instruction; no movement."),
    "messaging.send":    ("effect", "Send a message."),
    "calendar.write":    ("effect", "Create/modify events (sends invites)."),
    "crm.write":         ("effect", "Create/modify CRM records."),
    "payments.execute":  ("effect", "Execute a payment / move money."),
}

# Default principal-approval lifetime: 15 minutes (design judgment call).
APPROVAL_TTL_S = 900


def _validate_mode(mode, *, where):
    if mode is not None and mode not in _MODES:
        raise ValueError(
            f"{where}: unknown delegation mode {mode!r}; must be one of "
            f"{list(_MODES)}")


def validate_catalog_scope(scope):
    """Issuance-time: a mode-carrying grant must speak the catalog.

    Every allow/deny entry must be a catalog scope or a pattern matching
    at least one catalog scope (e.g. "payments.*" is fine; "pay.*" is
    rejected as unknown). Raises ValueError otherwise — fail fast on
    typos instead of minting a grant that can never verify.
    """
    problems = []
    normed = _norm_scope(scope)
    for pat in normed["allow"] + normed["deny"]:
        if pat in SCOPE_CATALOG:
            continue
        if (_looks_like_pattern(pat)
                and any(fnmatch.fnmatchcase(c, pat)
                        for c in SCOPE_CATALOG)):
            continue
        problems.append(pat)
    if problems:
        raise ValueError(
            f"unknown scope(s) {problems}; mode-carrying grants must use "
            f"the Vouch scope catalog "
            f"({', '.join(sorted(SCOPE_CATALOG))})")


def issue_principal_approval(*, principal_priv_hex, credential_id, action,
                             ttl_s=APPROVAL_TTL_S, issued_at=None,
                             nonce=None):
    """Mint a signed principal approval for one exact action.

    The principal (holder of the credential's issuer key) authorizes the
    agent to execute *this* action under a prepare-mode credential. The
    signature binds the exact action payload, the credential_id, a
    single-use nonce, and the expiry: replaying it for another action,
    another credential, or a second time does not verify.
    """
    now = _ts(issued_at)
    approval = {
        "credential_id": credential_id,
        "action": copy.deepcopy(action),
        "nonce": nonce or uuid.uuid4().hex,
        "issued_at": now,
        "expires_at": round(now + ttl_s, 3),
    }
    approval["signature"] = ed25519.sign_hex(
        principal_priv_hex, canonical(_unsigned(approval)))
    return approval


def verify_principal_approval(approval, *, principal_pubkey, action,
                              credential_id, now=None, seen_nonces=None):
    """Verify a principal approval. Returns (ok, reasons). Never raises.

    Checks: shape, credential binding, exact-action binding (canonical
    bytes), validity window, principal signature, and single-use nonce.
    seen_nonces is membership-read only; the caller reserves on allow.
    """
    now = _ts(now)
    reasons = []
    if not isinstance(approval, dict):
        return False, ["principal approval is not an object"]
    for f in ("credential_id", "action", "nonce", "issued_at",
              "expires_at", "signature"):
        _check(f in approval, reasons, f"approval missing field '{f}'")
    if reasons:
        return False, reasons
    _check(approval["credential_id"] == credential_id, reasons,
           "approval is for a different credential")
    try:
        action_match = (canonical(approval["action"]) == canonical(action))
    except Exception:
        action_match = False
    _check(action_match, reasons,
           "approval does not authorize this exact action")
    _check(approval["issued_at"] <= now + CLOCK_SKEW, reasons,
           "approval not yet valid")
    # Expiry is strict: no clock-skew grace extends an approval.
    _check(isinstance(approval["expires_at"], (int, float))
           and not isinstance(approval["expires_at"], bool)
           and now < approval["expires_at"], reasons, "approval expired")
    try:
        sig_ok = bool(ed25519.verify_hex(principal_pubkey,
                                         canonical(_unsigned(approval)),
                                         approval["signature"]))
    except Exception:
        sig_ok = False
    _check(sig_ok, reasons,
           "approval signature invalid (not signed by the principal?)")
    if seen_nonces is not None:
        try:
            seen = approval["nonce"] in seen_nonces
        except Exception:
            seen = True  # unusable nonce store: fail closed
        _check(not seen, reasons, "approval replay: nonce already used")
    return not reasons, reasons


def _check_mode(cred, action, principal_approval, now, approval_nonces):
    """PRD mode enforcement for one action request. Returns (ok, reasons).

    mode None (legacy pre-mode credential): no mode checks at all.
    Unknown mode: deny (fail closed). For mode-carrying credentials the
    action type must be a catalog scope, and prepare + effect-class
    action requires a valid signed principal approval.
    """
    mode = cred.get("mode") if isinstance(cred, dict) else None
    if mode is None:
        return True, []
    if mode not in _MODES:
        return False, [f"unknown delegation mode {mode!r}; failing closed"]
    atype = action.get("type", "") if isinstance(action, dict) else ""
    entry = SCOPE_CATALOG.get(atype)
    if entry is None:
        return False, [f"unknown scope '{atype}': not in the Vouch scope "
                        f"catalog; failing closed"]
    effect = entry[0]
    if effect == "read":
        return True, []
    if mode == "read":
        return False, [f"delegation mode 'read' does not authorize "
                        f"'{atype}'"]
    if effect == "draft":
        # Building the draft IS the prepare-mode job: no approval needed.
        return True, []
    if mode == "execute":
        return True, []
    # mode == "prepare", effect-class action: principal approval required.
    if not isinstance(principal_approval, dict):
        return False, [f"delegation mode 'prepare' requires a signed "
                        f"principal approval for '{atype}'"]
    ok_a, why_a = verify_principal_approval(
        principal_approval,
        principal_pubkey=cred.get("issuer_pubkey"),
        action=action, credential_id=cred.get("credential_id"),
        now=now, seen_nonces=approval_nonces)
    if not ok_a:
        return False, [f"principal approval rejected for '{atype}': {w}"
                       for w in why_a]
    return True, ""


# ---------------------------------------------------------------- issuance
def issue_delegation(*, delegator_priv_hex, delegator_pub_hex,
                     delegatee_pub_hex, scope, revocation_handle=None,
                     ttl_s=3600, issued_at=None, mode=None,
                     parent_mode=None):
    """One signed delegation link. Returns the link dict (with signature).

    revocation_handle: "rh-"+12 hex from secrets when not supplied; it is
    part of the signed link so the operator can revoke this grant via the
    manifest's revoked_credentials list. Default ttl is 1h (short-lived
    delegation grants).

    mode: PRD delegation mode for this grant (None = legacy pre-mode).
    A mode-carrying link's scope must speak the scope catalog, and the mode
    must not exceed parent_mode. parent_mode is advisory (caller-supplied):
    the authoritative escalation check happens at verification over the
    signed chain.
    """
    _reject_pattern_limit_keys(scope)
    _validate_limit_values(scope)
    _validate_mode(mode, where="delegation")
    _validate_mode(parent_mode, where="parent delegation")
    if mode is not None:
        validate_catalog_scope(scope)
        if (parent_mode is not None
                and _MODE_RANK[mode] > _MODE_RANK[parent_mode]):
            raise ValueError(
                f"delegation mode escalation: {parent_mode!r} -> "
                f"{mode!r}; a delegator cannot grant more mode than it "
                f"holds")
    now = _ts(issued_at)
    link = {
        "delegator_pubkey": delegator_pub_hex,
        "delegatee_pubkey": delegatee_pub_hex,
        "scope": _norm_scope(scope),
        "mode": mode,
        "issued_at": now,
        "expires_at": round(now + ttl_s, 3),
        "revocation_handle": revocation_handle or _new_revocation_handle(),
    }
    link["signature"] = ed25519.sign_hex(delegator_priv_hex,
                                         canonical(_unsigned(link)))
    return link


def _unsigned(d):
    return {k: v for k, v in d.items() if k != "signature"}


def issue_credential(*, principal_id, principal_priv_hex, principal_pub_hex,
                     agent_id, agent_pub_hex, scope,
                     delegations=(), revocation_handle=None, ttl_s=86400,
                     issued_at=None, credential_id=None, mode=None):
    """Mint an agent credential, signed by the principal (the issuer).

    delegations: extra links appended after the implicit principal->agent
    grant, e.g. agent->sub-agent re-delegations. Each must already be
    signed (see issue_delegation). The credential's effective scope must
    narrow the last delegation's scope.

    revocation_handle: "rh-"+12 hex from secrets when not supplied; part
    of the signed credential so the operator can revoke it via the
    manifest's revoked_credentials list. Default ttl stays 24h (existing
    flows/demos depend on it); delegations default to 1h.

    mode: PRD delegation mode for this credential (None = legacy pre-mode).
    A mode-carrying credential's scope must speak the scope catalog, and
    the whole chain must be mode-carrying with non-increasing modes — a
    mode upgrade needs a fresh principal-signed root grant (the
    principal's re-approval), never an intermediate's say-so.
    """
    now = _ts(issued_at)
    _reject_pattern_limit_keys(scope)
    _validate_limit_values(scope)
    _validate_mode(mode, where="credential")
    if mode is not None:
        validate_catalog_scope(scope)
    scope = _norm_scope(scope)
    links = list(delegations)
    if links:
        # Issuance-time chain soundness (H-2): every link must narrow its
        # parent, and the credential must narrow the last link. A
        # compromised intermediate cannot mint a widening link into a
        # principal-signed credential — issuance fails loudly instead.
        prev_scope = None
        for i, link in enumerate(links):
            if not isinstance(link, dict):
                raise ValueError(f"delegation link {i} is not an object")
            if i > 0:
                ok, why = scope_narrows(link.get("scope"), prev_scope)
                if not ok:
                    raise ValueError(
                        f"delegation link {i} invalid: {why}")
            prev_scope = link.get("scope")
        ok, why = scope_narrows(scope, links[-1]["scope"])
        if not ok:
            raise ValueError(f"credential scope invalid: {why}")
        if mode is not None:
            # Mode-carrying credential: the chain must be mode-carrying
            # end to end, with known, non-increasing modes.
            for i, link in enumerate(links):
                lm = link.get("mode")
                if lm is None:
                    raise ValueError(
                        f"credential mode {mode!r} requires every "
                        f"delegation link to carry a mode (link {i} has "
                        f"none); re-issue the chain with modes")
                if lm not in _MODES:
                    raise ValueError(
                        f"delegation link {i} has unknown mode {lm!r}")
            for i in range(1, len(links)):
                if (_MODE_RANK[links[i]["mode"]]
                        > _MODE_RANK[links[i - 1]["mode"]]):
                    raise ValueError(
                        f"delegation mode escalation at link {i}: "
                        f"{links[i - 1]['mode']!r} -> "
                        f"{links[i]['mode']!r}")
            if _MODE_RANK[mode] > _MODE_RANK[links[-1]["mode"]]:
                raise ValueError(
                    f"credential mode {mode!r} exceeds the last delegation "
                    f"link's mode {links[-1]['mode']!r}; a higher mode "
                    f"needs a fresh principal-signed grant")
    cred = {
        "credential_id": credential_id or f"cred-{uuid.uuid4().hex[:12]}",
        "principal": {"id": principal_id, "pubkey": principal_pub_hex},
        "agent_id": agent_id,
        "agent_pubkey": agent_pub_hex,
        "scope": scope,
        "mode": mode,
        "issued_at": now,
        "expires_at": round(now + ttl_s, 3),
        "delegations": links,
        "issuer_pubkey": principal_pub_hex,
        "revocation_handle": revocation_handle or _new_revocation_handle(),
    }
    cred["signature"] = ed25519.sign_hex(principal_priv_hex,
                                         canonical(_unsigned(cred)))
    return cred


def sign_action_request(*, agent_priv_hex, credential_id, action,
                        nonce=None, ts=None):
    """Proof-of-possession: the agent signs the exact attempted action."""
    ts = _ts(ts)
    envelope = {
        "credential_id": credential_id,
        "action": action,
        "nonce": nonce or uuid.uuid4().hex,
        "ts": ts,
    }
    envelope["agent_signature"] = ed25519.sign_hex(
        agent_priv_hex, canonical(_unsigned_action(envelope)))
    return envelope


def _unsigned_action(env):
    return {k: v for k, v in env.items() if k != "agent_signature"}


# ---------------------------------------------------------------- verification
def _check(cond, reasons, msg):
    if not cond:
        reasons.append(msg)
    return cond


def verify_delegation_link(link, now):
    """Verify one link's signature + expiry. Returns (ok, reasons)."""
    reasons = []
    for f in ("delegator_pubkey", "delegatee_pubkey", "scope",
              "issued_at", "expires_at", "signature"):
        _check(f in link, reasons, f"link missing field '{f}'")
    if reasons:
        return False, reasons
    _check(link["issued_at"] <= now < link["expires_at"], reasons,
           "delegation link expired or not yet valid")
    _check(ed25519.verify_hex(link["delegator_pubkey"],
                              canonical(_unsigned(link)),
                              link["signature"]),
           reasons, "delegation link signature invalid")
    return not reasons, reasons


def _verify_chain(cred, now, revoked_link_handles=None):
    """Delegation-chain continuity + scope narrowing. Returns (ok, reasons).

    Assumes the credential's own signature and expiry were already checked.
    Shared by verify_credential (v1) and verify_action_request_v2.
    Never raises on malformed input: every structural problem becomes a
    deny reason (fail-closed).

    revoked_link_handles: set-like of revoked per-link revocation
    handles (from the manifest's revoked_delegation_handles). Any chain
    containing a revoked handle is denied, even if every signature is
    valid — this is the surgical revocation of one delegation grant
    without killing the whole credential. A link with no handle cannot
    be revoked this way (nothing to match); it is treated as not
    revoked. None disables the check (the v1 path has no manifest).
    """
    reasons = []
    revoked = set(revoked_link_handles or ())
    links = cred.get("delegations") if isinstance(cred, dict) else None
    _check(isinstance(links, list) and len(links) >= 1, reasons,
           "delegation chain empty: principal must delegate to the agent")
    if reasons:
        return False, reasons
    principal_pubkey = (cred.get("principal") or {}).get("pubkey")
    _check(links[0].get("delegator_pubkey") == principal_pubkey, reasons,
           "chain root is not the principal")
    prev_scope = None
    for i, link in enumerate(links):
        if not isinstance(link, dict):
            reasons.append(f"link {i}: not an object")
            continue
        ok, why = verify_delegation_link(link, now)
        if not ok:
            reasons.extend(f"link {i}: {w}" for w in why)
            continue
        rh = link.get("revocation_handle")
        if rh and rh in revoked:
            reasons.append(f"link {i}: delegation link revoked")
        if i > 0:
            _check(link.get("delegator_pubkey") ==
                   links[i - 1].get("delegatee_pubkey"), reasons,
                   f"link {i}: chain continuity broken")
            # The narrowing diagnostic describes the signed chain: it is
            # evaluated against the previous structurally-valid link's
            # scope even when a link was revoked (revocation is its own
            # independent deny). Skipping the assignment here used to make
            # revoking link 0 emit a false "link 1: scope widens" because
            # link 1 was compared against None.
            ok_n, why_n = scope_narrows(link.get("scope"), prev_scope)
            _check(ok_n, reasons, f"link {i}: scope widens ({why_n})")
        prev_scope = link.get("scope")
    # PRD modes (H-3): a mode-carrying chain — any link or the credential
    # carries a mode — must carry a *known* mode on every link and the
    # credential, non-increasing along the chain. Mixed chains, unknown
    # modes, and escalations deny (fail closed). A fully modeless chain is
    # the legacy pre-mode path and skips this.
    modes = ([l.get("mode") if isinstance(l, dict) else None
              for l in links]
             + [cred.get("mode")])
    if any(m is not None for m in modes):
        mode_bad = False
        for i, m in enumerate(modes):
            who = f"link {i}" if i < len(links) else "credential"
            if m is None:
                reasons.append(f"{who}: mode-carrying chain with a "
                               f"modeless grant; failing closed")
                mode_bad = True
            elif m not in _MODES:
                reasons.append(f"{who}: unknown delegation mode {m!r}; "
                               f"failing closed")
                mode_bad = True
        if not mode_bad:
            for i in range(1, len(modes)):
                if _MODE_RANK[modes[i]] > _MODE_RANK[modes[i - 1]]:
                    who = (f"link {i}" if i < len(links)
                           else "credential")
                    reasons.append(
                        f"{who}: delegation mode escalation "
                        f"({modes[i - 1]!r} -> {modes[i]!r}); a higher "
                        f"mode needs a fresh principal-signed grant")
    _check(links[-1].get("delegatee_pubkey") == cred.get("agent_pubkey"),
           reasons, "chain does not terminate at the credential's agent")
    ok_n, why_n = scope_narrows(cred.get("scope"), prev_scope)
    _check(ok_n, reasons, f"credential scope exceeds delegation ({why_n})")
    return not reasons, reasons


def verify_credential(cred, trusted_issuers, now=None,
                      revoked_link_handles=None):
    """Full credential check. Returns (ok, reasons list).

    revoked_link_handles: optional set-like of revoked per-link
    revocation handles; any chain containing one is denied (surgical
    link revocation). None disables the check.
    """
    now = _ts(now)
    reasons = []
    for f in ("credential_id", "principal", "agent_id", "agent_pubkey",
              "scope", "issued_at", "expires_at", "delegations",
              "issuer_pubkey", "signature"):
        _check(f in cred, reasons, f"credential missing field '{f}'")
    if reasons:
        return False, reasons

    _check(cred["issuer_pubkey"] in set(trusted_issuers), reasons,
           "issuer not trusted by this verifier")
    _check(cred["issued_at"] <= now < cred["expires_at"], reasons,
           "credential expired or not yet valid")
    _check(ed25519.verify_hex(cred["issuer_pubkey"],
                              canonical(_unsigned(cred)),
                              cred["signature"]),
           reasons, "credential issuer signature invalid")
    if reasons:
        return False, reasons  # no point walking a forged credential

    ok_c, why_c = _verify_chain(cred, now, revoked_link_handles)
    reasons.extend(why_c)
    return not reasons, reasons


def verify_action_request(req, trusted_issuers, now=None,
                         seen_nonces=None, usage=None, approval_nonces=None):
    """Verify a full action attempt. Returns (ok, reasons).

    req: {"credential", "action", "nonce", "ts", "agent_signature",
          "principal_approval" (optional, for prepare-mode effect actions)}
    seen_nonces: set-like of recently seen nonces (replay protection).
    usage: dict-like the caller maintains for rate limits, keyed
           (agent_pubkey, action_type, day) -> count. This function only
           *reads* it; the caller increments on allow.
    approval_nonces: set-like of consumed principal-approval nonces
           (membership read only; the caller reserves on allow).
    """
    now = _ts(now)
    reasons = []
    for f in ("credential", "action", "nonce", "ts", "agent_signature"):
        _check(f in req, reasons, f"request missing field '{f}'")
    if reasons:
        return False, reasons

    _check(abs(now - float(req["ts"])) <= CLOCK_SKEW, reasons,
           "request timestamp outside tolerance")
    if seen_nonces is not None:
        _check(req["nonce"] not in seen_nonces, reasons,
               "replay: nonce already seen")
    cred = req["credential"]
    ok, why = verify_credential(cred, trusted_issuers, now)
    if not ok:
        return False, [f"credential: {w}" for w in why]

    # proof of possession: the presenter must hold the agent's private key.
    # The signed envelope is exactly what sign_action_request() produces.
    signed_envelope = {
        "credential_id": cred["credential_id"],
        "action": req["action"],
        "nonce": req["nonce"],
        "ts": req["ts"],
    }
    _check(ed25519.verify_hex(cred["agent_pubkey"],
                              canonical(signed_envelope),
                              req["agent_signature"]),
           reasons, "agent signature invalid (not the credential holder?)")
    if reasons:
        return False, reasons

    action = req["action"]
    atype = action.get("type", "")
    _check(scope_allows(cred["scope"], atype), reasons,
           f"action '{atype}' outside authorized scope")
    # H-2 enforcement-time fail-closed: a limit key the delegation chain
    # requires must not vanish at the credential — absent is never
    # "unlimited".
    ok_cl, why_cl = check_chain_limits_present(cred, atype)
    if not ok_cl:
        return False, reasons + why_cl
    # PRD modes (H-3): read/prepare/execute enforcement; prepare-mode
    # effect actions need a signed principal approval.
    ok_m, why_m = _check_mode(cred, action, req.get("principal_approval"),
                              now, approval_nonces)
    if not ok_m:
        return False, reasons + why_m
    if usage is not None:
        normed = _norm_scope(cred["scope"])
        if any(_looks_like_pattern(k) for k in normed["limits"]):
            # A credential minted outside issue_credential() with pattern
            # limit keys would silently evade throttling (fail-open), so
            # refuse it outright instead of verifying with no limits.
            return False, reasons + [
                "credential 'limits' keys must be literal action types, "
                "not patterns; failing closed"]
        lim = normed["limits"].get(atype, {})
        max_day = lim.get("max_per_day")
        if max_day is not None:
            day = time.strftime("%Y-%m-%d", time.gmtime(now))
            used = usage.get((cred["agent_pubkey"], atype, day), 0)
            _check(used < max_day, reasons,
                   f"rate limit exceeded: {used}/{max_day} {atype}/day")
    return not reasons, reasons


# ------------------------------------------------------------- v2 (Phase 11)
_TIER_RANK = {"allowlist": 0, "domain-control": 1}


def default_tier_policy(min_tiers):
    """Build a tier-policy hook from {action_pattern: minimum_tier}.

    hook(tier, action_type) -> (ok, reason or None). Action patterns are
    matched with fnmatch (first match in insertion order wins); tiers rank
    allowlist < domain-control. Unknown tier strings in the config deny
    (fail-closed). The hook never raises for config problems — it returns
    (False, reason); verify_action_request_v2 also denies if a custom hook
    raises.

    The required-tiers dict is attached as hook.min_tiers so the verifier
    can report it in receipt evidence.
    """
    required = dict(min_tiers or {})

    def hook(tier, action_type):
        for pat, need in required.items():
            if fnmatch.fnmatchcase(action_type, pat):
                if need not in _TIER_RANK:
                    return False, (
                        f"tier policy misconfigured: unknown tier {need!r}")
                if _TIER_RANK.get(tier, -1) >= _TIER_RANK[need]:
                    return True, None
                return False, (f"action '{action_type}' requires "
                               f"{need} enrollment")
        return True, None

    hook.min_tiers = dict(required)
    return hook


def _valid_ts(ts, now):
    try:
        return abs(now - float(ts)) <= CLOCK_SKEW
    except (TypeError, ValueError):
        return False


def verify_action_request_v2(req, *, manifest, operator_pubkeys,
                             policy_hook=None, now=None, nonces=None,
                             usage=None, spending=None, approval_nonces=None):
    """Verification v2: enrollment-anchored, PRD check order, fail-closed.

    req: {"credential", "action", "nonce", "ts", "agent_signature",
          "principal_approval" (optional, for prepare-mode effect actions)}.
    manifest: the signed trust-root manifest dict (may be None -> deny).
    operator_pubkeys: trusted operator pubkey hex (str or list).
    policy_hook(tier, action_type) -> (ok, reason or None); a hook that
        raises is treated as deny (never allow on hook error).
    nonces: set-like of seen nonces (membership read only; the caller
        reserves the nonce on allow).
    usage: dict-like for rate limits, keyed (agent_pubkey, action_type,
        day) -> count (read only; the caller increments on allow).
    spending: dict-like for spending ceilings, keyed (credential_id,
        action_type, day) -> cents used (read only; the caller records on
        allow via an atomic check-and-add).
    approval_nonces: set-like of consumed principal-approval nonces
        (membership read only; the caller reserves on allow).

    Check order (first failure wins):
      1. manifest freshness        -> "trust root stale: ..." /
                                        "trust root unavailable"
      2. principal/key status       -> "principal not enrolled",
                                        "key revoked", "principal suspended",
                                        "key superseded", "enrollment
                                        expired", "credential revoked"
      3. credential signature       -> "credential signature invalid"
      4. delegation chain           -> existing chain reasons (scope
                                        narrowing + mode-chain rule)
      5. scope, then tier policy    -> "action '<t>' outside authorized
                                        scope", "action '<t>' requires
                                        <tier> enrollment"
      6. mode                       -> "unknown delegation mode ...",
                                        "unknown scope ...",
                                        "delegation mode 'read' does not
                                        authorize ...",
                                        "delegation mode 'prepare'
                                        requires a signed principal
                                        approval ..."
      7. timestamp skew, then replay -> "request timestamp outside
                                        tolerance", "replayed request"
      8. proof-of-possession        -> "agent signature invalid (not the
                                        credential holder?)"
      9. limits                     -> "rate limit exceeded: ...",
                                        "spending ceiling exceeded: ...",
                                        chain-required limit keys missing

    Returns (ok, reasons, evidence). evidence holds the 7 frozen receipt
    fields on allow ({} on deny): principal_id, principal_tier, key_id,
    enrollment_log_seq, manifest_version, manifest_valid_until,
    tier_policy.
    """
    from . import enrollment  # lazy: enrollment imports this module at top
    now = _ts(now)

    # -- 1. manifest freshness ----------------------------------------
    if not isinstance(manifest, dict):
        return False, ["trust root unavailable"], {}
    ok_m, why_m = enrollment.verify_manifest(manifest, operator_pubkeys, now)
    if not ok_m:
        first = why_m[0] if why_m else "manifest verification failed"
        if first.startswith("trust root stale"):
            return False, [first], {}
        return False, [f"trust root stale: {first}"], {}

    # -- 2. principal / key status ------------------------------------
    cred = req.get("credential") if isinstance(req, dict) else None
    principal = cred.get("principal") if isinstance(cred, dict) else None
    principal_id = (principal.get("id")
                    if isinstance(principal, dict) else None)
    entry = enrollment.lookup_principal(manifest, principal_id)
    if entry is None:
        return False, ["principal not enrolled"], {}
    issuer_pubkey = (cred.get("issuer_pubkey")
                     if isinstance(cred, dict) else None)
    try:
        key_id = enrollment.jwk_thumbprint(issuer_pubkey)
    except Exception:
        key_id = None
    if key_id is None:
        return False, ["principal not enrolled"], {}
    kstatus = enrollment.principal_key_status(entry, issuer_pubkey, now)
    if kstatus == "revoked":
        return False, ["key revoked"], {}
    if kstatus == "suspended":
        return False, ["principal suspended"], {}
    if kstatus == "superseded-expired":
        return False, ["key superseded"], {}
    if kstatus == "expired":
        return False, ["enrollment expired"], {}
    if kstatus not in ("active", "superseded-valid"):
        # "unknown" or anything future: fail closed.
        return False, ["principal not enrolled"], {}
    revoked = manifest.get("revoked_credentials") or []
    rh = cred.get("revocation_handle")
    if rh and rh in revoked:
        return False, ["credential revoked"], {}

    evidence = {
        "principal_id": principal_id,
        "principal_tier": entry.get("tier"),
        "key_id": key_id,
        "enrollment_log_seq": entry.get("enrollment_log_seq"),
        "manifest_version": manifest.get("version"),
        "manifest_valid_until": manifest.get("valid_until"),
        "tier_policy": (dict(getattr(policy_hook, "min_tiers", None))
                        if getattr(policy_hook, "min_tiers", None)
                        else None),
    }

    # -- 3. credential signature (+ expiry, fail-closed) ---------------
    sig_ok = False
    try:
        sig_ok = bool(ed25519.verify_hex(
            cred["issuer_pubkey"],
            canonical(_unsigned(cred)),
            cred.get("signature")))
    except Exception:
        sig_ok = False
    if not sig_ok:
        return False, ["credential signature invalid"], {}
    if not (isinstance(cred.get("issued_at"), (int, float)) and
            isinstance(cred.get("expires_at"), (int, float)) and
            not isinstance(cred.get("issued_at"), bool) and
            not isinstance(cred.get("expires_at"), bool) and
            cred["issued_at"] <= now < cred["expires_at"]):
        return False, ["credential expired or not yet valid"], {}

    # -- 4. delegation chain (per-link revocation enforced) --------------
    ok_c, why_c = _verify_chain(
        cred, now, manifest.get("revoked_delegation_handles") or ())
    if not ok_c:
        return False, why_c, {}

    # -- 5. scope, then tier policy ------------------------------------
    action = req.get("action") if isinstance(req, dict) else None
    action = action if isinstance(action, dict) else {}
    atype = action.get("type", "")
    if not scope_allows(cred.get("scope"), atype):
        return False, [f"action '{atype}' outside authorized scope"], {}
    if policy_hook is not None:
        try:
            ok_p, why_p = policy_hook(evidence["principal_tier"], atype)
        except Exception:
            ok_p, why_p = False, "tier policy check failed"
        if not ok_p:
            return False, [why_p or
                           f"action '{atype}' requires higher-tier "
                           "enrollment"], {}

    # -- 6. mode --------------------------------------------------------
    # PRD: a prepare-mode action without a principal approval does not
    # verify as authorized. Unknown modes deny (fail closed); legacy
    # modeless credentials skip this step entirely.
    ok_m, why_m = _check_mode(
        cred, action,
        req.get("principal_approval") if isinstance(req, dict) else None,
        now, approval_nonces)
    if not ok_m:
        return False, why_m, {}

    # -- 7. timestamp skew, then replay ---------------------------------
    if not _valid_ts(req.get("ts") if isinstance(req, dict) else None, now):
        return False, ["request timestamp outside tolerance"], {}
    if nonces is not None:
        try:
            seen = (req.get("nonce") in nonces) if isinstance(req, dict) \
                else True
        except Exception:
            seen = True  # unusable nonce store: fail closed
        if seen:
            return False, ["replayed request"], {}

    # -- 8. proof-of-possession -----------------------------------------
    pop_ok = False
    try:
        envelope = {
            "credential_id": cred["credential_id"],
            "action": req["action"],
            "nonce": req["nonce"],
            "ts": req["ts"],
        }
        pop_ok = bool(ed25519.verify_hex(cred["agent_pubkey"],
                                         canonical(envelope),
                                         req.get("agent_signature")))
    except Exception:
        pop_ok = False
    if not pop_ok:
        return False, ["agent signature invalid (not the credential "
                       "holder?)"], {}

    # -- 9. limits: rate, then spending ----------------------------------
    normed = _norm_scope(cred.get("scope"))
    if any(_looks_like_pattern(k) for k in normed["limits"]):
        # A credential minted outside issue_credential() with pattern limit
        # keys would silently evade throttling (fail-open), so refuse it
        # outright instead of verifying with no limits.
        return False, ["credential 'limits' keys must be literal action "
                       "types, not patterns; failing closed"], {}
    # H-2 enforcement-time fail-closed: the delegation chain may require
    # limit keys the credential omits. Absent is never "unlimited".
    # (Defense in depth — step 4's chain check already enforces this for
    # well-formed chains.)
    ok_cl, why_cl = check_chain_limits_present(cred, atype)
    if not ok_cl:
        return False, why_cl, {}
    lim = normed["limits"].get(atype, {})
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    if usage is not None:
        max_day = lim.get("max_per_day")
        if max_day is not None:
            try:
                used = usage.get((cred["agent_pubkey"], atype, day), 0)
                over = not (used < max_day)
            except Exception:
                used, over = 0, True  # unusable usage store: fail closed
            if over:
                return False, [f"rate limit exceeded: {used}/{max_day} "
                               f"{atype}/day"], {}
    amount = action.get("amount_cents")
    if amount is not None:
        if (isinstance(amount, bool) or not isinstance(amount, int) or
                amount < 0):
            return False, ["action amount_cents must be a non-negative "
                           "integer"], {}
    ceiling = lim.get("max_spend_per_day")
    if (ceiling is not None and amount is not None and spending is not None):
        try:
            used_cents = spending.get(
                (cred["credential_id"], atype, day), 0)
            over = used_cents + amount > ceiling
        except Exception:
            used_cents, over = 0, True  # unusable store: fail closed
        if over:
            return False, [f"spending ceiling exceeded: "
                           f"{used_cents + amount}/{ceiling} {atype}/day "
                           f"(cents)"], {}
    return True, [], evidence
