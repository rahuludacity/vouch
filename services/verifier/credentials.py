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
import fnmatch
import json
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


def scope_allows(scope, action_type):
    """True iff action_type passes the scope's allow/deny patterns."""
    scope = _norm_scope(scope)
    allowed = any(fnmatch.fnmatchcase(action_type, pat)
                  for pat in scope["allow"])
    denied = any(fnmatch.fnmatchcase(action_type, pat)
                 for pat in scope["deny"])
    return allowed and not denied


def scope_narrows(child, parent):
    """True iff child grants no more than parent (for delegation links)."""
    c, p = _norm_scope(child), _norm_scope(parent)
    if any(pat not in p["allow"] for pat in c["allow"]):
        return False, "allow list wider than delegator's"
    if any(pat not in c["deny"] for pat in p["deny"]):
        return False, "cannot drop a delegator's deny"
    for action, lim in c["limits"].items():
        plim = p["limits"].get(action, {})
        for k, v in lim.items():
            pv = plim.get(k)
            if pv is not None and v > pv:
                return False, f"limit {action}.{k} looser than delegator's"
    return True, ""


# ---------------------------------------------------------------- issuance
def issue_delegation(*, delegator_priv_hex, delegator_pub_hex,
                     delegatee_pub_hex, scope, ttl_s=86400, issued_at=None):
    """One signed delegation link. Returns the link dict (with signature)."""
    now = _ts(issued_at)
    link = {
        "delegator_pubkey": delegator_pub_hex,
        "delegatee_pubkey": delegatee_pub_hex,
        "scope": _norm_scope(scope),
        "issued_at": now,
        "expires_at": round(now + ttl_s, 3),
    }
    link["signature"] = ed25519.sign_hex(delegator_priv_hex,
                                         canonical(_unsigned(link)))
    return link


def _unsigned(d):
    return {k: v for k, v in d.items() if k != "signature"}


def issue_credential(*, principal_id, principal_priv_hex, principal_pub_hex,
                     agent_id, agent_pub_hex, scope,
                     delegations=(), ttl_s=86400, issued_at=None,
                     credential_id=None):
    """Mint an agent credential, signed by the principal (the issuer).

    delegations: extra links appended after the implicit principal->agent
    grant, e.g. agent->sub-agent re-delegations. Each must already be
    signed (see issue_delegation). The credential's effective scope must
    narrow the last delegation's scope.
    """
    now = _ts(issued_at)
    scope = _norm_scope(scope)
    links = list(delegations)
    if links:
        ok, why = scope_narrows(scope, links[-1]["scope"])
        if not ok:
            raise ValueError(f"credential scope invalid: {why}")
    cred = {
        "credential_id": credential_id or f"cred-{uuid.uuid4().hex[:12]}",
        "principal": {"id": principal_id, "pubkey": principal_pub_hex},
        "agent_id": agent_id,
        "agent_pubkey": agent_pub_hex,
        "scope": scope,
        "issued_at": now,
        "expires_at": round(now + ttl_s, 3),
        "delegations": links,
        "issuer_pubkey": principal_pub_hex,
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


def verify_credential(cred, trusted_issuers, now=None):
    """Full credential check. Returns (ok, reasons list)."""
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

    links = cred["delegations"]
    _check(isinstance(links, list) and len(links) >= 1, reasons,
           "delegation chain empty: principal must delegate to the agent")
    if reasons:
        return False, reasons
    _check(links[0]["delegator_pubkey"] == cred["principal"]["pubkey"],
           reasons, "chain root is not the principal")
    prev_scope = None
    for i, link in enumerate(links):
        ok, why = verify_delegation_link(link, now)
        if not ok:
            reasons.extend(f"link {i}: {w}" for w in why)
            continue
        if i > 0:
            _check(link["delegator_pubkey"] ==
                   links[i - 1]["delegatee_pubkey"], reasons,
                   f"link {i}: chain continuity broken")
            ok_n, why_n = scope_narrows(link["scope"], prev_scope)
            _check(ok_n, reasons, f"link {i}: scope widens ({why_n})")
        prev_scope = link["scope"]
    _check(links[-1]["delegatee_pubkey"] == cred["agent_pubkey"], reasons,
           "chain does not terminate at the credential's agent")
    ok_n, why_n = scope_narrows(cred["scope"], prev_scope)
    _check(ok_n, reasons, f"credential scope exceeds delegation ({why_n})")
    return not reasons, reasons


def verify_action_request(req, trusted_issuers, now=None,
                         seen_nonces=None, usage=None):
    """Verify a full action attempt. Returns (ok, reasons).

    req: {"credential", "action", "nonce", "ts", "agent_signature"}
    seen_nonces: set-like of recently seen nonces (replay protection).
    usage: dict-like the caller maintains for rate limits, keyed
           (agent_pubkey, action_type, day) -> count. This function only
           *reads* it; the caller increments on allow.
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
    if usage is not None:
        lim = _norm_scope(cred["scope"])["limits"].get(atype, {})
        max_day = lim.get("max_per_day")
        if max_day is not None:
            day = time.strftime("%Y-%m-%d", time.gmtime(now))
            used = usage.get((cred["agent_pubkey"], atype, day), 0)
            _check(used < max_day, reasons,
                   f"rate limit exceeded: {used}/{max_day} {atype}/day")
    return not reasons, reasons
