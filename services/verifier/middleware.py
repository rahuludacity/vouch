"""Vouch Phase 14 — agent-differentiated serving reference middleware (PRD §3.7).

This is a *reference implementation* of how a site branches traffic by
agent-verification status. Sites own their own experience; this module
shows the shape:

    verified-agent lane  credential verifies -> cheap lane (summary, not
                         the full page) — the site's selfish reason to
                         install Vouch is lower serving cost on agent
                         traffic.
    human lane           normal browser traffic -> the normal page.
    challenge lane       unknown or unverified traffic -> the site's
                         status-quo challenge path ("verify to continue").

Security posture (reference implementations must be copy-safe):
  * Fail closed: every verifier error, malformed envelope, oversize
    envelope, cache error, or missing credential routes to the challenge
    lane. Nothing here can produce an allow except a live allow decision
    from the verifier.
  * No positive caching: an "allow" is ALWAYS a live verifier decision.
    Proof-of-possession is per-request — a cached allow would let a
    stolen credential ride a cached verdict without a valid agent
    signature, and it would blind the verifier's per-request
    rate/spending accounting. Only deny/unreachable verdicts are cached
    (short TTL), to absorb retry storms.
  * The verdict cache is keyed by sha256 of the canonical envelope
    bytes, not by credential_id — a tampered envelope cannot alias a
    cached entry.
  * Credential envelopes are size-capped (64 KiB) before JSON parsing.
  * No credential material lands in metrics, verdict dicts, or logs.
  * serve() binds 127.0.0.1 only (demo/test helper, not a deployment
    shape).

Language (PRD section 4): Tier 0 is "allowlist", Tier 1 is
"domain-control". This module never claims identity — a verifier "allow"
means the credential checked out, nothing more.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.parse
import urllib.request
from wsgiref.simple_server import WSGIRequestHandler, make_server


# ---------------------------------------------------------------------------
# classify
# ---------------------------------------------------------------------------

# Short, deliberately non-exhaustive list of well-known crawler/agent
# user-agent substrings. This is a HEURISTIC: a polite crawler's UA is a
# convenience signal, not authentication. A malicious client can forge any
# UA string, which is exactly why "agent" classification here only grants
# access to the *credential check*, and a verified-agent lane requires a
# live verifier allow.
_KNOWN_BOTS = (
    "googlebot",
    "bingbot",
    "slurp",
    "duckduckbot",
    "baiduspider",
    "yandexbot",
    "facebookexternalhit",
    "twitterbot",
    "applebot",
    "gptbot",
    "claudebot",
    "anthropic-ai",
    "ccbot",
    "bytespider",
)


def _first(value):
    """Accept the str-or-list shape that query parsing produces."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else ""
    return value


def classify(headers: dict, query: dict) -> str:
    """Classify a request as "human", "agent", or "unknown".

    Pure function, no I/O. ``headers`` maps header name -> value
    (lookup is case-insensitive); ``query`` maps query parameter name ->
    value (a plain str, or the list-of-str shape parse_qs produces).

    Precedence:
      1. ``?agent=1`` query override wins over everything (lets a site or
         a test force agent handling regardless of UA).
      2. Known-bot UA substrings -> "agent" (heuristic, documented above).
      3. Missing/empty User-Agent -> "unknown" (do not assume human).
      4. Anything else -> "human".
    """
    lowered_query = {str(k).lower(): _first(v) for k, v in query.items()}
    if str(lowered_query.get("agent", "")).strip().lower() == "1":
        return "agent"
    ua = ""
    for name, value in headers.items():
        if str(name).lower() == "user-agent":
            ua = str(value)
            break
    if not ua.strip():
        return "unknown"
    low = ua.lower()
    if any(bot in low for bot in _KNOWN_BOTS):
        return "agent"
    return "human"


# ---------------------------------------------------------------------------
# verifier client
# ---------------------------------------------------------------------------

class VerifierUnreachable(Exception):
    """The verifier could not be consulted (transport error, timeout, or a
    response that is not a well-formed decision). The middleware treats
    this as fail-closed -> challenge lane."""


class _VerifierClient:
    """Thin wrapper over POST {base_url}/v1/verify (matches the verifier
    service's endpoint shape in services/verifier/app.py)."""

    def __init__(self, base_url, timeout_s=5):
        self.base_url = base_url.rstrip("/")
        self.verify_url = self.base_url + "/v1/verify"
        self.timeout_s = timeout_s

    def verify(self, envelope: dict) -> dict:
        """Submit the agent's signed request envelope; return
        {"decision","lane","reason"}.

        The envelope is the agent's own signed request for this access:
        {"credential","action","nonce","ts","agent_signature"}. It is
        forwarded AS-IS to the verifier (plus tenant_id) — the verifier
        checks proof-of-possession against the agent's signature over the
        agent's own nonce/ts. The client MUST NOT mint a fresh nonce/ts
        here: that would break the agent's signature and every request
        would deny at proof-of-possession. Any transport/parse problem,
        or a malformed envelope, raises VerifierUnreachable (fail-closed
        upstream).
        """
        if not isinstance(envelope, dict):
            raise VerifierUnreachable("envelope is not an object")
        credential = envelope.get("credential")
        action = envelope.get("action")
        nonce = envelope.get("nonce")
        ts = envelope.get("ts")
        agent_signature = envelope.get("agent_signature")
        if not isinstance(credential, dict):
            raise VerifierUnreachable("envelope has no credential object")
        if not isinstance(action, dict):
            raise VerifierUnreachable("envelope has no action object")
        if not isinstance(nonce, str) or not nonce:
            raise VerifierUnreachable("envelope has no nonce")
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            raise VerifierUnreachable("envelope has no numeric ts")
        if not isinstance(agent_signature, str) or not agent_signature:
            raise VerifierUnreachable("envelope has no agent_signature")
        body = json.dumps({
            "tenant_id": "default",
            "credential": credential,
            "action": action,
            "nonce": nonce,
            "ts": ts,
            "agent_signature": agent_signature,
        }).encode("utf-8")
        request = urllib.request.Request(
            self.verify_url, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request,
                                        timeout=self.timeout_s) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise VerifierUnreachable(
                f"verifier request failed: {type(exc).__name__}") from exc
        if not isinstance(payload, dict):
            raise VerifierUnreachable("verifier returned non-object body")
        if payload.get("decision") not in ("allow", "deny"):
            raise VerifierUnreachable("verifier returned no decision")
        return {
            "decision": payload["decision"],
            "lane": str(payload.get("lane", "")),
            "reason": str(payload.get("reason", "")),
        }


def verifier_client(base_url, timeout_s=5):
    """Build a verifier client for the middleware."""
    return _VerifierClient(base_url, timeout_s=timeout_s)


# ---------------------------------------------------------------------------
# verdict cache
# ---------------------------------------------------------------------------

def _canonical_credential_bytes(envelope: dict) -> bytes:
    """Canonical byte form of a credential envelope.

    The cache key binds the *full credential bytes* — signature included.
    A tampered signature under the same credential_id serializes to
    different bytes and therefore a different key: id-only aliasing is
    impossible by construction.
    """
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


class VerdictCache:
    """Short-TTL cache of verifier decisions, keyed by envelope content.

    Non-allow decisions are stored with the short ``negative_ttl_s`` so a
    transient outage or a retried bad credential does not hammer the
    verifier; the class can technically store allows with ``ttl_s``, but
    VouchMiddleware deliberately never does (see _verify_agent: an allow
    must always be a live verifier decision). Size is capped (oldest
    entries evicted first) to bound memory. Only the decision/lane/reason
    are stored — never the credential itself.
    """

    def __init__(self, ttl_s=60, negative_ttl_s=10, max_entries=10000):
        self.ttl_s = ttl_s
        self.negative_ttl_s = negative_ttl_s
        self.max_entries = max_entries
        # digest -> (decision, lane, reason, expires_at). dicts are
        # insertion-ordered, so the front is the oldest for eviction.
        self._entries = {}

    @staticmethod
    def key_for(envelope: dict) -> str:
        return hashlib.sha256(
            _canonical_credential_bytes(envelope)).hexdigest()

    def get(self, envelope: dict):
        """Return (decision, lane, reason) or None on miss/expiry."""
        now = time.time()
        digest = self.key_for(envelope)
        entry = self._entries.get(digest)
        if entry is None:
            return None
        decision, lane, reason, expires_at = entry
        if expires_at <= now:
            del self._entries[digest]
            return None
        return (decision, lane, reason)

    def put(self, envelope: dict, decision: str,
            lane: str = "", reason: str = "") -> None:
        """Store a verdict. Non-allow decisions get the short negative TTL."""
        ttl = self.ttl_s if decision == "allow" else self.negative_ttl_s
        digest = self.key_for(envelope)
        while len(self._entries) >= self.max_entries:
            self._entries.pop(next(iter(self._entries)))
        self._entries[digest] = (decision, lane, reason, time.time() + ttl)


# ---------------------------------------------------------------------------
# WSGI middleware
# ---------------------------------------------------------------------------

def _wsgi_headers(environ) -> dict:
    """environ -> lowercase header-name dict (case-insensitive lookup)."""
    headers = {}
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            headers[key[5:].replace("_", "-").lower()] = value
        elif key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            headers[key.replace("_", "-").lower()] = value
    return headers


class VouchMiddleware:
    """WSGI branch: verified-agent / human / unverified->challenge.

    Flow per request:
      classify -> "agent": extract the credential envelope
          (X-Vouch-Credential header JSON, else ?vouch_credential query
          param; missing/malformed/oversize -> challenge lane)
        -> cache lookup (by credential content) -> verifier.verify on
           miss -> decision "allow" + lane "verified-agent" routes to
           agent_app; anything else (deny, unreachable, malformed, no
           credential) -> challenge_app (fail-closed).
        "human" -> human_app. "unknown" -> challenge_app.

    environ["vouch.verdict"] is set for downstream apps:
    {"classification","lane","decision","reason"} — counters only, no
    credential material. ``metrics`` (a plain dict) accumulates
    {"human","agent_allow","agent_challenge","unknown"}.
    """

    MAX_CREDENTIAL_BYTES = 64 * 1024

    def __init__(self, agent_app, human_app, challenge_app, *,
                 verifier, cache=None, metrics=None):
        self._agent_app = agent_app
        self._human_app = human_app
        self._challenge_app = challenge_app
        self._verifier = verifier
        self._cache = cache if cache is not None else VerdictCache()
        self._metrics = metrics

    def _count(self, key):
        if self._metrics is not None:
            self._metrics[key] = self._metrics.get(key, 0) + 1

    # -- envelope extraction --------------------------------------------
    def _extract_envelope(self, headers, query):
        """Return (envelope_dict, error_str). envelope is None on error.

        The raw envelope is size-capped *before* JSON parsing, and a
        non-dict JSON value is treated as malformed (an envelope is a
        credential object, never a bare string/number).
        """
        raw = headers.get("x-vouch-credential")
        if raw is None:
            raw = _first(query.get("vouch_credential"))
        if raw is None or str(raw) == "":
            return None, "missing"
        raw_str = str(raw)
        if len(raw_str.encode("utf-8")) > self.MAX_CREDENTIAL_BYTES:
            return None, "oversize"
        try:
            envelope = json.loads(raw_str)
        except Exception:
            return None, "malformed"
        if not isinstance(envelope, dict):
            return None, "malformed"
        return envelope, None

    # -- decision --------------------------------------------------------
    def _verify_agent(self, envelope):
        """Return (lane, decision, reason) for an agent-classified request.

        Never raises: any cache/verifier failure returns the challenge
        lane (fail-closed). The verifier's decision is the only path to
        the agent lane.

        Deliberately NO positive caching: an "allow" is always a live
        verifier decision. Proof-of-possession is per-request — a cached
        allow would let a stolen credential ride a cached verdict without
        a valid agent signature, and it would blind the verifier's
        per-request rate/spending accounting. Only deny/unreachable
        verdicts are cached (short TTL), so a retry storm does not hammer
        a downed verifier.
        """
        try:
            cached = self._cache.get(envelope)
        except Exception:
            cached = None
        if cached is not None:
            decision, lane, reason = cached
            # The cache only ever holds non-allow verdicts (see below);
            # anything cached routes to the challenge lane.
            return "challenge", decision, reason
        try:
            result = self._verifier.verify(envelope)
        except Exception:
            # Fail closed on unreachable/misbehaving verifier — and
            # remember the negative verdict briefly so a retry storm
            # does not hammer a downed verifier.
            try:
                self._cache.put(envelope, "unreachable", "",
                                "verifier unreachable")
            except Exception:
                pass
            return "challenge", "unreachable", "verifier unreachable"
        decision = result.get("decision", "deny")
        lane = result.get("lane", "")
        reason = result.get("reason", "")
        if decision != "allow":
            # Negative verdicts only (see docstring): cache briefly so a
            # retry storm does not hammer the verifier on every request.
            try:
                self._cache.put(envelope, decision, lane, reason)
            except Exception:
                pass
        if decision == "allow" and lane == "verified-agent":
            return "agent", decision, reason
        return "challenge", decision, reason

    def __call__(self, environ, start_response):
        headers = _wsgi_headers(environ)
        query = dict(urllib.parse.parse_qsl(
            environ.get("QUERY_STRING", ""), keep_blank_values=True))
        classification = classify(headers, query)

        if classification == "human":
            lane, decision, reason = "human", None, None
        elif classification == "unknown":
            lane, decision, reason = "challenge", None, \
                "no user-agent: treating as unverified"
        else:  # "agent"
            envelope, error = self._extract_envelope(headers, query)
            if envelope is None:
                lane, decision, reason = "challenge", "deny", \
                    f"credential envelope {error}"
            else:
                lane, decision, reason = self._verify_agent(envelope)

        # Counters only — no credential material in metrics or verdict.
        if lane == "agent":
            self._count("agent_allow")
        elif lane == "challenge" and classification == "agent":
            self._count("agent_challenge")
        elif classification == "human":
            self._count("human")
        else:
            self._count("unknown")
        environ["vouch.verdict"] = {
            "classification": classification,
            "lane": lane,
            "decision": decision,
            "reason": reason,
        }

        if lane == "agent":
            return self._agent_app(environ, start_response)
        if lane == "human":
            return self._human_app(environ, start_response)
        return self._challenge_app(environ, start_response)


# ---------------------------------------------------------------------------
# serve() demo trio
# ---------------------------------------------------------------------------

def _demo_human_app(environ, start_response):
    """The normal page: full render, as the site would serve a browser."""
    body = (b"<html><body><h1>Acme Store</h1>"
            b"<p>Welcome! This is the full storefront page.</p>"
            b"</body></html>")
    start_response("200 OK", [("Content-Type", "text/html; charset=utf-8"),
                              ("Content-Length", str(len(body)))])
    return [body]


def _demo_agent_app(environ, start_response):
    # The PRD demo point: the verified-agent lane does OBSERVABLY LESS
    # WORK than the human page — a small precomputed JSON summary, no
    # template render, no DB queries, no media. That is the site's selfish
    # incentive: cheaper serving on agent traffic.
    payload = {"lane": "verified-agent",
               "summary": "Acme Store — 3 featured products, in stock.",
               "rendered": "cheap-summary-only"}
    body = json.dumps(payload).encode("utf-8")
    start_response("200 OK", [("Content-Type", "application/json"),
                              ("Content-Length", str(len(body)))])
    return [body]


def _demo_challenge_app(environ, start_response):
    body = (b"<html><body><h1>Verify to continue</h1>"
            b"<p>This request looks automated and carries no valid Vouch "
            b"credential. Present a credential to continue.</p>"
            b"</body></html>")
    start_response("402 Payment Required",
                   [("Content-Type", "text/html; charset=utf-8"),
                    ("Content-Length", str(len(body)))])
    return [body]


class _QuietWSGIHandler(WSGIRequestHandler):
    """wsgiref handler that does not log requests (no URLs — which could
    carry a vouch_credential query param — in logs)."""

    def log_message(self, *args):
        pass


def serve(agent_app=None, human_app=None, challenge_app=None, verifier=None,
          port=0):
    """Build the middleware around a demo trio and serve on 127.0.0.1.

    Any of the three apps may be supplied; omitted ones default to the
    demo trio. Returns (server, port). Loopback only — this is a demo/PRD
    harness, not a deployment shape. Call server.shutdown() when done.
    """
    if human_app is None:
        human_app = _demo_human_app
    if agent_app is None:
        agent_app = _demo_agent_app
    if challenge_app is None:
        challenge_app = _demo_challenge_app
    app = VouchMiddleware(agent_app, human_app, challenge_app,
                          verifier=verifier, cache=VerdictCache(),
                          metrics={})
    server = make_server("127.0.0.1", port, app,
                         handler_class=_QuietWSGIHandler)
    return server, server.server_address[1]
