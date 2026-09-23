"""RFC 9421 HTTP Message Signatures — sign/verify for agent HTTP requests,
plus the /.well-known/vouch-keys key directory (JWKS shape).

Wire format is the Cloudflare Web Bot Auth convention (IETF RFC 9421
HTTP Message Signatures): a JWKS served at the well-known URI whose
entries carry kid = RFC 7638 JWK thumbprint, and per-request
Signature-Input / Signature headers. Vouch uses tag="vouch".

Covered components: @method @authority @scheme @path @query @target-uri
content-digest, plus lowercased named headers. content-digest is
`sha-512=:<base64>:` per RFC 9421.

Security posture (Singham): fail-closed on every parse/verify
exception; covered-component values derived from the *actual* request
(never trusted from the header's copies); header values treated as
untrusted (CR/LF stripped, length-capped); no key material in errors;
hmac.compare_digest for the keyid token comparison; no network calls
(fetching remote key directories is out of scope for this phase).
"""
import base64
import hashlib
import hmac
import re
import time

from . import ed25519

# Cap on any single covered-component value (untrusted header input).
_MAX_COMPONENT_LEN = 8192
# Cap on the number of covered components in one Signature-Input.
_MAX_COMPONENTS = 64

# Components with derivation rules (RFC 9421, Section 2.2). Anything else
# must be a lowercased HTTP field name (token chars, RFC 9110).
_DERIVED = frozenset({
    "@method", "@authority", "@scheme", "@path", "@query",
    "@target-uri", "content-digest",
})
_FIELD_RE = re.compile(r"^[a-z0-9][a-z0-9!#$%&'*+\-.^_`|~]*$")

# Scheme hard-coded to https: neither the frozen sign/verify signatures
# carry a scheme, and Web Bot Auth traffic is https in practice.
_SCHEME = "https"


def _jwk_thumbprint(pubkey_hex):
    # DEDUPE(phase9-merge): replace with from services.verifier.enrollment import jwk_thumbprint
    """RFC 7638 JWK thumbprint of an Ed25519 pubkey (base64url, no pad)."""
    try:
        raw = bytes.fromhex(pubkey_hex)
    except (ValueError, TypeError):
        raise ValueError("pubkey must be hex")
    if len(raw) != 32:
        raise ValueError("pubkey must be 32 bytes")
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    jwk = '{"crv":"Ed25519","kty":"OKP","x":"' + x + '"}'
    digest = hashlib.sha256(jwk.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _b64_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _sanitize(value):
    """Header/component values are untrusted: strip CR/LF, cap length."""
    s = value if isinstance(value, str) else str(value)
    s = s.replace("\r", "").replace("\n", "")
    if len(s) > _MAX_COMPONENT_LEN:
        raise ValueError("component value too long")
    return s


def _normalize_headers(headers):
    """Lowercase header names; duplicate case-variants are rejected.

    HTTP field names are case-insensitive (RFC 9110), so "Content-Type"
    and "content-type" in the same request are ambiguous — fail closed
    rather than pick one.
    """
    norm = {}
    for k, v in (headers or {}).items():
        kl = str(k).lower()
        if kl in norm:
            raise ValueError(f"duplicate header {kl!r}")
        norm[kl] = v
    return norm


def _check_component(name):
    if name in _DERIVED:
        return
    if not _FIELD_RE.match(name):
        raise ValueError(f"bad covered component {name!r}")


# ---------------------------------------------------------------- components
def _split_path(path):
    """Split 'path' into (path-only, query) — query excludes the '?'."""
    p = _sanitize(path)
    if "?" in p:
        return p.split("?", 1)
    return p, ""


def _derive_component(name, *, method, authority, path, headers, body):
    """Value for one covered component, from the actual request values."""
    lname = name.lower()
    if lname == "@method":
        return _sanitize(method).upper()
    if lname == "@authority":
        return _sanitize(authority).lower()
    if lname == "@scheme":
        return _SCHEME
    if lname == "@path":
        p, _q = _split_path(path)
        return p
    if lname == "@query":
        _p, q = _split_path(path)
        return ("?" + q) if q else ""
    if lname == "@target-uri":
        p, q = _split_path(path)
        full = p + ("?" + q if q else "")
        return _SCHEME + "://" + _sanitize(authority).lower() + full
    if lname == "content-digest":
        b = body if isinstance(body, (bytes, bytearray)) else bytes(body)
        return "sha-512=:" + base64.b64encode(
            hashlib.sha512(bytes(b)).digest()).decode("ascii") + ":"
    # named header: case-insensitive lookup over the actual request headers
    if lname in headers:
        return _sanitize(headers[lname])
    raise ValueError(f"covered header {name!r} not present in request")


def _inner_list(components, params):
    """Serialize the Signature-Input inner list (label excluded).

    Items are double-quoted component names; parameters are serialized in
    a fixed order so our own round-trip is deterministic.
    """
    items = " ".join('"' + c + '"' for c in components)
    parts = [
        f"created={params['created']}",
        f'keyid="{params["keyid"]}"',
        f'alg="{params["alg"]}"',
        f"expires={params['expires']}",
        f'tag="{params["tag"]}"',
    ]
    return f"({items});" + ";".join(parts)


# ---------------------------------------------------------------- signing
def sign_http_request(*, priv_hex, keyid, method, authority, path,
                      headers=None, body=b"", covered=("@method",
                                                      "@authority",
                                                      "@path",
                                                      "content-digest"),
                      tag="vouch", created=None, expires_s=300):
    """Sign an HTTP request per RFC 9421.

    Returns {"Signature-Input": ..., "Signature": ...} — the two header
    values to send with the request. `covered` names the components to
    cover (case-insensitive; stored lowercase).
    """
    if body is None:
        body = b""
    headers = _normalize_headers(headers)
    for token_name, token in (("keyid", keyid), ("tag", tag)):
        if '"' in str(token) or "\\" in str(token):
            raise ValueError(f"bad {token_name}: must not contain quotes")
    components = [str(c).lower() for c in covered]
    if not components or len(components) > _MAX_COMPONENTS:
        raise ValueError("bad covered component list")
    for c in components:
        _check_component(c)
    created = int(time.time()) if created is None else int(created)
    expires = created + int(expires_s)
    params = {"created": created, "keyid": str(keyid), "alg": "ed25519",
              "expires": expires, "tag": str(tag)}
    inner = _inner_list(components, params)
    lines = []
    for c in components:
        val = _derive_component(c, method=method, authority=authority,
                                path=path, headers=headers, body=body)
        lines.append('"' + c + '": ' + val)
    lines.append('"@signature-params": ' + inner)
    base = "\n".join(lines).encode("utf-8")
    try:
        sig = ed25519.sign(bytes.fromhex(priv_hex), base)
    except (ValueError, TypeError) as e:
        raise ValueError("bad private key") from e
    label = "sig1"
    return {
        "Signature-Input": f"{label}={inner}",
        "Signature": f"{label}=:{base64.b64encode(sig).decode('ascii')}:",
    }


# ---------------------------------------------------------------- parsing
def _parse_signature_input(value):
    """Parse a Signature-Input header value.

    Returns (label, [component names], {param: value}). Raises ValueError
    on anything unparseable. Only supports the shape our signer emits —
    label=(items);created=..;keyid="..";alg="..";expires=..;tag=".." —
    with per-item parameters rejected.
    """
    v = value if isinstance(value, str) else str(value)
    v = v.replace("\r", "").replace("\n", "")
    if len(v) > 8 * 1024:
        raise ValueError("Signature-Input too long")
    m = re.match(r"^\s*([A-Za-z][A-Za-z0-9!#$%&'*+\-.^_`|~]*)\s*=\s*\(", v)
    if not m:
        raise ValueError("bad Signature-Input: no label")
    label = m.group(1)
    rest = v[m.end() - 1:]
    if not rest.startswith("("):
        raise ValueError("bad Signature-Input: no inner list")
    # parse the parenthesized item list, rejecting per-item parameters
    items = []
    i = 1
    while True:
        while i < len(rest) and rest[i] == " ":
            i += 1
        if i >= len(rest):
            raise ValueError("bad Signature-Input: unterminated list")
        if rest[i] == ")":
            i += 1
            break
        if rest[i] != '"':
            raise ValueError("bad Signature-Input: item not a string")
        j = rest.find('"', i + 1)
        if j == -1 or "\\" in rest[i + 1:j]:
            raise ValueError("bad Signature-Input: bad item string")
        items.append(rest[i + 1:j].lower())
        i = j + 1
        while i < len(rest) and rest[i] == " ":
            i += 1
        if i < len(rest) and rest[i] == ";":
            raise ValueError("bad Signature-Input: per-item params rejected")
    if not items or len(items) > _MAX_COMPONENTS:
        raise ValueError("bad Signature-Input: bad item count")
    params = {}
    tail = rest[i:]
    for tok in (t.strip() for t in tail.split(";")):
        if not tok:
            continue
        if "=" not in tok:
            raise ValueError("bad Signature-Input: bad parameter")
        k, val = tok.split("=", 1)
        k = k.strip().lower()
        val = val.strip()
        if val.startswith('"') and val.endswith('"') and len(val) >= 2:
            inner_v = val[1:-1]
            if "\\" in inner_v:
                raise ValueError("bad Signature-Input: bad string param")
            val = inner_v
        elif val.startswith('"') or val.startswith(":"):
            raise ValueError("bad Signature-Input: bad parameter value")
        if k in params:
            raise ValueError("bad Signature-Input: duplicate parameter")
        params[k] = val
    return label, items, params


def _parse_signature(value, label):
    """Extract the raw signature bytes for `label` from a Signature header."""
    v = value if isinstance(value, str) else str(value)
    v = v.replace("\r", "").replace("\n", "")
    m = re.match(r"^\s*" + re.escape(label) + r"\s*=\s*:([A-Za-z0-9+/=]+):\s*$",
                 v)
    if not m:
        raise ValueError("bad Signature header")
    raw = base64.b64decode(m.group(1))
    if len(raw) != 64:
        raise ValueError("bad Signature header")
    return raw


# ---------------------------------------------------------------- verify
def verify_http_request(*, method, authority, path, headers=None, body=b"",
                        pubkey_hex, max_age_s=300, now=None):
    """Verify an RFC 9421-signed request. Returns (ok, reason).

    Every failure is fail-closed: (False, reason). The signature base is
    recomputed from the actual request values — nothing is taken on trust
    from the Signature-Input header's copies.
    """
    if body is None:
        body = b""
    now = time.time() if now is None else float(now)
    try:
        headers = _normalize_headers(headers)
        sig_input = headers.get("signature-input")
        signature = headers.get("signature")
        if sig_input is None or signature is None:
            return False, "missing Signature-Input or Signature header"
        label, components, params = _parse_signature_input(sig_input)

        alg = params.get("alg")
        if alg != "ed25519":
            # Algorithm confusion guard: only ed25519 is ever accepted.
            return False, f"unsupported signature algorithm {alg!r}"
        if params.get("tag") != "vouch":
            return False, "signature tag mismatch (expected 'vouch')"
        try:
            created = int(params.get("created", ""))
            expires = int(params.get("expires", ""))
        except (ValueError, TypeError):
            return False, "bad created/expires in Signature-Input"
        if not (created <= now <= expires):
            return False, "signature outside validity window"
        if now - created > max_age_s + 60:
            # created is absurdly old even ignoring expires (clock games)
            return False, "signature created too far in the past"
        if created > now + 60:
            return False, "signature created in the future"

        # Minimum covered set, checked against the parsed component list.
        low = [c for c in components]
        if "@method" not in low or "@authority" not in low:
            return False, ("missing required covered component "
                            "(@method and @authority required)")
        b = body if isinstance(body, (bytes, bytearray)) else bytes(body)
        if len(bytes(b)) > 0 and "content-digest" not in low:
            return False, ("missing required covered component "
                            "'content-digest' for non-empty body")

        # keyid binding: when present it must match the verifying key.
        keyid = params.get("keyid")
        if keyid is not None:
            try:
                want = _jwk_thumbprint(pubkey_hex)
            except ValueError:
                return False, "bad verifier public key"
            if not hmac.compare_digest(keyid, want):
                return False, "signature keyid does not match key"

        # Recompute the base from the actual request values.
        lines = []
        for c in low:
            _check_component(c)
            val = _derive_component(c, method=method, authority=authority,
                                    path=path, headers=headers, body=body)
            lines.append('"' + c + '": ' + val)
        inner = _inner_list(components, params)
        lines.append('"@signature-params": ' + inner)
        base = "\n".join(lines).encode("utf-8")
        raw_sig = _parse_signature(signature, label)
        ok = ed25519.verify(bytes.fromhex(pubkey_hex), base, raw_sig)
        return (True, "ok") if ok else (False, "signature does not verify")
    except ValueError as e:
        return False, f"invalid signature input: {e}"
    except Exception:
        # Fail closed on anything unexpected; no key material in the reason.
        return False, "signature verification error"


# ---------------------------------------------------------------- key directory
def _ms(ts):
    """Epoch seconds -> integer milliseconds."""
    return int(round(float(ts) * 1000))


def build_key_directory(manifest):
    """Build the /.well-known/vouch-keys JWKS from a trust-root manifest.

    The manifest is duck-typed (no import of enrollment — it lives on a
    parallel branch): manifest["principals"] entries carry keys with
    key_id/pubkey/label/status/valid_until, plus enrolled_at/expires_at.
    Only keys with status "active" are published. nbf/exp are epoch
    milliseconds: nbf from the principal's enrolled_at, exp from the key's
    valid_until (falling back to the enrollment's expires_at).
    """
    keys = []
    for principal in (manifest or {}).get("principals", []) or []:
        if not isinstance(principal, dict):
            continue
        nbf = _ms(principal["enrolled_at"]) if principal.get("enrolled_at") \
            else 0
        for key in principal.get("keys", []) or []:
            if not isinstance(key, dict):
                continue
            if key.get("status") != "active":
                continue
            pub = key.get("pubkey")
            try:
                x = _b64_nopad(bytes.fromhex(pub))
            except (ValueError, TypeError):
                continue
            kid = key.get("key_id") or _jwk_thumbprint(pub)
            exp = key.get("valid_until")
            if exp is None:
                exp = principal.get("expires_at")
            entry = {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid,
                     "use": "sig", "nbf": nbf}
            if exp is not None:
                entry["exp"] = _ms(exp)
            keys.append(entry)
    return {"keys": keys}
