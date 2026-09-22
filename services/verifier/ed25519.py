"""Ed25519 public-key signatures, pure Python (stdlib only).

Vouch's existing signing primitive is HMAC (symmetric) — perfect for
tenant-scoped receipts, but it cannot express *delegation*: a verifier
would need every delegator's secret to check a chain. Agent credentials
need true public-key signatures (principal -> agent -> sub-agent, each
link signed by the delegator's private key), so this module vendors a
compact RFC 8032 Ed25519 implementation instead of adding a dependency.
The repo's runtime contract stays stdlib-only (Dockerfile / quickstart.sh
install nothing but PyYAML).

Correctness is pinned by the RFC 8032 Section 7.1 test vectors in
tests/test_agent_verification.py — if this file is ever touched, those
vectors must still pass.

API:
    generate_keypair() -> (privkey_bytes, pubkey_bytes)   # 32 bytes each
    sign(privkey_bytes, message_bytes) -> signature_bytes # 64 bytes
    verify(pubkey_bytes, message_bytes, signature_bytes) -> bool
    pubkey_hex / privkey_hex helpers operate on hex strings.

Do NOT use this for anything needing side-channel resistance; it is a
correctness-first prototype implementation.
"""
import hashlib
import os

# ---- Curve parameters (RFC 8032, Section 5.1) -------------------------------
P = 2 ** 255 - 19


def _inv(x):
    return pow(x, P - 2, P)


_D = (-121665 * _inv(121666)) % P
_I = pow(2, (P - 1) // 4, P)

# Base point, encoded (little-endian y with sign bit of x)
_Gx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_Gy = 46316835694926478169428394003475163141307993866256225615783033603165251855960
_G = (_Gx, _Gy, 1, _Gx * _Gy % P)  # extended coords (X, Y, Z, T)

# Group order
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _xrecover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * _I % P
    if x % 2 != 0:
        x = P - x
    return x


def _edwards_add(p, q):
    (x1, y1, z1, t1), (x2, y2, z2, t2) = p, q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * _D * t2 % P
    d = z1 * 2 * z2 % P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalarmult(p, e):
    # Double-and-add, constant-ish structure (not constant-time).
    q = (0, 1, 1, 0)  # identity
    bits = bin(e)[2:]
    for bit in bits:
        q = _edwards_add(q, q)
        if bit == "1":
            q = _edwards_add(q, p)
    return q


def _encodepoint(p):
    # Normalize extended -> affine first: x = X/Z, y = Y/Z.
    x, y, z, _ = p
    zinv = _inv(z)
    x = x * zinv % P
    y = y * zinv % P
    # y as 255-bit little-endian, top bit = x parity
    return ((y | ((x & 1) << 255))).to_bytes(32, "little")


def _decodepoint(s):
    if len(s) != 32:
        raise ValueError("bad point encoding length")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != ((s[31] >> 7) & 1):
        x = P - x
    pt = (x, y, 1, x * y % P)
    # reject non-canonical / low-order points: [L]pt must be the identity.
    # (Compare normalized encodings — scalarmult returns (0,k,k,0), which is
    #  projectively the identity but not tuple-equal to (0,1,1,0).)
    if _encodepoint(_scalarmult(pt, _L)) != b"\x01" + b"\x00" * 31:
        raise ValueError("point not in prime-order subgroup")
    return pt


def _hint(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _clamp(h):
    # h: 32-byte digest prefix
    a = bytearray(h)
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(bytes(a), "little")


# ---- Public API ------------------------------------------------------------
def generate_keypair(seed=None):
    """Return (privkey, pubkey), 32 bytes each. privkey is the raw seed."""
    sk = seed if seed is not None else os.urandom(32)
    if len(sk) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(sk).digest()
    a = _clamp(h[:32])
    pk = _encodepoint(_scalarmult(_G, a))
    return sk, pk


def pubkey_from_priv(privkey):
    if len(privkey) != 32:
        raise ValueError("privkey must be 32 bytes")
    h = hashlib.sha512(privkey).digest()
    return _encodepoint(_scalarmult(_G, _clamp(h[:32])))


def sign(privkey, message):
    """Ed25519 sign. Returns 64-byte signature (deterministic, RFC 8032)."""
    if len(privkey) != 32:
        raise ValueError("privkey must be 32 bytes")
    h = hashlib.sha512(privkey).digest()
    a = _clamp(h[:32])
    prefix = h[32:]
    pk = _encodepoint(_scalarmult(_G, a))
    r = _hint(prefix + message) % _L
    r_pt = _encodepoint(_scalarmult(_G, r))
    s = (_hint(r_pt + pk + message) * a + r) % _L
    return r_pt + s.to_bytes(32, "little")


def verify(pubkey, message, signature):
    """Return True iff signature is a valid Ed25519 signature. Never raises."""
    try:
        if len(pubkey) != 32 or len(signature) != 64:
            return False
        a_pt = _decodepoint(pubkey)
        r_pt = _decodepoint(signature[:32])
        s = int.from_bytes(signature[32:], "little")
        if s >= _L:
            return False
        h = _hint(signature[:32] + pubkey + message)
        lhs = _scalarmult(_G, s)
        rhs = _edwards_add(r_pt, _scalarmult(a_pt, h))
        return _encodepoint(lhs) == _encodepoint(rhs)
    except Exception:
        return False


# ---- hex-string convenience -------------------------------------------------
def keypair_hex(seed=None):
    sk, pk = generate_keypair(seed)
    return sk.hex(), pk.hex()


def sign_hex(priv_hex, message: bytes) -> str:
    return sign(bytes.fromhex(priv_hex), message).hex()


def verify_hex(pub_hex, message: bytes, sig_hex) -> bool:
    try:
        return verify(bytes.fromhex(pub_hex), message, bytes.fromhex(sig_hex))
    except Exception:
        return False
