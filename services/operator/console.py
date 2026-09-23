"""Vouch Phase 13 — minimal operator console CLI.

A thin wrapper over services/verifier/enrollment.py. The operator's
Ed25519 key lives at <store>/operator.key (0600 JSON); all enrollment
events go to <store>/log.jsonl (the transparency log); `manifest`
rebuilds <store>/manifest.json from that log.

Security posture:
  - operator.key is created with os.open(O_CREAT, 0o600) — never
    chmod-after. Every command that needs the key refuses to run when
    the file is group/world-readable.
  - Private key material never reaches stdout, stderr, or exceptions.
    Error messages carry plain words, never key bytes.
  - No shell=True anywhere; DNS/HTTPS fetchers are injectable module
    attributes (fetch_txt / fetch_https) so tests use stubs.
  - serve-manifest binds 127.0.0.1 by default.
  - Domain/key validation reuses enrollment's validators; every misuse
    exits nonzero with a plain-word message.
"""

import argparse
import http.server
import json
import os
import sys
import time

from ..verifier import ed25519
from ..verifier import enrollment
from ..verifier.enrollment import (
    TransparencyLog,
    build_manifest,
    create_dns_challenge,
    enroll_principal_tier0,
    enroll_principal_tier1,
    jwk_thumbprint,
    revoke_key,
    rotate_key,
    suspend_principal,
    unsuspend_principal,
    verify_dns_challenge,
    verify_manifest,
)

# ---------------------------------------------------------------- injectable seams
# The enroll-tier1 flow needs DNS TXT + HTTPS fetchers. Production uses the
# real ones from enrollment.py; tests monkeypatch these two attributes.
fetch_txt = enrollment.fetch_txt_via_dig
fetch_https = enrollment.fetch_https_json

_KEY_FILE = "operator.key"
_PUB_FILE = "operator.pub"
_LOG_FILE = "log.jsonl"
_MANIFEST_FILE = "manifest.json"

_DEFAULT_STORE = os.path.join("~", ".vouch-operator")

# The "publish this TXT record, then re-run" state gets its own exit code
# so scripts can tell it apart from a hard failure.
EXIT_NEEDS_TXT = 2


# ---------------------------------------------------------------- small helpers
def _fail(msg, code=1):
    """Plain-word error to stderr. `msg` must never contain key material."""
    print(f"error: {msg}", file=sys.stderr)
    return code


def _store_paths(store):
    store = os.path.abspath(os.path.expanduser(store))
    return {
        "store": store,
        "key": os.path.join(store, _KEY_FILE),
        "pub": os.path.join(store, _PUB_FILE),
        "log": os.path.join(store, _LOG_FILE),
        "manifest": os.path.join(store, _MANIFEST_FILE),
    }


def _ensure_store(paths):
    os.makedirs(paths["store"], mode=0o700, exist_ok=True)


def _write_file_0600(path, data):
    """Create a file with mode 0600 atomically (no chmod-after)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def _atomic_write(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
    os.replace(tmp, path)


def _load_operator(paths):
    """Return (priv_hex, pub_hex). Refuses a loose key file, fail-closed."""
    key_path = paths["key"]
    if not os.path.exists(key_path):
        raise ValueError(
            "no operator key in this store (run init-operator first)")
    st = os.stat(key_path)
    if st.st_mode & 0o077:
        raise ValueError(
            "operator key file is group/world-readable; refusing to use it")
    try:
        with open(key_path, "r", encoding="utf-8") as f:
            blob = json.load(f)
    except (OSError, ValueError) as exc:
        raise ValueError(f"operator key unreadable ({exc.__class__.__name__})")
    if not isinstance(blob, dict):
        raise ValueError("operator key file is malformed")
    priv_hex = blob.get("privkey_hex")
    pub_hex = blob.get("pubkey_hex")
    if not isinstance(priv_hex, str) or not isinstance(pub_hex, str):
        raise ValueError("operator key file is malformed")
    # Consistency check without ever echoing the private key.
    try:
        derived = ed25519.pubkey_from_priv(bytes.fromhex(priv_hex)).hex()
    except (ValueError, TypeError):
        raise ValueError("operator key file holds a bad private key")
    if derived.lower() != pub_hex.lower():
        raise ValueError("operator key file is inconsistent")
    return priv_hex, pub_hex


def _open_log(paths):
    return TransparencyLog(paths["log"])


def _principal_exists(log, principal_id):
    try:
        principals, _, _ = enrollment._fold_log_into_principals(log.entries())
    except ValueError:
        return False
    return principal_id in principals


def _require_yes(args, what):
    if not getattr(args, "yes", False):
        return _fail(f"refusing {what} without --yes")
    return None


# ---------------------------------------------------------------- commands
def cmd_init_operator(args):
    paths = _store_paths(args.store)
    _ensure_store(paths)
    if os.path.exists(paths["key"]) and not args.force:
        return _fail("operator key already exists (use --force to replace)")
    priv_hex, pub_hex = ed25519.keypair_hex()
    if args.force and os.path.exists(paths["key"]):
        os.unlink(paths["key"])
    _write_file_0600(
        paths["key"],
        json.dumps({"privkey_hex": priv_hex, "pubkey_hex": pub_hex},
                   sort_keys=True) + "\n")
    with open(paths["pub"], "w", encoding="utf-8") as f:
        f.write(pub_hex + "\n")
    log = _open_log(paths)
    log.append("operator-key",
               {"pubkey": pub_hex,
                "action": "replaced" if args.force else "created"},
               priv_hex)
    print(f"operator keypair ready; public key: {pub_hex}")
    return 0


def cmd_new_principal(args):
    paths = _store_paths(args.store)
    try:
        priv_hex, pub_hex = _load_operator(paths)
    except ValueError as exc:
        return _fail(str(exc))
    log = _open_log(paths)
    try:
        cert, _entry = enroll_principal_tier0(
            log=log, principal_id=args.principal, pubkey_hex=args.pubkey,
            label=args.label, operator_priv_hex=priv_hex,
            operator_pub_hex=pub_hex)
    except ValueError as exc:
        return _fail(str(exc))
    print(f"enrolled {cert['principal_id']} tier allowlist "
          f"key_id {cert['key_ids'][0]['key_id']} "
          f"log_seq {cert['enrollment_log_seq']}")
    return 0


def cmd_dns_challenge(args):
    try:
        ch = create_dns_challenge(args.domain)
    except ValueError as exc:
        return _fail(str(exc))
    print(f"publish this TXT record, then re-run enroll-tier1 with "
          f"--challenge-token:\n  {ch['txt_name']} IN TXT \"{ch['token']}\"")
    return 0


def _challenge_from_args(args):
    domain = args.domain.strip().lower()
    txt_name = args.txt_name or ("_vouch-challenge." + domain)
    return {"domain": domain, "token": args.challenge_token,
            "txt_name": txt_name, "created_at": round(time.time(), 3)}


def cmd_enroll_tier1(args):
    if not args.challenge_token:
        try:
            ch = create_dns_challenge(args.domain)
        except ValueError as exc:
            return _fail(str(exc))
        print(f"publish this TXT record, then re-run with --challenge-token "
              f"{ch['token']}:\n  {ch['txt_name']} IN TXT \"{ch['token']}\"")
        print("error: publish TXT then re-run", file=sys.stderr)
        return EXIT_NEEDS_TXT
    challenge = _challenge_from_args(args)
    ok, reason = verify_dns_challenge(challenge, fetch_txt)
    if not ok:
        print(f"error: {reason}", file=sys.stderr)
        print("error: publish TXT then re-run", file=sys.stderr)
        return EXIT_NEEDS_TXT
    paths = _store_paths(args.store)
    try:
        priv_hex, pub_hex = _load_operator(paths)
    except ValueError as exc:
        return _fail(str(exc))
    log = _open_log(paths)
    try:
        cert, _entry = enroll_principal_tier1(
            log=log, principal_id=args.principal, domain=args.domain,
            pubkey_hex=args.pubkey, label=args.label, challenge=challenge,
            fetch_txt=fetch_txt, fetch_https=fetch_https,
            operator_priv_hex=priv_hex, operator_pub_hex=pub_hex)
    except ValueError as exc:
        return _fail(str(exc))
    print(f"enrolled {cert['principal_id']} tier domain-control "
          f"domain {cert['domain']} "
          f"key_id {cert['key_ids'][0]['key_id']} "
          f"log_seq {cert['enrollment_log_seq']}")
    return 0


def cmd_rotate_key(args):
    paths = _store_paths(args.store)
    try:
        priv_hex, _pub_hex = _load_operator(paths)
    except ValueError as exc:
        return _fail(str(exc))
    log = _open_log(paths)
    try:
        entry = rotate_key(
            log=log, principal_id=args.principal,
            old_pubkey_hex=args.old_pubkey, new_pubkey_hex=args.new_pubkey,
            label=args.label, operator_priv_hex=priv_hex,
            overlap_s=args.overlap_s)
    except ValueError as exc:
        return _fail(str(exc))
    new_kid = entry["payload"]["new_key"]["key_id"]
    print(f"rotated key for {args.principal}; new key_id {new_kid} "
          f"(old key usable for {int(args.overlap_s)}s)")
    return 0


def cmd_revoke_key(args):
    denied = _require_yes(args, "to revoke a key")
    if denied is not None:
        return denied
    paths = _store_paths(args.store)
    try:
        priv_hex, _pub_hex = _load_operator(paths)
    except ValueError as exc:
        return _fail(str(exc))
    log = _open_log(paths)
    try:
        entry = revoke_key(
            log=log, principal_id=args.principal, pubkey_hex=args.pubkey,
            reason=args.reason, operator_priv_hex=priv_hex)
    except ValueError as exc:
        return _fail(str(exc))
    print(f"revoked key {entry['payload']['key_id']} "
          f"for {args.principal}")
    return 0


def cmd_revoke_credential(args):
    denied = _require_yes(args, "to revoke a credential")
    if denied is not None:
        return denied
    handle = args.revocation_handle
    if (not isinstance(handle, str) or not handle
            or len(handle) > 256
            or any(ord(c) < 0x20 or ord(c) == 0x7F for c in handle)):
        return _fail("revocation handle must be a non-empty printable string")
    if not isinstance(args.reason, str) or not args.reason.strip():
        return _fail("reason must be a non-empty string")
    paths = _store_paths(args.store)
    try:
        priv_hex, _pub_hex = _load_operator(paths)
    except ValueError as exc:
        return _fail(str(exc))
    log = _open_log(paths)
    if not _principal_exists(log, args.principal):
        return _fail(f"unknown principal {args.principal!r}")
    now = round(time.time(), 3)
    # Frozen fold payload — matches _fold_log_into_principals exactly.
    payload = {"principal_id": args.principal,
               "revocation_handle": handle,
               "revoked_at": now,
               "reason": args.reason.strip()}
    try:
        log.append("revoke-credential", payload, priv_hex, ts=now)
    except ValueError as exc:
        return _fail(str(exc))
    print(f"revoked credential {handle} for {args.principal}")
    return 0


def cmd_revoke_delegation_link(args):
    """Surgically revoke one delegation grant by its link handle.

    Appends a "revoke-delegation-link" event to the transparency log;
    the next `manifest` rebuild folds the handle into
    revoked_delegation_handles, and verifiers deny any chain containing
    the link (fail-closed). The credential's other links — and the
    credential itself — keep working.
    """
    denied = _require_yes(args, "to revoke a delegation link")
    if denied is not None:
        return denied
    handle = args.revocation_handle
    if (not isinstance(handle, str) or not handle
            or len(handle) > 256
            or any(ord(c) < 0x20 or ord(c) == 0x7F for c in handle)):
        return _fail("revocation handle must be a non-empty printable string")
    if not isinstance(args.reason, str) or not args.reason.strip():
        return _fail("reason must be a non-empty string")
    paths = _store_paths(args.store)
    try:
        priv_hex, _pub_hex = _load_operator(paths)
    except ValueError as exc:
        return _fail(str(exc))
    log = _open_log(paths)
    if not _principal_exists(log, args.principal):
        return _fail(f"unknown principal {args.principal!r}")
    now = round(time.time(), 3)
    payload = {"principal_id": args.principal,
               "revocation_handle": handle,
               "revoked_at": now,
               "reason": args.reason.strip()}
    try:
        log.append("revoke-delegation-link", payload, priv_hex, ts=now)
    except ValueError as exc:
        return _fail(str(exc))
    print(f"revoked delegation link {handle} for {args.principal}")
    return 0


def cmd_suspend(args):
    denied = _require_yes(args, "to suspend a principal")
    if denied is not None:
        return denied
    paths = _store_paths(args.store)
    try:
        priv_hex, _pub_hex = _load_operator(paths)
    except ValueError as exc:
        return _fail(str(exc))
    log = _open_log(paths)
    try:
        suspend_principal(log=log, principal_id=args.principal,
                          reason=args.reason, operator_priv_hex=priv_hex)
    except ValueError as exc:
        return _fail(str(exc))
    print(f"suspended {args.principal}")
    return 0


def cmd_unsuspend(args):
    paths = _store_paths(args.store)
    try:
        priv_hex, _pub_hex = _load_operator(paths)
    except ValueError as exc:
        return _fail(str(exc))
    log = _open_log(paths)
    try:
        unsuspend_principal(log=log, principal_id=args.principal,
                            operator_priv_hex=priv_hex)
    except ValueError as exc:
        return _fail(str(exc))
    print(f"unsuspended {args.principal}")
    return 0


def cmd_manifest(args):
    paths = _store_paths(args.store)
    _ensure_store(paths)
    try:
        priv_hex, pub_hex = _load_operator(paths)
    except ValueError as exc:
        return _fail(str(exc))
    log = _open_log(paths)
    try:
        manifest = build_manifest(
            log=log, operator_priv_hex=priv_hex, operator_pubkey=pub_hex,
            valid_for_s=args.valid_for_s)
    except ValueError as exc:
        return _fail(str(exc))
    _atomic_write(paths["manifest"],
                  json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    print(f"manifest v{manifest['version']} written to {paths['manifest']}")
    return 0


def cmd_verify_manifest(args):
    paths = _store_paths(args.store)
    manifest_path = args.manifest or paths["manifest"]
    try:
        priv_hex, pub_hex = _load_operator(paths)
    except ValueError as exc:
        return _fail(str(exc))
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, ValueError) as exc:
        return _fail(f"cannot read manifest ({exc.__class__.__name__})")
    ok, reasons = verify_manifest(manifest, [pub_hex])
    if ok:
        print(f"manifest OK: v{manifest['version']}, "
              f"{len(manifest['principals'])} principal(s), "
              f"{len(manifest['revoked_credentials'])} revoked credential(s)")
        return 0
    for r in reasons:
        print(f"error: {r}", file=sys.stderr)
    return 1


def _manifest_handler(manifest_bytes):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in ("/", "/manifest.json"):
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(manifest_bytes)))
            self.end_headers()
            self.wfile.write(manifest_bytes)

        def log_message(self, *a):
            pass  # stay quiet; no request logging

    return Handler


def cmd_serve_manifest(args):
    paths = _store_paths(args.store)
    if not os.path.exists(paths["manifest"]):
        return _fail("no manifest.json in this store (run manifest first)")
    try:
        with open(paths["manifest"], "rb") as f:
            body = f.read()
    except OSError as exc:
        return _fail(f"cannot read manifest ({exc.__class__.__name__})")
    try:
        manifest = json.loads(body.decode("utf-8"))
    except ValueError:
        return _fail("manifest.json is not valid JSON")
    try:
        _priv_hex, pub_hex = _load_operator(paths)
    except ValueError as exc:
        return _fail(str(exc))
    ok, reasons = verify_manifest(manifest, [pub_hex])
    if not ok:
        for r in reasons:
            print(f"error: {r}", file=sys.stderr)
        return _fail("refusing to serve an invalid manifest")
    server = http.server.HTTPServer(
        (args.host, args.port), _manifest_handler(body))
    print(f"serving manifest on http://{args.host}:{server.server_port}/manifest.json")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


# ---------------------------------------------------------------- parser
def build_parser():
    p = argparse.ArgumentParser(
        prog="vouch-operator",
        description="Minimal operator console for the Vouch trust root.")
    p.add_argument("--store", default=_DEFAULT_STORE,
                   help="operator state directory "
                        "(default ~/.vouch-operator)")
    sub = p.add_subparsers(dest="command", required=True,
                           metavar="<command>")

    a = sub.add_parser("init-operator",
                       help="generate the operator Ed25519 keypair")
    a.add_argument("--force", action="store_true",
                   help="replace an existing operator key")
    a.set_defaults(func=cmd_init_operator)

    a = sub.add_parser("new-principal",
                       help="enroll a principal at tier 0 (allowlist)")
    a.add_argument("--principal", required=True)
    a.add_argument("--pubkey", required=True,
                   help="principal's Ed25519 public key (64 hex chars)")
    a.add_argument("--label", required=True)
    a.set_defaults(func=cmd_new_principal)

    a = sub.add_parser("dns-challenge",
                       help="mint a DNS challenge for a domain")
    a.add_argument("--domain", required=True)
    a.set_defaults(func=cmd_dns_challenge)

    a = sub.add_parser("enroll-tier1",
                       help="enroll a principal at tier 1 (domain-control). "
                            "Without --challenge-token it prints the TXT "
                            "record to publish and exits 2.")
    a.add_argument("--principal", required=True)
    a.add_argument("--domain", required=True)
    a.add_argument("--pubkey", required=True,
                   help="principal's Ed25519 public key (64 hex chars)")
    a.add_argument("--label", required=True)
    a.add_argument("--challenge-token", default=None,
                   help="256-bit hex token from the published TXT record")
    a.add_argument("--txt-name", default=None,
                   help="override the TXT owner name "
                        "(default _vouch-challenge.<domain>)")
    a.set_defaults(func=cmd_enroll_tier1)

    a = sub.add_parser("rotate-key", help="rotate a principal's key")
    a.add_argument("--principal", required=True)
    a.add_argument("--old-pubkey", required=True)
    a.add_argument("--new-pubkey", required=True)
    a.add_argument("--label", required=True)
    a.add_argument("--overlap-s", type=float, default=72 * 3600,
                   help="grace window for the old key (default 72h)")
    a.set_defaults(func=cmd_rotate_key)

    a = sub.add_parser("revoke-key", help="revoke one of a principal's keys")
    a.add_argument("--principal", required=True)
    a.add_argument("--pubkey", required=True)
    a.add_argument("--reason", required=True)
    a.add_argument("--yes", action="store_true",
                   help="confirm this destructive operation")
    a.set_defaults(func=cmd_revoke_key)

    a = sub.add_parser("revoke-credential",
                       help="revoke a credential by its revocation handle")
    a.add_argument("--principal", required=True)
    a.add_argument("--revocation-handle", required=True)
    a.add_argument("--reason", required=True)
    a.add_argument("--yes", action="store_true",
                   help="confirm this destructive operation")
    a.set_defaults(func=cmd_revoke_credential)

    a = sub.add_parser("revoke-delegation-link",
                       help="revoke one delegation link by its revocation "
                            "handle (surgical: the credential's other "
                            "links keep working)")
    a.add_argument("--principal", required=True,
                   help="principal at the root of the delegation chain "
                        "(audit context)")
    a.add_argument("--revocation-handle", required=True,
                   help="the link's revocation handle (rh-...)")
    a.add_argument("--reason", required=True)
    a.add_argument("--yes", action="store_true",
                   help="confirm this destructive operation")
    a.set_defaults(func=cmd_revoke_delegation_link)

    a = sub.add_parser("suspend", help="suspend a principal")
    a.add_argument("--principal", required=True)
    a.add_argument("--reason", required=True)
    a.add_argument("--yes", action="store_true",
                   help="confirm this destructive operation")
    a.set_defaults(func=cmd_suspend)

    a = sub.add_parser("unsuspend", help="lift a principal's suspension")
    a.add_argument("--principal", required=True)
    a.set_defaults(func=cmd_unsuspend)

    a = sub.add_parser("manifest",
                       help="rebuild manifest.json from the transparency log")
    a.add_argument("--valid-for-s", type=float, default=300,
                   help="manifest freshness window in seconds (default 300)")
    a.set_defaults(func=cmd_manifest)

    a = sub.add_parser("verify-manifest",
                       help="verify a manifest's signature and freshness")
    a.add_argument("--manifest", default=None,
                   help="path to a manifest file "
                        "(default <store>/manifest.json)")
    a.set_defaults(func=cmd_verify_manifest)

    a = sub.add_parser("serve-manifest",
                       help="serve manifest.json over HTTP as "
                            "application/json (localhost only by default)")
    a.add_argument("--port", type=int, default=8471)
    a.add_argument("--host", default="127.0.0.1",
                   help="bind address (default 127.0.0.1)")
    a.set_defaults(func=cmd_serve_manifest)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        return _fail(str(exc))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # never leak internals or key material
        return _fail(f"unexpected failure ({exc.__class__.__name__})")


if __name__ == "__main__":
    sys.exit(main())
