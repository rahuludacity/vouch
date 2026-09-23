"""Per-tenant HMAC signing keys for Vouch receipts.

File-backed tenant registry (tenants.json). Each tenant owns its own
256-bit HMAC key; every receipt is signed with the calling tenant's key,
so one tenant can never forge another tenant's audit trail.

Key rotation: rotate() mints a fresh current key and keeps the previous
key ids, so receipts issued before the rotation still verify.

This module doubles as the key resolver used by ReceiptLog:
    signing_key(tenant_id)      -> (kid, key_bytes) for new receipts
    verification_keys(tenant_id) -> {kid: key_bytes} for old receipts

CLI:
    python3 -m gatekeeper.tenants create <tenant-id>
    python3 -m gatekeeper.tenants rotate <tenant-id>
    python3 -m gatekeeper.tenants list

Key hygiene (H-5): key material is NEVER printed to stdout — only the
key id (kid). On create/rotate the fresh key is written once to a
0600 file for operator capture and the CLI prints that path instead.
The registry file itself is 0600 as well: it holds every tenant's
signing keys.
"""
import json
import os
import secrets
import sys
import threading
import time

DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "..", "tenants.json")
# NOTE (H-2 fix, 2026-09-20): retired keys are NEVER pruned. Key rows are
# tiny; proof is the product. Deleting a retired key would silently destroy
# verifiability of every receipt signed with it, so the full key history is
# retained indefinitely.


class TenantRegistry:
    def __init__(self, path=DEFAULT_PATH):
        self.path = os.path.abspath(path)
        self._lock = threading.RLock()
        self._tenants = {}
        self._load()

    # ---------- persistence ----------
    def _load(self):
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                self._tenants = json.load(f).get("tenants", {})

    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"tenants": self._tenants}, f, indent=2)
        # H-5: the registry holds every tenant's signing-key material —
        # 0600, never group/world-readable, even on a shared box.
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def _require(self, tenant_id):
        t = self._tenants.get(tenant_id)
        if t is None:
            raise KeyError(f"unknown tenant '{tenant_id}'")
        return t

    # ---------- management ----------
    def create(self, tenant_id):
        """Create a tenant with a fresh 256-bit key. Returns (kid, key_hex)."""
        with self._lock:
            if tenant_id in self._tenants:
                raise KeyError(f"tenant '{tenant_id}' already exists")
            key = secrets.token_hex(32)
            self._tenants[tenant_id] = {
                "created_at": round(time.time(), 3),
                "keys": {"k1": key},
                "current_kid": "k1",
            }
            self._save()
            return "k1", key

    def ensure(self, tenant_id):
        """Return (kid, key_hex) for tenant, creating it on first use."""
        with self._lock:
            t = self._tenants.get(tenant_id)
            if t is None:
                return self.create(tenant_id)
            kid = t["current_kid"]
            return kid, t["keys"][kid]

    def rotate(self, tenant_id):
        """Mint a new current key; retired keys stay verifiable forever.

        Returns (new_kid, new_key_hex). Retired keys are never deleted:
        every receipt ever signed stays verifiable (H-2 fix)."""
        with self._lock:
            t = self._require(tenant_id)
            n = 1
            kid = f"k{n}"
            while kid in t["keys"]:
                n += 1
                kid = f"k{n}"
            t["keys"][kid] = secrets.token_hex(32)
            t["current_kid"] = kid
            # No pruning: the full key history is retained so historical
            # receipts verify indefinitely (H-2 fix, 2026-09-20).
            t["rotated_at"] = round(time.time(), 3)
            self._save()
            return kid, t["keys"][kid]

    def list_tenants(self):
        with self._lock:
            return {
                tid: {
                    "current_kid": t["current_kid"],
                    "kids": sorted(t["keys"], key=lambda k: int(k[1:])),
                }
                for tid, t in self._tenants.items()
            }

    def write_key_capture(self, tenant_id, kid):
        """Write the kid's key material to a 0600 file for one-time capture.

        Returns the file path. Key material is NEVER printed: CLI callers
        print only this path (H-5). The operator reads the file once and
        is responsible for deleting it afterwards.
        """
        with self._lock:
            t = self._require(tenant_id)
            key_hex = t["keys"][kid]
        path = os.path.join(os.path.dirname(self.path),
                            f"{tenant_id}.{kid}.key")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(key_hex + "\n")
        # ...in case the file already existed with wider permissions.
        os.chmod(path, 0o600)
        return path

    # ---------- key resolution (ReceiptLog interface) ----------
    def signing_key(self, tenant_id):
        """(kid, key_bytes) to sign new receipts for tenant_id."""
        with self._lock:
            t = self._require(tenant_id)
            kid = t["current_kid"]
            return kid, bytes.fromhex(t["keys"][kid])

    def verification_keys(self, tenant_id):
        """{kid: key_bytes} to verify historical receipts for tenant_id."""
        with self._lock:
            t = self._require(tenant_id)
            return {kid: bytes.fromhex(k) for kid, k in t["keys"].items()}


def main(argv):
    reg = TenantRegistry(os.environ.get("GATEKEEPER_TENANTS_PATH", DEFAULT_PATH))
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[-4:])
        return 2
    cmd, rest = argv[1], argv[2:]
    if cmd == "create" and len(rest) == 1:
        kid, key = reg.create(rest[0])
        key_path = reg.write_key_capture(rest[0], kid)
        print(f"tenant '{rest[0]}' created (kid={kid}). Key stored in {reg.path}; keep it secret.")
        print(f"signing key written to {key_path} (mode 0600) for one-time operator capture; it is never printed.")
    elif cmd == "rotate" and len(rest) == 1:
        kid, key = reg.rotate(rest[0])
        key_path = reg.write_key_capture(rest[0], kid)
        print(f"tenant '{rest[0]}' rotated to {kid}. Old receipts still verify.")
        print(f"signing key written to {key_path} (mode 0600) for one-time operator capture; it is never printed.")
    elif cmd == "list" and not rest:
        for tid, info in reg.list_tenants().items():
            print(f"{tid}: current={info['current_kid']} keys={info['kids']}")
    else:
        print(f"unknown command: {' '.join(argv[1:])}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
