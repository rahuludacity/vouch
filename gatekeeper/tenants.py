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
"""
import json
import os
import secrets
import sys
import threading
import time

DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "..", "tenants.json")
MAX_PREVIOUS_KEYS = 3  # how many retired keys stay verifiable


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
        """Mint a new current key; retired keys stay verifiable.

        Returns (new_kid, new_key_hex)."""
        with self._lock:
            t = self._require(tenant_id)
            n = 1
            kid = f"k{n}"
            while kid in t["keys"]:
                n += 1
                kid = f"k{n}"
            t["keys"][kid] = secrets.token_hex(32)
            t["current_kid"] = kid
            # prune: keep current + newest MAX_PREVIOUS_KEYS retired keys
            ordered = sorted(t["keys"], key=lambda k: int(k[1:]))
            keep = set(ordered[-(1 + MAX_PREVIOUS_KEYS):])
            t["keys"] = {k: v for k, v in t["keys"].items() if k in keep}
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
        print(f"tenant '{rest[0]}' created (kid={kid}). Key stored in {reg.path}; keep it secret.")
        print(f"key_hex={key}")
    elif cmd == "rotate" and len(rest) == 1:
        kid, key = reg.rotate(rest[0])
        print(f"tenant '{rest[0]}' rotated to {kid}. Old receipts still verify.")
        print(f"new_key_hex={key}")
    elif cmd == "list" and not rest:
        for tid, info in reg.list_tenants().items():
            print(f"{tid}: current={info['current_kid']} keys={info['kids']}")
    else:
        print(f"unknown command: {' '.join(argv[1:])}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
