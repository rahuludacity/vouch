"""Migrate a v1 tenants.json registry into the control plane DB (Phase 2).

    python3 -m services.controlplane.migrate_tenants [--db PATH] [--tenants PATH]

Every tenant keeps its kid history byte-for-byte (k1, k2, ...), so receipts
signed before the migration still verify against the control plane's keys.
Each migrated tenant also gets one fresh `vouch_sk_*` API key (printed once)
so file-era tenants can use the tenant API immediately.

Tenants already present in the DB are skipped (idempotent re-runs are safe).
The source file is never modified.
"""
import os
import sys

HERE = os.path.dirname(__file__)
DEFAULT_DB = (os.environ.get("CONTROLPLANE_DB")
              or os.path.join(HERE, "..", "..", "data", "controlplane.db"))
DEFAULT_TENANTS = (os.environ.get("TENANTS_PATH")
                   or os.path.join(HERE, "..", "..", "tenants.json"))


def main(argv):
    db_path = DEFAULT_DB
    tenants_path = DEFAULT_TENANTS
    args = list(argv[1:])
    while args:
        a = args.pop(0)
        if a == "--db" and args:
            db_path = args.pop(0)
        elif a == "--tenants" and args:
            tenants_path = args.pop(0)
        else:
            print(f"unknown arg: {a}", file=sys.stderr)
            return 2
    from .models import ControlPlaneDB

    db = ControlPlaneDB(db_path)
    result = db.migrate_tenants_file(tenants_path)
    for tid in result["migrated"]:
        keys = db.get_keys(tid)
        print(f"migrated tenant '{tid}': kids={sorted(keys['keys'])} "
              f"current={keys['current_kid']}")
        print(f"  api_key (shown once): {result['api_keys'][tid]}")
    for tid in result["skipped"]:
        print(f"skipped tenant '{tid}': already in DB or no keys")
    if not result["migrated"] and not result["skipped"]:
        print("no tenants found in registry file")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
