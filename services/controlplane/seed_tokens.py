"""Mint service tokens for Vouch's internal consumers (Phase 2, §8).

    python3 -m services.controlplane.seed_tokens [--db PATH] [--rotate]

Tokens are shown ONCE — only their sha256 is stored. Distribute them as
environment variables:

    receipt-service -> RECEIPT_SVC_TOKEN on the gatekeeper (ingest auth),
                       and as both RECEIPT_SVC_TOKEN and CONTROLPLANE_SVC_TOKEN
                       on the receipt service (it validates the first and
                       presents the second to the control plane)
    runner          -> RUNNER_TOKEN (Phase 3)
    gatekeeper      -> GATEKEEPER_SVC_TOKEN on the gatekeeper, and
                       CONTROLPLANE_INVALIDATE_TOKEN on the control plane
                       (same value; used for push cache-invalidate)
    billing         -> BILLING_SVC_TOKEN (Phase 5)

Without --rotate, names that already have a token are left alone.
"""
import os
import sys

HERE = os.path.dirname(__file__)
DEFAULT_DB = (os.environ.get("CONTROLPLANE_DB")
              or os.path.join(HERE, "..", "..", "data", "controlplane.db"))

TOKENS = (
    # (service name, env var, scopes) — M-1: least privilege per consumer.
    # Only the gatekeeper and the receipt service ever see raw tenant HMAC
    # key material (keys:read); the runner and billing tokens cannot.
    ("receipt-service", "RECEIPT_SVC_TOKEN", "keys:read,cache:invalidate"),
    ("runner", "RUNNER_TOKEN",
     "deployments:read,deployments:status,cache:invalidate"),
    ("gatekeeper", "GATEKEEPER_SVC_TOKEN",
     "keys:read,deployment:verify,deployments:read,policies:read,"
     "cache:invalidate"),
    ("billing", "BILLING_SVC_TOKEN", "tenant:admin,cache:invalidate"),
)


def main(argv):
    db_path = DEFAULT_DB
    rotate = False
    args = list(argv[1:])
    while args:
        a = args.pop(0)
        if a == "--db" and args:
            db_path = args.pop(0)
        elif a == "--rotate":
            rotate = True
        else:
            print(f"unknown arg: {a}", file=sys.stderr)
            return 2
    from .models import ControlPlaneDB

    db = ControlPlaneDB(db_path)
    minted = {}
    for name, env, scope in TOKENS:
        if rotate:
            # rotate = delete existing, then mint fresh below
            db._write("DELETE FROM service_tokens WHERE name = ?", (name,))
        plaintext = db.seed_service_token(name, scope=scope)
        if plaintext is None:
            print(f"# {name}: already exists (use --rotate to replace; not shown)")
        else:
            minted[env] = plaintext
    if minted:
        print("# Service tokens — shown once. Export before starting services:")
        for env, token in minted.items():
            print(f"{env}={token}")
    if not rotate:
        print("# NOTE: tokens minted before Phase 7 carry the legacy 'internal'"
              " scope (all endpoints). Re-run with --rotate to scope them.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
