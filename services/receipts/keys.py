"""Server-side tenant key loading for the receipt service.

Phase 1: keys come from the shared tenants.json file (same file the
gatekeeper uses). Phase 2: this is replaced by the control-plane endpoint
GET /internal/tenants/{id}/keys (§4.7). Key material never leaves the
server: verify runs here, clients only see chain_ok / failures.
"""
import json
import os


def load_verification_keys(tenants_path, tenant_id):
    """{kid: key_bytes} for tenant_id. Raises KeyError if unknown tenant."""
    with open(os.path.abspath(tenants_path), "r", encoding="utf-8") as f:
        tenants = json.load(f).get("tenants", {})
    t = tenants.get(tenant_id)
    if t is None:
        raise KeyError(f"unknown tenant '{tenant_id}'")
    return {kid: bytes.fromhex(k) for kid, k in t["keys"].items()}
