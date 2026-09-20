"""Vouch Python SDK — governed agent deployment, with proof.

Stdlib only: urllib for HTTP, hmac/hashlib for receipt verification.

Quick start::

    from vouch import VouchClient

    client, tenant_id, api_key = VouchClient.provision("acme")
    client.put_policy("deploy-staging", {"allow": [{"rule_id": "tests", "tool": "run_tests"}],
                                         "deny": [{"rule_id": "no-db", "tool": "delete_database"}]})
    dep = client.deploy_agent(task_id="deploy-staging", agent_image="vouch/agent-demo:latest")
"""

from .client import VouchClient, VouchError
from .mcp import MCPClient
from .verify import verify_chain

__all__ = ["VouchClient", "VouchError", "MCPClient", "verify_chain"]
__version__ = "0.6.0"
