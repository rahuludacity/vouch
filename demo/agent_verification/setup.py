"""One-time setup for the agent-verification demo.

Generates Ed25519 identities (principal, agent, sub-agent, attacker),
issues the principal -> agent -> sub-agent credential chain, creates the
`smallville` tenant, and writes everything run_demo.sh needs.

Usage: DEMO_TMP=<dir> python3 demo/agent_verification/setup.py
Writes: $DEMO_TMP/{tenants.json,keys.json,credential.json,env.sh}
"""
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, REPO)

from services.verifier.credentials import (  # noqa: E402
    generate_keypair, issue_credential, issue_delegation)

TMP = os.environ["DEMO_TMP"]
os.makedirs(TMP, exist_ok=True)

tenants_path = os.path.join(TMP, "tenants.json")
env = dict(os.environ, GATEKEEPER_TENANTS_PATH=tenants_path)
subprocess.run([sys.executable, "-m", "gatekeeper.tenants",
                "create", "smallville"],
               cwd=REPO, env=env, check=True, capture_output=True)

p_priv, p_pub = generate_keypair()   # principal: Smallville permit office
a_priv, a_pub = generate_keypair()   # agent: the permit-filing service
s_priv, s_pub = generate_keypair()   # sub-agent: does the actual filing
x_priv, x_pub = generate_keypair()   # attacker: holds no credential

scope_agent = {"allow": ["form.submit", "form.read"],
               "limits": {"form.submit": {"max_per_day": 50}}}
scope_sub = {"allow": ["form.submit"],
             "limits": {"form.submit": {"max_per_day": 50}}}

link1 = issue_delegation(delegator_priv_hex=p_priv,
                         delegator_pub_hex=p_pub,
                         delegatee_pub_hex=a_pub,
                         scope=scope_agent, ttl_s=86400)
link2 = issue_delegation(delegator_priv_hex=a_priv,
                         delegator_pub_hex=a_pub,
                         delegatee_pub_hex=s_pub,
                         scope=scope_sub, ttl_s=86400)
cred = issue_credential(principal_id="smallville-permit-office",
                        principal_priv_hex=p_priv, principal_pub_hex=p_pub,
                        agent_id="permit-filer-1", agent_pub_hex=s_pub,
                        scope=scope_sub,
                        delegations=[link1, link2], ttl_s=86400)

with open(os.path.join(TMP, "keys.json"), "w", encoding="utf-8") as f:
    json.dump({"principal": {"priv": p_priv, "pub": p_pub},
               "agent": {"priv": a_priv, "pub": a_pub},
               "subagent": {"priv": s_priv, "pub": s_pub},
               "attacker": {"priv": x_priv, "pub": x_pub}}, f, indent=2)
with open(os.path.join(TMP, "credential.json"), "w",
          encoding="utf-8") as f:
    json.dump(cred, f, indent=2)
with open(os.path.join(TMP, "env.sh"), "w", encoding="utf-8") as f:
    f.write(f"export VERIFIER_TRUSTED_ISSUERS={p_pub}\n")
    f.write(f"export DEMO_PRINCIPAL_PUB={p_pub}\n")

print(f"demo material written to {TMP}")
print(f"principal pubkey: {p_pub[:16]}... (trusted issuer)")
