"""Demo agent clients.

Usage:
    python3 demo/agent_verification/agents.py good      # valid credential chain
    python3 demo/agent_verification/agents.py forged    # tampered credential
    python3 demo/agent_verification/agents.py swarm [N] # N credential-less bots

Env: DEMO_TMP (setup.py output), SITE_URL (default http://127.0.0.1:9011)
"""
import json
import os
import sys
import urllib.request
import urllib.error

REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, REPO)

from services.verifier.credentials import sign_action_request  # noqa: E402

TMP = os.environ["DEMO_TMP"]
SITE = os.environ.get("SITE_URL", "http://127.0.0.1:9011").rstrip("/")

keys = json.load(open(os.path.join(TMP, "keys.json"), encoding="utf-8"))
cred = json.load(open(os.path.join(TMP, "credential.json"), encoding="utf-8"))


def post_json(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def agent_envelope(priv_hex, credential, action):
    env = sign_action_request(agent_priv_hex=priv_hex,
                              credential_id=credential["credential_id"],
                              action=action)
    return {"tenant_id": "smallville",
            "credential": credential,
            "action": env["action"], "nonce": env["nonce"], "ts": env["ts"],
            "agent_signature": env["agent_signature"]}


def good():
    action = {"type": "form.submit", "target": "/permits/apply",
              "args": {"name": "R. Rao", "permit": "deck-extension"}}
    payload = agent_envelope(keys["subagent"]["priv"], cred, action)
    code, body = post_json(SITE + "/agent-submit", payload)
    print(f"good agent -> HTTP {code}")
    print(json.dumps(body, indent=2))
    return code == 200 and body.get("status") == "accepted"


def forged():
    import copy
    bad_cred = copy.deepcopy(cred)
    bad_cred["scope"] = {"allow": ["*"]}  # tampered; issuer sig now stale
    action = {"type": "form.submit", "target": "/permits/apply",
              "args": {"name": "Mallory", "permit": "everything"}}
    payload = agent_envelope(keys["attacker"]["priv"], bad_cred, action)
    code, body = post_json(SITE + "/agent-submit", payload)
    print(f"forged agent -> HTTP {code}")
    print(json.dumps(body, indent=2))
    return code == 429 and body.get("lane") == "unverified"


def swarm(n=10):
    challenged = 0
    for i in range(n):
        # credential-less bot: slams the agent endpoint with no passport
        code, body = post_json(
            SITE + "/agent-submit",
            {"action": {"type": "form.submit", "target": "/permits/apply",
                        "args": {"spam": i}}})
        if code == 429 and body.get("lane") == "unverified":
            challenged += 1
        else:
            print(f"  bot {i}: UNEXPECTED HTTP {code} {body}")
    print(f"bot swarm: {challenged}/{n} challenged (unverified lane)")
    return challenged == n


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "good"
    ok = {"good": good, "forged": forged,
          "swarm": lambda: swarm(int(sys.argv[2]) if len(sys.argv) > 2
                                 else 10)}[mode]()
    sys.exit(0 if ok else 1)
