"""Vouch agent runner — sandboxed container spec builder (ARCHITECTURE.md §2.5).

One container per deployment. The spec encodes the sandbox contract:

  - NEVER host networking. Agent containers attach ONLY to the dedicated
    docker network ``vouch-sandbox``, created with ``internal=True`` (no route
    to the outside world). The gatekeeper is the only other member of that
    network — that membership *is* the egress allowlist:
    ``ALLOWED_EGRESS = (http://gatekeeper:9000,)``. An agent that tries to
    reach anything else gets no route.
  - Read-only root filesystem; exactly one writable scratch dir (``/scratch``).
  - Memory + CPU limits, no privileged mode, all Linux capabilities dropped.
  - Identity env injection (``GATEKEEPER_URL``, ``VOUCH_TENANT_ID``,
    ``VOUCH_TASK_ID``, ``VOUCH_AGENT_ID``) so the agent's MCP client routes
    through the gatekeeper with the correct §4.1 identity headers. The agent
    itself is just an MCP client — no new contract (§4.9).

The spec is a plain dict of docker-SDK ``containers.run`` kwargs (with
``"image"`` as the positional). It is built without importing docker, so it is
unit-testable on hosts without a daemon. ``validate_spec`` is the
defense-in-depth gate: the runner calls it before every create, and tests
assert the sandbox properties through it.
"""

import re

SANDBOX_NETWORK = "vouch-sandbox"
# Egress allowlist, enforced by network membership: the gatekeeper is the only
# other member of the internal vouch-sandbox network.
ALLOWED_EGRESS = ("http://gatekeeper:9000",)

RUNNER_LABEL = "vouch.managed-by"
RUNNER_VALUE = "vouch-runner"

SCRATCH_DIR = "/scratch"
MEM_LIMIT = "512m"
NANO_CPUS = 1_000_000_000  # 1 CPU

DEFAULT_GATEKEEPER_AGENT_URL = "http://gatekeeper:9000/mcp"

_NAME_RE = re.compile(r"[^a-zA-Z0-9_.-]")

REQUIRED_ENV = (
    "GATEKEEPER_URL",
    "VOUCH_TENANT_ID",
    "VOUCH_TASK_ID",
    "VOUCH_AGENT_ID",
)


def container_name(dep_id):
    """Deterministic, docker-safe container name for a deployment."""
    return "vouch-" + _NAME_RE.sub("-", str(dep_id))


def agent_id_for(dep_id):
    """Deterministic agent identity for a deployment (X-Agent-Id)."""
    return "agent-" + _NAME_RE.sub("-", str(dep_id))


def build_container_spec(deployment, gatekeeper_url=DEFAULT_GATEKEEPER_AGENT_URL):
    """Build the docker-SDK ``containers.run`` spec for one deployment.

    ``deployment``: mapping with ``id``, ``tenant_id``, ``task_id``,
    ``agent_image`` (the §4.5 desired-state shape). ``gatekeeper_url`` is the
    gatekeeper's MCP endpoint *as seen from inside the sandbox network*.
    """
    for key in ("id", "tenant_id", "task_id", "agent_image"):
        if not deployment.get(key):
            raise ValueError(f"deployment is missing {key!r}")
    dep_id = str(deployment["id"])
    spec = {
        "image": str(deployment["agent_image"]),
        "name": container_name(dep_id),
        # No host networking, ever. The internal sandbox network carries only
        # the gatekeeper besides this agent (the egress allowlist).
        "network": SANDBOX_NETWORK,
        "environment": {
            "GATEKEEPER_URL": gatekeeper_url,
            "VOUCH_TENANT_ID": str(deployment["tenant_id"]),
            "VOUCH_TASK_ID": str(deployment["task_id"]),
            "VOUCH_AGENT_ID": agent_id_for(dep_id),
        },
        "read_only": True,
        "tmpfs": {SCRATCH_DIR: "size=100m,mode=1777"},
        "mem_limit": MEM_LIMIT,
        "nano_cpus": NANO_CPUS,
        "privileged": False,
        "cap_drop": ["ALL"],
        "detach": True,
        "labels": {
            RUNNER_LABEL: RUNNER_VALUE,
            "vouch.deployment": dep_id,
            "vouch.tenant": str(deployment["tenant_id"]),
        },
        "restart_policy": {"Name": "unless-stopped"},
    }
    validate_spec(spec)
    return spec


def validate_spec(spec):
    """Reject any spec that violates the sandbox contract. Raises ValueError."""
    if not isinstance(spec, dict):
        raise ValueError("spec must be a dict")
    if spec.get("network_mode") == "host" or spec.get("network") == "host":
        raise ValueError("host networking is forbidden for agent containers")
    if spec.get("network") != SANDBOX_NETWORK:
        raise ValueError(
            f"agent containers must attach to {SANDBOX_NETWORK!r}, "
            f"got {spec.get('network')!r}"
        )
    if spec.get("privileged"):
        raise ValueError("privileged containers are forbidden")
    if "ALL" not in (spec.get("cap_drop") or []):
        raise ValueError("all Linux capabilities must be dropped")
    if not spec.get("read_only"):
        raise ValueError("the root filesystem must be read-only")
    if not spec.get("mem_limit") or not spec.get("nano_cpus"):
        raise ValueError("memory and CPU limits are required")
    env = spec.get("environment") or {}
    missing = [k for k in REQUIRED_ENV if not env.get(k)]
    if missing:
        raise ValueError(f"spec is missing identity env: {', '.join(missing)}")
    return True


def ensure_sandbox_network(docker_client):
    """Create the internal sandbox network if missing; return its name.

    ``internal=True`` means no route to the outside world — only members of
    the network (the agent + the gatekeeper) can talk. Idempotent.
    """
    for net in docker_client.networks.list(names=[SANDBOX_NETWORK]):
        return net.name
    net = docker_client.networks.create(
        SANDBOX_NETWORK,
        internal=True,
        labels={RUNNER_LABEL: RUNNER_VALUE},
    )
    return net.name
