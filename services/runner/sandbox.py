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
    # VOUCH_DEPLOYMENT_TOKEN is injected by the runner at reconcile time
    # (H-1) and validated separately — see build_container_spec.
)


def container_name(dep_id):
    """Deterministic, docker-safe container name for a deployment."""
    return "vouch-" + _NAME_RE.sub("-", str(dep_id))


def agent_id_for(dep_id):
    """Deterministic agent identity for a deployment (X-Agent-Id)."""
    return "agent-" + _NAME_RE.sub("-", str(dep_id))


def build_container_spec(deployment, gatekeeper_url=DEFAULT_GATEKEEPER_AGENT_URL,
                         deployment_token=None, sandbox_network=SANDBOX_NETWORK):
    """Build the docker-SDK ``containers.run`` spec for one deployment.

    ``deployment``: mapping with ``id``, ``tenant_id``, ``task_id``,
    ``agent_image`` (the §4.5 desired-state shape). ``gatekeeper_url`` is the
    gatekeeper's MCP endpoint *as seen from inside the sandbox network*.
    ``deployment_token`` is the per-deployment gatekeeper credential (H-1)
    the control plane issued at deployment creation; it is injected as
    ``VOUCH_DEPLOYMENT_TOKEN`` — the ONLY way the agent authenticates to the
    gatekeeper. A spec without one is rejected: an agent container must never
    start without its credential.
    """
    for key in ("id", "tenant_id", "task_id", "agent_image"):
        if not deployment.get(key):
            raise ValueError(f"deployment is missing {key!r}")
    if not deployment_token:
        raise ValueError("deployment_token is required (H-1): the runner "
                         "must inject the deployment's gatekeeper credential")
    dep_id = str(deployment["id"])
    spec = {
        "image": str(deployment["agent_image"]),
        "name": container_name(dep_id),
        # No host networking, ever. The internal sandbox network carries only
        # the gatekeeper besides this agent (the egress allowlist).
        # NOTE: use the *adopted* network name (ensure_sandbox_network may
        # adopt the compose-created vouch_vouch-sandbox instead of creating
        # the bare name) — never hardcode SANDBOX_NETWORK here.
        "network": sandbox_network,
        "environment": {
            "GATEKEEPER_URL": gatekeeper_url,
            "VOUCH_TENANT_ID": str(deployment["tenant_id"]),
            "VOUCH_TASK_ID": str(deployment["task_id"]),
            "VOUCH_AGENT_ID": agent_id_for(dep_id),
            # H-1: per-deployment gatekeeper credential. The agent sends it
            # as X-Deployment-Token; the gatekeeper validates it before
            # honoring any identity header.
            "VOUCH_DEPLOYMENT_TOKEN": deployment_token,
        },
        "read_only": True,
        # noexec + nosuid on the only writable mount (L-5): even a code-exec
        # inside the container cannot drop a setuid binary or execute from
        # /scratch.
        "tmpfs": {SCRATCH_DIR: "size=100m,mode=1777,noexec,nosuid"},
        "mem_limit": MEM_LIMIT,
        "nano_cpus": NANO_CPUS,
        "privileged": False,
        "cap_drop": ["ALL"],
        # non-root user (M-5): the agent never runs as uid 0. Numeric
        # nobody:nogroup so minimal images without a passwd entry work.
        "user": "65534:65534",
        # no-new-privileges (L-5): a compromised agent process cannot gain
        # privileges via setuid binaries even if one were present.
        "security_opt": ["no-new-privileges:true"],
        "detach": True,
        "labels": {
            RUNNER_LABEL: RUNNER_VALUE,
            "vouch.deployment": dep_id,
            "vouch.tenant": str(deployment["tenant_id"]),
        },
        "restart_policy": {"Name": "unless-stopped"},
    }
    validate_spec(spec, sandbox_network=sandbox_network)
    return spec


def validate_spec(spec, sandbox_network=SANDBOX_NETWORK):
    """Reject any spec that violates the sandbox contract. Raises ValueError."""
    if not isinstance(spec, dict):
        raise ValueError("spec must be a dict")
    if spec.get("network_mode") == "host" or spec.get("network") == "host":
        raise ValueError("host networking is forbidden for agent containers")
    if spec.get("network") != sandbox_network:
        raise ValueError(
            f"agent containers must attach to {sandbox_network!r}, "
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
    # L-5: no-new-privileges + noexec on the scratch mount are part of the
    # contract, not decoration.
    if "no-new-privileges:true" not in (spec.get("security_opt") or []):
        raise ValueError("security_opt must include no-new-privileges:true")
    tmpfs = spec.get("tmpfs") or {}
    scratch_opts = tmpfs.get(SCRATCH_DIR, "")
    if "noexec" not in scratch_opts:
        raise ValueError(f"{SCRATCH_DIR} tmpfs must be mounted noexec")
    # M-5: the agent must not run as root. Accept numeric or named
    # non-root users; reject missing, "0", and "root".
    user = str(spec.get("user") or "").strip()
    if not user or user in ("0", "0:0", "root", "root:root"):
        raise ValueError("agent containers must run as a non-root user")
    env = spec.get("environment") or {}
    missing = [k for k in REQUIRED_ENV if not env.get(k)]
    if missing:
        raise ValueError(f"spec is missing identity env: {', '.join(missing)}")
    if not env.get("VOUCH_DEPLOYMENT_TOKEN"):
        raise ValueError("spec is missing VOUCH_DEPLOYMENT_TOKEN (H-1)")
    return True


def ensure_sandbox_network(docker_client):
    """Create the internal sandbox network if missing; return its name.

    ``internal=True`` means no route to the outside world — only members of
    the network (the agent + the gatekeeper) can talk. Idempotent.

    L-5: a pre-existing network is NOT trusted blindly — its ``internal``
    flag is verified, and a non-internal ``vouch-sandbox`` raises instead of
    silently granting agents egress. A poisoned network fails closed.
    """
    for net in docker_client.networks.list(names=[SANDBOX_NETWORK]):
        internal = (getattr(net, "attrs", None) or {}).get("Internal", False)
        if not internal:
            raise RuntimeError(
                f"docker network {SANDBOX_NETWORK!r} exists but is not "
                f"internal — refusing to attach agents (possible network "
                f"poisoning; delete it or recreate with internal=true)")
        return net.name
    net = docker_client.networks.create(
        SANDBOX_NETWORK,
        internal=True,
        labels={RUNNER_LABEL: RUNNER_VALUE},
    )
    return net.name
