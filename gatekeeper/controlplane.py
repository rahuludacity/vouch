"""Control-plane client for the gatekeeper (Phase 2, §4.3/§4.4).

Active ONLY when CONTROLPLANE_URL is set. Otherwise the gatekeeper uses the
file-backed TenantRegistry + policy.yaml exactly as v1 (zero behavior change).

KeyBundleCache: per-tenant key bundles from
    GET /internal/tenants/{id}/key-bundle   (bearer GATEKEEPER_SVC_TOKEN)
60s TTL. On fetch failure it serves stale entries up to STALE_MAX_AGE (600s)
— the trust boundary (§1): the gatekeeper keeps enforcing with cached keys
when the control plane is down. Past that it raises KeyError (unknown tenant
-> 403, fail closed). Implements the same resolver interface as
TenantRegistry: signing_key() / verification_keys().

PolicyBundleCache: per-tenant compiled policies from
    GET /internal/policies/bundle?tenant_id=&since_version=
A background poller refreshes known tenants every POLICY_POLL_INTERVAL
(default 15s); the gatekeeper also refreshes opportunistically when the key
bundle reports a newer policy_version than the cached bundle.
"""
import json
import re
import threading
import time
import urllib.request
import urllib.error
import hmac
import hashlib

from . import policy_v2

KEY_TTL = 60.0
KEY_STALE_MAX = 600.0
_HTTP_TIMEOUT = 5
# How long a (deployment_id -> tenant_id, status) binding is trusted before
# re-checking with the control plane. Revocation (stop/delete) takes effect
# within this window, or immediately via push-invalidate.
DEP_BIND_TTL = 300.0
# Deployment credential format (H-1):
#   vouch_dep_<deployment_id>_<tenant_id>_<issued_epoch>_<sig32>
# sig = HMAC-SHA256(platform deployment key,
#                   "<deployment_id>.<tenant_id>.<issued>")[:32 hex].
DEP_TOKEN_PREFIX = "vouch_dep_"
_DEP_TOKEN_RE = re.compile(
    r"^vouch_dep_(dep_[0-9a-f]{16})_(.+)_(\d+)_([0-9a-f]{32})$")


def parse_deployment_token(token):
    """-> (deployment_id, tenant_id, issued, sig), or None if malformed."""
    m = _DEP_TOKEN_RE.fullmatch(token or "")
    if not m:
        return None
    return m.group(1), m.group(2), int(m.group(3)), m.group(4)


class ControlPlaneError(Exception):
    """The control plane is unreachable or answered unusably."""


def _get_json(url, token):
    req = urllib.request.Request(url, method="GET")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            if not 200 <= resp.status < 300:
                raise ControlPlaneError(f"HTTP {resp.status} from {url}")
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise KeyError(f"unknown tenant (control plane 404): {url}")
        raise ControlPlaneError(f"HTTP {e.code} from {url}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise ControlPlaneError(f"control plane unreachable: {e}")


class KeyBundleCache:
    """Cached per-tenant HMAC key bundles. Same interface as TenantRegistry."""

    def __init__(self, base_url, token, ttl=KEY_TTL, stale_max=KEY_STALE_MAX):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.ttl = ttl
        self.stale_max = stale_max
        self._lock = threading.RLock()
        # tenant_id -> {"keys": {kid: bytes}, "current_kid", "status",
        #               "policy_version", "fetched_at"}
        self._entries = {}

    # ------------------------------------------------------------- fetching
    def _fetch(self, tenant_id):
        data = _get_json(
            f"{self.base_url}/internal/tenants/{tenant_id}/key-bundle", self.token)
        keys = data.get("keys") or {}
        current = data.get("current_kid")
        if not keys or current not in keys:
            raise ControlPlaneError("key bundle missing keys/current_kid")
        return {
            "keys": {kid: bytes.fromhex(k) for kid, k in keys.items()},
            "current_kid": current,
            "status": data.get("status", "active"),
            "policy_version": int(data.get("policy_version", 0) or 0),
            "fetched_at": time.time(),
        }

    def _entry(self, tenant_id):
        """Fresh-or-stale bundle. Raises KeyError when unusable (fail closed)."""
        now = time.time()
        with self._lock:
            e = self._entries.get(tenant_id)
            if e and now - e["fetched_at"] < self.ttl:
                return e
        try:
            fresh = self._fetch(tenant_id)
        except KeyError:
            with self._lock:
                self._entries.pop(tenant_id, None)
            raise
        except ControlPlaneError:
            with self._lock:
                e = self._entries.get(tenant_id)
                if e and now - e["fetched_at"] < self.stale_max:
                    return e  # keep enforcing with cached keys (§1)
            raise KeyError(f"unknown tenant '{tenant_id}'")
        with self._lock:
            self._entries[tenant_id] = fresh
            return fresh

    def invalidate(self, tenant_id):
        """Drop a tenant's cached bundle (push-invalidate hook, §4.3)."""
        with self._lock:
            self._entries.pop(tenant_id, None)

    # ------------------------------------------- TenantRegistry interface
    def signing_key(self, tenant_id):
        """(kid, key_bytes) for new receipts. KeyError -> 403 unknown tenant."""
        e = self._entry(tenant_id)
        return e["current_kid"], e["keys"][e["current_kid"]]

    def verification_keys(self, tenant_id):
        return dict(self._entry(tenant_id)["keys"])

    # ------------------------------------------------------- CP-only extras
    def status(self, tenant_id):
        return self._entry(tenant_id)["status"]

    def policy_version(self, tenant_id):
        try:
            return self._entry(tenant_id)["policy_version"]
        except KeyError:
            return 0


class PolicyBundleCache:
    """Cached per-tenant compiled policies from the control plane."""

    def __init__(self, base_url, token, poll_interval=15.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.poll_interval = poll_interval
        self._lock = threading.RLock()
        # tenant_id -> {"version": int, "policy": policy_v2.Policy}
        self._policies = {}
        self._stop = threading.Event()
        self._poller = threading.Thread(
            target=self._poll_loop, name="policy-poller", daemon=True)
        self._poller.start()

    # ------------------------------------------------------------- fetching
    def _fetch_bundle(self, tenant_id, since_version):
        return _get_json(
            f"{self.base_url}/internal/policies/bundle"
            f"?tenant_id={tenant_id}&since_version={since_version}",
            self.token)

    def _compile(self, data):
        tasks = {}
        for task_id, t in (data.get("policies") or {}).items():
            tasks[task_id] = {
                "version": t.get("version", 1),
                "rules": json.loads(t["rules_json"]),
            }
        return policy_v2.Policy.from_dict(
            {"version": data.get("version", 0), "tasks": tasks})

    def bundle_version(self, tenant_id):
        with self._lock:
            e = self._policies.get(tenant_id)
            return e["version"] if e else 0

    def note_tenant(self, tenant_id):
        with self._lock:
            self._policies.setdefault(tenant_id, None)

    def refresh_tenant(self, tenant_id):
        """Fetch + compile if the bundle advanced. Returns Policy or None.

        Never raises: on any failure the previous cached policy (if any)
        stays in force — enforcement never depends on a fresh fetch.
        """
        since = self.bundle_version(tenant_id)
        try:
            data = self._fetch_bundle(tenant_id, since)
        except (ControlPlaneError, KeyError):
            return self._cached_policy(tenant_id)
        if int(data.get("version", 0) or 0) <= since:
            return self._cached_policy(tenant_id)
        try:
            policy = self._compile(data)
        except (policy_v2.PolicyError, ValueError, KeyError):
            # The control plane validates on PUT; a bad bundle here means
            # corruption — keep enforcing the last good policy.
            return self._cached_policy(tenant_id)
        with self._lock:
            self._policies[tenant_id] = {
                "version": int(data["version"]), "policy": policy}
        return policy

    def _cached_policy(self, tenant_id):
        with self._lock:
            e = self._policies.get(tenant_id)
            return e["policy"] if e else None

    def policy_for(self, tenant_id):
        """Compiled Policy for the tenant, or None (caller uses file policy)."""
        self.note_tenant(tenant_id)
        cached = self._cached_policy(tenant_id)
        if cached is not None:
            return cached
        return self.refresh_tenant(tenant_id)

    def invalidate(self, tenant_id):
        with self._lock:
            self._policies.pop(tenant_id, None)

    def close(self):
        self._stop.set()

    # -------------------------------------------------------------- polling
    def _poll_loop(self):
        while not self._stop.wait(self.poll_interval):
            try:
                with self._lock:
                    tenants = list(self._policies)
                for tid in tenants:
                    try:
                        self.refresh_tenant(tid)
                    except Exception:  # noqa: BLE001 - poller must never die
                        pass
            except Exception:  # noqa: BLE001
                pass


class DeploymentTokenVerifier:
    """Validates per-deployment gatekeeper credentials (H-1 fix).

    Two steps, both must pass:
      1. Self-contained HMAC check against the platform deployment-signing
         key, fetched from the control plane
         (GET /internal/platform/deployment-token-key, deployment:verify
         scope) and cached with a 60s TTL / 10-minute stale-while-revalidate
         window — same resilience posture as the key bundles.
      2. Revocation-aware binding check: the deployment must still exist and
         be pending/running for the token's tenant
         (GET /internal/deployments/{id}), cached DEP_BIND_TTL (300s).

    verify() returns the authoritative tenant_id, or None when the
    credential is missing, malformed, forged, expired from cache, or
    revoked. Fail closed: if the platform key cannot be obtained at all,
    every token is rejected.
    """

    def __init__(self, base_url, token, ttl=KEY_TTL, stale_max=KEY_STALE_MAX,
                 bind_ttl=DEP_BIND_TTL):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.ttl = ttl
        self.stale_max = stale_max
        self.bind_ttl = bind_ttl
        self._lock = threading.RLock()
        self._key = None          # {"key": bytes, "fetched_at": float}
        self._bindings = {}       # dep_id -> {"tenant_id", "status", "at"}

    # ------------------------------------------------------------- fetching
    def _fetch_signing_key(self):
        data = _get_json(
            f"{self.base_url}/internal/platform/deployment-token-key",
            self.token)
        key_hex = data.get("key_hex", "")
        if len(key_hex) != 64:
            raise ControlPlaneError("bad deployment-token-key payload")
        return {"key": bytes.fromhex(key_hex), "fetched_at": time.time()}

    def _signing_key(self):
        """Platform key bytes, or None when unobtainable (fail closed)."""
        now = time.time()
        with self._lock:
            k = self._key
            if k and now - k["fetched_at"] < self.ttl:
                return k["key"]
        try:
            fresh = self._fetch_signing_key()
        except (ControlPlaneError, KeyError):
            with self._lock:
                k = self._key
                if k and now - k["fetched_at"] < self.stale_max:
                    return k["key"]
            return None
        with self._lock:
            self._key = fresh
            return fresh["key"]

    def _fetch_binding(self, dep_id):
        try:
            data = _get_json(
                f"{self.base_url}/internal/deployments/{dep_id}", self.token)
        except KeyError:
            return None  # unknown deployment -> revoked for our purposes
        return {"tenant_id": data.get("tenant_id"),
                "status": data.get("status"),
                "at": time.time()}

    def _binding(self, dep_id):
        now = time.time()
        with self._lock:
            b = self._bindings.get(dep_id)
            if b and now - b["at"] < self.bind_ttl:
                return b
        fresh = self._fetch_binding(dep_id)
        with self._lock:
            if fresh is None:
                self._bindings.pop(dep_id, None)
            else:
                self._bindings[dep_id] = fresh
            return fresh

    def invalidate_binding(self, dep_id):
        """Drop a cached deployment binding (push-invalidate hook)."""
        with self._lock:
            self._bindings.pop(dep_id, None)

    # --------------------------------------------------------------- verify
    def verify(self, token):
        """-> authoritative tenant_id, or None when the credential is bad."""
        parsed = parse_deployment_token(token)
        if parsed is None:
            return None
        dep_id, tenant_id, issued, sig = parsed
        key = self._signing_key()
        if key is None:
            return None  # fail closed: no key authority, no trust
        expect = hmac.new(
            key, f"{dep_id}.{tenant_id}.{issued}".encode("utf-8"),
            hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(expect, sig):
            return None
        binding = self._binding(dep_id)
        if (binding is None
                or binding["tenant_id"] != tenant_id
                or binding["status"] not in ("pending", "running")):
            return None
        return tenant_id
