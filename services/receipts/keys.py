"""Server-side tenant key loading for the receipt service.

Two sources, in order:
  1. The control plane (GET /internal/tenants/{id}/keys, §4.7) when
     controlplane_url is set — keys are fetched server-side and cached
     5 minutes. This is the key authority once tenants live in the
     control plane DB.
  2. The v1 tenants.json file (pre-migration tenants, and local-dev
     fallback when the control plane is unreachable).

Key material never leaves the server: verify runs here, clients only see
chain_ok / failures.

Raises:
  KeyError                 — tenant unknown to every configured source.
  KeyAuthorityUnavailable  — the control plane is configured but unreachable
                             AND the file doesn't know the tenant either.
                             (Callers should answer 503, not 404.)
"""
import json
import os
import threading
import time
import urllib.request
import urllib.error

_CP_TTL = 300  # control-plane key cache, seconds
_cp_cache = {}  # tenant_id -> (keys, fetched_at)
_cp_lock = threading.Lock()


class KeyAuthorityUnavailable(Exception):
    """Key authority unreachable and no local fallback knows the tenant."""


def invalidate_cache(tenant_id=None):
    """Drop cached control-plane keys (e.g. after a rotation race).

    The receipt service calls this when verification hits an unknown kid,
    then re-fetches once. Thread-safe.
    """
    with _cp_lock:
        if tenant_id is None:
            _cp_cache.clear()
        else:
            _cp_cache.pop(tenant_id, None)


def load_verification_keys(tenants_path, tenant_id,
                           controlplane_url=None, cp_token=""):
    """{kid: key_bytes} for tenant_id."""
    cp_configured = bool(controlplane_url)
    cp_unknown = False
    cp_down = False
    if cp_configured:
        try:
            return _cp_keys(controlplane_url, cp_token, tenant_id)
        except KeyError:
            cp_unknown = True  # not in CP: maybe a file-only (pre-migration) tenant
        except KeyAuthorityUnavailable:
            cp_down = True  # CP unreachable: the file may still answer
    try:
        return _file_keys(tenants_path, tenant_id)
    except (KeyError, FileNotFoundError, ValueError):
        if cp_configured and cp_down and not cp_unknown:
            # The authority is down and the file can't cover this tenant:
            # say so honestly instead of a misleading 404.
            raise KeyAuthorityUnavailable(
                f"control plane unreachable and tenant '{tenant_id}'"
                " not in the local registry")
        raise KeyError(f"unknown tenant '{tenant_id}'")


def _file_keys(tenants_path, tenant_id):
    with open(os.path.abspath(tenants_path), "r", encoding="utf-8") as f:
        tenants = json.load(f).get("tenants", {})
    t = tenants.get(tenant_id)
    if t is None:
        raise KeyError(f"unknown tenant '{tenant_id}'")
    return {kid: bytes.fromhex(k) for kid, k in t["keys"].items()}


def _cp_keys(base_url, token, tenant_id):
    now = time.time()
    with _cp_lock:
        hit = _cp_cache.get(tenant_id)
        if hit and now - hit[1] < _CP_TTL:
            return dict(hit[0])
    url = base_url.rstrip("/") + f"/internal/tenants/{tenant_id}/keys"
    req = urllib.request.Request(url, method="GET")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            if not 200 <= resp.status < 300:
                raise KeyAuthorityUnavailable(f"HTTP {resp.status}")
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise KeyError(f"unknown tenant '{tenant_id}'")
        raise KeyAuthorityUnavailable(f"control plane HTTP {e.code}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise KeyAuthorityUnavailable(f"control plane unreachable: {e}")
    keys = {kid: bytes.fromhex(k) for kid, k in (data.get("keys") or {}).items()}
    if not keys:
        raise KeyAuthorityUnavailable("control plane returned no keys")
    with _cp_lock:
        _cp_cache[tenant_id] = (keys, now)
    return dict(keys)
