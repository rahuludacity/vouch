"""HTTP forwarding client for the Vouch dashboard (:3000, Phase 4, §2.6).

The dashboard is a thin backend-for-frontend: it holds the operator's tenant
API key server-side (per session) and forwards every call to the control
plane (:9002) and receipt service (:9001) using the frozen §4 contracts.
It invents NO new upstream endpoints — everything here maps 1:1 onto
ARCHITECTURE.md §4.4/§4.5 (control plane) and §4.6 (receipt service).
"""

import json
import urllib.request
import urllib.error
from urllib.parse import urlencode


class UpstreamError(Exception):
    def __init__(self, status, payload):
        super().__init__(f"upstream {status}")
        self.status = status
        self.payload = payload


def fwd(method, base, path, key, body=None, params=None, timeout=15):
    """Forward one JSON call. Returns (status, parsed_body_or_raw_text).

    Never raises on HTTP errors: maps them to (status, body). Raises
    UpstreamError(502, ...) only when the upstream is unreachable, so the
    dashboard can render a clean "service unavailable" instead of a 500.
    """
    url = base.rstrip("/") + path
    if params:
        url += "?" + urlencode({k: v for k, v in params.items()
                                if v is not None and v != ""})
    data = None
    headers = {"Authorization": f"Bearer {key}"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, _parse(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, _parse(e.read().decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001 - connection refused, timeout, DNS
        raise UpstreamError(502, {"error": "upstream_unavailable",
                                  "message": str(e)})


def _parse(raw):
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return raw
