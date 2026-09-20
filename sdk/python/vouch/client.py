"""High-level client for the Vouch control plane, receipt service, and billing.

All tenant endpoints authenticate with the tenant API key (``vouch_sk_*``),
sent as a bearer token — the key *is* the tenant on every tenant-scoped
endpoint (ARCHITECTURE.md §4.5–4.6).
"""

import json
import urllib.error
import urllib.parse
import urllib.request


class VouchError(Exception):
    """Raised on any non-2xx API response."""

    def __init__(self, status, code, message):
        super().__init__(f"HTTP {status} [{code}]: {message}")
        self.status = status
        self.code = code
        self.message = message


class VouchClient:
    """One client, three services (control plane :9002, receipts :9001,
    billing :9004).

    Usage::

        client = VouchClient(api_key="vouch_sk_…")
        me = client.me()                       # tenant card + usage fan-in
        client.put_policy("deploy-staging", {...v2 rules...})
        dep = client.deploy_agent("deploy-staging", "vouch/agent-demo:latest")
    """

    def __init__(self, api_key, control_plane_url="http://127.0.0.1:9002",
                 receipt_service_url="http://127.0.0.1:9001",
                 billing_url="http://127.0.0.1:9004", timeout=30):
        self.api_key = api_key
        self.control_plane_url = control_plane_url.rstrip("/")
        self.receipt_service_url = receipt_service_url.rstrip("/")
        self.billing_url = billing_url.rstrip("/")
        self.timeout = timeout

    # ------------------------------------------------------------- factory
    @classmethod
    def provision(cls, name, control_plane_url="http://127.0.0.1:9002",
                  **kwargs):
        """Create a tenant and return ``(client, tenant_id, api_key)``.

        The API key is shown exactly once — store it; only its sha256 is kept
        server-side.
        """
        out = cls._raw("POST", f"{control_plane_url.rstrip('/')}/v1/tenants",
                       None, {"name": name}, kwargs.get("timeout", 30))
        client = cls(out["api_key"], control_plane_url=control_plane_url,
                     **{k: v for k, v in kwargs.items()
                        if k in ("receipt_service_url", "billing_url")})
        return client, out["tenant_id"], out["api_key"]

    # ------------------------------------------------------------- transport
    @staticmethod
    def _raw(method, url, api_key, body, timeout):
        data = (json.dumps(body).encode("utf-8")
                if body is not None else None)
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read().decode("utf-8") or "{}")
            except Exception:
                err = {}
            raise VouchError(e.code, err.get("error", "http_error"),
                             err.get("message", ""))

    def _cp(self, method, path, body=None, params=None):
        url = self.control_plane_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return self._raw(method, url, self.api_key, body, self.timeout)

    def _rc(self, method, path, body=None, params=None):
        url = self.receipt_service_url + path
        if params:
            url += "?" + urllib.parse.urlencode(
                {k: v for k, v in params.items() if v is not None})
        return self._raw(method, url, self.api_key, body, self.timeout)

    def _bl(self, method, path, body=None):
        return self._raw(method, self.billing_url + path, self.api_key,
                         body, self.timeout)

    # ---------------------------------------------------------------- tenants
    def me(self):
        """Tenant card + current-month usage fan-in (§4.5)."""
        return self._cp("GET", "/v1/tenants/me")

    def rotate_keys(self):
        """Rotate the tenant's HMAC signing key. Returns ``{"new_kid": …}`` —
        key material never leaves the server; old kids keep verifying."""
        return self._cp("POST", "/v1/tenants/me/rotate-keys", {})

    # ---------------------------------------------------------------- policies
    def list_policies(self):
        return self._cp("GET", "/v1/policies")

    def put_policy(self, task_id, rules):
        """Write a v2 policy (ARCHITECTURE.md §5). ``rules`` =
        ``{"allow": [{"rule_id", "tool", "args"?}…], "deny": […]}``.
        Unknown constraint ops → 422 (raised as VouchError)."""
        return self._cp("PUT", f"/v1/policies/{task_id}", {"rules": rules})

    def delete_policy(self, task_id):
        return self._cp("DELETE", f"/v1/policies/{task_id}")

    # --------------------------------------------------------------- API keys
    def list_api_keys(self):
        """Metadata only — no hashes, no plaintext (§4.5)."""
        return self._cp("GET", "/v1/api-keys")

    def create_api_key(self, name):
        """Returns ``{"id", "api_key", "name"}`` — plaintext shown once."""
        return self._cp("POST", "/v1/api-keys", {"name": name})

    def revoke_api_key(self, key_id):
        return self._cp("DELETE", f"/v1/api-keys/{key_id}")

    # ------------------------------------------------------------- deployments
    def deploy_agent(self, task_id, agent_image):
        """Create a deployment — the runner picks it up, sandboxes the
        agent, and injects gatekeeper identity env (§2.5, §4.5)."""
        return self._cp("POST", "/v1/deployments",
                        {"task_id": task_id, "agent_image": agent_image})

    def list_deployments(self):
        return self._cp("GET", "/v1/deployments")

    def get_deployment(self, deployment_id):
        return self._cp("GET", f"/v1/deployments/{deployment_id}")

    def stop_deployment(self, deployment_id):
        return self._cp("DELETE", f"/v1/deployments/{deployment_id}")

    # ---------------------------------------------------------------- receipts
    def receipts(self, task_id=None, tool=None, decision=None, agent_id=None,
                 limit=50, cursor=None):
        """Newest-first receipt list; ``cursor`` = seq for pagination (§4.6)."""
        return self._rc("GET", "/v1/receipts", params={
            "task_id": task_id, "tool": tool, "decision": decision,
            "agent_id": agent_id, "limit": limit, "cursor": cursor})

    def get_receipt(self, seq):
        return self._rc("GET", f"/v1/receipts/{seq}")

    def verify(self):
        """Server-side chain + signature verification (§4.6). Returns
        ``{"tenant_id", "receipts", "chain_ok", "failures"}``."""
        return self._rc("GET", "/v1/verify")

    # ---------------------------------------------------------------- billing
    def checkout(self, plan):
        """Start a Stripe test-mode checkout. Returns ``{"checkout_url",
        "session_id", "test_mode": True}``."""
        return self._bl("POST", "/v1/billing/checkout", {"plan": plan})

    def subscription(self):
        return self._bl("GET", "/v1/billing/subscription")

    def portal_url(self):
        return self._bl("GET", "/v1/billing/portal")
