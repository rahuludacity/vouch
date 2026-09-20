/** High-level client for the Vouch control plane, receipt service, billing.
 *
 * Tenant endpoints authenticate with the tenant API key (vouch_sk_*) as a
 * bearer token — the key *is* the tenant on every tenant-scoped endpoint
 * (ARCHITECTURE.md §4.5–4.6).
 */

export class VouchError extends Error {
  constructor(status, code, message) {
    super(`HTTP ${status} [${code}]: ${message}`);
    this.status = status; this.code = code; this.message = message;
  }
}

async function raw(method, url, apiKey, body, timeoutMs) {
  const res = await fetch(url, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  let obj = {};
  try { obj = text.trim() ? JSON.parse(text) : {}; } catch { /* keep {} */ }
  if (!res.ok) throw new VouchError(res.status, obj.error || "http_error", obj.message || "");
  return obj;
}

export class VouchClient {
  constructor(apiKey, {
    controlPlaneUrl = "http://127.0.0.1:9002",
    receiptServiceUrl = "http://127.0.0.1:9001",
    billingUrl = "http://127.0.0.1:9004",
    timeoutMs = 30000,
  } = {}) {
    this.apiKey = apiKey;
    this.cp = controlPlaneUrl.replace(/\/$/, "");
    this.rc = receiptServiceUrl.replace(/\/$/, "");
    this.bl = billingUrl.replace(/\/$/, "");
    this.timeoutMs = timeoutMs;
  }

  /** Create a tenant — returns {client, tenantId, apiKey}. Key shown once. */
  static async provision(name, { controlPlaneUrl = "http://127.0.0.1:9002", ...rest } = {}) {
    const out = await raw("POST", `${controlPlaneUrl}/v1/tenants`, null, { name }, 30000);
    return { client: new VouchClient(out.api_key, { controlPlaneUrl, ...rest }),
             tenantId: out.tenant_id, apiKey: out.api_key };
  }

  _cp(method, path, body, params) {
    let url = this.cp + path;
    if (params) {
      const q = new URLSearchParams(
        Object.fromEntries(Object.entries(params).filter(([, v]) => v != null)));
      url += "?" + q;
    }
    return raw(method, url, this.apiKey, body, this.timeoutMs);
  }
  _rc(method, path, body, params) {
    let url = this.rc + path;
    if (params) {
      const q = new URLSearchParams(
        Object.fromEntries(Object.entries(params).filter(([, v]) => v != null)));
      url += "?" + q;
    }
    return raw(method, url, this.apiKey, body, this.timeoutMs);
  }
  _bl(method, path, body) { return raw(method, this.bl + path, this.apiKey, body, this.timeoutMs); }

  // tenants
  me() { return this._cp("GET", "/v1/tenants/me"); }
  rotateKeys() { return this._cp("POST", "/v1/tenants/me/rotate-keys", {}); }

  // policies (v2 schema — ARCHITECTURE.md §5)
  listPolicies() { return this._cp("GET", "/v1/policies"); }
  putPolicy(taskId, rules) { return this._cp("PUT", `/v1/policies/${taskId}`, { rules }); }
  deletePolicy(taskId) { return this._cp("DELETE", `/v1/policies/${taskId}`); }

  // API keys (named; plaintext shown once)
  listApiKeys() { return this._cp("GET", "/v1/api-keys"); }
  createApiKey(name) { return this._cp("POST", "/v1/api-keys", { name }); }
  revokeApiKey(keyId) { return this._cp("DELETE", `/v1/api-keys/${keyId}`); }

  // deployments (runner picks them up; §2.5)
  deployAgent(taskId, agentImage) {
    return this._cp("POST", "/v1/deployments", { task_id: taskId, agent_image: agentImage });
  }
  listDeployments() { return this._cp("GET", "/v1/deployments"); }
  getDeployment(id) { return this._cp("GET", `/v1/deployments/${id}`); }
  stopDeployment(id) { return this._cp("DELETE", `/v1/deployments/${id}`); }

  // receipts
  receipts({ taskId, tool, decision, agentId, limit = 50, cursor } = {}) {
    return this._rc("GET", "/v1/receipts", undefined,
      { task_id: taskId, tool, decision, agent_id: agentId, limit, cursor });
  }
  getReceipt(seq) { return this._rc("GET", `/v1/receipts/${seq}`); }
  verify() { return this._rc("GET", "/v1/verify"); }

  // billing (Stripe test mode)
  checkout(plan) { return this._bl("POST", "/v1/billing/checkout", { plan }); }
  subscription() { return this._bl("GET", "/v1/billing/subscription"); }
  portalUrl() { return this._bl("GET", "/v1/billing/portal"); }
}
