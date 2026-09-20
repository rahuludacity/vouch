/** Minimal MCP Streamable HTTP client pinned to the Vouch gatekeeper.
 *
 * The gatekeeper reads tenant identity from headers: X-Tenant-Id,
 * X-Agent-Id, X-Task-Id. Every tools/call is policy-gated (denied calls
 * return JSON-RPC -32000 and never reach the upstream tool server).
 */

export class MCPError extends Error {}

export class MCPClient {
  constructor(gatekeeperUrl, { tenantId, taskId, agentId, timeoutMs = 30000 } = {}) {
    this.url = gatekeeperUrl.replace(/\/$/, "");
    this.tenantId = tenantId; this.taskId = taskId; this.agentId = agentId;
    this.timeoutMs = timeoutMs;
    this.sessionId = null;
    this._nextId = 1;
  }

  _headers(accept = "application/json") {
    const h = {
      "Content-Type": "application/json", Accept: accept,
      "X-Tenant-Id": this.tenantId, "X-Agent-Id": this.agentId,
      "X-Task-Id": this.taskId,
    };
    if (this.sessionId) h["Mcp-Session-Id"] = this.sessionId;
    return h;
  }

  async _post(message) {
    const res = await fetch(this.url, {
      method: "POST", headers: this._headers(),
      body: JSON.stringify(message),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const sid = res.headers.get("Mcp-Session-Id");
    if (sid) this.sessionId = sid;
    const text = await res.text();
    if (!res.ok) throw new MCPError(`gatekeeper HTTP ${res.status}: ${text}`);
    return text.trim() ? JSON.parse(text) : {};
  }

  async initialize() {
    const resp = await this._post({
      jsonrpc: "2.0", id: this._nextId++,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18", capabilities: {},
        clientInfo: { name: "vouch-sdk-js", version: "0.6.0" },
      },
    });
    if (!this.sessionId) throw new MCPError(`initialize failed: ${JSON.stringify(resp)}`);
    await this._post({ jsonrpc: "2.0", method: "notifications/initialized" });
    return resp;
  }

  /** Call a tool through the gatekeeper. Throws MCPError if denied. */
  async callTool(tool, args = {}) {
    const resp = await this._post({
      jsonrpc: "2.0", id: this._nextId++,
      method: "tools/call",
      params: { name: tool, arguments: args },
    });
    if (resp.error) {
      throw new MCPError(`denied: ${resp.error.message} (code ${resp.error.code})`);
    }
    return resp.result;
  }

  async close() {
    if (!this.sessionId) return;
    try {
      await fetch(this.url, {
        method: "DELETE", headers: this._headers(),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch { /* best effort */ }
    this.sessionId = null;
  }
}
