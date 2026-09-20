// Tests for MCPClient — header mapping against a stub gatekeeper.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { MCPClient } from "../src/index.js";

let server, port;
let lastHeaders = {};

before(async () => {
  server = createServer((req, res) => {
    let raw = "";
    req.on("data", c => raw += c);
    req.on("end", () => {
      lastHeaders = { ...req.headers };
      const out = JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": out.length });
      res.end(out);
    });
  });
  await new Promise(r => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
});

after(() => new Promise(r => server.close(r)));

test("sends X-Deployment-Token header when provided", async () => {
  const mcp = new MCPClient(`http://127.0.0.1:${port}/mcp`, {
    tenantId: "acme", taskId: "deploy-staging", agentId: "agent-001",
    deploymentToken: "dep_tok_123",
  });
  const out = await mcp.callTool("run_tests", { suite: "unit" });
  assert.deepEqual(out, { ok: true });
  assert.equal(lastHeaders["x-deployment-token"], "dep_tok_123");
});
