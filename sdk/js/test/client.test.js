// Tests for VouchClient — request/response mapping against a stub server.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { VouchClient, VouchError } from "../src/index.js";

let server, port, client;
const last = {};

const routes = {
  "POST /v1/tenants": [200, { tenant_id: "acme", api_key: "vouch_sk_abc", plan: "free" }],
  "GET /v1/tenants/me": [200, { tenant_id: "acme", plan: "pro", status: "active" }],
  "PUT /v1/policies/t1": [200, { task_id: "t1", version: 4 }],
  "PUT /v1/policies/bad": [422, { error: "invalid_policy", message: "unknown op" }],
  "GET /v1/receipts": [200, { items: [], next_cursor: null }],
  "GET /v1/verify": [200, { tenant_id: "acme", receipts: 0, chain_ok: true, failures: [] }],
  "POST /v1/deployments": [200, { deployment_id: "dep_1", status: "pending" }],
  "POST /v1/billing/checkout": [200, { checkout_url: "https://x", session_id: "cs_1", test_mode: true }],
};

before(async () => {
  server = createServer((req, res) => {
    let raw = "";
    req.on("data", c => raw += c);
    req.on("end", () => {
      Object.assign(last, {
        method: req.method, path: req.url,
        auth: req.headers.authorization || null,
        body: raw ? JSON.parse(raw) : undefined,
      });
      const key = `${req.method} ${req.url.split("?")[0]}`;
      const [code, obj] = routes[key] || [404, { error: "not_found" }];
      const out = JSON.stringify(obj);
      res.writeHead(code, { "Content-Type": "application/json", "Content-Length": out.length });
      res.end(out);
    });
  });
  await new Promise(r => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
  const base = `http://127.0.0.1:${port}`;
  client = new VouchClient("vouch_sk_test", {
    controlPlaneUrl: base, receiptServiceUrl: base, billingUrl: base,
  });
});

after(() => new Promise(r => server.close(r)));

test("provision returns client + tenant + key, unauthenticated", async () => {
  const { client: c, tenantId, apiKey } = await VouchClient.provision("acme",
    { controlPlaneUrl: `http://127.0.0.1:${port}` });
  assert.equal(tenantId, "acme");
  assert.equal(apiKey, "vouch_sk_abc");
  assert.deepEqual(last.body, { name: "acme" });
  assert.equal(last.auth, null);
  assert.ok(c instanceof VouchClient);
});

test("me sends bearer", async () => {
  const me = await client.me();
  assert.equal(me.tenant_id, "acme");
  assert.equal(last.auth, "Bearer vouch_sk_test");
});

test("putPolicy maps path + body", async () => {
  const out = await client.putPolicy("t1", { allow: [], deny: [] });
  assert.equal(out.version, 4);
  assert.equal(last.path, "/v1/policies/t1");
  assert.deepEqual(last.body, { rules: { allow: [], deny: [] } });
});

test("422 maps to VouchError", async () => {
  await assert.rejects(client.putPolicy("bad", {}), err => {
    assert.ok(err instanceof VouchError);
    assert.equal(err.status, 422);
    assert.equal(err.code, "invalid_policy");
    return true;
  });
});

test("receipts sends query params", async () => {
  await client.receipts({ limit: 10 });
  assert.ok(last.path.startsWith("/v1/receipts"));
  assert.ok(last.path.includes("limit=10"));
});

test("verify", async () => {
  assert.equal((await client.verify()).chain_ok, true);
});

test("deployAgent", async () => {
  const dep = await client.deployAgent("t1", "vouch/agent-demo:latest");
  assert.equal(dep.deployment_id, "dep_1");
  assert.deepEqual(last.body, { task_id: "t1", agent_image: "vouch/agent-demo:latest" });
});

test("checkout hits billing with test_mode", async () => {
  const out = await client.checkout("pro");
  assert.equal(out.test_mode, true);
  assert.deepEqual(last.body, { plan: "pro" });
});
