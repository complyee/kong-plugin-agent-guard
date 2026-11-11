// Live checks against a real Kong running the agent-guard plugin.
import crypto from "node:crypto";

const KONG = process.env.KONG ?? "http://localhost:8000";
const MOCK = process.env.MOCK ?? "http://localhost:9000";
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));
let failed = 0, passed = 0;

async function check(name, fn) {
  await fetch(`${MOCK}/_reset`, { method: "POST" });
  try { await fn(); passed++; console.log(`ok   ${name}`); }
  catch (e) { failed++; console.log(`FAIL ${name}\n     ${e.message}`); }
}
function eq(actual, expected, what) {
  if (actual !== expected) throw new Error(`${what}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}
const calls = async () => (await fetch(`${MOCK}/_calls`)).json();
const decides = async () => (await calls()).acr.filter((c) => c.operation === "decideAction");
const post = (path, body, headers = {}) =>
  fetch(`${KONG}${path}`, { method: "POST", body, headers: { "content-type": "application/json", ...headers } });
async function outcomeFor(decisionId) {
  for (let i = 0; i < 50; i++) {
    const o = (await calls()).acr.find((c) => c.operation === "reportExecutionOutcome" && c.parameters.decisionId === decisionId);
    if (o) return o.parameters;
    await sleep(100);
  }
  throw new Error(`no outcome report for ${decisionId}`);
}
const sign = async (p) => (await fetch(`${MOCK}/_sign`, { method: "POST", body: JSON.stringify(p) })).json();

// ---- decide mode ----
await check("grant forwards once with the decision id, body hash and query-bound resource", async () => {
  const body = JSON.stringify({ amount: 120, currency: "EUR" });
  const r = await post("/pay?ref=abc", body, { "X-Agent-Id": "agent-grant", "X-Acr-Action": "weaker.action" });
  eq(r.status, 200, "status");
  const [d] = await decides();
  eq(d.parameters.agent, "agent-grant", "agent");
  eq(d.parameters.action, "payments.transfer.create", "route map wins over client action header");
  eq(d.parameters.payloadHash, sha(body), "payloadHash is SHA-256 of the exact body");
  eq(d.parameters.resourceRef, "/pay?ref=abc", "resourceRef includes the query");
  const up = (await calls()).upstream;
  eq(up.length, 1, "upstream calls");
  eq(typeof up[0].headers["x-acr-decision-id"], "string", "decision id forwarded");
});

for (const [status, outcome, detail] of [
  [200, "executed", "http_200"],
  [202, "executed", "http_202_accepted"],
  [422, "aborted", "http_422"],
  [503, "downstream_error", "http_503"],
]) {
  await check(`upstream ${status} is reported as ${outcome} (${detail})`, async () => {
    const body = `{"n":${status}}`;
    const r = await post(`/pay?status=${status}`, body, { "X-Agent-Id": "agent-grant" });
    eq(r.status, status, "client sees upstream status");
    const [d] = await decides();
    const id = (await calls()).upstream[0].headers["x-acr-decision-id"];
    const o = await outcomeFor(id);
    eq(o.outcome, outcome, "outcome");
    eq(o.detailCode, detail, "detailCode");
    eq(o.payloadHash, d.parameters.payloadHash, "outcome carries Kong's hash");
  });
}

await check("pending returns 202 once and is not forwarded", async () => {
  const r = await post("/pay", "{}", { "X-Agent-Id": "agent-pending" });
  eq(r.status, 202, "status");
  eq(typeof (await r.json()).approvalId, "string", "approvalId");
  eq((await calls()).upstream.length, 0, "upstream calls");
});

await check("refusal returns 403 and is not forwarded", async () => {
  const r = await post("/pay", "{}", { "X-Agent-Id": "agent-refuse" });
  eq(r.status, 403, "status");
  eq((await calls()).upstream.length, 0, "upstream calls");
});

await check("no answer within the timeout fails closed with 503", async () => {
  const r = await post("/pay", "{}", { "X-Agent-Id": "agent-slow" });
  eq(r.status, 503, "status");
  eq((await calls()).upstream.length, 0, "upstream calls");
});

await check("missing agent identity is refused before asking ACR", async () => {
  eq((await post("/pay", "{}")).status, 403, "status");
  eq((await decides()).length, 0, "decide calls");
});

await check("agent name containing | is refused", async () => {
  eq((await post("/pay", "{}", { "X-Agent-Id": "a|b" })).status, 403, "status");
});

await check("unmapped route ignores a client action header", async () => {
  const r = await post("/unmapped", "{}", { "X-Agent-Id": "agent-grant", "X-Acr-Action": "payments.transfer.create" });
  eq(r.status, 403, "status");
  eq((await decides()).length, 0, "decide calls");
});

// ---- authenticated Consumer identity ----
await check("consumer source: unauthenticated request is stopped by key-auth", async () => {
  eq((await post("/consumer", "{}", { "X-Agent-Id": "agent-grant" })).status, 401, "status");
});

await check("consumer source: agent comes from the Consumer, not a spoofed header", async () => {
  const r = await post("/consumer", "{}", { apikey: "test-consumer-key", "X-Agent-Id": "agent-grant" });
  eq(r.status, 200, "status");
  eq((await decides())[0].parameters.agent, "agent-refund", "agent");
});

// ---- offline verify mode ----
const grantBody = '{"amount":50}';
await check("verify: a valid signed grant forwards without asking ACR to decide", async () => {
  const h = await sign({ agent: "agent-grant", action: "payments.transfer.create", body: grantBody });
  eq((await post("/verified", grantBody, { "X-Agent-Id": "agent-grant", ...h })).status, 200, "status");
  eq((await decides()).length, 0, "decide calls");
});

await check("verify: a changed body is refused", async () => {
  const h = await sign({ agent: "agent-grant", action: "payments.transfer.create", body: grantBody });
  eq((await post("/verified", '{"amount":5000}', { "X-Agent-Id": "agent-grant", ...h })).status, 403, "status");
});

await check("verify: a grant for another agent is refused", async () => {
  const h = await sign({ agent: "agent-other", action: "payments.transfer.create", body: grantBody });
  eq((await post("/verified", grantBody, { "X-Agent-Id": "agent-grant", ...h })).status, 403, "status");
});

await check("verify: an expired grant is refused", async () => {
  const h = await sign({ agent: "agent-grant", action: "payments.transfer.create", body: grantBody, expiresInSeconds: -60 });
  eq((await post("/verified", grantBody, { "X-Agent-Id": "agent-grant", ...h })).status, 403, "status");
});

await check("verify: an unknown key id is refused", async () => {
  const h = await sign({ agent: "agent-grant", action: "payments.transfer.create", body: grantBody, keyId: "key-unknown" });
  eq((await post("/verified", grantBody, { "X-Agent-Id": "agent-grant", ...h })).status, 403, "status");
});

await check("verify: no outcome report is sent in offline mode", async () => {
  const h = await sign({ agent: "agent-grant", action: "payments.transfer.create", body: grantBody });
  await post("/verified", grantBody, { "X-Agent-Id": "agent-grant", ...h });
  await sleep(500);
  eq((await calls()).acr.filter((c) => c.operation === "reportExecutionOutcome").length, 0, "outcome reports");
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
