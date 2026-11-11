// Stand-in for Agent Control Room and the upstream service, with no dependencies.
// /acr       answers decideAction, getGrantVerificationKey, reportExecutionOutcome
// /upstream  the service Kong forwards to; ?status=NNN picks its reply status
// /_calls, /_reset, /_sign  test controls (never part of a real deployment)
import http from "node:http";
import crypto from "node:crypto";

const API_KEY = "test-api-key";
const WORKSPACE = "ws-integration";
const KEY_ID = "key-current";
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const rawPublic = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64url");

let calls = { acr: [], upstream: [] };
let seq = 0;

const read = (req) => new Promise((ok) => { const c = []; req.on("data", (d) => c.push(d)); req.on("end", () => ok(Buffer.concat(c))); });
const json = (res, status, body) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));

async function acr(req, res, body) {
  if (req.headers["x-api-key"] !== API_KEY) return json(res, 401, { error: "bad key" });
  const { operation, parameters = {} } = JSON.parse(body.toString() || "{}");
  calls.acr.push({ operation, parameters, idempotencyKey: req.headers["idempotency-key"] });
  if (operation === "getGrantVerificationKey") {
    return json(res, 200, { verificationKeys: { workspaceId: WORKSPACE, keys: [{ keyId: KEY_ID, publicKey: rawPublic }] } });
  }
  if (operation === "reportExecutionOutcome") return json(res, 200, { recorded: true });
  if (operation === "decideAction") {
    const decisionId = `dec-${++seq}`;
    switch (parameters.agent) {
      case "agent-slow": await sleep(2500); return json(res, 200, { decision: { effect: "grant", decisionId } });
      case "agent-pending": return json(res, 200, { decision: { effect: "pending", decisionId, approvalId: `apr-${seq}` } });
      case "agent-refuse": return json(res, 200, { decision: { effect: "refuse", decisionId, rationale: "No rule grants this." } });
      default: return json(res, 200, { decision: { effect: "grant", decisionId } });
    }
  }
  return json(res, 400, { error: "unknown operation" });
}

function sign({ agent, action, body = "", expiresInSeconds = 300, keyId = KEY_ID }) {
  const decisionId = `dec-offline-${++seq}`;
  const expiresAt = new Date(Date.now() + expiresInSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
  const payloadHash = crypto.createHash("sha256").update(body).digest("hex");
  const message = ["acr-grant-v3", WORKSPACE, keyId, decisionId, agent, action, payloadHash, expiresAt, "", decisionId, "0"].join("|");
  const signature = crypto.sign(null, Buffer.from(message), privateKey).toString("base64url");
  return { "X-Acr-Key-Id": keyId, "X-Acr-Decision-Id": decisionId, "X-Acr-Expires-At": expiresAt, "X-Acr-Public-Signature": signature };
}

http.createServer(async (req, res) => {
  const body = await read(req);
  const url = new URL(req.url, "http://mock");
  if (url.pathname === "/acr") return acr(req, res, body);
  if (url.pathname.startsWith("/upstream")) {
    calls.upstream.push({ path: url.pathname + url.search, headers: req.headers, body: body.toString() });
    return json(res, Number(url.searchParams.get("status") || 200), { ok: true });
  }
  if (url.pathname === "/_calls") return json(res, 200, calls);
  if (url.pathname === "/_reset") { calls = { acr: [], upstream: [] }; return json(res, 200, {}); }
  if (url.pathname === "/_sign") return json(res, 200, sign(JSON.parse(body.toString())));
  if (url.pathname === "/_health") return json(res, 200, { ok: true });
  json(res, 404, {});
}).listen(9000, () => console.log("mock ACR + upstream on :9000"));
