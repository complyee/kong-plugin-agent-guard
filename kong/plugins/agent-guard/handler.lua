-- Agent Control Room enforcement point for Kong Gateway.
-- Modes (config.mode):
--   decide (default): ask Agent Control Room before Kong forwards.
--   verify:           check a grant the request already carries, offline (Ed25519).
--   verify_jwt:       bind a grant JWT to this request, after a JWT plugin
--                     verified its signature against the published key set.
local cjson = require "cjson.safe"
local client = require "kong.plugins.agent-guard.client"
local crypto = require "kong.plugins.agent-guard.crypto"
local request = require "kong.plugins.agent-guard.request"

local AgentGuardHandler = { PRIORITY = 900, VERSION = "0.1.0" }

local function decide_access(conf)
  local action = request.resolve_action(conf)
  if not action then
    return kong.response.exit(403, { message = "No governed action mapped for this route." })
  end
  local agent = request.resolve_agent(conf)
  if not agent then
    return kong.response.exit(403, { message = "Missing or invalid agent identity." })
  end
  local hash, hash_err = crypto.payload_hash()
  if not hash then
    return kong.response.exit(400, { message = hash_err })
  end
  local params = {
    agent = agent,
    action = action,
    resourceRef = kong.request.get_path_with_query(),
    payloadHash = hash,
  }
  local idem = "kong-" .. ngx.md5(cjson.encode(params))
  local answer, err = client.acr_call(conf, "decideAction", params, idem)
  if not answer then
    kong.log.err("ACR unreachable: ", err)
    return kong.response.exit(503, { message = "Not forwarded: no decision." })  -- fail closed
  end
  local d = answer.decision or {}
  if d.effect == "grant" then
    kong.ctx.plugin.decision = { decisionId = d.decisionId, payloadHash = hash }  -- the hash Kong computed
    kong.service.request.set_header("X-Acr-Decision-Id", d.decisionId)
    return  -- forward to the upstream service
  end
  if d.effect == "pending" then
    -- Held for a person. Return once; the caller polls getApprovalStatus. No loop here.
    return kong.response.exit(202, { message = "Held for review.", approvalId = d.approvalId or answer.approvalId })
  end
  return kong.response.exit(403, { message = "Refused.", rationale = d.rationale })
end

function AgentGuardHandler:access(conf)
  if conf.mode == "verify" then
    -- Required lazily: an install without lua-resty-openssl can still run decide mode.
    local verify = require "kong.plugins.agent-guard.verify"
    if not verify.verify_grant(conf) then
      return kong.response.exit(403, { message = "Grant check failed." })
    end
    return
  end
  if conf.mode == "verify_jwt" then
    local jwt_bind = require "kong.plugins.agent-guard.jwt_bind"
    if not jwt_bind.bind_grant_jwt(conf) then
      return kong.response.exit(403, { message = "Grant token is not bound to this request." })
    end
    return
  end
  return decide_access(conf)
end

local function report(premature, conf, decision, outcome, detail_code)
  if premature then
    kong.log.warn("reportExecutionOutcome dropped on worker shutdown for decision ", decision.decisionId)
    return
  end
  local _, err = client.acr_call(conf, "reportExecutionOutcome", {
    decisionId = decision.decisionId,
    payloadHash = decision.payloadHash,
    outcome = outcome,
    detailCode = detail_code,
  }, "outcome-" .. decision.decisionId)
  if err then
    kong.log.warn("reportExecutionOutcome failed for decision ", decision.decisionId, ": ", err)
  end  -- evidence only; no retries and no change to the response
end

function AgentGuardHandler:log(conf)
  -- Offline verification never schedules outcome reports, even with shared state.
  if conf.mode == "verify" or conf.mode == "verify_jwt" then return end
  local decision = kong.ctx.plugin.decision
  if not decision then return end
  local status = kong.response.get_status()
  local outcome = "aborted"
  if status >= 200 and status < 300 then
    outcome = "executed"
  elseif status >= 500 then
    outcome = "downstream_error"
  end
  local detail_code = status == 202 and "http_202_accepted" or "http_" .. tostring(status)
  local scheduled, err = ngx.timer.at(0, report, conf, decision, outcome, detail_code)
  if not scheduled then
    kong.log.err("reportExecutionOutcome scheduling failed for decision ", decision.decisionId, ": ", err)
  end
end

return AgentGuardHandler
