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
  local hash = crypto.payload_hash()
  local params = {
    agent = kong.request.get_header(conf.agent_header),
    action = action,
    resourceRef = kong.request.get_path(),
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

local function report(premature, conf, decision, outcome)
  if premature then return end
  local _, err = client.acr_call(conf, "reportExecutionOutcome", {
    decisionId = decision.decisionId,
    payloadHash = decision.payloadHash,
    outcome = outcome,
  }, "outcome-" .. decision.decisionId)
  if err then kong.log.warn("reportExecutionOutcome failed: ", err) end  -- evidence only
end

function AgentGuardHandler:log(conf)
  local decision = kong.ctx.plugin.decision
  if not decision then return end
  local status = kong.response.get_status()
  local outcome = (status < 500) and "executed" or "downstream_error"
  ngx.timer.at(0, report, conf, decision, outcome)
end

return AgentGuardHandler
