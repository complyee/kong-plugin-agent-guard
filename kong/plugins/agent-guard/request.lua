-- Which governed action is this request?
local _M = {}

function _M.resolve_action(conf)
  local key = kong.request.get_method() .. " " .. kong.request.get_path()
  local mapped = (conf.action_map or {})[key]
  if mapped and mapped ~= "" then return mapped end
  if conf.allow_action_header then
    local from_header = kong.request.get_header(conf.action_header)
    if type(from_header) == "string" and from_header ~= "" then return from_header end
  end
  return nil
end

function _M.resolve_agent(conf)
  local source = conf.agent_source or "header"
  local agent
  if source == "consumer" then
    local consumer = kong.client.get_consumer()
    agent = consumer and consumer[conf.consumer_id_field or "custom_id"]
  elseif source == "jwt_claim" then
    -- Explicit server-side adapter contract, NOT a decoded bearer token.
    -- Only a preceding authentication plugin may populate this shared slot
    -- after verifying signature, allowed algorithm, issuer, audience and expiry.
    local identity = kong.ctx.shared.acr_verified_identity
    local claims = type(identity) == "table" and identity.claims
    agent = type(claims) == "table" and claims[conf.agent_claim or "sub"]
  elseif source == "header" then
    agent = kong.request.get_header(conf.agent_header)
  end
  if type(agent) ~= "string" or agent == "" or agent:find("|", 1, true) then return nil end
  return agent
end

return _M
