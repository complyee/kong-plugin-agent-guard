-- Runs AFTER your JWT plugin has verified the token (give this plugin a lower
-- PRIORITY). That plugin checks signature, kid, alg EdDSA, iss
-- https://agent-cr.com, aud and exp against the JWK Set. This step checks the
-- token is for THIS request — the JWT plugin cannot.
-- Never trust the decoded claims unless the JWT plugin ran first and verified
-- the signature.
local cjson = require "cjson.safe"
local b64 = require "ngx.base64"
local crypto = require "kong.plugins.agent-guard.crypto"
local request = require "kong.plugins.agent-guard.request"

local _M = {}

function _M.bind_grant_jwt(conf)
  local auth = kong.request.get_header("Authorization") or ""
  local token = auth:match("^Bearer%s+(.+)$")
  if not token then return false end
  local seg = token:match("^[^.]+%.([^.]+)%.[^.]+$")
  local claims = seg and cjson.decode(b64.decode_base64url(seg) or "")
  if type(claims) ~= "table" or type(claims.acr) ~= "table" then return false end

  local agent = kong.request.get_header(conf.agent_header) or ""
  local action = request.resolve_action(conf) or ""
  if agent == "" or action == "" then return false end  -- unknown agent or unmapped route: refuse

  return claims.sub == agent
    and claims.acr.action == action
    and claims.acr.payloadHash == crypto.payload_hash()  -- Kong's own body hash
end

return _M
