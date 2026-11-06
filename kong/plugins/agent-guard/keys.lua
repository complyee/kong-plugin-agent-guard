-- Fetch the public grant-verification keys once and cache them.
-- getGrantVerificationKey needs the policy.read scope.
local client = require "kong.plugins.agent-guard.client"

local _M = {}

local function load_keys(conf)
  local answer, err = client.acr_call(conf, "getGrantVerificationKey", {}, nil)
  if not answer or not answer.verificationKeys then return nil, err end
  local by_id = {}
  for _, k in ipairs(answer.verificationKeys.keys or {}) do
    by_id[k.keyId] = k.publicKey  -- base64url, raw 32-byte Ed25519 key
  end
  return { workspaceId = answer.verificationKeys.workspaceId, keys = by_id }
end

function _M.get_keys(conf, key_id)
  local cache_key = "acr-keys:" .. conf.gateway_url
  local ttl = conf.keys_ttl or 3600
  local ks = kong.cache:get(cache_key, { ttl = ttl }, load_keys, conf)
  if ks and key_id and not ks.keys[key_id] then
    kong.cache:invalidate(cache_key)  -- unknown keyId: a rotation; refetch once
    ks = kong.cache:get(cache_key, { ttl = ttl }, load_keys, conf)
  end
  return ks
end

return _M
