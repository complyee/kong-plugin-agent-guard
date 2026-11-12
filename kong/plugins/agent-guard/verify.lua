-- Check a grant locally against the published Ed25519 key, with no call back.
-- A local check cannot see a revocation: call verifyDecision where a grant
-- revoked before expiry must be caught.
local pkey = require "resty.openssl.pkey"
local b64 = require "ngx.base64"
local crypto = require "kong.plugins.agent-guard.crypto"
local request = require "kong.plugins.agent-guard.request"
local keys = require "kong.plugins.agent-guard.keys"

local _M = {}

local SPKI_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"

local function load_ed25519_key(raw_b64)
  local raw_bytes = b64.decode_base64url(raw_b64)
  if not raw_bytes or #raw_bytes ~= 32 then
    return nil, "invalid Ed25519 raw public key length"
  end

  -- Primary: SubjectPublicKeyInfo DER (RFC 8410). Supported across all OpenSSL versions via d2i_PUBKEY.
  local spki_der = SPKI_PREFIX .. raw_bytes
  local key = pkey.new(spki_der, { format = "DER" })
  if key then return key end

  -- Fallback 1: lua-resty-openssl params table
  key = pkey.new({ type = "Ed25519", params = { public = raw_bytes } })
  if key then return key end

  -- Fallback 2: JWK format
  local jwk = string.format('{"kty":"OKP","crv":"Ed25519","x":"%s"}', raw_b64)
  key = pkey.new(jwk, { format = "JWK" })
  if key then return key end

  return nil, "cannot parse Ed25519 public key"
end

function _M.verify_grant(conf)
  local h = kong.request.get_header
  local key_id, decision_id = h("X-Acr-Key-Id"), h("X-Acr-Decision-Id")
  local expires_at, sig = h("X-Acr-Expires-At"), h("X-Acr-Public-Signature")
  -- acr-grant-v3 signs agent, action and lineage too. Agent and action come
  -- from this request, so a grant for another agent or route fails.
  -- A root grant has no parent, root = its own decisionId and depth 0.
  local agent = request.resolve_agent(conf) or ""
  local action = request.resolve_action(conf) or ""
  local parent_id = h("X-Acr-Parent-Decision-Id") or ""
  local root_id = h("X-Acr-Root-Decision-Id") or decision_id
  local depth = h("X-Acr-Delegation-Depth") or "0"
  if not (key_id and decision_id and expires_at and sig) then return false end
  if agent == "" or action == "" then return false end  -- unknown agent or unmapped route: refuse
  local hash = crypto.payload_hash()
  if not hash then return false end

  local ks = keys.get_keys(conf, key_id)
  local raw = ks and ks.keys[key_id]
  if not raw then return false end  -- unknown key or failed fetch: refuse

  local exp = crypto.utc_epoch(expires_at)
  if not exp then return false end
  if ngx.time() >= exp then return false end  -- expired: refuse

  local message = table.concat({ "acr-grant-v3", ks.workspaceId, key_id,
    decision_id, agent, action,
    hash, expires_at,  -- Kong's own body hash
    parent_id, root_id, depth }, "|")

  local key, key_err = load_ed25519_key(raw)
  if not key then
    kong.log.warn("failed to load grant verification key: ", key_err)
    return false
  end

  local sig_bytes = b64.decode_base64url(sig)
  if not sig_bytes then
    kong.log.warn("failed to decode grant signature for decision ", decision_id)
    return false
  end

  local ok, err = key:verify(sig_bytes, message)
  if not ok then
    kong.log.warn("grant signature verification failed for decision ", decision_id, ": ", err)
  end
  return ok == true
end

return _M
