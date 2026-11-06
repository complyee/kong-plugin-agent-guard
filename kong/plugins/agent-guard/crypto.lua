-- One-way fingerprints and time helpers. The request body is hashed here, in
-- the gateway; only the hash is ever sent to Agent Control Room.
local resty_sha256 = require "resty.sha256"
local str = require "resty.string"

local _M = {}

function _M.payload_hash()
  local body = kong.request.get_raw_body() or ""
  local h = resty_sha256:new()
  h:update(body)
  return str.to_hex(h:final())  -- only this hash is sent, never the body
end

function _M.sha256_hex(text)
  local h = resty_sha256:new()
  h:update(text)
  return str.to_hex(h:final())
end

-- expiresAt is UTC ("2030-01-02T03:04:05Z"); returns epoch seconds or nil.
function _M.utc_epoch(iso)
  local y, mo, d, hh, mi, ss = tostring(iso or ""):match("^(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)")
  if not y then return nil end
  return os.time({ year = y, month = mo, day = d, hour = hh, min = mi, sec = ss })
    - os.difftime(os.time(), os.time(os.date("!*t")))
end

return _M
