-- One helper for the gateway: every operation goes through the same address.
local http = require "resty.http"
local cjson = require "cjson.safe"

local _M = {}

function _M.acr_call(conf, operation, parameters, idem_key)
  local client = http.new()
  client:set_timeout(conf.timeout_ms)
  local res, err = client:request_uri(conf.gateway_url, {
    method = "POST",
    body = cjson.encode({ operation = operation, parameters = parameters }),
    headers = {
      ["content-type"] = "application/json",
      ["x-api-key"] = conf.api_key,  -- resolved from the vault by Kong
      ["idempotency-key"] = idem_key,
    },
  })
  if not res then return nil, err end
  -- Never log response bodies: they may contain sensitive upstream diagnostics.
  if type(res.status) ~= "number" or res.status < 200 or res.status >= 300 then
    return nil, "HTTP " .. tostring(res.status or "unknown")
  end
  local answer = cjson.decode(res.body)
  if type(answer) ~= "table" then return nil, "Invalid JSON response" end
  if answer.error then return nil, "ACR application error" end
  return answer
end

return _M
