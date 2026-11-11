-- Dependency-free test suite for kong-plugin-agent-guard.
-- Mocks the Kong and OpenResty APIs; runs on plain LuaJIT:  luajit spec/run.lua
package.path = "./?.lua;" .. package.path

----------------------------------------------------------------------
-- Pure-Lua SHA-256 (LuaJIT bit library) — stands in for resty.sha256
----------------------------------------------------------------------
local bit = require "bit"
local band, bxor, bnot = bit.band, bit.bxor, bit.bnot
local rshift, ror = bit.rshift, bit.ror

local K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function sha256_bin(msg)
  local len = #msg
  msg = msg .. "\128" .. string.rep("\0", (55 - len) % 64)
  local bits = len * 8
  msg = msg .. "\0\0\0\0"  -- high 32 bits of the 64-bit length (always 0 here)
  for i = 3, 0, -1 do
    msg = msg .. string.char(band(rshift(bits, i * 8), 0xff))
  end
  local h = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
  local w = {}
  for chunk = 1, #msg, 64 do
    for i = 0, 15 do
      local a, b, c, d = msg:byte(chunk + i * 4, chunk + i * 4 + 3)
      w[i] = a * 0x1000000 + b * 0x10000 + c * 0x100 + d
    end
    for i = 16, 63 do
      local s0 = bxor(ror(w[i - 15], 7), ror(w[i - 15], 18), rshift(w[i - 15], 3))
      local s1 = bxor(ror(w[i - 2], 17), ror(w[i - 2], 19), rshift(w[i - 2], 10))
      w[i] = band(w[i - 16] + s0 + w[i - 7] + s1, 0xffffffff)
    end
    local a, b, c, d, e, f, g, hh = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]
    for i = 0, 63 do
      local S1 = bxor(ror(e, 6), ror(e, 11), ror(e, 25))
      local ch = bxor(band(e, f), band(bnot(e), g))
      local t1 = band(hh + S1 + ch + K[i + 1] + w[i], 0xffffffff)
      local S0 = bxor(ror(a, 2), ror(a, 13), ror(a, 22))
      local maj = bxor(band(a, b), band(a, c), band(b, c))
      local t2 = band(S0 + maj, 0xffffffff)
      hh, g, f, e, d, c, b, a = g, f, e, band(d + t1, 0xffffffff), c, b, a, band(t1 + t2, 0xffffffff)
    end
    h[1] = band(h[1] + a, 0xffffffff); h[2] = band(h[2] + b, 0xffffffff)
    h[3] = band(h[3] + c, 0xffffffff); h[4] = band(h[4] + d, 0xffffffff)
    h[5] = band(h[5] + e, 0xffffffff); h[6] = band(h[6] + f, 0xffffffff)
    h[7] = band(h[7] + g, 0xffffffff); h[8] = band(h[8] + hh, 0xffffffff)
  end
  local out = {}
  for i = 1, 8 do
    out[#out + 1] = string.char(
      band(rshift(h[i], 24), 0xff), band(rshift(h[i], 16), 0xff),
      band(rshift(h[i], 8), 0xff), band(h[i], 0xff))
  end
  return table.concat(out)
end

local function to_hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function sha256_hex(s) return to_hex(sha256_bin(s)) end

----------------------------------------------------------------------
-- Minimal JSON encode/decode — stands in for cjson.safe
----------------------------------------------------------------------
local function json_encode(v)
  local t = type(v)
  if t == "string" then return '"' .. v:gsub('["\\]', "\\%0") .. '"'
  elseif t == "number" then return tostring(v)
  elseif t == "boolean" then return tostring(v)
  elseif t == "table" then
    if #v > 0 then  -- array-like
      local parts = {}
      for i = 1, #v do parts[i] = json_encode(v[i]) end
      return "[" .. table.concat(parts, ",") .. "]"
    end
    local parts = {}
    for k, val in pairs(v) do parts[#parts + 1] = json_encode(tostring(k)) .. ":" .. json_encode(val) end
    return "{" .. table.concat(parts, ",") .. "}"
  end
  return "null"
end

local function json_decode(s)
  local pos = 1
  local function skip_ws()
    local _, e = s:find("^[ \n\r\t]*", pos)
    pos = (e or 0) + 1
  end
  local parse_value
  local function parse_string()
    local i = pos + 1
    local buf = {}
    while true do
      local c = s:sub(i, i)
      if c == "" then error("json: unterminated string") end
      if c == '"' then pos = i + 1 return table.concat(buf) end
      if c == "\\" then
        local n = s:sub(i + 1, i + 1)
        local map = { ['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f", n = "\n", r = "\r", t = "\t" }
        if n == "u" then
          buf[#buf + 1] = string.char(tonumber(s:sub(i + 2, i + 5), 16) % 256)
          i = i + 6
        else
          buf[#buf + 1] = map[n] or n
          i = i + 2
        end
      else
        buf[#buf + 1] = c
        i = i + 1
      end
    end
  end
  local function parse_object()
    pos = pos + 1
    local obj = {}
    skip_ws()
    if s:sub(pos, pos) == "}" then pos = pos + 1 return obj end
    while true do
      skip_ws()
      local k = parse_string()
      skip_ws()
      pos = pos + 1 -- ":"
      obj[k] = parse_value()
      skip_ws()
      local c = s:sub(pos, pos)
      pos = pos + 1
      if c == "}" then return obj end
    end
  end
  local function parse_array()
    pos = pos + 1
    local arr = {}
    skip_ws()
    if s:sub(pos, pos) == "]" then pos = pos + 1 return arr end
    while true do
      arr[#arr + 1] = parse_value()
      skip_ws()
      local c = s:sub(pos, pos)
      pos = pos + 1
      if c == "]" then return arr end
    end
  end
  function parse_value()
    skip_ws()
    local c = s:sub(pos, pos)
    if c == '"' then return parse_string()
    elseif c == "{" then return parse_object()
    elseif c == "[" then return parse_array()
    elseif c == "t" then pos = pos + 4 return true
    elseif c == "f" then pos = pos + 5 return false
    elseif c == "n" then pos = pos + 4 return nil
    else
      local num = s:match("^%-?%d+%.?%d*[eE]?[+-]?%d*", pos)
      pos = pos + #num
      return tonumber(num)
    end
  end
  return parse_value()
end

----------------------------------------------------------------------
-- base64url decode — stands in for ngx.base64
----------------------------------------------------------------------
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
local function b64url_decode(data)
  return (data:gsub(".", function(x)
    if x == "=" then return "" end
    local r, f = "", (B64:find(x, 1, true) - 1)
    for i = 6, 1, -1 do r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and "1" or "0") end
    return r
  end):gsub("%d%d%d?%d?%d?%d?%d?%d?", function(x)
    if #x ~= 8 then return "" end
    local c = 0
    for i = 1, 8 do c = c + (x:sub(i, i) == "1" and 2 ^ (8 - i) or 0) end
    return string.char(c)
  end))
end

local function b64url_encode(data)
  return ((data:gsub(".", function(x)
    local r, b = "", x:byte()
    for i = 8, 1, -1 do r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and "1" or "0") end
    return r
  end) .. "0000"):gsub("%d%d%d?%d?%d?%d?", function(x)
    if #x < 6 then return "" end
    local c = 0
    for i = 1, 6 do c = c + (x:sub(i, i) == "1" and 2 ^ (6 - i) or 0) end
    return B64:sub(c + 1, c + 1)
  end) .. ({ "", "==", "=" })[#data % 3 + 1]):gsub("%=", "")
end

----------------------------------------------------------------------
-- Mocks for resty.* / ngx / kong
----------------------------------------------------------------------
local state -- per-test mutable state, reset by setup()

package.preload["resty.sha256"] = function()
  return { new = function()
    return {
      update = function(self, s) self._buf = (self._buf or "") .. s end,
      final = function(self) return sha256_bin(self._buf or "") end,
    }
  end }
end
package.preload["resty.string"] = function() return { to_hex = to_hex } end
package.preload["cjson.safe"] = function()
  return { encode = json_encode, decode = function(body)
    local success, value = pcall(json_decode, body)
    if not success then return nil, "Invalid JSON" end
    return value
  end }
end
package.preload["resty.http"] = function()
  return { new = function()
    return {
      set_timeout = function() end,
      request_uri = function(_, _, options)
        state.http_calls = (state.http_calls or 0) + 1
        state.last_http_request = options
        if state.http_err then return nil, state.http_err end
        return { status = state.http_status or 200, body = state.http_raw_body or json_encode(state.http_body or {}) }
      end,
    }
  end }
end
package.preload["resty.openssl.pkey"] = function()
  return { new = function()
    return { verify = function(_, sig, message)
      state.verify_message = message
      state.verify_sig = sig
      return state.verify_result
    end }
  end }
end
package.preload["ngx.base64"] = function()
  return { decode_base64url = b64url_decode }
end
package.preload["kong.db.schema.typedefs"] = function()
  return { protocols_http = {} }
end

local ExitSentinel = {}

local function setup(opts)
  opts = opts or {}
  state = {
    headers = opts.headers or {},
    method = opts.method or "POST",
    path = opts.path or "/payments/transfers",
    body = opts.body or "",
    body_missing = opts.body_missing,
    body_err = opts.body_err,
    path_with_query = opts.path_with_query,
    consumer = opts.consumer,
    shared = opts.shared or {},
    status = opts.status or 200,
    http_body = opts.http_body,
    http_err = opts.http_err,
    http_status = opts.http_status,
    http_raw_body = opts.http_raw_body,
    timer_err = opts.timer_err,
    logs = { err = {}, warn = {} },
    verify_result = opts.verify_result,
    verify_message = nil,
    exited = nil,
    upstream_headers = {},
    timers = {},
    cache = {},
    now = opts.now or os.time(),
  }
  _G.ngx = {
    md5 = sha256_hex,
    time = function() return state.now end,
    timer = { at = function(_, fn, ...)
      if state.timer_err then return nil, state.timer_err end
      state.timers[#state.timers + 1] = { fn = fn, args = { ... } }
      return true
    end },
  }
  _G.kong = {
    request = {
      get_header = function(name) return state.headers[name] end,
      get_method = function() return state.method end,
      get_path = function() return state.path end,
      get_path_with_query = function() return state.path_with_query or state.path end,
      get_raw_body = function()
        if state.body_missing then return nil, state.body_err end
        return state.body, state.body_err
      end,
    },
    response = {
      exit = function(status, body)
        state.exited = { status = status, body = body }
        error(ExitSentinel)
      end,
      get_status = function() return state.status end,
    },
    service = { request = {
      set_header = function(name, value) state.upstream_headers[name] = value end,
    } },
    ctx = { plugin = {}, shared = state.shared },
    client = { get_consumer = function() return state.consumer end },
    log = {
      err = function(...) state.logs.err[#state.logs.err + 1] = table.concat({ ... }) end,
      warn = function(...) state.logs.warn[#state.logs.warn + 1] = table.concat({ ... }) end,
    },
    cache = {
      get = function(_, key, _, loader, conf)
        if state.cache[key] == nil then state.cache[key] = loader(conf) end
        return state.cache[key]
      end,
      invalidate = function(_, key) state.cache[key] = nil end,
    },
  }
end

----------------------------------------------------------------------
-- Tiny harness
----------------------------------------------------------------------
local passed, failed = 0, 0
local function ok(cond, name)
  if cond then
    passed = passed + 1
    print("ok   - " .. name)
  else
    failed = failed + 1
    print("FAIL - " .. name)
  end
end

local function run_access(conf)
  local handler = require "kong.plugins.agent-guard.handler"
  local ok_call, err = pcall(handler.access, handler, conf)
  if not ok_call and err ~= ExitSentinel then error(err) end
end

local function base_conf(over)
  local conf = {
    gateway_url = "https://ws.agent-cr.com/api/public/v1/gateway",
    api_key = "resolved-by-vault",
    agent_header = "X-Agent-Id",
    agent_source = "header",
    consumer_id_field = "custom_id",
    agent_claim = "sub",
    allow_action_header = false,
    action_header = "X-Acr-Action",
    action_map = { ["POST /payments/transfers"] = "payments.transfer.create" },
    timeout_ms = 3000,
    mode = "decide",
    keys_ttl = 3600,
  }
  for k, v in pairs(over or {}) do conf[k] = v end
  return conf
end

----------------------------------------------------------------------
-- 1. SHA-256 conformance (validates the mock against known vectors)
----------------------------------------------------------------------
ok(sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "sha256 empty-string vector")
ok(sha256_hex("hello world") == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
  "sha256 hello-world vector")

----------------------------------------------------------------------
-- 2. crypto
----------------------------------------------------------------------
local crypto = require "kong.plugins.agent-guard.crypto"
setup({ body = "hello world" })
ok(crypto.payload_hash() == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
  "payload_hash fingerprints the body")
setup({ body = nil })
ok(crypto.payload_hash() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "payload_hash of a missing body is the empty hash")
ok(crypto.utc_epoch("2030-01-02T03:04:05Z") ==
   os.time({ year = 2030, month = 1, day = 2, hour = 3, min = 4, sec = 5 })
     - os.difftime(os.time(), os.time(os.date("!*t"))),
  "utc_epoch parses UTC expiresAt")
ok(crypto.utc_epoch("not-a-date") == nil, "utc_epoch refuses a bad date")

----------------------------------------------------------------------
-- 3. schema defaults
----------------------------------------------------------------------
local schema = require "kong.plugins.agent-guard.schema"
local fields = {}
for _, f in ipairs(schema.fields[2].config.fields) do
  local name = next(f)
  fields[name] = f[name]
end
ok(fields.mode and fields.mode.default == "decide", "schema: mode defaults to decide")
ok(fields.timeout_ms and fields.timeout_ms.default == 3000, "schema: timeout defaults to 3000 ms")
ok(fields.keys_ttl and fields.keys_ttl.default == 3600, "schema: keys cache defaults to 3600 s")
ok(fields.allow_action_header and fields.allow_action_header.default == false,
  "schema: client action headers disabled by default")
ok(fields.agent_source and fields.agent_source.default == "header"
  and table.concat(fields.agent_source.one_of, ",") == "header,consumer,jwt_claim",
  "schema: explicit identity sources with compatibility header default")
ok(fields.consumer_id_field and fields.consumer_id_field.default == "custom_id",
  "schema: Consumer identity defaults to custom_id")
ok(fields.agent_claim and fields.agent_claim.default == "sub",
  "schema: verified identity claim defaults to sub")
ok(fields.api_key and fields.api_key.referenceable == true and fields.api_key.encrypted == true,
  "schema: api_key is a vault reference, never plain text")

----------------------------------------------------------------------
-- 4. request.resolve_action
----------------------------------------------------------------------
local request = require "kong.plugins.agent-guard.request"
setup({ headers = { ["X-Acr-Action"] = "payments.refund.create" } })
ok(request.resolve_action(base_conf()) == "payments.transfer.create", "resolve_action: route map overrides a conflicting header")
setup({})
ok(request.resolve_action(base_conf()) == "payments.transfer.create", "resolve_action: action map fallback")
setup({ path = "/unmapped" })
ok(request.resolve_action(base_conf()) == nil, "resolve_action: nil when nothing matches")
setup({ path = "/unmapped", headers = { ["X-Acr-Action"] = "payments.refund.create" } })
ok(request.resolve_action(base_conf()) == nil, "resolve_action: unmapped header refused by default")
ok(request.resolve_action(base_conf({ allow_action_header = true })) == "payments.refund.create",
  "resolve_action: unmapped header requires explicit opt-in")
setup({ headers = { ["X-Acr-Action"] = "payments.refund.create" } })
ok(request.resolve_action(base_conf({ allow_action_header = true })) == "payments.transfer.create",
  "resolve_action: opt-in never overrides a mapped route")

setup({ consumer = { id = "consumer-uuid", custom_id = "settlement-agent" },
  headers = { ["X-Agent-Id"] = "spoofed-agent" } })
ok(request.resolve_agent(base_conf({ agent_source = "consumer" })) == "settlement-agent",
  "identity: Consumer custom_id overrides spoofed header")
ok(request.resolve_agent(base_conf({ agent_source = "consumer", consumer_id_field = "id" })) == "consumer-uuid",
  "identity: explicit Consumer id selection")
setup({ consumer = { id = "consumer-uuid" }, headers = { ["X-Agent-Id"] = "spoofed-agent" } })
ok(request.resolve_agent(base_conf({ agent_source = "consumer" })) == nil,
  "identity: missing custom_id does not fall back to id or header")
setup({ headers = { ["X-Agent-Id"] = "spoofed-agent" },
  shared = { jwt_claims = { sub = "unverified-agent" } } })
ok(request.resolve_agent(base_conf({ agent_source = "jwt_claim" })) == nil,
  "identity: arbitrary decoded JWT claims are not the verified adapter contract")
setup({ headers = { ["X-Agent-Id"] = "spoofed-agent" }, shared = {
  acr_verified_identity = { claims = { sub = "jwt-agent", client_id = "client-agent" } } } })
ok(request.resolve_agent(base_conf({ agent_source = "jwt_claim" })) == "jwt-agent",
  "identity: verified adapter sub overrides spoofed header")
ok(request.resolve_agent(base_conf({ agent_source = "jwt_claim", agent_claim = "client_id" })) == "client-agent",
  "identity: explicit verified claim selection")
ok(request.resolve_agent(base_conf({ agent_source = "jwt_claim", agent_claim = "absent" })) == nil,
  "identity: absent verified claim has no header fallback")
setup({ headers = { ["X-Agent-Id"] = "agent|injected" } })
ok(request.resolve_agent(base_conf()) == nil, "identity: grant field separator is refused")

----------------------------------------------------------------------
-- 5. decide mode
----------------------------------------------------------------------
setup({ headers = { ["X-Agent-Id"] = "agent-1" }, body = '{"amount":100}',
        http_body = { decision = { effect = "grant", decisionId = "dec-1" } } })
run_access(base_conf())
ok(state.exited == nil, "decide grant: request is forwarded")
ok(state.upstream_headers["X-Acr-Decision-Id"] == "dec-1", "decide grant: decision id reaches the upstream")
ok(kong.ctx.plugin.decision and kong.ctx.plugin.decision.payloadHash == crypto.payload_hash(),
  "decide grant: Kong's own body hash is stashed for the outcome report")

setup({ headers = { ["X-Agent-Id"] = "agent-1" },
        http_body = { decision = { effect = "reject", rationale = "amount too high" } } })
run_access(base_conf())
ok(state.exited and state.exited.status == 403 and state.exited.body.rationale == "amount too high",
  "decide refuse: 403 with the rationale")

setup({ headers = { ["X-Agent-Id"] = "agent-1" },
        http_body = { decision = { effect = "pending", approvalId = "ap-9" } } })
run_access(base_conf())
ok(state.exited and state.exited.status == 202 and state.exited.body.approvalId == "ap-9",
  "decide pending: 202 once with the approval id")

setup({ headers = { ["X-Agent-Id"] = "agent-1" }, http_err = "connection refused" })
run_access(base_conf())
ok(state.exited and state.exited.status == 503, "decide unreachable: 503, fail closed")

setup({ headers = { ["X-Agent-Id"] = "agent-1" }, path = "/unmapped" })
run_access(base_conf())
ok(state.exited and state.exited.status == 403, "decide unmapped route: 403")

setup({ headers = { ["X-Agent-Id"] = "spoofed-agent" } })
run_access(base_conf({ agent_source = "consumer" }))
ok(state.exited and state.exited.status == 403 and (state.http_calls or 0) == 0,
  "decide: absent authenticated Consumer refuses before ACR call")
setup({ headers = { ["X-Agent-Id"] = "spoofed-agent", Authorization = "Bearer unverified" } })
run_access(base_conf({ agent_source = "jwt_claim" }))
ok(state.exited and state.exited.status == 403 and (state.http_calls or 0) == 0,
  "decide: bearer token alone cannot supply verified identity")
setup({ consumer = { custom_id = "settlement-agent" },
  headers = { ["X-Agent-Id"] = "spoofed-agent", ["X-Acr-Action"] = "read_audit_log" },
  path_with_query = "/payments/transfers?account=123", body = '{"amount":100}',
  http_body = { decision = { effect = "grant", decisionId = "dec-query" } } })
run_access(base_conf({ agent_source = "consumer" }))
local submitted = json_decode(state.last_http_request.body).parameters
ok(state.exited == nil and submitted.agent == "settlement-agent" and submitted.action == "payments.transfer.create",
  "decide: ACR receives authenticated identity and route action despite spoofed headers")
ok(submitted.resourceRef == "/payments/transfers?account=123",
  "decide: resourceRef includes the query string")
for _, headers in ipairs({ {}, { ["Content-Length"] = "100" }, { ["Transfer-Encoding"] = "chunked" } }) do
  headers["X-Agent-Id"] = "agent-1"
  setup({ headers = headers, body_missing = true, body_err = "buffered to file" })
  run_access(base_conf())
  ok(state.exited and state.exited.status == 400 and (state.http_calls or 0) == 0,
    "decide: unreadable body refuses before authorization regardless of framing headers")
end
setup({ headers = { ["X-Agent-Id"] = "agent-1" }, body_missing = true })
run_access(base_conf())
ok(state.exited and state.exited.status == 400 and (state.http_calls or 0) == 0,
  "decide: nil body without an error is not treated as empty")
setup({ headers = { ["X-Agent-Id"] = "agent-1" }, body = "", body_err = "read failed" })
run_access(base_conf())
ok(state.exited and state.exited.status == 400 and (state.http_calls or 0) == 0,
  "decide: body read error refuses even with a string result")

----------------------------------------------------------------------
-- 6. verify mode (offline Ed25519 check)
----------------------------------------------------------------------
local KEYS_BODY = { verificationKeys = {
  workspaceId = "ws-1",
  keys = { { keyId = "key-1", publicKey = b64url_encode("0123456789abcdef0123456789abcdef") } },
} }
local VERIFY_HEADERS = {
  ["X-Agent-Id"] = "agent-1",
  ["X-Acr-Key-Id"] = "key-1",
  ["X-Acr-Decision-Id"] = "dec-1",
  ["X-Acr-Expires-At"] = "2030-01-02T03:04:05Z",
  ["X-Acr-Public-Signature"] = b64url_encode("a-signature"),
}

setup({ headers = VERIFY_HEADERS, body = "hello world", http_body = KEYS_BODY, verify_result = true })
run_access(base_conf({ mode = "verify" }))
local want_message = table.concat({ "acr-grant-v3", "ws-1", "key-1", "dec-1", "agent-1",
  "payments.transfer.create", sha256_hex("hello world"), "2030-01-02T03:04:05Z", "", "dec-1", "0" }, "|")
ok(state.exited == nil and state.verify_message == want_message,
  "verify: acr-grant-v3 message rebuilt in the exact signed field order")

setup({ headers = VERIFY_HEADERS, body = "hello world", http_body = KEYS_BODY, verify_result = true })
run_access(base_conf({ mode = "verify" }))
ok(state.exited == nil, "verify: a valid grant forwards")

setup({ headers = VERIFY_HEADERS, body = "tampered body", http_body = KEYS_BODY, verify_result = false })
run_access(base_conf({ mode = "verify" }))
ok(state.exited and state.exited.status == 403, "verify: a failed signature refuses")

setup({ headers = { ["X-Agent-Id"] = "agent-1" }, http_body = KEYS_BODY })
run_access(base_conf({ mode = "verify" }))
ok(state.exited and state.exited.status == 403, "verify: missing grant headers refuse")

local past = os.date("!%Y-%m-%dT%H:%M:%SZ", os.time() - 60)
local expired = {}
for k, v in pairs(VERIFY_HEADERS) do expired[k] = v end
expired["X-Acr-Expires-At"] = past
setup({ headers = expired, http_body = KEYS_BODY, verify_result = true })
run_access(base_conf({ mode = "verify" }))
ok(state.exited and state.exited.status == 403, "verify: an expired grant refuses")

local unknown_key = {}
for k, v in pairs(VERIFY_HEADERS) do unknown_key[k] = v end
unknown_key["X-Acr-Key-Id"] = "key-2"
setup({ headers = unknown_key, http_body = KEYS_BODY, verify_result = true })
run_access(base_conf({ mode = "verify" }))
ok(state.exited and state.exited.status == 403, "verify: an unknown key refuses after one refetch")

setup({ headers = VERIFY_HEADERS, path = "/unmapped", http_body = KEYS_BODY, verify_result = true })
run_access(base_conf({ mode = "verify" }))
ok(state.exited and state.exited.status == 403, "verify: an unmapped route refuses")
setup({ headers = VERIFY_HEADERS, body_missing = true, body_err = "buffered to file", http_body = KEYS_BODY, verify_result = true })
run_access(base_conf({ mode = "verify" }))
ok(state.exited and state.exited.status == 403 and (state.http_calls or 0) == 0,
  "verify: unreadable body refuses before key lookup or signature verification")
setup({ headers = VERIFY_HEADERS, consumer = { custom_id = "agent-1" }, body = "hello world", http_body = KEYS_BODY, verify_result = true })
run_access(base_conf({ mode = "verify", agent_source = "consumer" }))
ok(state.exited == nil and state.verify_message == want_message,
  "verify: signature reconstruction uses authenticated Consumer identity")
setup({ headers = VERIFY_HEADERS, body = "hello world", http_body = KEYS_BODY, verify_result = true })
run_access(base_conf({ mode = "verify", agent_source = "consumer" }))
ok(state.exited and state.exited.status == 403,
  "verify: missing Consumer cannot fall back to a client header")
local spoofed_verify = {}
for k, v in pairs(VERIFY_HEADERS) do spoofed_verify[k] = v end
spoofed_verify["X-Acr-Action"] = "read_audit_log"
setup({ headers = spoofed_verify, body = "hello world", http_body = KEYS_BODY, verify_result = true })
run_access(base_conf({ mode = "verify" }))
ok(state.exited == nil and state.verify_message == want_message,
  "verify: spoofed action header cannot change the signed route action")

----------------------------------------------------------------------
-- 7. verify_jwt mode (binding after a JWT plugin verified the token)
----------------------------------------------------------------------
local function grant_jwt(claims)
  return b64url_encode('{"alg":"EdDSA"}') .. "." .. b64url_encode(json_encode(claims)) .. ".sig"
end
local GOOD_CLAIMS = {
  sub = "agent-1",
  acr = { action = "payments.transfer.create", payloadHash = sha256_hex("hello world") },
}

setup({ headers = { ["X-Agent-Id"] = "agent-1", Authorization = "Bearer " .. grant_jwt(GOOD_CLAIMS) },
        body = "hello world" })
run_access(base_conf({ mode = "verify_jwt" }))
ok(state.exited == nil, "verify_jwt: a token bound to this agent, action and body forwards")

local wrong_action = { sub = "agent-1", acr = { action = "payments.refund.create",
  payloadHash = sha256_hex("hello world") } }
setup({ headers = { ["X-Agent-Id"] = "agent-1", Authorization = "Bearer " .. grant_jwt(wrong_action) },
        body = "hello world" })
run_access(base_conf({ mode = "verify_jwt" }))
ok(state.exited and state.exited.status == 403, "verify_jwt: a token for another action refuses")

local wrong_body = { sub = "agent-1", acr = { action = "payments.transfer.create",
  payloadHash = sha256_hex("other body") } }
setup({ headers = { ["X-Agent-Id"] = "agent-1", Authorization = "Bearer " .. grant_jwt(wrong_body) },
        body = "hello world" })
run_access(base_conf({ mode = "verify_jwt" }))
ok(state.exited and state.exited.status == 403, "verify_jwt: a token for another body refuses")

setup({ headers = { ["X-Agent-Id"] = "agent-1" }, body = "hello world" })
run_access(base_conf({ mode = "verify_jwt" }))
ok(state.exited and state.exited.status == 403, "verify_jwt: no bearer token refuses")
setup({ headers = { ["X-Agent-Id"] = "agent-1", Authorization = "Bearer " .. grant_jwt(GOOD_CLAIMS) }, body_missing = true })
run_access(base_conf({ mode = "verify_jwt" }))
ok(state.exited and state.exited.status == 403, "verify_jwt: unreadable body cannot match a grant")
setup({ headers = { ["X-Agent-Id"] = "spoofed-agent", Authorization = "Bearer " .. grant_jwt(GOOD_CLAIMS) },
  shared = { acr_verified_identity = { claims = { sub = "agent-1" } } }, body = "hello world" })
run_access(base_conf({ mode = "verify_jwt", agent_source = "jwt_claim" }))
ok(state.exited == nil, "verify_jwt: binding uses identity from the verified adapter")
setup({ headers = { ["X-Agent-Id"] = "agent-1", Authorization = "Bearer " .. grant_jwt(GOOD_CLAIMS) }, body = "hello world" })
run_access(base_conf({ mode = "verify_jwt", agent_source = "jwt_claim" }))
ok(state.exited and state.exited.status == 403, "verify_jwt: decoded grant claims do not authenticate the caller")
setup({ headers = { ["X-Agent-Id"] = "agent-1", ["X-Acr-Action"] = "read_audit_log",
  Authorization = "Bearer " .. grant_jwt(GOOD_CLAIMS) }, body = "hello world" })
run_access(base_conf({ mode = "verify_jwt" }))
ok(state.exited == nil, "verify_jwt: spoofed action header cannot change the bound route action")

----------------------------------------------------------------------
-- 8. log phase: outcome reporting
----------------------------------------------------------------------
local handler = require "kong.plugins.agent-guard.handler"
setup({ status = 200 })
kong.ctx.plugin.decision = { decisionId = "dec-1", payloadHash = "h" }
handler.log(handler, base_conf())
ok(#state.timers == 1, "log: one background report is scheduled")
state.timers[1].fn(false, unpack(state.timers[1].args))
local first_report = json_decode(state.last_http_request.body).parameters
ok(first_report.decisionId == "dec-1" and first_report.payloadHash == "h"
  and first_report.outcome == "executed" and first_report.detailCode == "http_200",
  "log: report preserves binding and HTTP detail")

setup({ status = 502 })
kong.ctx.plugin.decision = { decisionId = "dec-1", payloadHash = "h" }
handler.log(handler, base_conf())
ok(#state.timers == 1, "log: a 5xx upstream answer still schedules one report")

setup({ status = 200 })
handler.log(handler, base_conf())
ok(#state.timers == 0, "log: no stashed decision means no report")

setup({ status = 200 })
kong.ctx.plugin.decision = { decisionId = "dec-1", payloadHash = "h" }
handler.log(handler, base_conf())
state.timers[1].fn(true, unpack(state.timers[1].args))
ok((state.http_calls or 0) == 0, "log: premature timer sends no outcome report")

setup({ status = 200, http_err = "connection refused" })
kong.ctx.plugin.decision = { decisionId = "dec-1", payloadHash = "h" }
handler.log(handler, base_conf())
state.timers[1].fn(false, unpack(state.timers[1].args))
ok(state.http_calls == 1 and #state.timers == 1,
  "log: failed outcome delivery is attempted once without retry")

setup({ status = 403 })
kong.ctx.plugin.decision = { decisionId = "dec-1", payloadHash = "h" }
handler.log(handler, base_conf())
state.timers[1].fn(false, unpack(state.timers[1].args))
local reported = json_decode(state.last_http_request.body)
ok(reported.parameters.outcome == "aborted" and reported.parameters.detailCode == "http_403",
  "log: upstream 403 is aborted, not executed")

setup({ status = 502 })
kong.ctx.plugin.decision = { decisionId = "dec-1", payloadHash = "h" }
handler.log(handler, base_conf())
state.timers[1].fn(false, unpack(state.timers[1].args))
reported = json_decode(state.last_http_request.body)
ok(reported.parameters.outcome == "downstream_error",
  "log: 5xx is reported as downstream_error, not proof of no side effect")

-- Theme B regressions
for _, case in ipairs({
  { 201, "executed", "http_201" }, { 202, "executed", "http_202_accepted" },
  { 204, "executed", "http_204" }, { 400, "aborted", "http_400" },
  { 409, "aborted", "http_409" }, { 422, "aborted", "http_422" },
  { 500, "downstream_error", "http_500" }, { 504, "downstream_error", "http_504" },
  { 302, "aborted", "http_302" },
}) do
  setup({ status = case[1] })
  kong.ctx.plugin.decision = { decisionId = "dec-status", payloadHash = "h" }
  handler:log(base_conf())
  state.timers[1].fn(false, unpack(state.timers[1].args))
  local params = json_decode(state.last_http_request.body).parameters
  ok(params.outcome == case[2] and params.detailCode == case[3], "log: HTTP " .. case[1] .. " mapping")
end
setup({ timer_err = "too many pending timers" })
kong.ctx.plugin.decision = { decisionId = "dec-schedule", payloadHash = "h" }
handler:log(base_conf())
ok(#state.timers == 0 and (state.http_calls or 0) == 0 and #state.logs.err == 1
  and state.logs.err[1]:find("dec%-schedule") and state.logs.err[1]:find("too many pending timers"),
  "log: scheduling failure logs decision and cause without retry")
setup({})
kong.ctx.plugin.decision = { decisionId = "dec-shutdown", payloadHash = "h" }
handler:log(base_conf())
state.timers[1].fn(true, unpack(state.timers[1].args))
ok((state.http_calls or 0) == 0 and #state.logs.warn == 1 and state.logs.warn[1]:find("dec%-shutdown"),
  "log: premature shutdown logs decision without sending")
for _, status in ipairs({ 301, 401, 409, 422, 500 }) do
  setup({ http_status = status, http_body = { diagnostic = "sensitive-response-body" } })
  kong.ctx.plugin.decision = { decisionId = "dec-http", payloadHash = "h" }
  handler:log(base_conf())
  state.timers[1].fn(false, unpack(state.timers[1].args))
  local warning = state.logs.warn[1] or ""
  ok(state.http_calls == 1 and #state.timers == 1 and warning:find("dec%-http")
    and warning:find("HTTP " .. status) and not warning:find("sensitive%-response%-body")
    and not warning:find("resolved%-by%-vault"), "log: HTTP " .. status .. " rejected safely without retry")
end
setup({ headers = { ["X-Agent-Id"] = "agent-1" }, http_status = 500,
  http_body = { decision = { effect = "grant", decisionId = "invalid" } } })
run_access(base_conf())
ok(state.exited and state.exited.status == 503 and kong.ctx.plugin.decision == nil,
  "decide: non-2xx grant-shaped answer fails closed")
setup({ http_body = { error = { message = "sensitive-error-message" } } })
kong.ctx.plugin.decision = { decisionId = "dec-app", payloadHash = "h" }
handler:log(base_conf())
state.timers[1].fn(false, unpack(state.timers[1].args))
ok(#state.logs.warn == 1 and state.logs.warn[1]:find("ACR application error")
  and not state.logs.warn[1]:find("sensitive%-error%-message"), "log: application error rejected safely")
setup({ headers = { ["X-Agent-Id"] = "agent-1" }, http_body = { decision = { effect = "pending", approvalId = "ap-hold" } } })
run_access(base_conf())
handler:log(base_conf())
ok(state.exited and state.exited.status == 202 and #state.timers == 0 and state.http_calls == 1,
  "log: policy-hold 202 never reports upstream acceptance")
for _, mode in ipairs({ "verify", "verify_jwt" }) do
  setup({})
  kong.ctx.plugin.decision = { decisionId = "dec-offline", payloadHash = "h" }
  handler:log(base_conf({ mode = mode }))
  ok(#state.timers == 0 and (state.http_calls or 0) == 0, "log: " .. mode .. " never schedules reports")
end

setup({ http_raw_body = "not JSON" })
kong.ctx.plugin.decision = { decisionId = "dec-decode", payloadHash = "h" }
handler:log(base_conf())
state.timers[1].fn(false, unpack(state.timers[1].args))
ok(#state.logs.warn == 1 and state.logs.warn[1]:find("Invalid JSON response"),
  "log: malformed acknowledgement fails safely")
setup({ http_err = "timeout" })
kong.ctx.plugin.decision = { decisionId = "dec-timeout", payloadHash = "h" }
handler:log(base_conf())
state.timers[1].fn(false, unpack(state.timers[1].args))
ok(state.http_calls == 1 and #state.logs.warn == 1 and state.logs.warn[1]:find("dec%-timeout")
  and state.logs.warn[1]:find("timeout"), "log: network failure logs decision and cause")
setup({ http_status = 201, http_body = { execution = { outcome = "executed" } } })
kong.ctx.plugin.decision = { decisionId = "dec-ack", payloadHash = "h" }
handler:log(base_conf())
state.timers[1].fn(false, unpack(state.timers[1].args))
ok(state.http_calls == 1 and #state.logs.warn == 0, "log: valid 2xx acknowledgement does not warn")

----------------------------------------------------------------------
print(("---\n%d passed, %d failed"):format(passed, failed))
if failed > 0 then os.exit(1) end
