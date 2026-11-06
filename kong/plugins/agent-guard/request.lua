-- Which governed action is this request?
local _M = {}

function _M.resolve_action(conf)
  local from_header = kong.request.get_header(conf.action_header)
  if from_header and from_header ~= "" then
    return from_header
  end
  local key = kong.request.get_method() .. " " .. kong.request.get_path()
  return conf.action_map[key]  -- nil when nothing matches
end

return _M
