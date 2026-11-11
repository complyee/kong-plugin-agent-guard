local typedefs = require "kong.db.schema.typedefs"

return {
  name = "agent-guard",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = { type = "record", fields = {
      -- https://<workspace>.agent-cr.com/api/public/v1/gateway
      { gateway_url = { type = "string", required = true } },
      -- A Kong vault reference such as {vault://env/acr-api-key}, never the key itself
      { api_key = { type = "string", required = true, referenceable = true, encrypted = true } },
      { agent_header = { type = "string", default = "X-Agent-Id" } },
      { agent_source = { type = "string", default = "header", one_of = { "header", "consumer", "jwt_claim" } } },
      { consumer_id_field = { type = "string", default = "custom_id", one_of = { "custom_id", "id" } } },
      { agent_claim = { type = "string", default = "sub" } },
      { action_header = { type = "string", default = "X-Acr-Action" } },
      { allow_action_header = { type = "boolean", default = false } },
      -- "POST /payments/transfers" = "payments.transfer.create"
      { action_map = { type = "map", keys = { type = "string" }, values = { type = "string" }, default = {} } },
      { timeout_ms = { type = "integer", default = 3000 } },
      -- decide:     ask Agent Control Room before Kong forwards (default)
      -- verify:     check a grant the request already carries, offline (Ed25519)
      -- verify_jwt: bind a grant JWT to this request, after a JWT plugin
      --             verified its signature against the published key set
      { mode = { type = "string", default = "decide", one_of = { "decide", "verify", "verify_jwt" } } },
      -- How long the published verification keys are cached, in seconds
      { keys_ttl = { type = "integer", default = 3600 } },
    } } },
  },
}
