# kong-plugin-agent-guard

Agent Control Room enforcement point for [Kong Gateway](https://konghq.com). The plugin asks Agent Control Room before Kong forwards an agent's request — or, when the request already carries a grant, checks it offline against the published Ed25519 key set. Kong routes, Agent Control Room decides, and your upstream service does the work.

- Full integration guide: https://agent-cr.com/plugins#kong-gateway
- API reference: https://agent-cr.com/api

## What it does

- **Asks before forwarding** (`mode = "decide"`, the default). Each request is mapped to a governed action, the request body is fingerprinted locally (SHA-256 — the body never leaves your network), and Agent Control Room answers grant, refuse or hold. A grant forwards the request with its decision id; a refusal returns 403; a hold returns 202 once with the approval id; no answer returns 503 — the request is not forwarded.
- **Checks a grant offline** (`mode = "verify"`). When the request already carries a grant — issued to your application or after an approval — Kong verifies the `acr-grant-v3` Ed25519 signature locally against the published key set, rebuilt with this request's agent, action and body hash, so a grant for one agent, route or payload cannot be reused for another.
- **Binds a grant JWT** (`mode = "verify_jwt"`). If your application asks for the grant as a JWT (`grantFormat: "jwt"`), a JWT plugin that reads the public key set at `https://agent-cr.com/.well-known/jwks.json` verifies the signature; this mode then binds the token to this agent, route and body.
- **Reports the outcome** after the upstream answers, on a background timer that never delays the response. The report is evidence only.
- **Fails closed.** No answer, an unknown key, a missing header or a failed check always means the request is not forwarded.

## Requirements

- Kong Gateway 3.x (open source or Enterprise)
- An Agent Control Room workspace address: `https://<workspace>.agent-cr.com/api/public/v1/gateway`
- An API key with the `policy.decide` scope (plus `policy.read` for `verify` mode), held in a Kong vault or environment variable — never as plain text in plugin config
- The calling agents registered in your workspace, and rules for each mapped action

## Install

```sh
luarocks install kong-plugin-agent-guard
```

Then load the plugin, for example in `kong.conf`:

```
plugins = bundled,agent-guard
```

and restart Kong.

## Enable it on a route

Declarative (`kong.yml`):

```yaml
_format_version: "3.0"
services:
  - name: payments
    url: http://payments.internal:8080
    routes:
      - name: transfers
        paths: ["/payments/transfers"]
        plugins:
          - name: agent-guard
            config:
              gateway_url: https://<workspace>.agent-cr.com/api/public/v1/gateway
              api_key: "{vault://env/acr-api-key}"
              action_map:
                "POST /payments/transfers": payments.transfer.create
```

Or through the Admin API:

```sh
curl -X POST http://localhost:8001/services/payments/routes/transfers/plugins \
  --data name=agent-guard \
  --data config.gateway_url=https://<workspace>.agent-cr.com/api/public/v1/gateway \
  --data config.api_key='{vault://env/acr-api-key}' \
  --data 'config.action_map.POST /payments/transfers=payments.transfer.create'
```

## Configuration

| Parameter | Default | Description |
| --- | --- | --- |
| `gateway_url` | — (required) | Your workspace gateway address. |
| `api_key` | — (required) | A Kong vault reference such as `{vault://env/acr-api-key}`, never the key itself. |
| `agent_header` | `X-Agent-Id` | Request header naming the registered agent. |
| `action_header` | `X-Acr-Action` | Request header naming the governed action; wins over `action_map`. |
| `action_map` | `{}` | `"METHOD /path"` → action name. A request that matches nothing is refused. |
| `timeout_ms` | `3000` | Timeout for calls to Agent Control Room. |
| `mode` | `decide` | `decide`, `verify` or `verify_jwt` (see below). |
| `keys_ttl` | `3600` | How long the published verification keys are cached, in seconds. |

## Modes

### `decide` (default)

Ask Agent Control Room before Kong forwards. Responses:

| Decision | Kong answers | Forwarded? |
| --- | --- | --- |
| grant | upstream's response | yes, with `X-Acr-Decision-Id` |
| refuse | `403` with the rationale | no |
| pending (held for a person) | `202` once, with the approval id | no |
| no answer / unreachable | `503` | no |

### `verify`

Check a grant the request already carries, offline. The request must carry these headers:

- `X-Acr-Key-Id`, `X-Acr-Decision-Id`, `X-Acr-Expires-At`, `X-Acr-Public-Signature`
- `X-Acr-Parent-Decision-Id`, `X-Acr-Root-Decision-Id`, `X-Acr-Delegation-Depth` (delegated grants; a root grant omits them)

Keys are fetched once through `getGrantVerificationKey` and cached for `keys_ttl` seconds; an unknown key id triggers one refetch, which covers key rotation. A local check cannot see a revocation — call `verifyDecision` where a grant revoked before expiry must be caught.

### `verify_jwt`

Your application adds `grantFormat: "jwt"` to `decideAction` and sends `decision.grantJwt` as a bearer token. Point a JWT plugin that reads a JWKS URL — such as Kong's OpenID Connect plugin — at `https://agent-cr.com/.well-known/jwks.json`, allow only alg `EdDSA`, and require issuer `https://agent-cr.com` and your workspace address as audience. Give this plugin a lower priority so it runs after the JWT plugin: the JWT plugin proves Agent Control Room signed the token, and this mode proves it was signed for this agent, route and body. Check that your Kong edition's JWT plugin accepts EdDSA and a remote JWKS URL — the open-source `jwt` plugin uses per-consumer keys and does not, so there use `verify` mode instead.

## What it does not do

- It does not send request bodies to Agent Control Room; only a fingerprint.
- It never grants on its own. Only Agent Control Room's rules decide.
- It does not replace Kong's own authentication, rate limiting or routing.
- It does not wait in a loop on holds, and refuses when Agent Control Room cannot be reached.

## Development

The test suite mocks the Kong and OpenResty APIs and runs on plain LuaJIT:

```sh
luajit spec/run.lua
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
