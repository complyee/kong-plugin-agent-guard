# kong-plugin-agent-guard

Agent Control Room enforcement point for [Kong Gateway](https://konghq.com). The plugin asks Agent Control Room before Kong forwards an agent's request — or, when the request already carries a grant, checks it offline against the published Ed25519 key set. Kong routes, Agent Control Room decides, and your upstream service does the work.

- Full integration guide: https://agent-cr.com/plugins#kong-gateway
- API reference: https://agent-cr.com/api

## What it does

- **Asks before forwarding** (`mode = "decide"`, the default). Each request is mapped to a governed action, the request body is fingerprinted locally (SHA-256 — the body never leaves your network), and Agent Control Room answers grant, refuse or hold. A grant forwards the request with its decision id; a refusal returns 403; a hold returns 202 once with the approval id; no answer returns 503 — the request is not forwarded.
- **Checks a grant offline** (`mode = "verify"`). When the request already carries a grant — issued to your application or after an approval — Kong verifies the `acr-grant-v3` Ed25519 signature locally against the published key set, rebuilt with this request's agent, action and body hash, so a grant for one agent, route or payload cannot be reused for another.
- **Binds a grant JWT** (`mode = "verify_jwt"`). If your application asks for the grant as a JWT (`grantFormat: "jwt"`), a JWT plugin that reads the public key set at `https://agent-cr.com/.well-known/jwks.json` verifies the signature; this mode then binds the token to this agent, route and body.
- **Attempts to report the outcome in `decide` mode** after the upstream answers, using a non-blocking `ngx.timer.at` callback. This is best-effort evidence, not durable delivery or confirmation that a business transaction committed; see the reporting limitations below.
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
| `agent_source` | `header` | `header`, `consumer` or `jwt_claim`; applies in every mode. Header mode is for development or an authenticated trusted proxy that strips/overwrites caller headers, not public-client authentication. |
| `agent_header` | `X-Agent-Id` | Agent header used only in `header` mode. |
| `consumer_id_field` | `custom_id` | In `consumer` mode, use authenticated Kong Consumer `custom_id` or explicitly select `id`. Register that exact value as the ACR agent. No fallback. |
| `agent_claim` | `sub` | In `jwt_claim` mode, select a string claim from the verified server-side identity adapter described below. |
| `action_header` | `X-Acr-Action` | Used only on unmapped routes with explicit header opt-in. |
| `allow_action_header` | `false` | Allow an action header on an unmapped generic proxy route. Only enable behind a trusted action-selection boundary. Never overrides a mapped route. |
| `action_map` | `{}` | `"METHOD /path"` → action name; always authoritative over client headers. Query parameters do not change the map lookup. Unmapped requests refuse unless header opt-in is enabled. |
| `timeout_ms` | `3000` | Timeout for calls to Agent Control Room. |
| `mode` | `decide` | `decide`, `verify` or `verify_jwt` (see below). |
| `keys_ttl` | `3600` | How long the published verification keys are cached, in seconds. |

## Request authority and payload binding

For production, use `agent_source: consumer` with a preceding authentication plugin, or `jwt_claim` with a verified identity adapter. Missing identity, a missing selected Consumer field or a missing claim returns 403 without falling back to a caller header. Authentication must run before this plugin (priority 900); verify the actual order in your Kong deployment. Headers naming agents are not authentication.

`jwt_claim` does **not** decode a bearer token or assume Kong's JWT/OIDC plugins expose a common `jwt_claims` field. A trusted preceding authentication plugin/adapter must verify signature, allowed algorithm, issuer, audience and expiry, then publish this per-request server-side contract:

```lua
-- Set only after successful authentication. Never populate from request headers
-- or merely decoded JWT claims. Replace the selected claim with the verified value.
kong.ctx.shared.acr_verified_identity = { claims = verified_identity_claims }
```

The adapter is deployment-specific; it is not bundled. Configure its claim mapping and test it with the actual authentication plugin. Do not copy the ACR grant token's subject into this slot as a substitute for authenticating the caller. In `verify_jwt`, caller authentication and ACR grant-signature verification are separate requirements.

Kong hashes only a successfully read body. A genuinely absent or empty body is the empty string; a nil/error body read is refused (400 in `decide`, 403 in offline modes). Bodies buffered to disk are not read by this plugin: configure and test a bounded `client_body_buffer_size` and request-size limit appropriate to the route. No fallback hash is sent, and the request is not forwarded. Errors returned to clients do not expose temporary file paths.

In `decide`, `resourceRef` includes path and query; those query values are sent to ACR, so do not put secrets or raw business content in them. This is a policy input, **not** an addition to the `acr-grant-v3` signed message. Offline modes still bind agent, action and body only: do not use a grant on routes where query parameters alter the authorized work unless that work is also bound in the body or a distinct action. Test any downstream body/query rewrite against what Kong judged.

**Migration:** existing header-only action selection must add `action_map` entries or explicitly enable `allow_action_header` on a trusted generic proxy. Mapped routes now ignore conflicting action headers. This update does not add durable outcome reporting or exactly-once execution. Real Kong/authentication integration tests remain required before production rollout; the bundled tests use mocked APIs.

## Modes

### `decide` (default)

Ask Agent Control Room before Kong forwards. Responses:

| Decision | Kong answers | Forwarded? |
| --- | --- | --- |
| grant | upstream's response | yes, with `X-Acr-Decision-Id` |
| refuse | `403` with the rationale | no |
| pending (held for a person) | `202` once, with the approval id | no |
| no answer / unreachable | `503` | no |

### Approval, retries and execution idempotency

A `202` means policy has held the action for human review. Kong has not forwarded it, and it does not mean the upstream accepted or executed the work. The caller handles approval polling and resumption; the plugin does not wait or automatically resume. Refusal, pending approval and an unknown execution result are different states.

An ACR grant authorizes an agent, action and payload fingerprint; it is not an upstream transaction lock or an exactly-once guarantee. Side-effecting upstream services must enforce their own idempotency, for example with an `Idempotency-Key` or a unique business-operation reference. Keep that reference stable across retries and approval resumption, even if a new ACR decision is issued. Do not use a decision id as the sole business-operation key.

Track the logical operation reference, ACR decision/approval ids and individual request-attempt ids separately. The plugin's idempotency header on calls to ACR concerns those API calls only; it does not deduplicate upstream mutations. After a timeout, reconcile with the upstream operation record before retrying: the side effect may have happened even when its response was lost.

### Outcome reporting limitations

In `decide` mode, the `log` phase schedules one `ngx.timer.at(0, ...)` callback for a forwarded grant. There is no retry queue, durable spool or delivery guarantee across worker restarts. Scheduling failures log an error; premature shutdown callbacks and failed reports log warnings, all with the decision id. A hard worker crash can still lose a report without a warning. Non-2xx ACR replies, invalid JSON responses and application-error replies are treated as failures. Logs do not include HTTP response bodies or API keys. An HTTP acknowledgement is not a guarantee of business completion.

Reports classify the **proxy-observed HTTP response**, with `detailCode` preserving its status:

| Upstream status | Outcome | Detail code |
| --- | --- | --- |
| 2xx except 202 | `executed` | `http_<status>` |
| 202 | `executed` | `http_202_accepted` — accepted, not confirmed complete |
| 4xx | `aborted` | `http_<status>` |
| 5xx (including gateway timeout responses) | `downstream_error` | `http_<status>` |
| Other statuses (including redirects) | `aborted` | `http_<status>` |

An upstream 202 is different from the plugin's policy-hold 202: a policy hold is never forwarded and never schedules a report. Neither `executed` nor `aborted` proves whether a business side effect committed; a timeout or 5xx does not prove no side effect occurred. Do not treat `http_202_accepted` as final completion. ACR stores one outcome per decision, so a later different completion report for the same decision conflicts rather than replacing this observation; keep authoritative completion and reconciliation in the upstream operation record.

`verify` and `verify_jwt` never schedule outcome reports. They make no per-request decision/report call; `verify` still fetches verification keys on cache misses/rotation. Use the upstream service or orchestrator for durable completion reporting in offline architectures.

The online authorization decision is recorded during the ACR decision call independently of this timer. A missing outcome report means execution is unknown from this evidence, not refused, pending or necessarily unexecuted. For reliable business completion evidence, use the upstream service or orchestrator's durable operation record and an acknowledged reporting/reconciliation process.

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
- It does not provide upstream transaction deduplication; the upstream must enforce a stable business-operation idempotency key across retries and approval resumption.
- It does not guarantee execution-outcome delivery, exactly-once execution or business success from a gateway HTTP status.

## Development

The test suite mocks the Kong and OpenResty APIs and runs on plain LuaJIT:

```sh
luajit spec/run.lua
```

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Live integration tests

`spec/run.lua` checks the plugin logic with plain LuaJIT. `spec/integration/` starts a real Kong Gateway (DB-less, in Docker) with the plugin loaded, a stand-in Agent Control Room and a stand-in upstream, then sends real requests: grants, holds, refusals, timeouts, route-map authority, Consumer identity, offline Ed25519 grants and outcome reports.

```
docker compose -f spec/integration/docker-compose.yml up --abort-on-container-exit --exit-code-from tests
```

GitHub Actions runs the same command on every push (`.github/workflows/integration.yml`). The stand-in service is for testing only and never part of a deployment.
