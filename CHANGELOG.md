# Changelog

## 0.1.0

- First release: `agent-guard` plugin for Kong Gateway 3.x.
- `decide` mode: asks Agent Control Room before Kong forwards; grant forwards with the decision id, refusal returns 403, a hold returns 202 once, no answer returns 503 (fail closed).
- `verify` mode: offline `acr-grant-v3` Ed25519 grant check against the published key set, with cached keys and one refetch on rotation.
- `verify_jwt` mode: binds a grant JWT to the request's agent, action and body hash after a JWT plugin verified the signature against the public JWK Set.
- Outcome reporting (`executed` / `downstream_error`) on a background timer; evidence only, never delays the response.
