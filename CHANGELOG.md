# Changelog

## 0.2.0 — 2026-11-12

- Fix: offline `verify` loads the Ed25519 key as SubjectPublicKeyInfo DER (with params/JWK fallbacks) and logs load/verify failures; confirmed by the live Kong 3.9 suite (19/19).

- Tests (Theme C): live integration suite (`spec/integration/`) runs a real Kong 3.9 in Docker against a stand-in ACR and upstream, covering decide, verify, Consumer identity and outcome reports; GitHub Actions workflow `integration.yml`.

- Outcome evidence (Theme B): 2xx → executed (202 marked http_202_accepted), 4xx/other statuses → aborted, 5xx/timeouts → downstream_error; every report carries its HTTP detailCode. These are proxy observations, not confirmed business completion.
- Log timer scheduling failures, premature shutdown callbacks and report failures with decision ids; still best-effort, without retries or durable storage.
- Reject non-2xx, invalid JSON and application-error ACR replies; never log response bodies or keys.
- Keep offline modes free of outcome-report timers; document upstream-owned completion/reconciliation and the one-outcome-per-decision boundary.

- Security (Theme A): route mappings always win; unmapped action headers require explicit `allow_action_header = true`. Existing header-only configurations must opt in or add route mappings.
- Security: shared agent resolution across all modes, with authenticated Consumer and verified-JWT adapter sources; no fallback to client headers for these sources.
- Security: body read errors refuse instead of hashing an empty string; online `resourceRef` includes the query string. Offline signatures still bind agent, action and body, not the query.

- Documentation: separate policy holds, execution attempts and unknown outcomes; require stable upstream business-operation idempotency across retries and approval resumption.
- Documentation: explain decide-only best-effort timer reports, no durable delivery, missing evidence, acknowledgement limitations and proxy-observed HTTP-status mapping.
- Tests: cover premature timers, failed delivery without retry, and HTTP outcome mapping.

## 0.1.0

- First release: `agent-guard` plugin for Kong Gateway 3.x.
- `decide` mode: asks Agent Control Room before Kong forwards; grant forwards with the decision id, refusal returns 403, a hold returns 202 once, no answer returns 503 (fail closed).
- `verify` mode: offline `acr-grant-v3` Ed25519 grant check against the published key set, with cached keys and one refetch on rotation.
- `verify_jwt` mode: binds a grant JWT to the request's agent, action and body hash after a JWT plugin verified the signature against the public JWK Set.
- Outcome reporting (`executed` / `downstream_error`) on a background timer; evidence only, never delays the response.
