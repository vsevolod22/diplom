# TASK13: server-only OpenRouter summaries

**Production integration is off by default. A bounded synthetic host probe reached OpenRouter but returned HTTP404; no successful live model summary is accepted.** The API and summary UI were deployed on the LOCAL stand with the model disabled on 2026-10-08. This module registers real Nest routes and a real OpenRouter HTTP adapter, not simulated success. Tests use explicitly fake settings/providers/HTTP transports. TASK14 context/cache, TASK15 cumulative budget/cost UI and TASK16 streaming chat are not implemented here.

## Cookie HTTP contract

- `GET /api/v1/browser/scans/:scanId/llm/context`: authorized owner only; returns digest/platform, server `reportVersion`, `policyVersion`, policy disclosure and `enabled`. `enabled` means non-secret policy is ready, not that the key/provider/live deployment is ready. It never inspects the key.
- `POST .../llm/summary`: Origin/JSON/1024-byte body gate, cookie identity and server-derived `scan:read`. The **only** DTO is `{reportVersion, consent: {accepted: true, policyVersion}}`. Consent is request-scoped: no global consent record, chat history or stored summary. A fresh request requires applicable consent for the current report/policy. Cancellation/disconnect invalidates the request. Client prompt/context/findings/model/URLs are rejected.
- Both successful responses and LLM error responses are `no-store`, including case-insensitive and optional-trailing-slash router aliases for both LLM boundaries. A URL-scoped global exception filter is needed because Express JSON/size errors occur before controller filters; it hides raw body excerpts without changing unrelated API errors/private JWT route behavior. Encoded static route segments are not decoded by the actual Express router or this filter.

The cookie helper retains the existing account allowlist/local-demo, bearer rejection, cross-site and Origin gates. Private JWT scopes are not expanded. Owner authorization precedes policy/key errors. Missing key or incomplete policy returns `LLM_CONFIGURATION_UNAVAILABLE`, not fake AI output.

## Report and publication boundary

Only terminal current owner reports are summarized. The reader validates projections and consumes **every** Secrets/CVE/SBOM page, checking counts, cursor progress and duplicate IDs. Config/source subcoverage, failed/unsupported checks and unknown DB/OS/node provenance remain explicit. All findings (including late-page critical) must fit; overflow refuses before egress, never truncates. Model data contains bounded identifiers, enum/numeric evidence and coverage; free text, package/version strings, advisory URLs, credentials, env and raw output are excluded. No evidence URL is fetched.

A separate **read-only** SQLite handle reads owner-bound attempt/scope/terminal metadata and fences projections with `data_version`; any intervening commit, including an unrelated write, conservatively invalidates the snapshot. No schema/migration change. `reportVersion` hashes canonical bounded full authoritative projections, owner, target and attempt locally; only the hash and sanitized context leave the API. The context is deeply frozen. Access/session/read scope, policy and the complete report are rechecked immediately before the call and after awaiting it. Stale/removed/revoked results are discarded; an already started call cannot be retrospectively called zero-egress.

Zero-findings requests return the safe local `409 LLM_NO_EVIDENCE` refusal before provider/key lookup or egress, after the normal owner/consent/policy/freshness checks. No generated text, citations or fake AI success is returned. This applies to verified zero findings and incomplete/unknown coverage alike; missing/failed coverage does not become a checked zero or a clean-scan claim. Scanner reports remain available separately.

Replies are strict bounded JSON/plain text. Citation membership is checked only against this sent report and scan/digest/platform/version. Unknown IDs, tuple changes, tools, unsafe text and incomplete responses fail safely. Citations prove a source exists, **not** the inference: every model interpretation is labeled `hypothesis`; `scannerFacts` are server projections. No result writes.

## Required operator decisions — production default-off

No dotenv/file loading is performed. Supply approved settings to the **API process only**, not the worker, browser or shared env mount. Do not enable before three independent reviews, an approved model/price/data-processing decision and a separately authorized live validation. TASK37 adds the fixed opt-in LOCAL overlay and dedicated API-only gateway described below; default Compose/worker egress stay unchanged. Merely setting variables is not live integration acceptance.

| Environment names | Required decision / safety ceiling (not defaults) |
| --- | --- |
| `LLM_ENABLED` | Only exact `true` enables; unset/other values are off |
| `OPENROUTER_API_KEY` | Private API environment only, inspected after auth/consent; never printed or loaded from files by this module |
| `LLM_MODEL` | Exact approved vendor/model identifier; no fallback, `openrouter/auto`, `openrouter/free` or routing/tool modifiers. The only accepted `:free` request is the explicit verified free profile below |
| `LLM_PROVIDER_ALLOWLIST`, `LLM_ROUTING_APPROVED` | Explicit provider names and operator approval of supported routing/parameters/prices; no fallback routing |
| `LLM_POLICY_REVISION` | Explicit revision; policy hash also changes with any setting |
| `LLM_REGION` | Only `global` (no regional restriction) is supported; `eu`/`us` fail closed because this API has no enforceable regional selector |
| `LLM_RETENTION` | Explicit `no-training` or `no-storage`; request enforces `data_collection: deny`, plus `zdr: true` for no-storage. Declarations/operator approval do not prove provider compliance |
| `LLM_REQUEST_BUDGET_USD`, `LLM_INPUT_PRICE_PER_MILLION_USD`, `LLM_OUTPUT_PRICE_PER_MILLION_USD` | Explicit positive token-price admission budget and approved maximum token prices; ceilings $1 estimated token cost/request and $1000/million tokens. Provider prompt/completion price caps plus conservative request-byte token estimate checked before fetch; not an actual-bill cap or cumulative quota |
| `LLM_TIMEOUT_MS`, `LLM_REQUEST_BYTES`, `LLM_RESPONSE_BYTES` | Required positive finite values; ceilings 30000 ms / 262144 / 65536 bytes |
| `LLM_MAX_FINDINGS`, `LLM_OUTPUT_TOKENS` | Required positive integers; ceilings 1000 / 2048 |

The fixed endpoint is `https://openrouter.ai/api/v1/chat/completions`, default TLS verification, fixed JSON/Bearer headers, redirects forbidden, no endpoint override/tools/retries. Production uses `openrouter-transport.ts`, not native fetch: fixed `llm-egress:8080` CONNECT → verified TLS with SNI `openrouter.ai` → fixed HTTPS POST. The gateway sees no Bearer credential. No ambient proxy, direct internet or fallback transport is used. Timeout covers fetch and streamed body reads; declared and actual response bytes are bounded. One active request per owner, at most eight globally. Response token usage/truncation and model identity are checked. The budget check estimates token charges only; provider minimum/per-request fees, other surcharges and actual billed amounts are not bounded or verified here. Before live activation, an operator must explicitly approve those fees and establish enforceable all-fee bounds (or leave unsupported pricing disabled); neither `max_price` nor `LLM_REQUEST_BUDGET_USD` guarantees a maximum actual bill. Legacy paid fee/model/budget/privacy choices remain UNDECIDED/default-off; the explicit TASK37 free profile does not authorize a paid call. TASK15 accounting is not implemented by this patch. Unprovable budget/routing/retention requirements must remain disabled, not inferred from a model name.

## TASK37 explicit free-only profile

Public catalog `https://openrouter.ai/api/v1/models/liquid/lfm-2.5-2.6b:free/endpoints`, checked 2026-10-07: exact model `liquid/lfm-2.5-2.6b:free`, Liquid endpoint `liquid/fp8`, prompt/completion prices `0`, supported `response_format`, `structured_outputs`, `reasoning` and `include_reasoning`. This is a dated catalog observation, **not** a successful live summary or proof of privacy/retention. Routing uses provider slug `liquid`, not a display name or arbitrary provider list.

- `LLM_FREE_ONLY=true` requires exactly that model/provider, explicit `LLM_REQUEST_BUDGET_USD=0`, `LLM_INPUT_PRICE_PER_MILLION_USD=0`, `LLM_OUTPUT_PRICE_PER_MILLION_USD=0` and `LLM_REQUEST_PRICE_USD=0`. Missing, positive or malformed caps refuse before egress. Only this profile admits `:free`; routers, modifiers, unknown free IDs and paid fallbacks remain forbidden.
- Wire request carries `max_price: {prompt:0, completion:0, request:0}`, `allow_fallbacks:false`, `require_parameters:true`, JSON output and supported `reasoning:{exclude:true}`. No `models` list, tools, automatic retry or model switch. A changed catalog, rate limit or unavailable provider fails closed, not over to paid service.
- Reply identity accepts only the exact requested ID or its fixed canonical base `liquid/lfm-2.5-2.6b`, and only under that verified free profile. This is not arbitrary suffix removal/date matching. Free replies additionally require reported `usage.cost===0`. A nonzero/missing cost is refused after the already-started call; it cannot retroactively prevent a charge. Model identity alone never proves zero billing.
- All current cookie/Origin/owner/current report/explicit consent/critical findings/citation/plain-text/publication fences remain in force. Unexpected reasoning fields/content still refuse; never loosen JSON/citations to make this model appear successful. A real synthetic parent probe may still show the candidate cannot meet the contract.
- New settings are part of the policy hash/disclosure; prior consent is stale. `global` plus an explicitly approved supported retention/routing policy remains mandatory; zero prices do not waive privacy consent or imply regional enforcement.

The LOCAL entrypoint registers `LlmController` and its providers directly in `NginxLocalModule`, using its single `NginxLocalScansService`. Do not import `LlmModule` there: it brings the default `ScansModule`, which would duplicate the scan controller/service graph and undermine LOCAL admission. The disposable actual-Nest `nginx-local-llm.http.test.ts` covers this wiring and unchanged qualifiers.

LOCAL injection/deploy is documented in `server/deploy/proof/openrouter-free.md`. No key/env file is loaded by application code; Compose `env_file` injects the private file into **API only**, outside images/browser/worker. The optional descriptor-selected overlay is default-off and preserves both bases, LOCAL entrypoints and refresh/rollback composition. The worker cannot reach `llm-egress` and its registry gateway does not allow OpenRouter.

## Focused verification

From `server/api/`:

```sh
pnpm exec tsx --test --test-concurrency=1 src/llm/tests/llm.http.test.ts src/llm/tests/openrouter-provider.test.ts src/llm/tests/free-policy.test.ts src/llm/tests/openrouter-transport.test.ts
pnpm run typecheck
```

Local Nest HTTP, real cookie/AuthStore and trusted ledger fixture projections are tested with a fake model. Provider wire tests use injected mock transports; the real CONNECT transport is also tested against loopback HTTPS with a disposable test-only CA and synthetic credentials, including untrusted-certificate refusal. No external model call, full regression suite, UI build, deploy or production configuration change belongs to this verification.
