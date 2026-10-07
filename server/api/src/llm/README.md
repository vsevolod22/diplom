# TASK13: server-only OpenRouter summaries

**Production integration is off by default. No live model has been invoked or deployed for acceptance.** This module registers real Nest routes and a real OpenRouter HTTP adapter, not simulated success. Tests use explicitly fake settings/providers/HTTP transports. TASK14 chat, TASK15 cumulative budget/cost UI and TASK16 cache are not implemented here.

## Cookie HTTP contract

- `GET /api/v1/browser/scans/:scanId/llm/context`: authorized owner only; returns digest/platform, server `reportVersion`, `policyVersion`, policy disclosure and `enabled`. `enabled` means non-secret policy is ready, not that the key/provider/live deployment is ready. It never inspects the key.
- `POST .../llm/summary`: Origin/JSON/1024-byte body gate, cookie identity and server-derived `scan:read`. The **only** DTO is `{reportVersion, consent: {accepted: true, policyVersion}}`. Consent is request-scoped: no global consent record, chat history or stored summary. A fresh request requires applicable consent for the current report/policy. Cancellation/disconnect invalidates the request. Client prompt/context/findings/model/URLs are rejected.
- Both successful responses and LLM error responses are `no-store`. A URL-scoped global exception filter is needed because Express JSON/size errors occur before controller filters; it hides raw body excerpts without changing private JWT route behavior.

The cookie helper retains the existing account allowlist/local-demo, bearer rejection, cross-site and Origin gates. Private JWT scopes are not expanded. Owner authorization precedes policy/key errors. Missing key or incomplete policy returns `LLM_CONFIGURATION_UNAVAILABLE`, not fake AI output.

## Report and publication boundary

Only terminal current owner reports are summarized. The reader validates projections and consumes **every** Secrets/CVE/SBOM page, checking counts, cursor progress and duplicate IDs. Config/source subcoverage, failed/unsupported checks and unknown DB/OS/node provenance remain explicit. All findings (including late-page critical) must fit; overflow refuses before egress, never truncates. Model data contains bounded identifiers, enum/numeric evidence and coverage; free text, package/version strings, advisory URLs, credentials, env and raw output are excluded. No evidence URL is fetched.

A separate **read-only** SQLite handle reads owner-bound attempt/scope/terminal metadata and fences projections with `data_version`; any intervening commit, including an unrelated write, conservatively invalidates the snapshot. No schema/migration change. `reportVersion` hashes canonical bounded full authoritative projections, owner, target and attempt locally; only the hash and sanitized context leave the API. The context is deeply frozen. Access/session/read scope, policy and the complete report are rechecked immediately before the call and after awaiting it. Stale/removed/revoked results are discarded; an already started call cannot be retrospectively called zero-egress.

Replies are strict bounded JSON/plain text. Citation membership is checked only against this sent report and scan/digest/platform/version. Unknown IDs, tuple changes, tools, unsafe text and incomplete responses fail safely. Citations prove a source exists, **not** the inference: every model interpretation is labeled `hypothesis`; `scannerFacts` are server projections. No result writes.

## Required operator decisions — all production values UNDECIDED

No dotenv/file loading is performed. Supply approved settings to the **API process only**, not the worker, browser or shared env mount. Do not enable before three independent reviews, an approved model/price/data-processing decision and a separately authorized live validation. Existing Compose/egress rules are not changed by this implementation. Merely setting variables is not live integration acceptance.

| Environment names | Required decision / safety ceiling (not defaults) |
| --- | --- |
| `LLM_ENABLED` | Only exact `true` enables; unset/other values are off |
| `OPENROUTER_API_KEY` | Private API environment only, inspected after auth/consent; never printed or loaded from files by this module |
| `LLM_MODEL` | Exact approved vendor/model identifier; no fallback, `openrouter/auto` or routing/tool modifiers. Documentation placeholder: `<approved-vendor>/<approved-model>` — intentionally not runnable |
| `LLM_PROVIDER_ALLOWLIST`, `LLM_ROUTING_APPROVED` | Explicit provider names and operator approval of supported routing/parameters/prices; no fallback routing |
| `LLM_POLICY_REVISION` | Explicit revision; policy hash also changes with any setting |
| `LLM_REGION` | Only `global` (no regional restriction) is supported; `eu`/`us` fail closed because this API has no enforceable regional selector |
| `LLM_RETENTION` | Explicit `no-training` or `no-storage`; request enforces `data_collection: deny`, plus `zdr: true` for no-storage. Declarations/operator approval do not prove provider compliance |
| `LLM_REQUEST_BUDGET_USD`, `LLM_INPUT_PRICE_PER_MILLION_USD`, `LLM_OUTPUT_PRICE_PER_MILLION_USD` | Explicit positive per-request cap and approved maximum token prices; ceilings $1/request and $1000/million tokens. Provider price caps plus conservative request-byte token bound checked before fetch; not a cumulative quota |
| `LLM_TIMEOUT_MS`, `LLM_REQUEST_BYTES`, `LLM_RESPONSE_BYTES` | Required positive finite values; ceilings 30000 ms / 262144 / 65536 bytes |
| `LLM_MAX_FINDINGS`, `LLM_OUTPUT_TOKENS` | Required positive integers; ceilings 1000 / 2048 |

The fixed endpoint is `https://openrouter.ai/api/v1/chat/completions`, default TLS verification, fixed JSON/Bearer headers, redirects forbidden, no endpoint override/tools/retries. Timeout covers fetch and streamed body reads; declared and actual response bytes are bounded. One active request per owner, at most eight globally. Response token usage/truncation and model identity are checked. Unprovable budget/routing/retention requirements must remain disabled, not inferred from a model name.

## Focused verification

From `server/api/`:

```sh
pnpm exec tsx --test src/llm/tests/llm.http.test.ts src/llm/tests/openrouter-provider.test.ts
pnpm run typecheck
```

Local Nest HTTP, real cookie/AuthStore and trusted ledger fixture projections are tested with a fake model. The actual production provider factory/adapter uses injected mock fetch only. No external model call, full regression suite, UI build, deploy or production configuration change belongs to this verification.
