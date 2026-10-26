# Public LLM source handoff — 2026-10-26

Source-only work from baseline `b867a52`. This is an investigation/qualification handoff, not a spec approval, deployment receipt or live AI acceptance. Changes are confined to this LLM directory and its tests. No authenticated provider attempt, runtime/Docker/credential access, key search, quota refund/reset, source-settings/script edit, MCP operation or commit was performed.

## Evidence and remaining blockers

Read the coordinator's `docs/public-finalization-20261026.md` and sanitized native evidence:

- `324479cf-07ee-4d99-983b-2be9d6c000eb`: chat's HTTP200 NDJSON error carries `LLM_PROVIDER_RATE_LIMITED`, upstream status429, `headers/http_error`, **no retry hint**. Translation's application HTTP502 carries `LLM_INVALID_RESPONSE`, `content/invalid_content`. The exact rejecting predicate is **UNKNOWN**. There is no retained response here from which to infer language, identifiers, formatting or fidelity.
- `29f3a78d-9455-4131-b29a-45aca5c2c657`: historical `finish/invalid_finish`; actual upstream finish value **UNKNOWN**. The new finite finish diagnostics cannot retroactively classify it.

The 324 translation error originates after provider JSON parsing in the local translation validator. In contrast, invalid provider JSON/message shape uses `LLM_PROVIDER_UNAVAILABLE`. This narrows the stage, not the predicate. Neither successful summary nor successful Russian chat/translation is established by this work. Provider429 remains an external availability/rate-limit blocker with no verified cause, retry interval or repair ETA.

### Unauthenticated official metadata only

Read `https://openrouter.ai/api/v1/models/xingchen-agi/xing4.0-29b-a4b:free/endpoints` on 2026-10-26. It lists this exact model and endpoint tag `phala`, zero prompt/completion prices, and `response_format`, `structured_outputs`, `reasoning`, `max_tokens`, `temperature` among supported parameters. This is **catalog capability metadata**, not account availability, enforcement, live generation, ZDR-compliance or invoice proof.

Official references used:

- `https://openrouter.ai/docs/guides/features/structured-outputs`: JSON-object mode promises JSON, not an application object shape. JSON-schema mode uses `json_schema: {name,strict,schema}`. Enforcement varies by endpoint; local validation remains essential.
- `https://openrouter.ai/docs/api/reference/overview`: nonstreaming assistant messages may include `tool_calls: ToolCall[]`. An empty array contains no tool call.

## Source findings and changes

1. **Reproducible request/parser gap, not an invented runtime cause:** all three old requests used `response_format:{type:'json_object'}` while parsers require different exact objects. Legal JSON such as a translation wrapper is not the parser's required `{title,description}`. The fixed public Xing/Phala profile now sends operation-specific `json_schema` with `strict:true`, every property required and `additionalProperties:false` at each object level. Translation fields have exactly the corresponding input's `string` or `null` type. No provider-response repair, unwrapping, coercion, markdown-fence stripping, plugin, downgrade or retry is added. Separate legacy/Apodex profiles retain JSON-object mode; there is no runtime fallback to them.
2. The adapter accepts the documented inert `tool_calls:[]`; malformed/null/nonempty calls still reject. Unknown message keys, nonnull reasoning/refusal, nonempty annotations, wrong role/content/model, non-stop finish and invalid usage still reject. No tool is requested or executed. This is not the cause of the historical post-parser translation error.
3. Translation now brands the **first local failing predicate** with finite response-header diagnostics. Null/type/limit, text guard, normalization, link, markup, identifier, Russian-script and unchanged-nonprose checks retain their rejection behavior. No source/reply text, token, regex match, exception message or arbitrary provider string is emitted. The service's generic fallback cannot overwrite the first cause.
4. Policy identity changes from response-language revision `russian-prose-v3-grounded` to `russian-prose-v4-structured`. Existing consent and prepared-context identities must be refreshed. This changes no mounted setting, report/source identity, stored history, quota liability, model/provider, output cap or privacy setting.

The Russian/grounding guard is **not loosened**. Controlled tests demonstrate that valid Russian prose containing an unrecognized source-bound technical name (for example `zlib`) can still fail the finite script guard despite the prompt's name-preservation instruction. Arbitrary source words cannot safely be exempted: doing so admits untranslated prose/instructions. This is a known fail-closed limitation, **not evidence that 324 contained that name or failed that predicate**. No new dictionary exception was guessed from the target image.

## Exact provider-facing contract

Single fixed `POST https://openrouter.ai/api/v1/chat/completions`, API-only Bearer credential, JSON request/response, redirects forbidden. No browser-side provider call. The stand's source settings remain readonly and unchanged: model `xingchen-agi/xing4.0-29b-a4b:free`, endpoint only `phala`, `stream:false`, temperature0, max_tokens2048, timeout30000ms, response limit65536 bytes. Tests also exercise smaller fixture caps; they do not change the stand cap.

Unchanged routing: `only:['phala']`, `allow_fallbacks:false`, `require_parameters:true`, `data_collection:'deny'`, `zdr:true`, `max_price:{prompt:0,completion:0,request:0}`; reasoning `{enabled:false,exclude:true}`. No paid/auto routing, plugins, tools, second LLM, repair request, budget expansion or privacy relaxation.

Two messages: trusted system instructions, then one JSON-stringified user-data object:

| Operation | User-data object | Exact JSON object required inside `choices[0].message.content` |
| --- | --- | --- |
| Summary | Server-selected sanitized report, coverage and whole-report counts/selection | `{scanId:string,digest:string,platform:string,reportVersion:string,hypotheses:Array<{text:string,citations:string[]}>}` |
| Chat | Prepared `{version,report,history,question,omission}` with server-bound selected evidence and unresolved historical sources | `{scanId:string,digest:string,platform:string,reportVersion:string,text:string,citations:string[]}` |
| Translation | **Only** selected normalized `{title:string|null,description:string|null}` | `{title:string|null,description:string|null}`, with each null exactly matching the input field |

The schema constrains **shape**, not truth or safety. Local parsers still enforce exact current-report bindings, nonempty bounded citation/hypothesis arrays, citation membership, UTF-8 byte limits, plain-text/security, grounded CVE/TEMP identifiers and Russian prose. Translation also enforces per-field identifier preservation, nulls, normalization and exact nonprose preservation. Schema-conforming unsafe, English, stale or ungrounded JSON is not accepted.

Provider envelope: exact configured model, exactly one choice, normalized `finish_reason:'stop'`, assistant string `content` containing JSON, bounded zero-cost usage. Accounting/receipt observation precedes content/publication checks. Only documented optional empty metadata is allowed by the adapter's explicit message-key allowlist. Invalid/truncated/filtered/tool/reasoning output is not salvaged. Dispatched or unknown consumption is not refunded.

## Existing browser/API contract — no new endpoint or consent bypass

Base `/api/v1/browser/scans/:scanId/llm`; same cookie/Origin/ownership gates, source/report/policy/session fences and no-store behavior. New UI automation must use these existing endpoints, explicit applicable request consent and the one shared LLM service/capacity/quota path.

- Summary: GET `/context`; POST `/summary` body **exactly** `{reportVersion,consent:{accepted:true,policyVersion}}`, using summary context's policyVersion. Successful result has report binding, `hypotheses:[{kind:'hypothesis',text,citations}]` and server-derived `scannerFacts`; public selection additionally returns whole-report `findingCount`, `findingCounts`, `identifierCounts`, `coverage`, `contextSelection`. The model must not generate those server-enriched fields.
- Chat: GET `/chat/context` and `/history`; POST `/chat` body **exactly** `{epoch,revision,mutationId,reportVersion,question,consent:{accepted:true,policyVersion}}`, using chat context's separate policyVersion and fresh history CAS. JSON success includes report binding, `epoch,revision,turnId,deliveryMode:'completed-response',reply,usage` and public report counts/coverage/selection. `reply` has binding, `kind:'hypothesis',text,sources`; source objects are server-derived, not model JSON. Exact `Accept:application/x-ndjson` opts into existing validated-completed-reply frames; it is **not native token streaming**. HTTP200 is not success if the terminal frame is an error. Persisted completed turns are verified by history reads, never inferred from a request being sent.
- Translation: GET `/translation/context?findingId=...&assessmentIndex=...`; POST `/translation` body **exactly** `{reportVersion,findingId,assessmentIndex,sourceVersion,targetLanguage:'ru',consent:{accepted:true,policyVersion}}`, using translation context's separate policyVersion. Successful result has report/selection/source binding, `translation:{title,description}`, `machineTranslated:true,targetLanguage:'ru',model,provider:'OpenRouter',generatedAt`. The provider's content is only `{title,description}`, **not this enriched result or a `translation` wrapper**. Original advisory remains unchanged; display/toggle does not dispatch another translation. See `TRANSLATION.md` for binding/source field definitions and body limits.

### Finite translation diagnostics

Headers only: `X-LLM-Failure-Phase` / `X-LLM-Failure-Reason`. Body remains `{errorCode:'LLM_INVALID_RESPONSE'}` on local translation rejection.

- Top-level exact-object mismatch: `content/invalid_shape`.
- Per-field phases: `translation_title` or `translation_description`.
- First-rejection reasons: `null_mismatch`, `invalid_type`, `limit`, `unsafe_text` (existing cleanText guard), `not_normalized` (normalizePlain would change it), `invalid_link` (remaining domain/IP/mail/link guard), `invalid_markup`, `identifier_mismatch` (advisory or finite technical identifier sets), `not_russian`, `nonprose_changed`.
- These name bounded guards, not semantic fidelity or the raw offending content. A URL can hit the earlier text guard before the link guard. No retroactive classification of previous evidence is possible.

**Coordinator prerequisite:** `tests-e2e/public-ai-translation-live.mjs` maintains finite `DIAGNOSTIC_PHASES`/`DIAGNOSTIC_REASONS`; its offline test compares the complete arrays with backend exports. Synchronize the two new phases and seven new reasons from `provider-diagnostic.ts` before qualification, preserving exact finite/header-only projection and tests. Otherwise the runner drops the new predicates. This runner was not edited or executed in this scope.

## ONE later coordinator native qualification — not executed/authorized here

1. Before any generation, coordinator synchronizes/tests the evidence allowlists and reviews this source candidate. Existing runner's required cases do **not** include summary; a qualification claiming all three operations must explicitly include one native summary case, not infer it from chat. Do that runner/UI integration in its own scope, offline first.
2. Coordinator alone performs any separately approved normal build/deploy/preservation procedure, verifies actual source-image/readiness binding and unchanged fixed routing/key-mount/privacy/quotas. Never replay historical continuation/checker tokens or reset existing stores. No new key import or credential/account-limit probing is needed or permitted by this handoff.
3. Start **one** explicitly authorized native browser qualification with fresh request contexts/consent and a terminal owned report. Predetermine a maximum of **four** generation POSTs in that run: chat1, chat2 only after successful validated chat1, one summary, one selected advisory translation. One request per step; no automatic retries, refresh-triggered POSTs, extra model calls, hidden diagnostics probes or second LLM. GETs are read-only. This bound is a proposed plan for coordinator authorization, not permission for this author to call the provider.
4. On any provider429/503 stop further generation in the run, record bounded HTTP/NDJSON/providerFailure/diagnostic metadata, and mark remaining generation/persistence-dependent cases blocked. A missing retry hint remains absent; never invent a wait time or retry. On local validation failure retain only the finite predicate, stop that operation, keep original content and accounting; do not repair by another call or declare success.
5. Success requires actual Russian grounded chat1/chat2 with current citations; durable history after reload and fresh login; a separately successful grounded summary; faithful selected-field translation with per-field identifiers/nulls retained; original/translation toggle without another POST; unchanged original report/counts; foreign-owner denial and preserved safety/accounting. Language regex/schema alone cannot prove semantic fidelity. If prerequisites fail, retain accurate BLOCKED results rather than fabricating acceptance.
6. Persist only the existing sanitized evidence fields/statuses, not conversations, translated strings, raw requests/responses, keys, storageState, HAR or unsanitized provider messages. No refund/reset, fallback/model change, paid usage, privacy relaxation or new attempt follows from a failed run.

## Verification actually run

From `server/api`:

- `pnpm exec tsx --test --test-concurrency=2 src/llm/tests/*.test.ts`: **141/141 PASS**, no skips. Includes actual Nest/disposable stores/real adapter with synthetic transports, quota liability, per-write/session/source fences and provider429/no-retry behavior. No authenticated external model request.
- `pnpm exec tsc --noEmit`: **PASS**.
- Focused ESLint over all changed TypeScript source/tests: **PASS**.
- An earlier focused12-file run: **87/87 PASS**. Initial author-added type/test expectation errors were corrected before the final runs.

No full API/frontend suite, browser runner, UI build, deployment or live AI acceptance is claimed. Concurrent frontend/coordinator changes outside this directory are not authored or reverted here.
