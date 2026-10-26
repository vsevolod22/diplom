# H7 spec follow-up — finite finish diagnostics; native evidence remains scoped

## Disposition

Fresh pre-apply policy is full/strict/approval=false/spec_first=false/parallel/direct. Full current DOC8v4 and full delta39e2a254-d3d4-4a86-834e-ba107d726bab were reread immediately before APPLY; base4/sourceTASK42/body/ops matched. Prior preparation full reads of DOC15v4/DOC16v4 and empty doc8/source-TASK42 proposed lists remain historical facts. Existing six applied revisions were not replayed.

**Exactly one authorized FULL delta APPLIED:** `39e2a254-d3d4-4a86-834e-ba107d726bab`, source DIP-TASK-42, **DOC8 v4→v5**, applied_at `2026-10-26 14:05:06.375334+00`. State applied/review_status pending is valid under approval=false; no approval tool was called. Post-apply MCP `validate_spec` on the entire saved current DOC8 returned **valid:true**. Created `2026-10-26 13:57:27.153888+00`; the 20261025 filename prefix identifies the continuing evidence series, not a fabricated preparation timestamp.

The owner separately authorized ONLY this exact APPLY after reporting fresh normal diagnostic rollout **READY/exit0**, preservation of all4stores/JWT, rootlint/APItypecheckPASS and final source GO for stop-only finish acceptance/fixed body-request budgets/no fallback. These are attributed coordinator facts, not this lane's operational tests. The exact pre-apply checks completed and **APPLY HOLD is lifted only for this applied revision**. Historical HOLD/TARGET/rework wording preserved in its immutable body describes preparation time and is superseded by this authorization, not by a native PASS. **Native acceptance remains PENDING**; AI success, translation fidelity, provider privacy/billing and task closure do not follow from application.

## Narrow contract change

At preparation DOC8v4 enumerated exactly17 phases and17 reasons. Applied DOC8v5 retains all phases and original reasons and now documents22 reasons, adding exactly:

| Normalized rejected finish value | Public finite reason |
|---|---|
| `length` | `finish_length` |
| `content_filter` | `finish_content_filter` |
| `tool_calls` or `function_call` | `finish_tool_calls` |
| `error` | `finish_error` |
| Other/unknown/missing/null/nonstring non-stop | `finish_unknown` |

The exact normalized `stop` continues the unchanged success-validation path. Non-stop remains a failure even with valid-looking content. Raw provider/native finish strings never become headers or body fields. `invalid_finish` stays in the general allowlist for compatibility; new classification does not rewrite old attempts. No change to requests, prompt/policy hash, output cap/budget, routing/privacy requirements, response acceptance, body/frame schema, receipt/accounting, unknown dispatched liabilities, retry/fallback/refund/reset.

The complete resulting document was supplied to MCP `validate_spec` with DOC8 and returned **valid:true** before proposal. Proposal returned exactly **1 modified requirement**, “Конечные diagnostic headers без изменения body wire”, **0 added/removed/renamed**. All10 requirement identities remain; scenarios23→24. Nine unrelated requirements and Non-goals remain unchanged.

FULL body: `public-progress-20261025-doc8-finish-diagnostic-full.md` — 30463 UTF-8 bytes, local SHA256 `35de1ceee3cdab73a1100075a03bd32b4678af1233e611241cf35efed36805fa`. Full MCP response was read; no server digest is returned, so machine-exact remote hash equality is not claimed. Both base and resulting local SHA256 values were recomputed before APPLY and matched preparation records; server digest is unavailable. Machine-readable preparation/application/post-validation receipt: `public-progress-20261025-finish-diagnostic-receipt.json`.

## DOC15 / DOC16 — existing dependency, no duplicate amendments

DOC15 v4 requirement “Diagnostic headers failed chat без нового frame” explicitly binds closed enum/absence to DOC8. DOC16 v4 requirement “Translation diagnostic headers и граница русской проверки” likewise binds to DOC8 and has no separate literal list. Those full documents need no duplicate literal-list update: DOC8 is the shared normative dependency. After this authorized application DOC8v5 is the shared22-reason contract. DOC15/16 remain unchanged and inherit its enum/absence; no additional deltas were created. This finding is recorded in comments, **not** a no-spec-impact waiver for TASK42. Accepted TASK16 and other accepted tasks are not reopened.

## Read-only source handoff

- `server/api/src/llm/provider-diagnostic.ts`: 22 reasons, five finite normalized finish classifications, no raw/native strings.
- `server/api/src/llm/openrouter-provider.ts:136`: any `choice.finish_reason !== 'stop'` still throws failure with mapped reason. No acceptance relaxation.
- `server/api/src/llm/tests/provider-diagnostic.test.ts:61-96`: synthetic tests explicitly cover five reasons, unknown/typed/missing values, no raw echo, one call, unchanged successful stop, request reasoning-off/output caps/privacy/free routing. These tests were inspected, **not run by this lane**.
- Runner `tests-e2e/public-ai-translation-live.mjs` reason allowlist includes the same five additions. Fresh-owner login requires a new empty-cookie about:blank context, real UI authentication, matching owner identity and `/account`, then exact scan-report navigation with session/active fences. Redundant anonymous pre-auth scan GET is removed; `preAuthScanProbe:false`, no anonymous401 qualification is claimed. No cookie/storage injection or bypass is authorized.
- Coordinator reports synchronized runner99testsPASS; this is attributed handoff, not this lane's executed test result. No new browser/provider attempt was run here. Runner source change is not a successful fresh-login/translation native receipt.

## Actual native receipts — do not conflate scopes

Read-only bounded projections of matching JSON and Markdown:

1. **Cancellation/progress attempt f60d1c6c-1b6f-4f8c-a8fb-4d3254b6f7db**, run `c6cffe69-9d7c-4d97-8ea8-0bc90ab4a155`, `2026-10-25T21:03:55.955Z–21:04:23.016Z`: actuallyRun=true, **10PASS / 0BLOCKED / 0FAIL**. Cases include cancel_progress, durable published report preservation, reload/history/fresh-owner-login and safety. Coordinator reports the observed pre-cancel config checked subset was1of4. This is one checked outcome, not25% elapsed work/time/ETA. No LLM generation is qualified; the runner's cancel mode denies all LLM POSTs. Pre-cancel unpublished findings were not byte-compared; post-cancel published datasets form the persistence baseline. Historical failed cancel f086 remains unchanged.
2. **AI attempt29f3a78d-9455-4131-b29a-45aca5c2c657**, run `75d87bff-2fe8-4854-b309-9641fd8bbaee`, `2026-10-25T21:34:44.772Z–21:36:48.158Z`: actuallyRun=true, **9PASS / 9BLOCKED / 0FAIL**, not full success. Native report161CVE/0DebianTEMP/4pages. Chat1 BLOCKED under HTTP200 failed NDJSON with finite phase=finish/reason=invalid_finish; HTTP200 is not generation success. This locates a rejected normalized non-stop finish in the prior adapter path, **not its actual value**: length/content_filter/tool/native error/unknown cause cannot be inferred from that old generic reason. `native_finish_reason` was not read or persisted. Fresh login BLOCKED BROWSER_READ_FAILED; downstream translation_context/translation/toggle/preservation prerequisite blocked, actual translationPosts=0. Translation is NOT_RUN, not provider translation failure or successful Russian output. Successful chat/history semantic fidelity remains unqualified.

Current fresh CVE e1af activation/four-store receipts and loaded6h public scheduler metadata are a separate operational scope; see `public-progress-20261025-cve-receipt.md`. The coordinator additionally reports scheduler statusPASS after an exact two-field macOS metadata fix. This lane did not rerun scheduler/runtime status or duplicate its source review. Those facts do not convert AI BLOCKED into PASS.

## Remaining gate

- Diagnostic application gate satisfied for exactly39e2a254-d3d4-4a86-834e-ba107d726bab: explicit new owner GO, owner-reported READY/source GO, fresh full checks, successful v4→v5 APPLY and saved-full-document validation. No further delta/apply is authorized or needed by this receipt.
- Independently authorized native generation/history/fresh-owner-login/translation and quality results, without automatic retry or weakening finish/language/owner/receipt/transport guards. No new live attempt is authorized or performed by this document.
- Preserve original FAIL/BLOCKED receipts and unknown consumption; no replay, key/env/DB/JWT read, provider call, lifecycle operation, source edit or task closure by this lane.
