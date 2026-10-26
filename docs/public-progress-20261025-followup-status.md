# H7v2 spec follow-up — await actual progress/panel source readiness

## Scope and preserved prior result

This is a new follow-up to completed work `41081c06-0977-40c7-8394-b8f44e7284c9`, run `7a0c301f-ca6c-49d1-b63f-dacb2ae61ae2`, agent `h7v2-spec`. The completed prepared work and DIP-ARTF-551 were not reclaimed, recompleted or rewritten. No application source, README or other-owner operator document was edited.

Latest coordinator authorization permits discarding ONLY the five prepared pending proposals listed below, with a superseded reason, if necessary to incorporate actual source; all other revisions must remain untouched. This authorization does not authorize APPLY, lifecycle, live/provider calls, task closure or accepted-task changes. The coordinator explicitly asks to wait until backend progress is actually ready, then rewrite FULL bodies and validate ALL FIVE complete raw bodies before replacement proposals.

## Fresh MCP state observed

Policy remains full/strict, require_proposal_approval=false, spec_first=false, parallel/direct.

| Doc/base | Prepared delta | State/review |
|---|---|---|
| DOC2/base8 | a8f60d6f-3d4c-429f-9e0e-1d2cdf5339b7 | proposed/pending |
| DOC8/base3 | f1f39780-e53d-4d18-a3d9-e345312c67fb | proposed/pending |
| DOC9/base2 | e41fc1f0-0703-4d6d-b888-a97fc91a5232 | proposed/pending |
| DOC15/base3 | 51d4cad7-64e8-4813-bcfb-c33ee8f15df7 | proposed/pending |
| DOC16/base3 | 5dbc70b3-0514-4991-a780-1b4e9ed8dc79 | proposed/pending |

All five were freshly read in full with get_doc_delta. None is draft/rejected; update_doc_delta is therefore not available for in-place edits. Approval=false does not make pending editable. NO update/discard/delete/propose/apply was performed in this follow-up. Existing pending proposals remain intact while source readiness is awaited.

## Read-only source observations

- `server/api/src/llm/policy.ts` includes `responseLanguageRevision: russian-prose-v3-grounded` in the policy hash.
- `server/api/src/llm/provider-diagnostic.ts` exposes only factory-bound finite header projection: `X-LLM-Failure-Phase` and `X-LLM-Failure-Reason`. Phase enum: request, connect, tls, dispatch_guard, headers, body, json, model, envelope, finish, content, usage, accounting, deadline, caller_abort, language, grounding. Reason enum: invalid_request, rejected, io_error, timeout, aborted, http_error, invalid_type, limit, invalid_json, mismatch, invalid_shape, invalid_finish, invalid_content, invalid_receipt, observation_failed, not_russian, unknown_identifier. Arbitrary object/body/message metadata is not a header authority; absence remains absence. This is an additive diagnostic-header contract, not a new body/NDJSON schema or retrospective proof of the old chat502 cause.
- JSON exception filter and failed NDJSON delivery call diagnosticHeaders. Existing body wire remains separate; source handoff reports no body-wire change.
- `AdvisoryTranslationPanel.tsx` and `ScanChatPanel.tsx` contain visible per-request button authorization notes. Chat source-selection checkboxes are not permission checkboxes and are not a target for blanket removal.
- At this observation, `ScanSummaryPanel.tsx` still has consent state, a consent checkbox and a consent-dependent generation guard. Coordinator reports the UI author's scope has been extended to summary removal; this read is NOT a claim that the extended source work is already complete.
- A bounded search of `server/api/src/scans` and `server/api/src/ledger` found existing requestedChecks reads but no durable-outcomes-v1/resolvedChecks/checkedChecks projection. Backend progress is therefore still PENDING actual source handoff, not independently source-ready in this observation. No operational imports or test suites were run.

## Agreed progress target to reconcile after readiness

The coordinator's agreed owner GET metadata shape is `progress:{basis:durable-outcomes-v1,requestedChecks,outcomes,resolvedChecks,checkedChecks}`; main percent remains null. Its concrete types, allowed outcomes, bounds, atomicity/claim binding, absent/legacy handling and tests must come from the completed source, not guesses here. Active owner GET polling continues even with SSE; SSE remains a hint and does not publish intermediate findings/results. The eventual spec must distinguish resolved versus checked checks, preserve owner isolation and no premature result publication, and avoid converting check counts into elapsed-time estimates or native percent.

## Next mutation sequence — not executed yet

1. Await explicit completed backend progress and summary UI handoff, then read their exact public source/tests and fresh current document bases.
2. Reconcile only this lane's five FULL local resulting bodies, preserving unrelated requirements. Include actual russian-prose-v3-grounded, finite header enums/absence semantics, button-only request authority and owner-only progress metadata/privacy/polling without result publication. Original user permission changes the checkbox UX deliberately; it does not waive ownership/privacy/accounting.
3. Call validate_spec with the COMPLETE raw text of each of the FIVE resulting bodies, not just current bases or amended clauses. Record all five receipts and exact hashes.
4. Where source incorporation requires replacement of these noneditable pending proposals, use the expressly authorized discard with a considered-superseded reason, then propose a replacement FULL body against the fresh current base, preserving an old-to-new mapping. No parallel duplicate for the same active change; no other proposal or applied revision is touched. If a prepared body needs no replacement, retain its identity rather than discard gratuitously.
5. APPLY remains HOLD until separate coordinator review/GO; the prior completed work result is historical and does not become actual implementation/runtime/provider acceptance.

No HTTP, Docker, lifecycle, download/sign, provider, key/env/JWT/DB/holder read or task status/content/progress/closure operation occurred. Historical failures, unknown consumption and preservation boundaries remain unchanged.
