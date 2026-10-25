# H7 spec/evidence reconciliation — 2026-10-25

Run `7aa358d1-d67b-4ddb-b8c0-4c560c16b8f4`; exact work `540f464b-7984-41ae-96f5-c2a16529ce8d`; role acceptance/spec lane; agent `h7-spec`. Participant skill retrieved from MCP because the editor skill catalog did not contain it. Exact claim→context and heartbeat completed. Fresh policy full/strict/approval=false/spec_first=false/parallel/direct. Source read-only; owner declares it FROZEN. HEAD `b73c28a65dc482809de5bc066ef07ed87cf57def` plus other participants' pre-existing source changes, not a clean HEAD-only implementation identity.

## Deliverables and actual MCP receipts

| Document | Full local resulting body | Delta ID | Base | State | Validation | Requirements / scenarios | Ops |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DIP-DOC-16 | docs/public-final-spec-doc16-full-20261025.md | 1eef696c-4cdd-4174-bbd9-bebd24447e21 | v2→v3 | applied / pending review label | valid:true | 14 / 20 | 2 modified,3 added,0 removed/renamed |
| DIP-DOC-15 | docs/public-final-spec-doc15-full-20261025.md | 501162c5-2d7e-4695-8dd1-33dd52b17c34 | v2→v3 | applied / pending review label | valid:true | 11 / 20 | 2 modified,1 added,0 removed/renamed |

Both sourced from **DIP-TASK-42**, never accepted TASK16. During initial preparation fresh full DOC16v2/DOC15v2/DOC8v3/DOC9v2 were read; doc-specific/source-TASK42 proposed lists checked twice, including immediately before proposal, and were empty. Exactly two new proposals created; no duplicates, approved/applied history edits, apply calls or task lifecycle writes in that preparation. The later explicitly authorized apply continuation is recorded below. Proposal/apply echoes retain the complete submitted body and original requirement identities; manual full-text correspondence is not a claimed machine remote hash comparison.

Local UTF-8 bytes/SHA-256:

- DOC16 full body: 27664 bytes; `43bc66adc6f4822807c30beff4290dbb4011505257c4b0d404c34950d019db08`.
- DOC15 full body: 22347 bytes; `a458030a6a72456f9b9f35cf7b938807ec7cfcc5941265e51b8fbe3a2929d241`.
- Additive errata: docs/public-final-spec-evidence-errata-20261025.md; 5654 bytes; `6132e0776b646f1d3956274819af06a3565f44677debb50529704e5779541bf2`.

## Contract reconciliation

- DOC16: russian-prose-v2 enters underlying policy hash and invalidates old consent, including derived translation policy; supplied names/versions/IDs remain prompt-preserved, no invented fixes/counts/TEMP→CVE mapping. Full separate selected-text/source binding/original-provenance guards retained.
- Translation script check: prose needs ≥3 Russian letters and Russian count ≥Latin excluding identifiers; non-prose exact unchanged; no claim of semantic quality.
- Finite errors: upstream429/503 → LLM_PROVIDER_RATE_LIMITED/rate_limited;401 → LLM_PROVIDER_AUTH_FAILED/auth_failed; other observed300..599 → LLM_PROVIDER_UNAVAILABLE/unavailable.503 classification includes busy, not a diagnosed quota cause. No fabricated upstream status for network/timeout/generic failure.
- Retry-After: optional integer0..86400, bounded seconds/date parsing; no-hint differs from0; JSON header/body consistent; advisory only, no retry/fallback/refund/countdown dispatch. Unknown dispatched consumption stays unknown.
- Translation whole-operation deadline45000ms covers preflight/POST/postflight even ignored abort; request40s remains separate. Originals/coverage stay available.
- DOC15 amendment necessary: source really expands v1 error frames from literal LLM_UNAVAILABLE to three new codes + validated metadata. Receipt/usage/seq/tuple/fences/byte/time limits unchanged. Success unchanged; old strict error parsers may fail-closed and are not falsely called compatible. HTTP200 framed error is not generation PASS.
- DOC8 legacy LOCAL Apodex/Novita scope and DOC9 summary safe-error/original/report/no-auto-retry invariants read and preserved; no DOC8/9 proposal needed. Accepted TASK14/16/21/39/40/41 not touched/reopened.

## Errata result

Earlier audit's reported base/attempt3 Markdown run mismatch is **not reproduced** by direct fresh filesystem extraction. Current pairs all match: base66874291…, attempt2=72c55c66…, attempt3=b32b0957…. All SIX whole historical JSON/Markdown files are byte-identical to HEAD, independently compared via git show. New errata retracts the preceding claim of a current checked-in mismatch and preserves original files/FAIL outcomes; cause of earlier inconsistent read observation unknown. No invented historical edit/fix. Historical STOP is superseded prospectively by new owner authorization, not retroactive acceptance or permission for this lane to execute provider calls.

## Read-only source fingerprints at reconciliation

These are source-code hashes only, not credentials, provider payloads or runtime image certification. Frozen-source GO belongs to coordinator/reviewers.

| Path | SHA-256 |
| --- | --- |
| server/api/src/llm/policy.ts | 16b0cc03d02649c089877b5e2435a87a6c285e2ac849a0255413cdc856a449f0 |
| server/api/src/llm/prepared-request.ts | ccc21ae7dad88e4c90f55cfbfd3e81115c2f18551460eb1a378b82f452f8f99f |
| server/api/src/llm/translation-contract.ts | 55397b3159c556057314cc288233f0fbbfcf72498211f1cbdda2db050169faea |
| server/api/src/llm/openrouter-provider.ts | 43217c89be71ec98775eddd367336c34ef47d0ed3bd9c5d2dc01752de5047696 |
| server/api/src/llm/openrouter-transport.ts | 8aa4ca78f1706ad591356a2db737c95abe74c3094602a2630a859ac2267f6d9d |
| server/api/src/llm/llm-exception.filter.ts | 08bb2eb51ef3e55443728edb6b1eec5b2f45cd7d163c64d9d3890bcb68e73cb1 |
| server/api/src/llm/history-delivery.ts | cdbf09a3b71da5a93e687357ba6a74816c1400c6f3c0acd46c7acc3f6d814e6b |
| server/api/src/llm/history.service.ts | add89b93c9c7d4c58157b7206ef700a7faf5a5390a27462df0b1cab0d9098e9f |
| src/shared/api/scans/llmChatContract.ts | b464ba1ffe0d31a34636de81c5a67d92cd12938ccc21930634cb9ad3797d74b6 |
| src/shared/api/scans/llmPublicContract.ts | 07149d90e6f3c8085a73b9abf973a1b1795ab1ae54caad2e4c4f9ffc1ce1f183 |
| src/shared/api/scans/advisoryTranslationClient.ts | 6426e169e373210bac703c0e084a9b596de0e1b7a4715ffa3ae024d7aa0e1c9b |
| src/features/scans/AdvisoryTranslationPanel.tsx | b94c778d4522b27d068683f214478f308bf5e4d29c30670c7d991b9fef670ae0 |

## Preparation validation and historical hold

Actually executed: MCP validate_spec on BOTH complete bodies, valid:true; exact doc/source proposal duplicate checks; local requirement/scenario inventory (DOC16 original11 retained), local hashes; all six historical file byte comparisons and run-ID mapping; read-only scoped diff/status inspection. No suites, application build, provider/browser/native generation or lifecycle checks rerun; source security/correctness GO not impersonated.

**Historical preparation disposition: APPLY NOT CALLED; HOLD until separate coordinator approval after source GO**, despite policy approval=false. At that time docs remained v2 and work item completed prepared; this record is superseded only for apply disposition by the authorized continuation below, not rewritten as deployment/provider PASS. Proposal creation is not deployment, provider availability, ru semantic quality or TASK42 acceptance. Task status/content/progress/closure and accepted tasks untouched; only permitted [progress] comments recorded. No keys/raw env/private payload/DB reads, service lifecycle, commits/push or nested agents.

## Explicitly authorized APPLY continuation — 2026-10-25

The owner explicitly authorized applying the two prepared deltas after fresh current-doc/delta/policy/base checks and reported independent source GO with no P1/P2 in classifier/UI scope. This is **owner/coordinator-reported source review**, not a new review or runtime test executed by this spec participant. Only the spec APPLY hold is lifted; no permission for deployment/recovery/restart/provider operations is inferred.

Fresh MCP reads immediately before apply returned DOC16v2 and DOC15v2, both prepared deltas in state proposed, correct source TASK42, correct doc IDs and base_version2, with their full reviewed bodies and original identities intact. Policy remains full/strict/approval=false/spec_first=false/parallel/direct. Complete current bodies were manually compared against the prepared baselines; complete delta bodies against the prepared submissions. Local fullbody SHA256 values above were recomputed and match unchanged. No remote machine-exact body hash comparison is claimed. No version conflict or new proposal occurred.

Actual MCP apply receipts:

| Document | Applied delta | Actual version | applied_at UTC | Result |
| --- | --- | --- | --- | --- |
| DIP-DOC-16 | 1eef696c-4cdd-4174-bbd9-bebd24447e21 | v2→v3 | 2026-10-25T17:34:41.508273Z | state applied; full body unchanged |
| DIP-DOC-15 | 501162c5-2d7e-4695-8dd1-33dd52b17c34 | v2→v3 | 2026-10-25T17:34:41.659282Z | state applied; full body unchanged |

`review_status:pending` remains the server's review label; with require_proposal_approval=false it does **not** mean these revisions are still unapplied. No approve_doc_delta call, invented human approval step, proposal rewrite or accepted-task reopening occurred. Prepared fullbody files are deliberately unchanged, including their historical authoring HOLD wording. This continuation records that its condition was subsequently satisfied; it does not mutate the text the owner authorized. DIP-ARTF-549 remains the historical prepared handoff, not a deployment receipt. The already completed H7 work item is not reclaimed/recompleted.

## Operational limitation supplied with APPLY authorization — NOT deployment acceptance

The following facts are attributed solely to the owner's latest report; this spec participant made no Docker/HTTP/runtime/provider query:

- Actual normal rollout failed in new audit `deploy-2c9ed08b8269264b09bf14eb6189a649`, phase `build-submit-worker`; the exact worker-build root cause remains **UNKNOWN/unclassified**.
- A prior original four-store backup exists according to the owner; its contents, integrity, restoration and preservation were **not inspected or re-certified here**.
- New recovery checker performed no intent and refused on an actual retained auth-init image blob input/output error. This refusal is separate evidence and **does not establish the root cause of build-submit-worker**. No checker retry, recovery intent, manual unlock/start or lifecycle operation is performed by this lane.
- Owner-reported current observations: public8081 HTTP000; legacy8080 HTTP500. These are not live observations made here, not a healthy/deployed-new-source claim, and no protected endpoint/service was touched to verify or fix them.
- Docker Desktop restart awaits separate owner permission. APPLY authorization is **not restart authorization**; no restart or other recovery action is attempted.

Therefore the applied specification is **NOT deployment READY/PASS, current-source runtime PASS, successful provider generation, translation semantic-quality PASS or four-store preservation acceptance**. TASK42 remains blocked by the owner's instruction; this lane does not change its status/content/progress or close it. Accepted TASK14/16/21/39/40/41 remain untouched. Only this new manifest and an allowed TASK42 [progress] comment are updated; source, keys/env/private state, historical evidence, fullbody drafts and protected services are unchanged.
