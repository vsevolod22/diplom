# Public automation — selected-five APPLY receipt, 2026-10-26

**APPLIED / IMPLEMENTED CONTRACT; NOT AI OR OVERALL RUNTIME ACCEPTANCE.** Project `520a0059-d0f2-4f86-8d93-fc15035a5715`. This new additive manifest supersedes the operational APPLY HOLD for exactly the five selected deltas after explicit coordinator APPLY GO and reported actual rollout READY. It does not retroactively alter any authoring manifest, full body, historical FAIL, discarded proposal or unknown consumption.

## Fresh checks and actual Flownix application

Before the first apply, freshly read the full current server documents AND full selected deltas for DOC2/8/9/15/16. Verified matching project/doc/source identities, base versions, `state=proposed`, `review_status=pending`, complete requirements and intended ops. Existing component bindings remain DOC2/9→DIP-COMP-1; DOC8→DIP-COMP-3; DOC15/16→DIP-COMP-1/3. Fresh policy: full, strict, require_proposal_approval=false, spec_first=false, parallel/direct. No policy change or agent approval.

Each selected ID was applied **once**, sequentially, after all ten full reads and policy check. All five calls succeeded without conflict/retry; exact selected proposal bodies were applied without editing.

| Doc | Selected delta | Source | Base → saved | Server applied_at UTC | Ops modified/added | Complete reviewed body |
|---|---|---|---|---|---|---|
| DIP-DOC-2 | `cf2cf23d-f079-4bfa-b843-f07e6484f3cf` | DIP-TASK-9 | 9 → 10 | 20:40:38.917548 | 3/1 | `docs/public-automation-20261026-r2-doc2-full.md` |
| DIP-DOC-8 | `21561058-ace8-4918-a3a7-14d3290f6170` | DIP-TASK-42 | 5 → 6 | 20:40:41.752161 | 4/2 | `docs/public-automation-20261026-r2-doc8-full.md` |
| DIP-DOC-9 | `5406fc22-567a-4490-ba03-4875a4a5b994` | DIP-TASK-42 | 3 → 4 | 20:40:45.158836 | 3/3 | `docs/public-automation-20261026-r3-doc9-full.md` |
| DIP-DOC-15 | `c7c76a73-4fe2-4fd9-9259-55f48e9d577b` | DIP-TASK-42 | 4 → 5 | 20:40:48.132529 | 1/1 | `docs/public-automation-20261026-r2-doc15-full.md` |
| DIP-DOC-16 | `23d179fc-f49b-40fb-bfec-ec555b6f02c2` | DIP-TASK-42 | 4 → 5 | 20:40:51.144711 | 6/1 | `docs/public-automation-20261026-r2-doc16-full.md` |

Each response returned `state=applied` and the saved version above; `review_status=pending` remains the separate unmodified review field because human approval is not required by current policy. This is not a claim of human web-UI approval.

Saved-document `validate_spec(doc_slug, project_id)` was then called once for each of the five DOCs, **without a supplied body**, validating the server's saved complete document, not a local excerpt. All five responses were exactly `{"valid":true}`. No remote validation receipt ID/hash or separate machine byte-equality proof is supplied by that result.

Selected resulting package: 85 requirements / 150 scenarios, all 77 base requirement identities retained, 17 modified / 8 added / 0 removed / 0 renamed. These are package requirement counts from preparation/full-body inspection, not extra fields returned by validate_spec. No DOC1 change: native server percent/progress contract is unchanged.

## Historical authoring labels are not current state

The exact reviewed bodies retain their original preparation-era `SOURCE-BOUNDED PROPOSAL`, `NOT APPLIED`, `APPLY HOLD` and dated review wording. They were deliberately **not** rewritten during apply. For these five IDs only, the explicit coordinator authorization and successful MCP application recorded above supersede those operational preparation labels. Normative implemented contracts are now saved; neither application nor the source/deploy GO establishes AI quality, full runtime acceptance, privacy compliance or verified billing.

The discarded r2 DOC9 `3e230388-542f-439d-9eef-fb904db51789` was NOT applied. Its erroneous always-manual legacy claim remains historical and superseded by DOC9 r3: public-only GET recovery is distinct from app-wide authorized automatic POST, which still requires exact fixed-profile disclosure and fresh grants/guards. No other historical proposal was applied, edited, approved, deleted or discarded in this apply pass. Old approved TASK9/base1 `3e049e61-3462-4ff0-bd02-da80ed385fe7` remains untouched.

## Coordinator-attributed deployment and source evidence

The coordinator explicitly supplied APPLY GO for the selected five and reported:
- ONE normal rollout READY, audit `deploy-ed3d33be2f2b7fcc19e33544cea7b195`; four stores/JWT preserved; refresh lock absent.
- 425 source hashes match; both 8081/8080 return HTTP200; scheduler status PASS.
- Independent final AI/cache GO and progress/coverage GO after P1/P2 fixes.
- Full API 1411 PASS; full UI 994 PASS before the last tiny scope plus targeted 160/366 PASS; static build PASS. These are separately scoped reported runs, not combined into a fabricated new full-UI total.

These are **coordinator/author handoffs**, not deployment, preservation, HTTP, scheduler or test checks independently executed by this spec lane. No new native, provider, browser, shell, private API, credential, app-source, test/build or Git operations were performed here. The only remote mutations were five Flownix apply calls; local writes are new documentation receipts.

## Native attempt — retained FAIL, no retrospective promotion

Read existing metadata-only artifacts without changing them:
- `docs/public-automation-1f09fff7-5134-4461-873b-0519452c359b.json`
- `docs/public-automation-1f09fff7-5134-4461-873b-0519452c359b.md`

Attempt `1f09fff7-5134-4461-873b-0519452c359b`, run `8f428eb4-ce34-4082-8b91-405715ca9f0e`, actuallyRun=true, 2026-10-26 **20:26:36.032–20:27:36.281 UTC**, origin 8081. One account, one scan `914f89e9-716b-4fa0-bccd-fcfafed60aab`, real completed linux/amd64 report. Artifact cases native_scan/estimate/coverage_click are PASS; report remains **FAIL / ASSERTION_FAILED**. Overall qualification remains FAIL; subsequent blocked cases do not become PASS.

Artifact records one admitted browser summary POST, zero chat POSTs, zero translation POSTs, one passive summary read, and browserClosed=true. The coordinator attributes summary's unknown outcome to early browser close. Independent server egress and billing verification are explicitly false in the artifact. A browser POST observation is not proof of provider completion, returned/validated summary, zero consumption, successful cancellation or refund. Summary generation/reload/fresh-login restoration, chat/history, translation, anonymous/foreign-owner isolation and full preservation qualification are not established by this attempt. Zero translation calls mean NOT_RUN, not provider rejection or translation fidelity acceptance.

The coordinator reports the runner Secrets DTO assertion bug is proven and fixed with source/offline 130 PASS; **no new native attempt yet**. That correction does not rewrite the original FAIL or resolve the dispatched summary's unknown consumption. This lane did not run that fix or its tests. The old artifact's preparation/source412 wording is a dated original, not current rollout authority; the newer source425/deployment handoff above is separate attribution, not an edit to history.

## Continuing implementation limitations

- Local progress is an explicitly approximate unequal-weight observation model; server percent stays null, 100 only follows confirmed completed. Observed durable outcome/checked regression resets the estimate; invisible internal retry remains uncertain.
- Owner-local preferences are not device-synchronized or server consent. Fresh snapshot/session/applicable flags and exact OpenRouter/Xing/Phala/free disclosure fence dispatch/publication. Manual chat Send remains required.
- Shared frontend scheduling is local and bounded (one active / eight waiting, pending-only metadata singleflight), not distributed exactly-once. Attempt markers may precede dispatch; abort does not prove external cancellation. Cache miss does not clear markers or authorize replay.
- Public GET summary recovery is process-lifetime only: 64 entries / 2 MiB accounted / 64 KiB result; API restart, eviction or another instance loses cache. Reload/fresh login recovery requires the retained matching entry and current owner/report/policy/permissions. No DB durability guarantee. GET does not generate, access provider/key or consume provider quota.
- Legacy reports skip public GET recovery but may perform authorized guarded automatic POST under the exact applicable fixed disclosure; no Apodex/Novita/paid consent expansion. Translation remains public-only, selected/open-source-slot and memory-only; structured/script/citation guards do not prove semantic quality.

## Counts and scope

This apply pass: **10 fresh full server reads** (5 docs + 5 selected deltas), **1 fresh policy read**, **5 apply calls / 5 successes**, **5 saved-document validate calls / 5 valid:true**, **0 proposals/discards/approvals/status/progress/cascade/reopen/native claims**. Historical r2+r3 preparation remains **7 full raw-body validations / 7 valid** (including superseded r2 DOC9 and the extra DOC16 pass). With this pass, r2+r3 plus post-apply checking totals 12 validation calls: 7 raw-body and 5 saved-document calls, not 12 raw-body validations. The initial older package retains its separate history.

Taskdone is neither performed nor implied. No accepted parent/task was reopened. Existing preparation manifests/receipts/full bodies and native artifacts are unchanged; this manifest and `docs/public-automation-20261026-apply-receipts.json` are additive application evidence only.
