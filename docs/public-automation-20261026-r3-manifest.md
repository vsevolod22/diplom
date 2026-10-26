# Public automation — r3 DOC9-only receipt, 2026-10-26

**SOURCE-BOUNDED PROPOSALS; APPLY HOLD.** Project `520a0059-d0f2-4f86-8d93-fc15035a5715`. No apply/approve, status/progress/parent changes, native claims, runtime/provider calls, tests/builds, credentials or Git operations in this amendment. Only new `docs/public-automation-20261026-r3-*` files written. Existing manifests/full bodies/receipts remain historical, not silently corrected.

## Authorized correction

Only r2 DOC9 `3e230388-542f-439d-9eef-fb904db51789` was considered-superseded and discarded. Its original body and server row remain. Replacement **`5406fc22-567a-4490-ba03-4875a4a5b994`**, source **DIP-TASK-42**, fresh server **base_version 3**, state `proposed`, review_status `pending`, created_at `2026-10-26 20:19:31.440313+00`.

Full replacement body: `docs/public-automation-20261026-r3-doc9-full.md`.

- Public-only report profile gate controls passive **GET summary recovery**, not automatic POST generation.
- App-wide summary automation can operate on an authorized completed public or legacy report with the applicable saved owner autoSummary opt-in. Fresh snapshot identity/session/applicable flags, exact fixed disclosure, context/usage/quotas, citations and server guards remain mandatory.
- Exact OpenRouter / `xingchen-agi/xing4.0-29b-a4b:free` / Phala / free-only disclosure is not a grant for Apodex/Novita, another provider/model composition or paid fallback. Report profile and provider/disclosure profile are distinct.
- Legacy skips GET summary but may perform the guarded automatic POST. The earlier r2 statement that legacy generation is always manual, and the earlier alleged unresolved legacy-generation UI blocker, are **retracted**, not current limitations. Historical r2 text remains unchanged as evidence.

All 7 base requirement identities and all 10 r2 requirement identities retained; 10 requirements / 19 scenarios in r3. Existing button-authorized stale-context scenario remains a valid specific case, not a universal button-only restriction. Inherited nonnormative spelling `DIP-ТASK-16` (Cyrillic Т) is preserved deliberately, not silently normalized.

### Server-returned DOC9 operations versus base v3

Modified:
1. Явное раскрытие условий и согласие на один запрос
2. Ограниченный ручной запрос и отмена
3. Гипотезы обычным текстом и проверенные ссылки на источники

Added:
1. Owner-local настройки и ограниченная защита от автоповтора
2. Passive summary recovery до attempt marker
3. Bounded passive metadata scheduling

**3 modified / 3 added / 0 removed / 0 renamed.** These are operations against current applied v3, not a count of edits against discarded r2.

## Current five-body selection

Paths are relative to the `diplom` repository. Other four proposals/bodies were NOT rewritten, discarded, re-proposed or applied in r3; their metadata below is carried from r2 receipts, not a new validation of them.

| Doc | Base | Source | Selected delta | Complete body | Requirements/scenarios | Ops modified/added |
|---|---:|---|---|---|---:|---:|
| DIP-DOC-2 | 9 | DIP-TASK-9 | `cf2cf23d-f079-4bfa-b843-f07e6484f3cf` | `docs/public-automation-20261026-r2-doc2-full.md` | 33/53 | 3/1 |
| DIP-DOC-8 | 5 | DIP-TASK-42 | `21561058-ace8-4918-a3a7-14d3290f6170` | `docs/public-automation-20261026-r2-doc8-full.md` | 12/30 | 4/2 |
| DIP-DOC-9 | 3 | DIP-TASK-42 | `5406fc22-567a-4490-ba03-4875a4a5b994` | `docs/public-automation-20261026-r3-doc9-full.md` | 10/19 | 3/3 |
| DIP-DOC-15 | 4 | DIP-TASK-42 | `c7c76a73-4fe2-4fd9-9259-55f48e9d577b` | `docs/public-automation-20261026-r2-doc15-full.md` | 14/25 | 1/1 |
| DIP-DOC-16 | 4 | DIP-TASK-42 | `23d179fc-f49b-40fb-bfec-ec555b6f02c2` | `docs/public-automation-20261026-r2-doc16-full.md` | 16/23 | 6/1 |

Selected package remains 85 requirements / 150 scenarios, all 77 base requirement identities retained; 17 modified / 8 added / 0 removed / 0 renamed versus the respective applied bases. DOC1 is untouched: no server progress contract amendment. Old approved TASK9/base1 delta `3e049e61-3462-4ff0-bd02-da80ed385fe7` is untouched.

## Validation accounting — do not conflate generations

- **This r3 DOC9 amendment:** 1 authorized discard (completed before conversation compaction; confirmed afterward), **1 full raw-body `validate_spec` call → `{valid:true}`**, then 1 full-body proposal. 0 apply / approve / rejected validations / proposal transcription corrections. No excerpt/path-only validation.
- **Prior r2 package, historical receipts:** 6 full raw-body validations / 6 valid, 5 proposals, 5 authorized supersession discards, 0 apply. DOC16 had an extra complete corrected-body validation after an unproposed typo (`отбрасысывания`); both calls remain counted.
- Thus **r2+r3 = 7 complete raw-body validations / 7 valid**, including superseded r2 DOC9 and the extra DOC16 pass. The current selected five complete bodies have each passed full-body validation; this is not a claim that all five were revalidated in r3.
- The older initial package is separate: historical 6 full validations / 7 proposal calls / 2 own transcription discards / 0 apply. It is not the current selected package.
- `validate_spec` returned only `{valid:true}`; it supplied no validation receipt ID or hash. r3 byte count/hash and a machine-exact file-versus-remote equality check are **not computed** under the no-native-tools restriction. The echoed proposal body was inspected; no machine byte-equality proof is claimed.

## Source observations and boundaries

Read-only source in this amendment:
- `src/features/scans/ScanSummaryPanel.tsx`: `refresh()` gates `existing(context)` on completed + `status.profile === PUBLIC_IMAGE_PROFILE`; `generate()` has no report-profile gate, but checks current authorization and exact disclosure before POST and publication.
- `tests-vite/ui/scans/llmSummary.test.tsx:124–142`: default-client legacy cases with 403/404 recovery mock assert ZERO GET summary, one guarded POST with reportVersion/consent, context and usage reads. **Read, not run.**

Retained limitations: local serial scheduler one active/up to 8 waiting; bounded pending-only metadata singleflight, no settled readiness cache or distributed lock. Attempt markers can precede dispatch, abort does not prove external transport stopped, no global exactly-once. Translation outputs are memory-only and not restored after reload. Public summary recovery is process-lifetime only: cache limits 64 entries / 2 MiB accounted / 64 KiB result per DOC8 r2, lost on API restart/eviction/another replica; browser reload/fresh login recovery requires retained matching owner/report/policy result and fresh permissions. Passive GET does not call provider, consume provider quota, authorize replay or clear an attempt marker. Scanner report remains separate.

The user reports source freeze, independent AI/cache GO, and final static tests/build running. Those are attributed handoffs, **not this agent's test result, deployment verification or native acceptance**. No additional mismatch was found in the narrow GET-versus-generation source checks above; no broad runtime/semantic/privacy/billing acceptance is implied. TASK9/TASK42 statuses and accepted parents are unchanged by this lane. No new comments, claims, doc nodes or component changes in r3.

**Apply readiness:** prepared only. Wait for actual deployment and separate coordinator authorization; recheck bases and selected proposals before any later APPLY. Policy permission to apply is not user authorization.
