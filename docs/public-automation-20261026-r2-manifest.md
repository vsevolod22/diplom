# Public automation — superseding package r2, 2026-10-26

**PREPARED / PROPOSED, NOT APPLIED. ALL APPLY HOLD until NEW coordinator source GO/deploy.**

Repo `/Users/vsevolod/Documents/oldstartup/diplom`; Flownix project `520a0059-d0f2-4f86-8d93-fc15035a5715` (`DIP`). Zed / GPT-6.1-Sol, docs-only lane. Fresh policy: full/strict, approval=false, spec_first=false, parallel/direct. Policy permission to apply does not supersede the owner's HOLD. No new harness/native work claim.

## Exact proposals and fresh bases

| Doc | Base | Source | New delta ID | Server ops | Requirements / scenarios |
|---|---:|---|---|---|---:|
| DIP-DOC-2 | 9 | DIP-TASK-9 | `cf2cf23d-f079-4bfa-b843-f07e6484f3cf` | 3 modified + 1 added | 33 / 53 |
| DIP-DOC-8 | 5 | DIP-TASK-42 | `21561058-ace8-4918-a3a7-14d3290f6170` | 4 modified + 2 added | 12 / 30 |
| DIP-DOC-9 | 3 | DIP-TASK-42 | `3e230388-542f-439d-9eef-fb904db51789` | 3 modified + 3 added | 10 / 19 |
| DIP-DOC-15 | 4 | DIP-TASK-42 | `c7c76a73-4fe2-4fd9-9259-55f48e9d577b` | 1 modified + 1 added | 14 / 25 |
| DIP-DOC-16 | 4 | DIP-TASK-42 | `23d179fc-f49b-40fb-bfec-ec555b6f02c2` | 6 modified + 1 added | 16 / 23 |

All five returned `state:proposed`, `review_status:pending`; post-proposal source lists confirmed them. Removed/renamed **0** for every proposal. All **77** base requirement identities retained; **85 requirements / 150 scenarios** in resulting full bodies. Returned ops manually inspected against local clause comparison: **17 modified + 8 added**. Exact named ops, doc/source UUIDs, creation timestamps and hashes are in `public-automation-20261026-r2-receipts.json`.

### Complete body files and local SHA-256

- `docs/public-automation-20261026-r2-doc2-full.md` — 58518 bytes, `81a38204937fadc09de98d25c6227ec183699b2d599d52e5053e09be1547be74`.
- `docs/public-automation-20261026-r2-doc8-full.md` — 36363 bytes, `87b03753eb0b1477686c0aea3fce8b58f8869d11f6054202b6786041eca43bc5`.
- `docs/public-automation-20261026-r2-doc9-full.md` — 23945 bytes, `867b641cd2157b2b2f9fe197a983a5776e334708880a6f7debc88784418387e5`.
- `docs/public-automation-20261026-r2-doc15-full.md` — 28211 bytes, `21e713dd746d34ee42e9baf74eb0cf6ffa5f2d3a601f185de418e4c0c7a398fb`.
- `docs/public-automation-20261026-r2-doc16-full.md` — 35035 bytes, `e04100b1bfc03bd3f643995355ff81fa88c90ab484d3a24bd971a48ed83224d4`.

These are **entire documents**, not deltas/excerpts. Fresh full MCP document bases were read; matching dated base mirrors and their local hashes are recorded in `static-final.json`. `preparation.json` is intermediate local preparation, superseded by `static-final.json`/`receipts.json` for final sizes/hashes. Server does not return a document/validation digest; **machine-exact remote hash equality is not claimed**. Raw tool-call full bodies and echoed proposal bodies were manually compared; returned ops contain no unexpected requirement modifications/removals.

## Authorized supersession, history preserved

Only the five explicitly authorized old pending proposals were discarded as considered-superseded, before replacements:

| Doc | Discarded proposal |
|---|---|
| DOC2 | `e103d4c2-acb0-48fb-a8bc-a631df0f1e6b` |
| DOC8 | `9e36c15c-733a-4d4e-8285-5bd7e5695907` |
| DOC9 | `ac96de0e-88b4-4e97-ab8f-74fcdda5b0fd` |
| DOC15 | `492fe0ca-0b12-4af4-9a2b-96fc15f87295` |
| DOC16 | `b8fc139b-f221-4f05-bce9-e08c9270172e` |

No delete, pending rewrite or additional discard. Old approved TASK9/base1 `3e049e61-3462-4ff0-bd02-da80ed385fe7` remains untouched: it is not a current-base replacement or an apply candidate. Earlier transcription-error proposals `2432f604…`/`8661cf36…`, their discarded history and all old artifacts remain intact. DOC9's inherited nonnormative `DIP-ТASK-16` uses Cyrillic Т; preserved rather than rewriting earlier history. Historical review sections in DOC15/16 remain explicitly labelled historical, not current policy/GO.

## Actual validation ledger — r2 only

**6 complete raw-body `validate_spec` calls / 6 `valid:true`; all five final complete bodies validated BEFORE their proposal.**

Order: DOC9, DOC8, DOC15, DOC16 initial transcription, DOC16 corrected full body, DOC2. The initial DOC16 validate payload had `отбрасысывания` instead of `отбрасывания`; it was also format-valid but was **not proposed**. The complete corrected body was revalidated, then used for the sole DOC16 proposal. No partial/current-doc-only validation is counted as a full draft validation.

This r2 package: **5 new proposals, 5 authorized prior discards, 0 new-proposal discards, 0 apply, 0 approve, 0 task status/content/progress/closure changes**. The previous package's separate 6 full validations / 7 proposal calls / 2 own transcription discards / 0 apply remain historical, not added into r2 totals. Local OpenSpec/identity/LF/whitespace/hash checks passed; only inert docs assembly/static scripts were run. No application suites, build, native browser, provider, runtime or credential operations were run here.

## Source contract and limits

- **DOC2:** approximate non-equal-weight local work estimate, native `percent:null` unchanged; 100 only authorized `completed`. Reset on observed durable-outcome/checked-credit regression, queue reentry or scope change; missing metadata alone is not proof of retry. Invisible running→running retry cannot be identified without attempt/start metadata, and estimate can grow without new facts. List uses **one scoped list query / 2000ms while active**, no per-card status N+1; whole card is one semantic link and full coverage stays in detail. No DOC1 amendment: server progress contract unchanged.
- **Preferences / P1 fences:** explicit account Save, owner-scoped localStorage original/ru + autoSummary and fixed `report-automation-v1`; defaults original/off. Current snapshot identity plus applicable autoSummary/ru flags and direct subscriptions fence dispatch and publication, including callbacks ignoring abort. Revision string alone is not revocation authority. Exact model/provider/data/privacy/all-flags/caps allowlist precedes POST/publication; no dynamic-policy grant is invented. Failed persistence closes current memory authorization, not guaranteed durable revocation of an old disk record after later login.
- **Summary recovery / P2:** public-only `existing(context)` GET before attempt marker, even with autoSummary off, after fresh owner/report/policy/source/permission checks. GET does not generate or consume provider quota. Backend LRU **64 entries / 2MiB accounted bytes / 64KiB result**, per LlmService process instance; guarded successful publication only. Owner miss404 `LLM_SUMMARY_MISSING`; foreign/missing404 `SCAN_NOT_FOUND` before policy/cache. Existing enriched DTO, no cache wrapper, `X-LLM-Summary-Retention: process-lifetime`. Survives browser reload/fresh login only while instance/entry remain; **lost on API restart/replacement/replica/eviction**, no DB migration or guaranteed retention. Missing does not clear marker or authorize replay; a first unmarked attempt still separately requires applicable opt-in.
- **Queue / P2:** passive metadata pending singleflight shares local serial scheduler, one active / max8 waiting, max9 pending metadata keys; at most2 parallel GET within a metadata task. No settled readiness cache or GET attempt marker. Session change/last-subscriber abort fences publication. Generation cache64/opaque SHA-256 markers256 remain bounded local safeguards, not distributed exactly-once; an uncooperative external transport may outlive local cancellation. Translation output still cannot be recovered after reload.
- **Translation:** only mounted assessments of an OPEN advisory, not a hidden report crawl or invented global selected-source selector. Producer, strict decoder, helper and runner use exact `automaticDispatch:'account-preference'` (not booleans), ru/machine flag and no persistent translation cache. Original/source/provenance/unknown language/CVE-vs-TEMP and quotas/accounting remain independent.
- **LLM:** exact public Xing/Phala strict `json_schema` for summary/chat/translation with required fields/additionalProperties:false; legacy/Apodex `json_object` unchanged. Only absent or inert empty `tool_calls:[]`; no tools/reasoning salvage/repair/fallback. Current policy hash includes **`russian-prose-v4-structured`**. First bounded translation predicate headers, **19 phases / 29 reasons**, unchanged error body/NDJSON/receipt/CAS/accounting. Schema/script checks are not semantic fidelity or retrospective root-cause proof.
- **Chat:** composer editable immediately during GET; Send remains manual and admission-bound, independent of automation flags. No new automatic questions/history generation.

### Explicit source-readiness limitation (not implemented acceptance)

Final inspection still finds unconditional fixed-profile allowlist checks and automation authorization in `ScanSummaryPanel.generate()`, including the legacy path. Thus the handoff's tiny legacy-profile UI gate is **still incomplete in inspected source**; DOC9 preserves the legacy manual-generation contract as a target, not a claim this source currently satisfies it. Requires author/coordinator resolution and focused review before source GO. Do not treat public GET gating alone as fixing legacy generation. No source fix performed here.

Public nginx source already permits GET+POST on the exact summary location; deployment was **not** verified. `SUMMARY-RESULTS.md`'s earlier coordinator-required-edit/client-pending prose is an authoring snapshot, not evidence the current source still lacks ingress/recovery.

User-reported validation only: UI994 PASS before last disclosure literal, targeted143 after it; API154 before literal +38 targeted, runner123 PASS. Not rerun here, not native GO, not blanket current full-suite green. Native/provider/semantic/privacy/billing/preservation acceptance remains coordinator-owned; historical FAIL/BLOCKED and unknown dispatched liability are not rewritten or refunded.

## Handoff

Final source hashes (not frozen/deployed equality): `docs/public-automation-20261026-r2-source-snapshot.json`. Exact receipts/named ops: `docs/public-automation-20261026-r2-receipts.json`.

TASK9 remains regression/85; TASK42 remains blocked. Accepted parents/tasks unchanged. No new doc node, DOC1 proposal, README/app/tests/runtime/provider/credentials/Git writes. Only NEW own `docs/public-automation-20261026-r2-*` artifacts and permitted attributed TASK9/42 progress comments.

Before any future APPLY: obtain NEW coordinator source GO/deploy authorization, resolve/review the legacy gate, reread policy/full current docs/full deltas/bases, verify exact scope/body/ops. Version drift requires reconciliation/new authorization, not stale replacement. **This package itself grants no APPLY, deploy or generation authorization.**
