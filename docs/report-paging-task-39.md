# DIP-TASK-39 — author handoff (UI only)

Run: `701f3b9d-356c-46a6-9195-e14ae93df956`; preparatory lead → architect → author: `ui39:lead-author`.
Base HEAD: `127e93b7ef19d69743ff9af2a4147e72949dc36b`. No branch or commit created.

## Own diff paths

- `src/pages/scans/ScanDetailPage.tsx` — delegates report categories, retains existing status/SSE/cancel/auth and summary panel integration.
- `src/pages/scans/VulnAdvisoryCard.tsx` — compact CVE/package/version facts with native keyboard disclosure. CRITICAL source flags, compatibility disclaimers, conflicts/unknown agreement and limitations remain visible when closed. Provenance, source text and independent CVSS assessments remain in details.
- `src/pages/scans/scan-detail-a1.css` — scoped report/pager/list/mobile/focus styling, wider desktop report column.
- `src/pages/scans/CursorReportPager.tsx` — independent atomic page confirmation, previous/next/range, pending lock, error-retains-confirmed-page/retry, cursor and row consistency checks, access/identity reset and abort.
- `src/pages/scans/ScanReportSections.tsx` — category adapters, truthful checked/failed/unsupported/unknown/zero states, target/report stamp validation and independent visibility/state.
- `tests-vite/ui/scans/reportPaging.test.tsx` — 29 focused tests, including actual ScanDetail scope remount, late-response abort, cursor loops, repeated IDs, report drift, independent pages, errors and access loss.
- `tests-vite/ui/scans/reportPaging.browser.mjs` — finite mocked actual-route Chromium script; 320/375/1280, keyboard/focus, disclosure, separate source scores/canonical links, pending/error/retry/back and overflow assertions.
- `docs/report-paging-task-39.spec.md` — FULL proposed OpenSpec body.
- `docs/report-paging-task-39.md` — this evidence/handoff.

## Behaviour and boundaries

Report rows are local to a keyed pager, not persisted in shared QueryCache. Each previous page is freshly GET-loaded from its stored cursor. A transition commits its data, index and cumulative actual row range together, only after validation. A normal failed transition preserves the previous confirmed rows and clearly labels the unsuccessful request. Changing scope, scan, saved target or provided report stamps destroys state and aborts pending work. Access loss hides old rows rather than retaining private data. Changed identity/count or a changed revisited page resets history; cyclic cursors, repeated IDs and empty continuations do not advance the range.

CVE/Secrets/SBOM each have their own pager and checked count. SBOM packages are never summed as CVE. Unknown/failed/unsupported do not become zero. The existing category control changes visibility (fixture filters explicitly concern the current page), not global severity sorting/filtering. No totalPages/random access/autoload-all is invented.

Identity uses only available API facts: scope/session generation, scan, digest/platform/imageReference, status/perCheck stamps and counts, report checkedAt/scanner/OS/DB and confirmed row identities. Secrets results do not expose a new reportVersion, so none is fabricated; the existing server authorization and status contract remain essential. The UI cannot prove immutability absent matching server evidence.

Canonical CVE.org/NVD and fixed FIRST links remain built by existing guards. Source text is React plaintext; no raw HTML/Markdown/registry code, secret values or source-provided URLs are introduced. Native details and existing local Button/Alert are used; no dependency/manifests/lockfile changes.

The summary panel and its independent cross-page citation verifier are unchanged. Mocked integration tests still confirm citations from a hidden category and later page. Browser tests intercept ALL API calls and abort nonlocal requests; there are no auth writes/scanner jobs/model calls or POSTs in the browser run. Unit summary tests use fake local responses only.

## Validation

Executed successfully:

```sh
pnpm exec vitest run tests-vite/ui/scans/reportPaging.test.tsx tests-vite/ui/scans/vulnAdvisoryCard.test.tsx tests-vite/ui/scans/llmSummaryPage.test.tsx tests-vite/ui/scans/llmSummary.test.tsx tests-vite/ui/scans/ScanPages.test.tsx --maxWorkers=1 --reporter=dot
# 5 files, 80 tests passed (29 new pager tests)
pnpm exec tsc -b --noEmit
pnpm exec eslint src/pages/scans/ScanDetailPage.tsx src/pages/scans/VulnAdvisoryCard.tsx src/pages/scans/CursorReportPager.tsx src/pages/scans/ScanReportSections.tsx tests-vite/ui/scans/reportPaging.test.tsx tests-vite/ui/scans/reportPaging.browser.mjs
pnpm build
node tests-vite/ui/scans/reportPaging.browser.mjs
# 320/375/1280px passed; no overflow, pageerrors or POSTs
git --no-pager diff --check
```

Generated screenshots (synthetic fixtures only): `test-results/task39-report-{320,375,1280}.png`, `test-results/task39-cve-{320,375,1280}.png`, `test-results/task39-cve-details-{320,375,1280}.png`. Actual baseline `test-results/scan-list-375.png` and produced mobile/desktop report crops were inspected. These tests do not assert live readiness, manual SR validation, Safari/Firefox, production performance or deploy.

Initial failures were corrected: a new test serialized an undefined QueryCache entry; the first browser fixture incorrectly included a strict-wire field on SBOM/CVE status. Legacy UI regression exposed duplicate coverage copy and nonchecked Secrets reload behaviour; compatibility was restored without transport edits. Final narrow suites pass.

## Spec and review handoff

- New bound document: `DIP-DOC-10` (`DIP-COMP-1`, `report-paging-ui`), registration baseline only.
- Full delta: `a7bf9545-9416-4b49-81a7-4e3052303f43`, source `DIP-TASK-39`, base v1, `state=proposed`, `review_status=pending`, **UNAPPLIED**.
- `validate_spec`: valid; ops add 11 requirements and remove none. DOC1/2/6/9 and all earlier deltas are untouched.
- `require_proposal_approval=false`, `spec_first=false`; no approval bypass or policy change. Parent decides acceptance/application/commit/deploy after independent correctness, security and spec reviews.

Author completes only the author work item and leaves TASK39 in testing. Exactly three independent review work items must be delegated to other agents; this author does not claim or judge them. TASK22/23/full plan and backend tasks are not closed.

## Concurrent / excluded changes

Peer28 owns `src/features/scans/{ScanScene,GlowEffect,MagicCard,scan-a1.css}`, its scene tests/docs and screenshots. Those paths changed concurrently, are not authored here and must not be included in this author's patch. Build/browser results describe the shared working tree at test time, not a solo isolated peer28 performance measurement. Backend AI owns `server/**`; no server file was edited here.

Four original foreign untracked notice files in `docs/notices/` and `public/notices/` are untouched. No private/auth data files were read, no LIVE calls or model/provider calls were made, no spec was applied, and no task was moved to done.

## Supplemental repair evidence — 2026-10-08 (not acceptance)

The sections above and DIP-ARTF-112 are historical author evidence, not updated acceptance claims. Read **FULL DIP-ARTF-117 v1 and DIP-ARTF-118 v1** before repairing their four medium findings. No completed author/review item was reclaimed; no review or synthesis item was claimed. Original independent correctness/spec outcomes remain `changes_requested`; original security approval remains historical, not approval of these repairs. Aggregate acceptance still requires supplemental independent rechecks by **ui39:correctness** and **ui39:spec**, then the parent's exact unclaimed verdict/synthesis step. TASK39 stays testing.

### Repair-only changed paths and finding mapping

- `src/pages/scans/CursorReportPager.tsx`: **C1** preserves metadata for every visited page, independent of displayed index. Replays compare cursor, start, ordered IDs and continuation; mismatch clears unsafe history and restarts retry at undefined cursor. Only earlier entries participate in overlap/cycle checks; no forward row payload or shared QueryCache persistence added. **C2** requires checked known-total terminal cumulative actual rows to equal total, and continuation cumulative rows to remain below total. Invalid sequence retains confirmed page/range and retries the failed cursor. Unknown-total/nonchecked coverage is not forced to equal a count.
- `src/pages/scans/ScanReportSections.tsx`: **C3** compares available checked Secrets scannerVersion against confirmed status; incompatible responses reset without publishing their rows, including after status-key remount. Missing status metadata is not invented. **S1** removes the empty-demo zero inference; only explicitly checked findingCount=0 displays zero. Absent/null count remains unknown with empty-current-page copy, never both unknown and zero.
- `tests-vite/ui/scans/reportPaging.test.tsx`: **15 additional regressions** (44 pager/category tests total): changed forward IDs and continuation after 1→2→1→2; unchanged replay; premature terminal, empty terminal with rows remaining, continuation after reaching total and valid retry completion; unknown-total empty/nonempty terminal and nonchecked coverage; first/post-status-reset Secrets scanner mismatch plus absent status version; demo absent/null/explicit-zero counts. Related old synthetic terminal fixtures now provide their actual totals (1 or 2); default 3 remains for three-row sequences and explicit null remains representable.
- `tests-vite/ui/scans/ScanPages.test.tsx`: only the existing empty-demo assertion is corrected to expect unknown plus empty-page copy and no zero claim. Existing fixture/transport is untouched. Existing current-page no-matches/reset test remains passing.
- `docs/report-paging-task-39.md`: this appendix only; previous handoff retained verbatim.

No further change to ScanDetailPage/advisory/CSS/browser runner/spec, peer28 source/tests/docs, server, shared transports, notices or dependencies. The spec delta `a7bf9545-9416-4b49-81a7-4e3052303f43` remains proposed/pending and **UNAPPLIED**, verified by list_doc_deltas. These repairs restore the already proposed identity/sequence/truthful-count contract; they do not rewrite or supersede the pending proposal and create no duplicate delta.

### Red → green and exact validation commands

Before production fixes, the selected new/updated regressions returned **9 failures, 1 pass, 52 skipped** across two files, reproducing all four findings. The explicit-zero control passed. This is intentional red evidence, not a final failing suite.

```sh
node --input-type=module -e 'import { startVitest } from "vitest/node"; const ctx = await startVitest("test", ["tests-vite/ui/scans/reportPaging.test.tsx", "tests-vite/ui/scans/ScanPages.test.tsx"], { run: true, watch: false, maxWorkers: 1, cache: false, reporters: ["dot"], testNamePattern: "preserves forward fingerprints|rejects .*terminal|rejects continuation at confirmed total|rejects initial Secrets scanner|rejects stale Secrets scanner|demo empty Secrets count|keeps an empty checked demo" }, { envDir: false }); process.exitCode = ctx?.state.getFiles().some(file => file.result?.state === "fail") ? 1 : 0; await ctx?.close();'
```

After fixes, the final post-format run returned **5 files / 95 tests passed** (5.53s); it includes existing advisory/citation tests and current-page filter reset. All APIs/provider responses are mocked; Vite envDir=false prevents environment-file loading.

```sh
node --input-type=module -e 'import { startVitest } from "vitest/node"; const ctx = await startVitest("test", ["tests-vite/ui/scans/reportPaging.test.tsx", "tests-vite/ui/scans/ScanPages.test.tsx", "tests-vite/ui/scans/vulnAdvisoryCard.test.tsx", "tests-vite/ui/scans/llmSummaryPage.test.tsx", "tests-vite/ui/scans/llmSummary.test.tsx"], { run: true, watch: false, maxWorkers: 1, cache: false, reporters: ["dot"] }, { envDir: false }); process.exitCode = ctx?.state.getFiles().some(file => file.result?.state === "fail") ? 1 : 0; await ctx?.close();'
pnpm exec prettier --write src/pages/scans/CursorReportPager.tsx src/pages/scans/ScanReportSections.tsx tests-vite/ui/scans/reportPaging.test.tsx
pnpm exec tsc -b --noEmit
pnpm exec eslint src/pages/scans/CursorReportPager.tsx src/pages/scans/ScanReportSections.tsx tests-vite/ui/scans/reportPaging.test.tsx tests-vite/ui/scans/ScanPages.test.tsx
node --input-type=module -e 'import { build } from "vite"; await build({ envDir: false });'
git --no-pager diff --check -- src/pages/scans tests-vite/ui/scans/ScanPages.test.tsx
```

Typecheck/lint/build/diff check passed. An initial typecheck caught widened `status: string` in the new demo test; explicit Promise<ScanResults> annotation fixed it. No unrelated diagnostics were suppressed. Build transformed 2298 modules (1.88s). Build/typecheck/browser describe the shared working tree; they are not isolated claims about peer28, backend acceptance or performance.

Mocked actual-route Chromium rerun: **320/375/1280px PASS**, including independent pages, pending/error/retry/back, keyboard disclosure/filter focus, canonical URLs, no horizontal overflow, no pageerrors and no POST. The existing script is executed in memory with envDir=false and a new screenshot prefix, without modifying that script or overwriting original screenshots:

```sh
node --input-type=module -e 'import { readFile } from "node:fs/promises"; const source = (await readFile("tests-vite/ui/scans/reportPaging.browser.mjs", "utf8")).replace("createServer({ server:", "createServer({ envDir: false, server:").replaceAll("test-results/task39-", "test-results/task39-repair-"); await import("data:text/javascript," + encodeURIComponent(source.replace("from \u0027@playwright/test\u0027", "from " + JSON.stringify(import.meta.resolve("@playwright/test"))).replace("from \u0027vite\u0027", "from " + JSON.stringify(import.meta.resolve("vite")))));'
```

New screenshots: `test-results/task39-repair-{report,cve,cve-details}-{320,375,1280}.png`. Inspected actual new 320px CVE and 1280px details images: headline/conflict/CRITICAL-source facts remain visible; details retain independent scores and keyboard outline. These browser checks are compatibility checks; the four repair findings are covered by the focused regressions above. No LIVE, manual screen reader, Safari/Firefox or deploy claim.

### SHA-256 — before → repaired snapshot

Paths relative to startup/diplom. Full historical snapshots remain in DIP-ARTF-117/118; this table appends the changed snapshot, not replaces it.

| Path | Before | After |
|---|---|---|
| src/pages/scans/CursorReportPager.tsx | d997008bb43bf1b983ce9a4ca0ed66a569cbf957b57a3424b51fcc3a43321ced | 857d52cbb6778013f7389b3dcd40dbe9716de471f0fd1ad69708cd733b03ecb6 |
| src/pages/scans/ScanReportSections.tsx | 1cdb1e7fb4632ad3ee83d4f8cd49342c69ae1d8378b4ae4cd01f62596ffd742e | 077d0dcf71da1f749a50dbf5b011d7e8883d40c175507918816d62480a1250d5 |
| tests-vite/ui/scans/reportPaging.test.tsx | c338839a165d7a9f22602c7d61d5fabdcccf3c08a7ee0c16ade78d4433f7bcaa | 97764ea54989faaeb70b105172c56e63489386d1b24114d3e6d538ee7aac4a88 |
| tests-vite/ui/scans/ScanPages.test.tsx | 6dba0aaaf481b8c23c65e60a69b4091f7103ecebd1a7fe1a6621c6dfa50e6e78 | 1db0427f8ad1a7544c848a37b4e7667ac6a362aa5cb936fc847d45a5f67a8c52 |

Handoff doc pre-append SHA-256: `3a55d07942bc144acef0e0a2b148912f0b985cc3f102a7210a93bd6ba170f5f5`; post-append hash belongs in the new supplemental artifact (no self-referential hash).

Peer28 starting/ending hashes match exactly: ScanScene `73e3336320c5e0368a128b514b39cedb98846f0c887694d46e7b25a4ac770a2f`, GlowEffect `8388be36fec36c92eab2939563f50ee835ca6c8fdbb4d59f6a0f919297b5df71`, MagicCard `03b7d479700e95375fca65861bd997d03a1b9899c26e83f4454a59efb13c5b67`, scan-a1.css `144f753de745af2d9f3076a2833e8d563590450a656877dec0c716d1c0e350a8`. No peer28 edit or attribution of their changes.

Final handoff: new supplemental artifact only, preserving DIP-ARTF-112/116/117/118. Parent resumes the same independent correctness/spec reviewers; author does not approve repairs, rewrite review outcomes, claim verdict, apply spec, commit or close TASK39.

## Supplemental C4 repair — 2026-10-08 (awaiting independent recheck)

Read **FULL DIP-ARTF-121**. Its independent correctness recheck confirms C1/C2/C3/S1 repaired on the ARTF119 snapshot but remains `changes_requested` for C4: same IDs/cursors/report metadata did not detect changed normalized content. The earlier sections, ARTF119, original artifacts and all reviewer outcomes remain historical and unchanged. Supplemental spec approval recorded in DIP-ARTF-120 applies to its reviewed snapshot, not author acceptance of C4.

### C4-only changed paths and behavior

- `src/pages/scans/reportRowFingerprint.ts` (new owned UI utility): synchronous canonical encoding of complete typed normalized row arrays, not IDs/headline-only projections or raw HTTP envelopes. Keys sort recursively with deterministic code-unit order; arrays retain order, null and field states retain meaning, absent/undefined optional object properties are equivalent. The per-page encoding is bounded to 2MiB UTF-16 code units with nesting capped at32; overflow rejects rather than truncates/strips facts. No async crypto, dependencies, global cache, localStorage or logs. Existing wire normalization/redaction remains upstream and unchanged; this encoder is not a new sanitizer or server reportVersion.
- `src/pages/scans/ScanReportSections.tsx`: all category adapters supply mandatory rowFingerprint from complete normalized CVE findings, Secrets findings and SBOM components. Severity/fix/installed/package/CVE/provenance, all source assessments/title/description/CVSS/states/versions/language, conflicts and limitations remain in the encoding and continue rendering unchanged. Unrelated raw transport-envelope fields are not fingerprinted. Nonchecked rows use the empty normalized array; existing outcome/count/scanner/target identity checks remain intact.
- `src/pages/scans/CursorReportPager.tsx`: every local visited entry retains immutable canonical rowFingerprint alongside cursor/start/ordered IDs/continuation. Back and forward replays compare before committing. Same-metadata/same-ID content drift throws an identity-error subtype; no rejected content publishes. Per explicit repair request, only this content-replay error retains the last confirmed payload/index/range, clearly labeled as the prior snapshot whose replay was not confirmed. All stored visited entries are cleared, the active confirmation baseline is null, both navigation controls are disabled, and retry starts undefined cursor. Retry failure still retains/labels that prior view; a successful first page establishes a fresh baseline. Access loss, scope/session/scan/status remount and metadata identity errors still clear rows; no shared QueryCache payload was introduced.
- `tests-vite/ui/scans/reportPaging.test.tsx`: **9 new focused tests** (53 tests in this file). Two direction tests each exercise13 CVE mutation dimensions with constant IDs/report metadata/cursor: severity/fix, package/installed version, CVE ID, row provenance, source severity/fix, source title/description, text state/redaction, source provenance, CVSS, language, contributors, conflicts and limitations. Also: reordered-key stable Back+forward positive control; canonical nested-key/undefined/null/array-order and size-budget tests; Secrets same-ID Back/forward each changing ruleId/severity/category; retained-view access-loss and scope-reset controls. CVE drift tests verify identical last-confirmed DOM/range, disabled navigation, offline first-cursor retry retention and successful first-cursor recovery. 26 CVE +6 Secrets content-drift scenarios are exercised inside these parameterized tests.
- `docs/report-paging-task-39.md`: this additional appendix only. No changes this round to ScanPages, advisory/detail/CSS/browser runner/local spec, peer28/server/shared transports/dependencies/notices.

### C4 validation (not the full95 suite)

Intentional red before production changes: selected C4 tests **2 failed,1 passed,44 skipped**. Both Back and forward same-ID drift published changed rows without the expected rejection; stable-repeat control passed. Exact red command:

```sh
node --input-type=module -e 'import { startVitest } from "vitest/node"; const ctx = await startVitest("test", ["tests-vite/ui/scans/reportPaging.test.tsx"], { run: true, watch: false, maxWorkers: 1, cache: false, reporters: ["dot"], testNamePattern: "C4" }, { envDir: false }); process.exitCode = ctx?.state.getFiles().some(file => file.result?.state === "fail") ? 1 : 0; await ctx?.close();'
```

Final scoped validation: **one file /53 tests PASS** (2.99s), including prior paging/identity/access/error regressions. Typecheck and targeted lint passed with no warnings; a temporary Fast Refresh warning from exporting the encoder with the component was resolved by the owned utility split, not suppression. Exact final command sequence:

```sh
pnpm exec prettier --write src/pages/scans/CursorReportPager.tsx src/pages/scans/ScanReportSections.tsx src/pages/scans/reportRowFingerprint.ts tests-vite/ui/scans/reportPaging.test.tsx
pnpm exec tsc -b --noEmit
pnpm exec eslint src/pages/scans/CursorReportPager.tsx src/pages/scans/ScanReportSections.tsx src/pages/scans/reportRowFingerprint.ts tests-vite/ui/scans/reportPaging.test.tsx
node --input-type=module -e 'import { startVitest } from "vitest/node"; const ctx = await startVitest("test", ["tests-vite/ui/scans/reportPaging.test.tsx"], { run: true, watch: false, maxWorkers: 1, cache: false, reporters: ["dot"] }, { envDir: false }); process.exitCode = ctx?.state.getFiles().some(file => file.result?.state === "fail") ? 1 : 0; await ctx?.close();'
git --no-pager diff --check -- src/pages/scans tests-vite/ui/scans/ScanPages.test.tsx
```

Vitest envDir=false/cache=false; all API data synthetic/mocked, no model calls. Full95 suite/build/browser not rerun for this narrow repair; their earlier results are historical. No new screenshot or LIVE readiness claim.

### C4 snapshot — SHA-256 before → after

```text
src/pages/scans/CursorReportPager.tsx
  857d52cbb6778013f7389b3dcd40dbe9716de471f0fd1ad69708cd733b03ecb6
  243c73f9ee8e100dc026ceeec487b6eadb6d36d0a16f4fa8ced41f5d544f5ffb
src/pages/scans/ScanReportSections.tsx
  077d0dcf71da1f749a50dbf5b011d7e8883d40c175507918816d62480a1250d5
  998a4aabd626ef1057c8c552bfe95b1039cd2f3dfbfaca66637938b8757f78fb
src/pages/scans/reportRowFingerprint.ts
  NEW (no prior file)
  2477d2b465dd0625f8065c01236190dd283ce2ad8a8d09e661bb844f659d9b19
tests-vite/ui/scans/reportPaging.test.tsx
  97764ea54989faaeb70b105172c56e63489386d1b24114d3e6d538ee7aac4a88
  5b9aea1848a5babf1ab19d6266c567d836b8eacd8488d237139b296e820108de
```

Doc pre-C4 appendix hash: `22e90ae77e55dd66c3cc5726e62faca3bbb58adc6bb7ba7d98bfa4d8dc1cd7e2`; new artifact records final doc hash. ScanPages remains `1db0427f8ad1a7544c848a37b4e7667ac6a362aa5cb936fc847d45a5f67a8c52`, local spec remains `26e874f9abb58a9ca8cc7b60f58da013ad1b4310acd5bfea46c3a75f214ab2b4`. All four peer28 source hashes again match this session's initial values exactly.

**Independent handoff:** parent resumes `ui39:correctness` for C4 recheck. Because this requested content-replay retention path differs from the prior all-identity-errors-clear behavior and the fingerprint contains normalized row text locally, also request `ui39:security` to independently verify local lifetime, access/scope clearing and retained-view boundaries. Neither is self-approved. No old work reclaimed/recompleted or review/verdict claimed, no originals rewritten, no provider/LIVE/private access, commit, spec application or task closure. Pending DOC10 delta remains untouched/unapplied; TASK39 remains testing.

## SPEC-39-C4-DOC1 alignment — 2026-10-08 (documentation only)

Read **FULL DIP-ARTF-123**, full original pending DOC10 delta, current DOC10 v1 registration baseline and raw local proposed spec. Independent spec finding is a medium blanket-reset/retention contract mismatch; requested code behavior is retained, with **no rollback or code/test changes**. Earlier handoff sections/artifacts/delta statuses describe their historical snapshots and are preserved, not rewritten as current acceptance.

### Exactly two local documentation paths changed

- `docs/report-paging-task-39.spec.md`: only Requirement «Сброс идентичности и доступа» and its scenarios are revised. Strictly clear all visible/retained rows, active confirmation and history on lost access or changed subject/session generation/scan/target/provided report identity or metadata, explicitly including checkedAt/count/scannerVersion and any historical snapshot. The sole content-only replay exception requires the same authorized context, target, report metadata, ordered finding IDs, cursor and continuation; reject incoming payload, retain exactly the last confirmed snapshot with historical/stale/current-response-uncertainty labeling, attribute its old rows/page/range/count only to that snapshot, reset active confirmation/all cursor stacks, disable navigation and retry first cursor. Added GIVEN/WHEN/THEN scenarios cover Back/forward content-only drift, ordinary recovery-retry failure retaining the same stale view/first-cursor attempt, and confirmed first-page recovery establishing a new baseline/removing stale labeling. Existing reset/access scenarios now explicitly clear retained snapshots as well. No change to any other requirement, Purpose or Non-goals.
- `docs/report-paging-task-39.md`: this append-only alignment record.

### Delta supersession — preserve history, do not mutate pending text

- Old **`a7bf9545-9416-4b49-81a7-4e3052303f43`**: was proposed/pending, so update_doc_delta was not permitted and not attempted. Per explicit request, `discard_doc_delta` recorded it as **discarded**, preserving its full old body/history; not deleted, edited, human-rejected or applied. Supersession reason names DIP-ARTF-123/SPEC-39-C4-DOC1 and the missing narrow same-context content-only retention exception.
- New **`f1c3d491-ccf7-4aef-a960-fd10f5276368`**: FULL revised body proposed against **DIP-DOC-10 v1**, source **DIP-TASK-39**, existing **DIP-COMP-1** binding. Returned **state=proposed, review_status=pending**, **UNAPPLIED**. Current DOC10 baseline is not overwritten.
- `validate_spec` on the final full body against DOC10 returned **valid:true** before supersession/proposal; no reported format issues. Whole returned body and ops inspected. All **12 requirement names retained**, now **18 scenarios**. Server ops are relative to the current registration baseline, not the discarded proposal: **11 added, zero removed, zero renamed, zero changed**. Existing «Фактическая граница отчёта» remains unchanged.

Verified ops (`kind=added` for every item):
1. Независимые последовательные страницы
2. Подтверждённый номер и диапазон
3. Ошибка перехода с сохранением данных
4. Сброс идентичности и доступа
5. Непротиворечивая последовательность
6. Отдельные достоверные итоги
7. Компактные факты CVE
8. Отдельные оценки и ограничения
9. Безопасные тексты и ссылки
10. Доступное чтение без вымышленного доступа
11. Независимость ИИ-источников

### Preservation / document hashes

- Local spec before: `26e874f9abb58a9ca8cc7b60f58da013ad1b4310acd5bfea46c3a75f214ab2b4`.
- Local FULL revised spec after: `a6c82a86ecfd968a879e1ad750ad879953254cfdd985274c70af5b78cb5dfed9`.
- SHA-256 of the exact concatenated prefix/suffix outside the reset requirement block, before **and** after: `8c5f5cb4a85033e2d5a98c558c853e81392ea9a5fa84460b8c52603b76d9ab5d` — byte-preservation PASS for all other requirements/Purpose/Non-goals.
- Handoff pre-alignment-append SHA-256: `f5529dbb4ba2a5b49d019074a019a153c01af19884150eabd6ccf4ddad5a2e6f`; final hash recorded in the new supplemental artifact, avoiding a self-referential hash.
- Spec whitespace check PASS. This is document preservation/format verification, not a code test rerun. No test/typecheck/lint/build/browser repeats performed.

**Parent handoff:** give new delta **`f1c3d491-ccf7-4aef-a960-fd10f5276368`** and the new evidence artifact to the same independent **ui39:spec** reviewer. Historical SPEC-39-C4-DOC1 verdict remains changes_requested until independent recheck; author makes no approval/conformance verdict. No code or peer28/backend/shared/private/notice changes, no LIVE/provider/model calls, commits, spec application, task close or harness verdict/review claim. TASK39 remains testing; new delta remains UNAPPLIED.
