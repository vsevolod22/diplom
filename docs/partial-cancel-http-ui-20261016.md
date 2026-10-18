# Partial cancellation — HTTP/UI integration handoff

Implementation/validation: 2026-10-17. Requested filename retains 20261016.

## Implemented behavior

- `src/pages/scans/ScanReportSections.tsx`: `cancelled` is now a terminal state eligible to display saved per-check results. Previously CVE/SBOM never loaded for cancelled scans and the Secrets identity check rejected checked cancelled results. Existing target/version/count/evidence checks and cursor validation remain in place.
- Only checks with a confirmed `perCheck` outcome load report pages. Missing cancelled results say that no completed result was saved and counts are unknown, rather than indefinitely waiting or implying a checked zero.
- `src/pages/scans/ScanDetailPage.tsx`: confirmation and explanatory copy describe retained durable completed checks. Terminal copy reads **«Сканирование отменено. Сохранены результаты завершённых проверок.»** and explicitly does not claim all requested checks completed. The no-checkpoint variant instead says no completed results were saved. Unknown checks and stopped realtime are described as cancelled, not successfully completed.
- `src/shared/api/scans/scanTransport.ts`: a legacy Secrets response with `coverage: null` and an empty terminal page now maps to an absent result (`coverage: []`), not a fabricated `skipped` outcome. Rows/cursors without coverage are rejected. A real checked-zero result remains checked zero.
- `server/api/src/scans/scans.config.http.test.ts`: aligned the existing synthetic database version assertion with the backend checkpoint migration, v15 (was v14); no migration code changed.

### HTTP projection audit: already cancellation-compatible

No production server projection change was needed. `scans.service.ts` already reads existing durable result tables regardless of terminal scan state:

- `status`: saved per-check results survive; requested but missing results are `null`, not checked zero. Multi-check legacy `result` remains `null`.
- `report-v1`: saved datasets load via the normal snapshot/hash/cursor implementation. Missing datasets return 404, not a fabricated empty checked report.
- Legacy Secrets: owner-known scan with no rows/result returns `{ findings: [], nextCursor: null, coverage: null }`. Empty rows alone do not prove coverage. Missing SBOM/CVE return 404.
- Archive envelopes can contain only checkpointed keys; HTTP exposes the saved subset and leaves missing requested per-check coverage null.
- SSE emits terminal cancellation and closes; replay after the terminal event ID contains no further scan events. SSE remains a hint; the UI obtains status and reports through GET.

`httpScanTransport.ts` and `reportView.ts` needed no changes. No new public report schema, status, cancellation outcome, or report-version algorithm was introduced.

## Added verification

### Actual HTTP + temporary ledger + actual strict browser parsers

New `server/api/src/scans/scans.partial-cancel.http.test.ts` runs a real Nest application/auth/SQLite on loopback with temporary database files. It dynamically imports the actual browser parsers (without pulling browser source into server-only production typechecking).

The test creates **10 ordinary/archive cases**: no checkpoint, Secrets-only, SBOM-only, CVE-only and all three saved. It also creates **2 independent config cases**, with/without a completed config checkpoint. Scanner outputs/OCI config bytes are synthetic; checkpoint persistence and cancellation are real.

Verified:

- Checkpoints are not public while running; foreign cancellation is rejected; owner HTTP cancellation is idempotent; late checkpoint/finalization cannot replace terminal results.
- Status, legacy and report-v1 endpoints through both cookie/browser and JWT routes, plus anonymous/foreign access fences.
- Every page of each saved 12-row dataset (limit 5), strict production decoding, unique complete traversal and correct total/matched counts.
- Missing archive result properties are actually absent in the stored archive reader, not synthesized; missing HTTP coverage stays null.
- No-checkpoint/null Secrets report is absence; missing report-v1/SBOM/CVE return 404.
- Ordinary and archive CVE v2 policy/DB evidence round-trips through strict parsers.
- Repeated reads are equal; after closing/restarting the API against the same **temporary** DB, first pages (including opaque cursor/version-bound identity and historical timestamps) are equal and traversal still succeeds.
- SSE replay contains exactly queued/running/cancelled; terminal cursor reconnect has no new scan event; event streams respect ownership.
- Selected config checkpoint survives cancellation/reopen independently; missing config stays absent, not skipped.

### UI/transport

Changes to `tests-vite/ui/scans/`:

- `reportViewControls.test.tsx`: cancelled all-three datasets, independent pagination/remount, each saved subset, no-checkpoint/no requests, and a completed failed checkpoint retaining unknown count.
- `liveScans.test.tsx`: real UI button/transport flow with synthetic HTTP responses, SSE-hint-to-authoritative-GET refresh, retained saved rows, explicit cancellation copy, stopped stream, absent sibling requests, remount and no-checkpoint copy.
- `scanTransport.test.ts`: absent null report vs checked-zero; reject orphan rows/cursors; cancelled checked/unknown mixed status.
- `configScans.test.tsx`: saved/missing config on cancelled detail, independent unknown Secrets, no invented report requests.

Pre-existing dirty test changes were preserved; additions do not replace their earlier cases.

### Disposable real browser

Extended the pre-existing dirty `tests-e2e/report-live-api.mjs`, preserving its completed-report/filter/sort/access tests. Seeds real durable checkpoints for an ordinary scan (Secrets+CVE), an archive scan (SBOM) and a no-checkpoint scan, leaves them running, and cancels each through the real UI button/HTTP POST.

Chromium verifies retained saved datasets through all three pages (25/25/11), unknown siblings, status/realtime/copy, SSE cancellation, reload and anonymous/foreign endpoint denial. HTTP responses are not mocked. Auth/ledger/cache are disposable; browser non-loopback egress is blocked. The original completed-report case still verifies filters, sorting, all supported limits and logout.

## Initial validation (before the R1–R4 re-review)

Commands were run sequentially across API/UI/browser phases; no full UI/API suites ran concurrently.

From `server/api`:

```sh
pnpm exec tsx --test src/scans/scans.partial-cancel.http.test.ts src/scans/scans.cancel.http.test.ts src/scans/scans.report.http.test.ts src/scans/scans.archive.http.test.ts src/scans/scans.config.http.test.ts src/scans/scans.events.http.test.ts src/scans/scans.events.test.ts src/scans/report-service.test.ts src/scans/report-page.test.ts
pnpm exec tsc --noEmit
```

**30 tests passed; 0 failed/skipped/cancelled. API typecheck passed.** The new matrix is one Node test containing the 12 scenarios above.

From repository root:

```sh
pnpm exec vitest run tests-vite/ui/scans/reportViewControls.test.tsx tests-vite/ui/scans/liveScans.test.tsx tests-vite/ui/scans/scanTransport.test.ts tests-vite/ui/scans/reportViewContract.test.ts tests-vite/ui/scans/reportPaging.test.tsx tests-vite/ui/scans/configScans.test.tsx
pnpm exec tsc --noEmit --incremental false
node tests-e2e/report-live-api.mjs
```

**253 tests passed across 6 UI files; no skips. Frontend typecheck passed.** Chromium **147.0.7727.15** integration passed in **16.102 s**: 121 original report-page receipts plus the three added cancellation scenarios; **0 browser errors, 0 external browser requests, no mocked HTTP**. Cleanup verified API exit code 0, browser/listeners closed and temporary SQLite/cache removed.

Intermediate issues fixed before these final results: an invalid empty late-finalization fixture (replaced with valid failed outcomes), a Playwright assertion using a data helper rather than a Locator, TypeScript inference for the new config-case array (explicit type added), and the stale v14 assertion in the existing config HTTP test. No failing validation remains in the listed commands. Scoped `git diff --check` and explicit checks of both new files passed. Full UI/API suites and deployment qualification were not run.

## Boundaries and follow-up

Writes are restricted to the permitted scans HTTP/UI/transport/test paths and this document. No ledger/worker/runtime/bootstrap/configuration/deployment changes; no tracker, commits, staging, branches, Docker, live scanner/DB acquisition, private keys or existing application state. Temporary synthetic files alone were opened/migrated during this work.

This closes the HTTP/UI integration slice, **not release acceptance**. The initial backend request-changes disposition has been superseded: `docs/partial-cancel-independent-review-20261016.md`, section **Independent re-review after R1–R4 fixes — 2026-10-17**, independently APPROVES the revised R1–R4 paths. HTTP/UI integration has now been rerun against those changes, as recorded below. Migration/rollback approval, old-writer shutdown, full-suite coordination and live qualification remain separate follow-up work.

## Current revalidation after independently approved R1–R4 fixes — 2026-10-17

### Changes in this follow-up

Only `tests-e2e/report-live-api.mjs` and this handoff were edited in this follow-up. Pre-existing concurrent changes, including token-aware HTTP fixture callers, were preserved. No production HTTP/UI changes were necessary; no ledger/worker/runtime/OCI source or fixture was modified. OCI fixture fixes were reported by the coordinator; the OCI suite itself was not rerun here.

- Updated the remaining Chromium completed-report seed to call `finishCombined(scanId, attempts, outcomes, undefined, job.leaseToken)`, passing the original claim token as the mandatory last argument.
- Kept all existing completed-report and three cancellation scenarios; added a fourth cancellation scenario using the **real `consumeOne`**, actual SQLite checkpoint writes and a narrowly scoped failure trigger in the new disposable database. Archive/scanner output remains injected synthetic data, not live acquisition.
- Verified both HTTP and actual browser access restrictions for **each cancelled scan**: another enrolled owner gets 404 and the UI error with no report sections; anonymous access gets 401/login-required with no report sections.

### Storage-error honest boundary

The new browser fixture creates a running archive job requesting Secrets/SBOM/CVE. The real consumer commits 61 positive Secrets findings through its checkpoint callback. A temporary SQLite trigger rejects only the SBOM checkpoint INSERT for that scan with `SQLITE_CONSTRAINT_TRIGGER` / `SYNTHETIC_STORAGE_CANARY`.

Assertions confirm:

1. `consumeOne` rejects with the original storage exception, rather than synthesizing `SCAN_FAILED` outcomes or returning a successful scan.
2. State remains `running`, public archive/Secrets results remain absent, events remain exactly queued/running, and the checkpoint table contains only Secrets.
3. Before user cancellation, real HTTP status reports null per-check coverage and the browser shows no report rows or checked-zero/failure totals. Raw storage error text does not appear in the UI.
4. After removing the test trigger, clicking the real cancellation button succeeds. Status becomes `cancelled`; saved Secrets alone are retained. SBOM/CVE stay absent/unknown, not failed or checked zero.
5. All saved Secrets pages (25/25/11), reload, SSE and both HTTP/UI owner fences pass. SSE contains exactly one cancelled event and no fabricated completed/failed event or raw storage canary.

This is deterministic checkpoint-write fault injection against a freshly created temporary DB. It is **not** a disk-full/locking stress test or a cancellation-publication-error test; no new storage-error HTTP outcome was introduced.

### Commands and results on current bytes

Executed in separate sequential phases, never full suites:

```sh
# From server/api — invocation timeout 60 s
pnpm exec tsx --test src/scans/scans.partial-cancel.http.test.ts src/scans/scans.cancel.http.test.ts src/scans/scans.report.http.test.ts src/scans/scans.archive.http.test.ts src/scans/scans.config.http.test.ts src/scans/scans.events.http.test.ts src/scans/scans.events.test.ts src/scans/report-service.test.ts src/scans/report-page.test.ts
pnpm exec tsc --noEmit

# From repository root — combined UI/typecheck invocation timeout 90 s
pnpm exec vitest run tests-vite/ui/scans/reportViewControls.test.tsx tests-vite/ui/scans/liveScans.test.tsx tests-vite/ui/scans/scanTransport.test.ts tests-vite/ui/scans/reportViewContract.test.ts tests-vite/ui/scans/reportPaging.test.tsx tests-vite/ui/scans/configScans.test.tsx
pnpm exec tsc --noEmit --incremental false

# From repository root — invocation timeout 220 s, script-owned deadline 180 s
node tests-e2e/report-live-api.mjs
```

| Check | Final observed result |
| --- | --- |
| Focused HTTP/report/SSE tests | **30 passed**, 0 failed/skipped/cancelled; 4.691 s |
| API typecheck | Passed, exit 0 |
| Six focused UI/transport files | **253 passed**, no skips; 43.66 s |
| Frontend typecheck | Passed, exit 0 |
| Disposable Chromium 147.0.7727.15 | **PASS**, 20.326 s; 121 original completed-report page receipts plus four cancellation scenarios |
| Browser safety/cleanup | 0 page errors; 0 external requests; no mocked HTTP; API exit 0; browser/listeners closed; temporary SQLite/cache removed |

All previous matrix assertions (ordinary/archive/config saved subsets, no-checkpoint/null report, all legacy/report-v1 pages, immutable terminal cursor/response after API reopen, owner access and SSE) passed on the revised backend.

One intermediate browser fixture failure was observed and corrected: eagerly seeding a fourth active scan hit the real per-owner `AdmissionLimited` guard before readiness. No limit was bypassed or changed. The fourth fixture is now created over the test process's private IPC **after** the first three scans are cancelled. Both subsequent browser runs passed; the final run additionally includes cancelled-page foreign/anonymous UI navigation. The failing attempt also removed its disposable databases and closed its listeners.

No failing validation remains in the commands above. No stand, existing/live DB, private key, Docker, tracker, commit/stage/branch, or live scanner was used.

### Validated source fingerprints

SHA-256 captured after validation. The seven production hashes below were unchanged across the final browser rerun; the test harness hash is the final extended file. These identify this working-tree snapshot without committing or staging it.

```text
e5d30ab9a40964908e53a7c8fa375993198714ad1f7393146ad9887fb68bf858  server/api/src/ledger/ledger.ts
561739bb5e752027080ef03bfcb881c37601ea702f37934034e99b4f9da56786  server/api/src/worker/outbox-consumer.ts
50b52e2cbdb6f1b14298dc8e6b8c62832ca65403e990da07e12cb587bcba3886  server/api/src/worker/archive-result-contract.ts
d33bb619c963aa9adab68f5734f9ca1a5ad7717bec0ce5b28065fa302959ef17  server/api/src/worker/archive-scan-worker.ts
9f2570a7c898f0b75fab0eb16b0984868e1bfdaaf2a808bd57d56b31eb83ccfb  src/pages/scans/ScanReportSections.tsx
0e1a85889cfece295b0df2abb5057a445063f6359b8a14e9624910bca2f1831f  src/pages/scans/ScanDetailPage.tsx
f6a4c044ae5d3ed5f1137ddfd9f3bb6105a7e218c0dd52a50ce890c414606002  src/shared/api/scans/scanTransport.ts
338299611d1034bfae6a66a4d6fadb2e0c05bdd8b2b1e69811073221b5a64f2b  tests-e2e/report-live-api.mjs
```
