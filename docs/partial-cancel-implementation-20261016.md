# Durable partial cancellation — ledger/worker implementation handoff

Implementation date: 2026-10-17. Requested handoff filename retains 20261016.

## Scope and disposition

Implemented the selected durable-checkpoint design for the TASK2/6 ledger/worker slice. This is **not full TASK2 acceptance**, a production qualification, or a spec approval. HTTP, DTO/transport, report assembly/pagination, SSE client handling, UI and tracker/spec changes belong to the coordinator.

Implementation writes are confined to `server/api/src/ledger/**`, `server/api/src/worker/**`, and this new document, plus the explicitly permitted necessary signature-call updates in the 16 external test/seed files listed below for the R1–R4 revision. No external production files or qualification scripts were edited. The pre-existing untracked `worker/secrets-publication-boundary.test.ts` was preserved; its cancellation characterization and original-claim token calls were deliberately updated. Other dirty/concurrent work was not reverted. No tracker mutations, Docker/live scanners, existing application database opens/migrations, old `.local-auth`, keys/holders/HOLD access, commits, staging or branches were used. Tests use disposable synthetic databases and fixtures.

## Implemented behavior

- Scan state remains **`cancelled`**, even if some or all requested checks have durable checkpoints. No new public state or per-check outcome was invented.
- The worker commits each complete, validated, sanitized, bounded check result independently. A checkpoint is **not** a public running report: normal readers remain unchanged until terminal publication.
- `cancel(scanId, subject)` publishes the eligible checkpoint snapshot, sets terminal cancellation, acknowledges outbox/revokes its lease token, and inserts one terminal event in **one `BEGIN IMMEDIATE` transaction**. Any publication/state/event failure rolls everything back.
- If the checkpoint commits first, cancellation preserves it. If cancellation commits first, new checkpoints/finalization return false. Final completion winning first still makes cancellation return `conflict`.
- Checkpoints bind the ledger-derived owner, entire pinned job, scan ID, attempt, random per-claim lease token, check name, payload kind, commit time and a SHA-256 integrity digest. The digest detects inconsistent stored bytes; it is not an authentication mechanism against a hostile database administrator.
- New writes require a running/current attempt, exact claim identity, undelivered outbox, non-revoked token and `lease_until > clock`. Equality is expired. Ordinary/archive finalization and legacy finalizers also enforce live leases. `attemptActive` now returns false after retry revocation or wall-clock expiry.
- `retry()` clears the token/lease and removes checkpoints. A replacement claim gets a new token/attempt and removes old checkpoints. Old and new attempts never contribute to one cancellation report.
- **Expiry semantics:** expiration prevents new writes, but cancellation may preserve a previously committed checkpoint of the still-current, non-revoked token even after lease expiry. Expiry alone does not erase historical completed evidence. Retry/replacement does revoke that eligibility. This permits cancellation after a worker crash without treating an expired worker as authorized to publish new results.
- Owner checks precede cancellation publication. Stored owner/target/policy inconsistencies fail closed. Other owners cannot read results.
- No checkpoint/no completed check remains **absent/unknown**. It is not a checked zero, fabricated timeout, unsupported result or newly synthesized failure. A genuinely completed failed/unsupported check retains its existing contract outcome.

## API shape for the coordinator

Internal worker/ledger API (not HTTP DTOs):

```ts
// claim returns Job with a fresh leaseToken. Job's field is optional at the type
// level for existing manually-constructed scanner jobs; checkpoints require it.
ledger.claim(now?, leaseMs?, archiveLeaseMs?): Job | undefined

// Mandatory final caller-token argument; undefined is accepted by the type
// because Job.leaseToken is optional, but is refused at runtime.
ledger.finish(scanId, attempts, state, errorCode, leaseToken): boolean
ledger.finishWithResult(scanId, attempts, findings, scannerVersion, leaseToken): boolean
ledger.finishWithSbom(scanId, attempts, sbom, scannerVersion, leaseToken): boolean
ledger.finishWithVuln(scanId, attempts, image, findings, scannerVersion, leaseToken): boolean
ledger.finishCombined(scanId, attempts, outcomes, config, leaseToken): boolean
ledger.finishArchive(scanId, attempts, report, config, leaseToken): boolean
ledger.retry(scanId, attempts, nextRunAt, leaseToken): boolean
ledger.attemptActive(scanId, attempts, leaseToken): boolean

ledger.checkpointActive(job: Job): boolean
ledger.checkpointCombined(job: Job, outcome: CombinedOutcome): boolean
ledger.checkpointConfig(job: Job, report: ImageConfigResult): boolean
ledger.checkpointArchive(
  job: Job,
  check: 'secret' | 'sbom' | 'vuln',
  report: ArchiveScanReport, // exact envelope containing this ONE check
): boolean

ledger.cancel(scanId, subject):
  'cancelled' | 'already_cancelled' | 'conflict' | 'not_found'
```

Finalizers/retry/attemptActive receive the token from the **original claim**, not a fresh context lookup. Pass explicit `undefined` for unused `config`, or for the default `errorCode` in `finish`, before the token. All finalizers and retry compare this caller token inside their write transaction and refuse missing/wrong/revoked/expired authority. A checkpoint returns false for missing/stale/revoked/expired authority and duplicate completed check; invalid payload/contract/storage errors throw. The first committed check cannot be overwritten, even by a different valid result from the same attempt. Do not expose the internal lease token to HTTP clients.

`scanNginxArchive` options now accept an internal synchronous lifecycle callback:

```ts
onCheckpoint?: (
  check: 'secret' | 'sbom' | 'vuln',
  report: ArchiveScanReport,
) => boolean
```

It runs after the subprocess/parser/identity checks and a completed per-check scratch audit. The production consumer supplies the fenced ledger callback. Returning false stops further work. A custom injected archive runner must emit the callback to preserve checks *before* its whole report resolves; returning a final report alone cannot reconstruct outcomes that were never checkpointed.

`configAttemptContext` remains a metadata/context lookup used to validate stored identity, including on cancellation after expiry; it is **not** a sufficient live authorization test. It now returns the claim token and any execution-profile binding in its job. Use `checkpointActive` for exact live worker authority. Config capability issuance and post-load checks do so.

### Cancelled per-check projection

No new public report schema was added. Cancellation writes the existing durable result tables:

| Reader | After cancellation |
| --- | --- |
| `state` / `snapshot` | State remains `cancelled`. |
| `result`, `secretDataset`, `findings` | Existing sanitized secret result/finding contract when checkpointed. `result` / `secretDataset` are undefined when missing. The legacy `findings` method still returns an empty page for an owner-known scan with no rows; **do not infer checked coverage from that empty page**. |
| `sbom`, `sbomDataset` | Existing checked/failed SBOM contract when checkpointed; undefined otherwise. |
| `vuln`, `vulnDataset` | Existing checked/failed vulnerability contract, including frozen v2 DB evidence when present; undefined otherwise. |
| `configResult` | Existing validated selected-config report when checkpointed; undefined if interrupted/not checkpointed. Unselected skipped config is not invented during cancellation. |
| `archiveResult` | Existing archive envelope with only checkpointed check properties. Missing secret/SBOM/CVE keys stay absent. Full requested-check equality is retained for non-cancelled historical reports; only cancelled reports allow a nonempty requested subset. No archive envelope is created when there are no archive checkpoints. |
| `events` | One `cancelled` terminal event, no checkpoint events or fabricated completion events. |

Archive checkpoints must share the exact receipt/scanner identity. Their snapshot uses maximum already-audited metrics; its single `checkedAt` remains the vulnerability checkpoint's completion timestamp when CVE evidence exists. It does not become the cancellation timestamp. Independent config stays in the existing config table.

Coordinator must remove any HTTP/report/UI shortcut that discards all coverage merely because state is cancelled. Preserve absent/unknown for missing checks and bind pages/report versions to the immutable terminal snapshot. This implementation does not change those layers or claim their acceptance tests pass.

## CVE evidence and size limits

- The scan's independent CVE policy marker is authoritative; missing/forged/stripped evidence is rejected, not silently treated as legacy.
- V2 `checkedAt` is the original completed check time. `dbPolicy.evaluatedAt` is finalized at the checkpoint's in-transaction eligibility fence. Expiry crossing that fence yields the existing failed-check representation, preserving independent checks.
- Cancellation/reopen validates the stored receipt at its historical timestamps; it does not refresh dates, reevaluate against cancellation time, or claim current DB freshness. Legacy archive freshness likewise remains tied to the historical completed check.
- Checkpoint identity is bounded to 4096 UTF-8 bytes; each payload to 2,000,000 bytes, with config additionally bounded to 16384 bytes by its existing validator. Existing finding/component counts, allowlists, advisory budgets and exact-key validation remain enforced.
- The merged archive snapshot must remain within the existing 2,000,000-byte contract. Incoming CVE optional advisory metadata is deterministically omitted with the existing `report_budget` marker when necessary; core findings/IDs and previously committed siblings are not dropped or rewritten.
- No partial JSON, raw stdout, Match, Code, raw paths, environment/history values, or scanner stderr is stored. Existing subprocess close/kill/byte-cap boundaries were not relaxed.

## Forward migration and operational boundary

Runtime `ledger.ts` remains the sole migrator. New **v15**, after unchanged v14 history, adds nullable `outbox.lease_token` and `scan_checkpoints`, keyed by `(scan_id, attempt, lease_token, check_name)`, with SQL byte/check/foreign-key constraints. Existing terminal reports are not rewritten or backfilled. Retention deletes checkpoint rows along with terminal scan data; active checkpoints remain.

A v14 running row receives no fabricated token. It must be reclaimed through a new claim before the new code authorizes writes. Stop old writers before deploying: do not run old workers against a newly migrated volume. Older binaries reject v15; rollback requires a compatible binary or a separately verified pre-migration backup. No existing volume was migrated in this work.

Synthetic forward/reopen and failure-rollback tests cover v15; in-scope downgrade fixtures were updated to remove v15 objects before modeling an older schema. In-scope tests using epoch-1000 claims now supply a coherent synthetic ledger clock (or real claim time), rather than weakening production expiry checks. The external OCI fixture still needs coordinator changes described below. R1–R4 adds no further migration and did not access any existing application DB.

The older `ledger/README.md` v11-era statements about discarded in-memory outcomes describe the prior implementation; coordinator-owned specification/document reconciliation is still required.

## R1–R4 independent-review revision

Read `partial-cancel-independent-review-20261016.md` in full. Its verdict remains **REQUEST CHANGES pending independent re-review**; this section records fixes, not reviewer approval.

- **R1:** `finishWithVuln` now has the same transactional live-lease fence as the other finalizers, including exact expiry equality, retry revocation and migrated null-token rejection.
- **R2:** validate the original archive secret/SBOM checked envelopes with exact keys before deriving combined outcomes. Derived objects use explicit fields, never payload spreads that can override discriminators or hide nested version data. Canonical requested-check subsets and exact CVE OS/node branches are enforced; existing nested finding/component/OS/advisory, size, receipt and policy validators remain in force for checkpoint, finalization and stored reads.
- **R3:** six finalizers, retry and attemptActive require an explicit final caller token. The shared SQL guard matches that exact token to the current running/undelivered attempt and requires a live lease. Consumer and tests pass their original claim token. Retry with expired or migrated null-token authority is deliberately refused; a new claim is needed.
- **R4:** archive checkpoint exceptions are recorded and propagated unchanged even if abort wins Promise.race or an adapter swallows/replaces the exception. Runner/cleanup errors after a committed archive checkpoint also propagate. Terminal persistence is outside the scanner fallback catch. Only `DbUsabilityError` is translated to the existing CVE DB-unavailable outcome; SQLite errors are not scanner failures. Failure leaves the running scan and committed sibling available to cancellation; no report/event is fabricated for an unfinished check.

`ledger/ledger.review-regressions.test.ts` was added **before production fixes**: the first run produced **76 tests, 42 passed / 34 failed**, reproducing the review defects. Added cleanup/abort/nested cases bring the final suite to **82 passed / 0 failed**. It tests all seven write APIs against valid/wrong/missing/expired/retry/null-token/replacement/cancelled authority, original malformed archive envelopes at three boundaries, and consumer-level SQLite failure after a committed sibling. These tests use new in-memory SQLite only.

## Exact validation after R1–R4

Working directory: `/Users/vsevolod/Documents/oldstartup/diplom/server/api`. Installed dependencies; no install or live qualification. Exact commands and latest results:

```sh
# Deadline 20 s: 82 passed, 0 failed/cancelled/skipped; exit 0.
node --import tsx --test --test-reporter=tap src/ledger/ledger.review-regressions.test.ts

# Deadline 60 s: 265 passed, 0 failed/cancelled/skipped; exit 0 (~10.76 s).
node --import tsx --test --test-reporter=tap src/ledger/*.test.ts src/worker/outbox-*.test.ts src/worker/image-config-runner.test.ts src/worker/secrets-publication-boundary.test.ts src/worker/archive-scan-worker.test.ts src/worker/scan-worker.cancel.test.ts src/worker/archive-process.test.ts

# Deadline 60 s: exit 0.
pnpm exec tsc --noEmit

# Deadline 60 s: 49 passed, 0 failed/cancelled/skipped; exit 0 (~7.26 s).
node --import tsx --test --test-reporter=tap src/runtime/runtime-http.continuation.test.ts src/scans/scans.advisory.test.ts src/scans/scans.archive.http.test.ts src/scans/scans.cancel.http.test.ts src/scans/scans.events.http.test.ts src/scans/scans.events.test.ts src/scans/scans.partial-cancel.http.test.ts src/scans/scans.report.http.test.ts src/scans/scans.sbom.http.test.ts src/scans/scans.vuln.http.test.ts src/llm/tests/history.http.test.ts src/llm/tests/llm.http.test.ts src/llm/tests/nginx-local-llm.http.test.ts src/llm/tests/quota.http.test.ts

# Deadline 20 s: 4 passed, 2 failed; exit 1 (~2.40 s). Details below.
node --import tsx --test --test-reporter=tap src/oci/nginx-local-policy.test.ts
```

Scoped `git --no-pager diff --check -- server/api/src/ledger server/api/src/worker docs/partial-cancel-implementation-20261016.md` (also including the 16 named external files) passed with exit 0 under a 10-second deadline. This Git check covers tracked diffs, not untracked file contents.

The 82 regression tests are included in the 265-test suite; do not sum them as distinct tests. Earlier combined external run (same external command with `src/oci/nginx-local-policy.test.ts` added) was **53 passed / 2 failed**, consistent with the split rerun. The initial implementation's 183-pass result predates this review revision and is not the current total. No full-suite acceptance is claimed.

Coverage includes checkpoint-before/after-cancel, separate SQLite writer connections, cancel-vs-finalize, revoked/replaced/expired leases, immutable duplicates, target/check/token/owner mismatches, strict redaction through table/WAL/reopen sinks, bounded archive metadata omission, selected config independence, ordinary/archive CVE receipt freeze and expiry, corrupted checkpoints, publication/state/outbox/event rollback, migration rollback, retention, and abrupt synthetic worker SIGKILL after a committed WAL checkpoint. Ordinary and actual archive runner pipelines use injected scanner/acquisition data, never live Trivy or a live CVE store.

Initial production changes: `ledger/ledger.ts`, `ledger/schema.ts`, `worker/outbox-consumer.ts`, `worker/archive-scan-worker.ts`, `worker/image-config-runner.ts`. R1–R4 production fixes: `ledger/ledger.ts`, `worker/archive-result-contract.ts`, `worker/outbox-consumer.ts`. Regression suites: `ledger/ledger.checkpoint.test.ts` and `ledger/ledger.review-regressions.test.ts`; existing in-scope migration/fencing and worker cancellation/config/archive/redaction tests were deliberately updated/extended.

## External signature-only updates and outstanding integration issues

Only necessary caller-token additions (including explicit unused-argument placeholders) were made outside ledger/worker. No external assertions, fixtures or production logic were changed in this revision. Paths relative to `server/api/src`:

1. `oci/nginx-local-policy.test.ts`
2. `runtime/runtime-http.continuation.test.ts`
3. `scans/scans.advisory.test.ts`
4. `scans/scans.archive.http.test.ts`
5. `scans/scans.cancel.http.test.ts`
6. `scans/scans.events.http.test.ts`
7. `scans/scans.events.test.ts`
8. `scans/scans.partial-cancel.http.test.ts`
9. `scans/scans.report.http.test.ts`
10. `scans/scans.sbom.http.test.ts`
11. `scans/scans.vuln.http.test.ts`
12. `llm/tests/history-wire-native.seed.ts` (signature updated; **not executed**)
13. `llm/tests/history.http.test.ts`
14. `llm/tests/llm.http.test.ts`
15. `llm/tests/nginx-local-llm.http.test.ts`
16. `llm/tests/quota.http.test.ts`

Two remaining failures in `oci/nginx-local-policy.test.ts` require fixture changes beyond the authorized signature-only scope:

- `v12 binding is atomic, legacy remains unqualified, reopen/fences/retention/rollback preserve rows`, line 134: expected true, got false. The fixture creates a ledger with the real clock, then claims at 1000 and 628000 milliseconds since epoch. The second lease ends at 1255000; finalization correctly refuses it as expired. Coordinator must use a coherent injected clock or current-time claims, keeping the stale-first-claim assertion.
- `v11 forward upgrade never promotes legacy rows and conflicting v12 DDL rolls back`: `SQLITE_ERROR: duplicate column name: lease_token`. Its synthetic v11 downgrade removes v12–v14 objects but leaves v15 `outbox.lease_token` and `scan_checkpoints`. It also expects upgraded user_version 14 at line 159. Coordinator must remove v15 objects when constructing v11 and expect current version 15; preserve rollback/legacy-identity assertions. Do not relax the production migrator.

`scripts/task2-qualification-run.ts` has two `finishCombined` calls near lines 187–188 still requiring the new arguments. This script was **not modified or run** (outside write scope). Coordinator change for each original `job`:

```ts
ledger.finishCombined(id, job.attempts, outcomes, undefined, job.leaseToken)
```

API `tsc --noEmit` passes but is not evidence that this separately scoped script is compatible. These remaining integration issues preclude claiming full TASK2 acceptance.

## Remaining coordinator work / not claimed

- HTTP/report assembly, cancelled per-check transport, pagination/version binding, SSE/snapshot integration, UI rendering/copy and corresponding integration/browser tests.
- Apply the approved product/spec decision and update stale documentation in the coordinator-owned workflow; no tracker/spec changes were made here.
- Independent **re-review of R1–R4**, the two OCI fixture updates and qualification-script token calls above, migration/rollback operational approval and any resource/live scanner/DB qualification. Synthetic tests are not live qualification.
- Full TASK2/6 acceptance remains open; this handoff only establishes the tested ledger/worker implementation slice.
