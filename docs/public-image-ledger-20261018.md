# Public image ledger integration — 2026-10-18

## Ownership and dependencies

This slice writes only `server/api/src/ledger/ledger.ts`, new `server/api/src/ledger/ledger.public-image.test.ts`, new `server/api/src/ledger/ledger.archive-consistency.test.ts` (R1 follow-up), new `server/api/src/ledger/ledger.public-debian-temp.test.ts` (Debian identifier follow-up), and this document. Existing dirty ledger source/tests/schema and R1–R4 token, lease, original-envelope and storage-error hardening were retained. No ordinary schema, scanner parser, API/UI, worker, OCI, deployment or environment file was changed by this slice. No commit or branch was created.

Read-only integration sources: `server/api/src/worker/docs/public-image-worker-20261018.md`, `docs/public-image-api-ui-20261018.md`, `docs/public-image-config-20261018.md`, OCI `public-image-policy.ts`, worker `public-image-evidence.ts`, `archive-result-contract.ts` and `vuln-findings.ts`.

## Implemented behavior

- `validateStoredArchive` first validates the original archive envelope through the worker contract. Only a complete `isPublicReceipt(receipt)` selects public second-pass normalization in the private `validateCombined` helper. A profile string or a generic job alone cannot widen legacy SBOM/CVE validation.
- Public SBOM OS/package/version validation uses the worker's shared `publicOs`, `PUBLIC_ECOSYSTEMS`, `publicPackageName` and `publicPackageVersion`. Supported ecosystems are exactly `apk/deb/rpm/npm/pypi/gem/gomod/cargo/maven/composer/nuget`; OS families are exactly `alpine/debian/ubuntu/redhat/centos/rocky/alma/oracle/amazon` with bounded numeric releases. Maven, Go, scoped npm, Composer, mixed-case NuGet and bounded epoch/comma versions retain their reviewed normalized rules.
- Public CVE sources use `PUBLIC_VULN_SOURCES`, with sorted unique bounded source lists. The existing archive-image/platform/check-bound SHA-256 finding identity, duplicate detection, exact field sets, sanitized secrets and advisory limits remain mandatory.
- Public-only `NODE_INVENTORY_UNKNOWN` is accepted for checked/unsupported public CVE coverage; `NODE_INVENTORY_ABSENT` remains legacy-only. Unsupported OS/EOL envelopes remain unsupported, not invented checked-zero coverage.
- One shared `validateArchiveJob` checks receipt against stored job registry/repository/digest/platform and image scope at checkpoint, finalization and owner-scoped read. Legacy archives still require enumerated nginx candidates. Any public receipt on an nginx execution binding fails, including on stored reads. Original requested checks and LOCAL check-set restrictions remain checked separately.
- Public checkpoint persistence, merged receipts, first-result immutability, exact archive/config/diffID identity, evidence hashes, committed DB evaluation, cancellation publication, retry/replacement revocation, reopen and retention use the existing transactional machinery. Expiry forbids new writes without erasing accepted checkpoints. Historical reads use the accepted evaluation, not present-day DB freshness.
- Generic checked secret/SBOM/CVE results remain archive-only. `finishCombined` still rejects non-Alpine checked outcomes, and the legacy `finishWithResult` final state fence now explicitly requires the legacy Alpine registry/repository/platform. Its former lack of a repository fence must not allow new generic jobs to bypass receipts. Ordinary SBOM/CVE paths and table contracts were not widened.

### No SQL enum migration

Public output remains JSON in `scan_archive_results`; checkpoint payloads remain JSON in `scan_checkpoints`. Public data is validated before either write and again before publication/read. Tests assert public reports do not populate ordinary `scan_results`, `scan_findings`, `scan_sbom_results`, `scan_sbom_components`, `scan_vuln_results` or `scan_vuln_findings`. No enum/schema migration is needed or introduced. Existing dirty schema/migration work was not altered.

## Config composition handoff

The config agent's actual exported interface is `admittedConfigTarget(job, publicImagePolicy = false)`, not a profile-string argument. Ledger's narrowly used `publicConfigTarget` requires a valid pinned public target, no execution binding, and explicit `admittedConfigTarget(job, true)`. Default legacy predicate calls are unchanged.

- `checkpointConfig` accepts that safe target only in the config lane, followed by exact `validateConfigReport` and original immutable claim/token validation.
- `finishCombined` permits public config-only completion and generic failed scanner outcomes with a validated config report/target. It does not permit checked generic secret/SBOM/CVE outcomes.
- Config findings still bind the claimed manifest digest/platform; original claim/context is compared again inside the fenced transaction.

**Coordinator integration verified during R1 follow-up:** `outbox-consumer.ts` now supplies the explicit fifth composition argument. The earlier four-argument blocker is resolved; the current call is:

```ts
const config = await runImageConfig(
  ledger, job, controller.signal, options.configLoader, options.publicImagePolicy === true,
);
```

That worker file remains outside this slice's exclusive writes and was not edited here. Ledger tests verify public config persistence/cancellation using closed normalized config fixtures. Verification of the call site is not a native/live config qualification; the runner default remains restricted.

## Worker/coordinator lease handoff

The existing worker call remains valid:

```ts
ledger.claim(now, 3 * options.timeoutMs + 27_000, 627_000);
```

When the explicit third argument is supplied, ledger now reserves `max(leaseMs, archiveLeaseMs)` for every **non-Alpine image** job, not just `library/nginx`. This is a conservative scheduling reservation, not execution authority. Generic public scans therefore receive the full 627-second archive budget. The existing `CONFIG_LOAD_MS + 1000` allowance remains additional only when config is selected. Alpine's earlier lease timing is unchanged; no retry starts sooner. Tests check the exact boundary, including refusal of replacement one millisecond before expiry.

## API accessor handoff

```ts
ledger.pinnedTarget(scanId, subject)
// { registry: string, repository: string, digest: string, platform: string } | undefined
```

The query itself includes both scan ID and owner. It works for queued/config-only/terminal rows, returns no foreign-owner identity, and returns `undefined` after retention. API can adopt it instead of traversing paginated history. This slice does not edit API call sites.

## Validation and exact observed output

All commands below ran from `server/api`, except the indicated diff check. Tests use temporary SQLite/in-memory handles and controlled HTTP/registry/scanner fixtures. They do not use Docker, a live DB release, live registry, native Trivy, old environment files or a deployed stand.

### Ledger + public HTTP/service/report selection

```sh
pnpm exec tsx --test src/ledger/*.test.ts src/scans/public-image.http.test.ts src/scans/public-image.service.test.ts src/scans/public-image-report.test.ts
```

Final observed summary, exit 0:

```text
ℹ tests 320
ℹ suites 0
ℹ pass 320
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 8153.313084
```

This includes existing ledger/migration/retention/R1–R4 tests, the new public ledger cases, and both full public HTTP cases. In particular:

```text
✔ public module HTTP admission: canonical official/namespaced inspection, auth, resource/DB/readiness guards and replay (264.639167ms)
✔ public module HTTP persisted reports: normalized Debian/all-ecosystem archive → strict status/results/SBOM/report-v1 (98.756292ms)
```

New coverage includes exact/raw/nested payload rejection before checkpoint/final writes and on stored reads, normalized package/source/OS negatives, malformed CVE hashes, cross-target receipts, wrong/missing token, wall-clock expiry, retry/replacement/cancel revocation, mixed checkpoint receipts, checkpoint hash/owner corruption with atomic rollback, cancelled subset recovery after reopen/expiry, historical DB evidence, retention, 64-layer/public resource boundaries, config-only and generic archive-only fencing, full lease scheduling and public consumer storage-error propagation.

### Worker/config and existing HTTP regression selection

```sh
pnpm exec tsx --test src/worker/public-image-consumer.test.ts src/worker/outbox-cancel.test.ts src/worker/outbox-config*.test.ts src/worker/image-config-runner.test.ts src/oci/pinned-image-config.test.ts src/scans/scans.*http.test.ts src/scans/browser-scans.http.test.ts
```

Observed summary, exit 0:

```text
ℹ tests 89
ℹ suites 0
ℹ pass 89
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 3025.624
```

### Typecheck / whitespace

```sh
pnpm exec tsc --noEmit
```

Final observed result: exit 0, no compiler diagnostics/output.

From repository root:

```sh
git --no-pager diff --check -- server/api/src/ledger/ledger.ts server/api/src/ledger/ledger.public-image.test.ts
```

Observed result: exit 0, no output. The new test file is untracked; its TypeScript and execution are covered by the commands above.

Intermediate development failures were corrected rather than hidden: an initial parenthesis typo, the concurrently finalized boolean OCI composition signature, a readonly DB fixture mutation, and two new expiry assertions initially using `nextUpdate` rather than the current policy's fourteen-day `updatedAt` boundary. `nextUpdate` crossing is stale-but-usable under the current policy and was not changed to satisfy the tests. No existing tests were weakened, skipped or removed by this slice.

These selections are not an unqualified full-repository test result. The config handoff independently records an out-of-scope stale source assertion in `worker/vuln-db-trust-wiring.test.ts`; this slice did not change or suppress it. Native/live public scan, container/cgroup, signed-release readiness and deployment qualification remain outside this work.

## Independent-review R1/P1 follow-up — accepted checkpoint consistency

Read `docs/public-image-chain-review-20261018.md`, R1. The ledger previously validated the final archive in isolation. A runner could return a different but individually valid final report and make already accepted checked findings inaccessible after final delivery. The worker owner fixes the late-audit rewrite separately; this ledger defense does not rely on that fix.

### Transactional guard

`finishArchive` now calls `assertArchiveCheckpointConsistency` **inside the existing IMMEDIATE transaction**, after validating the current live claim and applying the existing final CVE policy evaluation, but **before any outbox/result/state/event write**.

- Only checkpoints belonging to the current attempt/token are selected. The extracted `validatedCheckpoint` helper revalidates size, evidence hash, stored owner/original job identity and complete per-check contract; cancellation reuses the same helper without changing its expiry/recovery semantics.
- Every accepted archive checkpoint must have the exact final receipt (including archive SHA-256, config identity and ordered layers/diffIDs) and scanner version.
- Accepted Secrets and SBOM payloads must match the final payload exactly. Failed/changed/cleared results are rejected even if individually valid. Uncheckpointed siblings may honestly fail; consistent accepted siblings can still finalize into a partial report.
- Accepted config checkpoints, if present, must also equal the final validated config report.
- CVE coverage, DB identity, findings and advisory data must remain consistent. The current policy's derived `dbPolicy` evaluation may change at the final fence; completion timestamps and aggregate metrics need not equal earlier per-check snapshots. Existing canonical `report_budget` advisory omission may occur independently at checkpoint aggregation/final serialization, but core CVE findings and other advisory replacements are not exempted.
- The only failed-CVE downgrade exception for an accepted nonfailed CVE checkpoint is current-policy `DB_UNAVAILABLE` **independently proven by `DbUsabilityError` when reevaluating the accepted checkpoint's DB at the captured final lease time**. A returned failure label or a replacement DB identity is not evidence. Genuine CVE expiry cannot excuse either Secrets or SBOM being changed/erased.
- A contradiction throws `TypeError` and rolls back. The attempt remains live, original checkpoints remain available for cancellation/reopen recovery, and no contradictory terminal report replaces them. Wrong/missing/expired/retried/replaced/cancelled authority still returns `false` before this guard and makes no writes.

No SQL/schema, worker, API or browser code was changed for R1. No earlier patches or existing tests were removed, skipped or weakened.

### R1 regression evidence

New `server/api/src/ledger/ledger.archive-consistency.test.ts` adds **54 tests**, each exercised for legacy nginx or public receipts. Coverage includes positive Secrets/SBOM checkpoints replaced by failures or changed/cleared findings; owner-scoped cancellation recovery after reopen; unchanged accepted siblings with unfinished-stage failure; archive hash/layer/diffID receipt mixing; invented DB expiry; changed CVE findings/DB/advisory; allowed current-policy reevaluation and genuine DB downgrade; unrelated Secrets **and** SBOM erasure rejected during genuine downgrade; report-budget compatibility; invalid/revoked tokens; and corrupt stored checkpoint hashes.

The new standalone suite passed (54/54). After the final test expansion, the following combined command was rerun from `server/api`:

```sh
pnpm exec tsx --test src/ledger/*.test.ts src/scans/public-image.http.test.ts src/scans/public-image.service.test.ts src/scans/public-image-report.test.ts src/worker/outbox-config-archive.test.ts src/worker/outbox-cancel.test.ts src/worker/public-image-consumer.test.ts src/worker/public-image-worker.test.ts src/worker/archive-scan-worker.test.ts
```

Exact final summary, exit 0:

```text
ℹ tests 413
ℹ suites 0
ℹ pass 413
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 10244.266916
```

The previously passing public persisted-report HTTP regression remains green, as do existing ledger R1–R4, migration/retention, checkpoint freshness and selected worker/config cancellation regressions. `pnpm exec tsc --noEmit` was rerun: exit 0, no diagnostics/output. Tracked ledger source `git diff --check` passed without output. This is targeted offline validation, not a full-repository or native/live scanner qualification. No Docker, live DB/registry, old environment loading or commit was performed.

The coordinator's fifth config argument is now verified in source (see corrected config handoff above). Independent-review R2 belongs to API/browser owners and was not altered or claimed resolved by this ledger slice.

## Native Debian TEMP identifier follow-up

Read `server/api/src/worker/docs/native-debian-20261018.md` and the worker's `publicVulnerabilityId`. The native worker handoff reports **88 Debian packages and 241 vulnerability findings: 236 CVEs + 5 Debian TEMP advisories**. Those are worker/coordinator candidate observations, not a native scan performed by this ledger slice. The old ledger's CVE-only second-pass expression would have rejected the complete valid public result; silently discarding the five advisories or relabeling the total as 241 CVEs is not an acceptable workaround.

### Narrow persistence change

- Only `validateCombined`'s already receipt-selected public branch now delegates identifier admission to `publicVulnerabilityId(f.cveId, f.ecosystem)`.
- CVE grammar remains unchanged. The one additional namespace is exactly `TEMP-[0-9]{7}-[A-F0-9]{6}` and only ecosystem `deb`, behind a complete validated public receipt. Arbitrary advisory namespaces, raw/object identifiers, unknown ecosystems and malformed/lowercase/oversized TEMP identifiers remain rejected. The worker independently requires Debian OS evidence before producing this normalized namespace.
- Compatibility field `cveId` stores the **exact original source identifier**. No new ID is generated to replace TEMP, and no alias/coercion/truncation occurs. The existing finding SHA-256 continues to include that exact identifier, ecosystem, package/version, provenance and archive target tuple. Duplicate detection and identity across replay/checkpoint/cancel/reopen remain unchanged.
- The existing `validateAdvisoryBudget` / worker advisory validator remains mandatory. TEMP metadata normalized without CVSS has no references; fabricated CVE/NVD canonical URLs (whether containing a TEMP ID or an unrelated CVE) fail before checkpoint/final writes and again on stored reads. This slice does not invent links or expand advisory-v1 namespaces.
- Legacy nginx archives and ordinary Alpine result paths remain **CVE-only**, even with otherwise valid TEMP-shaped input and correct hashes. There is no SQL enum/schema migration: public reports/checkpoints still use the existing JSON stores, and tests assert the ordinary result/finding tables remain empty for public TEMP reports.
- No filtering, sorting, paging, count metadata, check/receipt envelope, CVE DB freshness policy, resource/count bound, token fence or accepted-checkpoint consistency rule was changed. API/UI owners add neutral labels and `{ cve, debianTemp }` count partition metadata separately; ledger does not relabel 241 findings as 241 CVEs.

### TEMP regression coverage and exact outputs

New `ledger.public-debian-temp.test.ts` uses synthetic, explicitly fixture-only identities and a count-shape example (88 packages, 236 synthetic CVE findings, 5 synthetic TEMP findings). It is not a copy of native raw output and is not evidence of a newly published native scan. Tests cover exact roundtrip/partition, replay, complete ordered data across a page boundary, same source ID on distinct packages, full-identity duplicate rejection, checkpoint consistency, cancellation/reopen/retention, incorrect source-ID hashes, wrong namespace/ecosystem, raw identifiers, fabricated references, legacy rejection and wrong/missing/expired/retried/replaced/cancelled authority with no writes.

From `server/api`:

```sh
pnpm exec tsx --test src/ledger/ledger.public-debian-temp.test.ts
```

Observed, exit 0:

```text
ℹ tests 106
ℹ suites 0
ℹ pass 106
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 775.076375
```

Expanded offline regression selection:

```sh
pnpm exec tsx --test src/ledger/*.test.ts src/scans/public-image.http.test.ts src/scans/public-image.service.test.ts src/scans/public-image-report.test.ts src/worker/native-debian-normalization.test.ts src/worker/vuln-findings.test.ts src/worker/public-image-worker.test.ts
```

Observed, exit 0:

```text
ℹ tests 507
ℹ suites 0
ℹ pass 507
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 8755.236292
```

`pnpm exec tsc --noEmit` passed with exit 0 and no diagnostics/output. Tracked `ledger.ts` whitespace check passed with exit 0 and no output. All prior ledger R1–R4, archive consistency, legacy validation, migration/retention and selected public HTTP regressions remain green in this selection. No existing test was weakened, skipped or removed.

**Coordinator boundary:** this slice changed only ledger source, its new test file and this handoff. No Docker, live environment, registry, scanner, production DB or DB outside these disposable fixtures was accessed. No rebuild/restart/deployment/commit was performed. The native coordinator should rebuild only after worker, ledger, API and UI fixes are all integrated; these passing fixture tests do not claim a newly published 241-finding Debian report.
