# Runtime TASK6 continuation — independent review, 2026-10-17

## Disposition

**Changes requested for the new caller-journal CLI: two confirmed P2 correctness/safety findings.** The exact dynamic Nest selection, default-off/pre-JSON authentication, and SQLite timestamp conversion are acceptable within the inspected local source and controlled tests. This is not blanket approval of the continuation or approval to initialize an operator journal before the path-exclusion findings are fixed.

**Live capture remains disabled and unqualified.** These tests do not prove isolated Linux Engine API 1.47 qualification, independent controller/observer counters, no-bypass confinement, successful Linux application IPC, current topology/source acceptance, nginx activation, or deployed UI acceptance. No successful qualification callback or platform spoofing was used.

## Scope and constraints

Read `docs/runtime-task6-continuation-20261016.md`, the uncommitted changes/new files below, and their relevant existing dependencies:

- `server/api/src/runtime/runtime-live-bootstrap.ts`
- `server/api/src/runtime/runtime-caller-init.ts`
- `server/api/src/runtime/runtime-image-link.adapter.ts`
- `server/api/src/parent-ingress.ts`
- `server/api/src/parent-ingress.runtime.test.ts`
- `server/api/src/runtime/runtime-bootstrap.continuation.test.ts`
- `server/api/src/runtime/runtime-http.continuation.test.ts`
- `server/api/src/runtime/runtime-image.test.ts`
- Relevant qualification/coordinator, IPC, dispatch-permit, journal/path checks, contract, module/service/identity/intake, main/AppModule and store providers; continuation runbook diff.

Review performed on macOS (`darwin`), Node v23.11.0, using installed dependencies. Production/tests were read-only. Only this new review document was written in the repository, after listing/verifying `docs/` and checking that this destination did not exist. Probes used newly generated disposable directories/databases or controlled in-memory bytes; temporary files were removed in `finally`. Targeted HTTP tests used loopback ephemeral listeners and synthetic accounts/keys/stores. No full suites, Docker, Engine, registry/scanner calls, live DB, private data/config, tracker actions, commit, branch, or deployment changes.

## Findings

### R1 — P2: an explicitly excluded DB can be deleted as the new caller DB's SQLite sidecar

**Location:** `server/api/src/runtime/runtime-caller-init.ts:12-17`; delegated `runtime-caller-journal.ts:14-30` and `runtime-store.ts:69-107`.

The CLI checks normalized absolute operands and four distinct base names, then delegates to `initializeCallerJournal`. Neither layer excludes SQLite's generated sidecar namespace. For example, choose the new caller path `/private-owned-dir/caller.sqlite` and explicitly identify the API runtime DB as `/private-owned-dir/caller.sqlite-journal`. All operands are absolute, lexically canonical and distinct; the directory can be owned 0700 and the existing excluded DB 0600. The initializer creates the caller file and starts a SQLite transaction. SQLite uses the explicitly excluded path as its rollback journal, overwrites it and removes it on commit. Initialization returns successfully.

**Independent reproduction:** created a fresh 0700 temporary directory and a real, closed SQLite database at `caller.sqlite-journal` with a synthetic table/row; supplied that path as the first exclusion and separate absent auth/image paths. Calling `runtimeCallerInit` succeeded; `caller.sqlite` existed afterward and the explicitly excluded SQLite database no longer existed. No real database was involved.

**Impact:** explicit exclusions do not currently protect all files touched by initialization. A permitted but unfortunate operator filename can cause irreversible destruction of an unrelated API/auth/image database, even with serving stopped. This does not require a browser attack or a concurrent writer. The low-level helper predates this continuation; the new CLI exposes its unchecked assumption and must not claim the stronger exclusion guarantee.

**Requested fix:** before any create/open/write, reserve and compare the complete caller and protected SQLite path namespaces, not just base DB filenames. Include rollback journal, WAL, SHM and the caller writer-lock path; account for collisions in both directions. Reject pre-existing unexpected sidecars rather than letting initialization reinterpret/delete them. Put the safety invariant in the shared low-level initializer/open path as appropriate, so a direct caller cannot bypass the CLI guard.

**Regression acceptance:** using only disposable stores, reject the demonstrated `caller.sqlite-journal` exclusion before creating the caller DB; assert the protected file's bytes are unchanged. Cover `-wal`, `-shm`, `.writer`, reverse namespace collisions, and existing sidecars. Preserve ordinary distinct-file initialization.

### R2 — P2: filesystem aliases in forbidden operands bypass the CLI's separate-DB guarantee

**Location:** `server/api/src/runtime/runtime-caller-init.ts:12-17`; delegated `runtime-store.ts:94-104`.

`resolve(p) === p` establishes lexical normalization, not filesystem canonicality. `checkedPath` validates the caller's parent/file but only `lstat`s forbidden paths, swallowing missing-path errors. At initialization the new caller file does not yet exist, so there is no caller inode to compare. It does not resolve symlinked exclusion parents or dangling exclusion symlinks.

**Independent reproductions, both accepted:**

1. In a fresh private directory, create a dangling `runtime-alias.sqlite` symlink pointing to the not-yet-created `next.sqlite`. Initialize `next.sqlite` with `runtime-alias.sqlite` as the API-runtime exclusion. Both paths then have the same `realpath`.
2. Create a directory symlink `alias-dir` pointing to the private directory. Use the absent forbidden operand `alias-dir/next.sqlite` and the caller operand `next.sqlite`. Initialization succeeds and both names resolve to the newly initialized caller DB.

All supplied strings pass the CLI's absolute/normalized/distinct checks. The second case does not require an existing leaf symlink. This contradicts the handoff's claim that exclusions apply even when the protected DB is absent.

**Impact:** the supposedly independent caller journal may be the very file named by a protected API/auth/image path. Later initialization/opening of that protected store can operate on the caller journal. Do not rely on a later application-ID check to make this safe; separation must hold before initialization writes anything. This is an operator-input correctness issue, not evidence of remote/browser privilege escalation.

**Requested fix:** validate all four operands against filesystem identity before creation. Reject symlink components/leaf aliases, or safely canonicalize existing parents plus an absent basename, and fail closed when the identity of an exclusion cannot be established. Check existing inode identity as well. Apply this alongside R1's sidecar namespace checks. Do not create protected DBs or discover their names from private ambient config.

**Regression acceptance:** reject both demonstrated alias forms without creating the caller DB; preserve the dangling symlink/parent and all protected files. Include aliases to existing protected files and normal distinct absent protected paths.

## Accepted local behavior and important qualifications

### Exact dynamic Nest module selection

`configureParentIngress` selects the supplied descriptor and resolves `RuntimeIdentity` and `RuntimeApiService` with `strict:true` **before** registering middleware. There is no catch/global-provider/static fallback. Ordinary `main.ts` still creates Nest with `bodyParser:false`, calls the one-argument helper, and imports the static default-off runtime module through AppModule.

The five targeted composition cases pass: default, exact dynamic, unregistered dynamic with static present, omitted/rebuilt selection in dynamic-only composition, and diagnostic dual variants. The diagnostic dual-import case verifies marker scoping without a runtime DB; it is not endorsement of deploying duplicate route/controller variants.

An additional independent probe rebuilt the dynamic descriptor using the **identical denied-port object**, not merely a new equivalent port. The rebuilt descriptor was rejected, the original service's raw marker remained unset, and the original registered descriptor succeeded. This probe started no listener and opened no database. Keep the exact descriptor in root imports and ingress selection, import only one runtime variant in deployment, and never continue listening after a selection/configuration failure.

### Permit/bootstrap/journal handling

The new bootstrap calls `acceptOperatorQualification` before socket construction, rejects equal IPC credential/dispatch keys, and composes only application IPC plus the serialized coordinator. It imports no Engine client and initializes no store. Existing qualification validation includes Linux platform, bounded expiry, review and local WeakSet permit membership; existing coordinator rechecks review/expiry and gates publication. Existing journal code verifies the whole-intent HMAC before an atomic one-use reservation and preserves consumption/revocation across reopen. The new targeted journal test confirms changed-owner rejection, exclusive writer, no overwrite, restart to indeterminate, nonce/consent replay rejection and durable revoke. Fixed CLI failure output avoids leaking supplied paths/underlying errors.

**Coverage limitation:** `runtime-bootstrap.continuation.test.ts:101-127` runs on macOS. The first condition in `acceptOperatorQualification` is `process.platform !== 'linux'`, so both assertions short-circuit there. Those passing assertions do **not** independently exercise the review callback, expired-record branch, equal-key branch, or a successful qualified Unix constructor on Linux. The qualification-before-socket ordering is established here by source inspection, not positive Linux execution. A genuine authorized qualification environment must cover those branches without spoofing platform or using an always-true reviewer. R1/R2 concern path isolation; they do not demonstrate a bypass of the HMAC or replay guards.

### Default-off authentication before JSON

For both static and selected dynamic modules, malformed JSON without a cookie returns 401; foreign Origin returns 403 before JSON parsing. Authenticated duplicate keys return 400. Controls accept 1024 bytes and reject 1025; imports at 65536 bytes reach closed DTO validation, while 65537 return 413. Consented live requests with the unavailable port return 403 `QUALIFICATION_MISSING`, leave history empty and dispatch zero times. Actual-module historical tests also exercise owner boundaries, immutable reports/restart and seeded admission cancel/revoke publication fences.

These are controlled tests of the source parent bootstrap, not verification that a deployed nginx/frontend or full production AppModule has been activated. Seeded interrupted rows and orderly reopen are not abrupt-process crash/stale-lock reconciliation evidence.

### SQLite timestamp conversion

The adapter only transforms exact `YYYY-MM-DD HH:mm:ss` to `YYYY-MM-DDTHH:mm:ss.000Z`, then delegates to `timestamp`, which requires canonical formatting and a Date round trip. Invalid normalized dates are rejected rather than rolled forward. Canonical ISO milliseconds are preserved; offsets, ambiguous local dates, arbitrary text and missing checked metadata fail closed. Complete `link(...)` validation catches invalid/missing scanner metadata and preserves independent SBOM/CVE outcomes; checked time is not replaced with link time.

The real-ledger controlled HTTP test reproduces SQLite-generated checked time and verifies its frozen association through reopen/replay. An independent 22-case adapter probe in `America/Los_Angeles` and `Asia/Kolkata` checked both checked outcomes: leap-day conversion, unchanged ISO milliseconds, absent/null time, invalid leap day, hour 24, leap second, fractional SQLite shape, offset ISO, leading whitespace, and absent/invalid scanner version. All expected acceptance/rejection assertions passed, without network or registry access. Changing TZ in this disposable probe is not platform spoofing or Linux qualification.

## Validation performed

From `server/api`, with a **60000 ms** outer timeout:

```sh
node --import tsx --test src/parent-ingress.runtime.test.ts src/runtime/runtime-bootstrap.continuation.test.ts src/runtime/runtime-http.continuation.test.ts src/runtime/runtime-image.test.ts
```

Result: **12 tests passed, 0 failed, 0 skipped/cancelled**, reported duration 1060.284334 ms.

Additional independent inline Node/tsx probes, each with a **10000 ms** outer timeout:

- Sidecar collision and dangling symlink: confirmed both unsafe accepted cases; disposable files removed.
- Real SQLite protected-sidecar deletion and absent-file/symlink-parent alias: confirmed both findings; disposable files removed. Relative caller path, wrong authorization, literal duplicate and extra operand all rejected without creating the target.
- Same-port rebuilt Nest descriptor: rejected; original exact descriptor succeeds, strict service identity preserved; no listener/stores.
- Timestamp/full-link metadata matrix: **22 cases passed** using controlled in-memory bytes and two non-UTC TZ settings.

Scoped `git diff --check` passed for the three modified tracked production/test files in this review (`parent-ingress.ts`, `runtime-image-link.adapter.ts`, `runtime-image.test.ts`). No full suite, full API typecheck, Docker or older qualification proof was run. Prior handoff typecheck/lint claims were not treated as independently rerun evidence.

Before and after tests/probes, the SHA-256 aggregate over sorted path strings plus current file bytes for the eight scoped TypeScript files, continuation handoff and operator runbook was identical:

```text
877c37061f50829c0c6f10ef034932c553906e92a29de26112bc935d844ad6ed
```

No reviewed input was edited. Existing unrelated dirty work was not reverted, staged, or modified by this review. The sole intended repository write is this report.

## Next action

Fix R1/R2 with disposable regression cases before using or approving the new operator initializer. Preserve the exact-module/pre-JSON/default-off behavior and strict timestamp conversion. Obtain separately authorized, independently accepted isolated Linux Engine API 1.47 and current application-topology evidence before any live enablement/readiness claim; these local tests and this review cannot supply that qualification.
