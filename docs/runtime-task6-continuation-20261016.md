# DIP-TASK-6 runtime continuation — 2026-10-16 handoff

## Disposition

Implemented the feasible local runtime integration work, not just a plan. **Live capture remains disabled and unqualified.** No task completion/spec mutation is claimed. The feature delta `e831c1d0-a64f-49d7-95d8-8a448afc2a09` was already applied as DOC13v2 per the parent/user and `testing-followup-20261016.md`; the old runbook UNAPPLIED header was corrected. No task-sourced delta was created; parent owns spec/status reconciliation. Prior accepted R1–R11 evidence was not reopened or rerun.

The authorized session runs on macOS and was supplied no independently accepted external Linux fixture/controller/enrollment or application-topology acceptance. No private environment, Docker endpoint, retained holder or key was searched for. Thus a genuine qualified live run is unavailable **within the authorized inputs of this session**, not a claim that no Linux machine exists elsewhere. Docker Desktop, synthetic fixtures and the controlled tests below do not qualify it.

## Source findings and implementation

1. **Real integration defect fixed: image result timestamps.** `ScanLedger.finishCombined` / `finishWithSbom` can produce SQLite UTC `CURRENT_TIMESTAMP` (`YYYY-MM-DD HH:mm:ss`). The runtime adapter previously copied that into a closed contract requiring canonical ISO millisecond UTC. The new actual HTTP/ledger/store integration reproduced HTTP400 on a valid owner/config/platform association. `runtime-image-link.adapter.ts` now translates only the exact SQLite UTC shape into `YYYY-MM-DDTHH:mm:ss.000Z`, leaves canonical ISO unchanged, and validates the entire association before returning. Invalid dates, timezone-less ISO, offset ISO, missing metadata or arbitrary strings fail closed as `IMAGE_LINK_UNAVAILABLE`; no local timezone guessing or substitution of link time. Digest/platform verification and independent SBOM/CVE outcomes are unchanged. No shared ledger migration or record rewrite.
2. **API-only qualified composition prepared.** New `runtime-live-bootstrap.ts` exports `createQualifiedRuntimePort`: existing genuine operator qualification permit → private `UnixApplicationCaller` → `SerializedCaptureCoordinator`. Qualification is checked before socket inspection; application bearer and dispatch key must differ. No Engine import, environment enable flag, discovery, listener, store initialization, fake attestation or fallback. This helper is not invoked by ordinary startup.
3. **Explicit caller-journal initializer prepared; independent-review R1/R2 path fixes implemented for re-review.** New `runtime-caller-init.ts` wraps the existing separate journal initialization API with an explicit authorization switch and three required forbidden DB paths (API runtime/auth/image). The shared low-level guard now checks canonical existing parents plus base/rollback/WAL/SHM/writer-lock families for all operands, including absent leaves, and rejects filesystem aliases/collisions before any create/open. See the R1/R2 section for precise behavior and validation. Refuses overwrite, requires private parent directory, outputs fixed tokens without paths/errors/keys. No credential argument, environment discovery, listener, lock removal or automatic recovery.
4. **Current parent bootstrap already exists.** `main.ts` uses `bodyParser:false` and `configureParentIngress`; that function installs real cookie/Origin-authenticated runtime intake before JSON parsing. `AppModule` imports the default runtime module. This is exercised through the actual parent ingress in new tests, not reimplemented for that test.
5. **Qualified dynamic-module composition gap fixed in the follow-up.** `configureParentIngress(app, runtimeModule = RuntimeApiModule)` now accepts the exact descriptor returned by `RuntimeApiModule.withQualifiedCapture(port)` and used in the root module's `imports`. It calls `app.select(runtimeModule)` and resolves identity/service with `strict:true` before middleware registration; there is no static or global-provider fallback. Omitted selection retains the default static behavior. Unregistered/rebuilt descriptors throw. `main.ts` and `app.module.ts` remain unchanged/default-off; no live port was installed. See the follow-up regression results below.
6. **Deployment/UI are present as source, not activated by this work.** `server/deploy/stand.nginx.conf` has runtime route candidates but `$runtime_ingress_enabled` remains0. No runtime DB setting was found in the Compose YAML sources searched. `ScanCreatePage.tsx` already mounts `RuntimeScanPanel` for authenticated non-demo users; the panel explicitly distinguishes historical/live and exclusions. No new UI implementation was required or performed. Its deployed browser behavior still needs verification after authorized activation.

## New controlled integration coverage

All test data is newly generated: temporary SQLite stores, synthetic account/session data and Ed25519 keys, synthetic projected inspect metadata, and synthetic image config/manifest bytes. No real Docker/registry/scanner calls. Local HTTP listeners bind loopback on ephemeral ports and close in cleanup. The image test uses the existing controlled byte-loader seam, but **actual owner ledger reads, image verifier, runtime service/controller, durable store and browser report parser**.

| Test area | What was actually exercised |
|---|---|
| Caller CLI / journal | Executable CLI; explicit-authorization refusal; no overwrite;0600 DB; no creation of excluded DBs; exclusive writer; whole-intent HMAC rejects changed owner; consumed/dispatched restart becomes indeterminate; same consent/nonce cannot dispatch again under a changed attempt; durable revoke; fixed failure output |
| API qualification | On macOS the platform guard rejects both synthetic records before any socket lookup; no platform spoof or successful fake reviewer. These tests do not independently exercise the Linux review/expiry/equal-key branches; qualification-before-socket ordering is source-inspected, not positive Linux execution |
| Nest composition | Real dynamic module with a permanently denied port; exact module selection; live capability false. Not a qualified positive capture |
| Real default HTTP bootstrap | Actual `RuntimeApiModule` and `configureParentIngress`; temporary real AuthStore/LedgerStore/RuntimeStore; cookie required, foreign Origin rejected, enrollment/explicit consent required; signed >1KiB historical intake; malformed duplicate-key rejection |
| Report identity / privacy | Exact full container/context/version, endedAt/hash; all fixed exclusions; strict browser parser; no source Env/labels/network canaries or import signature in the closed runtime DB; no source canary, broker subject, key or SQLite detail in checked JSON responses |
| Restart / changing target | Close/reopen API/runtime/auth storage; operator re-enrollment changes full ID/context/version; old report and finite SSE remain unchanged; same historical intent replays old receipt; default live denial adds no capture; seeded interrupted admission becomes failed INDETERMINATE without recapture |
| Owner boundary | Foreign detail/results/events/history cursor/cancel/revoke/image-link are denied; foreign image job denied before byte-loader I/O |
| Cancel / revoke | Controlled rows paused at real durable admission (no Engine dispatch), actual HTTP cancel/revoke plus no-op repeat, late commit rejected before and after reopen, exactly one terminal event |
| Image association | Real ledger with synthetic checked SBOM + failed CVE; loader error redacted; wrong platform rejected; config-digest mismatch rejected; correct manifest/config remain distinct; correct platform and original checked time preserved; append-only association survives runtime/auth reopen and replays without new loader I/O |

These are integration tests, not real scanner outcomes, independently observed Engine counters, namespace isolation, Linux IPC success, abrupt-process crash/stale-lock cleanup, nginx deployment validation or UI acceptance. Interrupted rows were seeded through actual store APIs and reopened; no crash evidence is invented.

## Initial continuation validation

From `server/api` (each invocation bounded to60s):

```sh
node --import tsx --test src/runtime/runtime-bootstrap.continuation.test.ts src/runtime/runtime-http.continuation.test.ts src/runtime/runtime-image.test.ts
pnpm exec tsc --noEmit -p ../runtime/tsconfig.json
```

- New continuation tests plus focused updated image regression: **7/7 PASS**, no skipped/cancelled tests.
- Runtime TypeScript project (includes API runtime and broker source dependencies): **PASS**.
- Focused ESLint on the six changed/new TypeScript files: **PASS** after removing one unused test import.
- Scoped `git diff --check`: **PASS**.
- Initial integration run intentionally exposed the timestamp mismatch (3/4 passed, valid link HTTP400); the adapter fix makes that path pass. No dependency install, old proof script or Docker lifecycle command was used.

## Follow-up: exact dynamic module selection

The user explicitly expanded write scope to parent ingress and targeted tests. Actual paths were found and read: `server/api/src/parent-ingress.ts`, `server/api/src/app.module.ts`, `server/api/src/main.ts`. Only parent ingress required a production change; no AppModule/main activation was necessary.

The reviewed qualified bootstrap must create **one** descriptor, include it instead of the static runtime module in its root imports, and pass that same descriptor to `configureParentIngress(app, selectedRuntimeModule)` after `NestFactory.create(..., { bodyParser:false })` and before init/listen. Do not rebuild the descriptor for selection, import both variants into a deployed root, or catch a selection failure and continue listening. The optional argument selects existing providers only: it mints no permit, performs no Engine/IPC connection, reads no enable environment variable and cannot qualify the port. Default startup still calls `configureParentIngress(app)` unchanged.

New `server/api/src/parent-ingress.runtime.test.ts` uses real Nest modules, real cookie authentication and newly created temporary auth/runtime stores. It does not initialize an image ledger. The dynamic test port is permanently unavailable (`available:false`), with capture throwing if reached; dispatch count stays zero. This is not a fake successful permit or live-capture qualification.

Five regression cases:

1. Default static composition and existing one-argument bootstrap: real HTTP authentication/pre-JSON intake, live denied.
2. Exact registered dynamic composition: same HTTP behavior, correct injected denied port, `authenticated-pre-json` capability, live denied.
3. Explicit unregistered dynamic descriptor with static module present: throws, no fallback, no raw-intake marker; correct static configuration still succeeds afterward.
4. Dynamic-only root: omitted/static selection and a separately rebuilt descriptor throw; the registered descriptor succeeds.
5. Static and dynamic variants in a diagnostic-only root without a runtime DB: only the explicitly selected service gets the raw-intake marker. This checks strict module scoping, not a recommended deployed composition.

Both HTTP cases assert malformed JSON with no cookie returns401 and with foreign Origin returns403 **before parsing**; authenticated duplicate keys return400; controls accept1024 bytes/reject1025; import DTO validation accepts the raw65536-byte boundary and rejects65537 with413; consented live capture returns403 `QUALIFICATION_MISSING`, no capture row and no dispatch.

Reproduction before the production fix: **1/5 PASS,4/5 FAIL**, including Nest `RuntimeApiModule does not exist in current context` for the dynamic root. After the fix: **5/5 PASS**. Final combined focused command below: **12/12 PASS**, zero skipped/cancelled tests (1.135s). Runtime-project typecheck, separately targeted parent-ingress regression typecheck and focused ESLint **PASS**. Lint initially found a test cleanup binding (`prefer-const`), corrected without dropping cleanup. Each new composition test has a10–15s deadline; its HTTP requests have3s deadlines; command invocations were bounded to60s.

**Full API typecheck was not green at the previous composition checkpoint.** It passed earlier, but concurrent parent-owned lease-token API changes subsequently produced **12 TS2554 errors in four neighboring test files**: `src/ledger/ledger.cve-policy.test.ts` (1), `src/ledger/ledger.migration.test.ts` (6), `src/ledger/ledger.outbox.test.ts` (4), `src/worker/image-config-runner.test.ts` (1). Missing arguments to the changed ledger methods are outside this write scope; those files were not modified by this work. The concurrent update also changed the existing runtime image fixture to call `finishCombined(..., undefined, job.leaseToken)` using its actual `claim()` token. That edit was already present on reread and was preserved, not overwritten. The intermediate combined run failed11/12 before the fixture update; final12/12 and both focused typechecks passed with the updated actual API. No lease check was weakened.

From `server/api`:

```sh
node --import tsx --test src/parent-ingress.runtime.test.ts src/runtime/runtime-bootstrap.continuation.test.ts src/runtime/runtime-http.continuation.test.ts src/runtime/runtime-image.test.ts
pnpm exec tsc --noEmit -p ../runtime/tsconfig.json
pnpm exec tsc --noEmit --target ES2022 --module NodeNext --moduleResolution NodeNext --strict --esModuleInterop --experimentalDecorators --emitDecoratorMetadata --skipLibCheck src/parent-ingress.runtime.test.ts
# Broader diagnostic run: blocked by the neighboring test errors listed above.
pnpm exec tsc --noEmit -p tsconfig.json
```

From repository root:

```sh
pnpm exec eslint server/api/src/parent-ingress.ts server/api/src/parent-ingress.runtime.test.ts server/api/src/runtime/runtime-http.continuation.test.ts
```

Scoped `git diff --check` passes. No ledger/worker/scans/UI files, live stand or existing DB were changed; no old proof, Engine call, stage/commit/branch or tracker mutation. Only new disposable test stores/listeners were created and cleaned up.

## Independent-review follow-up: R1/R2 path isolation

Read `docs/runtime-task6-independent-review-20261017.md` and reproduced the two P2 findings using only new disposable paths **before changing production code**. The initial87-case regression matrix failed on the actual excluded SQLite rollback-journal deletion and both demonstrated dangling-leaf/symlink-parent aliases. The reviewer report itself is unchanged; this is an implementation response **awaiting the original reviewer's reassessment**, not self-approval.

### Shared invariant, not a CLI-only check

Only production change for this follow-up: `server/api/src/runtime/runtime-store.ts`, in shared `checkedPath` plus its family helper. Existing `initializeRuntimeStore`, `RuntimeStore`, `initializeCallerJournal` and `CallerJournal` all call this guard before file/lock creation or SQLite opening, so direct library calls cannot bypass the CLI exclusion invariant. Parent composition/permit gates were not changed.

- Each nonempty path operand must be absolute and lexically normalized, without NUL, and have an **existing canonical directory parent**. `realpath(parent)` must exactly equal that parent. Existing leaf/family members must be regular, non-symlink files whose realpath is exactly the supplied path. This rejects dangling symlinks, directory-symlink ancestors and existing aliases rather than following or silently normalizing them.
- Missing leaf members are allowed only through the explicit `lstat(..., {throwIfNoEntry:false})` branch. Missing parents, permission/loop/non-directory/other identity errors fail closed with `RUNTIME_UNAVAILABLE`. An absent protected basename under an existing canonical directory remains usable. Empty optional exclusions still represent unconfigured API paths; the caller CLI still requires all three exclusions.
- Reserve exactly five family names for every operand: base, `-journal`, `-wal`, `-shm`, `.writer`. Pairwise exact-name comparisons cover forward and reverse collisions, including collisions between exclusions; existing device/inode comparisons cover hardlink identity. No prefix approximation: `own.sqlite-wal.backup` remains an ordinary distinct filename.
- **Init requires the whole new family to be empty**, not merely the main file. Any pre-existing sidecar or lock is rejected without interpreting, overwriting or deleting it. This prevents SQLite from using an excluded DB as a rollback journal.
- **Open/recovery retains valid private storage:** the main file must exist; all present own members must be owned0600/single-link/regular/canonical in the existing owned0700 directory and disjoint from exclusions. An existing `.writer` is refused, never adopted or deleted. Genuine private SQLite WAL snapshots still reopen and retain data. This is not arbitrary sidecar-content attestation or abrupt-process crash certification.

Compatibility impact: shared direct APIs now also refuse relative/noncanonical exclusions, protected paths whose parent directories do not yet exist, and overlapping protected families. Operators must supply canonical paths and provision approved parents explicitly; the guard creates no excluded files/directories and performs no cleanup. These are static filesystem identity/admission checks under the existing trusted-operator/private-directory assumption, not proof against concurrent same-UID namespace replacement, hostile mounts or missing Linux isolation.

### Regression evidence

New `server/api/src/runtime/runtime-path-isolation.test.ts`: **99/99 cases PASS** after the fix (original87 cases plus12 opener/recovery cases). Every rejected fixture action is checked against a recursive pre-action snapshot of names, inode/device, modes, link counts, file SHA-256 bytes and symlink targets; assertions fail even if the operation throws only after damage. No source DB/private data is used.

Coverage includes:

- Reviewer's real closed SQLite DB at `caller.sqlite-journal`: CLI refusal without creating the caller file or changing/deleting protected bytes.
- All four suffixes, both collision directions, existing and absent protected bases; unexpected existing own sidecars at init even with no exclusions.
- Direct caller/runtime init and reopen, including existing protected bytes at sidecar/lock names; collisions and inode aliases between exclusions too.
- Both exact CLI alias reproductions; direct init/open dangling/existing leaf symlinks, symlinked parents, absent parents, relative and dotdot operands; protected-sidecar symlinks and hardlinks at every own family member.
- Ordinary distinct existing/absent exclusions, non-colliding similar sibling names, normal reopen, and real quiescent SQLite WAL snapshot copies with integrity/data checks for each store. These copies are test recovery fixtures, not live DB backups or abrupt-crash evidence.

Executed from `server/api`, each invocation bounded to60s:

```sh
# Before production fix: failed regression matrix; both reviewer reproductions confirmed.
node --import tsx --test src/runtime/runtime-path-isolation.test.ts
# After fix, extended matrix plus prior focused regressions:
node --import tsx --test src/runtime/runtime-path-isolation.test.ts src/runtime/runtime-bootstrap.continuation.test.ts src/runtime/runtime-http.continuation.test.ts src/runtime/runtime-image.test.ts src/parent-ingress.runtime.test.ts
pnpm exec tsc --noEmit -p ../runtime/tsconfig.json
```

Final combined result: **111/111 PASS**, zero skipped/cancelled tests,1.405s. Runtime-project typecheck **PASS**. Focused ESLint on `runtime-store.ts` and `runtime-path-isolation.test.ts` **PASS**; scoped `git diff --check` **PASS**. Full API typecheck/full suites and old proofs were not rerun in this path-only follow-up; the earlier neighboring typecheck errors are historical, not a new claim about current files.

This follow-up changes only the shared runtime path guard, adds the regression file, and updates this handoff/operator runbook. No parent composition, ledger/worker/scans/UI, live DB/stand, tracker, review report, stage/commit/branch or qualification state changed. The existing review/expiry/equal-key test coverage limitation on macOS is acknowledged above; independent Linux inputs listed next remain mandatory.

## Minimal operator/parent handoff — not performed

### Existing historical lane

Parent authorization is required before any live-stand change. Allocate/initialize a **new separate** runtime SQLite file in a canonical owned0700 directory with0600 file and explicit non-alias exclusions. Enroll only approved subjects/full IDs/context/version and public signer keys using the existing `runtime-init.ts` CLI. Configure the approved `RUNTIME_DB_PATH`, preserving auth/image paths. Review/activate only the existing runtime nginx locations with their original limits and safe logging; do not enlarge other routes. Verify current capability, cookie/Origin controls, immutable reports, finite events and UI against that deployed build. This enables historical functionality only, not live capture.

### Live lane

The smallest next external action is an **operator-owned qualification handoff**, not setting an environment boolean:

1. Supply the already-owned dedicated isolated Linux Engine API1.47 environment and a separately reviewed trusted controller/observer implementation and enrollment described in `server/broker/proof/EXTERNAL_FIXTURE.md`. That controller is **not supplied by this patch**. Real no-bypass qualification needs independent namespace/mount/FD/UID/access checks and actual Engine/tap counters: positive1, negatives0. Existing candidates and file-mode/hash echoes are not acceptance. Do not rerun old proofs or perform lifecycle operations without new parent authorization.
2. Independently qualify the additional API/application caller/broker/observer/daemon topology and the **current** source/protocol hashes. API receives only private application job IPC; it must not have Engine/tap/controller sockets, daemon data or inherited alternate authority. Preserve exact subject/full target/broker-subject admission, configured image semantics, current context/version/epoch, short qualification expiry, and a genuine independent-review callback. Never replace the callback with `() => true`.
3. With writer stopped and explicit authorization, initialize the independent caller journal; do not reuse the API runtime DB. From `server/api`, documentation syntax only:

   ```text
   node --import tsx src/runtime/runtime-caller-init.ts init <absolute-new-caller.sqlite> --authorize-runtime-caller-journal <absolute-api-runtime.sqlite> <absolute-auth.sqlite> <absolute-image-ledger.sqlite>
   ```

   Operator supplies real canonical paths and private directory. The CLI needs no secret and does not start anything. Generate fresh distinct IPC credential/dispatch key through the reviewed operator path, never browser/env/log output.
4. In the separately confined caller composition, use existing `launchEnrolledRuntime` with the genuine qualification, reviewed tap boundary, exact subject callback and initialized journal. In the API composition, call new `createQualifiedRuntimePort` with that genuine qualification and only application IPC inputs, then `RuntimeApiModule.withQualifiedCapture(port)`. **The parent-ingress selection fix is now implemented.** A separately reviewed operator bootstrap must import the chosen dynamic module in place of the default static runtime module and pass that exact descriptor to `configureParentIngress(app, selectedRuntimeModule)`; retain `bodyParser:false` and pre-JSON cookie/Origin admission. Ordinary `app.module.ts`/`main.ts` were deliberately not activated or changed. Default module/provider stays off until this reviewed branch is explicitly selected. No generic proxy route or API Engine mount.
5. Verify actual HTTP→IPC→journal→broker→Engine→publication on the newly qualified environment, including target stop/change, expiry, cancel/revoke, acknowledgement loss, restart/one-use replay and owner boundaries. Reconcile proven stale locks manually only after establishing no writer remains; never auto-delete locks or recapture ambiguous attempts. Requalify before claiming readiness after restart or source/topology change. Keep writable layer, volumes and traffic excluded; no whole-host/effective-isolation claim.
6. Parent records actual new evidence and the task-sourced full-document delta/status when warranted. Feature DOC13v2 application and these local tests alone do not close TASK6.

## Exact continuation write set

New:
- `server/api/src/runtime/runtime-live-bootstrap.ts`
- `server/api/src/runtime/runtime-caller-init.ts`
- `server/api/src/runtime/runtime-bootstrap.continuation.test.ts`
- `server/api/src/runtime/runtime-http.continuation.test.ts`
- `docs/runtime-task6-continuation-20261016.md`

Modified:
- `server/api/src/runtime/runtime-image-link.adapter.ts`
- `server/api/src/runtime/runtime-image.test.ts`
- `server/runtime/docs/operator-runbook.md`

Follow-up adds `server/api/src/parent-ingress.runtime.test.ts`, modifies `server/api/src/parent-ingress.ts`, and updates the previous runtime composition test comment, runbook and this handoff. `app.module.ts`/`main.ts` remain unchanged.

No broker source change was needed. Beyond the explicitly authorized parent-ingress fix there are no deployment/config/UI edits, stage/commit/branch, tracker mutations, live changes, Docker/socket access, full inspect dumps, old `.local-auth`/retained holders/HOLD access, private environment/key reads or old proof reruns. Temporary synthetic keys and stores belong only to these tests and are cleaned up.
