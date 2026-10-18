# Public Docker Hub image-only API/UI — 2026-10-18

## Ownership / coordination

API/UI agent writes only `server/api/src/scans/**`, new `server/api/src/oci/public-image.module.ts` / `public-image.main.ts`, `src/pages/scans/**`, `src/shared/api/scans/**`, `tests-vite/ui/scans/**`, and this requested handoff. Existing dirty changes are preserved. No worker, other OCI, ledger, deploy, scripts, AppModule, old environment or commits are modified by this agent.

OCI-owned contract: `inspectPublicImage(reference: ImageReference)` from `oci/public-image-archive.ts`, returning `{registry, repository, digest, configDigest, platform, layers}` after authenticated bounded manifest/config inspection. API uses the actual `PUBLIC_IMAGE_LIMITS` from `oci/public-image-policy.ts`, not the narrower nginx legacy limits. Policy IDs are `public-hub-amd64-v1` and `public-hub-resources-v1`.

## Composition / wire

- Separate `PublicImageModule` / `public-image.main.ts`; default AppModule/main and nginx proof/local modules unchanged. No generic user flag. Browser cookies/allowlist/origin and internal JWT guards retained. The later bounded 8081 correction below selects the exact local-account origin through a compiled public-module provider, without broadening default/LLM trust.
- The public module exposes image scan/auth endpoints, **not runtime/host or LLM**. Its separate `configurePublicImageIngress` installs normal Nest body parsers only: the shared parent ingress requires/selects RuntimeApiModule and therefore must not be reused by this root. The new HTTP tests exercise the same bodyParser:false/bootstrap path as main. It deliberately does not import the default ScansModule indirectly. Existing runtime/LLM widgets may report unavailable against this image-only composition.
- Production DB trust is the default; this explicit entrypoint alone can select the existing reviewed `localDbTrustAnchorFromEnv()` helper (`LOCAL_CVE_TRUST_SHA256`, fixed key path). No trust-reader or production anchor rewrite.
- Public service accepts canonical `registry-1.docker.io/library/name:tag` / `registry-1.docker.io/namespace/name:tag` or pinned `@sha256:…`. No implicit registry, alias, URL, credentials, ports, nested path or non-amd64 platform. Anonymous DockerHub inspection, not private-registry authentication.
- The inspector runs before enqueue, with identity/config digest/layer resource fences. Common admission, ledger, readiness before/after resolution, idempotency fingerprint/replay, vulnerability enablement and authenticated current DB freshness guards are inherited. Jobs have **no nginx execution binding**; explicit worker public policy is required.
- Search uses the existing service hook: `eligibility: 'public-hub-profile'`, **`scannable: false`**. A Hub hit remains a candidate, selectable for actual eligibility inspection; it is not authorization.
- Checked SBOM and checked/unsupported CVE envelopes carry `profile: 'public-hub-amd64-v1'` **only when the selected persisted check belongs to an archive whose complete receipt passes `isPublicReceipt`**. Serving a result through PublicImageModule is not normalization authority. Legacy Alpine and exact-nginx archive evidence stays unmarked. The receipt decision and ordinary/report-v1 projection share one deferred read snapshot. Public profile markers remain closed literals; the browser's public numeric OS validation and legacy release grammar are unchanged. Failed report envelopes and secret wire stay unchanged. Public `NODE_INVENTORY_UNKNOWN` is separately allowlisted and displayed as unknown inventory, never inferred absence; the legacy absence reason remains distinct.
- Status uses the same actual archive-receipt classification when evidence exists. Without an archive, a valid generic non-Alpine/non-exact-nginx target without an execution binding may carry the public marker for queued/config-only identity; this does not upgrade checked legacy evidence. An actual valid public receipt selects public normalization even when its target name/digest also matches a legacy target.
- Status obtains the pinned full reference directly through **`ledger.pinnedTarget(scanId, subject)`**, inside the owner-checked read snapshot. No history traversal, process-local tag cache, or direct SQL bypass is used. Legacy targets still receive their accurate pinned identity without being relabelled.
- Browser ecosystem allowlist: `apk,deb,rpm,npm,pypi,gem,gomod,cargo,maven,composer,nuget`. SBOM controls and both query parsers use the closed set, preserving lexical tie keys/cursors. Literal name filtering additionally supports `:` for Maven identities. Raw fields and unknown ecosystem strings still fail closed.
- Manual canonical input and server eligibility are independent of discovery availability. Changing target/checks/consent invalidates pending submission; current subject/session fences and idempotent retry are retained. New public launches perform fresh preflight and API revalidation. UI explains image-only, DockerHub, amd64, resource and capability limits.

## Integration notes to OCI / worker / ledger owners

1. OCI inspector/public policy files are consumed read-only. No nginx binding is emitted for generic public jobs.
2. Worker must be explicitly started with public policy and validate archives/config independently; API acceptance never enables the old worker.
3. The initial controlled HTTP integration run exposed the old ledger restriction `validateStoredArchive → validateCombined → Invalid SBOM` for Debian/expanded ecosystems. The coordinator subsequently integrated the public receipt contract; the actual SQLite-backed public HTTP persistence regression now passes. No ledger file was edited by this API/UI agent.
4. The public config loader/runner/ledger wiring was subsequently integrated by its owners, including the forwarded explicit consumer argument reported by the coordinator. Default/legacy gates must remain restricted. This R2 slice changes no worker/config wiring and does not claim live config/DB/container qualification.

## Initial validation (before ledger integration and R2)

The results below are the historical first-pass record, not current outstanding blockers. Current R2 results follow in the next section.

No Docker, deployment, old-environment mutation, git branch/commit or live registry/Trivy qualification was performed. Temporary test databases and controlled HTTP fixtures are disposable; no existing local environment was loaded.

Commands run from repository root unless otherwise stated:

```sh
pnpm exec vitest run tests-vite/ui/scans --maxWorkers=2
pnpm exec tsc --noEmit -p server/api/tsconfig.json
pnpm exec tsc --noEmit -p tsconfig.json --incremental false
pnpm exec eslint src/pages/scans/ScanCreatePage.tsx src/pages/scans/ReportViewControls.tsx src/pages/scans/ScanReportSections.tsx src/shared/api/scans/publicImageProfile.ts src/shared/api/scans/reportView.ts src/shared/api/scans/scanTransport.ts src/shared/api/scans/llmChatContract.ts
```

- Scan UI suite: **24 files, 568 tests passed** with two workers, including seven new public-profile cases. An earlier unlimited-concurrency run had one timing-sensitive existing eligibility focus/replay assertion (565/566); its exact rerun and the full two-worker suite passed. No unrelated test was edited to conceal it.
- Both TypeScript checks and targeted lint passed after the test helper type fixes. They do not establish native/live scanner or deployment qualification.
- New public service/report tests verify inspector identity/config/resource fences, second readiness check, scope/default-profile/replay fences, historical boolean DB rejection, all reviewed ecosystems, Maven literal filters and query-bound lexical pagination.
- `scans/public-image.http.test.ts` drives real loopback Nest HTTP, real cookie auth and SQLite with controlled readiness and hash-linked OCI manifest/config byte transport. Its **admission test passes**: namespaces/official images, server suggestion hook, eligibility, pinned queued status, no nginx binding, cookie/JWT separation, foreign-origin/unlisted/owner guards, replay/conflict, forbidden flags/registries/implicit references/platforms, oversized layers, missing readiness and DB.
- Combined selected API/regression command: **55 tests: 54 passed, 1 failed**. Passing coverage includes ordinary browser/API HTTP guards, legacy config/archive/report HTTP, idempotent replay, discovery/query/page tests, and nginx candidate/LOCAL policy proofs.
- The one failure is deliberately retained: `public module HTTP persisted reports: normalized Debian/all-ecosystem archive → strict status/results/SBOM/report-v1`. It fails in out-of-scope `ledger.ts:validateCombined` via `validateStoredArchive` / `finishArchive` with **`TypeError: Invalid SBOM`**. No native public result has been claimed. That test uses a synthetic normalized persisted outcome, not fabricated live scanner output. The remaining generic config-target path is also an integration requirement, not verified working.

Selected API command (run from `server/api`):

```sh
pnpm exec tsx --test src/scans/public-image.http.test.ts src/scans/public-image.service.test.ts src/scans/public-image-report.test.ts src/scans/scans.http.test.ts src/scans/browser-scans.http.test.ts src/scans/scans.replay.test.ts src/scans/scans.config.http.test.ts src/scans/scans.archive.http.test.ts src/scans/scans.report.http.test.ts src/scans/image-reference.test.ts src/scans/image-search.test.ts src/scans/report-query.test.ts src/scans/report-page.test.ts src/oci/nginx-local-policy.test.ts src/oci/nginx-candidate.test.ts
```

## R2 follow-up — receipt-derived markers and direct owner identity

Independent finding: `docs/public-image-chain-review-20261018.md`, **R2**. The original wrapper applied the public marker to legacy normalized results merely because PublicImageModule served them. A legitimate persisted Alpine SBOM release `edge` was then rejected by the deliberately numeric public browser contract.

### Changes

- `server/api/src/scans/public-image-scans.service.ts`: ordinary and report-v1 markers now require the **actual selected check's complete public receipt**, using the OCI-owned `isPublicReceipt` predicate. Marker selection and response projection share the same deferred ledger read snapshot. Legacy Alpine and exact-nginx results retain their unmarked wire semantics.
- Status uses the same receipt authority for archived evidence, not the endpoint or repository alone. Public target-based queued/config-only identity is kept separate from result normalization; known legacy Alpine/exact-nginx targets remain unmarked until there is actual public receipt evidence.
- Replaced the O(n) paginated history walk with the new owner-scoped `ledger.pinnedTarget(scanId, subject)` accessor. No direct SQL or ledger/worker writes.
- Added `server/api/src/scans/public-image-legacy.http.test.ts`. This slice writes only that new scoped test, the public scan service, and this handoff. No browser grammar was loosened, no independent reviewer document was rewritten, and no default AppModule/nginx composition was changed.

### Reproduction and regression evidence

Before the service correction, the new **real loopback HTTP** regression reproduced the review finding: both legacy Alpine `edge` and exact-nginx `edge` SBOM responses failed the actual browser parser with `Недопустимый профиль SBOM`. Its queued status case also failed when a test guard prohibited calling `ledger.list`.

After correction, the regression passes using actual Nest ingress/controllers, cookie auth **and internal JWT routes**, real SQLite enqueue/claim/finish/read, and the actual browser parser for **both ordinary and report-v1** responses. Persisted reports are declared synthetic normalized fixtures, not live scanner/image evidence. It verifies:

1. A legacy Alpine `edge` SBOM published with `finishCombined` remains unmarked and decodes through both report forms; status agrees.
2. A legacy exact-nginx archive SBOM with the previously allowed `edge` release remains unmarked and decodes through both forms; status agrees.
3. Genuine public numeric receipt-backed reports retain the public marker. A public receipt still selects the public contract on a target that also matches an Alpine or exact-nginx legacy target; repository names alone do not decide the contract.
4. Forging a public checked report's release to `edge` is rejected by the browser parser in ordinary **and** report-v1 form. The real ledger also refuses publication of a genuine public-receipt checked SBOM with that nonnumeric release. Legacy unmarked replies still reject a different OS family; no legacy grammar was expanded.
5. Queued public/config-only identity uses `pinnedTarget` with the exact scan ID and owner. A throwing `ledger.list` guard proves no history traversal for queued or completed status reads. Allowlisted foreign owners receive 404 and do not reach the pinned-target accessor.

### Repeated validation

- Focused public selection initially passed **15/15** after correction; the regression then additionally covered an actual public receipt on a legacy Alpine target.
- Expanded API/legacy/nginx selection below: **65/65 passed**, including all eight tests/subtests in the new R2 HTTP regression, both previous public HTTP tests (including the previously blocked Debian/all-ecosystem persistence test), ordinary SBOM/CVE HTTP, config/archive/report HTTP, auth, discovery, replay and nginx LOCAL/candidate proofs.
- `pnpm exec vitest run tests-vite/ui/scans --maxWorkers=2`: **24 files, 568/568 tests passed**.
- API `pnpm exec tsc --noEmit -p server/api/tsconfig.json` and repository `pnpm exec tsc --noEmit -p tsconfig.json --incremental false`: **both passed**.

Expanded API command, from `server/api`:

```sh
pnpm exec tsx --test src/scans/public-image-legacy.http.test.ts src/scans/public-image.http.test.ts src/scans/public-image.service.test.ts src/scans/public-image-report.test.ts src/scans/scans.http.test.ts src/scans/browser-scans.http.test.ts src/scans/scans.replay.test.ts src/scans/scans.config.http.test.ts src/scans/scans.archive.http.test.ts src/scans/scans.report.http.test.ts src/scans/scans.sbom.http.test.ts src/scans/scans.vuln.http.test.ts src/scans/image-reference.test.ts src/scans/image-search.test.ts src/scans/report-query.test.ts src/scans/report-page.test.ts src/oci/nginx-local-policy.test.ts src/oci/nginx-candidate.test.ts
```

No Docker, deployment, old-environment modification, registry/Trivy execution, live qualification, branch or commit was performed. This API/UI R2 retest does not resolve or reclassify the independent worker-owned R1 finding; that remains its owner's/reviewer's responsibility.

## Disposable real-browser public API proof

New exclusively owned files:

- `tests-e2e/public-image-api.mjs` — managed Chromium/Vite/API orchestration and browser assertions.
- `server/api/src/scans/public-image.browser-fixture.ts` — test-only PublicImageModule/Nest fixture with controlled OCI transport/readiness/archive outcomes. It is not imported by any application module or production worker entrypoint.

Exact command, from the repository root (`diplom`):

```sh
node tests-e2e/public-image-api.mjs
```

Use the existing workspace dependencies and installed Playwright Chromium. The command re-execs with a minimal environment before loading application/browser libraries; it does not load an old stand environment, Vite env files or the normal Vite config. It creates new disposable auth/ledger SQLite files and a Vite cache in its own temporary directory. The original `tests-e2e/report-live-api.mjs` and coordinator changes (including `prefer-const` in the service test) were not edited.

### Actual browser flow verified

1. Start actual PublicImageModule/Nest ingress and disposable SQLite, and register two disposable accounts through real auth HTTP. Both accounts are explicitly enrolled in the existing browser allowlist; no guard is bypassed.
2. Launch actual Chromium against the current Vite UI. Log in through the UI and verify the real HttpOnly/SameSite session cookie without printing it.
3. Navigate to `/scans/new`; manually enter `registry-1.docker.io/browser-proof/application:controlled`, select **Secrets + SBOM + Image config**, leave CVE off, and confirm target/check consent. No image suggestion substitutes for manual entry.
4. Observe a **fresh eligibility POST after the submit action and before scan creation**, then the actual canonical scan POST/202. Assert that the payload contains only the four reviewed fields, there is one creation POST, and the browser's detail view confirms the pinned digest/platform from an authorized queued status.
5. Invoke the real `consumeOne` through private test IPC with explicit public composition. The actual config module verifies controlled hash-linked manifest/config bytes (numeric UID 1000). The injected public archive runner supplies normalized synthetic Secrets/SBOM outcomes; actual config/secret/SBOM checkpointing and SQLite final publication execute with the consumer's claim/lease machinery. Native/default scanner fallbacks are fail-fast.
6. Verify the actual browser report renders **Debian 12 inventory with `deb` and `npm` rows**, Secrets line zero and Image config coverage. Use the actual SBOM filter select for npm and deb, inspect the real report-v1 HTTP responses, and verify the corresponding two rows and global matched/total counts in the rendered UI.
7. Reload the page: the real owner cookie and durable checked report remain usable; report-v1 starts at the first page/default filters and all four inventory rows render again.
8. Open a separately seeded, real-ledger legacy Alpine `edge` report through the public endpoint and render it in Chromium. Both the ordinary SBOM response and the rendered report-v1 response remain unmarked, preserving R2's legacy/public contract distinction without relaxing public numeric validation.
9. In separate browser contexts, log in as the other enrolled account and verify actual status/ordinary SBOM/report-v1/Secrets endpoints return 404 with no owner rows; the UI displays the denial. Anonymous requests return 401 and the UI presents the login guard with no rows.

All browser application requests continue unchanged through Vite's real proxy to Nest. There is **no HTTP `fulfill`, fetch/response substitution or mocked API server**. Context routing blocks every origin except the proof's exact loopback origin; service workers/downloads are disabled, background networking is disabled, and non-loopback DNS resolution is blocked. Direct context API requests are also constrained to that origin with redirects disabled. This is not a network-namespace/container qualification claim.

### Observed result and bounds

The final new proof command passed on Chromium **147.0.7727.15**, in **7,673 ms**, with:

- `pageErrors: 0`, `externalBrowserRequests: 0`, `mockedHttp: false`;
- one public consumer invocation, two pinned config object loads, accepted Secrets/SBOM checkpoints, checked config, and completed durable status;
- explicit cleanup PASS: disconnected/closed browser, API exit code 0, closed Nest/Vite loopback listeners, removed disposable SQLite and Vite cache (ENOENT verified).

The first development attempt reached the rendered report but used an over-specific filter locator. It exposed an armed Playwright response-wait rejection during failure handling. The new proof was corrected to use the real control's label and to handle armed response rejections immediately; its failed-attempt scratch was removed and no proof processes remained. The corrected command then passed twice. Normal cleanup runs in `finally`; navigation/actions, API readiness, consumption and cleanup have explicit bounds, with a 100-second managed deadline and an outer owned-process-group watchdog. Failure output uses fixed stage names instead of raw exceptions/auth/scanner bodies; no password, cookie, token, environment or injected config canary is printed.

Additional **targeted-only** validation passed:

```sh
node --check tests-e2e/public-image-api.mjs
pnpm exec eslint server/api/src/scans/public-image.browser-fixture.ts
pnpm exec tsc --noEmit --target ES2022 --module NodeNext --moduleResolution NodeNext --strict --esModuleInterop --experimentalDecorators --emitDecoratorMetadata --skipLibCheck server/api/src/scans/public-image.browser-fixture.ts
```

No full API/UI suite was rerun for this slice. The coordinator's reported **full API 1164 PASS** is preserved as coordinator evidence, not claimed as a new run by this agent.

### Deliberate limitations

**Real:** Chromium, current UI, Vite, PublicImageModule/Nest/ingress, cookie auth/ownership guards, SQLite, API admission/idempotency path, public consumer/config checks/checkpoints/finalization, report-v1 and browser parsing/rendering.

**Controlled:** scanner readiness; anonymous OCI manifest/config transport bytes; normalized Secrets/SBOM public archive runner outcomes and synthetic receipt/metrics; preseeded normalized legacy Alpine `edge` evidence. The public archive runner is deliberately injected at the normalized-outcome seam: no real layer download, gzip/tar acquisition, archive-byte validation, raw Trivy JSON normalization or native scanner invocation is established by this proof. Config verification is real but its input bytes are synthetic.

CVE is deliberately unchecked: no signed CVE DB, CVE findings, vulnerability freshness qualification, public registry availability, Linux cgroup/tmpfs qualification, Docker, deployment, old-state mutation or live-image security acceptance is claimed. No branch or commit was created.

## Initial prepared native 8081 handoff — historical NOT_RUN

New file at that stage: `tests-e2e/public-image-live.mjs`. **The initial delivery was prepared source with offline guard validation only; native execution was NOT_RUN because the isolated Docker/native stand was unavailable then.** Neither this proof nor the old `tests-e2e/local-stand-live.mjs` was executed by this agent against a stand. The existing disposable Chromium/PublicImageModule integration PASS above is retained; it is not relabelled native evidence. The later coordinator-reported real Node PASS and newly prepared Debian mode are recorded separately below.

### Expected first action once Docker is genuinely available

The operator/coordinator must first establish or independently attest the **separate, approved native public stand at exactly `http://127.0.0.1:8081`**, with its intended isolated fresh account/report storage, actual public API and worker entrypoints, native Trivy 0.69.3, reviewed 4 GiB/2304 MiB resource envelope, bounded egress, and matching signed/current CVE DB trust/release on API and worker. Browser HTTP cannot attest Docker volume isolation, process image IDs, cgroups, key mounts or signature files. Docker availability alone is not readiness.

Use only the coordinator's approved isolated-8081 lifecycle procedure. This slice does not invent/run a launcher or Compose command, read activation/private env files, change the old stand, or use an old/shared volume. Do not work around a blocked rollout plan, change this script to 8080, pass an origin override, or run the old live smoke as a substitute.

**Only after that gate, the exact held proof command is:**

```sh
# Working directory: diplom
node tests-e2e/public-image-live.mjs --run-native
```

The first network-mutating proof action is registration of **one newly generated random account** through the actual UI on 8081. Email/password are generated in memory; no user/old credentials are accepted, printed or saved. The stand must already authorize that fresh account through its reviewed browser access policy. A genuine 403/DB/readiness/resource/admission failure is a stop/no-qualification result: the script does not enroll itself, edit an allowlist/env, weaken a guard, swap trust, drop CVE/config, choose another target or retry creation.

The proof intentionally retains its new stand-side account and at most one new scan. Passwords, cookies, raw reports, screenshots/traces/storage state and auth bodies are not written to disk. On timeout or lost POST acknowledgement, a native attempt may still exist; the receipt reports that uncertainty and there is **no relaunch or automatic cancellation**. The script cleans up only its own browser contexts/process, timers/listeners/IPC watchdog—not Docker, servers, stand accounts, jobs, DBs or volumes.

### Fixed single-target behavior

- Only `127.0.0.1:8081`, only canonical `registry-1.docker.io/library/node:22.14.0-alpine3.21`, only requested **Secrets + SBOM + CVE + config**. There are no URL, port, target, account, password, env-file, check-set or worker-timeout overrides, and no target/check fallback matrix.
- The default invocation without `--run-native` says `NOT_RUN` and exits without contacting the stand. `--self-test` is offline only. Unknown arguments and direct internal-child invocation are refused before any browser/network/account work. The native child receives only minimal standard runtime environment variables, not existing stand/JWT/provider credentials or Vite env values.
- Use the actual manual canonical-reference input. Select the requested checkboxes only after a genuine full-four-check `READY` response for that exact reference; then require consent and a **new real eligibility response after submit is armed and before the single creation POST**. Only that recent, exact server grant permits the unchanged UI POST. An unrelated automatic saved-nginx eligibility probe is blocked as an unrelated read, not replaced by mocked eligibility.
- No fetch patch, request `fulfill`, HTTP response replacement, backend fixture, readiness override or injected OCI/scanner result. Browser app/API traffic is continued unchanged only to the fixed proof origin; non-loopback/8080, unrelated API reads, WebSockets and unintended mutations are blocked. No Docker/server process is started or stopped.
- Wait up to **660 seconds for native terminal status**, allowing the native attempt's possible 600-second budget plus bounded queue/transport allowance. The entire native proof has a 15-minute deadline, bounded browser cleanup and an outer owned-child-group watchdog (last resort by approximately 15m55s). No repeated scan POST.
- Establish pinned identity exclusively from actual authorized GET status: explicit full `library/node@sha256:…`, digest, `linux/amd64`; reject absent/mismatched identity and keep it immutable. Do not project digest/platform from the request or substitute legacy Alpine/nginx. The fixed Node target is not a legacy exception: checked results require the public marker, exposed receipt profile/resource/config digest, public check version and no nginx qualification binding. Actual legacy evidence stays governed by the already tested R2 behavior, but is not a fallback in this one-target proof.
- Require completed, genuinely checked outcomes for **all four requested checks**, positive accepted SBOM inventory, checked OS CVE coverage and strict config evidence. Failed/partial/cancelled, missing SBOM/CVE, unknown count, unsupported/EOL OS or config failure cannot yield success. The sanitized outcome receipt preserves known per-check outcomes/reasons instead of inventing zeros.
- Reuse the actual strict browser decoders and report-v1 query contract. Walk complete accepted reports within the existing 1000-row/20-page bounds; enforce unique rows, totals, matched counts, cursors, target/scanner/check timestamp identity and status count agreement. Preserve real inventory and verify npm filter rows **when present**. Missing npm SBOM evidence is reported as not reported—not proof of package absence or full npm CVE coverage.
- Validate matching strict CVE v2 DB identity/source/schema/hashes, saved worker/evaluation clocks, policy warnings and expiry between status and report. Keep current versus saved freshness checks distinct. A confirmed checked **zero CVE count is allowed**; no positive count or invented finding is required. `OS_EOL`, `OS_UNKNOWN`, unsupported or absent CVE coverage is never treated as a pass. Browser checks validate API-reported evidence, not DB signatures/key mounts independently.
- Verify actual rendered report rows/config coverage, reload with identical durable pinned/report/DB evidence, close the initial context, prove anonymous 401, then log in from a **fresh context with only that new in-memory account** and verify the same persisted reports again.

### Outcome interpretation / outstanding native gaps

A future successful execution may emit **`PASS_SINGLE_NATIVE_TARGET`** only after the actual four-check report/DB/UI/reload/fresh-login checks complete. `wholeSystemQualification` is always false: even that result is not complete deployment, scheduler, cancellation, arbitrary-image/ecosystem or security qualification. Failure/unsupported/unavailable/deadline cases emit **`NOT_QUALIFIED`** with a fixed stage/code and allowlisted actual per-check outcomes; raw errors/auth/server/scanner bodies are suppressed. Account/scan uncertainty is explicit. A native execution claim is not set merely because the native mode was requested.

**Unverified at the initial prepared handoff (later coordinator Node evidence below supersedes the applicable items):** server reachability/startup on 8081; actual fresh-storage isolation and public/native composition; fresh-account permission; real gateway/manifests/layer/archive handling; this tag's current resolved digest/platform/inventory/npm/EOL behavior; signed DB readiness/expiry on both processes; native Trivy outcomes/counts/config; Docker resource enforcement; and the complete live-browser path. The existing UI eligibility client timeout may stop a cold registry/DB preflight before the longer server inspector budget; the proof must stop honestly rather than fabricate readiness or bypass the UI. No unsupported/EOL result or source-only overlay is native acceptance.

### Only validation performed for this new handoff

```sh
node --check tests-e2e/public-image-live.mjs
node tests-e2e/public-image-live.mjs --self-test
```

Both returned exit 0. The self-test explicitly reported **`OFFLINE_GUARDS_ONLY`, `nativeExecution: false`, `nativeQualification: NOT_RUN`, `networkRequests: 0`, `accountsCreated: 0`**. It checks argument refusal, fixed-origin/8080/credential-origin rejection, exact READY/check-set gates and refusal of target/scope/extra-field intent overrides. It does not import Playwright or perform browser/server/Docker/account operations. No native command, old smoke, running server, actual account creation or full suite was run for this slice.

## Bounded 8081 access correction — ready for coordinator rebuild

The coordinator subsequently established the isolated 8081 stand and reported an actual native-proof attempt: registration **201**, **one new account, zero scans**, followed by eligibility **403 SCAN_ACCESS_DISABLED**. That report supersedes the earlier reachability/fresh-account assumptions above; it does **not** establish native scanning qualification. This agent did not contact that stand or execute either browser proof during this correction.

### Exact trust selection

- Additional explicitly authorized helper edit: `server/api/src/llm/browser-identity.ts`. The helper's fourth argument is a closed union of **exactly** `http://127.0.0.1:8080` and `http://127.0.0.1:8081`, with a runtime fail-closed check and default **8080**. No environment/request-selected trusted origin, arbitrary loopback port, hostname alias or external origin is accepted for all-local trust.
- `server/api/src/scans/browser-scans.controller.ts` optionally injects the `BROWSER_SCAN_LOCAL_ORIGIN` symbol; absent provider retains 8080. Only `server/api/src/oci/public-image.module.ts` supplies the compiled literal **8081**. This is one selected origin, not a two-origin allowlist: public composition rejects all-local 8080 and default composition rejects all-local 8081.
- `BrowserIdentity.resolve()` still invokes the helper with its original three arguments, preserving the LLM bridge's default 8080 boundary. Default AppModule/ScansModule/runtime implementations were not changed. The token is neither global nor exported from PublicImageModule.
- All-local still requires both explicit flags (`SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS=true`, `AUTH_ALLOW_INSECURE_LOCAL_HTTP=true`), exact matching `AUTH_ORIGIN`, and a real unrevoked cookie session. Misconfigured all-local cannot fall back to enrollment. With all-local off, explicit user enrollment remains unchanged; mutation origin/body guards, bearer/cross-site rejection, owner denial and internal JWT separation remain enforced.
- Previously owned public HTTP fixtures now use logical AUTH_ORIGIN/Origin 8081. They still bind **ephemeral loopback ports**, never fixed 8081, and continue to use explicit enrolled IDs. The existing real-browser fixture's explicit enrollment was left unchanged, as were old guard tests and both proof scripts.

### Focused regression and validation

New `server/api/src/scans/public-image-origin.http.test.ts` uses real Nest/public and default module compositions, HTTP cookie registration/logout, SQLite enqueue/status and ephemeral listeners. Only readiness and OCI inspection are injected controlled fixtures; no registry/native scanner evidence is claimed. It proves public-8081 eligibility and creation without enrolled IDs, exact default/public origin separation, anonymous/invalid/revoked-cookie denial, foreign mutation Origin/content-type rejection, bearer/cross-site rejection, owner 404, explicit enrollment boundaries, insecure-flag rejection, external/alias/alternate-port configuration rejection, invalid helper-argument rejection and unchanged LLM-bridge defaults. Every HTTP request has a five-second timeout; test cases are bounded and close their own app/remove temporary databases/restore environment in `finally`.

Commands actually run for this correction:

```sh
# Working directory: diplom/server/api
pnpm exec tsx --test src/scans/public-image-origin.http.test.ts src/scans/browser-scans.http.test.ts src/scans/public-image.http.test.ts src/scans/public-image-legacy.http.test.ts src/scans/public-image.service.test.ts

# Working directory: diplom
pnpm exec tsc --noEmit -p server/api/tsconfig.json
pnpm exec tsc --noEmit -p tsconfig.json --incremental false
pnpm exec eslint server/api/src/llm/browser-identity.ts server/api/src/scans/browser-scans.controller.ts server/api/src/oci/public-image.module.ts server/api/src/scans/public-image-origin.http.test.ts
```

**Results: 17/17 API tests/subtests passed; both TypeScript checks and targeted lint passed.** Legacy Alpine/exact-nginx receipt/ordinary/report-v1 regressions and controlled public Debian/expanded-ecosystem persistence remain passing. No full suite was rerun. The coordinator's earlier full API **1164 PASS** and the earlier actual disposable Chromium integration PASS remain historical evidence, not newly executed results.

**Next action belongs to the coordinator:** rebuild/restart only the approved isolated public API composition so it contains the compiled 8081 provider, then separately authorize/run the unchanged native proof command documented above. This patch itself makes no deployment or native PASS claim. No Docker/lifecycle command, live HTTP/account/scan operation, old environment/state access, commit or old-proof modification was performed in this correction.

## Second bounded native probe — compiled Debian mode, prepared only

### Prior real Node evidence — coordinator report, not a rerun

The coordinator reports the original Node proof command completed with **exit 0 / PASS**, finished **2026-10-18T08:52:44.099Z**:

- Scan `39915a8e-d352-4329-b46d-4716c678d1cb`, digest prefix `01393fe…`. Only a prefix was supplied in this handoff request; no full digest is invented here.
- All four requested checks checked; **SBOM 217 (npm 200), CVE 158 (apk 97 / npm 61), Secrets 0, config 1**.
- The coordinator rebuilt the actual public stand with the compiled DI-selected 8081 browser origin correction. The earlier eligibility-403 root cause is resolved; it is not an outstanding origin blocker.

This records the coordinator's real single-target evidence, not a native run performed by this agent or whole-system qualification. The original disposable browser integration PASS remains independent controlled-fixture evidence. Neither result is projected onto Debian.

### New exact command — coordinator to run once

```sh
# Working directory: diplom; approved isolated native stand must already be running
node tests-e2e/public-image-live.mjs --run-native-debian
```

The first mutating action remains actual UI registration of one newly generated in-memory random account on **exactly `http://127.0.0.1:8081`**. The coordinator should run this once and capture its allowlisted receipt/exit status. The proof may retain that new account and at most one native scan; no automatic relaunch or stand cleanup is attempted. This slice does not run that command, contact the stand, read existing credentials/state, or operate Docker.

### Closed selection and retained checks

- `tests-e2e/public-image-live.mjs` now has exactly two compiled native selections. Existing `--run-native` still selects **`registry-1.docker.io/library/node:22.14.0-alpine3.21`** (expected SBOM OS `alpine`); new `--run-native-debian` selects **`registry-1.docker.io/library/debian:bookworm-slim`** (expected SBOM OS `debian`). There is no arbitrary target/URL/port/credential/environment override or fallback matrix.
- Each outer mode maps to its own closed internal child flag (`--native-child` or `--native-debian-child`). Direct external child invocation remains refused without the managed IPC parent. Both native children receive only the same minimal allowlisted runtime environment; AUTH_ORIGIN, target, credential, DB-path, NODE_OPTIONS/NODE_PATH and other application configuration are not forwarded.
- Both modes reuse the same actual manual reference/check selection/consent and fresh exact four-check eligibility-before-one-POST proof. Each requires its own canonical eligibility and intent, and its own exact pinned repository regex. A Node grant/intent/pin cannot authorize Debian or vice versa. No request/response mocks or injected scanner data were added.
- Strict public receipt/profile/resource/config/check-version, immutable GET-established digest/platform, terminal state/all-four-checked, positive SBOM inventory, actual selected OS, saved/current DB metadata/freshness, complete paginated rows/counts, rendered UI, owner ID, anonymous denial, reload and fresh own login checks remain. Report CVE OS/Node subcoverage is additionally required to equal status subcoverage. Legacy/EOL/unknown OS and missing SBOM/CVE do not pass; a genuinely checked zero CVE count remains valid.
- Debian **does not require positive npm inventory or findings**. Actual npm filter/UI verification still runs only when npm components are reported. Zero reported npm rows remain `not-reported-not-proof-of-absence`; unsupported public Node coverage must remain exactly `NODE_INVENTORY_UNKNOWN`, never `NODE_INVENTORY_ABSENT`. The sanitized receipt now includes the validated Node coverage under inventory as well as DB evidence. No npm absence or full npm CVE coverage is inferred.
- Bounds remain unchanged: up to **660 seconds** for native terminal status, **15-minute** proof deadline plus bounded own-child/browser cleanup. No lifecycle operations, old smoke changes, additional accounts for owner tests, repeated scan POSTs or full new matrix.

### Offline validation actually run

```sh
node --check tests-e2e/public-image-live.mjs
node tests-e2e/public-image-live.mjs --self-test
```

**Both exited 0.** The self-test reported **`OFFLINE_GUARDS_ONLY`, `nativeExecution:false`, `nativeQualification:NOT_RUN`, `networkRequests:0`, `accountsCreated:0`**, listing both fixed references. It covers both native-mode/internal-child mappings, refusal of direct children/mixed modes/target arguments, cross-mode eligibility/intent/pinned identity rejection, exact four-check READY gating, fixed-origin safety and stripping hostile environment overrides. It imports neither Playwright nor browser TS decoders and performs no browser/server/Docker/account operations.

**Debian native result is NOT_RUN/unverified.** This edit changes only the proof and this own handoff. No API/UI/full suite or actual native proof was rerun. A future Debian PASS would establish only this second exact target's observed API/UI/native evidence, not arbitrary Debian tags/images, all ecosystems, absence of Node, DB signature mounts/resource enforcement or whole-system qualification.

## Public Debian TEMP identifiers — source contract / controlled validation, not native publication

Source evidence read: `server/api/src/worker/docs/native-debian-20261018.md`. The worker-owned candidate replay retained **88 Debian packages and 241 vulnerability findings: 236 CVE + 5 exact Debian TEMP advisories**. That diagnostic is not a newly published all-four ledger/API/UI result. No native report bytes, account credentials or actual ledger rows were read by this API/UI change; no worker/ledger/OCI/deploy source was edited. The ledger owner's integrated public-only acceptance is consumed through the existing ledger API.

### New reviewed wire contract

- Compatibility field **`cveId` keeps the exact identifier**, including `^TEMP-[0-9]{7}-[A-F0-9]{6}$`. TEMP is accepted only with ecosystem **`deb`** and the actual receipt-derived **`public-hub-amd64-v1`** marker. It is not rewritten into a CVE, silently dropped, or widened to GHSA/arbitrary identifiers/other ecosystems. No legacy intake waiver is introduced. Legacy plain historical rows and legacy advisory-backed CVE grammar remain intact; TEMP is not admitted as legacy evidence.
- Public checked vulnerability **status has top-level `identifierCounts: { cve, debianTemp }`**. Its sum must equal `perCheck.vuln.findingCount`. Public checked ordinary and report-v1 **vulnerability envelopes have the same top-level field**, whose sum equals `findingCount`. Each counter and the aggregate are bounded by the existing 1000-finding report limit. These are counts of saved finding rows by identifier namespace, not a claim of distinct unique advisory records or current exposure.
- `PublicImageScansService` derives counts from the **complete checked persisted archive's findings** in the **same deferred owner-checked read snapshot** that chooses the public receipt marker and projects status/report. No direct SQL, history traversal, supplied scanner aggregate, current page count or frontend inference is authority. Legacy, failed, unsupported and queued results carry no invented partition/zero.
- The browser requires the partition for public checked vulnerability status/report, checks the total, validates the closed ID/ecosystem namespace and bounds each returned page's CVE/TEMP counts by the global partition. A complete whole-report page must exactly match the partition. report-v1's existing totals/matched/offset/cursor/filter validators remain active; UI report identity additionally requires partition equality with authoritative status, across pagination/reload/filter transitions.
- On a filtered report, `identifierCounts` still describes the **entire saved report before filters**. The existing `page.matchedCount` describes the complete selected filter, while visible-page namespace counts describe only returned rows. No global filtered partition is fabricated from a page. Vulnerability sorting uses severity with the existing opaque `findingId` tie key, so TEMP requires no arbitrary new query/ID-filter grammar; SBOM literal-name and closed ecosystem filters remain unchanged.
- TEMP advisory metadata must have **empty references** in this increment; no genuinely mapped external TEMP reference support is added. `validAdvisoryReferences` explicitly enforces that rule. `canonicalReferences(TEMP)` produces no links. CVE.org/NVD/BDU/FIRST URLs are not fabricated for TEMP. Existing advisory text/CVSS/provenance/source/byte limits remain closed.

Examples of aggregate semantics (not live response captures):

```json
{ "findingCount": 241, "identifierCounts": { "cve": 236, "debianTemp": 5 } }
```

The same helper yields `{ "cve": 158, "debianTemp": 0 }` for an all-CVE 158-row public report. **241 total findings must never be labelled “241 CVE”.** Older public checked responses lacking the new field fail closed in the updated browser; deploy matching API/UI source together, after coordinating the ledger integration. Existing stored valid public receipts require no rewrite: counts are derived on read.

### UI and native-proof source changes

- Public report heading/category/coverage/summary/pagers use **«Уязвимости»**; actual legacy reports retain their CVE labels. Whole-report summary explicitly says **«236 CVE, 5 Debian advisories»**, independently of the loaded/filter subset. A public native select replaces the old CVE-specific mobile/desktop category labels without editing the out-of-scope shared feature component.
- Each TEMP card displays the exact compatibility ID, **«Debian advisory (не CVE)»** and neutral **«Advisory ID»**, with no invented external links or “this CVE”/BDU messaging. No findings are hidden merely to obtain a CVE-only presentation. Node coverage `NODE_INVENTORY_UNKNOWN` continues to mean unknown inventory, not package absence.
- `tests-e2e/public-image-live.mjs` retains both closed Node/Debian modes, fixed 8081, four checks, fresh eligibility, one POST, full immutable target/receipt/DB/count/UI/owner/reload/fresh-login checks, bounds and own-browser-only cleanup. It now matches the public **«Результаты Уязвимости»** region, verifies each report's partition against status and against all fully paginated accepted rows, and emits **`counts.vulnTotal`, `counts.cve`, `counts.debianTemp`**. For the candidate count shape those are **241 / 236 / 5**, not `cve:241`. Node's 158-CVE partition remains **158 / 158 / 0**. Native source is prepared only; neither native mode was executed for this slice, and the earlier coordinator-reported Node PASS is not relabelled a run of the revised source.

### Actual controlled regression evidence

New owned files:

- `server/api/src/scans/public-vulnerability-identifiers.ts` — API count helper using the worker's ecosystem-aware `publicVulnerabilityId`.
- `server/api/src/scans/public-vulnerability.fixture.ts` — declared synthetic normalized count-shape fixture, not a native report/digest; not imported by application composition.
- `server/api/src/scans/public-vulnerability.http.test.ts` — real disposable Nest/PublicImageModule/auth/cookie/SQLite HTTP, no HTTP substitution. Actual persistence and strict browser parser roundtrips walk **every ordinary and report-v1 row** for both 241/236/5 and all-CVE 158/0 cases. It verifies unchanged whole counts on severity-filtered/empty pages, empty TEMP references, read-snapshot nesting, owner 404/anonymous 401 and no discarded/relabelled TEMP IDs.
- `src/shared/api/scans/publicVulnerabilityIdentifiers.ts` and `tests-vite/ui/scans/publicVulnerabilityIdentifiers.test.tsx` — closed browser namespace/count validators, source-helper agreement, strict metadata/reference/namespace/ecosystem/raw-field negatives, actual parser/transport-to-React report rendering/filter/reload and status/partition mismatch rejection. UI tests use controlled synthetic fetch, **jsdom**, not a new Chromium/native execution claim. The new HTTP test separately supplies actual HTTP evidence.

Focused final API command, from `server/api`:

```sh
pnpm exec tsx --test src/scans/public-vulnerability.http.test.ts src/scans/public-image.http.test.ts src/scans/public-image-legacy.http.test.ts src/scans/public-image-origin.http.test.ts src/scans/scans.vuln.http.test.ts src/scans/scans.report.http.test.ts src/scans/report-page.test.ts src/scans/report-query.test.ts
```

**29/29 tests/subtests passed**, including legacy Alpine edge/exact-nginx, public receipt identity and 8081 composition guards.

Focused final public/UI command, from repository root:

```sh
pnpm exec vitest run tests-vite/ui/scans/publicVulnerabilityIdentifiers.test.tsx tests-vite/ui/scans/publicImageProfile.test.tsx tests-vite/ui/scans/vulnAdvisoryCard.test.tsx tests-vite/ui/scans/reportViewControls.test.tsx tests-vite/ui/scans/task39CveMetadata.test.ts --maxWorkers=2
```

**5 files, 78/78 passed.** An additional bounded transport/legacy rerun also passed **129/129**:

```sh
pnpm exec vitest run tests-vite/ui/scans/publicVulnerabilityIdentifiers.test.tsx tests-vite/ui/scans/scanTransport.test.ts tests-vite/ui/scans/liveScans.test.tsx --maxWorkers=2
```

During development, an overly broad ID check initially rejected two existing short unmarked CVE fixtures. The fix preserved that legacy boundary; no old guard tests were rewritten to conceal the regression. Public validation remains strict. Additional existing report-v1 contract/pagination/label/DB-report selections passed; full suites were not rerun.

Final API and UI TypeScript checks passed:

```sh
pnpm exec tsc --noEmit -p server/api/tsconfig.json
pnpm exec tsc --noEmit -p tsconfig.json --incremental false
```

Targeted eslint passed for all edited/new API/UI/test TypeScript files. `node --check tests-e2e/public-image-live.mjs` and `node tests-e2e/public-image-live.mjs --self-test` both exited 0. Offline self-test includes **241 = 236 CVE + 5 TEMP**, 158/0, invalid namespace/ecosystem/reference refusal and existing two-mode intent/origin/env guards; it reported **OFFLINE_GUARDS_ONLY**, zero network requests/accounts and native execution false.

**Next coordinator action:** integrate/rebuild the matching public API/UI and ledger source, then separately authorize one new `node tests-e2e/public-image-live.mjs --run-native-debian` execution and capture its allowlisted receipt. This source/controlled contract evidence is not a fresh native Debian all-four publication PASS. No Docker/native/live account/scan commands, old proof edits, worker/ledger writes, full new matrix or commit were performed by this slice.

## Web build HOLD correction — frontend test dependency boundary

The coordinator reported API/worker builds completed, with only web failing at BuildKit reference **`desktop-linux/desktop-linux/nyjnzbqz5xs6lia1tb4yjgo05`**. This slice read that exact history using **read-only** `docker buildx history logs --builder desktop-linux --progress=plain nyjnzbqz5xs6lia1tb4yjgo05`. Raw stdout/stderr were captured and filtered **in memory**; only fixed reference, safe source paths/line/column/error codes were emitted. Raw logs/environment/secrets were neither printed nor saved.

Sanitized diagnostics from that record:

| Source | Line:column | Code |
| --- | --- | --- |
| `server/api/src/ledger/ledger.ts` | 1:22, 4:25, 5:25 | TS2307 |
| `server/api/src/ledger/schema.ts` | 1:21, 2:59 | TS2307 |
| `server/api/src/ledger/schema.ts` | 20:4 | TS7006 |

**Exact root cause:** the new frontend test `tests-vite/ui/scans/publicVulnerabilityIdentifiers.test.tsx` imported `server/api/src/scans/public-vulnerability.fixture.ts`. That fixture's **type-only** `ArchiveScanReport` import brought `archive-scan-worker.ts` → `vuln-worker.ts` → `ledger.ts`/`schema.ts` into the root TypeScript program. Type-only imports still cause TypeScript to resolve/typecheck their modules. The web Dockerfile intentionally installs only the frontend graph (`pnpm install --frozen-lockfile --filter diplom...`), so `better-sqlite3`, `drizzle-orm`, `drizzle-orm/better-sqlite3` and `drizzle-orm/sqlite-core` cannot resolve there. The missing Drizzle types also produce the derivative TS7006 on `table`. The host's installed API dependencies had masked the unwanted coupling during earlier no-emit checks.

**Fix, scoped to the owned UI test:** replace the API archive fixture import with independently declared synthetic **browser wire rows**, typed with the browser's `VulnFinding`. Retain the pure worker ID helper/normalizer agreement, closed report query/pagination helpers, 241/236/5 rendering and negative tests. The separate actual Nest/auth/SQLite HTTP test continues using its API-owned archive fixture. No report validation, count/identity assertion, production contract, backend dependency, Dockerfile, launcher or deployment source is relaxed/changed to make the build pass.

Before/after host `tsc --explainFiles` / `--listFilesOnly` inspection confirmed the cause and correction. After the fix **none** of `ledger.ts`, `schema.ts`, `public-vulnerability.fixture.ts`, `archive-scan-worker.ts` or `vuln-worker.ts` is present in the frontend compiler file graph.

Validation actually run after correction:

```sh
# Working directory: diplom; production build with minimal standard environment,
# NODE_ENV=production and no forwarded application/stand environment variables
pnpm build
pnpm exec vitest run tests-vite/ui/scans/publicVulnerabilityIdentifiers.test.tsx tests-vite/ui/scans/publicImageProfile.test.tsx tests-vite/ui/scans/vulnAdvisoryCard.test.tsx --maxWorkers=2
pnpm exec eslint tests-vite/ui/scans/publicVulnerabilityIdentifiers.test.tsx

# Working directory: diplom/server/api
pnpm exec tsx --test src/scans/public-vulnerability.http.test.ts
```

- **Host production `tsc -b && vite build`: exit 0**, Vite build complete, approximately **13.16 seconds**. Production output was captured in memory and emitted as a sanitized result only; the existing nonfatal chunk-size warning remains.
- **16/16 focused UI tests passed**; targeted lint passed.
- **1/1 actual disposable HTTP/SQLite TEMP test passed**, retaining complete ordinary/report-v1 persistence/parser/count/owner coverage. No full suite was run.

Only the owned test source and this handoff were edited in this correction; normal host build artifacts were regenerated. **No Docker build/up/restart/exec/cleanup/mutation, live HTTP/native/account/scan operation, launcher edit or commit was performed.** The running 8081 stand remains the coordinator-reported prior revision, **HOLD at build**; launcher agent owns guarded recovery. Host build PASS is not a Docker rebuild, rollout or native Debian publication PASS.

## Entrypoint / operator boundary

Public API entrypoint for a **new, explicitly reviewed composition after integration**, not an instruction to modify/deploy the old stand:

```sh
# Working directory: server/api
pnpm exec tsx src/oci/public-image.main.ts
```

It still requires existing dedicated JWT/auth/ledger/readiness/gateway configuration and an explicit public worker composition. API LOCAL trust selection does not automatically change the worker's production anchor: both sides must use the same independently reviewed DB trust composition. No package script, deployment manifest or old environment was changed.
