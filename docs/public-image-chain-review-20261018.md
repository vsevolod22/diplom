# Independent public-image chain review — 2026-10-18

## Verdict

**Changes requested for two reproducible contract defects.** The reviewed public worker/ledger/API/browser boundaries otherwise receive **scoped offline approval**, not live image/scanner/deployment qualification.

| ID | Priority | Finding | Suggested owner |
| --- | --- | --- | --- |
| R1 | P1 | A later scratch failure replaces an already accepted checked checkpoint with a failed final outcome, hiding its findings and closing cancellation recovery | Worker + ledger |
| R2 | P2 | Public API relabels legacy Alpine SBOM as public, causing the browser to reject a valid legacy OS release | API/read model + browser contract |

Neither finding is a claim of a falsely clean result or cross-owner disclosure. R1 loses access to accepted evidence; R2 makes a legitimate report unreadable.

### Scope and safeguards

Read the requested handoffs:

- `docs/public-image-ledger-20261018.md`
- `docs/public-image-api-ui-20261018.md`
- `docs/public-image-config-20261018.md`
- `server/api/src/worker/docs/public-image-worker-20261018.md`

Also read the acquisition handoff and relevant implementation/tests. Review focused on `worker/public-image*`, archive runner/consumer/result contract, public ledger changes, public scans service/HTTP routing, config composition, and browser profile/identity/report parsing and display.

**Only this report was authored.** No production/test source, environment, historical holder, deployment, branch or commit was modified. Existing/concurrent dirty work was left alone. Probes used `tsx -e`, in-memory SQLite and the existing disposable worker fixture helper; no probe source file was saved. No Docker, registry request, native Trivy invocation, old environment loading, private-key inspection or full suite was performed.

This is a review of the working-tree snapshot observed during the session, not an immutable commit review. Handoffs contain historical integration blockers that have since been fixed; findings below are based on current source and probes, not those stale blocker statements.

## R1 — P1: later scratch failure discards an accepted checked result

### Locations

- `server/api/src/worker/archive-scan-worker.ts:194–216`: quiescent per-check audit and synchronous checkpoint acceptance.
- `server/api/src/worker/archive-scan-worker.ts:223–228`: final audit failure aborts the internal signal, then **every** selected check is replaced with `abortedFailure()`, including completed/accepted siblings.
- `server/api/src/worker/outbox-consumer.ts:127–151`: the `checkpointCommitted` protection applies to thrown runner/cleanup errors, but not a normally returned report containing these replacement failures.
- `server/api/src/ledger/ledger.ts:903–940`: `finishArchive` validates the final envelope/claim, then inserts that report and clears delivery/token authority without reconciling accepted checkpoint outcomes.
- `server/api/src/ledger/ledger.ts:680–684,733–747`: after final delivery checkpoints are not selected for publication, and cancel of the terminal scan returns `conflict`.

### Reproduction and observed result

A disposable probe exercised the **real** `consumeOne → scanPublicImageArchive → ScanLedger` path, with synthetic scanner/acquisition/DB dependencies only:

1. Create `new ScanLedger(':memory:')`; enqueue the fixture public target for `['secret', 'sbom']`.
2. Use `publicLifecycle` from `worker/public-image-test-fixtures.ts`.
3. The synthetic secret response has one inert `Secrets` item (`RuleID: 'synthetic-rule'`, `StartLine: 7`, and a noncredential canary in `Match`).
4. Scratch audit returns a bounded value for Secrets. The consumer's actual checkpoint callback returns `true`; the accepted normalized checkpoint contains **one finding** and no raw canary.
5. On the next SBOM stage, make the injected scratch audit throw. This models the runner's existing error path: the production auditor also throws for unsafe scratch, entry/byte limits and filesystem errors (`archive-scratch.ts:13–58`). It does not require allocating an oversized image or running a real scanner.
6. Let the consumer finish normally, read the owner-scoped archive result, and attempt cancellation.

Exact observed output:

```json
{"acceptedSecretFindings":1,"publishedSecret":{"outcome":"failed","reason":"SCAN_FAILED"},"terminal":"failed","cancel":"conflict","rawCanaryPersistedInFinal":false}
```

A preceding checked-zero fixture produced the same outcome replacement. The positive-finding probe rules out treating this as merely a count-display discrepancy.

### Impact

The successful Secrets stage passed its own scratch audit and durable checkpoint transaction. A subsequent independent stage failure nevertheless removes that result from the published report. The checkpoint rows need not be physically deleted for evidence to become inaccessible through the normal API: final delivery clears the token, the final report says failed, and cancellation recovery is no longer available.

This contradicts the worker handoff's completed-sibling preservation guarantee. The implementation correctly protects against a **thrown** cleanup error after a checkpoint, but misses this **returned failure report** path. It also affects the shared legacy archive lifecycle; it is not restricted to a particular generic repository.

The UI does not report this as zero vulnerabilities/secrets: it reports an unknown/failed check. The defect is lost accepted evidence and partial-result semantics, not a false safety claim.

### Requested correction

Do not allow the global abort rewrite to silently replace checks whose audited checkpoint was accepted. Preserve the completed subset, or propagate a runner failure while retaining checkpoint publication/recovery authority instead of publishing a contradictory final report. Keep failures/unknown outcomes for the unfinished stage and do not mark its unverified bytes checked.

Add a ledger-side consistency guard or explicit reconciliation between final output and accepted checkpoints so this invariant does not depend solely on one runner's behavior. Preserve existing claim/token/receipt fences and intentional DB-usability decisions; a CVE freshness downgrade must not become an excuse to erase unrelated accepted Secrets/SBOM results.

**Regression test:** real in-memory ledger + consumer + injected archive lifecycle, positive Secrets checkpoint accepted, later SBOM audit error, then owner read/reopen/cancel as applicable. Assert that the accepted normalized finding remains available (and raw `Match` does not), the unfinished check is not checked, and no terminal failure report silently supersedes the accepted result. Include a final-audit-only failure and internal deadline-abort variant.

## R2 — P2: endpoint composition relabels legacy Alpine evidence as public

### Locations

- `server/api/src/worker/outbox-consumer.ts:45–49,155–192`: `library/alpine` deliberately retains legacy runners even in the public composition.
- `server/api/src/worker/cyclonedx-components.ts:101–104` and `server/api/src/ledger/ledger.ts:105–114`: the retained legacy Alpine SBOM contract permits a bounded nonnumeric release such as `edge`.
- `server/api/src/scans/public-image-scans.service.ts:67–73`: nonfailed SBOM/CVE reports and status are unconditionally given `profile: 'public-hub-amd64-v1'` according to the serving service, not the evidence's actual normalization contract.
- `src/shared/api/scans/publicImageProfile.ts:17` and `src/shared/api/scans/scanTransport.ts:108–120`: a public-marked checked SBOM must have a numeric public OS release; an unmarked legacy Alpine SBOM can retain the legacy release grammar.

### Reproduction and observed result

A `tsx -e` probe used the real ledger, public service and browser parser, without HTTP/network/scanner I/O:

1. Enqueue an owner-scoped pinned `library/alpine` SBOM job in `:memory:` SQLite.
2. Claim it and successfully `finishCombined` with a normalized checked Alpine SBOM: `os: { name: 'alpine', version: 'edge' }`, one `apk` component `busybox@1.37.0-r0`, scanner `0.69.3`, and the original token.
3. Call `new PublicImageScansService({ ledger }, resolverStub).report(owner, id, 'sbom', {})`.
4. Pass the actual returned object to `parseCurrentSbom`.

Exact observed output:

```text
{"profile":"public-hub-amd64-v1","os":{"name":"alpine","version":"edge"}}
browser rejected: Недопустимый профиль SBOM
```

This is a valid persisted legacy-contract fixture, not a claim that a live Alpine edge image currently emits exactly this release string. The browser's existing public-profile test independently establishes the same contract distinction: unmarked Alpine `edge` is accepted; public-marked `edge` is rejected (`tests-vite/ui/scans/publicImageProfile.test.tsx:44–46`).

Both HTTP controllers route SBOM reads through `scans.report`, so the problematic wrapper is on the real endpoint path. The report-v1 wrapper also calls the same unconditional profile addition. The probe itself was service/parser integration, **not** a new HTTP or live-image proof.

### Impact and requested correction

A public endpoint can serve legacy Alpine jobs and history, but turns their valid SBOM into a payload its own browser refuses to display. A public endpoint/profile name is not proof that the worker used the public normalized contract. The current dedicated public HTTP fixture covers Debian/public receipts, not this retained-Alpine path.

Derive the report marker from the actual result contract/receipt, retaining legacy wire semantics for legacy Alpine evidence; alternatively explicitly normalize/reject incompatible results at the worker/read-model boundary with an honest failure outcome. Do not globally relax numeric public OS validation or invent a numeric replacement for a nonnumeric release. Align status/report markers under the same decision.

**Regression test:** public-composition endpoint serving a real ledger-backed legacy Alpine SBOM with a nonnumeric allowed release; decode both ordinary and report-v1 responses with the actual browser parser. Also retain the negative test that a genuine public-contract receipt cannot claim that release checked.

## Other reviewed boundaries — scoped offline approval

No additional actionable defect was established in the following inspected paths. These statements apply to the reviewed contracts/fixture cases, not all real scanner outputs.

| Boundary | Evidence and disposition |
| --- | --- |
| OS/EOL/checked-zero | Public runner distinguishes unknown OS from checked coverage and converts validated EOL to unsupported. Known OS proceeds through the public CVE parser before checked publication. Parser requires positive OS package inventory, rejects missing/empty coverage, unknown class/type, conflicting OS family and unmatched vulnerability/package identities. Six extra synthetic probes below passed. This does not prove Trivy's lifecycle knowledge for every release. |
| Language inventory | Known language mappings and package names/versions are closed. Positive Node inventory is required for Node checked; otherwise public output uses `NODE_INVENTORY_UNKNOWN`, not inferred absence. Empty emitted language results fail closed. An OS-only checked result is not evidence that all eleven language/ecosystem analyzers ran. |
| Raw findings/storage | Public worker normalization drops raw paths, `Env`, source text and secret `Match`; secret rules become opaque hashes. Archive contract validates original exact envelopes before derived fields. Ledger revalidates normalized package/source/advisory fields and finding identity, binds the receipt, and uses archive JSON rather than widening ordinary result tables. Targeted negative tests reject raw/nested extras on checkpoint/final/read. The R1 canary was absent from the accepted normalized checkpoint and final report; no all-sink/live confidentiality claim is made. |
| Public authority vs legacy | Worker public selection requires explicit composition, canonical target and no execution profile. Alpine and explicitly selected exact-nginx paths remain separate. Arbitrary stored profile data does not enable public archive scanning. Ledger rejects public receipts against nginx execution bindings. R2 concerns wire labelling, not execution authorization. |
| Expiry/cancel/claim fences | Checkpoint writes compare original job/context and live token/attempt/time; retry/replacement revoke prior authority. Cancellation publishes the accepted subset atomically, including after lease expiry/reopen, without accepting late output. Historical DB evidence is evaluated at its accepted time rather than current wall time. Existing tests passed. R1 is the distinct gap when a normal final report supersedes that subset. |
| Storage error classification | Consumer retains the original checkpoint exception when abort wins or an injected runner swallows it, and does not relabel it DB unavailable. Genuine DB-usability crossings alone are downgraded. Tests for this and thrown cleanup errors passed; they do not cover R1's normal-return path. |
| Identity and owner reads | Archive JSON binds config/platform/ordered diffIDs; CycloneDX validates config and diffID multiplicity; worker verifies archive hash. Public ledger checkpoint/final/read bind receipt registry/repository/digest/platform to the job and reject mixed checkpoint receipts. Service and HTTP owner guards prevent foreign-owner reads in tested paths. HTTP tests use actual loopback Nest/cookie auth/SQLite with controlled transport, not a registry. |
| Config/LOCAL trust | Public config permission is explicit at predicate/loader/runner composition. Original claim/context and loaded pinned identity are checked before/after loading. Default/proof trust remains production anchored; explicit public/LOCAL composition can select the reviewed local anchor helper. Targeted config/fencing tests passed. Operator mounts/fingerprint/release agreement were not inspected or qualified. |
| Browser | Public profile/ecosystem/source allowlists, pinned target checks, report-v1 cursor bridge and target-aware checked-report display were inspected. Unknown inventory is displayed as unknown, not absence. Marker/legacy SBOM incompatibility remains R2. |

### Known coordinator work — not new findings

1. Forward the explicit fifth public argument to `runImageConfig` in `outbox-consumer.ts`.
2. Replace the public status history traversal with the ledger's owner-scoped `pinnedTarget` accessor.

These were still visible in the last source reads and were expressly excluded by the review request. Their completion remains a coordination/retest gate, not a newly reported defect. None of the passing fixture tests should be represented as proving that pending call-site work complete.

## Validation performed during this review

### 1. Public worker/ledger/API/HTTP selection

Working directory: `server/api`.

```sh
pnpm exec tsx --test src/worker/public-image-worker.test.ts src/worker/public-image-consumer.test.ts src/worker/public-image-runtime.test.ts src/ledger/ledger.public-image.test.ts src/scans/public-image.http.test.ts src/scans/public-image.service.test.ts src/scans/public-image-report.test.ts
```

**Observed:** exit 0; **157 passed, 0 failed, 0 skipped**. Includes actual loopback public HTTP admission and persisted Debian/all-ecosystem report decoding. Existing tests remain green despite the missing R1/R2 cases.

### 2. Config and cancellation selection

Working directory: `server/api`.

```sh
pnpm exec tsx --test src/oci/pinned-image-config.public.test.ts src/oci/pinned-image-config.test.ts src/worker/image-config-runner.test.ts src/worker/outbox-cancel.test.ts src/worker/outbox-config.test.ts src/worker/outbox-config-archive.test.ts
```

**Observed:** exit 0; **103 passed, 0 failed, 0 skipped**. This deliberately does not include the known stale source-string assertion in `vuln-db-trust-wiring.test.ts`; no test was edited or suppressed to report these results.

### 3. Browser public/transport selection

Working directory: repository root.

```sh
pnpm exec vitest run tests-vite/ui/scans/publicImageProfile.test.tsx tests-vite/ui/scans/scanTransport.test.ts --maxWorkers=2
```

**Observed:** exit 0; **2 files, 40 passed**. An initial invocation additionally supplied a `reportView.test.ts` name filter; only these same two files matched. The exact two-file command above was then independently rerun and passed.

### 4. Additional disposable probes

Run via `pnpm exec tsx -e` from `server/api`, with no saved test source:

- Four public CVE parser negatives: no results; Python inventory without OS inventory; empty Debian OS inventory; Ubuntu result conflicting with Debian metadata. All rejected.
- Two public runner negatives: validated EOL Debian and unknown OS. Both returned unsupported CVE and `NODE_INVENTORY_UNKNOWN`, not checked-zero. Combined output: `PASS 6 synthetic negative-coverage probes; no native scanner or registry`.
- R1: real ledger + consumer + synthetic public archive lifecycle, first checked-zero then positive-secret checkpoint, later scratch error. Both reproduced outcome loss; positive output recorded above.
- R2: real ledger + public service + actual browser parser. Reproduced profile/OS mismatch recorded above.

No new full-project typecheck/build was run: this review changes no TypeScript. Handoff typecheck claims are not substituted for review-time validation. No full-suite or live qualification claim is made.

## Acceptance boundary after fixes

Re-run the focused selections plus the requested R1/R2 regression cases after the owners' changes and the two known coordinator integrations. Real pinned Trivy output compatibility (especially distro/PURL and offline language/Java behavior), signed-release readiness, physical cgroup/tmpfs behavior, Docker Hub availability and deployment composition still require separately authorized qualification. The eleven-value normalized enum is an allowed data contract, not a promise that every public image or language inventory is supported or fully covered.

---

## Independent re-review — R1/R2 corrections, 2026-10-18

### Current disposition

**R1 and R2 are resolved for the reviewed paths. Scoped offline approval; no new blocking defect established in this focused re-review.** This disposition supersedes the original request-for-changes verdict for these two findings only. The original report above, its historical source locations, outputs and validation claims are preserved unchanged.

| Item | Re-review disposition |
| --- | --- |
| R1 original worker/consumer reproduction | PASS: late scratch failure propagates after the accepted checkpoint; no contradictory final report is delivered; owner cancellation recovers the positive finding |
| R1 final-audit and internal deadline variants | PASS: new real-ledger recovery tests preserve exactly the accepted subset, including through reopen/cancel |
| Archive transactional final consistency | PASS within `finishArchive`: contradictory outcomes/receipt, corrupt checkpoint, changed findings/DB/advisory and invalid authority are fenced without publication writes |
| Genuine current-policy DB expiry exception | PASS: independently recomputed from the accepted checkpoint DB at the fenced ledger clock; inclusive deadline and just-expired cases behave correctly; unrelated accepted evidence cannot be erased |
| R2 original legacy Alpine `edge` reproduction | PASS: ordinary/report-v1 reports and status remain legacy/unmarked and decode successfully |
| Exact legacy/public marker and owner routing | PASS: receipt selects persisted contract, including public receipts on otherwise legacy target identities; foreign owner denied; queued/config-only status uses the owner-scoped direct target accessor |
| Coordinator config/trust integrations | PASS: fifth config policy argument is forwarded; generic config requires explicit public composition; corrected trust wiring assertion passes without a skip filter |

### Scope and preservation

This pass reread the modified worker lifecycle/consumer, ledger consistency helper and finalization transaction, public scans service, direct target accessor, related DB policy/evidence code, and the new regression tests. Only this append was authored; no production/test source was changed. Original report prefix before this append: **18,156 bytes**, SHA-256 **`d66832fe0eff1eccdbb44d2c044195b7207de4960134de4301081758009479df`**.

All further probes ran inline with `tsx -e` using actual in-memory SQLite and existing disposable fixture helpers. HTTP tests used their temporary SQLite/auth data, loopback Nest ingress and synthetic normalized reports. No Docker, registry, native scanner, old environment/holder, deployment, full suite or commit was used. No new TypeScript build/typecheck was run. Source references below describe the re-review snapshot; the original review's earlier line numbers remain historical.

### R1: original reproduction now preserves recovery authority

The worker now records a successful checkpoint callback in `checkpointAccepted` and, after a later scratch/deadline/abort, throws `Archive interrupted after accepted checkpoint` instead of returning replacement failures (`archive-scan-worker.ts:119,219–220,232–236`). The consumer's existing accepted-checkpoint exception path propagates that error rather than calling the all-failed fallback (`outbox-consumer.ts:127–135`). Cleanup remains in the runner's `finally`.

Repeated the original positive-secret probe independently, retaining its actual consumer/ledger path and synthetic later-SBOM audit failure. New assertions required the interruption, a still-running attempt with no published final archive, foreign-owner denial, owner cancellation, one recovered normalized Secrets finding, and no unaudited SBOM/raw canary.

Observed output:

```json
{"probe":"original-R1","interruptionPropagated":true,"cancel":"cancelled","recoveredSecretFindings":1,"unverifiedSbomPublished":false}
```

This is **recovery preservation**, not automatic partial-result finalization: the interrupted attempt remains running until cancellation/recovery or the existing retry/replacement lifecycle decides its disposition. The three new `public-image-checkpoint-recovery.test.ts` cases independently exercise next-stage audit failure, final-audit-only failure after both checks were accepted, and an injected short internal deadline with late valid-looking scanner bytes. All passed, including no final delivery attempt, cleaned disposable scratch, durable sanitized checkpoints, reopen/owner-cancel publication, and absence of future unaudited checks.

### Ledger invariant and genuine DB expiry exception

`validatedCheckpoint` revalidates checkpoint size/hash, immutable owner/job identity and payload before comparison (`ledger.ts:702–714`). `assertArchiveCheckpointConsistency` then compares the accepted receipt/scanner and per-check outcomes. Config checkpoints must equal the final config; Secrets/SBOM outcomes must remain exact; current-policy CVE comparison permits ledger reevaluation of `dbPolicy`, and recognizes the explicitly bounded optional report-budget advisory omission (`ledger.ts:717–764`).

Crucially, the helper runs **inside** the live-token/fenced-clock `finishArchive` transaction, after the intentional CVE DB usability evaluation but **before** delivery/token clearing, result insertion, state transition or event (`ledger.ts:958–996`). The new legacy/public regression matrix checks rollback and subsequent cancellation/reopen rather than merely asserting that an error was thrown. Its 54 cases passed.

The DB-unavailable exception is not enabled by a supplied reason string or a different final DB. It only permits the checked/unsupported accepted CVE checkpoint to become `failed/DB_UNAVAILABLE` under the current DB policy when `finalizeDbEvidence` of the **accepted checkpoint's DB, original checkedAt and accepted policy receipt** actually throws `DbUsabilityError` at the transaction's captured `evaluatedAt`. Contract/corruption errors propagate. Other accepted checks still undergo their own equality checks.

An independent adversarial probe constructed valid current-policy checkpoints for Secrets, SBOM and CVE, with the original DB's `UpdatedAt + 14 days` at **initial ledger clock +100 ms**, while keeping the attempt lease live. It tested both a worker-returned `DB_UNAVAILABLE` and a still-checked report requiring ledger-side reevaluation:

| Final ledger clock | Returned `DB_UNAVAILABLE` | Normal checked final | Unrelated accepted evidence |
| --- | --- | --- | --- |
| Initial +99 ms | Rejected; unchanged checked final can still complete | Accepted checked | Preserved |
| Initial +100 ms, exactly the inclusive deadline | Rejected; unchanged checked final can still complete | Accepted checked | Preserved |
| Initial +101 ms | Accepted as genuine CVE expiry | Ledger downgrades CVE to `DB_UNAVAILABLE` | Secrets/SBOM preserved; terminal state `partial` |

For every case an additional final attempting to replace accepted Secrets with `SCAN_FAILED` was rejected, even after genuine CVE expiry. Owner-scoped final reads retained exact Secrets/SBOM; foreign-owner reads returned no report. Before expiry, rejection left the attempt/checkpoint authority active and no final report published.

An additional replacement-DB attack changed the supplied DB so **it** expired before the original accepted DB. Ledger reevaluation downgraded that replacement, but the consistency exception independently found the original checkpoint DB still usable and rejected finalization. Cancellation recovered the original CVE evidence unchanged. Exact combined probe output:

```json
[{"offsetMs":99,"mode":"returned","vuln":"checked","state":"completed"},{"offsetMs":99,"mode":"ledger","vuln":"checked","state":"completed"},{"offsetMs":100,"mode":"returned","vuln":"checked","state":"completed"},{"offsetMs":100,"mode":"ledger","vuln":"checked","state":"completed"},{"offsetMs":101,"mode":"returned","vuln":"failed","state":"partial"},{"offsetMs":101,"mode":"ledger","vuln":"failed","state":"partial"},{"replacementDbExpiryCannotAuthorize":true,"cancelPreservesOriginal":true}]
```

The checked/completed rows for the returned-failure cases at +99/+100 reflect the **subsequent valid unchanged final**, not acceptance of the invented failure. These boundaries concern the current fourteen-day policy, including legacy archive receipts explicitly bound to that policy in the regression tests; they do not silently change legacy DB freshness policy. Consistency approval here is scoped to archive finalization through `finishArchive`, not a claim that every ledger method implements the same invariant. Existing explicit retry/replacement revocation semantics remain outside this fix.

### R2: evidence-derived markers and exact owner reads

`PublicImageScansService.report` now derives nonfailed SBOM/CVE markers from the actual validated public archive receipt, in the same read snapshot as the report (`public-image-scans.service.ts:68–80`). It no longer relabels an ordinary legacy Alpine report based on the serving endpoint. `status` uses an owner-scoped snapshot plus `pinnedTarget(scanId, subject)`; a persisted archive receipt decides the contract even if the target also matches an exact legacy identity. Without an archive, generic public queued/config-only targets get the public marker while Alpine/exact-nginx legacy targets remain unmarked (`public-image-scans.service.ts:82–99`). The direct target SQL predicates on both ID and subject (`ledger.ts:1397–1400`); there is no history traversal.

Repeated the original actual-ledger/service/browser-parser probe with legacy Alpine `edge`, then extended it to report-v1 and status. Replaced `ledger.list` with a throwing function to make any history lookup fail, and asserted foreign-owner service reads are rejected. Output:

```json
{"probe":"original-R2","profilePresent":false,"legacyVersion":"edge","ordinaryAndReportV1Accepted":true,"historyTraversal":false,"foreignOwnerRejected":true}
```

The new `public-image-legacy.http.test.ts` also passed through actual cookie-owner and JWT-owner controllers, ordinary/report-v1 responses and the actual browser parsers:

- Legacy Alpine and exact-nginx `edge`: no marker on report/status; release retained and parsed.
- Public receipt on generic, exact-nginx and Alpine target identities: public marker retained; numeric public grammar remains mandatory. Target identity alone does not override a persisted receipt.
- Foreign listed browser account: 404 for status and report-v1 SBOM; no foreign target lookup for queued status.
- Queued generic public versus legacy targets: pinned full reference with the correct marker policy; history lookup prohibited by the fixture.
- Genuine public checked nonnumeric release: still rejected at persistence, with no published archive.

Snapshot protection was inspected in source and exercised by ordinary/report-v1 HTTP reads; no separate concurrency stress/production database experiment is claimed.

### Coordinator handoffs rechecked

The fifth argument is present at `outbox-consumer.ts:87`: `options.publicImagePolicy === true`. The corrected trust source assertion now expects the explicit third `buildVulnConfig` argument and checks the public worker's explicit anchor selection (`vuln-db-trust-wiring.test.ts:184–194`). That test file was executed **without** the previous skip filter and passed, including its signed disposable DB trust fixtures.

An independent generic config-only probe used the real consumer, real in-memory ledger, public-aware pinned loader with hash-linked synthetic OCI bytes, and actual public status/browser parsing. With public policy disabled, the loader was not called and config was not checked; with explicit public policy enabled, the loader performed its two controlled object reads and the result was checked. Both owner result/status and foreign-owner absence were asserted; raw fixture canaries were absent from normalized results.

```json
[{"publicPolicy":false,"transportCalls":0,"outcome":"failed","profile":"public-hub-amd64-v1"},{"publicPolicy":true,"transportCalls":2,"outcome":"checked","profile":"public-hub-amd64-v1"}]
```

The status marker in the disabled case describes the public service's generic pinned target, **not** worker authorization or checked coverage. The explicit worker-policy gate remains effective. This probe does not claim registry inspection, live config loading or deployment anchor/mount agreement.

### Re-review validation commands and observed results

All Node selections below ran from `server/api`; no glob/full-suite invocation was used.

```sh
pnpm exec tsx --test src/ledger/ledger.archive-consistency.test.ts src/worker/public-image-checkpoint-recovery.test.ts src/scans/public-image-legacy.http.test.ts
```

**65 passed, 0 failed/skipped**: 54 archive-consistency cases, 3 worker recovery cases and 8 HTTP parent/subtest results.

```sh
pnpm exec tsx --test src/worker/vuln-db-trust-wiring.test.ts src/worker/public-image-consumer.test.ts src/scans/public-image.http.test.ts src/worker/outbox-config.test.ts
```

**28 passed, 0 failed/skipped**, including the corrected trust source assertion without filtering.

```sh
pnpm exec tsx --test src/ledger/ledger.public-image.test.ts src/worker/public-image-worker.test.ts src/worker/outbox-cancel.test.ts src/scans/public-image.service.test.ts src/scans/public-image-report.test.ts
```

**150 passed, 0 failed/skipped**: focused surrounding public storage/contract/coverage/cancellation regression checks.

From repository root:

```sh
pnpm exec vitest run tests-vite/ui/scans/publicImageProfile.test.tsx tests-vite/ui/scans/scanTransport.test.ts --maxWorkers=2
```

**2 files, 40 passed**. Total across these four selections: **283 test results passed**, plus the inline original R1/R2, DB-boundary/replacement and explicit-config probes above. All commands exited 0. No full suite, typecheck/build or live qualification result is implied.

### Remaining qualification boundary

No further code change is requested by this focused re-review. The original R1/R2 contract blockers and the two explicitly tracked coordinator handoffs are cleared for this observed snapshot. Real pinned Trivy output compatibility, lifecycle-data completeness, offline language/Java behavior, physical resource isolation, signed-release operational readiness, Docker Hub availability and deployment remain separately authorized qualification work. Preserve that distinction when incorporating this approval into a broader acceptance decision.

---

## Independent review — native Debian schema alignment and identifier classification, 2026-10-18

### Verdict and native-evidence boundary

**Scoped source/offline approval. No new blocking defect established in the reviewed Debian epoch/TEMP → ledger → API/browser changes.** Exact Debian TEMP advisories are an explicitly supported, separately classified namespace now; their presence is not itself an unsupported-generic-non-CVE defect. This addendum supersedes any earlier CVE-only description in this report **only for the new public Debian TEMP contract**. It does not widen legacy intake or authorize arbitrary advisory IDs.

The evidence levels remain distinct:

| Evidence | What is established / not established here |
| --- | --- |
| User/coordinator-reported native Node PASS on the new 8081 stand | Reported counts: 217 packages, 158 CVE findings, including 61 npm CVE findings. Accepted as supplied prior-run evidence, not independently rerun here and not presented as a run of all revised source below. |
| Worker-owned native Debian candidate handoff | Reports 88 normalized Debian packages and 241 normalized findings: 236 CVE findings + 5 TEMP advisories, with original full native objects/identity and no projection. This is a candidate normalization proof, not a published native ledger/API/UI/all-four result. |
| This review | Source inspection, 195 focused Node test results, 49 jsdom test results, inline synthetic raw/normalized/service/browser probes and the proof script's offline self-test. No stand or native scanner was accessed. |
| Coordinator's new native Debian full-chain run | **Pending / not verified by this review. No Debian full-chain PASS claimed.** No result receipt was supplied during this pass. |

Do not describe 241 findings as “241 CVEs”, and do not describe a namespace partition as a count of distinct unique advisory records: one source ID can affect multiple package/location findings.

### Inputs, scope and preservation

Read:

- `server/api/src/worker/docs/native-debian-20261018.md`, including the native rejection diagnosis, original-byte identity guarantee, candidate replay and safety limitations.
- `docs/public-image-ledger-20261018.md`, native Debian TEMP follow-up.
- `docs/public-image-api-ui-20261018.md`, TEMP/count/UI/native-proof source handoff.
- The actual worker evidence/CycloneDX/vulnerability/advisory/envelope changes, ledger public identifier branch and regressions, public service/count projection, browser identifiers/transport/report/card code and relevant tests.
- `tests-e2e/public-image-live.mjs` source and `native-debian-diagnostic.ts` source. The latter is an executing native/network diagnostic and was **not imported or run**.

Only this addendum was authored. Previous report/re-review prefix before appending: **32,743 bytes**, SHA-256 **`9f2f4366ca2364af5073f05e2e1ee915fe8aafe0c63961f2edc593c134ccc557`**. No production/test source, native report, private environment, live ledger, old holder, Docker resource, branch or commit was modified/accessed. Tests used only their disposable SQLite/scratch and synthetic fixture data.

The no-network restriction was kept literally: **no sockets/HTTP listeners, live requests, registry calls, Docker or native modes** were started. The new HTTP regression was read for coverage but not executed in this pass. In-memory service/browser probes cover the relevant projections without claiming HTTP/auth transport evidence; previous HTTP results remain their owners' evidence. jsdom fetch was mocked by the selected tests, not sent to 8081 or another origin.

### 1. Worker: exact dpkg version identity, no source-epoch substitution

`publicDebianVersion` (`worker/public-image-evidence.ts:33–41`) reconstructs only the permitted binary inventory identity, `[Epoch:]Version[-Release]`, and revalidates the resulting bounded ASCII version. Numeric epoch is a safe integer in `[0,2147483647]`; null/string/fractional/negative/nonfinite/out-of-range values reject. Empty revision is not appended; a nonempty revision must satisfy the existing bounded version-fragment grammar. A separate epoch plus embedded `:` rejects rather than double-prefixing or dropping identity. Composition must still fit the original 80-character limit.

`cyclonedx-components.ts:30–47` compares the complete display version to the decoded PURL identity with its canonical positive numeric epoch qualifier. It does not strip display epoch to obtain agreement. Duplicate/noncanonical/zero/overflow epoch qualifiers, wrong version, extra qualifier, architecture and distro remain rejected. No APK/RPM/language qualifier relaxation was introduced.

`vuln-findings.ts:91–98,113–129` validates public `deb` package inventory and requires the same package name and exact reconstructed binary version to equal the original finding's `InstalledVersion`. It does not replace that finding version or infer a matching version from source package fields. The finding hash retains the exact installed version and original ID.

An additional inline raw-fixture probe deliberately gave a binary package `Epoch:1` and different source-package evidence (`SrcEpoch:9`, different source name/version/revision). The normalizer correctly retained the binary `1:4.13+dfsg1-1+deb12u1`. Epoch-stripped versions, a source-epoch-prefixed version and the separate source package's complete version all rejected. The source epoch was not substituted for the binary epoch.

The same probe checked exact composed length 80 versus 81, the maximum allowed epoch, PURL epoch `0`, `01`, mismatched `2` and overflow. These are sanitized synthetic shapes, not a read/rewrite of native scanner bytes.

### 2. TEMP: narrow admission and unchanged legacy authority

The worker helper permits exactly `^TEMP-[0-9]{7}-[A-F0-9]{6}$` for ecosystem `deb`; normal CVE grammar is unchanged. The raw public parser additionally requires Debian OS evidence for TEMP and the usual matching OS result class/type/inventory (`vuln-findings.ts:113–128`). Ubuntu metadata/result and a Node/npm TEMP result were independently rejected. Lowercase/nonhex/short/long/newline/alternative namespace IDs do not get normalized into a passing value or silently discarded.

The archive contract uses the helper **only after complete public-receipt selection** (`archive-result-contract.ts:44–60`). Ledger's second pass likewise selects `publicVulnerabilityId` only through its already-validated public receipt branch (`ledger.ts:73–79,137–145`); its legacy branch remains CVE-only. Correctly rehashed TEMP input does not turn a legacy/nginx/ordinary Alpine result into public authority. No SQL enum/schema migration or arbitrary-ID envelope was added.

`ledger.public-debian-temp.test.ts` passed its 106-case matrix, including public exact-ID roundtrip and namespace partition, same source ID on different packages, duplicate/hash rejection, legacy checkpoint/final/read and ordinary result rejection, malformed IDs/ecosystems/raw fields, forged references, token/expiry/retry/replacement/cancel fences, retained accepted checkpoint identity, reopen and retention. This verifies the public acceptance boundary without claiming raw distro evidence can be reconstructed from the normalized storage envelope; the raw worker boundary is where Debian OS inventory is established.

### 3. No fake CVE links, including TEMP with CVSS evidence

The compatibility property remains named `cveId` but stores the exact source TEMP identifier. Neither normalizer nor ledger invents a replacement CVE, removes TEMP findings to make totals pass, or creates a CVE/NVD mapping.

- Worker advisory `references()` creates canonical CVE/NVD URLs only for a valid CVE ID; even its FIRST calculator link requires those CVE references (`vuln-advisory.ts:84–90`).
- Ledger retains the mandatory advisory validator/budgets, which reject fabricated canonical references for TEMP.
- Browser `validAdvisoryReferences` explicitly requires an empty TEMP reference list, and `canonicalReferences(TEMP)` returns `[]`.
- `VulnAdvisoryCard` displays the exact TEMP ID, “Debian advisory (не CVE)” and “Advisory ID”, suppressing CVE/BDU fallback wording and external links. React text remains text, not supplied HTML.

The independent raw probe included a valid CVSS 3.1 vector and NVD CVSS assessment **on a TEMP finding**. It retained the CVSS assessment while producing zero external references; canonical browser references were also empty. Thus the no-link result was not merely an artifact of fixtures lacking CVSS. jsdom tests separately reject unrelated-CVE/TEMP-as-CVE/FIRST references and render a TEMP card with no links.

Exact probe summary:

```json
{"originalTempPreserved":true,"binaryEpochPreserved":true,"sourceEpochNotSubstituted":true,"tempCvss31References":0,"strictRejectedCases":16,"composedVersion80ByteBoundary":true,"networkRequests":0}
```

The 16 rejected variants covered malformed/unsupported namespaces, binary/source version mismatch, Ubuntu/npm TEMP scope leakage and invalid/mismatched PURL epochs. No generic GHSA/DSA or other non-CVE namespace support is inferred from the TEMP exception.

### 4. API/browser: whole-report partition, page bounds and neutral labels

`PublicImageScansService` computes `identifierCounts` from the **complete validated owner-scoped archive** in the same deferred read snapshot as ordinary/report-v1/status projection (`public-image-scans.service.ts:69–104`). `publicIdentifierCounts` checks the allowed identifier/ecosystem namespace and unmapped TEMP references. Counts are not taken from scanner aggregates, a page, a filter or a process-local tag cache. Legacy/queued/failed/unsupported outcomes receive no invented partition.

Browser `validateIdentifierCounts` requires the exact public checked partition, bounded to 1000 findings with sum equal to `findingCount` or status vulnerability count. `parseCurrentVuln` applies public ID/ecosystem validation, rejects TEMP in legacy replies, bounds each visible page's namespace rows by the whole-report partition, and requires exact equality for a complete whole-report page (`scanTransport.ts:219–237`). Existing report-v1 offset/cursor/total/matched/filter validation remains active. The report component additionally matches profile and partition to authoritative status across page/filter/reload identity (`ScanReportSections.ts:127–165`).

An independent socket-free probe persisted the declared synthetic Debian count-shape fixture through the real in-memory ledger and used actual public service/browser parsers:

- Status and every ordinary/report-v1 page retained `{cve:236,debianTemp:5}` and total 241.
- Walking both complete paginations produced the same exact finding-ID multiset, 241 unique finding IDs and five unchanged TEMP rows with empty references.
- A LOW-only page retained the whole saved partition, with matched count 5; an empty CRITICAL filter retained that partition with matched count 0. No filtered/global count was inferred from the current page.
- The all-CVE Node **count-shape fixture** retained total 158 / CVE 158 / TEMP 0. Its synthetic inventory does not reproduce or independently prove the stand's 217 packages or 61 npm findings.
- Archive reads were asserted to occur inside the read-snapshot hook with the exact owner; `ledger.list` was made fail-fast to forbid history traversal. Foreign-owner status/report reads were rejected.

Observed summaries:

```json
[{"fixture":"Debian-shape","vulnTotal":241,"cve":236,"debianTemp":5,"snapshotArchiveReads":22,"networkRequests":0},{"fixture":"all-CVE-Node-shape","vulnTotal":158,"cve":158,"debianTemp":0,"snapshotArchiveReads":18,"networkRequests":0}]
```

The focused jsdom tests verify neutral public “Уязвимости” headings/coverage/category/report presentation, whole-report “236 CVE, 5 Debian advisories”, visible-page “0 CVE, 5 Debian advisories” under the TEMP-only fixture filter, no “241 CVE”, and failure to publish a page whose otherwise valid partition contradicts status. Existing historical unmarked fixture compatibility was not mistaken for new legacy TEMP admission; server legacy writes and TEMP browser intake remain closed.

### 5. Native proof source and candidate diagnostic

The reviewed proof source keeps its two closed Node/Debian selections and emits the distinct vocabulary **`counts.vulnTotal`, `counts.cve`, `counts.debianTemp`**. It partitions fully walked rows and compares the result with status and each report's saved partition before success; it no longer labels all vulnerability rows as CVEs. The actual rendered public region is “Результаты Уязвимости”. Original target/receipt/DB/owner/reload/fresh-login/four-check and single-launch guards remain in source.

`node --check` and `--self-test` passed. The latter explicitly reported `OFFLINE_GUARDS_ONLY`, `nativeExecution:false`, `nativeQualification:NOT_RUN`, `networkRequests:0`, `accountsCreated:0`, including the 241 = 236 CVE + 5 TEMP and 158/0 vocabulary checks. Neither native mode was executed.

Read-only inspection of `native-debian-diagnostic.ts` confirms that the normalizer entry points are called with the full original parsed value and archive binding, after full JSON/CycloneDX identity validation; no `.Results` projection or dropped-finding filter is used to achieve normalization. The executable also contains pinned target/version/hash/DB/scratch checks and fixed diagnostic aggregates. This source inspection does **not** re-attest its earlier container execution or establish native full-chain publication, resource enforcement or report delivery.

### Commands actually run in this pass

Working directory `server/api`:

```sh
pnpm exec tsx --test src/worker/native-debian-normalization.test.ts src/ledger/ledger.public-debian-temp.test.ts src/ledger/ledger.archive-consistency.test.ts src/worker/public-image-checkpoint-recovery.test.ts src/worker/vuln-findings.test.ts src/worker/cyclonedx-components.test.ts src/scans/report-page.test.ts src/scans/report-query.test.ts
```

**195 passed, 0 failed/skipped**, exit 0. This includes the new Debian parser/ledger slice and focused legacy/R1 invariant/recovery/pagination regressions, not a full suite.

Working directory repository root:

```sh
pnpm exec vitest run tests-vite/ui/scans/publicVulnerabilityIdentifiers.test.tsx tests-vite/ui/scans/publicImageProfile.test.tsx tests-vite/ui/scans/vulnAdvisoryCard.test.tsx tests-vite/ui/scans/scanTransport.test.ts --maxWorkers=2
node --check tests-e2e/public-image-live.mjs
node tests-e2e/public-image-live.mjs --self-test
```

**4 files, 49 jsdom tests passed**; proof syntax/offline self-test passed; all exited 0. Total test results: **244**, plus the inline source-epoch/TEMP/CVSS/snapshot/paging probes described above. No build/typecheck, HTTP test, Chromium/native proof, live query or full-suite result is claimed from this pass.

### Acceptance boundary / coordinator action

No additional code change is requested for this reviewed narrow schema/classification slice. Integrate worker/ledger/API/UI together: the new browser deliberately refuses public checked vulnerability replies missing `identifierCounts`, while older valid persisted public reports can derive counts on read without rewriting source IDs. Existing R1/R2 closure remains supported by the targeted recovery/consistency tests, not broadened into whole-system approval.

Wait for the coordinator's separately authorized native Debian full-chain receipt before recording a fresh all-four native publication/API/UI PASS. Preserve the actual `vulnTotal/cve/debianTemp` partition, package/OS identity, original epoch-bearing versions and unknown Node coverage in that result. The candidate's 88 / 241 / 236 / 5 values are evidence to reconcile against, not constants the proof is allowed to fabricate or a requirement to force mutable future scanner/DB results into those exact counts.

---

## Independent review — acknowledged recovery/build/redeploy command, 2026-10-18

### Verdict

**BLOCK the current `recover-build-and-redeploy` command before live execution: one confirmed backup-path blocker.** The intended normal clean shutdown can leave the two WAL-mode source databases without sidecars; the subsequently read-only-mounted helper cannot open that state for its backup/read checks. This is independently reproduced with the actual exported SQLite core and disposable databases. No other blocker was established in the reviewed admission/drain/image/namespace/audit/crash fences.

This is not a finding that old image metadata must somehow be recovered or retrospectively qualified. The separate, explicitly acknowledged replacement model is appropriate for the stated missing-old-image situation. Its unavailable-prior-image/rollback limitations are honestly recorded. The block below concerns the **new command's own backup mechanism**, not a demand to satisfy the earlier metadata-certifying reconciliation.

### Scope, immutable inputs and safety

Reviewed:

- `scripts/public-image-stand.mjs`, especially recovery admission, independent prior-runtime policy, `recoverySqlite`, drain/helper/pin/recreation sequence and completed-history validation.
- `scripts/test_public_image_stand.mjs`, replacement fixtures, interruption cases and its real SQLite test.
- `docs/public-image-recover-redeploy-20261018.md`.
- Referenced public API/auth/worker shutdown and SQLite-open code; no private data was read.

Exact reviewed script/test SHA-256 values match the handoff:

```text
835687537c0fa2b0f284ae23d46fae22602f7daffd41cf0c97b57857c0965c73  scripts/public-image-stand.mjs
e650e64e914f9e6b78d569e8614ef73d218bb6931900b7afc22b57daaefb3b8d  scripts/test_public_image_stand.mjs
```

Only this addendum was authored. Preserved report prefix: **48,715 bytes**, SHA-256 **`c1b141ddb243e65de97973323742d48e3a8576e69d71fb7f4d64e5e5b2f6a5a3`**. No production/test source edit, live Docker/Compose command, socket/HTTP request, stand lifecycle, private state/env/key/DB read, old-holder access, branch or commit occurred. All controller Docker/request functions in the selected tests were injected fixtures; SQLite probes opened only newly created temporary files. The exported core was imported without invoking the CLI.

### RR1 — P1 blocker: closed WAL databases cannot be backed up through the new read-only helper

**Locations**

- `public-image-stand.mjs:1303–1314`: stop web/API, drain durable work, require worker exit 0 and no remaining writers.
- `public-image-stand.mjs:1155–1161`: mount both source volumes **readonly**, with `volume-nocopy`, into the helper.
- `public-image-stand.mjs:1049–1069`: open the original databases `readonly:true` and immediately query integrity/schema/content. No immutable-open or other handling of a closed WAL database without writable shared-memory/sidecar access is present.
- `public-image-stand.mjs:1315–1326`: the helper must produce both verified backups before any data-copy receipt or replacement execution can proceed.
- `test_public_image_stand.mjs:1874–1885`: the existing successful WAL test leaves its source writer connections open until `t.after`, and its source directories are writable. It does not model the helper's post-shutdown read-only filesystem.

**Why this affects the intended path**

Both actual stores select WAL (`auth/auth.store.ts:37–38`, `ledger/ledger.ts:203–205`). API shutdown closes the auth handle; worker shutdown closes the ledger after drain. A normal last-connection close checkpoints and can remove the WAL/shared-memory files, leaving only the main files with their WAL-mode headers. That valid state is precisely what the acknowledged command can produce before mounting `/auth` and `/data` read-only.

Opening those files `readonly:true` is not sufficient: SQLite still needs its WAL/shared-memory opening machinery. With no existing sidecars and no ability to create them, the integrity/read query fails. `query_only=ON` does not provide an immutable reader or remove that filesystem requirement. This happens before `db.backup(destination)` can create a verified snapshot; an otherwise writable `/backup` does not fix the source-side opening problem.

**Independent offline reproduction**

Used the actual `recoverySqlite` export, the installed `better-sqlite3`, and temporary auth/ledger fixtures with the required tables/schema and zero durable work. For each source pair:

1. Create WAL databases and committed rows.
2. **Close both writer connections first**; assert/record that only `auth.sqlite` and `ledger.sqlite` remain.
3. Use a separate writable destination directory.
4. Compare writable-source access against source files mode 0400 and source directory mode 0500, preventing the same sidecar creation disallowed by a read-only volume mount.
5. Invoke the unchanged exported core.

Observed:

```json
[{"readonlySourceDirectory":false,"afterCleanClose":["auth.sqlite","ledger.sqlite"],"backupSucceeded":true,"authIntegrity":"ok","ledgerIntegrity":"ok"},{"readonlySourceDirectory":true,"afterCleanClose":["auth.sqlite","ledger.sqlite"],"backupSucceeded":false,"sqliteCode":"SQLITE_READONLY_DIRECTORY"}]
```

A second control created the same required clean fixtures in WAL versus DELETE journal mode, with both sources nonwritable. WAL failed; DELETE backed up successfully and its standalone snapshots restored into a separate writable directory with the same logical fingerprints:

```json
[{"journal":"WAL","sourceFilesAfterCleanClose":["auth.sqlite","ledger.sqlite"],"sourceDirectoryWritable":false,"backupSucceeded":false,"sqliteCode":"SQLITE_READONLY_DIRECTORY"},{"journal":"DELETE","sourceFilesAfterCleanClose":["auth.sqlite","ledger.sqlite"],"sourceDirectoryWritable":false,"backupSucceeded":true,"standaloneSnapshotRestoresLogicalState":true}]
```

These are host-side SQLite reproductions, **not a Docker filesystem/kernel or Linux error-code claim**. The corresponding live helper failure code has not been observed. They isolate a real unsupported source state in the exact core: cleanly closed WAL files, no sidecars, no source-directory writes. The production source stores are WAL, so the DELETE control is not an instruction to switch them to DELETE or a passing test of the current live path.

**Operational consequence**

The failure occurs **after web/API/worker have been stopped**, with the original image catalog entries unavailable and rollback explicitly not guaranteed. The command correctly remains HOLD rather than falsely publishing success, but it may strand the isolated stand unavailable **before verified host backups exist**. The read-only helper does not erase source data; this is a recovery availability/backup-assumption blocker, not demonstrated data corruption or a false-success receipt.

**Required correction and regression**

Implement and test a source-read/snapshot strategy that actually supports the quiesced WAL/no-sidecar state under its declared filesystem policy. Keep source identity, WAL consistency, integrity/FK/content checks and bounded/private snapshots. Do not paper over the failure by claiming online-backup alone solves read-only WAL opening, copying only a potentially stale main file, ignoring WAL, or silently loosening mount/write authority. If the chosen design changes sidecar/reader lifetime or permits any source filesystem writes, explicitly review that narrower authority and crash sequencing before enabling it.

The missing regression must close every source connection before the core is invoked, verify the main-only WAL state, enforce nonwritable source directories (or an equivalent deliberately injected filesystem/VFS restriction), and require successful verified snapshots. Separately cover committed WAL frames with existing sidecars, partial-helper failure, and restoration of accounts/session rows, report rows, schema versions and sequences from the resulting standalone snapshots. A writable-directory or still-open-writer test alone does not clear this blocker. Retain the current no-recreate/HOLD behavior on a backup failure.

### Other assessed boundaries — no additional blocker established

| Boundary | Disposition |
| --- | --- |
| Missing old image metadata | The new command is a separate explicit `--ack-unavailable-prior-images` replacement path. It compares old engine/Config image IDs with saved pins, independently checks runtime policy and records `originalImageMetadataVerified:false` / `rollbackToPriorImages:false`. It does not inspect retargeted tags as historical proof or globally relax ordinary image validation. Historical prebuild identity/source quiescence is clearly operator-attested where the earlier launcher recorded none. No retroactive qualification is claimed. |
| Retained/8080 isolation | Fixed project `dip-public-images`, one bound local Unix endpoint, exact prefiltered namespace and volume/network membership. Recovery mutation targets are exact owned IDs/services; only the newly created helper ID is removed. No old-project up/stop/prune/data-copy path or port-8080 request was found. Injected fixtures prohibit old-resource arguments; this is source/fixture assurance, not a live inventory attestation. |
| Build before admission fencing | Four builds occur sequentially before any stop, candidate immutable IDs/defaults/references/config are validated, saved main pins remain unchanged until after backup, and prior process/control/storage/network continuity is rechecked. Mutable source outside the captured Dockerfiles/ignore/Compose files is an explicit no-concurrent-change attestation, not signed build provenance. |
| Drain and writer exit | Web receives explicit fast SIGTERM, API must exit 0, worker continues until both queued/running scans and undelivered outbox work reach zero, then must exit 0. The gateway remains live but has no DB mount. Foreign volume consumers and failed/nonzero writer shutdown refuse rather than being normalized into clean quiescence. The five-minute drain limit may refuse legitimate longer work; that bounded refusal is documented and is not another defect. |
| Backup/restore semantics apart from RR1 | SQLite online backup, not raw main/WAL copying; integrity/FKs/schema/pending checks, all-table/schema/sequence fingerprints, source/copy rechecks, private bounded host copies, hash/fsync checks are appropriate in intent and pass writable-source tests. They are not an implemented generic restore procedure. A successful backup does not restore missing images, and the code/docs do not promise automatic rollback. Snapshot/data guarantees remain conditional on fixing RR1. |
| New process/data verification | Recreation is no-build/no-pull, uses validated immutable IDs, skips the original initializers and retains volume/network identities. Before reopening web, new API reads must match both saved database fingerprints; fresh worker heartbeat/API health and final namespace checks are required. A detected startup content change leaves HOLD with backups, not silent migration acceptance. This is detection, not automatic reversal of startup writes. |
| Durable audit and crash exclusion | Original marker bytes/inodes are retained; private intent/stage records precede mutation submissions. Failures retain guard/original or incomplete audit history; ordinary up/stop cannot complete or ignore that state. Host backup hashes, original identity and completion manifest are validated on future lifecycle. Guard archival/restoration and postcommit console-loss fixture cases pass. No automatic lock removal, old-container restart, backup pruning or rollback is attempted. |
| Qualification language | Success is `RECOVERED_REDEPLOY_PRIOR_IMAGES_UNVERIFIED`; deployment/readiness is explicitly separate from native scan/browser/Trivy qualification. The unauthenticated 8081 readiness request exists in source only and was injected, not sent, during this review. |

The process/namespace checks are guards against unsupported state, not an atomic lock on all possible external Docker administrators. The documented no-concurrent-lifecycle/build/database-maintenance attestation remains a prerequisite. This review does not manufacture historical old-image evidence or require a broader unavailable-image bypass.

### Validation actually performed

From repository root:

```sh
node --test --test-name-pattern='replacement|SQLite recovery core|missing saved image metadata|status missing runtime|future build failure' scripts/test_public_image_stand.mjs
node --check scripts/public-image-stand.mjs
node --check scripts/test_public_image_stand.mjs
```

Observed: **25 test results passed, 0 failed/skipped**, exit 0, approximately 11 seconds; both syntax checks exited 0. This was a name-filtered source-fixture selection, not the handoff's four-file/288-result run and not a full suite. The passing selection includes old-image evidence refusal, acknowledged replacement ordering, writer/drain/helper/copy failure fencing, interrupted archive boundaries, completion tamper checks, future build records, durable console-loss behavior and the existing still-open-writer SQLite backup test.

Also ran three disposable inline SQLite probes: a minimal closed-WAL readonly-directory reproduction; the exact exported-core writable versus nonwritable comparison; and the WAL/DELETE nonwritable-source plus standalone restore control. Outputs relevant to the blocker are recorded above. All temporary probe files/directories were removed; no probe source file was saved.

### Required disposition before execution

**Do not treat this review as approval to run the current recovery command.** Clear RR1 with the corrected core/helper design and post-clean-close/nonwritable-WAL regression, then independently recheck the backup and interruption sequence. The existing unavailable-old-image acknowledgement and honest no-rollback/no-qualification result vocabulary should remain unchanged. No additional operational permission, private-state inspection, forced unlock or live Docker run was performed or implied by this review.

---

## Independent recovery re-review — RR1 staged WAL snapshots / RDEP helper boundaries, 2026-10-18

### Current verdict

**RR1 P1 is resolved on the reviewed corrected snapshot. Scoped offline source approval; no remaining blocker established in this focused re-review.** This supersedes the preceding recovery-command BLOCK for the old source hashes, without deleting that finding or its original reproduction. The RDEP-1/2/3 labels below refer to the author's additional hardening areas, not invented earlier findings by this reviewer.

| Boundary | Re-review disposition |
| --- | --- |
| RR1: cleanly closed WAL/no sidecars/nonwritable source | PASS with actual native SQLite on Node 23: private staging produces verified, independently restorable snapshots without original-source SQLite opens or source mutation |
| RR1: committed WAL and source-family fences | PASS in focused regressions; main plus WAL are staged, SHM is reconstructed privately, source drift rejects rather than producing a verified pair |
| RDEP-1: drain/result authority | PASS in inspected source/injected lifecycle tests: fresh validated ledger-only probe, no exec in unavailable original application images; retry is not zero pending |
| RDEP-2: helper execution boundary | PASS in inspected source/injected tests: stopped create → full created inspections → exact returned-ID start → running checks; unsafe created controls never start; uncertain start stays HOLD |
| RDEP-3: lossless preservation comparison | PASS: typed BigInt INTEGER, REAL/BLOB/TEXT/NULL distinction and exact high `sqlite_sequence`; independent signed-64-bit roundtrip passed |
| Old image metadata and operational qualification | Unchanged: prior metadata is not certified, rollback to missing images is not guaranteed, and no live Docker/deployment/native qualification is established by this approval |

No further code change is requested by this focused re-review. Existing explicit operator acknowledgement, correct isolated namespace, source/lifecycle quiescence and retained-data prerequisites still apply; this is not an automatic recovery, forced unlock or new qualification waiver.

### Exact reviewed inputs and report preservation

```text
858b754e8ff7f37592657db7689400a59481b8357435ac9dd458460bf6bae8d6  scripts/public-image-stand.mjs
2953613e44f4bbba6eb949ab68d74bc44ba3dc2fda7b91cb11bfaec57245df22  scripts/test_public_image_stand.mjs
b8f7d4447cbe550740ebe1b78718ed807e49d5388637c1dbce72d5fb2085cb9c  docs/public-image-recover-redeploy-20261018.md
```

Hashes were checked at both the beginning and end of source/probe validation and remained unchanged. Preserved report prefix before this append: **62,842 bytes**, SHA-256 **`ce2f5f759279b5074afa10d7608222199559fbe7624830970af55383c0f71de4`**. Only this report append was authored. Production/test sources, stand/private state, dependency installation/builds and old retained resources were not changed or accessed.

No Docker/Compose command, private-file/environment/DB access, network/listener/live request, old-image execution, native stand proof, branch or commit occurred. The selected lifecycle tests inject the Docker and HTTP adapters; all SQLite files and simulated writer mutations belong to new disposable fixtures, removed afterward.

### Compatible runtime was actually used

The installed compatible runtime was discovered as:

```text
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node
Node v23.11.0
NODE_MODULE_VERSION 131
SQLite 3.53.2
```

A real `better-sqlite3(':memory:')` open/query/close succeeded before SQLite validation. Every substantive test/probe below used that explicit Node executable. No ABI-127 failure was treated as a pass, no native dependency was rebuilt, and no SQLite test was skipped. An initial shell discovery command ended with an unsupported `command -v -a` option after successfully locating Node; the explicit runtime/binding checks above and all validation commands subsequently succeeded.

### RR1 fix: source byte reads, SQLite only on private staging

The corrected `copyStableSqlite` (`public-image-stand.mjs:1043–1075`) captures the original main and optional WAL as a bounded regular single-link family. It rejects a rollback journal/unsafe sidecars, reads source bytes with `O_RDONLY/O_NOFOLLOW/O_NONBLOCK`, and hashes/stamps the family before copying, after copying, after SQLite processing, and across completion of both databases. It does not create original sidecars or copy SHM. It stages main **and WAL when present** as private `db.sqlite` / `db.sqlite-wal`, letting SQLite rebuild its own private shared-memory state.

`recoverySqlite` now requires explicit quiescent mode for backup output, opens the **stage** writable with query-only SQL, and applies the online-backup API to that recovered consistent stage (`1088–1134`). The standalone snapshots, not raw staged files, are reopened and validated for integrity/FKs/schema/content, hashed/fsynced, and returned as backup evidence. Private staging is cleaned, and both original source fences are checked again before a successful pair returns.

The output-null comparison path intentionally remains a readonly SQLite read transaction of the **new validated live API's writable-mounted databases**. It is not reused as a main-only immutable source-volume backup. The new code does not solve RR1 by granting write access to the retained source volumes, ignoring WAL, changing source journal mode, or merely making the old source directories writable.

**Independent repeat of the original P1 input state:**

- Created actual auth/ledger WAL fixtures and committed account/session/report data.
- Closed every source writer and verified the directory contained only the two main `.sqlite` files.
- Changed source files to 0400 and source directory to 0500.
- Repeated the old readonly-source integrity query as a control: it still failed with `SQLITE_READONLY_DIRECTORY` on the compatible Node 23 runtime.
- Ran the corrected exported core with the required new `{ quiescent:true }` option and a constructor wrapper that rejects **any** SQLite open of an original source path. It observed two private stage opens and two snapshot-validation opens, and zero original-source opens.
- Restored only the resulting standalone snapshots into a separate writable directory. Checked account BLOB, session ownership, retained report, exact signed-64-bit minimum/maximum and adjacent `2^53`/`2^53+1` values, and the exact high event sequence. Restored fingerprints matched both backup fingerprints.
- Verified original source bytes, inode/device, mode, size, mtime/ctime and directory member names were unchanged; no source sidecars appeared; private stage directories were removed.

Observed output:

```json
{"node":"v23.11.0","abi":"131","priorReadonlyError":"SQLITE_READONLY_DIRECTORY","stagedBackup":"PASS","sqliteSourceOpens":0,"sourceBytesAndIdentityUnchanged":true,"sourceSidecarsCreated":0,"standaloneRestoration":"PASS","signed64BitValuesExact":true,"sequenceAbove2Pow53Exact":true,"stageDirectoriesRemoved":true}
```

This directly clears the previous host-side SQLite reproduction rather than substituting a writable source, a DELETE-mode database or an ABI error. It is still not a live Docker read-only-mount/kernel proof.

### Additional WAL, pair-fence and failure checks

The new real SQLite regressions passed for both required states:

1. Cleanly closed main-only WAL sources in nonwritable directories.
2. Committed WAL frames left by a deliberately terminated **disposable child writer**, with all original files/sidecars made nonwritable before backup. Restored account/session/BLOB/report rows, schema/data fingerprints and `sqlite_sequence=9007199254740993` remained exact, while source file bytes/names/modes stayed unchanged.

Source-copy drift, partial second-database failure, pending work, incompatible schema and FK failures remain refusals. Staging is bounded within the existing helper scratch policy; the revised capacity/value limits can refuse large input rather than claiming arbitrary database-size support.

An additional independent probe changed the temporary original auth DB **after its stage had been processed and cleaned**, while the ledger stage was opening. This deliberately simulated an external writer violating quiescence, using a separate fixture connection—not a write by the recovery core. Final cross-database source verification rejected the pair with `SQLITE_SOURCE_CHANGED`; no successful pair/ready result was returned and both stage directories were cleaned:

```json
{"node":"v23.11.0","crossDatabaseSourceDriftRejected":true,"error":"SQLITE_SOURCE_CHANGED","verifiedPairReturned":false,"stagingCleaned":true,"note":"simulated external write to disposable auth fixture only"}
```

Thus source stability is checked beyond each individual stage's lifetime, not only while copying that one database. Successful auth output left by a later failure is partial evidence, not authorization to publish a complete backup pair or redeploy.

### RDEP-1/2: fresh-image probe and create/inspect/start controls

Inspected `backupArguments` / `validateBackupHelper` (`1216–1253`) and the controller's `makeHelper` / drain / backup sequence (`1366–1414`):

- Both purposes use the already independently validated **fresh immutable API image**, fixed Node entrypoint/program, network none, readonly root, UID 65532, bounded tmpfs/resources, no JWT/hook/provider environment and exact readonly/nocopy source volumes.
- Drain mounts only ledger, not auth. Its byte-fenced private SQLite copy supplies the count; a source-change retry is accepted only as the exact retry envelope, never normalized to zero. No drain SQL/program is executed in an original worker/API container.
- The controller creates each helper **stopped**, validates the exact returned ID/name/image/config/mounts/state, records controls, reinspects created state and starts **that ID**, not a mutable name/tag. Running policy/control revalidation precedes accepting output or issuing controller execs. The backup entrypoint naturally begins after the approved start; this is not a claim that post-start inspection precedes process execution.
- Recovery namespace/volume accounting excludes only that exact validated helper and expected mounted volume. It does not suppress a foreign ledger consumer. Probe stop/removal returns to the ordinary six-container census before worker shutdown/backup.
- After recreation, `inspectOne` requires a new application container ID different from the original as well as the selected fresh image, before data-comparison/heartbeat execs. Old image metadata is neither silently certified nor used to authorize probe execution.

Injected tests passed for both helper purposes' create/created-inspect/start/running-inspect/exec ordering, unsafe created controls causing zero starts, uncertain starts causing no exec/recreation, forged old-worker output never being requested, foreign consumer rejection, exact removal and retained HOLD at the new mutation boundaries. These are source/fixture results, not observed Docker startup behavior.

### RDEP-3: typed lossless fingerprints

`sqliteTypedRow` and fingerprint queries (`1076–1084,1098–1115`) now preserve SQLite INTEGER as exact BigInt decimal in raw rows, including rowid and `sqlite_sequence`. REAL is separately typed with its IEEE-754 bytes; BLOB/TEXT/NULL remain distinct. Safe integers are enabled before reading integer values; pending-count RPC conversion follows an explicit safe-range check rather than general Number coercion.

The real SQLite regression distinguishes adjacent `9007199254740992` and `9007199254740993` values and sequence values by different hashes. Typed-serializer tests distinguish INTEGER/REAL/BLOB/TEXT/NULL, signed zero and reject unsupported/oversized values. The independent standalone-restore probe above additionally retained `-9223372036854775808`, `9223372036854775807`, both adjacent high values and the high sequence exactly. The old lossy Number-based fingerprint assumption is no longer used for accepted row/sequence preservation.

### Validation actually executed for this re-review

Working directory: repository root. Explicit compatible runtime used:

```sh
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --test --test-name-pattern='replacement|SQLite recovery core|missing saved image metadata|status missing runtime|future build failure|RR1|RDEP' scripts/test_public_image_stand.mjs
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --check scripts/public-image-stand.mjs
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --check scripts/test_public_image_stand.mjs
```

Observed: **35 test results passed, 0 failed/skipped**, exit 0, approximately 20.8 seconds; both syntax checks passed. The selection retains relevant original recovery/drain/crash/receipt guards and adds all new RR1/RDEP cases. Two independent inline native-SQLite probes produced the outputs above. All disposable probe data was removed; no test/probe source file was saved.

The author's **298-pass four-file result remains author evidence**; it was not rerun or relabelled as this review's result. No full suite, dependency reinstall/rebuild, Docker helper, real lifecycle/private-state operation or stand/network request was run.

### Final scope of approval

For the exact hashes above, the original RR1 source-level blocker is cleared and the reviewed new helper/fingerprint boundaries receive **scoped offline approval**. There is no retrospective old-image qualification and no guarantee of rollback to unavailable image metadata. The corrected result remains `RECOVERED_REDEPLOY_PRIOR_IMAGES_UNVERIFIED`; original HOLD/audit preservation and explicit no-automatic-retry/rollback semantics must remain.

This review does not assert that a live recovery has succeeded, that current private databases fit the declared limits, or that Docker/container normalization, cgroups, mounts, signed-release readiness or native/browser scanning has been qualified. Any execution remains the coordinator's existing explicitly acknowledged isolated-8081 operation under the documented prerequisites, never a reason to touch 8080/retained resources or manually remove guards.

---

## Independent re-review: one-shot same-audit pre-lifecycle resume — 2026-10-18

### Verdict and exact review boundary

**SCOPED OFFLINE APPROVE. No blocking defect established in the reviewed mount-order fix and explicit same-audit resume.** This is approval of source-level admission, continuity, one-shot/crash fencing and fixture behavior for the exact hashes below, not a report that the real command has run or succeeded. Original reviews and their historical BLOCK/approval decisions above remain unchanged.

Reviewed inputs, SHA-256 (unchanged before/after validation):

| File | SHA-256 |
| --- | --- |
| `scripts/public-image-stand.mjs` | `a9c9e6780af82f78dcf24eedc562825a01a02fd9c747d8098c2a9e580f0ca582` |
| `scripts/test_public_image_stand.mjs` | `061cc7e5f35dd03553b41414e44bfabf2eb11b7d45cec35176616edbad42026e` |
| `docs/public-image-recover-redeploy-20261018.md` | `94a257e7657683bfbecd7a71e7e434d7229e1e99d341c5a67633b76aa5d741e2` |

The pre-append review document was **77,099 bytes**, SHA-256 `ef9a0be9713facae8a4352fa97350451f067a3ba6b42cda39671f324fe96045f`; that byte prefix is preserved. Only this review document was edited. No production/test source, operator note, private state, environment file, retained resource or Git history was changed. No Docker command, registry/network request or live stand request was made. All lifecycle/HTTP responses below came from injected disposable fixtures.

The author's diagnosis of the actual retained attempt—image/profile policy passed, only observed mount ordering differed—is **author evidence**, not independently observed live evidence in this pass. The independent reproduction below verifies that particular source-level failure boundary without reading the real audit. Likewise, the author's 329-test result is not relabelled as this review's test execution.

### Admission and narrowly bounded compatibility

Source checked: `public-image-stand.mjs:1153–1173,1272–1345,1347–1484,1531–1547,1564–1575`; operator contract checked especially `public-image-recover-redeploy-20261018.md:27–55`.

- The CLI requires the explicit resume command, exact acknowledgement and exact `redeploy-<32 lowercase hex>` audit argument. It does not authorize a fresh recovery, force/reconciliation unlock, rebuild or generic retry.
- `preLifecycleResume` requires exactly the original intent/baseline/prior pins/candidate/failure, empty backups and six numbered phases in the fixed order ending at `new-image-validation`. The failure must be the canonical guard failure at that checkpoint, with consistent phase/failure timestamps. Later/missing phases, helper/start artifacts, extra entries, another guard or a partial prior resume refuse.
- Only the nominated incomplete audit is skipped by completed-history validation. Every other recovery/reconciliation history remains subject to its ordinary complete-receipt checks. This is not a global incomplete-history bypass.
- The existing original operation records, endpoint, profile/Compose, public CVE evidence and captured Dockerfile/ignore inputs reconstruct the full original intent. Saved prior pins must still match the main pins. The complete current prior namespace is independently validated against the fixed runtime policy **without inspecting or certifying unavailable old own-image metadata**.
- Normal continuity hashing sorts only the engine-observed `Mounts` by unique destination. It retains every complete mount field. It does not sort `HostConfig.Mounts`, command/entrypoint/Env arrays, network contents or process evidence.
- Reading an older order-sensitive baseline is confined to explicit resume: at most six already validated complete mount records are permuted to reproduce each saved hash. The projected snapshot must then equal the entire saved baseline. Container/image IDs, process start/finish/PID/restart evidence, declared controls, volume identity/consumers and network controls/endpoints are not exempted.
- All selected fixed image tags are independently inspected and policy-checked; their immutable IDs must equal the saved candidate, initializer IDs must remain unchanged, and references/consumers must be own-only. Candidate config and current prior-runtime continuity are revalidated before the resume claim. The resume branch skips every build phase and has no image-pull path; recreation continues using immutable IDs with no-build/pull-never controls.

A guard failure at this checkpoint is not itself proof that candidate policy passed previously. That is acceptable here because candidate policy, identity and the entire runtime baseline are proved again before lifecycle. The admission does not trust the sanitized historical error as image authority.

### One-shot claim, durable audit and preservation

The exclusive `mkdir` of `resume.lock` is the one-shot claim. Its parent is synced before proceeding; the receipt is written exclusively and synced before the same-audit `resume.json`, canonical `resume-baseline.json` and durable `resume-authorized` phase. Thus competing resumes cannot both acquire admission. A crash leaving even an empty/partial resume directory is a sticky HOLD, not a reusable token.

Captured original files are checked by bytes/stamps/inodes, and relevant directories/state/JWT/pins/source/CVE evidence are fenced across subsequent adapter calls. The original failure is never replaced by the new attempt's catch path. Lifecycle phases remain durable-before-submit. Ordinary up/fresh recovery cannot adopt an interrupted resumed transaction or create a second audit around it. Completion binds the original files and new records; archived guard validation requires the matching one-shot receipt. Interruption during guard archival returns to HOLD rather than silently declaring success.

After admission, the existing reviewed sequence remains: stop ingress/API, drain via a separately created/inspected fresh-image helper, cleanly stop the worker, verify writer quiescence, back up from private main+WAL staging, commit immutable pins, recreate/validate fresh application IDs, compare retained logical data before reopening web, then postflight/archive. No old application exec is introduced. SQLite staging, readonly/nocopy source mounts, source-family fences and lossless integer fingerprints retain their previous boundaries; focused regressions were rerun below.

The documented data/JWT limits are honest, not additional invented guarantees. The original baseline had no historical database-content snapshot or JWT inode capture. Current own JWT bytes are checked against the same still-retained API container's immutable Env, then current file identity is fenced. Before fresh quiescence the guarantee is the same original volumes/validated consumers, **not byte-identical databases since the failed attempt**; legitimate live writes can have continued. Consistent backups and subsequent logical-content checks occur at the newly proven shutdown boundary. Neither missing old images nor absent historical evidence is retrospectively certified. No automatic rollback to unavailable images is promised.

### Validation actually executed

Used `/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node` (observed `v23.11.0`), not the incompatible default ABI. From repository root:

```sh
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --test --test-name-pattern='resume|runtime Mounts ordering|sanitized subreasons' scripts/test_public_image_stand.mjs
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --test --test-name-pattern='^replacement |^future build failure|^completed replacement receipt|^SQLite recovery core|^RR1 |^RDEP' scripts/test_public_image_stand.mjs
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --check scripts/public-image-stand.mjs
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --check scripts/test_public_image_stand.mjs
```

Observed, all exit 0:

- **32 test results passed**, 0 failed/skipped/cancelled, approximately 9.9 seconds: mount-order continuity, successful same-audit resume, altered admission/runtime/image evidence refusals, endpoint pinning, crash/replay HOLD, audit/JWT inode replacements, receipt/history corruption and sanitized diagnostics.
- **23 test results passed**, 0 failed/skipped/cancelled, approximately 18.5 seconds: original recovery/drain/shutdown/backup/data/crash/receipt guards plus real temporary SQLite RR1/RDEP regressions. Native SQLite cases actually executed, including clean main-only WAL databases from nonwritable sources, committed WAL from a terminated disposable writer, standalone snapshot restoration, source drift and exact 64-bit values/sequences. These are not kernel/Docker mount proofs.
- Both syntax checks passed. The two selections overlap the drain/shutdown regression; the counts are per invocation, not a claim of 55 distinct tests. No full suite was run.

### Three additional independent disposable probes

An inline Node module loaded source fixtures in memory with test registration disabled and injected adapters only; no probe/source file was saved. Fixture roots and all generated data were removed afterward.

1. **The reported failure boundary, not only a candidate-config failure:** modelled the preceding order-sensitive hashing by changing only the in-memory `secretlessControl` mount selection back to its unsorted observation. After candidate config returned successfully, reversed only observed mount arrays in subsequent synthetic prior-runtime inspection responses. This produced `PRIOR_RUNTIME_CONTINUITY_REFUSED`, six exact phases, a saved candidate and empty backups, with no lifecycle submission. Passed that untouched synthetic audit to the actual current resume implementation. It completed in the same audit, preserved all original artifact bytes/inodes and issued no build/pull. This is a controlled compatibility model, not execution of the historical binary or proof about the private retained audit.
2. **Competing resumes:** rendezvoused two current resume calls at candidate-config validation on one disposable audit, then released both. Exactly one completed and one refused; exactly one `resume-authorized` and one `stop-web` phase existed, only one audit existed, and the archived guard retained its one-shot receipt. The losing call did not overwrite the original failure or prevent the winner's completion.
3. **No unrelated-history bypass:** added a second empty/incomplete synthetic recovery audit beside the nominated failed audit. Resume refused before any additional Docker-adapter call.

Observed probe summaries:

```json
{"probe":"order-sensitive prior-runtime failure after candidate policy","synthetic":true,"exactSixPhases":true,"originalArtifactsPreserved":true,"sameAuditResume":"PASS","buildOrPullOnResume":0}
{"probe":"two resumes rendezvous before final continuity and exclusive claim","synthetic":true,"completed":1,"refused":1,"admissions":1,"audits":1,"durableOneShotReceipt":true}
{"probe":"only nominated incomplete history is exempt","synthetic":true,"otherIncompleteAudit":"REFUSED","dockerAdapterCallsAfterAdmission":0}
```

### Scope of approval, not live acceptance

No source-level blocker remains from this independent check for the explicit one-shot **same-audit pre-lifecycle continuation**, under the documented operator attestation that the previous command/builds returned and no concurrent launcher/tagger/lifecycle/storage maintenance is outstanding. The approval does not broaden image policy, authorize a new audit, permit deletion of guards, or certify unavailable prior images.

No actual resume/redeploy, Docker durability/mount behavior, current private DB contents/capacity, signed-release runtime readiness, native/full-chain scan or browser qualification is claimed. The result remains `RECOVERED_REDEPLOY_PRIOR_IMAGES_UNVERIFIED`. A real post-admission failure is still manual-review HOLD, with preserved failure/audit and no second resume or automatic rollback. This review supplies no authority to touch port 8080, other projects or retained resources.

---

## Independent re-review: exact phase-10 created-drain continuation — 2026-10-18

**Verdict: SCOPED OFFLINE APPROVE. No blocking defect established in the reviewed empty-DriverConfig normalization and `continue-recover-created-drain` admission/continuation.** This verdict applies to the exact source hashes below and the documented narrow operator prerequisites, not to live recovery completion. The author's actual stage-10 diagnosis, successful live read-only check and 373-test result remain author evidence; none was independently observed against private/live resources in this pass.

| Reviewed file | SHA-256 |
| --- | --- |
| `scripts/public-image-stand.mjs` | `0b4c2f6d9a01d23d9ac194565032e291424d32b8d73c1a39e3d94edb3e56361d` |
| `scripts/test_public_image_stand.mjs` | `7cf146b19bd4f71fcc48e1ad43a5afad1f6c6d1efd59b631687bda79e38b4bc8` |
| `docs/public-image-recover-redeploy-20261018.md` | `3a2fc4fc04bb10e73b641fbccd85b26867ac9b8963a5123d799a91bee6c9bdeb` |

Pre-append review: **89,144 bytes**, SHA-256 `ef7aa4ba8c6a583d92f511369cf7af4af4666732a2ef7c1ed2d253832e22e643`; preserve that prefix unchanged. Only this review document was edited. No production/test/operator source edit, Docker/private-state access, network/live request, old-holder operation, full suite or commit was performed.

### Source-level admission and normalization

Inspected `public-image-stand.mjs:1246–1279,1281–1402,1403–1637,1656–1664` and the operator note's current-stage contract (`3–75`).

- Helper volume options accept only `{NoCopy:true}` or `{NoCopy:true,DriverConfig:{}}`. Null/array/custom driver options, unknown option keys, copy-up and writable source mounts remain rejected. This is inert engine-metadata compatibility, not custom driver authority. Observed helper volume driver/source must match the original inspected local volume's mountpoint.
- Created-drain admission requires exactly the original ten numbered phase records, ending at `drain-helper-submission`, and the precise original/resume artifact sets. The canonical original failure remains the old pre-lifecycle failure; it is not misrepresented as a new durable helper-ID receipt. Existing `resume.lock/receipt.json` must equal the original resume artifact, including original-file hashes/inodes and state directory/profile/JWT/pins identities. Backups must be empty; a helper-control record, later phase, partial continuation lock, extra file or other incomplete history refuses admission.
- Before adoption, the own-only namespace census permits precisely six original containers plus the deterministic helper name. The explicit requested helper ID must match inspection; its fresh candidate API image, Node executable/program, Env, resources, readonly/nocopy mounts, namespace and controls are independently validated. Adoption additionally requires status created, PID 0, restart count 0, zero never-started timestamps/exit code, no error/OOM/dead/restarting state, and a valid creation time. Name/tag alone cannot authorize starting a different helper.
- Original web/API IDs, controls, process start/restart evidence and clean stopped states are checked; stop timestamps must follow their durable stop phases and precede helper creation. Original worker/gateway and initializers retain their required process states/identities. Original volume/network identity and exact current consumer/endpoint policy remain enforced. Only the exact requested helper is excluded from its expected ledger consumer set; foreign consumers are not hidden.
- The original intent, source/build inputs, JWT/profile/CVE and prior/candidate pins are re-proved. All fixed candidate images/references/consumers and rendered candidate config are revalidated without old-image certification, rebuild, pull or tag repair. Complete current continuity and the created helper are checked again before the claim.

### One-shot progression and downstream fences

The separate `continue-drain.lock` is created exclusively inside the existing recovery guard, synced, and given its synced receipt before same-audit continuation records and the durable authorization phase. Partial lock/receipt or any later artifact remains sticky HOLD. This does not recycle the earlier resume claim or open a general retry path.

The continuation initializes the stopped set to web/API and adopts the existing drain helper. It **does not repeat web/API stops, drain-helper create, build/pull or initializer execution**. It reinspects the created helper/control identity, records that exact helper, writes the helper-start boundary and starts that ID. Accepted failures add a sanitized continuation-failure record without overwriting the original failure; replay/fresh recovery remains refused.

After that single start, existing safety boundaries remain in force: validated fresh-helper drain, exact helper stop/removal, clean worker shutdown, no-live-writers gate, separately created/inspected fresh backup helper, readonly/nocopy original sources, fenced private main+WAL staging, integrity/bounded private backup hashes, immutable recreation and retained logical-content verification before reopening web. Gateway identity remains fenced while backups are taken. Success archives both prior guards/receipts and the new claim; completed-history validation binds the adopted helper record to the continuation receipt. No exec in an unavailable original application image is introduced.

### Offline validation actually run

Explicit compatible Node runtime: `/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node`. Commands from repository root:

```sh
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --test --test-name-pattern='created-drain|DriverConfig' scripts/test_public_image_stand.mjs
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --test --test-name-pattern='remaining drain backup|^RR1 |^RDEP|^SQLite recovery core' scripts/test_public_image_stand.mjs
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --check scripts/public-image-stand.mjs
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --check scripts/test_public_image_stand.mjs
```

Observed: **36 + 19 passing test results**, zero failed/skipped/cancelled, approximately 22.4 and 9.6 seconds; both syntax checks passed. Coverage includes admission refusals, successful same-audit adoption with no repeated lifecycle, interruption/replay fences across drain/backup/recreation/archive, fixed sanitized downstream errors, plus actual temporary native-SQLite WAL/source-drift/restore/64-bit regressions. All Docker/HTTP responses were injected fixtures, not live operations.

Two additional independent inline probes loaded the current fixture definitions in memory with test registration disabled; no source/probe file was saved, and all temporary roots were removed:

1. Captured the entire disposable state/audit tree before and after `check-recover-created-drain`. Every file/directory member set, file byte content, inode/device, mode and mtime/ctime remained equal; zero mutation submissions. Access times were intentionally not asserted.
2. Rendezvoused two continuation contenders at candidate-config validation on the same created-helper fixture. Exactly one completed and one refused; exactly one adopted-helper start, zero repeated original web/API stops, zero drain creates/build/pulls, one audit and the archived durable continuation receipt. The losing contender did not spoil the winning transaction or replace original evidence.

```json
{"probe":"read-only check","synthetic":true,"stateAndAuditBytesInodesModesMtimeCtimeUnchanged":true,"mutationSubmissions":0}
{"probe":"two created-drain continuation contenders","synthetic":true,"completed":1,"refused":1,"adoptedHelperStarts":1,"repeatedWebApiStops":0,"drainCreates":0,"buildPull":0,"audits":1,"durableClaimArchived":true}
```

**Final scope:** offline approval of this exact phase-10 one-shot continuation under the explicit previous-client-returned/no-concurrent-launcher-or-storage-operation attestation. The current helper ID is newly established and bound before start; no earlier durable ID receipt is invented. This does not certify unavailable old images, historical DB-content equality, Docker/kernel durability, live drain/backup/redeploy or native/browser qualification. The live outcome is still unverified by this reviewer; any accepted continuation failure remains manual-review HOLD, not permission for another continuation or guard removal. Port 8080 and retained/other projects remain out of scope.

---

## Independent re-review: phase-12 started/expired drain continuation — 2026-10-18

**Verdict: SCOPED OFFLINE APPROVE. No blocking defect established for the reviewed authority/process split, historical OOM-only compatibility and explicit phase-12 continuation, including clean expired-probe retirement and renewal.** This is source/fixture approval for the hashes below, not a declaration that the live command or backup/redeployment succeeded. The author's actual false-to-null diagnosis, later timer expiry, successful live read-only models and 403-test result remain author evidence, not independently observed private/live facts in this pass.

| Reviewed input | SHA-256 |
| --- | --- |
| `scripts/public-image-stand.mjs` | `138e81693a5ded501d4d0f17af627e45333f5e68314e34ef9abfde834182af3e` |
| `scripts/test_public_image_stand.mjs` | `318896a93a719856a91699bff801d283595e25abc79d2ee590c1959f762aecc9` |
| `docs/public-image-recover-redeploy-20261018.md` | `878af423eff950dec1e03c48e71824a58ed08b9571289bf0d977c557ec216413` |

Pre-append review prefix: **97,656 bytes**, SHA-256 `c5774bb1b1cb80ed3f92a18fbeac73e10098297d71c94b6018717ff8e16fc93c`. Preserve all previous text unchanged. Only this reviewer-owned document was edited; no production/test/operator source edits, Docker, private state/env/DB/key reads, network/live calls, old-holder operations, full suite or commit.

### What was independently checked

Source inspected especially `public-image-stand.mjs:1246–1282,1297–1330,1368–1480,1549–1707`; current operator contract `public-image-recover-redeploy-20261018.md:3–68`; new fixture/regression cases `test_public_image_stand.mjs:1746–1861`.

**Configured authority versus process identity:** every controller helper observation still runs independent fixed-policy validation before authority projection. `HELPER_AUTHORITY_V3` preserves image/Node program/args, exact base Env, user/directory/labels, sandbox resources/security, readonly/nocopy volume semantics and remaining Config metadata. Only already-validated policy-equivalent defaults are normalized: OOM false/null, unset swappiness null/-1, the two no-new-privileges spellings, absent/exact-empty DriverConfig, inert startup/ArgsEscaped metadata and equivalent empty/default/order representations. Unknown nonneutral HostConfig fields still refuse, as do OOM-disable true, devices/GPU authority, extra Env/hooks, custom drivers, copy-up, writable mounts and reduced resources. Process PID/start/restarts are separate evidence, not silently dropped identity constraints: running observations bind and compare the epoch; intentional stop requires its preserved start/restart evidence and exited state.

**Historical compatibility remains narrower than V3:** a helper record without a V3 marker is checked against the original raw Config/HostConfig digest with exactly the OOM field tried as false or null. Swappiness/hostname or any other historical raw difference cannot enter through the new projection. Tests explicitly rejected additional legacy swappiness and Config differences. This fixes the reported benign delta without certifying arbitrary historical drift.

**Exact phase-12 admission:** require all twelve fixed ordered phases, prior original/resume/created-continuation artifacts and matching guard receipts, the original helper-control record, and the exact prior `drain-helper-start` / `HELPER_CONTROL_IDENTITY` failure. Empty backups, no drain/later phase or partial/new started-continuation state. Prior state/input/pin/receipt hashes and inodes remain fenced. Current helper ID/image/creation/config must match the recorded helper and prior receipt; start time is bounded by phase 012 and the recorded failure, with zero restarts. Original stopped web/API, running worker/gateway, exited initializers, volumes/networks/consumers and selected candidate image/config policy are re-proved without inspecting unavailable old image metadata.

A running helper must retain its observed epoch/PID; an exited one must be clean exit 0/PID 0, without OOM/error, and have a 355–390-second timer lifetime whose finish has already elapsed (the source permits a one-second clock tolerance). Created-again, early-clean-exit, killed/OOM, restarted or changed-epoch cases refuse. This is a finite admission for the inspected probe's lifetime, not a generic acceptance of exited helpers.

**One-shot and renewal:** exclusive `started-drain.lock`, synced receipt and same-audit authorization precede any retirement or use. All previous locks/failures/artifacts remain unchanged and are bound by the new receipt. New failures use `started-failure.json`; older continuations cannot replay the transaction. The old helper is never sent another start. A still-running probe at most 30 seconds old can be used without start; otherwise the exact validated helper is cleanly stopped if needed, epoch/authority checked, and removed by ID without volume deletion. Then the deterministic distinct `drain-next` is created stopped, inspected against the same validated candidate/sandbox/source policy, recorded and started by its newly returned ID. The expired path is tested with a different replacement ID. A retirement/create/start interruption remains sticky HOLD rather than falling back to restarting the old ID.

**Downstream fences:** no repeated web/API stop, build/pull, initializer rerun or original-application exec. Fresh/current probe drain and removal still precede clean worker shutdown and the no-live-writers gate. Backup uses a separate create/inspect/start helper, readonly/nocopy retained sources, private main+WAL staging and source stability fences, integrity/bounded 0600 copy/hash checks, immutable recreation and logical-content comparison before web reopening. Original gateway and storage/network identities remain fenced. Completed history binds the preserved failures/receipts and replacement-probe record. The new engine-shape models are expressly pure configuration checks, not native health/SQLite/container execution proof.

### Validation actually executed for these hashes

Explicit compatible Node 23 runtime; from repository root:

```sh
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --test --test-name-pattern='OomKillDisable|started-drain|started legacy helper|helper authority projections|expired-probe' scripts/test_public_image_stand.mjs
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --test --test-name-pattern='^RR1 |^RDEP|^SQLite recovery core|remaining drain backup' scripts/test_public_image_stand.mjs
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --check scripts/public-image-stand.mjs
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --check scripts/test_public_image_stand.mjs
```

Observed: **30 + 19 passing test results**, zero failed/skipped/cancelled, approximately 29.9 and 10.2 seconds. Both syntax checks passed. The first selection covers false→null compatibility, created/running/exited authority projection, OOM/device/Env/resource/custom-driver refusals, legacy one-field-only proof, running/expired renewal, twenty admission refusals, epoch/collision checks, later uncertainty/archival/replay and completed-history corruption. The second reruns downstream drain/backup/restored-data/readiness refusals plus actual disposable native-SQLite RR1/RDEP WAL/source-drift/restore/64-bit regressions. All lifecycle and HTTP responses are injected fixtures; no Docker/live proof was fabricated. These are targeted selections, not the author's 403-result run.

**Final scope:** offline approval for the exact phase-12 same-audit continuation under the documented prior-client-returned/no-concurrent-launcher/tagger/storage/lifecycle attestation. Natural expiry is handled by retiring the reviewed old probe and creating a fresh one, never restarting its old ID. This neither retrospectively qualifies old images nor claims live drain, backup, redeploy, current private DB capacity/content or native/browser success. Any accepted uncertainty remains manual-review HOLD; no generic retry or manual guard removal is authorized. Port 8080 and retained/other resources remain outside scope.

---

## Independent re-review: phase-24 backup transport / honest regeneration — 2026-10-18

**Verdict: SCOPED OFFLINE APPROVE. No blocking defect established in the reviewed exact phase-24 continuation, bounded private exec export, or explicit expired-snapshot regeneration policy.** Approval applies to these source hashes and documented quiescence/operator prerequisites, not to live deployment success. The author's actual Docker archive/tmpfs diagnosis, helper expiry, live read-only proof and 428-test result remain author evidence, not independently observed private/live facts in this pass.

| Reviewed input | SHA-256 |
| --- | --- |
| `scripts/public-image-stand.mjs` | `a823650f4e57d03322a58fc48408612ef000ecbcfb0bc16b1671ebc28bf077ae` |
| `scripts/test_public_image_stand.mjs` | `237284aea62188b4ae5932a80f9028fcd28675d4fbc7a284351523092bd198d7` |
| `docs/public-image-recover-redeploy-20261018.md` | `d0ee8660480a6a875d38db1b0945aafd2b0c9d6eb757964d2f7bdcb08f261d14` |

Pre-append review prefix: **105,808 bytes**, SHA-256 `acdcfe441000fbf242dfa58344723d3b806c4e121f2f887cd55d4f59338d32d2`. Previous review text is preserved unchanged. Only this document was edited; no production/test/operator source edits, Docker/private state/env/key access, network/live calls, full suite, old-holder operations or commit.

### Admission, source preservation and unavailable old evidence

Source inspected especially `public-image-stand.mjs:1151–1206,1349–1389,1455–1518,1627–1743,1796–1834`; new tests `1752–1851`; current operator note `3–71`.

- Admission is a distinct acknowledged operation on the same audit: exact ordered phases 001–024, all prior canonical original/resume/created/started artifacts and matching lock receipts, original helper/drain-next/backup records, exact backup-copy / DOCKER_UNCLASSIFIED failure, empty host backups and no partial/new transfer or later evidence. Prior state/input/JWT/pin/CVE/hash/inode fences and complete other histories remain enforced.
- The specified legacy backup helper must match its recorded exact ID/image/authority and no-restart process epoch. Its creation/start is bounded by the backup phases. Only validated still-running state or clean zero timer exit approximately 295–330 seconds after phase 024 is admitted; killed/OOM/restarted/unsafe state refuses. Web/API/worker must remain original cleanly stopped processes, including phase-consistent worker finish; gateway/initializers, storage/network identity and exact consumers remain checked. Candidate tags, immutable IDs, image metadata and rendered config are re-proved without old-image certification.
- The exclusive synced `backup-transfer.lock` and same-audit receipt/authorization bind every old file before renewal. Legacy program acceptance is confined to this admission; normal helper creation requires the new held-snapshot program. No old helper start, repeated drain/application stop/build/pull/initializer run or old application exec is introduced.
- If the legacy helper is still live, a validated manifest of its actual receipt/snapshot/source hashes is captured in the audit before controlled retirement. Regenerated snapshots must match both old/new file/logical receipts and exact source identities/hashes. If the helper has already clean-expired, the audit explicitly records `LEGACY_TMPFS_EXPIRED_NO_DURABLE_SNAPSHOT_RECEIPT` under the new regeneration policy. It does **not** mark the original archive copy successful or invent its lost snapshot bytes/hashes.
- For expired input, historical preservation rests on retained exact volumes/writers, drain/clean-shutdown history and the no-external-maintenance attestation, not a nonexistent old source-content hash. New verified backup API snapshots and new main/WAL hashes fence the fresh generation/export; post-recreation logical comparison remains required. This is an explicit acknowledged limitation, not a fabricated retrospective byte-equality guarantee.
- Retirement touches only the validated legacy RO helper, never its volumes. Distinct `backup-export` is created stopped, fully inspected/recorded and started by its fresh returned ID from the same candidate image. The no-live-writers gate precedes generation, and exact helper-only consumers/authority/epoch remain checked during export. Every accepted uncertainty retains original failures/guards and partial evidence plus a new transfer-failure record; earlier continuations cannot replay it.

### Bounded transport, private publication and lifetime

`backupExportOperation` uses fixed auth/ledger/backup paths in the actual helper program. Its path injection parameter is an offline-test seam, not a CLI path argument. Manifest/chunk requests have closed shapes and finite role/offset/size limits; traversal, negative/oversized reads and changed stamps refuse. Reads use readonly NOFOLLOW/NONBLOCK opens and before/after path/fd checks for regular single-link owned files. File identities use lossless decimal BigInt fields. Main/optional-WAL families are hashed; rollback journals refuse; empty WAL is valid; SHM is not copied as snapshot data.

The initial manifest validates ready receipts, snapshot hashes/sizes/modes and source-family identities/hashes and is recorded durably **before transport**. Each exec frame contains at most 1 MiB decoded bytes, with strict role/offset/key set, exact encoded length and canonical base64 checks. The Docker subprocess captures output internally under its finite 16 MiB buffer; a maximum frame is approximately 1.4 MiB. No DB/base64 content goes into logs, Env or argv; argv contains only the fixed reader and bounded metadata request. There is no archive `cp` in this path.

Host writes use exclusive 0600 partial files, sequential bounded writes/full SHA-256 and fsync, then verify owner/mode/size/inode/directory identity. Publication is an atomic no-overwrite hard link followed by removing only the operation's partial name and syncing the directory. Existing finals/partials refuse; failures do not erase partial evidence to retry. Final standalone backups are rehashed and the complete source/snapshot manifest is reread/compared before verification receipt, helper cleanup, pin commit or recreation. Malformed chunks and source drift cannot authorize new services.

The new helper retains the 120-second generation watchdog, then fsyncs ready metadata and holds snapshots until explicit cleanup. This avoids timer-driven loss during review/transfer without relaxing RO/nocopy source mounts, no-network/UID/resource bounds or allowing an indefinite launcher invocation. RAM snapshots still cannot survive container/daemon/host loss; only host fsynced evidence is durable. Keeping the helper alive on HOLD does not turn it into a source DB writer or promise power-loss persistence of tmpfs.

### Targeted validation actually executed

Compatible explicit Node runtime; repository root:

```sh
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --test --test-name-pattern='phase-24|backup-copy|native export reader|bounded exec transfer|quiescent backup API|backup transport' scripts/test_public_image_stand.mjs
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --test --test-name-pattern='backup export rejects|^RR1 |^RDEP|^SQLite recovery core' scripts/test_public_image_stand.mjs
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --check scripts/public-image-stand.mjs
/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node --check scripts/test_public_image_stand.mjs
```

Observed: **24 + 12 passing test results**, zero failed/skipped/cancelled, approximately 36.4 and 8.6 seconds; both syntax checks passed. Tests cover running/expired legacy admission and preserved originals, no repeated lifecycle/cp, source/runtime/evidence refusals, uncertain transfer/recreation/archive HOLD, strict chunks/no-overwrite/partial retention, empty WAL and changed-file/traversal rejection, repeated real SQLite backup API generations, original RR1/RDEP WAL/restore/source-drift/64-bit safeguards. These are targeted runs, not the author's 428-result run. Docker/HTTP calls use injected fixtures only.

### Additional independent real-SQLite end-to-end fidelity probe

An inline disposable probe loaded only fixture definitions in memory with test registration disabled. It created actual SQLite auth/ledger databases, inserted a BLOB larger than 2 MiB and event sequence `9007199254740993`, closed both source writers and recorded source hashes/inodes/modes/ns timestamps. It then ran the real exported backup API core, actual fixed-operation manifest/chunk reader, actual bounded host transfer, standalone reopen/integrity/content checks and logical fingerprint comparison.

The host process is not UID 65532: only manifest UID metadata was translated to synthetic helper UID 65532 at the transport-admission seam, with the original real-host stamps used for native chunk reads. The native source reader continued to validate actual host ownership. This is transparent offline namespace modelling, **not** a Docker/UID-isolation or RO-kernel proof. No other identity/hash/byte information was substituted.

Observed:

```json
{"probe":"real SQLite backup to bounded host export to standalone reopen","node":"v23.11.0","authSnapshotBytes":2125824,"ledgerSnapshotBytes":24576,"chunks":4,"maxChunkBytes":1048576,"sourceAndSnapshotFenceChecks":6,"exactSnapshotBytes":true,"integrity":"ok","blobExact":true,"sequenceAbove2Pow53Exact":true,"logicalFingerprintsExact":true,"originalSourcesUnchanged":true,"privateFinalMode":"0600","finalSingleLink":true}
```

Both transferred standalone files matched their generated snapshot bytes exactly; original source directory members/bytes/inodes/modes/mtime/ctime remained unchanged. The probe reopened the published files successfully, retained the BLOB/high sequence and matched both logical fingerprints. Temporary data was removed; no probe/source file was saved.

**Final scope:** offline approval for this exact phase-24 bounded transfer and explicitly acknowledged regeneration from verified quiescent sources. Lost legacy tmpfs snapshots are honestly recorded as unavailable, not certified retrospectively. No live Docker transport, current private DB capacity/content, drain/backup/redeploy or native/browser qualification is claimed. Accepted failures remain manual-review HOLD with no generic replay, old-helper restart, automatic rollback or guard removal. Port 8080 and retained/other resources remain outside scope.
