# Public Docker Hub archive worker — 2026-10-18

## Scope and composition

This document lives under the worker's exclusive write scope. The coordinator may move it to the project `docs/` directory during integration.

`public-image-worker.main.ts` explicitly calls `runWorker(undefined, PRODUCTION_DB_TRUST_ANCHOR, true)`. The default `worker.main.ts` is unchanged. There is no environment flag, HTTP field, or stored `executionProfile` that enables public archive scanning.

`consumeOne(..., { publicImagePolicy: true })` selects `scanPublicImageArchive` only for canonical non-Alpine image jobs with a validated public Docker Hub digest/platform target and no execution profile. `library/alpine` retains its pinned legacy runners. Explicit exact-nginx LOCAL/proof composition retains its existing exact target/receipt/parser behavior even when the public option is present. An arbitrary execution profile is rejected before config loading or archive/scanner work.

The OCI module owns reinspection and archive acquisition. Public worker imports its `preparePublicImageArchive`, `validPublicTarget`, `isPublicReceipt`, and limits; it does not download layers through another path or scan a remote tag. The public receipt binds registry, repository, immutable selected manifest digest, config digest, ordered diffIDs/layer digests, archive SHA-256 and these versions:

- `public-hub-amd64-v1`
- `public-hub-resources-v1`
- `trivy-0.69.3-public-archive-v1`

## Shared lifecycle and bounds

Both archive runners use the same scanner invocation, archive SHA-256 recheck, DB preflight/postflight identity verification, scratch audits, checkpoint/final freshness fences, cleanup and cancellation machinery. Scanner JSON and CycloneDX pass the existing archive identity validators before normalization. There is no alternate parser that skips config/diffID identity checks.

Public acquisition/scanner accounting uses `PUBLIC_IMAGE_LIMITS`; legacy nginx uses `ARCHIVE_LIMITS`. Public limits include 64 layers, 512 MiB total compressed layers, 1 GiB total expanded layers, 1152 MiB archive, 2 GiB scratch, 100000 archive/scratch entries, 320 requests and 544 MiB wire bytes. Consult the shared OCI policy as the authoritative source. Clean secret reports require matching positive layer inspection evidence, including all inspected diffIDs; public supports 64 layers, legacy remains capped at 32.

Every Trivy stage remains bounded to 120 seconds, output caps remain 1 MB Secrets / 2 MB CycloneDX / 8 MB CVE, and the complete archive/scanner attempt remains bounded to 600 seconds. Normalization remains limited to 1000 components, packages, results and findings; unsupported larger reports fail safely. CVE advisory budgets are unchanged. No host extraction or unbounded subprocess/environment is introduced.

The dedicated public process requires:

- `/data/ledger.sqlite`, `/data/worker.ready`, cache `/tmp/trivy`;
- Linux cgroup v2 memory limit exactly 4 GiB, zero swap, CPU `100000 100000`, PID limit 128;
- `/tmp/trivy` is a real, non-symlink tmpfs with capacity at least 2 GiB + 16 MiB and at most 2304 MiB (deploy with 2304 MiB);
- the existing pinned Trivy 0.69.3 binary, bounded egress gateway and trusted read-only CVE DB release/cache composition.

Resource evidence is checked at startup and during heartbeat/consumption. The tmpfs quota complements the periodic logical 2 GiB scratch audit. Deployment changes are deliberately outside this worker change. No LOCAL nginx readiness/qualification marker is granted to the public composition. DB trust uses the production anchor, not a LOCAL override. Existing deployment variables are read only by runtime code; no existing local environment was loaded during implementation.

## Coverage and normalization

Public OS recognition comes exclusively from scanner evidence, never repository names, tags or image config environment variables. Explicit supported families are `alpine`, `debian`, `ubuntu`, `redhat`, `centos`, `rocky`, `alma`, `oracle`, and `amazon`; versions must be bounded numeric release identifiers. Unknown/missing/malformed OS evidence produces explicit `OS_UNKNOWN` unsupported CVE coverage. Validated `EOSL: true` produces `OS_EOL` unsupported coverage after validating the result types/inventory. Omitted/false EOSL is not invented EOL evidence. No additional lifecycle database or support-date inference is performed.

Checked public CVE coverage requires positive validated OS package inventory and a known result class/type. Empty/missing package evidence is not checked-zero coverage. Each public CVE must match a package name/version in its result inventory. Unknown result types, conflicting OS result families, unknown severity-source strings and malformed package data fail the CVE check, not silently disappear. Non-CVE advisory identifiers are not promoted to CVEs and currently fail this strict CVE parser.

Positive Node package inventory yields `node: { outcome: 'checked' }`. Otherwise the public report says `node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_UNKNOWN' }`; it never claims `NODE_INVENTORY_ABSENT` without inspection. For EOL/unknown OS, Node remains unknown because its vulnerability coverage is not established. An explicitly emitted empty language result fails closed. No Java language DB is fetched; unsupported offline Java resolution can fail the check, not masquerade as coverage.

The bounded normalized CVE and SBOM ecosystem enum is:

```
apk deb rpm npm pypi gem gomod cargo maven composer nuget
```

Explicit Trivy result mappings include OS families above and `node-pkg/npm/yarn/pnpm`, `python-pkg/pip/pipenv/poetry/uv`, `gemspec/bundler`, `gobinary/gomod`, `rust-binary/cargo`, `jar/pom/gradle`, `composer`, and `dotnet-core/nuget`. Unknown mappings fail closed.

CycloneDX normalization reads actual `metadata.component.properties` identity evidence, OS components and library PURLs, not JSON CVE result shapes. It validates package name/version against the decoded PURL, OS namespace/distro and an allowed package architecture. `golang` PURLs normalize to `gomod`. Grouped Maven/npm/composer display identities are supported when they match PURL namespace/name. OS components need not precede libraries. Unknown component types/ecosystems, arbitrary qualifiers, mismatched versions/distro/config/diffIDs, unsafe names and incomplete inventory fail the SBOM check. Only normalized image, platform, OS and bounded component identities leave this boundary; scanner paths/properties/Env do not.

Public `severitySources` additionally admits `debian`, `pypi`, `pip`, `go-vulndb`, `rustsec`, `cargo`, `maven`, `nuget`, `composer`, and `php-security-advisories`, in addition to the previous source set and honest `unknown` for missing sources. Arbitrary present source strings and invalid vendor severity levels fail. Advisory-v1's independent schema is unchanged; sources outside that older schema remain `unknown` with invalid-metadata limitations rather than new unaudited advisory schema values.

## Persistence contract handoff to coordinator

The coordinator owns ledger/scans/UI changes. Worker report contracts strictly validate public receipts/version/metric limits, exact per-check envelopes, normalized public SBOM/Secrets/CVE fields and advisory budgets. Legacy envelope/limits remain unchanged. Persistence must still validate requested checks, target/job binding, original attempt/lease token, freshness and the full normalized data contract.

Required coordinator schema support:

1. CVE and SBOM ecosystems: the eleven-value enum above. Package name rules must admit bounded Go module paths, Maven `group:artifact`, Composer `vendor/package`, NuGet mixed-case names and existing scoped npm names. Public package versions additionally admit bounded epoch `!` and comma separators; the existing legacy parser version grammar remains unchanged.
2. Public CVE node reason `NODE_INVENTORY_UNKNOWN`; checked/unsupported OS envelopes otherwise retain their current shape. Legacy `NODE_INVENTORY_ABSENT` remains legacy-only.
3. Public receipt versions and expanded public metrics/resource bounds (do not weaken legacy limits globally).
4. Additional bounded `severitySources` listed above. Advisory-v1 source schema is not expanded by this worker change.
5. Generic public archive checkpoint/final storage, job/receipt target validation, config target admission and UI/read-model validation. The consumer continues passing the original job object and token to checkpoint/final calls.

Checkpoint callbacks remain synchronous. Their storage/contract errors propagate unchanged even if abort wins the runner race or a test runner swallows the exception. A cleanup/runner failure after a successful checkpoint is never converted into fabricated failures for completed siblings. Cancellation retains previously accepted checkpoint authority and never publishes late uncooperative final output. DB usability/freshness crossings alone map to `DB_UNAVAILABLE`; storage errors do not.

`image-config-runner.ts` was not edited. Generic config loader/admission behavior must be composed by the coordinator/OCI agent; the worker does not bypass that module's authorization checks. No ledger, scans, OCI, UI or deployment files were changed by this worker implementation.

## Validation boundaries

Targeted tests use synthetic receipts/config identities, fixture scanner JSON/CycloneDX, stubbed DB verification, temporary filesystem scratch, bounded subprocess harnesses and an in-memory ledger protocol spy. They exercise eleven ecosystems, OS families, PURL/source/identity negatives, independent partial results, strict metric envelopes, 64-layer inspection evidence, checkpoint/error propagation, original-token preservation, cancellation and stubbed resource rejection.

Commands:

```
pnpm exec tsc --noEmit
pnpm exec tsx --test src/worker/public-image-worker.test.ts src/worker/public-image-consumer.test.ts src/worker/public-image-runtime.test.ts src/worker/vuln-findings.test.ts src/worker/cyclonedx-components.test.ts src/worker/secret-findings.test.ts src/worker/archive-process.test.ts src/worker/archive-scratch.test.ts
```

Observed validation: all 46 targeted tests passed. Worker-only dependency-graph typechecking also passed using:

```
pnpm exec tsc --noEmit --target ES2022 --module NodeNext --moduleResolution NodeNext --strict --esModuleInterop --experimentalDecorators --emitDecoratorMetadata --skipLibCheck src/worker/*.ts
```

Full API typechecking passed earlier, but the last full run was blocked by a concurrently added out-of-scope error at `src/scans/public-image.service.test.ts:28`: the `Ready.anchor()` test helper conflicts with the base service's `anchor` property (TS2416). That file was left to its owner.

The initial selection above did not perform Docker, live Trivy image scans, registry requests, native SQLite runs, live DB or deployment qualification. The R1 follow-up below additionally exercises real disposable SQLite; it still makes no native-scanner/live qualification claim. Passing fixtures must not be presented as deployment qualification.

## R1 follow-up — accepted checkpoint preservation

Addresses P1/R1 in `docs/public-image-chain-review-20261018.md`: the old global abort rewrite could replace accepted audited Secrets with `SCAN_FAILED` in a normally returned final report, allowing final delivery to hide the accepted finding and revoke cancellation recovery.

The shared archive runner now records whether a synchronous checkpoint callback actually returned acceptance. If a later scratch audit, internal deadline, caller cancellation or other abort interrupts the attempt, it throws `Archive interrupted after accepted checkpoint` before the global rewrite and before returning any final report. This is intentionally propagation/recovery, not a synthetic partial finalization. The existing consumer's `checkpointCommitted` fence propagates the error without invoking `finishArchive` or fallback sibling failures. The original job, attempt/token, accepted checkpoint rows and recovery authority remain intact; owner cancellation can publish only the already accepted normalized subset. Without any accepted checkpoint, existing failed/timeout report behavior remains unchanged. Normal non-aborted completion and intentional DB-usability downgrades remain unchanged. The runner still waits for audits and performs cleanup in `finally`.

No later unverified bytes are upgraded to checked evidence. In particular, valid-looking SBOM bytes returned after an internal deadline or before a failing SBOM scratch audit never receive a checkpoint and never appear in cancellation recovery. If Secrets and SBOM each passed their own audit/checkpoint but only the final audit fails, recovery may publish both accepted snapshots; the failed final audit does not grant any additional coverage.

An optional `deadlineSignal` exists only in the internal third-argument lifecycle injection seam for deterministic regressions. It is combined with, rather than substituted for, the production 600-second deadline, so it can only tighten that bound. It is not an HTTP/job/environment or production options field.

### Coordinator / ledger-agent handoff

- Worker changes introduce no enum, receipt, metrics or stored envelope schema changes.
- Ledger finalization still needs its independent consistency invariant: final delivery must not silently contradict accepted checkpoint evidence or hide it by clearing token/delivery authority. Preserve intentional CVE DB-usability rules without treating them as permission to erase unrelated Secrets/SBOM findings. The ledger agent owns this guard; no ledger source was edited here.
- On this runner's interrupted-after-checkpoint path the consumer must propagate, not finalize normally. Recovery/cancel uses the existing owner/attempt/lease/receipt fences; no lease extension, replacement-claim inheritance or retry policy was added.
- The coordinator's fifth `runImageConfig(..., options.publicImagePolicy === true)` argument in `outbox-consumer.ts` and its updated trust source assertion were left untouched. Their file contents were not rewritten by this follow-up. R2/endpoint composition remains outside this worker fix.

### R1 regression evidence

New `public-image-checkpoint-recovery.test.ts` uses a real disposable file-backed `ScanLedger`, actual `consumeOne` and `scanPublicImageArchive`, and `publicLifecycle` for synthetic acquisition/scanner output and injected faults. All three scenarios start with one positive Secrets finding whose audit and real checkpoint transaction succeed:

1. The subsequent SBOM scratch audit throws; no SBOM checkpoint or future CVE scanner runs.
2. Both per-check checkpoints succeed, then only the final scratch audit throws.
3. An internal deadline expires during SBOM; an uncooperative fixture still returns valid-looking SBOM bytes, which must not be published.

Each scenario asserts consumer rejection, no normally returned final report, zero `finishArchive` calls, a still-running original claim, retained sanitized SQLite checkpoint rows, no delivered archive result, scratch cleanup, reopen plus owner cancellation, the accepted positive finding remaining visible, and no raw `Match`, source path or code canary in stored/published data. Only previously audited accepted snapshots are recovered. The existing real-ledger legacy cancellation test now explicitly expects late runner rejection after its accepted checkpoint while asserting that owner-visible cancelled evidence is unchanged.

Targeted command (from `server/api`):

```
pnpm exec tsx --test src/worker/public-image-checkpoint-recovery.test.ts src/worker/archive-scan-worker.test.ts src/worker/public-image-worker.test.ts src/worker/public-image-consumer.test.ts src/worker/archive-process.test.ts src/worker/archive-scratch.test.ts src/worker/vuln-db-trust-wiring.test.ts
```

Observed: **48 passed, 0 failed, 0 skipped**, including the coordinator's unchanged trust wiring/source assertion. Worker dependency-graph typecheck passed using the explicit `src/worker/*.ts` command above. The last full `pnpm exec tsc --noEmit` run encountered four concurrent out-of-scope errors in `src/scans/public-image-legacy.http.test.ts`: `configDigest` is inferred as `string` instead of a SHA-256 template type at line 32, and header union values are not assignable to `Record<string, string>` at lines 93, 97 and 105. That file was left to its owner.

No Docker, live Trivy/native scanner, registry traffic, live vulnerability DB or deployment execution was used for this follow-up. Real SQLite fixture integration is not a scanner or deployment qualification.
