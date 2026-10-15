# Independent OLD worker public-source binding, 2026-10-15

## Disposition

**VERIFIED SIX-MEMBER PUBLIC SOURCE-SLICE BINDING; NOT full OLD-worker recovery/startup approval.** Actual bytes match the authorized canonical receipt for original worker image `sha256:8748cbebba753603d79f320c2fb476c46ab676ce12e0aa08bee0021a3e14e57a`. The inspected ledger constructor has a concrete version13 boundary: version14 is unsupported. No actual DB version, current stand state, full import closure or runtime readiness was observed.

This report can supply exact source references to a separately reviewed recovery decision. It cannot replace unavailable DIP-ARTF-502 in full, assert unknown contents of that artifact, grant holder adoption/cleanup, lift HOLD, or authorize worker/API/web startup. Existing user consent permits ordinary queued scanner resumption in a separately approved operation; this review neither runs it nor treats ordinary queue writes as a no-write proof.

## Authorized receipt and byte verification

Read ONLY `/private/tmp/dip-old-public-storage-slice-20261012-frontier/worker-slice.json` and its six explicit public members, using bounded stdlib-only read scripts, nofollow directory/file FDs, regular/single-link/owner0600 member checks, owner0700 packet root, stable FD/path metadata, exact lengths and SHA-256. No directory enumeration, other retained root, member receipt, log, private P2/store/recovery/env file or source execution/import was used.

Receipt SHA-256: `2277f55863f9a8b98dcac5ca973e4209ac032f62cbd9dc0b58f8b9c0bba6dd38`.

Canonical receipt records roleworker, exact image above, acquisition container ID `1a41cc7c0b98b7a9f787a7d8ae600941deb04a74c40ab4d393318ad00e3b0503`, fixedIntakeCollectedtrue. It explicitly records startup/fullSourceClosure/semanticClosure/installedDependencies/storageCompatibility/provenanceIndependentlyEstablishedByReader allfalse. This acquisition container is not the original serving worker identity or recovery target.

Public reader source `server/deploy/trust/read_old_storage_sources.py:142–149` writes this schema. `extract_old_image_sources.py:695–713` defines member mapping: `/app/<suffix>` becomes `<packet>/worker/<suffix>`, with per-member exact byte/hash records. No receipt path can select arbitrary files here; the six paths were cross-checked against fixed WORKER_SOURCES/WORKER_METADATA before reading.

| Image path under `/app/server/api/` | Bytes | Verified SHA-256 |
| --- | ---: | --- |
| `src/worker/nginx-local-worker.main.ts` | 75 | `7c7461eba0026e1bde51cc44ef0d881d076c4fa48919629cd6720c3502e9c67e` |
| `src/worker/worker-runtime.ts` | 5311 | `79b5c7e9659a98203faef37b41a773746f202583ca0cb1ea0e2abfe508c8f61e` |
| `src/worker/outbox-consumer.ts` | 9014 | `98a1a46a02daad0df0a4234330efff12c57a584ea076392b4cf3be0e10dbcb51` |
| `src/ledger/ledger.ts` | 65517 | `9b0b3cce477da38aa91aeba2946a9b1ab334615f9b3f3a5d8273a45b36c14626` |
| `src/ledger/schema.ts` | 1394 | `9c3d13432ae04d6c3693ca46f774823f9acafad5ba04ba3321062d087d72e0bf` |
| `package.json` | 648 | `a1091e0a9ad0d65798134fa912e215ac0daa1f9ecc596af0778b048ee4a1dcec` |

The ledger digest independently agrees with hardcoded OLD ledger source pins in public `qualify_preservation_images.py:80` and controller `small_plan()` profile. Those are static pin agreements, not new execution or native proof. No additional hardcoded complete OLD-worker startup digest/closure was found in the searched public trust Python files.

The receipt/image relationship remains conditional on the previously accepted acquisition/provenance record and supplied502 summary. Hash consistency by itself does not prove image extraction or runtime loader resolution. This review did not independently re-establish acquisition provenance.

## Actual inspected startup and storage behavior

- `nginx-local-worker.main.ts:1–2` imports `runWorker` and calls `await runWorker("local")`. It does not select the proof branch. The package is ESM; declared better-sqlite3 is12.11.1 and drizzle-orm0.44.7; tsx^4.20.0/TypeScript~5.9.3 are declarations, not installed-version evidence. Package default start is API `tsx src/main.ts`, not proof of the actual worker Path/Args or `.js`→`.ts` loader binding.
- `worker-runtime.ts:42–53`: requires storage/cache variables; clears the local readiness marker; LOCAL requires ledger `/data/ledger.sqlite`, ready `/data/worker.ready`, cache `/tmp/trivy` and the fixed cgroup envelope. It calls `recoverArchiveScratch()` BEFORE ledger construction, then invokes `/usr/local/bin/trivy --version` with a5000ms bound and requires0.69.3. It reads the public signing key to construct optional vulnerability configuration. None of those actions was run by this reviewer.
- `ledger.ts:175–187`: `new Database(filename,{timeout:5000})` is ordinary RW and can create an absent database; it is NOT readonly/fileMustExist. It selects journal_modeWAL, foreign_keysON, busy_timeout5000, reads user_version, and rejects version>13 or<0. **WAL selection occurs before the version rejection**, so a rejected14 startup cannot be represented as a guaranteed no-write probe.
- `ledger.ts:187–361`: all schema initialization/migration/backfill branches are gated on version0 or version<2 through<13. At exact13 none of those DDL/row-copy/event-backfill branches execute. Nevertheless the constructor still enters BEGIN IMMEDIATE, checks foreign keys and commits, then restores foreign_keysON and constructs drizzle. This is no constructor DDL/backfill at13, not byte-identical/read-only startup or full schema validation. Earlier versions migrate, and zero can initialize tables. The schema.ts comment saysv11 but is stale relative to the actual constructor's13 ceiling; do not use that comment as a version predicate.
- At14 the OLD worker is source-incompatible; do not use an OLD-worker-profile confirmation or a generic migration13/14 admission predicate to claim otherwise. No actual original ledger version was read here. A phaseholder failure is not turned into an observed DB-version receipt.
- `worker-runtime.ts:57–77`: the heartbeat checks cgroups/gateway and writes/removes readiness files; when the gateway is ready the loop invokes `consumeOne` every bounded loop iteration. The direct inspected route does not instantiate auth/quota/history/provider components, and no history backfill is visible in these bodies. This is not a negative guarantee about unreviewed imported module bodies.
- `outbox-consumer.ts:30–155` and `ledger.ts:448–464`: queued/expired-running jobs can be claimed, lease/attempt/state/event rows changed, config loading and selected secret/SBOM/vulnerability/archive work invoked, and results/failures persisted. Ordinary resumption may restart an expired queued/running scan. This is expected application behavior, not a preservation diagnostic/proof execution or provider-readiness proof.
- `worker-runtime.ts:79–83`: normal SIGTERM/SIGINT aborts the loop, stops the heartbeat, clears ready markers, closes ledger and removes handlers. `ledger.close():975` closes the ordinary SQLite connection. Graceful cleanup is inside the loop's try/finally after ledger construction; an earlier constructor/startup exception is not covered by that loop finalizer. Constructor failure itself closes its DB in catch.
- `ledger.prune()` exists but is not called in the inspected runWorker/consumeOne bodies. No claim is made about callers outside the six-file slice.

## Minimal missing public proof / usable recovery condition

The verified constructor supports a **conditional storage-source statement only**: if the actual original ledger is still the correct natural version13 schema, the inspected constructor skips its DDL/backfill branches. This is insufficient by itself to approve whole-worker recovery or certify all state preserved. Exact14 rules out this OLD worker; unknown version must not be assumed13.

There are concrete unreviewed startup/import dependencies, not a request for an unbounded new campaign:

1. `/app/server/api/src/oci/bounded-image-archive.ts`: `recoverArchiveScratch()` is explicitly invoked before ledger open; its startup mutation/cleanup effects are outside this authorized six-member slice.
2. `/app/server/api/src/oci/nginx-local-policy.ts`: eagerly imported by runtime/ledger/consumer, and its top-level behavior and imported closure are not supplied here.
3. Eager scanner/config imports in outbox/ledger (for example `worker/image-config-runner.ts`, `oci/pinned-image-config.ts`, `worker/archive-result-contract.ts` and `image-config/report-contract.ts`) are not reviewed bytes here; no absence of import-time provider/history/state effects is established for them. Ordinary selected scanner work is consented, but that does not fill missing import-source evidence.
4. Actual serving worker launch/loader and installed-dependency binding are not in this receipt. Existing independent public evidence may satisfy these gaps; this report does not invent it or acquire more sources.

Therefore: **accept this exact six-member binding and conditional ledger13 constructor finding; do not relabel it a reconstructed full502 OLD-worker startup acceptance.** If recovery needs a full no-init/no-history/provider startup claim, the missing accepted public closure/effect/launch evidence must be supplied or the OLD worker stays excluded from that claim. This report does not independently approve partial API/web recovery either; that is a separate reviewed operation.

No Docker/copy/native/test/import/provider execution, stand query, private content read, recovery action or source/Git/tracker change was performed. Only this optional public review document was written.
