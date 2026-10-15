# DIP-TASK-6 rework author handoff

Run `d18c354c-0705-417b-990a-b4a273569e75`, exact author `0b98fe80-6030-4552-8c87-5b4b744fd1a3`, agent `runtime-host:author`. Actual completed lead `ab389091-35f3-4d09-980e-c98665b39343` → architect `941b9efa-118c-414a-9041-ded44e485598` → this author only. Inputs: deduplicated integrator DIP-ARTF-179 (169/171/175), concrete R1–R11 plan DIP-ARTF-181.

## Ready for new independent review, not accepted/deployed/live-qualified

TASK6 author rework is implemented and focused validation passes. TASK6 goes to testing90, NOT done. The full target remains DIP-DOC-13 / UNAPPLIED delta `e831c1d0-a64f-49d7-95d8-8a448afc2a09`, judged decision `0f73856a-098b-4e20-889a-5a5af03f1f0b`. Current project parallel/direct, approval=false, spec_first=false. No spec apply, task close, commit/deploy, stand provisioning, real enrollment/keys/provider/models, real Engine/Docker or host8 implementation. Actual three independent review IDs are obtained after author completion; this author does not claim them or integrator.

## R1–R11 implementation and evidence

| Rework | Change                                                                                                                                                                                                                                                             | Focused evidence                                                                                                                                                                                                 |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R1     | Per-consent unique authority version, owner/target enrollment isolation; real mutations pre-admitted, repeated revoked/terminal operations no remote/rate/version effects; cancel returns actual changed/cancelled/state; durable local fence survives IPC failure | Disposable actual store/service Alice/Bob + independent Alice consent, real first revoke/cancel, completed/failed/cancelled no-ops and lost invalidation                                                         |
| R2     | Strict closed/hash-validated owner immutable semantic replay BEFORE current NEW-work authority/trust/freshness/live availability                                                                                                                                   | Actual service expiry/revoke/enrollment-version replacement/restart, changed valid intent409/foreign denial; actual Nest HTTP expired replay; terminal live-intent replay with live unavailable and no recapture |
| R3     | Fixed stopped/invalid/definite-denial reasons persist; private IPC failed reply retains actual ack; only uncertainty becomes INDETERMINATE                                                                                                                         | Controlled actual service reasons; actual confined caller + fake transport stopped/one send; actual Unix fake-Engine invalid state has typed invalid reason and v1 is unchanged                                  |
| R4     | Finite FIFO16 including active, absolute5s wait; expired queued effects never execute; saturation/uncertainty disable qualified port                                                                                                                               | Independently tested queue17th denial/15 expirations/recovery and blocked ack→revoke→publication FIFO (not qualified coordinator acceptance)                                                                     |
| R5     | Owner/report/replay/full8 preflight before I/O; active2 global/1 owner/no queue, exact inflight coalescing and owner write rate;5s deadline; retain slot for unsettled uncooperative loader                                                                        | Counted controlled adapter aggregate/coalescing/replay/full8/foreign/error; actual5s timeout retains slot until loader settles; existing actual verifier/pinned byte-loader chain test                           |
| R6     | Parent injects RuntimeIdentity.resolve before scarce raw slots; unauthenticated partial requests allocate no slots; legacy hook503, never parsed Body fallback                                                                                                     | Local disposable HTTP no-cookie/invalid-cookie partial requests plus authenticated success; actual Nest authenticated raw1024/65536 and no-hook503 tests                                                         |
| R7     | Whole closed intent domain-separated HMAC permit; independently initialized private-caller SQLite atomically consumes exact attempt/consent/nonce before dispatch, records scoped revocations and restart uncertainty                                              | Durable journal mutation/replay/restart/nonce/attempt/revoked/noninterference tests; actual EnrolledRuntimeCaller with fake transport exact sequential replay yields zero extra sends                            |
| R8     | Shared browser-safe lexical parser; consent/state/reason/mode/source/link coherence and WebCrypto canonical snapshot/capture SHA256 before transport presentation                                                                                                  | One-fault consent/fact/hash/state/source/context/owner/lexeme negatives, actual transport duplicate response rejection and mounted valid hash/provenance rendering                                               |
| R9     | Selected detail refreshes alongside history; mounted/account/same-session-generation/action/view fences and resets; stale cancellation retired                                                                                                                     | Actual React/jsdom running→failed refresh, cancelled terminal refresh, target reset/current-form consent vs archive, late response after account/session transition and unmount                                  |
| R10    | Source replaces toReversed/findLastIndex; removes ES2023 scoped library masking                                                                                                                                                                                    | NORMAL API no-emit tsc, inherited backend scoped tsc and scoped UI tsc all pass; no ignores/exclusions/API tsconfig change                                                                                       |
| R11    | Archived consent/enrollment/sourceVersion distinct from current consent; SBOM/CVE independent reason/scannerVersion/checkedAt/unavailable/partial image-only fields visible                                                                                        | Actual mounted archived vs new-form consent, checked SBOM and failed CVE fields; exclusions and historical/live distinction retained                                                                             |

## Owned snapshot

`owned-files.sha256` updates the original33-file manifest. It honestly contains **40 files = original33 +7 additions**, excluding the manifest itself:

- `server/broker/src/audit.ts` (explicitly authorized source compatibility fix).
- `server/api/src/runtime/runtime-caller-journal.ts`.
- `server/api/src/runtime/runtime.rework.test.ts`.
- `server/api/src/runtime/runtime-boundaries.rework.test.ts`.
- `server/runtime/src/dispatch-permit.ts`.
- `server/runtime/src/runtime-json.ts` (shared pure parser, API old entrypoint re-exports).
- `server/runtime/tests/runtime-ui.rework.test.tsx`.

Existing app.module/page seams are retained, not expanded in rework. Owned runtime/API/new broker modules and dedicated panel/transport only; normal broker v1 preserved. `main.ts` is exclusively parent-owned and was NOT edited. No auth, shared ledger/schema, OCI/verifier/worker/CVE/AI/report/list/detail/scenes/CSS/ScanSummaryPanel/LiveScanSession/shared image transport edits. Concurrent peer work must not be attributed to this author. HEAD remains `741e4aaf4b6c41dd176ddfe6ff175781958f8f73`; uncommitted worktree. Manifest SHA256/artifact IDs are given in Flownix handoff; hashes identify review inputs, not signed deployment proof.

## Executed final focused validation

From `server/api`:

```sh
node --import tsx --test src/runtime/runtime.test.ts src/runtime/runtime.integration.test.ts src/runtime/runtime-image.test.ts src/runtime/runtime-broker.test.ts src/runtime/runtime-transport.test.ts src/runtime/runtime.rework.test.ts src/runtime/runtime-boundaries.rework.test.ts
node node_modules/typescript/bin/tsc -p tsconfig.json --noEmit --incremental false
```

Final **24/24 backend/transport tests pass**,0 failed/skipped; includes the original13 plus11 dedup regression tests. Duration5948ms. Normal API typecheck passes without an override.

From repository root:

```sh
node --import ./server/api/node_modules/tsx/dist/loader.mjs --test server/runtime/tests/runtime-ui.rework.test.tsx
node server/api/node_modules/typescript/bin/tsc -p server/runtime/tsconfig.json --noEmit
node node_modules/typescript/bin/tsc -p server/runtime/tsconfig.ui.json --noEmit
```

**1/1 actual mounted React/jsdom test passes**,0 failed/skipped; backend/UI scoped typechecks pass. Owned source Prettier and scoped tracked diff check pass. This is **25 focused tests total**, NOT the broad suite/old62, real browser E2E, real Engine/Linux qualification or deployment acceptance. Initial new service regressions failed3/3 before implementation, then passed; disposable fixture socket-length/exact-fence/explicit localhost-origin setup were corrected, not production guards loosened. Synthetic ephemeral test Ed25519/HMAC material and owned disposable test DBs only; no actual private environment/trust/key reads or mutations.

## Parent bootstrap contracts still required (not performed)

1. Parent-exclusive `main.ts`: Nest `bodyParser:false`; install `createRuntimeIntake(req => app.get(RuntimeIdentity).resolve(req,true))` BEFORE existing JSON body parser. The old unconfigured `runtimeIntake` is intentionally503. Keep existing image/AI1KiB policy. This is an exported authenticated factory, not a parent main edit.
2. Explicitly initialize/enroll separate runtime SQLite on canonical0700 auth durable volume/file0600, nonalias to auth/image DB. Parent-approved `RUNTIME_DB_PATH`; public owner/full-ID/context/version/signer trust; exclusive writer/stale-lock reconciliation. No real init/enrollment/env changes occurred.
3. Bounded nginx runtime namespace: import65536/control1024 inclusive, required cookie/Origin, finite header/body/time/rate budgets and no body/credential/evidence logging. No IPC/Engine socket ingress and no generic proxy. No nginx/deploy edits occurred.
4. Conditional live only AFTER real TASK5 isolated operator-owned Linux Engine API1.47 fixture/controller/source/topology/no-bypass positive1/all-negative0 evidence PLUS independent NEW application/permit/journal/protocol/topology/source acceptance. Explicit independent caller journal init on its PRIVATE volume (not API DB), separate dispatch key/application bearer, exact subject/target mapping, current real qualification, and caller/API restart reconciliation. No normal-broker or default-runtime live enablement. Private launch inputs and source-qualified dependency closure are documented in operator-runbook; no actual launch performed.

TASK5 remains blocked75 for those precise qualifications, NOT generic Docker availability. Its missing live fixture does not block these historical repairs or permanently block separately authorized host8. Host8 proceeds only after TASK6 review and separate work, not in this author turn. Native macOS host != Desktop Linux VM. Config ID != manifest digest; image SBOM/CVE association is image-package-only, never writable layer/volume/traffic/full OS or whole-host assurance. Unsupported/failed checks are not zero findings. Signed historical packages are enrolled provenance, not live proof or collector completeness.
