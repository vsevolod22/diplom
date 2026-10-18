# TASK6 runtime author slice: operator and parent handoff

This is an implementation/runbook, not deployment acceptance. The feature delta `e831c1d0-a64f-49d7-95d8-8a448afc2a09` is **applied as DIP-DOC-13 v2**, per the parent/user's current status and `docs/testing-followup-20261016.md`; the former UNAPPLIED header was stale. There is no task-sourced TASK6 delta recorded by this continuation; parent owns spec/status reconciliation. DIP-TASK-5's external qualification is unchanged; host task 8 is deferred. See `docs/runtime-task6-continuation-20261016.md` for the new controlled integration results and remaining operator handoff.

## What is usable after explicit parent bootstrap

- Enrolled account → selected full container ID/context/version → separate <=300s consent/nonce/epoch → operator-signed **already sanitized** package → authenticated historical intake → atomic immutable owner report, finite event replay and dedicated UI history/detail.
- Optional owner-admitted image-job association: reuses the existing approved pinned-image loader and **the same verifier instance** for verify/read, checks exact config digest, child manifest and supported `linux/amd64` platform, then freezes independent image SBOM/CVE outcomes/provenance. The adapter converts only the ledger's exact UTC SQLite `YYYY-MM-DD HH:mm:ss` timestamp to canonical ISO UTC, retaining second precision as `.000Z`; canonical ISO inputs remain unchanged and malformed/ambiguous dates fail closed. It validates the complete association before returning it. It neither admits a new image job nor runs a scanner. No dummy image rows are created.
- A real code path for qualified Linux-local application capture exists, but is **not enabled or qualified by this author work**. Default production runtime DI has no live port. Ordinary broker `main.ts`/runner stays disabled. Imported `running: true` is the enrolled source's historical statement, never a live claim.
- Coverage is allowlisted configured metadata only. Exclusions are always `writable-layer`, `volume-contents`, `traffic`, `effective-isolation`, `exploitability`, `whole-host`. Configured non-root is not proof of effective UID or vulnerability-free isolation. Docker Desktop's Linux VM is not native macOS host coverage.

## Parent-owned bootstrap and ingress — current source, not deployment acceptance

1. Current `server/api/src/main.ts` already creates Nest with `bodyParser: false` and calls `configureParentIngress` from `parent-ingress.ts`. That function selects the default `RuntimeApiModule`, installs `createRuntimeIntake` with real `RuntimeIdentity` **before** ordinary JSON parsing, and marks raw intake configured. The continuation tests this actual path with temporary stores and loopback HTTP; it does not establish deployed activation. Cookie/Origin authentication happens before raw-body admission. Legacy unconfigured `runtimeIntake` deliberately returns503 for POST; parsed `@Body` is not a fallback. Preserve the existing per-route image/AI limits. `configureParentIngress(app, selectedRuntimeModule)` now accepts the exact dynamic descriptor used in the root module's `imports`; omit the second argument only for the default static module. It selects that module and resolves `RuntimeIdentity`/`RuntimeApiService` with `strict:true` before installing middleware. Missing/unregistered/rebuilt selections throw without fallback. Retain the same descriptor instead of invoking `withQualifiedCapture` again for ingress; do not import both variants in a deployment.
2. `app.module.ts` has only the additive `RuntimeApiModule` import. No `main.ts`, auth store, shared ledger/schema, OCI/verifier/worker/CVE or report/list/detail/scenes were edited by this author.
3. On the existing auth durable volume, explicitly authorize a **separate** runtime SQLite file in a canonical operator-owned 0700 directory, with file0600; no symlink/hardlink/path/inode alias to auth/image DB. Set only parent-approved `RUNTIME_DB_PATH` to that absolute file; preserve existing `AUTH_DB_PATH` and `SCAN_LEDGER_PATH`. Serving never initializes/migrates or falls back to memory. Absent/invalid/uninitialized/busy DB → runtime unavailable.
4. Current `server/deploy/stand.nginx.conf` already contains runtime-only route candidates, with `$runtime_ingress_enabled` set to **0**. Parent must review/authorize deployment activation separately; this continuation changes no nginx/Compose files or listeners on the live stand. Imports: complete JSON body <=65536 bytes (inclusive); controls: <=1024 bytes (inclusive), including whitespace/wrapper. Allow only required methods/path, preserve cookie and same-origin Origin, enforce finite request/connection/header/time/rate budgets. Do not route application IPC/Engine through nginx. Do not log request bodies, cookies, signatures, credentials or evidence. Do not globally enlarge other API route limits. No deployment/configuration/stand mutation was performed here.
5. Reads/history responses are bounded to <=65536 aggregate bytes, max20 reports/page. Runtime targets max100 per response; enrollment max1000 globally; captures max10000 globally/max1000 per owner, at most2 running; writes12/owner/min, consent max10000, image links max8/capture. These are fixed `runtime-host-policy-v1` limits, not UI-tunable values. Plan explicit retention/migration separately when caps are reached; never silently delete terminal history.

Raw intake has global active2/per-owner1/zero queue,5s absolute complete-body budget, fixed12 owner/min, a conservative process-global pre-auth60/min budget and bounded1024 rate keys. The nginx source separately defines60/IP/min and120/global/min budgets; those are not in-process guarantees or proof of deployed ingress activation. Missing/invalid cookies never reserve raw slots. Image linking performs owner/report/prior-link/full8 preflight BEFORE loader I/O; global active2/per-owner1/zero queue, exact inflight coalescing,12 owner writes/min and5s deadline. Abort/error releases only after actual loader settlement; an uncooperative loader retains its scarce slot rather than admitting unlimited underlying I/O. These budgets are not nginx replacements.

## Explicit store initialization and enrollment

Operator entrypoint (from `server/api`, using its installed `tsx`):

- `node --import tsx src/runtime/runtime-init.ts init <absolute-new-runtime.sqlite> --authorize-runtime-store`
- With API writer stopped: `node --import tsx src/runtime/runtime-init.ts enroll <absolute-runtime.sqlite> --authorize-runtime-store <absolute-owned-public-enrollment.json>`

Angle-bracket operands are documentation metavariables, not executed commands or provisioned paths. The author did not initialize/enroll a real stand or read any private key. Enrollment CLI file must be canonical owned file0600 under directory0700, <=65536 bytes. Public enrollment has these **exact** fields:

```text
subject          existing application account ID (not email or broker credential)
target           {targetId:32 lowercase hex, containerId:64 lowercase hex,
                  context:bounded slug, contextVersion:positive integer,
                  version:positive integer, importAllowed:boolean, liveAllowed:boolean}
signerId         32 lowercase hex, operator-selected enrolled signer identity
publicKey        canonical base64 DER Ed25519 SPKI, never a private key
fingerprint      lowercase SHA256 hex of those DER public-key bytes
sourceVersion    "operator-runtime-v1"
```

Account authentication alone creates no runtime access. There is no public enrollment/target discovery route. Re-enrollment requires an increasing target version and invalidates consent for that owner/target by the enrollment version. The durable epoch is a monotonic unique consent-version allocator, NOT global consent validity: another owner's enrollment/revoke/cancel never revokes unrelated authority. Real mutations receive owner rate admission; repeated revoke and terminal cancel are no-ops. A durable bijective `runtime_subjects` mapping assigns a separate internal broker subject; browser consent never exposes it. Before live deployment the operator supplies its exact mapping to the independently confined caller admission callback, not a permissive wildcard.

The DB owns an exclusive `<runtime.sqlite>.writer` lock, WAL and FULL synchronous mode. Graceful close releases the lock. After a crash, **operator must first establish that no writer remains**, then reconcile only that stale runtime lock. Serving never deletes someone else's lock or auto-adopts a replaced inode. On reopening, interrupted `running` reports become failed `INDETERMINATE` without recapture. Terminal capture/report/event commits are atomic; late/cancelled/stale authority/attempts cannot overwrite terminal evidence. Image associations are append-only first-success saga records; no distributed transaction with the image ledger and no retrospective CVE result rewrite.

## Historical package production, verification and transport

The browser exposes actual enrolled targets and an explicit selected-mode consent. The operator obtains subject, target/version, consentId, nonce, authority epoch and expiry from that authorized receipt. Operator collection is separately authorized. Do **not** send broad `docker inspect`, environment, labels, mount paths, network addresses or private keys to API/UI.

Operator signing utility (from `server/api`):

`node --import tsx src/runtime/runtime-sign.ts --authorize-runtime-sign <absolute-owned-sanitized-input.json> <absolute-owned-local-ed25519-pkcs8.pem>`

This command is documentation only; it was not run against an actual key. The utility does no Engine call, inventory, model call or networking. It consumes an already sanitized `inspect-snapshot-v1`, rejects raw/extra fields and invalid snapshot hashes, builds a separately versioned receipt, and writes only the signed package to stdout. Input/key paths must be canonical single-link owned file0600 under directory0700; key is never an API argument or environment variable. Key bytes are cleared after local parsing (no promise of erasing all Node/OpenSSL copies). Output can be pasted into the dedicated panel; protect operator outputs as evidence, not public telemetry. This utility is **not** a collector or qualification service.

Input has **exact** fields:

```text
snapshot             unchanged closed inspect-snapshot-v1, including canonical v1 hash
startedAt            canonical UTC millisecond ISO time, <=snapshot.observedAt,
                     interval <=5000ms; observedAt is receipt endedAt
running              boolean or "unknown", from the SAME observation/source
imageConfigDigest    null or "sha256:" plus 64 lowercase hex
imageSemantics       "unknown" iff digest null, else "docker-config-sha256-v1"
subject,targetId,targetVersion,consentId,nonce,authorityEpoch,signerId
                     exact current enrollment/consent binding
```

Claim image semantics only if that source independently supports Docker config-ID meaning. It is not an OCI manifest digest. Unknown semantics stays null; unsupported linkage does not become checked CVE/SBOM. The signing utility cannot prove supplied source facts or image semantics; enrolled operator trust has that responsibility.

Package has exactly `{payload,hash,signature}`:

- `payload`: `{schema:"runtime-import-v1",subject,targetId,targetVersion,consentId,nonce,signerId,sourceVersion:"operator-runtime-v1",capture}`.
- `capture`: `{schemaVersion:"runtime-capture-v1",snapshot,startedAt,endedAt,running,imageConfigDigest,imageSemantics,binding:{nonce,consentId,authorityEpoch},hash}`.
- Snapshot hash: SHA256 of canonical snapshot **without** hash, unchanged v1 rules.
- Capture hash: SHA256 UTF8 `runtime-capture-v1\n` + canonical capture **without** hash.
- Envelope hash: SHA256 UTF8 `runtime-import-v1\n` + canonical payload.
- Signature: Ed25519 over UTF8 `runtime-import-v1\n` + canonical payload; canonical unpadded base64url64-byte signature, length86.
- Canonical JSON sorts object keys recursively, preserves array order, uses JSON string encoding. Closed schemas prevent unknown keys; server raw parser rejects duplicate/prototype keys, invalid UTF8, unsafe/noninteger numeric lexemes including `1.0`/`1e0`, excessive depth/nodes/strings/members.
- NEW-work intake checks exact current subject, full target/context/version, source/signer trust, receipt binding/epoch/nonce and time. Inclusive freshness: <=300000ms old, <=30000ms future skew; consent itself must remain unexpired at commit. Signature proves enrolled provenance, not source completeness.
- HTTP body is `{idempotencyKey:32 lowercase hex,package:<signed-envelope>}`. Closed structure/capture/envelope hashes and owner-scoped immutable intent lookup precede NEW-work consent/trust/freshness/qualification. Exact same-owner replay returns the original receipt even after expiry/revoke/re-enrollment/restart/lost live qualification, without re-signing, new dispatch or nonce use. Different valid intent conflicts409. Nonce consumes in the same successful transaction. Cancel/revoke/restart fence late completions. Response acceptance202 is not completed evidence; read durable detail/status.
- Browser history/detail uses the shared lexical/UTF8 parser, enforces report/capture consent, coherent state/reason/mode/provenance/link relations, and recomputes canonical snapshot/capture SHA256 using WebCrypto before presentation. Selected detail refreshes with history; mounted/account/session/action/selection fences discard late responses. Archived consent/enrollment/source version and per-image reason/scanner/time stay distinct from current form authority.
- Dedicated browser transport preserves the **raw package text** (duplicate/numeric lexemes are not JSON.parse-normalized), bounds bytes and response buffers, uses same-origin cookie/no-store and account-generation fences. The panel remains separate from image parsers/reports and demo scenes.

## Dedicated browser routes

All under `/api/v1/browser/runtime`, cookie-authenticated; POST additionally requires allowed same-origin Origin and closed raw-body intake. No Bearer browser transport.

| Method | Suffix                                     | Body / response purpose                                                                        |
| ------ | ------------------------------------------ | ---------------------------------------------------------------------------------------------- |
| GET    | `/capabilities`                            | historical capability, conditional live, host not_authorized                                   |
| GET    | `/targets`                                 | owner-enrolled target IDs only; no Engine enumeration                                          |
| POST   | `/consents`                                | `{targetId,mode,confirmed:true}`; separate nonce/epoch/time receipt                            |
| POST   | `/consents/:id/revoke`                     | `{}`; `{revoked:true,changed:boolean}`; scoped durable consent fence and live invalidation ack |
| POST   | `/imports`                                 | `{idempotencyKey,package}`; historical receipt202                                              |
| POST   | `/captures`                                | `{idempotencyKey,consentId,targetId}`; conditionally qualified capture202                      |
| GET    | `/captures?cursor=...`                     | bounded strictly owner history, cursor is owner capture ID                                     |
| GET    | `/captures/:id` or `/captures/:id/results` | immutable owner report and append-only image links                                             |
| GET    | `/captures/:id/events`                     | **finite** durable SSE replay batch; Last-Event-ID supported, not persistent stream            |
| POST   | `/captures/:id/cancel`                     | `{}`; `{changed,cancelled,state}` actual transition; only running work is cancelled            |
| POST   | `/captures/:id/image-links`                | `{imageScanId}`; owner admitted chain, no image creation/scanning                              |

Foreign capture/detail/event/cursor IDs return404. UI refresh reads durable status; no fake process-local liveness or persistent event delivery promised.

## Conditional Linux-local live composition

**Do not enable this on macOS/ordinary Docker Desktop, shared public socket, remote Engine or unqualified fixture.** No Engine socket is mounted into API; only a private application job socket may be exposed to the Linux-local API/application composition.

Before launch, actual operator-controlled isolated Linux Engine API1.47 fixture/controller plus independent TASK5 source/topology/no-bypass and actual positive1/all-negative0 evidence are required per `server/broker/proof/EXTERNAL_FIXTURE.md`. Additionally qualify new runtime caller/application topology/protocol/hash manifest and all admitted subjects/targets. Candidate/mock tests, boolean echo, file modes or source hash echo are not independent acceptance.

- `launchEnrolledRuntime` is an **exported explicit operator composition**, not an env-enable/run-on-import launcher. Inputs: actual current reviewed qualification, boundary root and tap endpoint, application-only socket and fresh application bearer credential and a separate dispatch HMAC key, explicitly initialized independent private-caller journal path plus forbidden API/auth/image DB paths, explicit image config semantics, exact subject/full-target/broker-subject callback. No real credentials/init/enrollment are performed by this implementation.
- `acceptOperatorQualification` mints a private in-process permit only on actual Linux with current independently checked fixture/application/protocol record (<=300s), source/topology hashes, context/version and initial durable epoch. No HTTP JSON/cast can substitute for the permit. Review is rechecked for capability, dispatch and publication.
- Caller builds fresh exact-ID/context/subject/consent/version/time broker policy and one bounded allowlisted GET through existing `Broker`/`UnixEngine` boundaries. No exec/create/export, root mount, privileged DinD, seccomp exemption or proxy method/path/header facility.
- Independently call `initializeCallerJournal(newPath, forbiddenPaths)` only in an explicitly authorized operator bootstrap with serving stopped. The caller journal has its own application/schema ID, private0600/0700 path and exclusive writer lock, WAL/FULL durability, fixed10000 attempts/revocations and no silent pruning. It is NEVER the API runtime DB. After crash, operator reconciles only a proven stale caller lock; consumed/dispatched rows reopen as indeterminate and remain consumed, with no retry. `CallerJournal.consume` verifies whole-intent `runtime-dispatch-permit-v1` HMAC then atomically reserves exact owner/target/context/consent/nonce/epoch/capture-attempt before the sole Engine read; nonce/consent reuse or changed binding cannot grant another send. Scoped invalidation does not invalidate unrelated callers. Synthetic transport tests are not qualification.
- `UnixApplicationCaller` accepts only canonical owned directory0700/socket0600 and fixed `/runtime-job-v1` capture/invalidate requests <=1024 bytes. Capture wire includes the whole-intent permit; invalidation wire contains `{subject,consentId,epoch}`, never a global epoch advance. Definitive stopped/invalid/denied responses carry actual dispatched/aborted ack and fixed reason; missing ack remains INDETERMINATE. Sender uses `new UnixApplicationCaller(applicationSocket, applicationCredential, dispatchKey)`. App credential and separate dispatch key are distinct from Engine/broker credentials; it stays operator bootstrap-local, not env/browser/public API. Socket inode is pinned; uncertain timeout/disconnect disables admission pending operator reconciliation.
- `SerializedCaptureCoordinator` serializes acknowledgement admission/invalidation/final commit with max16 pending INCLUDING active, absolute5s queue-wait deadline, and zero later effects for expired queue entries. Saturation/uncertain invalidation disables live until operator reconciliation; scoped consent fences replace global cancellation epochs. IPC returns a bounded combined definitive dispatch ack and evidence, not a streaming ack. Absolute5s timeout/lost ack/abort/invalidation uncertainty disables the port (`INDETERMINATE`); no automatic retry. Revocation durably fences publication before waiting for live invalidation; old observations cannot commit afterward.
- API-side `createQualifiedRuntimePort` in `server/api/src/runtime/runtime-live-bootstrap.ts` composes `acceptOperatorQualification` → `UnixApplicationCaller` → `SerializedCaptureCoordinator`. It checks qualification before socket inspection, requires distinct application credential/dispatch key, and performs no Engine access, environment discovery, initialization or qualification fabrication. Parent can select `RuntimeApiModule.withQualifiedCapture(port)` with that genuine permitted coordinator instead of the default module, in the reviewed Linux-local bootstrap. Keep the returned dynamic module object in the reviewed root module's `imports` and pass that same object to `configureParentIngress(app, selectedRuntimeModule)` before init/listen. The parent ingress composition gap is fixed; ordinary `main.ts`/`AppModule` remain unchanged and use the default-off static module. Keep API's only external transport application IPC, never direct `EnrolledRuntimeCaller`/Engine construction. Bind actual context/source/topology/acceptance generation to qualification and reconcile the separate caller/API durable journals on restart before declaring live ready. Application source qualification must include the one-use journal/permit protocol, not just the v1 broker.

Caller-journal initialization now has a bounded-purpose CLI (from `server/api`):

```text
node --import tsx src/runtime/runtime-caller-init.ts init <absolute-new-caller.sqlite> --authorize-runtime-caller-journal <absolute-api-runtime.sqlite> <absolute-auth.sqlite> <absolute-image-ledger.sqlite>
```

Operands are documentation metavariables. All four paths must be canonical absolute and have existing canonical parent directories; an absent leaf is permitted, but missing parents, symlink components/leaves (including dangling symlinks) and non-regular existing members are refused, not silently resolved. Before any DB/lock create/open, the shared runtime/caller path guard compares each complete family: base, `-journal`, `-wal`, `-shm`, `.writer`. Exact member-name collisions in either direction and existing device/inode aliases, including between excluded families, are refused. Similar sibling names such as `caller.sqlite-wal.backup` are not suffix-family members. API/auth/image paths are explicit exclusions, not read as enrollment or key sources. Initialization requires the entire new family to be absent: pre-existing sidecars/locks are rejected without deletion or overwrite. Reopen retains legitimate private SQLite recovery files only when owned0600/single-link/regular/canonical and disjoint from all exclusions; an existing writer lock always requires separate operator reconciliation. Existing own directory0700/file0600 checks remain. This stricter shared guard also covers direct runtime/caller initialization and serving constructors, so a CLI bypass does not bypass exclusions. Relative protected paths or not-yet-provisioned protected parent directories now fail closed; supply explicit canonical paths/parents rather than relying on normalization. The CLI creates only the new caller journal, refuses overwrite, never reconciles a writer lock and outputs only a fixed success/failure token. It does not start any listener or qualify anything. Stop the relevant writer and obtain parent authorization before an actual operator initialization; test execution created only temporary journals.

No positive Linux application IPC/coordinator/launch/topology acceptance was run on this author's macOS machine. Host8 support, native macOS inventory, whole-OS CVE and writable-layer vulnerability detection are **not implemented or claimed**.
