# Isolated public stand: acknowledged replacement recovery — 2026-10-18

## CURRENT: phase-24 backup-copy HOLD — bounded private export, new review required

**Do not rerun any earlier recovery/continuation or remove locks.** The operator's phase-12 continuation completed trusted drain and clean worker shutdown, created the validated backup helper and reached **`backup-copy`, reason `DOCKER_UNCLASSIFIED`**. The new source implements an exact phase-24 continuation with a different transport; it is not a force-unlock or replay of drain/shutdown.

### Actual read-only diagnosis

Own audit `redeploy-a38c3a387e22331d69e7d9746baf7f27` retained these later phases:

| Phase | Boundary | Time, UTC |
| --- | --- | --- |
| 013 | continue-started-drain-authorized | 13:15:01.372 |
| 014 | retire-started-drain-remove | 13:15:01.459 |
| 015 | drain-helper-submission | 13:15:02.037 |
| 016 | drain-helper-start | 13:15:02.451 |
| 017 | drain | 13:15:02.868 |
| 018 | drain-helper-stop | 13:15:03.931 |
| 019 | drain-helper-remove | 13:15:04.172 |
| 020 | stop-worker | 13:15:04.939 |
| 021 | writers-quiescent | 13:15:06.585 |
| 022 | backup-helper-submission | 13:15:06.950 |
| 023 | backup-helper-start | 13:15:07.206 |
| 024 | backup-copy | 13:15:10.204 |

The exact backup helper is `dip-public-images-recovery-a38c3a387e22331d69e7d9746baf7f27-backup`, ID `9838391978d1b3fde20f5e850417aa0d3edaba31fd5eaff8446e45f0b78b6128`, using the validated candidate API image. At first inspection it was running, PID 96287, restart count 0, and passed all helper controls. Web/API/worker are **exited 0**, PID 0, original identities retained; worker finished `2026-10-18T13:15:05.615968543Z`. Gateway remains its original running process. Both initializers remain exited 0. Host `backups/` is **empty**; there is no durable original backup receipt, copied DB, pin commit or recreation record.

The previous transport was Docker archive `cp` from `/backup`, which is a private tmpfs. A bounded **read-only archive probe of only `/backup/ready.json`** returned file-not-found while this validated helper was running; no tar contents, DB bytes or raw stderr were printed, and no host file was created. The immutable helper program creates `ready.json` only after successful snapshots, and phase 024 follows the successful ready response. This corroborates this engine's archive view not exposing the running tmpfs. The original sanitized failure does not retain its exact daemon stderr, so this note does not pretend that text was recovered. No original database-copy command was retried.

The old reviewed program exits 300 seconds after ready. By the later checker it had **exited cleanly on that timer**. Its lost tmpfs bytes and in-memory-only ready response cannot retroactively be made durable. Original records are preserved rather than rewritten as verified backup evidence.

### Correct transport and snapshot lifetime

- No Docker `cp` in the deployment path. Use a fixed standard-library Node reader only inside the exact freshly validated backup-image helper: fixed `auth`/`ledger` paths, readonly opens with NOFOLLOW/NONBLOCK, regular single-link owned files, bounded sizes and lossless BigInt file identities. Caller-supplied arbitrary paths/roles/offsets refuse.
- Durably record `backup-export-manifest.json` **before transport**: backup API integrity/logical/file SHA-256 receipts, private snapshot file identities and main/optional-WAL source-family identities/content hashes. No SHM is copied; rollback journals refuse. The reader supports an existing empty WAL without treating it as snapshot data loss.
- Read at most **1 MiB per exec** as strict canonical base64 frames. The launcher captures the child output internally; it never logs bytes/base64 or puts DB contents in argv/Env. Validate role, offset, encoded/decoded length, exact key set and file identity on every read. Sequential bounded host writes compute the full expected file SHA-256.
- Create each private `.auth.sqlite.exporting` / `.ledger.sqlite.exporting` exclusively at 0600. Verify owner/mode/inode/directory identity and full hash; fsync, then atomically publish through a no-overwrite hard link and remove only that operation's temporary name. Existing final/partial files are never overwritten or erased to retry. Verify final standalone files again and re-read the manifest to fence source/snapshot identities/content across export before committing pins or deploying anything.
- New backup helpers keep the initial **120-second generation watchdog**, then fsync ready metadata, clear that watchdog and hold completed snapshots until explicit stop/cleanup. The same 1 GiB/no-swap, CPU/PID limits, 512 MiB private tmpfs, RO/nocopy source volumes, UID 65532, no network/socket and no restart policy remain. Holding snapshots is intentional review-HOLD behavior, not a DB writer or infinite launcher command. RAM snapshots still do not survive container/daemon/host loss; host manifests and completed fsynced files are the durable evidence.
- `LEGACY_RECOVERY_BACKUP` remains accepted only for this exact phase-24 admission. Normal creation requires the new held-snapshot program; there is no arbitrary helper-program allowance.

### Exact continuation and honest regeneration gate

After independent re-review, from `diplom`:

```sh
node scripts/public-image-stand.mjs continue-recover-backup-copy --ack-quiescent-backup-transfer --audit redeploy-a38c3a387e22331d69e7d9746baf7f27 --helper-id 9838391978d1b3fde20f5e850417aa0d3edaba31fd5eaff8446e45f0b78b6128
```

The acknowledgement attests the previous command returned, daemon work settled and no external launcher/tagger/lifecycle/storage operation is outstanding. It explicitly accepts **verified quiescent-source regeneration when the legacy tmpfs has expired**, not a claim that unavailable old snapshot bytes/hashes were preserved.

Admission is exact: phases 001–024, all preceding original/resume/created/started receipts and lock identities, helper/drain-next/backup records, exact `started-failure.json` at backup-copy with DOCKER_UNCLASSIFIED, empty host backups and no later/transfer/unknown record. Require original profile/JWT/pins/source/public CVE/build-input identities, exact namespace/consumer sets, unchanged gateway process and cleanly stopped original web/API/worker with phase-consistent exit times. Require the specified backup ID, validated fresh candidate API image, exact legacy program/authority and original no-restart epoch. Only still-running legacy state or clean zero exit 295–330 seconds after phase 024 is admitted. No killed/OOM/restarted helper or unknown failure is adopted.

Read-only checker (executed successfully with this source; no exec/DB open/lifecycle/state write):

```sh
node scripts/public-image-stand.mjs check-recover-backup-copy --audit redeploy-a38c3a387e22331d69e7d9746baf7f27 --helper-id 9838391978d1b3fde20f5e850417aa0d3edaba31fd5eaff8446e45f0b78b6128
# READ_ONLY_BACKUP_COPY_PROOF_PASS; helper-state=exited;
# plan=RENEW_LEGACY_WITH_HELD_SNAPSHOTS; no lifecycle/exec/build/state write;
# helper authority/candidate profile/remaining engine-shape models validated;
# future native execution NOT proven; independent review required.
```

The mutation command exclusively creates `backup-transfer.lock` under the existing guard, fsyncs its receipt and appends `backup-transfer.json`, its baseline and authorization phase in the **same audit**. Every previous phase/failure/receipt/control file retains its bytes and inode. No old helper start, drain, web/API/worker stop, build/pull, initializer rerun, source DB migration/reset or old application exec is repeated.

If the legacy helper is still running, capture and durably bind its existing ready receipt, snapshot hashes and source-family fences first. Retire only that exact RO helper by controlled stop (if needed)/remove without volumes. Create distinct `...-backup-export` from the same immutable candidate API ID, stopped → inspect all controls/volume sources → record → start its **new ID** → bind epoch. Generate verified backup API snapshots from the same quiescent sources. When the old manifest was captured, require **exact old/new file and logical receipts plus source identities/hashes** before transfer. Native tests confirm deterministic standalone bytes for repeated backup API generations on the same unchanged sources.

When already clean-expired, record `LEGACY_TMPFS_EXPIRED_NO_DURABLE_SNAPSHOT_RECEIPT` and generate **new verified snapshots** from the retained quiescent sources. There is no original DB-byte snapshot or old source hash to certify retrospectively: the preservation evidence is exact retained volume/writer identities, clean shutdown/drain history, no other consumers/operations, fresh source-family hash fences, verified new backups and post-recreation logical comparison. This limitation is explicit; the launcher does not mark the old copy attempt PASS.

After bounded private export and final source/hash checks, continue only the existing immutable pin commit/recreation/data/readiness/public-HTTP/archival tail. Hold snapshots until verified transfer and explicit helper cleanup. Any accepted failure creates only `backup-transfer-failure.json`, retains all old failures/locks plus partial export evidence and blocks replay/earlier commands. Success archives the added lock and validates transport/generation evidence in completed history. The original stand/8080 is neither inspected nor controlled.

Review inputs: fixed-path bounded exec protocol and no-output handling; fsync/no-overwrite/private partial evidence; BigInt source/snapshot identity fences; exact phase-24 admission/one-shot history; legacy-only program admission; explicit live-manifest matching versus unavailable-snapshot regeneration; held snapshot lifetime; no repeated drain/shutdown/build/pull; unchanged RR1/RDEP-1/2/3/security/resource/JWT/CVE guards. **No lifecycle/recovery/exec/continuation was executed by this author. No native Docker/browser deployment success is claimed.**

## Historical phase-12 started drain helper (already attempted)

**Do not retry the created-drain continuation, pre-lifecycle resume, initial recovery, or remove locks.** The operator's actual phase-10 continuation submitted the single helper start and then failed at **`drain-helper-start`, reason `HELPER_CONTROL_IDENTITY`**. This section supersedes the historical commands below. The new explicit phase-12 continuation is implemented and requires independent re-review before use.

### Read-only diagnosis and current state

Exact helper ID remains `ebd3e74260e08595f44ff5e94b202650c25094c7dfcc8c4ebd556b9455b3c180` in audit `redeploy-a38c3a387e22331d69e7d9746baf7f27`. At first inspection it was **running**, PID 85214, restart count 0, started `2026-10-18T12:44:56.119626553Z`. All independent helper sandbox controls passed. Reconstructing the saved created digest by changing exactly one current field reproduced it:

| Field | Created value | Running value | Meaning |
| --- | --- | --- | --- |
| `HostConfig.OomKillDisable` | `false` | `null` | OOM killer remains enabled; both were already allowed by policy |

The failure was a **raw Config/HostConfig equality error**, not newly unsafe controls. `true` is still rejected. Existing phase/failure records remain unchanged:

```text
001–010: previous build → image validation → resume → web/API stop → helper create
011 continue-created-drain-authorized  2026-10-18T12:44:55.866Z
012 drain-helper-start                2026-10-18T12:44:56.002Z
continue-failure.json: checkpoint=drain-helper-start, reason=HELPER_CONTROL_IDENTITY
```

No `drain`/backup/recreation phase followed. Web/API remain cleanly stopped and identity-fenced; worker/gateway remain their original running processes; initializers are retained/exited. By the later read-only check the helper had **exited 0 after its existing six-minute timer**, with the same start epoch and no restarts/OOM. This is not permission to restart its ID. Backups are still empty.

### Consolidated identity: authority, defaults, process epoch

Every observation first passes `validateBackupHelper` against the independent fixed sandbox. New helper identity uses `HELPER_AUTHORITY_V3`:

- Hash validated configured authority, not the whole Docker inspection envelope. Keep image, command/executable/args, user/directory, exact base Env, labels, readonly/nocopy mounts, resources, capabilities, network/restart isolation, kernel paths, log configuration and remaining Config metadata.
- Normalize only already-allowed equivalent defaults: OOM `false/null`; swappiness `null/-1` (unset); the two no-new-privileges spellings; no capabilities/ports expressed as empty/null; readonly/nocopy mount `DriverConfig` absent versus exactly `{}`; ordering of validated declaration targets/tmpfs options; empty forbidden startup metadata; inert validated Linux Node `ArgsEscaped` metadata. This does **not** accept `OomKillDisable:true`, custom swappiness, custom drivers, copy-up, extra Env, shell/hook/stop-signal overrides, missing resource bounds, writable sources or additional namespaces/devices.
- Unknown **nonneutral HostConfig fields still refuse on every inspection**. Unknown neutral HostConfig fields are not authority or identity evidence. Other Config fields are retained in identity, not globally discarded. Declared mount source/RO/NoCopy semantics remain authoritative; observed volume source/driver/access and allowed tmpfs observations are independently validated against the retained volumes/profile.
- Track ID/creation and the **process start timestamp, PID and restart count separately**. Bind the running epoch after the single start; refuse subsequent epoch/PID/restart drift. After intentional stop, require the same start epoch and restart count with exited PID 0. Volatile State/network runtime observations do not masquerade as configured authority.
- For this historical V2 helper, reconstruct the original raw created digest by changing **only `OomKillDisable` between false and null**. Every other historical Config/HostConfig field must still match. There is no broad legacy normalization or acceptance of missing old image metadata as image proof.

This is helper-specific consolidation, not a wider global container/image/default-stand policy. The ordinary launcher and original `dip-local-full` remain outside this recovery.

### Remaining path checked without lifecycle

The read-only checker validates the exact current helper/epoch, all original runtime/volume/network/storage consumers, source/profile/JWT/CVE identities, completed candidate tags/IDs/metadata and rendered candidate configuration. It additionally runs **pure configuration models** derived from inspected Engine 28 shapes plus the independent policy and validated images for all four fresh candidate services and the readonly/nocopy backup helper's created/running forms. These models test configured defaults/resources/Env/mounts/security and default-equivalent authority projections; they do not create a container, open SQLite, execute Node in Docker or prove future native health/backup execution.

Executed current-stage check:

```sh
node scripts/public-image-stand.mjs check-recover-started-drain --audit redeploy-a38c3a387e22331d69e7d9746baf7f27 --helper-id ebd3e74260e08595f44ff5e94b202650c25094c7dfcc8c4ebd556b9455b3c180
# READ_ONLY_STARTED_DRAIN_PROOF_PASS; helper-state=exited;
# plan=RETIRE_OLD_CREATE_FRESH_RO_PROBE; no lifecycle/exec/build/state write;
# helper authority/candidate profile/remaining engine-shape models validated;
# future native execution NOT proven; independent review required.
```

### Historical phase-12 command — ALREADY ATTEMPTED; DO NOT REPEAT

```sh
node scripts/public-image-stand.mjs continue-recover-started-drain --ack-started-drain-only --audit redeploy-a38c3a387e22331d69e7d9746baf7f27 --helper-id ebd3e74260e08595f44ff5e94b202650c25094c7dfcc8c4ebd556b9455b3c180
```

Admission requires exactly phases 001–012, validated original/resume/created-continuation receipts, the original helper-control record and exact recorded `HELPER_CONTROL_IDENTITY` failure; no drain/later phases, backup bytes or started-continuation record. Require the same original state-file/marker/input/pin identities, complete other histories, exact own census/consumers, unchanged cleanly stopped web/API, original worker/gateway epochs and all prior security/resource/CVE fences. Require the specified helper ID/image/creation/config; restart count 0; start time between phase 012 and the recorded failure. A running helper must have its exact original epoch. An exited helper is admitted only with exit 0, no OOM/error, and a verified 355–390-second timer interval already elapsed on the host—not an early exit, kill, restart or arbitrary exited container.

The distinct acknowledgement attests the previous client returned, work settled, no concurrent launcher/tagger/storage/lifecycle operation exists, and the reviewed expired-probe renewal below is understood. It does not repeat the pre-lifecycle/created acknowledgement or certify rollback to missing prior images.

Exclusively create `started-drain.lock` inside the existing recovery guard, fsync its receipt, append `started-drain.json`, `started-drain-baseline.json` and `continue-started-drain-authorized` in the **same audit**. Bind every original file's bytes/inode, exact helper ID/image/authority/process epoch and state identity; preserve all previous failures and locks. Partial receipt/lock or any later uncertainty is sticky HOLD, not replayable. An accepted failure adds only a new sanitized `started-failure.json`, never rewriting `continue-failure.json`.

**No start is ever reissued for the old ID.** If still running with sufficient lifetime (at most 30 seconds old), use that exact running helper. Otherwise, after the new receipt is durable, revalidate it, stop only that RO helper if still running, verify its clean exit/unchanged authority/epoch, record retirement and remove only its exact container ID **without volume deletion**. Then create the distinct `...-drain-next` helper from the same validated candidate API ID, with the identical reviewed sandbox. Create stopped → inspect exact controls/volume source → record → start its **new** ID once → bind/revalidate its process epoch. A naturally expired helper is not restarted or assumed useful just because its configuration is safe.

The remaining trusted drain → probe removal → clean worker shutdown → no-writers gate → fresh backup helper → verified staged main+WAL snapshots/0600 backups → immutable recreation → logical retained-data checks → readiness/public HTTP → archival transaction is unchanged. No repeated web/API stop, build/pull, initializer rerun, database migration/reset or original-application exec. Success archives all previous locks plus `started-drain.lock`; complete history validates original failure/created receipt/helper record and any distinct replacement probe. Failed retirement/start/backup/recreation/archive preserves all uncertainty evidence and blocks every earlier continuation.

Review inputs: `helperAuthorityProjection`, strict per-observation validation and process epoch fencing; V2 one-field reconstruction; exact phase-12 evidence/one-shot history; explicit timer-expiry retirement and distinct replacement ID; current-engine service/backup models; RR1/RDEP-1/2/3 preservation. New fixtures first reproduced the exact false→null failure, then cover engine-observed shapes across created/running/exited, unsafe authority rejection, raw legacy mismatch rejection, epochs/collisions, 20 admission refusals, timer renewal, uncertainty/archive boundaries and completed-history tampering. **No lifecycle/recovery/exec/continuation was performed by this author. No independent review or native/browser success is self-declared.**

## Historical retained stage: created drain helper (already attempted)

The reviewed pre-lifecycle resume was actually attempted by the operator and stopped at **`drain-helper-submission`**, not at image validation. **Do not repeat the initial replacement or pre-lifecycle resume commands. No manual lock removal is authorized.** The new source below implements a separate one-shot continuation of this exact stage; it is not a generic restart or another pre-lifecycle acknowledgement.

Authorized read-only inspection found the following exact retained chain (UTC):

| Phase | Recorded boundary | Time |
| --- | --- | --- |
| 001 | build-submission | 12:00:53.553 |
| 002 | build-egress | 12:00:53.559 |
| 003 | build-worker | 12:00:55.918 |
| 004 | build-api | 12:00:58.598 |
| 005 | build-web | 12:00:59.352 |
| 006 | new-image-validation | 12:01:26.721 |
| 007 | resume-authorized | 12:18:45.124 |
| 008 | stop-web | 12:18:45.473 |
| 009 | stop-api | 12:18:47.503 |
| 010 | drain-helper-submission | 12:18:48.949 |

Actual retained runtime, without starting/stopping/exec:

- Original web: **exited 0**, PID 0; finished `2026-10-18T12:18:46.373140548Z`.
- Original API: **exited 0**, PID 0; finished `2026-10-18T12:18:47.871633382Z`.
- Original worker and gateway: **running**, original process/container/image identities retained, restart counts 0.
- Both original volume initializers: exited 0; not rerun.
- Drain helper `dip-public-images-recovery-a38c3a387e22331d69e7d9746baf7f27-drain`: exact ID `ebd3e74260e08595f44ff5e94b202650c25094c7dfcc8c4ebd556b9455b3c180`, **created**, PID 0, never-started timestamps, restart count 0; fresh validated API image.
- No helper-start/drain/backup/recreation phase or helper-control record exists. `backups/` is empty. The original failure still says `new-image-validation`: that first failure was deliberately never rewritten; the newer retained boundary is phase 010 plus the operator's returned error and the inspected never-started state.

### Actual guard mismatch and narrow normalization

The helper's declared readonly/nocopy ledger volume is:

```json
{"Type":"volume","Source":"dip-public-images_scan_ledger","Target":"/data","ReadOnly":true,"VolumeOptions":{"NoCopy":true,"DriverConfig":{}}}
```

Docker Engine adds the **empty** `DriverConfig: {}` metadata on create. The preceding validator required exact `{NoCopy:true}`, causing refusal before helper start. No image Env/entrypoint/resource policy needed widening. The new helper policy accepts only absent `DriverConfig` or exactly `{}`; null, arrays, custom Name/Options, unknown option keys and `NoCopy:false` still refuse. Both helper purposes retain create → inspect → exact-ID start. Observed helper volume source/driver is additionally bound to the inspected retained volume mountpoint.

Two regressions were executed against the preceding source and **failed**: the real empty-DriverConfig helper metadata and the missing same-audit created-drain continuation. They pass with the fix. The fixture models a truly never-started helper and records zero initial start submissions rather than pretending the previous attempt completed.

### Read-only current-stage check

This command was executed successfully against the retained **own** audit/resources with the new source; it performs no create/start/stop/exec/copy/build/pull, database open, state/lock write or replay:

```sh
node scripts/public-image-stand.mjs check-recover-created-drain --audit redeploy-a38c3a387e22331d69e7d9746baf7f27 --helper-id ebd3e74260e08595f44ff5e94b202650c25094c7dfcc8c4ebd556b9455b3c180
# READ_ONLY_CREATED_DRAIN_PROOF_PASS; no lifecycle/exec/build/state write;
# exact helper remains created; independent review required before continuation.
```

The command's internal Docker allowlist rejects anything except container/volume/network/image `ls`/`inspect` and fixed Compose `config`. All engine calls use the original literal local Unix endpoint. It reads only own JWT internally to compare the immutable retained API Env; neither JWT nor a hash of raw JWT/Env is output or saved. Public pinned CVE files and public trust key only; no private signing keys or old project/state inspected. A successful check proves **current admission controls**, not future helper execution, job drain, backups or deployment/native-browser success.

### Historical phase-10 command — ALREADY ATTEMPTED; DO NOT REPEAT

```sh
node scripts/public-image-stand.mjs continue-recover-created-drain --ack-created-drain-only --audit redeploy-a38c3a387e22331d69e7d9746baf7f27 --helper-id ebd3e74260e08595f44ff5e94b202650c25094c7dfcc8c4ebd556b9455b3c180
```

The distinct acknowledgement attests the previous client returned, daemon work settled, and no other launcher/tagger/lifecycle/storage operation is outstanding. The helper ID is the explicitly inspected target; the previous validator failed before recording its returned ID, so this does not fabricate an earlier durable helper-ID receipt. It establishes the exact current ID through census/inspect and durably binds it before the first start.

Required gates and behavior:

1. Exactly phase 001–010 above, original canonical build-HOLD `mutation.json` alone, prior pins/candidate/baselines, original failure, existing resume receipt and `resume.lock/receipt.json`. All hashes/inodes and state directory/profile/JWT/pins identities captured in the prior resume receipt must still match. Empty backups; no helper-control/start/later phase, continuation lock/receipt, unknown file, incomplete archive or competing recovery. Other history must already be complete. No new audit is created.
2. Exact name/project-label census **before inspection**, allowing only the six original applications/initializers plus this one deterministic helper. No foreign consumers or misleading project-label resources. Exclude only this exact validated helper from ledger consumer census; it has no auth mount. Original six runtime configs, immutable prior pins, process starts/restarts, volume/network identity/membership and public CVE/profile/source/build-input fences remain enforced without inspecting unavailable old image metadata.
3. Web/API must remain cleanly stopped with original IDs/control/start/restart evidence and exit times consistent with the durable stop phases and helper creation. Worker/gateway remain the original running processes. The helper must be exact requested ID, **created**, PID 0, restart count 0, never-started timestamps, no OOM/dead/restarting state, exact `node` executable/program, fresh candidate API ID and all sandbox/env/mount controls. No stopped/running replacement or restarted helper is adopted.
4. All selected fixed tags and inspected image metadata must still equal the completed immutable candidate; validate Compose candidate configuration with dummy JWT. No build/pull/tag repair, initializer rerun or old-image metadata fallback. Verify all controls again before admission.
5. Exclusively mkdir `continue-drain.lock` **inside the existing recovery guard**; fsync its receipt, append `continue-drain.json` and `continue-drain-baseline.json`, then durable `continue-created-drain-authorized`. Preserve every original phase/failure/intent/baseline/resume record and inode. Partial lock/receipt is sticky HOLD; two contenders cannot both acquire it. Read-only check never creates it.
6. Reinspect the exact created helper/control hash, write its validated helper record, durably record helper-start, then **start that existing ID once**. No drain-helper create and no repeated web/API stops. Thereafter execute the existing reviewed fresh-helper drain, helper stop/removal, clean worker shutdown, no-writers backup gate, fresh validated backup helper, fenced private main+WAL snapshots, verified 0600 backups, immutable recreation, retained-data checks and postflight. The gateway stays identity-fenced through backup. No original application is exec'd or restarted.
7. Success archives both prior locks plus `continue-drain.lock` in the same audit and validates the continued history/receipt against the exact adopted helper record. Any accepted continuation failure adds only fixed sanitized `continue-failure.json`, retains the original failure and all locks, and refuses replay/ordinary lifecycle. No automatic rollback to unavailable images. An interruption during receipt/backup/recreation/archival is **not** another eligible created-drain continuation.

### Remaining diagnostic coverage and reviewer handoff

Helper guards now name fixed safe subreasons, including `HELPER_STATE`, `HELPER_IMMUTABLE_IMAGE`, `HELPER_ENTRYPOINT_PROGRAM`, `HELPER_ENV_STARTUP_AUTHORITY`, `HELPER_RESOURCES`, `HELPER_TMPFS`, `HELPER_UNKNOWN_HOST_AUTHORITY`, `HELPER_VOLUME_NOCOPY_DRIVER`, `HELPER_VOLUME_SOURCE` and identity/membership groups. Continuity, writer exits, JSON/protocol/deadlines, backup copy/hash/mode, new runtime security/readiness, logical retained data, public HTTP, postflight volume/network/initializer identity, source/JWT/CVE/audit fences and archive completion have fixed named subreasons. Native errors remain withheld under the fixed operation/phase token; Docker failures use only fixed sanitized categories. No raw stderr/stdout/Env is put into a failure record.

Original reviewers should recheck: narrow helper metadata normalization; exact phase-10 evidence and immutable input binding; read-only adapter; helper ID/never-started admission; one-shot receipt and crash/archive fences; no repeated admissions/build/pull/initializers; RR1 staged SQLite snapshots and RDEP-1/2/3 invariants; safe diagnostics. New fixtures cover 31 admission refusals, 13 subsequent interruption boundaries, explicit command parsing/replay, original byte/inode preservation, and detailed failure-code regressions. The live read-only check passed; **no lifecycle/recovery/continuation was executed by this author**. Review acceptance is not self-declared.

## Implemented command and review boundary

This is an **implemented one-shot build/backup/redeployment transaction**, not a plan-only path or a metadata-certification unlock. It targets only the existing `dip-public-images` qualification stand on `127.0.0.1:8081`.

**Historical context:** RR1 and RDEP-1/2/3 were addressed; the reviewed replacement failed before lifecycle, then the reviewed mount-order resume stopped at the created drain helper. The current new review inputs are the empty-DriverConfig fix, diagnostics and exact phase-10 continuation described above. This note is not an approval to operate. The reviewer reports are preserved unchanged in `public-image-chain-review-20261018.md` and `public-image-launcher-review-20261018.md`.

Initial replacement command (already attempted on this stand; **do not repeat it on its retained recovery HOLD**), from `diplom`:

```sh
node scripts/public-image-stand.mjs recover-build-and-redeploy --ack-unavailable-prior-images
```

The user has authorized finishing this isolated stand. There is no further interactive permission gate in the implementation. The explicit acknowledgement accepts the documented unavailable-prior-image risk and attests the known original build failure, reviewed working-copy source and quiescence described below. Do not run a preceding reconciliation/unlock or ordinary `up`.

**No live lifecycle/recovery execution was performed for this change.** All test Docker/lifecycle calls are injected fixtures; SQLite tests use temporary databases. The mount-order diagnosis below used authorized read-only access to this stand's exact audit, candidate images and six exact containers/two volumes/four networks, plus Compose `config` with the dummy JWT. Runtime Env was handled internally; neither a JWT nor its raw hash was output. No recovery, launch, container exec, build, pull, stop/start, migration, lock change, staging or commit was performed. No old project was inspected. Original `dip-local-full`, its port 8080, databases, JWT, volumes, images, networks and locks remain outside this operation. Earlier authorized read-only findings are recorded separately in `public-image-running-build-only-operator-20261018.md`.

Exclusive writes:

- `scripts/public-image-stand.mjs`
- `scripts/test_public_image_stand.mjs`
- This new operator note.

No server/API, Compose, Dockerfile, shared launcher, refresh/scheduler or ignore file was changed. Existing ignored `.local-public-images/` covers the new private audit/backups too; root/Dockerfile-specific ignore guards remain mandatory.

## Historical pre-lifecycle refusal and explicit same-audit resume (already attempted)

The authorized read-only diagnosis of `redeploy-a38c3a387e22331d69e7d9746baf7f27` found:

- Its six durable phases end at `new-image-validation`; `failure.json` says `guard`. `candidate.images.json` exists. No later stop/helper/exec/recreation phase or helper record exists, and `backups/` is empty.
- All six candidate image selections pass independent execution metadata validation, and the rendered immutable candidate profile passes `validateConfig`. The new image policy does **not** need broader Env, entrypoint or resource allowances.
- The six current container IDs, immutable images, process start/finish/PID/restart evidence and network settings match the saved baseline. Volume controls and network IDs/controls/endpoints also match.
- The API/worker continuity digests were order-sensitive to the engine's observed `Mounts` array. Permuting **only the same complete current mount records** reproduces each original baseline digest. Docker inspection changes this observation order; it is not an actual source, destination, access, declaration or resource change. This was the real guard mismatch after candidate validation, reported under the overly broad checkpoint.

The fix canonicalizes only observed runtime `Mounts` by unique `Destination` for continuity hashing, retaining every field. It does not sort `HostConfig.Mounts`, command/entrypoint/Env arrays, ignore unknown fields, or weaken runtime mount validation. New failures distinguish fixed sanitized `NEW_IMAGE_METADATA_REFUSED`, `CANDIDATE_PROFILE_REFUSED`, `PRIOR_RUNTIME_CONTINUITY_REFUSED` and `RESUME_EVIDENCE_REFUSED`; raw Docker output and Env stay withheld.

Historical command, already attempted and **not eligible at the current phase-10 HOLD**:

```sh
node scripts/public-image-stand.mjs resume-recover-build-and-redeploy --ack-pre-lifecycle-only --audit redeploy-a38c3a387e22331d69e7d9746baf7f27
```

This is a continuation of that exact incomplete transaction, not a reconciliation/unlock, fresh recovery, or generic retry:

1. Require the existing recovery guard and its exact matching intent; exact original build-HOLD records; exactly six ordered terminal-build/pre-validation phase records; the original guard failure at `new-image-validation`; saved baseline/prior pins/candidate; and an empty backup directory. Unknown/missing files, start evidence, later phase, partial resume/archives or any other outstanding guard refuse. Other histories must already be complete. No new audit is created.
2. Re-pin the original local Unix endpoint. Reconstruct and compare the entire original intent: original marker inode/hash, profile/Compose hashes, CVE metadata/verified public release, Dockerfile/ignore hashes, old immutable pins and helper policy. Re-run independent complete prior-runtime/namespace validation **without old-image inspection**. Compare the exact original baseline, allowing only a bounded permutation (maximum six independently validated observed mounts) to read the old order-sensitive digest. Every other field and declared mount order must match.
3. Internally compare the own JWT with the immutable retained API container's Env; its exact container/process identity must still match the original baseline. The old intent did not record a JWT inode or database-content snapshot: this path does **not** pretend to have historical cryptographic evidence it never captured. The JWT is not printed or hashed, and no private signing keys or old JWT files are read. Own state-file identities are captured and fenced for the resumed transaction.
4. Inspect and independently validate all selected fixed tags, require exact equality with the already written candidate IDs, verify own-only image references/consumers and unchanged initializer pins, then re-render/validate the candidate profile. **No build, pull, image replacement, old-image fallback or fresh tag selection is authorized.** Changed tags/IDs refuse rather than rebuilding.
5. Repeat the full current runtime/storage/network baseline proof. Exclusively create `resume.lock` inside the existing recovery guard, fsync the acknowledgement receipt, and append `resume.json` plus a canonical `resume-baseline.json` in the **same** audit. Original failure/intent/baseline/candidate/phase bytes and inodes remain unchanged and are bound in the new receipt. A partial/existing resume lock or receipt is sticky HOLD, not restartable. Concurrent resumes cannot both acquire it.
6. Continue the existing reviewed admission fencing → fresh validated drain probe → clean writer shutdown → private main+WAL snapshots/verified backups → immutable-ID recreation → retained-data/postflight → archival transaction. Every subsequent lifecycle boundary is still durable-before-submit. The initializers are not rerun. Success archives the original operation and recovery guard, including `resume.lock`, in the same audit; completed history validates both the preserved original failure and resume evidence. Failure retains HOLD without a second attempt/audit or automatic rollback.

**Data guarantee:** before shutdown, these are the same original named volumes and exact validated consumers, with no launcher database access or lifecycle submission from the failed attempt. Because the API/worker remained live, legitimate database activity can continue; there is no claim of byte-identical live databases since the old baseline (no such snapshot existed). The resumed transaction takes consistent backups only after verified drain/clean shutdown and then checks logical content through deployment before reopening web. Accounts/history/volumes are retained, not migrated or reset.

The acknowledgement attests the previous command returned, its builds are terminal/quiescent, and no concurrent host launcher/tagger/lifecycle/storage operation is outstanding. It does not certify unavailable old image bytes or rollback availability. Any failure after resume admission remains a manual-review HOLD; ordinary `up` still cannot clear it.

## What the acknowledgement means

This is deliberately **not** `reconcile-running-build-only`. That earlier command requires independently inspectable old image metadata. The reported egress/worker/API IDs no longer resolve in Docker's image catalog despite their containers still reporting the saved IDs. This new command explicitly does not certify those old image bytes/defaults, does not substitute newly retargeted tags as old-image evidence and does not promise rollback to missing images.

The operator acknowledgement covers:

- The identified original operation really failed during build, before start/lifecycle submission. All its builds are terminal; no start-submission record has been removed or original marker/pins rewritten.
- The currently running exact six-container isolated stand and its saved pins are the intended data-preservation baseline. For the existing legacy marker, historical pre-build equality is operator-attested: the old launcher did not record it.
- The working-copy application source and four existing Dockerfiles have been reviewed. No other source edit, build/tagger, launcher, lifecycle, topology or database-maintenance operation is outstanding. The original client returned and outstanding daemon work settled after long quiescence.
- The unavailable old-image provenance is accepted for **replacement**, not certified. Any failure after admission fencing may leave the public stand unavailable with a sticky HOLD and no automatic rollback.

These are facts to attest, not another approval loop. If they are false or cannot be supported, the command is inappropriate. No force option exists.

## Admission and independent prior-runtime validation

Only an existing private profile/JWT/pin set and the exact isolated namespace are accepted. The launcher does not provision empty account/ledger volumes or create a new JWT on this path.

- Original operation records must be exactly the canonical endpoint-bound `up` build HOLD (`mutation.json` alone), or the newer closed set `mutation.json`, `build-evidence.json`, `build-failure.json`. A start record, unknown record, pending pin file or any other recovery guard refuses admission.
- Resolve one local Unix endpoint, require it to match the original marker and pin it for every Docker command. No TCP/SSH/remote endpoint or mutable context/TLS-selector override is used.
- Census exact names/project labels before inspection: six own containers, two own volumes and four own networks. Missing/extra/mislabeled resources refuse. Foreign volume/image consumers are detected by ID-only projections, without inspecting their environments.
- Both engine `Image` and `Config.Image` must equal saved pins. Exact current IDs/process start/restart evidence are recorded. Four application processes must be running, the API healthy, and both original initializers successfully exited.
- **No old own-image inspection is performed on this path.** Runtime command, entrypoint, user/directory, environment, JWT, ports, mounts, healthcheck, resources, tmpfs and namespace/security settings are checked against the independent fixed profile. The same finite base-environment rules are used; arbitrary `NODE_OPTIONS`, provider variables, hooks, shell/volume defaults or self-authorization do not become allowed just because an old container has them.
- This independent container check is a private recovery path, not a global `allowMissingImages` flag. Ordinary status/up and metadata-certifying reconciliation still require their prior image evidence. Ordinary image validation remains strict.
- Volumes require exact local-driver ownership/consumer sets. Network IDs, labels, isolation, default private IPv4 IPAM, disjoint subnets and exact endpoint membership must match. No old project is adopted or inspected.
- Profile/JWT/pins/Compose, original operation bytes/inodes and public CVE/trust file identities are fenced. Four Dockerfiles and root ignore files are captured and fenced as public build inputs. The rest of the reviewed application source is covered by the no-concurrent-source-change attestation, not a fabricated signed build provenance.

Worker resources remain 4 GiB, memory=swap total/no swap, CPU 1, PIDs 128; `/tmp` 16 MiB and `/tmp/trivy` 2304 MiB retain reviewed UID 65532/noexec/nosuid constraints. Public API/worker entrypoints and read-only pinned CVE/trust mounts are unchanged. No CVE refresh/scheduler integration is introduced.

## Actual transaction sequence

### 1. Lock and durable baseline

Acquire `.local-public-images/.recover-build-and-redeploy.lock` while retaining the original `.operation.lock` unchanged. All ordinary lifecycle and other recovery modes exclude this guard. Create a private `redeployments/redeploy-<32-hex>/` audit, intent, prior pins and secret-redacted baseline before any build submission.

The audit states `originalImageMetadataVerified: false` and `rollbackToPriorImages: false`. It includes the original marker hash/identity, endpoint, current process/control baseline, source/profile/CVE pins and reviewed Dockerfile/ignore hashes. The actual JWT is neither written to audit nor hashed: its runtime Env entry is removed before control hashing.

### 2. Finish all builds before stopping anything

Build egress, worker, API and web **sequentially**, bounding simultaneous compiler pressure while the existing 4 GiB worker is still live. Each build has a durable stage record. A build failure leaves the previous containers running, with the original HOLD plus the new audit/guard retained.

All six selected image metadata objects are then independently validated. Four own IDs must be distinct with reviewed execution defaults and no foreign tag/digest aliases/references; exact previously reviewed containerd self-digests remain accepted. The two initializer selections must remain the existing pinned BusyBox ID; they are not recreated.

Write a candidate immutable-ID overlay and validate its rendered public profile. Candidate pins do not replace saved pins yet. Recheck the entire prior runtime/process/volume/network baseline after building. Newly retargeted tags are **not** treated as the running image identities.

### 3. Fence admissions and drain durable work

The inspected source shutdown patterns are:

- `server/api/src/oci/public-image.main.ts`: SIGTERM/SIGINT awaits `app.close()` and exits.
- `server/api/src/auth/auth.store.ts`: module destruction closes the auth connection.
- `server/api/src/worker/worker-runtime.ts`: SIGTERM aborts the consumer, waits for its finally path and closes the ledger.

The command stops the exact original **web, then API** IDs, verifying successful exits and retained identities. Web receives explicit fast **SIGTERM**, rather than nginx's configured graceful SIGQUIT, to close long-lived SSE/upstream connections before API shutdown. Web has no database mounts; only this stateless role may exit 143 as well as 0. The API must exit 0. This removes external admission and stops the sole API/auth writer. The worker continues draining.

Create a separate **fresh validated immutable API-image drain probe**, with only the ledger volume mounted read-only/no-copy, network none, no JWT and the same bounded helper sandbox described below. It is created **stopped**, fully inspected/validated, started by that exact ID and revalidated running before any probe execution. There is **no exec in an original application container** and no reliance on its Node/SQLite implementation or a forged old-worker response.

The fresh probe copies a bounded main+WAL byte snapshot into its private writable scratch, with source identity, size, time and full content-hash fences before/after copying and querying. It never opens the original database with SQLite and never copies SHM. Source changes return a strict retry result rather than zero pending; the existing five-minute drain budget still bounds retries. The probe opens only its private consistent copy, uses no migrating application constructor, requires schema 15 and checks both:

```sql
SELECT
  (SELECT count(*) FROM scans WHERE state IN ('queued','running')) +
  (SELECT count(*) FROM outbox WHERE delivered_at IS NULL) AS n;
```

Both must drain to zero. Only the exact validated read-only probe name/ID is accounted for in private recovery census/consumer checks: unknown names, wrong labels, extra consumers and unexpected mounts still refuse. The probe does not mount auth. After zero, stop/remove only that new exact probe ID, restore the ordinary six-container census and then stop the worker. No original container is restarted. The older CVE refresh probe is schema-14-specific and is intentionally not reused. No job is deleted, cancelled or marked delivered by the launcher.

After drain, gracefully stop the exact worker and require exit 0. Refuse SIGKILL/OOM or nonzero database-writer exits, changed processes/configuration, new writers or unexpected membership. The stateless Python gateway has no database mount or explicit SIGTERM handler; it deliberately stays running and identity-fenced through backup. Its termination is handled only by the subsequent fresh-image controlled recreation, without certifying an old gateway exit. No database-writer stop requirement is relaxed. There is **no automatic resume of old containers** on failure.

### 4. Consistent SQLite backup, private host copies

With admissions fenced, the probe removed, API/worker exited zero and **no running volume consumers**, create a uniquely named backup helper from the **new validated immutable API image**. Both helper purposes follow **create stopped → inspect exact returned ID/image/config/mounts → record validated controls → reinspect created state → start that exact ID → inspect/compare running controls**. There is no `docker run`. A rejected created helper has zero start or backup-execution submissions; uncertain creation/start retains HOLD without broad cleanup.

The backup helper has:

- Network `none`, no ports/socket/host mounts, read-only root, UID/GID 65532, all capabilities dropped and no-new-privileges.
- Only the two exact own account/ledger volumes mounted **read-only with `volume-nocopy`**; no image-directory population into data volumes.
- A `/backup` noexec/nosuid tmpfs capped at 512 MiB; 1 GiB memory=swap/no swap, CPU 1, PIDs 32, restart `no` and `--pull never`.
- Fixed launcher-supplied Node program; no app JWT or inherited provider/hook environment.

The same exported core is tested against real offline SQLite databases. It:

1. Requires the explicit internal quiescent-backup mode, which the controller reaches only after writer shutdown and no-writer checks. Source access consists solely of bounded **O_RDONLY / O_NOFOLLOW / O_NONBLOCK byte reads**. It does **not** open a source DB using SQLite, require source-directory writes, change journal mode or pretend a main-only immutable read includes WAL.
2. Capture main and any WAL files (regular, single-link, bounded); reject a rollback journal or unsafe sidecars. Copy main **and WAL if present** into a new private 0700 scratch directory with 0600 files. Do not copy SHM: SQLite reconstructs it in the private writable copy. Compare full source hashes and file identities/times/sizes before/after copying, after reading/backup and across completion of both DBs. Missing/changed files refuse; no missing-WAL fallback is permitted.
3. Open only the private copy writable (`fileMustExist`, query-only SQL), allowing SQLite's WAL recovery/sidecar machinery to work without source writes. This supports cleanly closed WAL headers with no sidecars, and preserved committed WAL frames after an abrupt writer exit. Require auth version 0 with expected tables and ledger version 15; check integrity/FKs and zero durable pending ledger work.
4. Fingerprint schema, all application rows and `sqlite_sequence` in a read transaction using **safeIntegers(true)** and raw rows. Encode INTEGER as typed exact BigInt decimal, REAL as typed IEEE-754 bytes, and distinguish BLOB hex, TEXT and NULL. Never coerce row/sequence integers to Number. Unsupported or oversized values refuse; RPC pending counts are converted only after an explicit safe range check.
5. Apply SQLite's **online backup API to that consistent private copy**. These verified standalone files—not raw staging files—are the saved backups. Reopen/recheck snapshot integrity/FKs/lossless contents, recheck the source-copy fingerprint and all original source byte fences, then remove only the helper's private staging files. The controller's quiescence makes sequential auth/ledger snapshots represent the same fenced state.
6. Set snapshot files to 0600 and record byte/hash/content evidence in private metadata. No source chmod, source SQLite checkpoint, source SHM creation or migration is used.

Copy only those verified snapshot files to the private host audit. Docker copy does not use ownership-preserving `-a`. Require current-user ownership, one link, regular/non-symlink file, **0600**, bounded size and an exact hash match to the helper-verified bytes; fsync files/directories. No backup bytes, usernames, sessions, passwords or report content are sent to stdout.

Each source main+WAL family, saved DB/file and logical scan is bounded at 256 MiB; individual TEXT/BLOB values at 4 MiB; schema objects/tables are bounded. Total helper scratch remains 512 MiB, unchanged. Before staging each family, require conservative free space for twice its byte footprint plus 16 MiB; already-produced snapshots count against free space. Near quota, oversized, incompatible or unstable data refuses rather than ignoring WAL, granting source write access, accepting a raw copy as the backup or migrating. At least 1 GiB host free space is required before build/lifecycle work. No automatic backup pruning is performed; history is capped at four audits.

Stop/remove **only the inspected exact newly created helper ID** after copies are verified. Any uncertain helper outcome stays HOLD; no broad cleanup/prune is attempted.

### 5. Commit pins and controlled recreation

Preserve the original main pin file under `saved-main-pins.json` with its inode/bytes; install the already-validated candidate pins under the recovery lock. JWT, profile, CVE overlay, accounts/ledger volumes and all four network identities remain unchanged.

Recreate only egress, worker and API, in order, using immutable IDs:

```text
compose ... up -d --no-deps --no-build --pull never --force-recreate <exact-service>
```

There is no build/pull in the execution phase. Initializers are skipped; volumes/networks are neither reset nor recreated. No ordinary `up` is called, so unavailable old-image inspection is not a bootstrap prerequisite.

Before reopening web, independently re-fingerprint both live databases in read-only SQLite transactions from the **validated fresh API process** and require equality to the lossless verified-snapshot fingerprints. This live read is not a quiescent main-only/immutable read. Before any post-recreation exec, require a new container ID distinct from the original ID as well as the exact new image/config identity. This detects unexpected schema/content changes at startup; it does not silently accept a migration. Require a fresh worker heartbeat timestamp at/after the new worker process start, not an old ready file. API must become healthy.

Recreate web only after those checks. Final postflight validates all six image/config/resource/JWT bindings, fresh application IDs, unchanged initializer controls/IDs, retained volume/network identities and complete endpoint membership. Recheck running/healthy states and worker heartbeat; require an unauthenticated 401 through native loopback `http://127.0.0.1:8081/api/v1/auth/me` without sending credentials.

This is deployment/readiness evidence, **not native browser/real scan/Trivy qualification or production acceptance**. The coordinator can perform those proofs afterward on separate new-stand accounts/data without accessing original port 8080.

### 6. Archive original failure without rewriting it

Only after successful replacement/data/postflight checks, atomically move the whole original operation directory into the audit, preserving its original mutation file and any newer build-evidence/failure records. The original marker is **never deleted or rewritten**.

Write a strict result plus completion manifest binding all private audit files and original/backup identities/hashes; move the recovery guard into its archived operation history. Ordinary lifecycle recognizes only complete validated redeployment history. Missing/tampered phase/receipt/backup/original identity blocks subsequent ordinary up/stop.

Successful result:

```text
operation: RECOVERED_REDEPLOY_PRIOR_IMAGES_UNVERIFIED
originalImageMetadataVerified: false
rollbackToPriorImages: false
jwtPreserved: true
```

It is a new deployment result, not retroactive PASS for the failed build or missing old images.

## Failure and durability behavior

The recovery has a 20-minute total Docker budget, individual bounded calls, sequential builds (up to 10 minutes each within the total), a 5-minute drain limit, 2-minute backup watchdog, 90-second service readiness bounds and a bounded helper lifetime. No failed mutation is automatically retried. Readiness polling does not resubmit recreation.

Every mutation boundary is recorded durably before submission. Failures also attempt a fixed sanitized `failure.json`; original HOLD plus recovery guard/audit persist. Failures **after admissions are stopped may leave web/API/worker stopped or a partial new deployment**. They require review of the exact retained state, not automatic retry/unlock or assumed rollback to missing images. Verified backups remain available if already produced; before backup, existing volumes are never overwritten by the launcher.

A crash after archiving the guard but before commit attempts to restore the exclusion barrier with identity checks. An incomplete/tampered history still blocks lifecycle. A console-delivery failure after durable success does not roll the deployment/audit back.

Do not manually delete locks, old markers or incomplete audits. Do not publish SQLite backups or raw container Env/Docker stderr. Restore/retry policy after an uncertain failure is deliberately not a generic force-recovery command.

## Future failed builds

For future ordinary `up --build` attempts on an existing six-container stand, the launcher writes `build-evidence.json` before build submission with exact IDs, process/control/storage/network baseline and its hash. A build failure writes a separate fixed `build-failure.json` (`checkpoint: build`, sanitized category, evidence hash).

Both files stay with the original marker on failure. The existing running-build reconciliation and the new replacement command recognize only this exact closed record set and validate it against the current baseline. Older zero-service recovery eligibility is not broadened. First-time zero-resource builds retain their existing closed behavior.

The new replacement command also records its own pre-build baseline and fixed per-build/failure stages. It never rewrites the old failed attempt's records.

## Private audit layout

```text
.local-public-images/redeployments/redeploy-<32-hex>/
  intent.json
  baseline.json
  prior-pins.json
  candidate.images.json
  helper-drain.json
  helper-backup.json
  phase-*.json
  backup-receipt.json
  backups/auth.sqlite
  backups/ledger.sqlite
  saved-main-pins.json
  original-operation.lock/mutation.json
  original-operation.lock/build-evidence.json  # only for newer original attempts
  original-operation.lock/build-failure.json   # only for newer original attempts
  result.json
  completion.json
  recovery-operation.lock/intent.json
  failure.json                              # preserved for the explicit resumed attempt
  resume.json                               # only for explicit pre-lifecycle resume
  resume-baseline.json                      # canonical, original baseline retained too
  recovery-operation.lock/resume.lock/receipt.json  # same receipt; partial lock => HOLD
  continue-drain.json                        # only for exact created-drain continuation
  continue-drain-baseline.json
  recovery-operation.lock/continue-drain.lock/receipt.json
  # On accepted continuation failure only: continue-failure.json; no completion/replay.
```

New receipts declare `helperPolicy: CREATE_INSPECT_START_V2` and bind both helper creation/control records in the completion manifest. A resumed completed history additionally binds its original failure, resume receipt and canonical baseline; the original records are never rewritten PASS. Incomplete attempts retain their failure and live root recovery guard/helper. Directories are owned 0700; private JSON/pins and SQLite backup files are 0600. Do not check this ignored directory into Git or include it in build context.

## Validation and independent review inputs

Executed checks, bounded and **offline** (Docker fixtures / temporary SQLite, no lifecycle execution):

```sh
node --test scripts/test_public_image_stand.mjs scripts/test_local_stand.mjs scripts/test_refresh_local_cve.mjs scripts/test_schedule_local_cve.mjs
# 428 passed, 0 failed, 0 skipped; 133.08 seconds; 180-second bound.

node --check scripts/public-image-stand.mjs
node --check scripts/test_public_image_stand.mjs
# Both passed; combined 10-second bound.
```

Coverage includes: old image evidence absent; independent runtime hook/env/resource refusal; exact namespace and endpoint; sequential build-before-stop; rejected fresh defaults/references/config; state/CVE/Dockerfile replacement; graceful stop/drain failures; helper capability/namespace/copy-up refusal; backup hash/mode/copy corruption; data mismatch before web reopens; every mutation/archive interruption boundary; complete-history tampering; original marker inode retention; future build baseline/failure records; and console loss after committed success.

Four new regressions were first run against the blocked source and **all four failed**: clean-close read-only WAL backup, adjacent >2^53 integer comparison, old-worker exec authority and post-start helper rejection. They pass after these changes.

Additional real offline better-sqlite3 tests close every source connection and assert main-only WAL files in 0500 source directories / 0400 source files before backup. Another bounded child writes committed WAL and is deliberately terminated; after it is dead, sources/sidecars are made nonwritable, backed up, copied as standalone DBs to a separate restore directory and reopened. Accounts, sessions, BLOBs, reports, versions and exact >2^53 `sqlite_sequence` survive, with original source bytes/files/modes unchanged. Adjacent INTEGER/sequence values yield different hashes; INTEGER/REAL/BLOB/TEXT/NULL encodings remain distinct. Source drift, partial second-DB failure, pending work, schema 14 and FK corruption still refuse.

Injected lifecycle checks assert both purposes' create → created inspections → exact-ID start → running inspection → exec order; unsafe created controls cause zero starts for that helper. Forged old-worker output is not requested/accepted, the readonly probe cannot hide a foreign ledger consumer, stable-copy retries do not become zero pending, and create/start/removal/archive interruptions retain the original HOLD. No original application ID receives any exec.

Native SQLite tests used the existing **Node v23.11.0 / NODE_MODULE_VERSION 131**, compatible with the installed native binding. No dependency install/rebuild or test skip was used. The reviewer's earlier ABI-127 mismatch is not a SQLite pass and is not silently normalized here; original recheck needs a compatible already-installed runtime. These host-side tests are not a real Docker filesystem/kernel/normalization or live deployment proof.

Independent review inputs:

1. `scripts/public-image-stand.mjs`: exact phase-24 quiescent-backup continuation/read-only checker; bounded fixed-path exec export with lossless file/source identity fences, fsynced private no-overwrite publication and manifest history; held-snapshot helper program and legacy-only admission/regeneration evidence. Prior authority/process-epoch/resource/model and earlier-stage refusal rules remain enforced. Prior RR1 hash-fenced main+WAL snapshots, RDEP-1 fresh drain authority, RDEP-2 stopped helper create/inspect/start, RDEP-3 exact INTEGER serialization, namespace/JWT/CVE/resource/HOLD rules and ordinary old-image inspection remain enforced.
2. `scripts/test_public_image_stand.mjs`: retained prior coordinator/transaction/native SQLite/security/default tests; archive-free transport regression, fixed-path native reader, empty WAL, multi-chunk exact bytes/no overwrite/private partials, deterministic quiescent backup generations, live/expired phase-24 continuation, admission drift/corrupt frames/source-fence/crash/history checks. Full executed total: 428 tests, no failures/skips.
3. This note; existing Compose/Dockerfiles/API/worker shutdown/storage sources are reference inputs only and were not changed.

SHA-256 of the exact passing source/test inputs:

```text
a823650f4e57d03322a58fc48408612ef000ecbcfb0bc16b1671ebc28bf077ae  scripts/public-image-stand.mjs
237284aea62188b4ae5932a80f9028fcd28675d4fbc7a284351523092bd198d7  scripts/test_public_image_stand.mjs
```

**Returned for independent recheck of bounded private exec export, held snapshot lifetime and exact phase-24 quiescent backup continuation/regeneration with preserved evidence, retaining all prior authority/process-epoch/model and RR1 / RDEP-1 / RDEP-2 / RDEP-3 guards. No review is self-cleared by this author. No real deployment/native-browser success is claimed, and this source change has not executed recovery or resume.**
