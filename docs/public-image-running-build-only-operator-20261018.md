# Running isolated stand / failed-build reconciliation — 2026-10-18

## Handoff status

**Implemented and offline-tested; independent review REQUIRED before any reconciliation. Live reconciliation is currently BLOCKED by missing saved-image metadata (read-only findings below).** Initial implementation was source-only; the later diagnosis used only explicitly authorized read-only exact isolated resources/state. No recovery or lifecycle mutation was performed. Docker/native/browser qualification is not established by this source change.

Coordinator-reported, not independently observed here: `up --build` failed at `checkpoint=build` after API/worker builds succeeded and the web build failed. The previous six isolated containers, two volumes and four networks still exist, with the application services running the previous immutable pins. Original `dip-local-full`/port 8080 is protected and is outside this operation. The existing zero-service build-only and network-only recovery modes are deliberately ineligible.

Exclusive writes for this change:

- `scripts/public-image-stand.mjs`
- `scripts/test_public_image_stand.mjs`
- This new operator note.

No shared launcher, Compose, Dockerfile, ignore file, original stand state/locks, signing key, database or environment file was edited/read. No Docker mutation/recovery, launch, staging or commit was performed. All tests use temporary fixture roots and injected Docker implementations. Separately authorized live read-only diagnosis is described below; it did not invoke reconciliation or change any private state.

## Authorized read-only diagnosis: current blocker

The follow-up probes resolved one local Unix endpoint, pinned it on every subsequent Docker read and checked it against the original own mutation record. They read only the owned `compose.images.json` and mutation record, exact saved image IDs/current service tags, and the six exact `dip-public-images-<role>-1` containers. Container project labels were checked before full own-container inspection. Raw container Env, raw Docker stderr and JWT data were never printed or hashed; the actual JWT file was not opened. No old-project resource was inspected, and no volume/network/database data was opened.

Observed results (not a full runtime qualification):

| Role | Container Image and Config.Image match saved pin | Saved-ID image inspect | Current tag |
|---|---|---|---|
| auth-volume-init | yes, exited | resolves | same ID; image policy accepted |
| scan-volume-init | yes, exited | resolves | same ID; image policy accepted |
| egress | yes, running | **NO_SUCH_IMAGE** | different ID; image policy accepted |
| worker | yes, running | **NO_SUCH_IMAGE** | different ID; image policy accepted |
| api | yes, running | **NO_SUCH_IMAGE** | different ID; image policy accepted |
| web | yes, running | resolves | same ID; image policy accepted |

Thus the refusal occurs **before** an old-image metadata policy comparison: Docker cannot inspect three saved IDs, despite the containers still reporting them. It is not a requirement for a tag in `docker image inspect`: this launcher already permits untagged own pinned images when their metadata is available. The engine/storage reason those old IDs became unresolvable has **not** been established; no claim of pruning, corruption or a particular containerd bug is made.

The diagnostic-only patch preserves all guards and reports fixed, role-specific fields, with no raw exception/output/cause:

```text
status: checkpoint=runtime-image-egress; reason=RUNTIME_IMAGE_METADATA_UNAVAILABLE
reconciliation: checkpoint=proof-pinned-image-egress; reason=PINNED_IMAGE_METADATA_UNAVAILABLE
```

Egress is the first missing role in the existing traversal order; worker/API are independently confirmed missing too. Generic image-inspection failures do not authorize using the new tag's defaults or self-authorizing from the running container Config. No such fallback was added. The diagnostics were fixture-tested after the patch; no live reconciliation was rerun. No locks, markers, pins, images or containers were changed during diagnosis.

**Remain HOLD.** An independently reviewed way to recover trustworthy metadata/evidence for the exact old IDs (or another separately approved operational path) is needed before this reconciliation could pass. Merely accepting the diagnostic patch does not repair the missing evidence and is not authorization to retry/start/recreate anything.

## Exact command — reference only, currently BLOCKED

From the `diplom` repository root:

```sh
node scripts/public-image-stand.mjs reconcile-running-build-only --ack-build-failed-before-start
```

This acknowledgement is intentionally different from `--ack-no-services`: services already exist. The operator must verify and attest **all** of the following before invocation:

1. The identified `up --build` command actually returned with failure at **build**, not initializer pull, image selection, pin writing, pinned-config validation, start or postflight. The original failure evidence has not been edited or confused with another attempt.
2. That failed operation never submitted a service start/stop/recreate or other lifecycle command; the existing containers are the previously running stand, with the previous saved pins. No external client deleted a start-submission record or rewrote the pins/marker.
3. The launcher/client has returned, outstanding daemon build work has settled after long operator-observed quiescence, and no concurrent launcher, builder, tagger, lifecycle operation or topology writer is outstanding. A client timeout by itself does not prove daemon quiescence.
4. Independent review has accepted these exact sources and the sufficiency of the operator-held historical failure evidence for this attempt.

If these statements cannot be established, **do not acknowledge**. Do not substitute another recovery mode or manually delete a lock. There is no force flag and ordinary `up`/`stop` does not auto-reconcile.

### Evidence limit: do not invent a pre-build snapshot

The older launcher recorded an endpoint-bound build/pull HOLD marker, but **did not persist a pre-build container-ID/control snapshot or a durable `checkpoint=build` failure receipt**. Its build marker also remains in place through later stages. Marker phase alone therefore cannot prove that a failed attempt stopped during build.

This command combines the explicit operator attestation with the exact original marker, absence of any start-submission record, current saved pins, independent runtime/config validation and repeated stable current-resource snapshots. It verifies that the current six container IDs, pinned images, configuration, process start/restart evidence, volumes, networks and build-tag selections remain unchanged throughout reconciliation. It cannot retrospectively prove equality to a nonexistent pre-build snapshot, or prove that another client never briefly created and deleted a resource. The receipt explicitly records `prebuildBaseline: OPERATOR_ATTESTED`, not fabricated historical proof. Independent review must not describe this as fully automated historical certification.

## Admission invariants

The new mode is a separate closed policy. The existing zero-service modes retain their original restrictions.

- **Exact operation boundary:** only an original canonical `up` marker with phase `build-pull-start-outcome-unconfirmed` and a mandatory matching local Unix endpoint. The operation directory must contain **only `mutation.json`**: any start-submission, extra record or pending pin file blocks admission. Profile, JWT, image pins and any CVE overlay must already exist in their safe owned paths; nothing is provisioned or rotated.
- **Pinned endpoint:** context resolution happens once; every subsequent Docker/Compose command uses the literal recorded matching Unix endpoint, without inherited context/TLS selector overrides. Remote/TCP/SSH endpoints refuse. Config rendering uses only the nonsecret placeholder, never the actual JWT.
- **Namespace before inspect:** a complete name/project-label census requires exactly the six fixed isolated container names (stopped containers included in census), two fixed volume names and four fixed network names, all with the correct project. Unknown names, foreign-project mislabels and missing/extra resources refuse before any resource/image inspection. Legacy names are never followed; no legacy Env/JWT is opened.
- **Immutable running identity:** every service uses its saved image ID in both the engine `Image` and `Config.Image`. Four own pinned images remain distinct; both initializers share the reviewed pinned BusyBox ID. Images are independently validated for ownership, command, entrypoint, environment, working directory and execution defaults. Arbitrary container image IDs are not followed during namespace inspection.
- **Runtime profile:** the existing independent validator checks exact public API/worker commands, strict runtime environment and own JWT match, mounts, public read-only CVE/trust bindings, resources, tmpfs, namespaces, security options, admission and loopback port 8081. Worker remains 4 GiB with memory=swap total/no swap, CPU 1, PIDs 128 and the reviewed tmpfs mounts. No global allowlist was broadened.
- **Healthy existing execution:** four application services must be running, with the API's configured healthcheck healthy; both initializers must have exited successfully. Restarting/dead/OOM/error states refuse. Container IDs, immutable images, PIDs, started/finished timestamps, restart counters and secret-redacted control hashes are snapshotted and compared at the archival proof fences. Healthcheck logs/timestamps are not treated as stable configuration.
- **Volumes:** only own local-driver volumes with the exact expected consumers; foreign consumers refuse. Scope, creation time, mountpoint, labels, options and the rest of the inspected volume control record are snapshotted. No mountpoint is opened. Databases remain live: this is a control-plane identity check, **not a data backup/content consistency claim**.
- **Networks:** all four own default local bridges must have their expected isolation, recognized labels, no custom options/config-from authority and disjoint canonical private IPv4 subnet/default-gateway pairs. Network IDs and exact own endpoint/container membership must match the container attachments; foreign endpoints refuse. Complete inspected network control records are hashed and compared repeatedly. No network is removed, recreated, connected or disconnected.
- **State/CVE fences:** profile/JWT/pins/source/CVE-overlay bytes and file identities are retained and rechecked. Enabled public CVE assets are reverified and their metadata identities fenced throughout. Current activation is not reloaded; private signing keys are never consulted. The original failure marker bytes/inode and operation directory identity remain unchanged.

### Partial build tags are not runtime authority

API/worker builds can legitimately retarget `dip-public-images-api:local` and `dip-public-images-worker:local` while old containers still use their previous immutable IDs. Old pinned own images may consequently be untagged; that alone is not a refusal. Their independent image policy and own-only reference policy must still pass.

There must be exactly the four expected own tags. Their current images are independently validated; foreign tag/digest aliases refuse, apart from the already-reviewed exact local containerd self-digest. Each pinned/current-tag own image may be referenced **only** by the exact current isolated containers that actually use its ID. A newly retargeted image must have no container references. BusyBox can be shared with unrelated initializers; this does not authorize references to the four own application images.

Current tag-to-ID mappings are recorded separately from the running pins and must remain stable across proof rounds. The command does **not** promote tags to pins, rewrite pins, roll tags back, finish the failed build or restart anything. Images/build artifacts remain untouched.

## Durable result, not PASS

The command uses `.reconcile-running-build-only.lock`, mutually excludes both existing recovery guards and shares only the established archival transaction/fences. A 60-second total Docker-call budget applies, with no retries. Namespace/runtime proofs run before preparation, before/after original-lock archival and at guard release.

A successful receipt is stored under:

```text
.local-public-images/reconciliations/running-build-only-<32-hex-nonce>/
  acknowledgement.json
  completion.json
  original-operation.lock/
    mutation.json
  reconciliation-operation.lock/
    intent.json
```

The original lock and marker are atomically moved with bytes/inodes preserved. The durable receipt uses:

```text
operation: RUNNING_BUILD_ONLY_NO_LIFECYCLE_SUBMITTED
originalOutcome: HOLD_PRESERVED
startSubmission: ABSENT
prebuildBaseline: OPERATOR_ATTESTED
```

It binds original marker/lock identities and hash, endpoint, profile/source/CVE/pin hashes and identities, transaction nonce, explicit acknowledgement, six runtime IDs/pins/control hashes/process evidence, volume/network control hashes and the four current build-tag IDs. The runtime API JWT value is removed before hashing the container control snapshot; no raw Env, JWT value or standalone JWT hash is recorded or printed. The completion hashes the acknowledgement and links the original marker. Files/directories are synced around atomic archival boundaries.

Any interrupted preparation/commit leaves the original HOLD and/or a recovery guard/incomplete history. Ordinary lifecycle refuses unsafe/incomplete history and cannot finish it. A pre-intent read-only refusal can release only the new empty recovery guard, preserving the original operation HOLD; any later retry still requires this explicit acknowledgement and full re-evaluation. A precommit failure after guard archival attempts to restore the exclusion barrier, never deleting original evidence. Loss of console output after durable completion does not roll back completed records. Completed running-build history is a distinct strict schema recognized by subsequent ordinary lifecycle commands.

Receipt success is **not** a successful build, service deployment, new-image qualification or production acceptance. Do not immediately use bare `up` assuming it will preserve the old images: ordinary `up` intentionally selects current tags and can replace pins. Fix/review the failed build independently and obtain separate authorization for any subsequent `up --build` or other lifecycle operation. This reconciliation submits none.

Public stand accounts remain separate on `127.0.0.1:8081`. Original port 8080/data stay outside the namespace. Existing CVE refresh/scheduler tooling must not control this stand; its release remains pinned and manual refresh remains unsupported.

## Offline validation and exact review inputs

Four initial running-build fixtures failed before implementation because the CLI was absent. Two additional missing-image diagnostic regressions failed before the diagnostic patch. Final bounded checks, from `diplom`:

```sh
node --test scripts/test_public_image_stand.mjs
# 99 passed, 0 failed; approximately 7.9 s; 30 s bound.

node --test scripts/test_public_image_stand.mjs scripts/test_local_stand.mjs scripts/test_refresh_local_cve.mjs scripts/test_schedule_local_cve.mjs
# 275 passed, 0 failed; approximately 15.9 s; 60 s bound.

node --check scripts/public-image-stand.mjs
node --check scripts/test_public_image_stand.mjs
# Both passed; combined 10 s bound.
```

Fixtures cover the synthetic actual launcher build-failure boundary; partial tag retargeting without pin promotion; existing zero-service refusals; wrong marker/phase/endpoint/start evidence; malformed/unsafe/missing private state; exact-name/project-label prefiltering; foreign image/volume consumers; unsafe runtime environment/resources/commands; stopped/unhealthy/restarting services; process/config/file/CVE/network/volume/tag identity changes; every archival interruption checkpoint; tampered receipts/original inodes; completed-history lifecycle acceptance and output loss after completion. Additional regressions cover missing pinned metadata for egress/worker/API with current tags available, no tag/container-config fallback, retained original HOLD/pins, sanitized role diagnostics and status not opening the JWT. Docker calls and runtime operations in all these tests are injected fixtures, not real operations.

Independent reviewer should examine:

1. `scripts/public-image-stand.mjs`: running proof/admission, partial-tag reference policy, secret-redacted snapshots, strict receipt/history branch, shared transaction integration and all recovery-guard exclusions. Follow-up changes are limited to fixed image-evidence errors and their propagation; no admission predicates or recovery behavior were relaxed. Pay particular attention to the historical evidence limit and the current missing-metadata blocker above.
2. `scripts/test_public_image_stand.mjs`: new running-build fixtures plus all retained previous/coordinator regressions.
3. This note. Existing profile/Compose/shared helpers may be read as references but were not changed.

SHA-256 of the exact passing source/test inputs:

```text
b06bd6b25f3cede4902f9c036be21b44d309d737dfc0ee8f4d35c21249e32ac5  scripts/public-image-stand.mjs
f40922307d1eb5d6d29d0827008763abbf46fe8fb119bc4722759d4fe940f151  scripts/test_public_image_stand.mjs
```

**Gate remains closed: missing old-image evidence is unresolved, independent review is required, and the exact acknowledgement must be supportable.** No live reconciliation or Docker/native/browser pass is claimed.
