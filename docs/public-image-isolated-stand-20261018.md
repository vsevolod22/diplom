# NEW isolated public-image qualification stand — 2026-10-18

## Purpose and boundary

This launcher can provision **new, isolated qualification data** once independent re-review is complete, a coordinator supplies the ignore rules below, and a local Docker engine is started. It is not in-place activation of `dip-local-full`, not a migration/copy of its databases, and not production acceptance. The retained-stand source-only activation block and legacy public-profile refusal remain unchanged.

**Review remediation:** this revision addresses R1–R4 from `docs/public-image-launcher-review-20261018.md`. The original independent review remains unchanged as the historical REQUEST CHANGES record. Passing implementation regressions are not independent approval: **re-review and native qualification are still outstanding**. Do not launch merely because the offline tests pass.

This slice writes only:

- `scripts/public-image-stand.mjs`
- `scripts/test_public_image_stand.mjs`
- this document

`server/deploy/compose.public-images.yaml` and the shared helpers are unchanged read-only review inputs for the current follow-up.

This agent has not run Docker, a real launcher/reconciliation command, or accessed live private state, databases, environment/signing-key files or JWTs. No original stand operation, staging or commit was performed. All executable verification here uses injected Docker fixtures and disposable temporary roots.

**Coordinator-reported real attempt (not independently inspected by this agent):** Docker 28.0.4 is available; root ignores were supplied; strict Compose normalization was adjusted for `entrypoint: null` and `networks.ipam: {}`. A subsequent real up built the four NEW images, failed before service startup at image-policy validation, and retained `.local-public-images/.operation.lock/mutation.json` in phase `build-pull-start-outcome-unconfirmed`. The coordinator reports no public containers, volumes or networks and an untouched, running `dip-local-full`. Real private state now exists from that explicit coordinator launch. This follow-up changes only source/tests/docs and does **not** read, reconcile, unlock or operate that real state.

## REQUIRED coordinator action before any launch

Append this exact line to **both** repository-root `.gitignore` and `.dockerignore`, **after any negations**:

```gitignore
.local-public-images/
```

These two files are coordinator-owned and were not changed here; the coordinator is supplying the additions. The launcher still refuses `up` before Docker calls, public activation reads or private-state creation unless both files explicitly protect the directory. Root ignore files are read bounded/no-follow as owned single-link regular files, not through symlinks into an env/key file. Its check conservatively rejects any later `!` rule. It also refuses **any** Dockerfile-specific ignore override (regular file, directory or symlink, even if it appears safe) for all four allowlisted build paths: `server/deploy/{api,worker,stand}.Dockerfile.dockerignore` and `server/deploy/gateway/Dockerfile.dockerignore`. These overrides supersede root `.dockerignore`; they must not silently drop new or retained private-state protections. The guard is rechecked before build and before start. This matters especially because the reused web Dockerfile has `COPY . .`: the new JWT must never enter the build context or image. Do not supply it via an env file, shell export or Compose command line.

Also retain the existing ignores for `.local-stand`, `.local-auth` and other private files; do not weaken those rules. Leave original stands **as found**: the coordinator now reports `dip-local-full` running. Do not stop/start or otherwise operate it for this qualification. This launcher does not inspect its containers, read its signing secret, stop/start it or acquire/remove its operation lock.

## Coordinator run sequence — NOT executed in this delivery

From repository root `diplom`, after independent re-review, the ignore additions and local Docker startup:

```sh
# First launch: explicitly acknowledges NEW isolated accounts and databases.
node scripts/public-image-stand.mjs up --build --isolated

# Read-only, redacted inspection; does not open/create the JWT.
node scripts/public-image-stand.mjs status

# Stop only inspected running container IDs in dip-public-images; retain storage.
node scripts/public-image-stand.mjs stop

# Subsequent launch reuses this stand's JWT, accounts, reports and pinned release.
node scripts/public-image-stand.mjs up --build
```

`up` also supports omitting `--build` after suitable images exist. `--isolated` is mandatory when no own profile exists, and may be repeated on later launches without resetting anything. There is no `down`, `prune`, reset, database import, forced unlock, migration-from-LOCAL, refresh or acceptance-bypass option. The separate, explicitly reviewed `reconcile-build-only --ack-no-services` command below is restricted to a failed pre-start build with zero namespace resources; it is never invoked by ordinary `up`. Unknown/duplicate flags refuse before side effects. No package scripts or existing launcher commands were changed.

Docker operations have bounded client timeouts: inventory/config/context operations default to 30 seconds, separate build and detached start operations each have 600 seconds, explicit BusyBox acquisition has 120 seconds, and container stop has 90 seconds with a 30-second stop grace. `up --build` is **not** a combined build-and-execute submission anymore; see the image-policy boundary below.

Only a local Unix-socket endpoint is accepted; TCP/SSH/remote contexts are refused. The selected/default context is resolved once as client metadata (or an explicit Unix `DOCKER_HOST` is validated directly). **Every subsequent engine/config/build/pull/start/stop/postflight call gets that literal `DOCKER_HOST`**, with `DOCKER_CONTEXT`, `DOCKER_TLS_VERIFY` and `DOCKER_CERT_PATH` removed from an operation-scoped sanitized environment. The mutable current context or a later named-context edit cannot redirect those calls. When both ambient host and context are set, context selection has Docker's precedence during resolution only; neither selector remains authoritative afterward. This requires a trusted Docker executable/plugin, Unix socket and client configuration: a Unix URI is not attestation of a daemon's physical location or protection against an administrator replacing the socket/daemon. Detected errors/identity drift after submission retain HOLD; there is no re-resolution or retry against another endpoint. No background server/watch process is started by the host script.

Open **http://127.0.0.1:8081** and register **new accounts**. Neither old accounts nor old reports are imported. Use a **separate browser context/incognito profile** for proof: cookies are scoped by host/path, not TCP port, so an existing `127.0.0.1:8080` browser session must not be reused as isolation evidence. The new JWT issuer/audience are `dip-public-images`; old scan tokens are not credentials for this composition.

## Fixed standalone composition

| Item | Isolated value |
| --- | --- |
| Compose project | `dip-public-images` |
| Host binding | **only** `127.0.0.1:8081` → web port 8080 |
| State directory | `.local-public-images`, owned non-symlink mode 0700 |
| JWT | `.local-public-images/scan-jwt`, owned single-link regular mode 0600, 48 random bytes encoded as 96 lowercase hex characters |
| Account volume | `dip-public-images_auth_accounts` → API `/auth` |
| Ledger/report volume | `dip-public-images_scan_ledger` → API/worker `/data` |
| Networks | Own `auth_internal`, `scan_internal`, `registry_uplink`, `web_edge`, each prefixed `dip-public-images_` |
| Internal networks | auth and scan; only egress also joins registry uplink, web joins web edge |
| Images | Own `dip-public-images-{egress,api,worker,web}:local` tags; reused existing Dockerfiles |
| Ownership | `org.diplom.public-image-stand=v1`, Compose project label, plus `org.diplom.public-image-project=dip-public-images` on built images |
| API | `node --import tsx src/oci/public-image.main.ts` |
| Worker | `node --import tsx src/worker/public-image-worker.main.ts` |
| Worker resources | **4 GiB memory; 4 GiB memory+swap total = zero additional swap; CPU 1; PIDs 128** |
| Worker `/tmp` | 16 MiB, rw/noexec/nosuid, UID/GID 65532 |
| Worker `/tmp/trivy` | 2304 MiB, rw/noexec/nosuid, UID/GID 65532 |

All services have read-only roots, dropped capabilities, no-new-privileges and fixed memory/swap/CPU/PID limits. API/worker/egress run as 65532:65532, web as 101:101. Two bounded BusyBox initializers run as root with **only CHOWN added** to change ownership of the top of their own named volume; they do not copy, recursively clear or initialize data from any other stand. Fresh database tables/migrations are created only when the API/worker opens these new own volumes. Subsequent launches retain them; no existing legacy database is opened or auto-migrated.

API and web also receive bounded noexec/nosuid `/tmp` tmpfs mounts. There is no Docker socket, privileged container, host network, shared network, external volume or private-key mount. No API/worker host port is exposed. LLM flags remain false; this is the public image-only API composition, not the old runtime/host/LLM service. Existing unrelated frontend widgets may be unavailable against it.

The Compose file intentionally uses **JSON-compatible YAML**, which Compose accepts. This lets offline tests parse the actual shipped source with built-in `JSON.parse`, independently normalize its build contexts/JWT sentinel, and compare it to a separately coded normative model without installing a YAML parser or invoking Docker.

## Independent pre-start image policy (R1)

Ownership labels alone never authorize execution. Both cached own tags (including when no container exists) and all selected post-build images are checked against a service policy coded independently of inspected image/container values. Container validation calls the same policy before accepting inherited metadata. It pins the image entrypoint, default command, working directory, default user, exposed-port set and stop signal; rejects image healthchecks, anonymous volume declarations, ONBUILD/shell/startup overrides; and admits only the reviewed base metadata below:

- All images: a fixed system-only `PATH`; Python may have its reviewed `/usr/local/bin` prefix duplication. No writable `/tmp` or project directory enters executable search.
- API/worker: `NODE_VERSION=24.11.1`, `YARN_VERSION=1.22.22`.
- Gateway: `PYTHON_VERSION=3.13.7`, bounded hexadecimal `GPG_KEY` and `PYTHON_SHA256` metadata. `LANG` is **optional**; if present it must be exactly `C.UTF-8`. The reviewed actual gateway has no LANG. PATH rules are unchanged.
- Web: `NGINX_VERSION=1.27.5`, optional bounded numeric `NJS_VERSION`, `NJS_RELEASE`, `PKG_RELEASE`, `DYNPKG_RELEASE` metadata.
- BusyBox initializers: the fixed PATH only; default shell command, no image entrypoint or extra execution metadata.

No `NODE_OPTIONS`, `LD_PRELOAD`, scanner/provider settings, Python hooks, nginx entrypoint knobs, proxy variables, inherited JWT or arbitrary extra keys are accepted—even when image **and** container contain the same value. Working directories are independently fixed to `/app/server/api` for API/worker, `/opt/gateway` for egress, **`/` for web** (the reviewed actual Linux image), and empty for BusyBox. Only the reviewed Linux Node API/worker roles may carry boolean `ArgsEscaped: true` as inert base metadata; `false`/absence remain accepted. Non-boolean forms and true on other image roles are rejected. This does not authorize string commands, alternate entrypoints, Windows images or any other startup authority. Application image users and entrypoints match the reused Dockerfiles; the BusyBox image default user is empty and the explicit service user is root for CHOWN only. The nginx image's inherited port 80 plus declared 8080 are accounted for as image metadata, **not additional host publication**; host binding remains only 127.0.0.1:8081.

Version/hash strings admitted as inert base metadata are **not image authenticity/signature evidence**. Unknown legitimate future base metadata also refuses until reviewed; there is no permissive fallback. Trusted Dockerfiles/build inputs/base-image publishers and a trusted builder remain prerequisites. Offline fixtures do not establish the actual upstream image bytes/defaults or native compatibility.

The startup sequence is now:

1. Validate the fixed source configuration and existing namespace/cached images; preserve all original guards.
2. For `--build`, record durable mutation intent **before** a separate `compose build` using the validation sentinel, then explicitly acquire `busybox:1.37.0`. No service container starts in these steps. Build/acquisition failure or unsafe resulting defaults leave HOLD.
3. Inspect and independently validate all six service image selections, including the shared initializer image, and snapshot their immutable engine IDs. Without `--build`, missing/invalid cached selections refuse; startup never pulls implicitly.
4. Write own mode-0600 `compose.images.json`, containing exactly the six `image: sha256:<engine-id>` substitutions and no other service authority. Render and compare the pinned configuration against the original normative model with **only those validated image identities substituted**. Recheck pins and ignores before submission.
5. Start with **`up -d --no-build --pull never`** and the image-ID overlay last. A tag replacement cannot change the identities consumed by start; no intervening build/pull may select different bytes. Existing resource/auth/network/mount rules are unchanged.
6. Revalidate actual postflight image defaults, runtime guards and the exact selected IDs. Only successful postflight releases the mutation receipt/lock. A bad image discovered after build is a HOLD without container startup, not permission to bypass validation or clean up automatically.

The standalone Compose file and its fixed normative configuration have not been weakened or changed. The coordinator's null-entrypoint/empty-IPAM normalization and regression are preserved; IPAM is now explicitly required to be an empty object for that normalization (arrays/scalars/nonempty objects are not erased). Positive fixtures now represent distinct Dockerfile image defaults (including inert Node/Python/nginx metadata) separately from overridden service commands; the launcher no longer treats either the image or container as its own policy reference.

## Own stable secret and state

Only explicit `up` can provision the private directory or signing secret. No ambient `SCAN_JWT_SECRET`, scanner/provider setting, dotenv, `COMPOSE_*`, proxy or `NODE_OPTIONS` is inherited. The Docker child receives only the existing Docker-client allowlist and, for Compose, the **own** JWT substitution. Config rendering and the separate build use a 96-zero validation sentinel; only the final immutable-ID start uses the stable own secret. The secret is never included in argv, logs, profile/overlay JSON or uncertainty receipts. Do not publish raw Docker inspection output: the engine necessarily stores the API environment. Launcher status output is redacted.

Creation uses exclusive no-follow writes, fsync, and subsequent bounded no-follow reads. Symlinks, hardlinks, wrong owner/mode, malformed JWT and missing JWT on an established profile refuse without rotation or fallback to any other secret. The launcher never reads `.local-auth` or `.local-stand/scan-jwt`.

`profile.json` contains only version, own project identity and public CVE pins (or null). It is canonical, mode 0600 and read no-follow. An owned-looking namespace without its profile is a collision, not permission to adopt data. A restart cannot silently change an enabled pin to disabled, disable/enable CVE from ambient env, or replace the own JWT.

## CVE: public files only, pinned, NO updater integration

On first up, the launcher calls the existing **`loadCveActivation(root)`**. It reads only the current public activation JSON/public PEM and validates the existing immutable public release layout, modes and SPKI fingerprint. It does **not** read the private DB signing key or LOCAL JWT. If activation is absent, the new profile pins **CVE disabled**. If activation is present but invalid, launch refuses; it does not silently fall back to disabled.

When enabled, the launcher persists the five public metadata fields in its own profile and creates its own fixed `compose.cve.json` overlay. This overlay adds only matching CVE environment and exact RO binds:

- API and worker: the pinned release directory → `/opt/release`.
- API and worker: the public PEM → `/opt/local-db-trust/public.pem`.
- Worker: the pinned release `db` → `/tmp/trivy/db`, read-only underneath its own 2304 MiB tmpfs.

All binds have `create_host_path: false`. No parent trust directory/private PEM is mounted. The overlay cannot reset worker memory or tmpfs; the entire rendered config is compared against the fixed normative public model. Existing LOCAL/CVE overlays are **not** passed to this project.

Subsequent up validates the **own pinned release**, not the current activation. Status/stop use the own public profile for inspection and do not need to open current activation, release contents, PEM or JWT. A changed/invalid later LOCAL activation therefore cannot silently change this stand. However, deletion of the pinned release or replacement of its public PEM can prevent a restart; keep these public assets available unchanged. Authentic signed DB verification, freshness and public API/worker readiness remain runtime requirements, not claims made by the launcher's file-layout check.

**Existing CVE refresh/scheduler tools do not control this stand. Manual refresh is unsupported.** Do not point them at this project, edit `profile.json`/`compose.cve.json`, swap pins in place or remove public release assets to force a refresh. A future reviewed isolated refresh workflow must preserve this project's commands/resources, credentials and own data. An expired pinned DB can block new CVE admissions; the launcher does not redate/re-sign it or claim freshness. Without CVE, choose only supported non-CVE checks for qualification.

## Inspection and uncertainty safety

Before any lifecycle mutation, the launcher reads name/project-label projections. A row matching the own namespace prefix **or** own project label must have an **exact per-kind allowlisted name before any full resource inspect**: the six own container names, two own volumes or four own networks. An off-allowlist name with a misleading isolated label—including a legacy/dev/HOLD name—causes a generic collision refusal **without inspecting it or reading its environment/JWT**. Normal unrelated rows are skipped. Exact own names with foreign labels may be inspected only to reject ownership; actual names, service identity, IDs and labels are checked again after that allowed inspection. Image tags likewise must be exact own allowlisted tags before inspection. It checks exact service names, ownership, image labels, commands/entrypoints, environment, resources, tmpfs, capabilities/security, kernel path protection, port bindings, mount declarations and observed mounts, and network membership. Foreign volume users/endpoints, shared/old volumes, socket/private binds, mixed legacy commands, resource drift and renamed/unowned collisions refuse before up/stop. Desktop `/host_mnt` aliases are accepted only on macOS with matching exact RO bind declarations, not as arbitrary path normalization.

The launcher uses **only its own** `.local-public-images/.operation.lock`, acquired exclusively, plus the separate own reconciliation exclusion barrier described below. It never uses or clears `.local-stand` locks. Before the first build/acquisition/start or stop mutation it fsyncs `mutation.json` inside this lock. The same receipt remains through build, image inspection, immutable-ID start and postflight; it is not cleared merely because build completed. New mutation markers also record the pinned literal endpoint. Before any future service-start submission, an additional fsynced `start-submission.json` is written inside the operation lock. Its presence makes build-only reconciliation ineligible even if resources were later removed. Fixed `checkpoint=` diagnostic tokens distinguish build, initializer acquisition, per-role image policy, image pins, pinned config, start and postflight; raw errors and Env values remain suppressed. Acknowledged commands are followed by runtime inventory checks; only then is the receipt removed and lock released. A client error/timeout, unsafe/incomplete postflight, replaced lock or lost outcome retains HOLD. No retry, cleanup, reset or secret replacement is attempted. Even a stale empty lock is not stolen automatically. Status remains observational and reports a visible HOLD; unsafe partial inventory may still refuse inspection.

A HOLD requires human-reviewed reconciliation of this project's exact container/image/volume state and receipt. Each timeout is a client bound, **not cancellation of Docker daemon work**. Do not remove locks, rerun direct Compose, invoke the legacy launcher, or delete volumes to make a failed command appear successful.

## Explicit build-only HOLD reconciliation — review BEFORE invocation

**This command has NOT been run on the real stand.** It is proposed source for independent review, not permission to operate live state now. The coordinator should review the exact files/hashes in the handoff below, independently confirm eligibility and the original local engine, then explicitly invoke it if approved.

Exact command from repository root:

```sh
node scripts/public-image-stand.mjs reconcile-build-only --ack-no-services
```

`--ack-no-services` is the operator's assertion that the original operation never submitted service execution and that the selected local endpoint is the engine used for the failed build. **A current zero-resource census alone cannot prove that services never existed.** Older markers have no endpoint/start-boundary record; for those, the receipt explicitly records `endpointProvenance: operator-acknowledged-legacy-marker`, not a fabricated machine-proven match. Before using that compatibility path, independently confirm the original failure was pre-start and the original engine/context is still selected. New markers with an endpoint must match it exactly and record `recorded-match`. A Unix URI still requires a trusted local socket/CLI; it is not physical-location attestation.

### Machine-enforced eligibility

The command refuses unless all of the following hold:

- Explicit exact command/ack flag, canonical repository path, protected root ignores, and no Dockerfile-specific ignore overrides. No missing stand directory/profile/JWT is provisioned; only the narrowly scoped reconciliation/audit state is created.
- Existing own mode-0700 state and original `.operation.lock`, same filesystem for atomic archival, and **only** `mutation.json` inside that lock. The canonical original marker must be version 1, project `dip-public-images`, command `up`, phase **exactly** `build-pull-start-outcome-unconfirmed`, with either no legacy endpoint or the matching recorded Unix endpoint. Other phases, missing/malformed/linked markers, start-submission evidence and extra lock files refuse.
- Own canonical profile, existing single-link owned mode-0600 JWT, unchanged inode/bytes/mode, and no unknown state/pending/image-pin files. This intentionally excludes later pre-start stages that already wrote `compose.images.json` as well as all post-start recovery. There is no generic unlock or fallback to another secret.
- The shipped JSON-compatible source is independently checked against the fixed model **before** Compose may parse any referenced file: only the reviewed JWT placeholder and relative contexts are accepted; `env_file`, `extends`, foreign contexts, extra authority and hardcoded JWTs refuse. Profile/source/overlay/JWT identities and contents are captured and checked repeatedly.
- CVE uses only the own pinned metadata; no later activation is loaded. With CVE enabled, the existing public release-layout/SPKI validator is rerun, the own public overlay must match exactly, and pinned release/DB/public-PEM metadata must remain stable. Bundle/DB contents are not read in bulk. No private signing key, old JWT/env, database or old operation lock is read. This is not a live signed-DB freshness/readiness proof.
- A **projection-only** all-container/all-volume/all-network census on one validated pinned Unix endpoint reports **ZERO** own namespace resources, including stopped/unowned own-name collisions and mislabeled rows. No container/volume/network `inspect` or Env read is needed to reject an occupied namespace. Original stands with their normal labels are skipped.
- Exactly the four NEW own image tags exist, each image independently passes the narrowed Linux/base metadata policy, has its own labels, one exact own tag and no foreign digest/project/service references. Container-ID-only `ancestor=<validated image ID>` projections must also show no running or stopped container referencing any selected image; no referenced container is inspected. Immutable IDs remain unchanged across repeated proof rounds. The acknowledgement records `imageContainerReferences: 0`. No image is pulled, tagged, built or deleted by reconciliation.

The Docker portion has one monotonic 60-second budget, individual calls at most 30 seconds, no retries and no re-resolution of the endpoint. It uses only context resolution, name/label lists, image-reference container-ID projections, four own image inspections per proof round and sentinel-only Compose config rendering. **No build, pull, up, stop, exec, down, prune, volume/network creation or database migration/copy is submitted.** The own JWT never enters a Docker child environment during reconciliation, is never printed/hashed into a receipt, and is not rotated or copied.

### Durable archive transaction and crash behavior

The command first exclusively creates own `.local-public-images/.reconcile-build-only.lock`. Normal up/stop refuse while either control lock exists. Reconciliation never steals an existing/stale/substituted guard and never acquires or clears a LOCAL/old stand lock.

After read-only proof, it fsyncs a reconciliation intent and an acknowledgement under a new exclusive mode-0700 directory:

```text
.local-public-images/reconciliations/build-only-<32 lowercase hex>/
  acknowledgement.json
  original-operation.lock/
    mutation.json
  completion.json
  reconciliation-operation.lock/
    intent.json
```

Receipt files are mode 0600. The original operation-lock directory is **atomically renamed**, not copied/deleted, into this archive. Original mutation bytes are untouched; original directory/file device/inode identities and mutation SHA-256 are bound into the acknowledgement and verified before/after moving. State/profile/source/public-CVE snapshots and the actual namespace/image proof are rechecked at successive commit boundaries. The original failure remains **`HOLD_PRESERVED`**, never rewritten to PASS. The separate acknowledgement/completion operation is **`NOT_EXECUTED_SERVICES`**, explicitly acknowledging the pre-start reconciliation rather than certifying a successful scan/deploy.

Only after original evidence, acknowledgement and completion have been fsynced does the reconciliation guard move atomically into the archive and both parent directories get fsynced. The completion receipt links the acknowledgement and original mutation by SHA-256. No JWT value or JWT hash is stored; the file is checked in memory for stable inode/content/mode. Audit metadata is integrity/correlation evidence under the trusted owner-controlled filesystem, not an external signature or an authenticity claim.

An interrupted/failed pre-commit step preserves the original failure and any prepared audit records. If the original operation lock has moved, the separate reconciliation guard still excludes ordinary launch. A fault during guard release attempts to restore that exact guard barrier without deleting/replacing foreign paths. Empty/stale guards are never stolen. Missing/incomplete/tampered archive records also block normal up/stop even if a guard path was manually removed. History checks are bounded to 32 archives; unknown/partial entries or the maintenance limit require review, not automatic deletion.

A refusal before durable reconciliation intent may release **only this command's verified empty temporary guard**; the original operation HOLD remains. No later interrupted transaction is resumed by regular up or by blindly retrying reconciliation. A completely committed archive with lost console output is reported as committed/acknowledgement unavailable: inspect the protected audit receipts before the next step, do not rerun as a force-unlock. These guarantees assume a trusted filesystem/CLI and cooperative operator; no lock can exclude an administrator performing direct concurrent Docker or filesystem manipulation. Do not operate the stand concurrently during reconciliation.

### Handoff after independent approval

For the currently reported pre-image-policy failure, an approved successful reconciliation should print `NOT_EXECUTED_SERVICES` with a relative receipt path, leave JWT/profile/CVE pins intact, retain the original failure in the archive and leave all service resources absent. **This is expected future behavior, not an observed live result.** Do not manually remove either lock if the command refuses or is interrupted.

Only after reviewing a complete committed receipt may the coordinator explicitly retry:

```sh
node scripts/public-image-stand.mjs up --build
```

That remains a separate real operation with its own guards, endpoint/start receipts and native postflight checks. It does not use the reconciliation acknowledgement as scan/deployment acceptance. If any public resources already exist or a start marker/pin file is present, this build-only command is deliberately not the recovery mechanism; obtain a separate scoped review instead of widening it.

## Coordinator's native/browser proof — still outstanding

After Docker startup and a successful isolated launch:

1. Confirm status addresses only `dip-public-images`, port 8081 and the intended enabled/disabled CVE pin. Check actual engine cgroup-v2 memory 4 GiB, swap zero, CPU 1/PIDs 128 and physical 2304 MiB tmpfs plus nested RO DB binds. Runtime resource checks can refuse unsupported engine/kernel behavior; do not weaken them to manufacture a pass. Budget sufficient Docker VM memory for the worker, other services and overhead.
2. In a separate browser context, register/login as a new account at 8081. Confirm no old account/report appeared and only own isolated volumes are mounted. Leave original stands untouched in their existing state; the coordinator reports the original LOCAL stand running.
3. Exercise fresh public Docker Hub/amd64 admission with an independently resolved, bounded canonical reference. Verify identity inspection, readiness/auth/origin guards and rejection of legacy/profile-bypass flags; do not treat a discovery suggestion as scan authorization.
4. Run native public image acquisition/Trivy checks and observe owner-scoped persisted reports. With CVE enabled, require authenticated fresh pinned DB evidence; with CVE disabled, demonstrate the expected CVE refusal rather than claiming a checked-zero result. Exercise cancellation/partial results as appropriate.
5. Stop/relaunch **this** stand and verify own credentials/reports/pins persist. Record actual source revision/image IDs, resource/trust evidence, selected digest, commands and results. Do not label launcher startup, HTTP auth health or fixture results as native scanner/production acceptance.

This source/tests follow-up performs no native Docker, registry, browser, cgroup/tmpfs or live signed-DB proof. Coordinator-reported builds/metadata are not native service qualification, report acceptance or an independently reviewed reconciliation.

## Offline validation performed

From repository root:

```sh
node --test --test-name-pattern='review R' scripts/test_public_image_stand.mjs
node --test scripts/test_public_image_stand.mjs
node --test scripts/test_public_image_stand.mjs scripts/test_local_stand.mjs scripts/test_refresh_local_cve.mjs scripts/test_schedule_local_cve.mjs
node --check scripts/public-image-stand.mjs
node --check scripts/test_public_image_stand.mjs
```

Review-first red/green evidence:

- Before changing launcher behavior, six regression tests reproducing R1–R4 were added and run against the independently reviewed source: **0 passed, 6 failed**, exit 1. They confirmed inherited hook acceptance, cached/new-image start-before-validation, off-allowlist inspection, override guard bypass and missing endpoint binding. No Docker or injected payload code was executed.
- After implementation, those six passed. Expanded review coverage now comprises **11 tests passed, 0 failed, 0 skipped**, exit 0 (about 2.1 seconds with concurrent regression testing; 30-second tool bound).
- Final isolated-only suite: **42 passed, 0 failed, 0 skipped**, exit 0 (about 4.8 seconds while running concurrently with the combined suite; 30-second tool bound).
- Final combined isolated + unchanged legacy launcher/CVE/refresh/scheduler suites: **218 passed, 0 failed, 0 skipped**, exit 0 (about 12.9 seconds; 60-second tool bound).
- Both `node --check` commands: exit 0, no diagnostics (10-second tool bound).

The earlier 31/207 results were pre-review evidence, not approval; the current results above supersede them. No prior test was skipped or disabled, no expected standalone configuration was loosened, and no legacy launcher/refresh/scheduler source or tests were changed in remediation.

An additional scoped `git diff --check` returned exit 0; new untracked files are not covered by Git's diff whitespace check, while the script syntax and shipped Compose JSON parsing are covered above. All results are offline fixture/source validation, not Docker or native/browser qualification.

Coverage is fixture-only: first-up opt-in/ignore guards, exact shipped Compose source, CVE on/off, real public-file loader on disposable synthetic releases, pinned restarts, own stable JWT and new volume identities, redacted environment boundary, safe status/stop, malformed profiles/keys/overlays, resource/entrypoint/tmpfs drift, socket/foreign mount/endpoint/writer collisions, Desktop RO aliases, preflight errors, postflight HOLD, client timeout and replaced/stale locks. Review additions cover matching image/container hooks, cached/newly built/initializer image policy, independent execution defaults, benign Node/Python/nginx metadata, tag substitution and pin-file tampering, misleading project labels on legacy/HOLD/unknown names, overrides at every Dockerfile path (including dangling/safe-looking overrides), late pre-build overrides, mutable default/named contexts, explicit host precedence, binding on up/status/stop and post-submit endpoint failure. Legacy launcher/CVE/refresh/scheduler behavior and the retained-stand activation block are regression-tested without changing their files.

## R1–R4 implementation handoff for independent re-review

| Finding | Implemented boundary | Evidence / remaining gate |
| --- | --- | --- |
| R1 P1 | Independent service image/environment/default policy before execution; separate build; initializer acquisition/validation; immutable-ID overlay; no-build/no-pull start; exact postflight IDs | Original probes reproduced red before fixes, now green; expanded cached/new/all-service/default/tag/pin fixtures pass. Actual upstream image/default/builder compatibility remains unqualified. |
| R2 P2 | Exact projected per-kind names checked before resource inspect; misleading labels cause refusal without Env/JWT reads | Both legacy namespaces, unrelated/HOLD names and unknown own-prefixed names tested with intercepted inspect requests. No foreign details are returned. |
| R3 P2 | Refuse any Dockerfile-specific ignore override for all four builds before side effects; repeat guard before build/start; retain root after-negations rule | Empty/comment-only, symlink, directory, safe-looking and late pre-build override fixtures pass. Coordinator owns root additions; no ignore override support is claimed. |
| R4 P2 | Resolve once; bind literal Unix `DOCKER_HOST` and remove context/TLS selectors for every subsequent engine command | Default/named context changes, both ambient selectors, explicit Unix host, up/status/stop and post-submit failure fixtures pass. Trusted CLI/socket/client configuration remains a prerequisite; no physical-location attestation is claimed. |

Historical R1–R4 remediation source SHA-256 (superseded by the current follow-up inputs below):

```text
1ae9ecef2d9160d632a29c448b890dff23ec0036750575da4845a7e0be7ea1a1  scripts/public-image-stand.mjs
7a6825066d8e1a3434e5dec20066bb258b0d2a2d3defc5c4de75132b9c9f2eee  scripts/test_public_image_stand.mjs
fa562e64f4feb6d9f366bc3bf14a7b0f3773fbc00e97e7e153a7ed1f52f6cc99  server/deploy/compose.public-images.yaml
```

The Compose source hash is unchanged from the independent review. The review document itself is untouched. This was an implementation handoff, **not a self-issued review approval**. The coordinator's later real build/HOLD and the current source-only follow-up are described separately above/below. This agent performed no Docker commands, real secret/state access/creation, old stand operations, private env/signing-key reads, staging or commits.

## Current follow-up review inputs and bounded verification

**Independent source review is required before invoking reconciliation. No live reconciliation or launcher command was run by this agent.** The real namespace census, engine version, image metadata and original stand status in this document are coordinator reports, not observations from these tests.

Exact primary review inputs:

1. `scripts/public-image-stand.mjs` — narrow metadata policy; source/ignore no-follow guards; `buildMarker`, `emptyNamespace`, `builtImageIds`, `captureFile`/`directoryIdentity`, `reconcileBuildOnly`, `assertReconciliationHistory`; strict CLI dispatch; future start-submission receipt and fixed diagnostic tokens.
2. `scripts/test_public_image_stand.mjs` — preserves the coordinator's normalization regression; actual-shape compatibility fixtures; all rejection, identity, archive, endpoint, replay, reference and interrupted-commit cases.
3. `docs/public-image-isolated-stand-20261018.md` — operator attestation, limitations, transaction/commit semantics and exact proposed command.

Unchanged supporting inputs, read-only: `server/deploy/compose.public-images.yaml`; `scripts/public-image-stand-profile.mjs` constants/public metadata schema; `scripts/local-stand.mjs` Docker adapter/environment and public CVE validators; `scripts/setup-local-cve.mjs` exclusive-write/fsync primitives. No legacy launcher/refresh/scheduler implementation, Dockerfile, package script, Compose source or root ignore file was edited in this follow-up.

Current code/test/Compose identities:

```text
333c24cf36267500cd3986ab7c98076554e3b9498a8f0c3c816335250c91d1fd  scripts/public-image-stand.mjs
9c4cbf2918d11894c37a7cbf43e8493da6a0481712f696ac169421c6629acae6  scripts/test_public_image_stand.mjs
fa562e64f4feb6d9f366bc3bf14a7b0f3773fbc00e97e7e153a7ed1f52f6cc99  server/deploy/compose.public-images.yaml
```

New regressions were exercised red before the corresponding fixes: four initial compatibility/normalization/reconciliation cases failed against the prior source; further fault fixtures exposed identical-byte replacement of an archived original lock, root-ignore symlink following, and container references to otherwise valid own images. Those conditions now refuse safely without hiding them by changing the expected standalone configuration or skipping prior tests.

Final commands/results for the current source hashes:

```sh
node --test scripts/test_public_image_stand.mjs
node --test scripts/test_public_image_stand.mjs scripts/test_local_stand.mjs scripts/test_refresh_local_cve.mjs scripts/test_schedule_local_cve.mjs
node --check scripts/public-image-stand.mjs
node --check scripts/test_public_image_stand.mjs
```

- Isolated suite: **65 passed, 0 failed/cancelled/skipped**, exit 0, about **9.4 seconds** under concurrent testing; **30-second outer bound**.
- Combined isolated + unchanged legacy launcher/CVE/refresh/scheduler suites: **241 passed, 0 failed/cancelled/skipped**, exit 0, about **15.4 seconds**; **60-second outer bound**.
- Both syntax checks: exit 0, no diagnostics; **10-second bound**.

The 65-test selection includes the prior coordinator regression and expanded fixture loops for both CVE modes, all marker/phase/start/pin refusals, stopped/foreign/mislabeled resources, image alias/digest/container references, unsafe/missing/linked credentials, source indirection, public-CVE changes, inode/directory replacement, all injected pre-commit crash boundaries, archive collisions/tampering, endpoint mismatch/change, incomplete history, lost output after commit and safe stage-only diagnostics. It uses no real Docker adapter, live private directory, database, key, env file or old stand. Test cleanup removes only disposable temporary roots.

Proposed operator command **after independent review and independent original-engine/pre-start confirmation**, not an instruction to run now:

```sh
node scripts/public-image-stand.mjs reconcile-build-only --ack-no-services
```

Expected success is an auditable `NOT_EXECUTED_SERVICES` reconciliation with the original HOLD preserved, not PASS and not a native qualification. If any eligibility check or commit boundary refuses, preserve all original/reconciliation locks and evidence and obtain a scoped review; do not manually remove them or widen this command to cover services that might have run. Only a complete reviewed receipt permits the coordinator to consider a separate explicit `up --build` and the still-outstanding native/browser proof.
