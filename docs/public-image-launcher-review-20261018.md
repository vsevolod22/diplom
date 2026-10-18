# Independent defensive review: isolated public-image launcher — 2026-10-18

## Decision

**Changes requested for the defensive isolation contract; no real-daemon launch approval.** The shipped composition and ordinary fixture paths are carefully separated from `dip-local-full` and `dip-auth-stand`, and the isolated suite independently passed **31/31**. However, four defensive gaps remain: image defaults are partly self-authorizing and partly checked only after execution; mislabeled legacy names can reach inspection; effective Dockerfile-specific ignore policy is not checked; and a checked Docker endpoint is not pinned for subsequent commands.

These are conditional failure paths, not evidence that any existing stand, key, JWT or database has been accessed or damaged. The root ignore prerequisite currently also blocks `up`, as intended. Do not remove that gate or treat passing fixtures as permission to launch.

Review scope: `scripts/public-image-stand.mjs`, `scripts/test_public_image_stand.mjs`, `server/deploy/compose.public-images.yaml`, and `docs/public-image-isolated-stand-20261018.md`. Shared helper implementations, the four reused Dockerfiles, and public ignore-rule source were inspected only to establish these files' actual boundaries. No production or test source was changed. This review document is the only repository file written by this review.

## Findings

### R1 — P1: image defaults are not independently constrained before execution

**Locations:** `scripts/public-image-stand.mjs:231–247,326–329,390–399`; `server/deploy/compose.public-images.yaml:24–88`.

There are two related holes in the image-policy boundary:

1. `validateContainer()` builds its expected environment from **all** of `image.Config.Env`, then overlays the service environment. An unexpected setting inherited from the image is therefore accepted when the container inherits it too. An offline probe added the same `NODE_OPTIONS=--require=/tmp/unreviewed.cjs` to the synthetic API image and container; `inspectNamespace()` accepted it. This does not execute that module, but proves that the validator accepts a setting capable of changing Node startup. Dropping host `NODE_OPTIONS` from the Docker child environment does not address image-inherited settings. Other image defaults, including working directory, are also used as their own reference rather than an independent policy.
2. With no existing container, cached image tags are checked only for the two ownership labels. A synthetic correctly labeled API tag with `Entrypoint=["/bin/sh","-c"]` passed preflight and reached the intercepted `compose up` submission. The fixed entrypoint check is inside container inspection and cannot reject this image until **after** Compose has started it. The Compose source does not override image entrypoints. `--build` likewise combines build and execution before the launcher can inspect the newly built images.

The normal shipped Dockerfiles do not show this unexpected `NODE_OPTIONS` setting. The finding concerns stale, incorrectly built, or otherwise policy-drifted images that retain plausible labels; labels alone are not an image-default allowlist. A postflight HOLD preserves uncertainty but cannot undo already executed startup code or writes to this stand's own account/ledger volumes. This is not a demonstrated escape into old volumes.

**Required change:** define a service-specific image policy independently of inspected image/container values. Validate inherited environment names/values, entrypoint, working directory, and other relevant execution defaults before starting containers. Allow reviewed base-image metadata explicitly rather than allowing every image environment key. For build launches, separate build from start, inspect the resulting image identities/defaults, and ensure start consumes those validated identities without an intervening build or uncontrolled pull/tag substitution. Apply equivalent scrutiny to initializer images. Keep the existing postflight validation and HOLD behavior.

**Regression acceptance:** matching unexpected image/container `NODE_OPTIONS`, `LD_PRELOAD`, scanner/provider settings, and entrypoint drift must refuse before start; cover both cached-image/no-container restart and newly built images. Benign reviewed Node/Python/nginx base metadata must still work. A mutation error must continue to retain HOLD without cleanup or secret output.

### R2 — P2: project-label collisions can inspect legacy container environments before refusing

**Locations:** `scripts/public-image-stand.mjs:298–310`; `docs/public-image-isolated-stand-20261018.md:104`.

Candidate selection accepts namespace name **OR** project label. The code then issues `inspect` before checking whether the projected name is one of the exact permitted names. A synthetic list row:

```text
dip-local-full-api-1<TAB>dip-public-images
```

caused a request for `container inspect dip-local-full-api-1` before refusal. The probe intercepted that request and returned an empty synthetic response; no real resource or environment was read. A real equivalent response includes `Config.Env`, potentially including the legacy JWT. Even if ownership/name validation immediately rejects it and nothing is logged or mutated, that violates the stronger boundary that the launcher must not read the old stand's JWT. It also qualifies the runbook's claim that legacy names from list projections are skipped without inspection. Normal legacy rows with their normal legacy project label are correctly skipped by the current tests.

**Required change:** validate projected names against the exact per-kind name allowlist **before** requesting full inspection. An off-allowlist name bearing this project's label should cause a generic collision refusal without inspection, not be silently adopted or silently ignored. Continue checking labels, service identity, IDs and actual names after inspecting valid candidates.

**Regression acceptance:** test both legacy namespaces, unrelated/HOLD names, and unexpected own-prefixed names with a forged/mistaken isolated project label. Assert no `inspect` request for them, no secret access, and no lifecycle mutation. Preserve normal skipping of unrelated resources and collision refusal for exact own names with foreign labels.

### R3 — P2: the build-context guard checks root ignores, not effective Dockerfile-specific ignores

**Locations:** `scripts/public-image-stand.mjs:179–186,382–395`; `server/deploy/compose.public-images.yaml:26–27,37–38,53–54,79–80`; `server/deploy/stand.Dockerfile:7`.

`checkIgnores()` requires the exclusion in repository-root `.gitignore` and `.dockerignore`, but does not check for `<Dockerfile>.dockerignore` files. Dockerfile-specific ignore files take precedence over root `.dockerignore`. An offline fixture with both required root exclusions and an empty/comment-only `server/deploy/stand.Dockerfile.dockerignore` passed `checkIgnores()`.

With such an override, the launcher can create/read its JWT and submit a root-context build whose effective excludes do not protect `.local-public-images`. The reused web build performs `COPY . .`; private state can enter the build context and intermediate build layers/cache even if it is not intentionally copied into the final nginx image. An empty override can also drop the root exclusions for old `.local-stand`/`.local-auth` assets, which is particularly incompatible with the required legacy-data boundary.

**Qualification:** no Dockerfile-specific ignore files were found under the current `server/deploy` source. Both current root ignore files lack the required new-state exclusion, so actual `up` should presently refuse. This is a confirmed guard bypass on a synthetic source layout, not observed private-data inclusion or an instruction to launch.

**Required change:** simplest is to refuse any Dockerfile-specific ignore override for all four allowlisted Dockerfiles. Alternatively, validate the effective ignore policy for each build, including the new state and retained legacy private-state exclusions, and preserve it through context submission. Root-only validation is insufficient if overrides are allowed. Do not weaken the existing after-negations rule.

**Regression acceptance:** root excludes plus an unsafe Dockerfile-specific override must refuse before Docker calls, activation reads, or new private-state creation. Cover the web Dockerfile and the gateway/API/worker build paths. Test safe policy behavior deliberately if override support is retained. Never use a real JWT/private directory as the test input.

### R4 — P2: local endpoint validation is not an operation-wide endpoint binding

**Locations:** `scripts/public-image-stand.mjs:148–154,344,367–397`; `scripts/local-stand.mjs:52–56,76–83`.

`requireLocalEngine()` resolves and checks a Unix endpoint once, but returns no bound endpoint and does not update the Docker environment. Subsequent `docker` processes continue using the inherited context selector or the mutable current context from Docker client configuration. With neither `DOCKER_HOST` nor `DOCKER_CONTEXT` set, an ordinary concurrent context switch can therefore move later inventory, up, stop or postflight commands to a different daemon, including a remote one, despite the initial local-only check. A named context definition can likewise change. The own filesystem lock does not lock Docker's client configuration.

This is a **source-based race finding**; no context switch or Docker client was invoked during review. Existing endpoint fixtures cover initial TCP/SSH refusal, not continued use of the checked endpoint.

**Required change:** resolve the allowed endpoint once, then explicitly bind every inventory/config/build/start/stop/postflight command to that same validated Unix endpoint. For example, clear context selection and pass the resolved `DOCKER_HOST` in an operation-scoped sanitized environment. Do not keep resolving a mutable context implicitly. Treat any detected daemon/endpoint identity uncertainty after submission as HOLD, not permission to inspect another daemon or retry. A trusted Unix socket/CLI remains a prerequisite; the URI alone is not attestation of a daemon's physical location.

**Regression acceptance:** injected client resolution changes after preflight must not redirect later commands; assert explicit binding on every call. Retain early remote refusal and mutually consistent environment handling when ambient context and host selectors are both supplied. Never perform a real remote-context test for this regression.

## Controls that passed source/fixture review

| Area | Observed control and qualification |
| --- | --- |
| Fixed standalone namespace | Project `dip-public-images`, exact six services, two explicitly named own volumes, four own networks, and own image tags. Normative rendered-config comparison rejects unknown configuration rather than merging arbitrary legacy overlays. R1/R2 remain exceptions to the claimed execution/inspection boundary. |
| Ports and networks | Only web publishes `127.0.0.1:8081` to 8080. Auth/scan networks are internal; worker has only scan, egress adds registry uplink, web adds web edge. Foreign endpoints and foreign users of own volumes refuse. No host networking or API/worker published ports in the shipped model. This is not a live packet-isolation test. |
| Mounts | Named storage references only own auth/ledger volumes. No socket, old database volume, host private-key or old-JWT bind is in the fixed model. CVE overlays permit only exact public release, public PEM, and nested worker DB binds, RO with host-path creation disabled. Darwin aliases require matching bounded declarations. No recursive/submount behavior was tested on a daemon. |
| Existing public CVE data | The invoked loader validates public activation metadata, immutable release layout and public-key fingerprint. It does not invoke the setup helper's private-key provisioning path. Restarts use own pinned public metadata rather than rereading current activation. Status/stop need neither public-file content reads nor JWT-file reads. The synthetic loader test instruments public opens; it is not authentic signed-DB usability/freshness evidence. |
| Own stable JWT | Explicit up only; 48 random bytes, exclusive/no-follow mode-0600 file, own mode-0700 directory, bounded reads, no hardlink/symlink adoption, no missing-established-secret replacement. Existing API JWT must match the own file before up. Config uses a sentinel; real up passes the own JWT through the child environment, not argv. CLI messages are redacted. Docker inspection and the returned status inventory remain secret-bearing data and must not be dumped. |
| Commands and resources | Exact public API/worker commands, fixed init/egress/web commands, read-only roots, dropped capabilities, no-new-privileges, exact limits. Worker: 4 GiB memory and memory+swap total, CPU 1, PIDs 128, `/tmp` 16 MiB and `/tmp/trivy` 2304 MiB. Initializers add only CHOWN and target the top of their own volumes. Image-entrypoint timing is R1; actual enforcement and physical tmpfs/cgroup behavior remain unproved. |
| Child invocation | Shared `runDocker()` uses `execFile`, an argv array, bounded timeouts/buffers and suppressed raw failures. Ambient dotenv/Compose/scanner/provider/proxy/Node settings are not copied through the child-env allowlist. `/dev/null` is the explicit env file. Trusted Docker executable/plugin/client configuration is still assumed; image defaults are R1 and endpoint binding is R4. No real client configuration was read in this review. |
| Collision/default behavior | No default command, down/prune/reset/import/forced-unlock path. Unknown/duplicate flags refuse. First up requires `--isolated`; root ignore protection is checked before provisioning. Exact own collisions without a profile refuse adoption. Missing profile on status/stop creates no state. No claim of race-free exclusion against other Docker administrators or direct Compose users. |
| Lock/HOLD | Only the own lock is acquired. A durable mutation receipt precedes lifecycle submission; timeout/error/unsafe postflight leaves HOLD, suppresses success, and blocks retry. Replaced/stale locks are not stolen. Lock verification is retained at relevant boundaries. This is outcome preservation, not daemon cancellation or rollback. |
| Stop, cleanup, restore | Stop targets inspected running own container IDs, checks postflight identity/stopped state, and retains own accounts/reports/volumes/JWT/pins. No production failure path deletes containers/volumes, resets databases, rotates keys, or restores old data. Read-only preflight failures release only the own verified lock and can leave established own profile/JWT for a retry. Test cleanup changes modes/removes only disposable fixture roots. There is no implemented backup/restore or automated HOLD-recovery workflow to approve. |

## Bounded offline validation

Commands ran from repository root with a clean child environment (`env -i`, literal tool PATH, and `/tmp` for fixture temp storage where needed):

```sh
node --test scripts/test_public_image_stand.mjs
node --check scripts/public-image-stand.mjs
node --check scripts/test_public_image_stand.mjs
```

- Isolated suite: **31 passed, 0 failed/cancelled/skipped/todo**, exit 0, reported duration about **0.95 seconds**, 30-second outer bound.
- Both syntax checks: exit 0, no diagnostics, 10-second bound.
- Additional one-shot in-memory probes: **four assertions confirmed**, exit 0 within a 30-second bound:
  1. legacy-name/own-project-label collision reaches synthetic container inspection before refusal;
  2. matching unexpected image/container `NODE_OPTIONS` passes namespace validation;
  3. unsafe entrypoint on an owned-looking cached image reaches intercepted up submission;
  4. an unsafe Dockerfile-specific ignore override passes the root ignore guard.

The probes reused the existing synthetic fixture builder, loaded only its setup prefix in memory, imported the actual launcher validators, and supplied explicit injected Docker runners. They did not register/run the rest of the test suite, execute Docker, execute injected entrypoints/modules, or build an image. All created profile/JWT/ignore inputs were synthetic and lived in disposable temporary roots outside the repository; cleanup ran in `finally`. No probe source file was added. An initial probe-harness attempt failed before fixture creation because a data-URL module used `fileURLToPath(import.meta.url)`; correcting only the in-memory harness URL allowed the assertions to run. That harness error is not a product finding.

No Docker command, real launcher CLI invocation, environment-file read, private-state/key/JWT/database read, network request, browser check, broader suite, staging or commit was performed. The previously documented **207-test combined run was not rerun** and is not claimed as new review evidence. R4 is supported by the source control flow, not a live or synthetic daemon experiment.

### Reviewed source identity (SHA-256)

```text
14dbda674a5debcf43dfc92552efe68a0fe1548c88586ef45222fa564c14fdb3  scripts/public-image-stand.mjs
fc9b7a287624082daabc2cfd638cbed25192091608e16e764323b7702a6a3cc0  scripts/test_public_image_stand.mjs
fa562e64f4feb6d9f366bc3bf14a7b0f3773fbc00e97e7e153a7ed1f52f6cc99  server/deploy/compose.public-images.yaml
05d61a1609fde0861ce051abf9551ef4f13d830ec9088f693a88c2cbaf210fbe  docs/public-image-isolated-stand-20261018.md
```

## Required disposition and later qualification

1. Address R1–R4 in a separate authorized implementation change with targeted synthetic regressions; retain the current fail-closed ignore gate and legacy launcher's activation block. Do not change production/test code as part of this review-only delivery.
2. Coordinator supplies the required new-state exclusions in both ignore files **after** effective build-context protection is established. No private state should be created merely to test this prerequisite.
3. Human-reviewed native qualification must establish actual Compose/Engine compatibility, bounded resources, physical tmpfs/nested RO DB mounts, auth/origin/issuer behavior, new-account/report isolation, public acquisition/Trivy behavior and fresh authenticated CVE evidence when enabled. Strict inspection may legitimately refuse engine versions/defaults not represented by fixtures; do not weaken it to manufacture acceptance.
4. Use an isolated browser context, keep old stands untouched/stopped as required, and demonstrate this stand's own stop/relaunch persistence. Any restore rehearsal must use separate own isolated targets and preserve its JWT and consistent SQLite/WAL state; no backup/restore implementation or successful rehearsal is evidenced here.
5. Any HOLD requires reviewed reconciliation of exact own resources and mutation outcome. Do not delete a lock/receipt, run direct Compose, use legacy lifecycle tools, delete volumes or rotate a secret to clear it. A client timeout is not daemon cancellation.

**Bottom line:** the normal-path source and 31 passing fixtures support substantial isolation controls, not the absolute defensive guarantee or real-daemon correctness. The confirmed gaps should be closed before this launcher is relied on for the requested no-legacy-data/no-legacy-JWT boundary.

---

## Independent remediation re-review — 2026-10-18

### Exact scoped verdict

**APPROVE the R1–R4 remediation at the source identities below for the reviewed source/offline safety mechanisms. R1, R2, R3 and R4 are CLOSED within this re-review scope; no remaining blocker was found in those remediated mechanisms.**

This is **not** real-daemon launch authorization, proof of an absolute isolation guarantee, native/browser/Trivy qualification, restore acceptance, or production approval. Trusted source/build inputs, Docker executable/plugin/client configuration, builder, base-image publishers and Unix socket remain prerequisites. Actual upstream image defaults, Compose image-ID handling, engine inspection compatibility, resource enforcement, mounts and runtime behavior have not been exercised on Docker.

This appended disposition supersedes only the earlier open R1–R4 dispositions for these new identities. The original REQUEST CHANGES review, original findings, original test results and original hashes above remain preserved as historical evidence; they were not rewritten to describe the remediation retroactively. Only this review document was changed during re-review. Implementation, tests, Compose, the author's runbook and ignore files were read-only.

### Reviewed remediation identities

These hashes were independently computed, not copied as an assertion from the author's handoff:

```text
1ae9ecef2d9160d632a29c448b890dff23ec0036750575da4845a7e0be7ea1a1  scripts/public-image-stand.mjs
7a6825066d8e1a3434e5dec20066bb258b0d2a2d3defc5c4de75132b9c9f2eee  scripts/test_public_image_stand.mjs
fa562e64f4feb6d9f366bc3bf14a7b0f3773fbc00e97e7e153a7ed1f52f6cc99  server/deploy/compose.public-images.yaml
a49a06230099e83a4cb6c047d3c4d94d18e1d1c048f58993fdb9d709b9ed8c20  docs/public-image-isolated-stand-20261018.md
```

Launcher/test/Compose hashes match the remediation handoff. Compose is byte-identical to the original reviewed composition. The historical review before this append was **19,366 bytes**, SHA-256 `79958b4076303c6ecdc7ae5beb41b85a0d80c4e17c3fabda00c8ac600f135110`; preservation of that exact byte prefix and unchanged reviewed input hashes is checked as part of this delivery.

### Finding-by-finding disposition

| Finding | Independent source finding and probe result | Disposition |
| --- | --- | --- |
| **R1: image environment/defaults before execution** | `public-image-stand.mjs:238–272` defines service policy independently of image/container data: bounded reviewed base metadata only; fixed entrypoint, default command, user, working directory, ports and stop signal; startup/default overrides rejected. `:287` validates the image before accepting inherited container environment. The original matching API image/container `NODE_OPTIONS` probe now rejects, as do matching preload/scanner/provider variants. Cached API entrypoint drift with no containers refuses before `up`. Expanded independent probes reject environment and entrypoint corruption for **all six services**, cached and freshly built/acquired, before any service/init start. | **CLOSED — source/offline** |
| **R2: exact projected names before inspect** | `:351–356` validates all candidate names for that resource kind before issuing full inspection. Independent mixed projections put a valid own row before a mislabeled legacy/HOLD row; all nine kind/name cases refused without inspection of either row for that kind or lifecycle mutation. This covers both legacy namespaces, not just normal unrelated rows. | **CLOSED — source/offline** |
| **R3: Dockerfile-specific ignore overrides** | `:190–199` rejects any override at each of the four allowlisted Dockerfile paths, using existence checks that do not follow dangling symlinks. Checks occur at initial up (`:425`), before build (`:482`) and before start (`:494`). The original unsafe override probe now rejects; all four paths refuse before Docker fixture calls, activation reads or state creation. The 42-test suite also passes directory, dangling-symlink, safe-looking and late pre-build override cases. | **CLOSED — source/offline** |
| **R4: operation-wide endpoint binding** | `:154–165` resolves/validates once, returns a frozen operation environment with literal Unix `DOCKER_HOST`, and removes context/TLS selectors. All status/absent/mutation branches use the returned options (`:432,439,459`). Independent default/named-context probes change the synthetic context after resolution and assert the same bound host on every later inventory/config/build/pull/start/stop/postflight call. Explicit Unix host avoids resolution; post-submit endpoint failure retains HOLD. | **CLOSED — source/offline** |

### Startup ordering and immutable-image handoff

The ordering was inspected directly and tested independently of the author's new test registrations:

1. Existing namespace/cached-image validation and normative unpinned config validation precede build/start. Cached invalid images refuse without starting containers, even when labels look owned.
2. For `--build`, `intent()` durably records uncertainty before a separate `compose build`; only the config sentinel crosses that build's environment. BusyBox acquisition is a separate `image pull` without JWT substitution (`:483–486`). Neither submission starts the service/volume-initializer containers. The build still executes trusted Dockerfile instructions; this review does not claim to sandbox a hostile builder or untrusted build source.
3. `selectedImages()` validates and snapshots all six service selections (`:389–401,488`), including both initializers using the acquired/cached BusyBox image. Sharing a cached inspection does not bypass either service's validation.
4. `pinImages()` produces own mode-0600 `compose.images.json` with only six `image: sha256:<engine-id>` substitutions (`:403–417`). The pinned config is validated against the original normative model with those exact validated IDs substituted, and the overlay bytes are rechecked (`:489–494`). It cannot grant additional mounts, ports, resources, networks or service authority.
5. The image overlay is last in `-f` order. Final submission is exactly **`up -d --no-build --pull never`** (`:498–499`); no new build or implicit tag-based pull is requested. The own JWT is supplied only for this Compose submission, not config/build/pull/inspection.
6. Postflight checks both `container.Image` and `container.Config.Image` against the selected service ID (`:284–285,500`). Independent CVE-off/on positive probes replace the API tag at the intercepted start boundary: containers still consume the previously validated IDs, not the replacement tag. The suite also passes pin-overlay tamper refusal before start.

Independent pre-init/start corruption coverage comprised **24 scenarios**: two stages (cached and post-build/pull), six services, and two faults (environment preload and entrypoint). All refused with zero `up` submissions and zero fixture containers created. Cached pre-mutation refusals release the own lock; post-build/acquisition refusals retain the mutation receipt/HOLD. This is the intended distinction between a read-only refusal and an uncertain/mutating workflow, not an automatic rollback.

### Secret, isolation and failure boundary recheck

- Independent positive probes with CVE off and on verified exact six-service image-only overlays, every selected image inspected before start, stable own JWT across status/stop/restart, no JWT in argv or launcher logs, and no JWT in profile/image/CVE overlays. Config and build receive the sentinel; final start receives the own synthetic secret; other engine operations receive no JWT substitution.
- A separate injected post-submit endpoint failure retained a **secret-free receipt and HOLD**, with no success message or automatic cleanup. The passing suite retains timeout, replaced/stale lock, missing/unsafe established JWT, pinned public CVE and storage-persistence coverage. No restore/recovery implementation is newly approved.
- `runDocker()` still uses bounded `execFile` argv execution and withholds raw failures (`scripts/local-stand.mjs:76–83`); the CLI wrapper still emits fixed safe diagnostics. Raw Docker inspect/status return values remain secret-bearing in memory and must not be dumped. The redaction approval is for the launcher CLI output/artifacts, not arbitrary caller logging of its returned inventory.
- The unchanged Compose model retains the fixed own namespace, named volumes, networks, loopback port 8081, RO public CVE mounts, resource limits and commands. No new old-stand/private-key/JWT mount, legacy lifecycle operation, volume deletion, import, reset or forced-unlock path was introduced by the remediation.
- The current **public** root `.gitignore` and `.dockerignore` now contain the coordinator's `.local-public-images/` exclusion, and retain legacy private-state exclusions. A direct call to `checkIgnores()` on the repository root passed; it only checked public ignore policy and override-path existence. Unlike at the original review, the missing-ignore gate is no longer an outstanding source prerequisite. This guard-only check did not invoke the launcher, Docker or activation loading, or inspect/create private state. Keep these exclusions and the override prohibition intact.

### New bounded evidence

Commands ran from `diplom` with `env -i`, a literal tool PATH, and `/tmp` for fixture storage where needed:

```sh
node --test scripts/test_public_image_stand.mjs
node --check scripts/public-image-stand.mjs
node --check scripts/test_public_image_stand.mjs
```

- **42 tests passed, 0 failed/cancelled/skipped/todo**, exit 0; reported duration **1.67 seconds**, 30-second outer bound. This is the isolated suite only, not the author's combined 218-test run.
- Both syntax checks exited 0 without diagnostics, 10-second bound.
- Two additional independent in-memory probe invocations each exited 0 within a 30-second bound. The first replayed the original four probes with corrected expected outcomes and expanded the pre-start gate: matching image/container environment rejection (four settings); cached-entrypoint refusal; mixed projected-name refusal (nine cases); Dockerfile override refusal (four paths); and the 24 all-service/stage/fault scenarios above.
- The second checked endpoint binding (seven cases: default/named selectors across up/status/stop plus explicit-host resolution bypass), immutable-ID/tag substitution and secret handling with CVE off/on, and post-submit endpoint-failure HOLD. All assertions passed. Synthetic endpoint changes are strings supplied to injected runners, not context switches or network requests.
- Only fixture setup functions were loaded from the current test source into memory; the author's new test registrations were not used as the independent probe assertions. Actual launcher validators/orchestration were imported unchanged. All lifecycle calls used injected runners with no Docker fallback. Temporary synthetic state and canaries were confined to disposable roots outside the repository, and cleanup ran in `finally`. No test/probe source file was written.

No real Docker/client/context operation, network request, real launcher CLI invocation, private environment/config/key/JWT/database read, native/browser check, broad/full suite, staging or commit was performed. All secret reads described above refer to generated synthetic fixture state, never the project's private state. The author's red-before-fix and combined-suite claims were not independently replayed here and are not added as fresh reviewer evidence.

### Remaining qualification, not reopened R1–R4

Before any separately authorized native qualification, retain the existing requirements for an untouched old stand, trusted immutable source/build inputs, no concurrent direct-Compose/administrator mutation, and human reconciliation of any HOLD. A Unix endpoint is not physical-daemon attestation; image metadata/labels are not image-content authenticity. Effective context policy, overlays and source files must remain stable through submission under that trusted-workspace assumption.

Native validation must still establish actual upstream image/default compatibility, Compose consumption of the pinned engine IDs, resource/cgroup/tmpfs and nested RO DB behavior, auth/origin/issuer and browser isolation, owner-scoped persistence, public acquisition/Trivy readiness, fresh authenticated CVE evidence when enabled, and any separate own-target restore rehearsal. Do not weaken strict checks to make an incompatible daemon pass, remove locks to retry, or use legacy data/credentials for proof.

**Final re-review disposition: R1–R4 remediation APPROVED for the exact source/offline scope above; no open remediation blocker found. Real-daemon launch, native qualification, restore correctness and production acceptance remain NOT APPROVED / NOT TESTED by this review.**

---

## Independent follow-up: native metadata compatibility and explicit build-only reconciliation — 2026-10-18

### Scoped decision and factual boundary

**QUALIFIED SOURCE APPROVAL:** no blocking correctness/safety finding was identified in the reviewed metadata compatibility changes or the narrowly gated `reconcile-build-only --ack-no-services` implementation at the hashes below. The command is an appropriate *candidate* for the reported failed first build **only if the operator independently establishes every command precondition below and the command's own checks succeed**. This is not a determination that the actual private state is eligible, not an invocation, and not launch/native/production acceptance.

The coordinator/user reports that the real first isolated up built four new images, failed during image-policy validation before image selection completed or service startup, and retained the old-format phase `build-pull-start-outcome-unconfirmed`; public container/volume/network projections were zero; the original engine was Docker Desktop on its Unix socket; the original `dip-local-full` remained running and untouched. These are **supplied operational facts, not observations made by this reviewer**. No real marker, JWT, profile, environment, private directory, image or daemon was inspected to confirm them. The matching failure reproducer supports plausibility but is not historical execution evidence by itself.

**Important update to earlier operational guidance:** leave the original stand running **as found**, untouched. Earlier review text concerning a stopped original stand is historical context, not an instruction to stop it now. Neither reconciliation nor a later isolated retry authorizes any operation on `dip-local-full`, `dip-auth-stand`, their locks, volumes, databases, keys or JWTs.

### Exact reviewed inputs

Independently computed SHA-256:

```text
333c24cf36267500cd3986ab7c98076554e3b9498a8f0c3c816335250c91d1fd  scripts/public-image-stand.mjs
9c4cbf2918d11894c37a7cbf43e8493da6a0481712f696ac169421c6629acae6  scripts/test_public_image_stand.mjs
fa562e64f4feb6d9f366bc3bf14a7b0f3773fbc00e97e7e153a7ed1f52f6cc99  server/deploy/compose.public-images.yaml
2064bc9cb093be7ef621ae9fc17899a3974282794942b9fbeb5c95907496544c  docs/public-image-isolated-stand-20261018.md
```

Launcher/test/Compose identities match the current handoff. The Compose source remains unchanged from the original review. Prior review history before this append is **32,307 bytes**, SHA-256 `d57f3d7d47df0e022c88e650274f81f19668fc6b2bf1ab44087184a3ed9134fa`; this delivery checks preservation of that exact prefix and unchanged reviewed input hashes. Only this review document is edited.

### Metadata changes: narrow compatibility, not permissive fallback

Source: `scripts/public-image-stand.mjs:121–155,251–315`.

- Gateway `LANG` is no longer required, but if present must still be exactly `C.UTF-8`. Required Python version/key/hash metadata, fixed PATH rules and the rejection of unexpected environment keys remain. The change does not admit arbitrary locale values or startup hooks.
- Only Linux Node API/worker roles may use boolean `ArgsEscaped: true`; false/absence remain accepted. Malformed/non-boolean forms and true on other roles refuse. Linux image identity, exact array commands and entrypoints are still checked; no shell/string-command bypass was introduced. Both image and container validation apply the role restriction.
- Web working directory is independently fixed to `/`, rather than accepting any observed directory. Other roles retain their fixed directories; web `/tmp`, empty or alternate directories refuse.
- Compose normalization accepts only inherited `entrypoint: null` and genuinely empty object IPAM. Explicit empty entrypoint arrays, nonempty IPAM, and IPAM arrays/scalars refuse. The normative composition, resource limits, own storage/network names and loopback publication were not relaxed.

The independent metadata probes passed these intended shapes and rejected hooks across all six roles, invalid LANG, Windows Node images, non-Node true flags and alternate web directories. This validates policy logic on synthetic metadata; it does not independently authenticate the coordinator's actual images or establish that no further native compatibility issue remains.

### Reconciliation boundary reviewed

| Required property | Source and reviewed behavior |
| --- | --- |
| **Explicit, new-stand-only action** | Exact CLI command/one exact ack flag are required (`:681–687`). Missing state/profile/JWT is never provisioned. State/control/audit paths are confined to `.local-public-images`; no legacy lock/lifecycle operation is used. Ordinary up/stop never dispatch reconciliation (`:234–242`). |
| **Exact original phase and no later-stage evidence** | `buildMarker()` (`:470–476`) accepts canonical version-1 own-project `up` markers with phase exactly `build-pull-start-outcome-unconfirmed`, plus only an optional valid matching Unix endpoint. The original lock must contain **only** `mutation.json` (`:552–555`). A start-submission file, extra lock file, image pins, pending pins or unexpected state excludes reconciliation (`:578–587`). Missing/malformed/linked/wrong-mode evidence is not repaired. |
| **Source checked before Compose indirection** | The JSON-compatible Compose source is captured bounded/no-follow and independently validated before config rendering (`:454–464,563–566`). The exact reviewed JWT placeholder and relative build contexts are required; env-file/extends/foreign-context/extra-authority changes refuse before Compose can open such references. Own CVE overlay must be exact; disabled mode refuses an unexpected overlay. |
| **Own key/profile/state identity** | `captureFile()`/directory checks (`:438–452`) retain inode/device/mode/content stamps. The existing own JWT must already be a single-link owned mode-0600 regular file of exactly 96 lowercase hex characters. It is only checked in memory, never regenerated, copied, placed in Docker child environment or recorded by value/hash. Profile, JWT, marker, source, state/control directories and public CVE metadata are rechecked through the transaction. Same-byte file/directory replacement is not accepted as preservation. |
| **Local endpoint and honest legacy provenance** | One validated Unix endpoint is pinned for all later calls. A marker with an endpoint must match exactly. An endpoint-less marker is intentionally accepted only under the explicit operator acknowledgment, and the new receipt says `operator-acknowledged-legacy-marker`, not `recorded-match` (`:594–595,619–620`). The archive does not modify the legacy marker to invent an endpoint. |
| **ZERO own resources, including stopped/foreign/mislabeled collisions** | `emptyNamespace()` (`:515–523`) uses all-container/name/project-label projections and volume/network projections. Any own namespace name or isolated project label refuses, even if foreign/unowned or stopped. No container/volume/network inspect or Env read is submitted. Ordinary unrelated original-stand projections are skipped, not inspected or operated. |
| **Exactly four validated own built images, no external references** | `builtImageIds()` (`:525–543`) requires exactly the four own tags, each independently validated, one exact RepoTag, no RepoDigests, no foreign project/wrong-service labels, and four distinct immutable IDs. All-container `ancestor=<ID>` projections must be empty; referenced containers are never inspected/stopped. Missing images, extra tags, alias/digest/shared references and unsafe defaults refuse. BusyBox need not be present for this build-only archive; all six selections including BusyBox remain mandatory before a later service start. |
| **Repeated read-only Docker proof** | Proof runs before intent and at subsequent archive/commit boundaries. Image IDs must remain identical, and namespace/resource/reference checks repeat (`:597–604,626,633,643`). One monotonic 60-second Docker budget bounds all calls; individual calls are at most 30 seconds, with no retries or endpoint re-resolution. Allowed operations are metadata/context resolution, projections, four own image inspections per round and sentinel-only Compose config. No build/pull/start/stop/exec/delete/data-copy operation occurs. |
| **Archive, not erasure or automatic unlock** | A distinct exclusive reconciliation guard excludes ordinary lifecycle. Durable intent and acknowledgement precede atomic rename of the **original directory** into a new audit archive (`:608–632`). Original marker bytes and lock/marker identities are preserved. `HOLD_PRESERVED` remains the original outcome; `NOT_EXECUTED_SERVICES` belongs to the acknowledged reconciliation, not successful startup or an authenticated proof of all prior history. |
| **Completion and exclusion barrier** | Completion links original marker and acknowledgement hashes; exclusive writes and explicit directory fsyncs surround record creation and both lock-directory renames (`:634–657`). A failure before acknowledged commit retains original/audit evidence; a failure during guard release attempts to restore only that exact guard barrier. Incomplete/tampered histories block ordinary lifecycle even without the normal lock (`:478–514,660–674`). A pre-intent refusal can release only this call's verified empty temporary guard, never the original HOLD. |
| **No silent history recovery/replay** | History is bounded to 32 archives and structurally/hash/identity checked. Missing/partial/tampered entries refuse. No transaction is automatically resumed or stolen. Lost output after successful commit is reported as committed with acknowledgement unavailable, not rolled back or blindly replayed. |
| **Future start distinction** | New mutation markers record the selected endpoint. Before any future start submission, `start-submission.json` is written and fsynced (`:762–767`), excluding this narrow reconciliation even if resources were subsequently deleted. This improves future evidence; it does not retroactively prove the older invocation never started services. |

Independent synthetic success probes checked original directory/marker identities after rename, byte-identical failure history, unchanged JWT/profile identity and content, secret-free receipts/output, matching receipt hashes, four proof rounds and 16 own-image inspections, and no replay. Fifteen unsafe eligibility scenarios refused without service operations or archive completion. Seven injected checkpoint failures preserved original evidence and prevented ordinary `up` from completing/clearing reconciliation.

### What the acknowledgment can and cannot establish

The current census and image-reference checks establish only what the chosen daemon reports **during this command's proof rounds**. They cannot prove that resources never previously existed, that a prior start was never submitted and then removed, that an old daemon has not been reset/replaced, or that a timed-out mutation has finished. A Unix URI identifies the selected socket path, not a cryptographically identified historical daemon.

For the endpoint-less original marker, `--ack-no-services` is therefore a substantive operator assertion of **both**:

1. the original attempt terminated before any service-start submission, with no outstanding mutation that could later create services; and
2. the selected original local engine/socket is the one on which that attempt ran, not another empty daemon/context.

That legacy assertion is explicitly represented in the receipt. The routine cannot independently validate it from the old marker. The reported failure reproducer plus present zero lists are supportive but insufficient on their own; the coordinator must corroborate the original invocation's control-flow/failure boundary and engine continuity from its operational evidence. If that cannot be established, **retain HOLD and obtain a different scoped reconciliation review**. Do not label receipt creation as historical proof or rewrite the original failure to PASS.

### Preconditions for a separately authorized operator invocation

The reviewed command, **not executed by this reviewer**, is:

```sh
node scripts/public-image-stand.mjs reconcile-build-only --ack-no-services
```

Qualified approval of that command's use is conditional on **all** of the following:

1. **Exact reviewed source and independent authorization.** Run from the canonical `diplom` repository using the reviewed code/test/Compose identities above. Keep root private-state exclusions and no-override policy intact. Do not add env files, direct Compose overrides, forced flags or bypass code. This review does not authorize the agent to operate live state.
2. **Original invocation and engine established.** For this old marker, explicitly confirm the pre-image-policy/pre-start failure on the original Docker Desktop Unix endpoint, and that no earlier start or unresolved background mutation can still execute. Confirm the selected endpoint is that original engine; a current empty daemon or a matching reproducer alone does not satisfy this. If an endpoint is recorded in any eligible newer marker, it must also match literally. Do not switch/reset/recreate the engine to obtain zero resources.
3. **Narrow eligibility, not a cleanup workflow.** Only the exact original build-phase marker, own existing canonical profile/JWT/pinned CVE state, no service-start evidence, no pins/pending/unknown state and no prior incomplete reconciliation are acceptable. The command must find zero own containers (including stopped), volumes and networks, and exactly four clean, validated, unshared own build images. A refusal is not permission to delete a resource, remove a pin/marker, rewrite metadata or widen the allowlist.
4. **No concurrent operations.** Quiesce operations for this new stand and its source/endpoint/image tags during reconciliation. Existing original stands may remain running untouched; do not stop/restart/inspect them for this workflow. These filesystem locks cannot exclude Docker administrators, direct Compose users, socket replacement or uncooperative filesystem edits.
5. **Preserve evidence and credentials.** Do not manually remove either lock, copy/rotate the own JWT, import old data, or alter original/archived receipts. The command itself may read the *new stand's own* protected state to verify identity; this reviewer has not done so. Never publish raw JWT/Env or full Docker inspect output.
6. **Review completion before considering anything else.** Expected success is one complete protected archive with original bytes/inodes retained, `HOLD_PRESERVED`, acknowledged `NOT_EXECUTED_SERVICES`, correct endpoint provenance and matching completion hashes; no service operation is submitted. A refusal/interruption requires preserving all evidence and a new scoped assessment, not an ordinary-up retry or force-unlock. Lost output after committed completion requires reviewing receipts, not replaying the command.

Only after independent confirmation of a complete committed reconciliation may the coordinator consider a **separate explicitly authorized** isolated `up --build`. It still must validate all six image selections, use immutable-ID no-build/no-pull start, and pass runtime guards. Reconciliation is not a restart request, DB restore, data migration, scanner readiness check, or native/production acceptance.

### Fresh bounded offline verification

Run from `diplom` with `env -i`, literal tool PATH, and `/tmp` for synthetic fixture storage where needed:

```sh
node --test scripts/test_public_image_stand.mjs
node --check scripts/public-image-stand.mjs
node --check scripts/test_public_image_stand.mjs
```

- **65 passed; 0 failed, cancelled, skipped or todo**, exit 0, reported duration **3.60 seconds**, 30-second outer bound.
- Both syntax checks passed without diagnostics, 10-second bound.
- An additional independent in-memory invocation passed three synthetic reconciliation success/provenance cases (legacy/recorded endpoint, CVE off/on), fifteen eligibility refusals, seven interrupted transaction checkpoints, and metadata acceptance/rejection probes. It loaded only fixture/setup functions, not the test registrations, and imported the actual implementation unchanged. Its injected runner allowlisted only context inspection, list projections, own image inspection and Compose config, checked the pinned endpoint and bounded timeouts, and rejected all other operations. Only sentinel substitution was allowed for config; no own synthetic JWT entered the runner environment. All temporary state was generated outside the repository and cleaned in `finally`; no probe file was added.
- Interrupted checkpoints are **exception injections**, not SIGKILL, real daemon failure, filesystem power-loss or crash-recovery experiments. Source inspection confirms explicit fsync/rename ordering, but this is not a proof of the live filesystem's durability semantics or exclusion against a concurrent administrator.
- The combined 241-test run and the author's earlier red-before-fix claims were **not** independently rerun. No full/broad suite or native test was run.

**No real Docker, network, actual reconciliation/launcher CLI invocation, private directory/state/key/JWT/database read, environment-file read or environment discovery, staging or commit was performed.** All state/secret/receipt accesses in executable checks were confined to synthetic temporary fixtures. Actual live command eligibility, daemon history, original-stand status and real image defaults remain coordinator-supplied/unverified by this reviewer.

**Final follow-up verdict:** metadata compatibility and build-only reconciliation source **QUALIFIED APPROVED** at these hashes, with no blocking source finding in the assessed scope. Use of the command is conditional on the explicit original-attempt/original-engine acknowledgment and all machine/operator preconditions above. **Actual private-state eligibility, live reconciliation completion, later isolated launch, restore/native/scanner/browser/resource correctness and production acceptance are NOT established by this review.**

---

## Narrow compatibility delta: Linux Python ArgsEscaped and local containerd self-digests — 2026-10-18

**Verdict: QUALIFIED SOURCE APPROVAL for these two changes; no blocking safety issue found in this delta.** All original-attempt/original-engine acknowledgment, zero-resource, state-identity, image-reference, archive/HOLD and no-concurrency conditions from the preceding review remain required. This is not confirmation of actual private-state eligibility or permission for this agent to invoke reconciliation/startup.

Reviewed SHA-256:

```text
b692d656e6d6e408f630c42abca8b120f6189876c1bb336c885c3a9fce6ba827  scripts/public-image-stand.mjs
a61ebd6e578dd052386d668e9a0ea9ac9836ec2f462576a77728d3b342c4cd0d  scripts/test_public_image_stand.mjs
```

**Scope check:** reversing only the two stated implementation changes and their explanatory comments **in memory** reproduced the preceding reviewed implementation hash `333c24cf36267500cd3986ab7c98076554e3b9498a8f0c3c816335250c91d1fd` exactly. No implementation file was written. Thus endpoint binding, phase/start/pin gates, namespace/reference checks, credential preservation and durable archive logic are unchanged by this delta. Compose and the runbook also retain their previous hashes. Prior review history before this append is 50,538 bytes, SHA-256 `2020fd3f0dcc1935132b31d9177b4c8b374b39df82f6be85f49c871ba48930cf`; its exact prefix is preserved.

### Checks and qualifications

- **Python egress flag (`public-image-stand.mjs:260–290,298–315`):** boolean `ArgsEscaped: true` now also passes for the reviewed **Linux egress** role, as it already did for API/worker. False/absence remain accepted. This is not general truthiness: strings, numbers, null, arrays and objects refuse. True still refuses for web/initializers, and Windows images refuse. The same helper covers image and container validation. Exact commands/entrypoints, working directory, user, PATH/environment allowlists and startup-authority checks remain intact. Independent probes accepted Linux egress true and rejected Python/preload/Node hooks, alternate entrypoint and malformed flags; this did not become an environment or shell-execution bypass.
- **Local self-digest (`:525–546`):** the added nonneutral case is exactly the singleton array `["dip-public-images-<current-role>@" + image.Id]`. `validateImage()` has already validated the Linux image and strict immutable `sha256:<64 lowercase hex>` ID. Both repository/role and the entire digest string must match; no prefix, registry normalization, different hash, wildcard or extra entry is accepted. A different legitimate manifest digest is still not admitted by this exception. Existing neutral handling is unchanged.
- **Other references remain forbidden:** the single exact own `:local` RepoTag requirement, ownership/service-label checks, empty ancestor-container projections and four-distinct-ID requirement remain in place. Foreign repository, another own role's repository, wrong hash, extra/duplicate digest, registry-qualified alternative, scalar/object digest shape, trailing newline and extra foreign tag all refused in independent probes. The accepted digest is local metadata correlated with the already validated ID, **not publisher authentication or proof of historical daemon identity**. Reconciliation still uses immutable IDs and read-only metadata operations, not digest-triggered pulls.
- **Original evidence:** synthetic refusals preserved the original mutation bytes and left HOLD. Synthetic successes with neutral or exact-self digests retained the original failure in its archive, `HOLD_PRESERVED` and legacy endpoint provenance, with no service operation or secret output. The original marker is not rewritten to PASS. As previously reviewed, a late failure can occur after atomic archival; the archived original evidence and exclusion/history barriers, not necessarily the original pathname, preserve HOLD.

### Fresh bounded verification

A clean child environment and disposable temporary fixture roots were used:

```sh
node --test --test-name-pattern='reviewed Docker 28 Linux metadata|reviewed metadata allowances|exact local containerd self-digests|refuses missing, extra, unsafe or foreign-referenced images' scripts/test_public_image_stand.mjs
node --check scripts/public-image-stand.mjs
node --check scripts/test_public_image_stand.mjs
```

- **4 selected registered tests passed**, zero failures/cancellations/skips/todo, exit 0, about 0.27 seconds, 30-second bound. The new digest regression includes the four stated variants: exact-self success, foreign-repository refusal, wrong-hash refusal and extra-digest refusal. Updated metadata tests cover image/container egress true and role/type/Linux restrictions.
- Both syntax checks passed, 10-second bound.
- Additional independent in-memory probes passed neutral/exact-self reconciliation with egress true, ten digest/tag rejection cases, and role/type/Linux/hook/entrypoint checks. Only fixture/setup functions were loaded, not test registrations. An injected runner restricted calls to context inspection, list projections, own image inspection and sentinel-only Compose config; no Docker fallback or service operation was permitted. Temporary fixture cleanup ran in `finally`.
- The entire isolated suite and broader suites were **not rerun** for this two-change review. The prior 65-test result applies to the prior hashes, not as fresh evidence for this revision.

**Nonblocking documentation follow-up:** `docs/public-image-isolated-stand-20261018.md:95` still describes Node-only true flags, and `:164` still excludes all nonneutral digests. Update those descriptions and the source/test handoff hashes before relying on that runbook as an exact current-policy reference. This appended note supplies the reviewed exceptions without silently rewriting prior review history; the runbook itself was not changed here.

The coordinator's reports of current valid configuration/profile/images, zero services and untouched original marker remain **unverified operational input**, not observations from this review. No real Docker, network, live reconciliation/startup, private environment/state/key/JWT read, environment discovery, staging or commit occurred. Only this review document was appended; implementation/tests were read-only. **The previous conditional command preconditions are unchanged; actual-state and native/production approval remain out of scope.**

---

## Independent scoped review: two-network partial-start reconciliation — 2026-10-18

### Verdict and operational limits

**QUALIFIED SOURCE APPROVAL for `reconcile-network-only --ack-no-services` at the hashes below. No blocking source issue was found in the reviewed narrow eligibility/archival path.** The command is suitable for the reported two-network partial-start case only when the coordinator independently satisfies the operator preconditions and every machine guard passes. This review does not invoke the command or establish actual private-state eligibility.

The user/coordinator reports that nine separately authorized empty retained CVE networks were removed by exact IDs, unrelated/old holders were untouched, and the new stand currently has zero containers/volumes, exactly its empty `auth_internal` and `registry_uplink` networks, an endpoint-bound start HOLD, start-submission evidence and saved image pins. Those are **reported operational facts, not reviewer observations**. This command neither performs nor authorizes any deletion. Its receipts do not infer, attest or retrospectively approve the nine prior releases, and do not prove that services never briefly existed. Leave all original/unrelated stands and holders untouched in their current state.

The separately authorized coordinator command, **not run here**, is:

```sh
node scripts/public-image-stand.mjs reconcile-network-only --ack-no-services
```

Before invoking it, the coordinator must confirm the original launcher has returned, that outstanding daemon work has settled after **long operator-observed quiescence**, and that no concurrent launcher, resource writer, direct Compose/admin operation, source/pin edit or endpoint change is active. The single acknowledgment explicitly supplies that attestation; the program cannot derive it from repeated snapshots or a timed-out client. The selected Unix endpoint must match both original records. If any point is uncertain, retain HOLD rather than invoking recovery or changing evidence to manufacture eligibility.

### Exact reviewed identities

```text
3dd8fb9116c1f33d9acca50aecb29eb46d796cedbcb62f9dd5f5dcadb700f761  scripts/public-image-stand.mjs
fb1289dea4a811cace49f161b77db92d7506c1e7d1c2f3e88111ec5b5750accf  scripts/test_public_image_stand.mjs
fa29f1d0673c0d3d2675348ca42986dab890c727203091b22b8c4a172d3f152a  docs/public-image-network-only-operator-20261018.md
fa562e64f4feb6d9f366bc3bf14a7b0f3773fbc00e97e7e153a7ed1f52f6cc99  server/deploy/compose.public-images.yaml
```

These were independently computed and match the operator handoff's source/test hashes. The unchanged Compose remains the same fixed composition. Prior review before this append is **56,998 bytes**, SHA-256 `683cd1d8de3e6cb79fbd5b15784bd164c3b2f6af74815924cf01a71ebcf73107`; that exact prefix is preserved. Only this report is edited; implementation, tests and operator note are read-only.

### Narrow proof and preservation checks

| Boundary | Reviewed source/result |
| --- | --- |
| **Separate explicit command, not broader build-only recovery** | CLI requires exactly `reconcile-network-only --ack-no-services` (`public-image-stand.mjs:841–850`). Ordinary up/stop do not call recovery. Both recovery guards and original operation HOLD exclude ordinary lifecycle (`:262–270`). Build-only eligibility remains zero-network/no-start/no-pin eligibility; it is not broadened to this case. |
| **Exact phase and mandatory endpoint** | `networkStartMarker()`/`startSubmission()` (`:506–516`) accept only canonical own-project version-1 `up`, phase `start-outcome-unconfirmed`, and the exact corresponding `service-start-submission` record. Both require the same recorded Unix endpoint and it must match the resolved endpoint. No legacy endpoint-less fallback, build-phase marker, extra record or alternate phase is accepted. |
| **Stable own state, key and source** | The shared transaction captures owned/no-follow/single-link protected files and exact directory identities (`:678–744`). It requires profile, existing JWT, canonical six-service pin file and exactly the expected state entries. Profile/JWT/pins/source/marker/start/CVE identities and bytes are repeatedly verified, including after archival. Missing state is not provisioned, the key is not regenerated/copied/hashed into receipts, and current activation/private signing keys are not consulted. Source validation precedes Compose file indirection. |
| **ZERO containers and volumes** | `networkOnlyNamespace()` (`:563–580`) scans all containers, including stopped ones, and volume name/project projections. Own-prefix or own-project-label rows refuse, including foreign/mislabeled collisions, before container/volume inspection. No old container Env/JWT is fetched. |
| **Exactly two expected empty networks** | Network candidates must be exactly `dip-public-images_auth_internal` and `dip-public-images_registry_uplink` before any network inspect. Only those names are inspected. `emptyOwnNetwork()`/`networkPairSnapshot()` (`:517–562`) enforce distinct stable IDs, bridge/local scope, correct internal flags, empty endpoint tables, reviewed labels, no custom options/authority/peers/services, and disjoint canonical private IPv4 subnet/default-gateway pairs. Extra/missing/mislabeled networks, occupied endpoint tables or custom/overlapping IPAM refuse. This checks reported current membership/configuration, not absence of future writers or historical attachment. |
| **Images, pins and reference checks** | `builtImageIds()` requires exactly four own tags, independently safe image defaults, one exact own RepoTag, neutral or exact own-self RepoDigest, correct project/service labels, distinct IDs and zero running/stopped ancestor-container references (`:654–675`). Network recovery additionally matches all four IDs to saved pins and independently selects/validates all **six** service tags, including BusyBox, against the six pins (`:745–758`). Arbitrary pin IDs are never used as inspect targets. BusyBox sharing is explicitly allowed; it does not authorize aliases/references to the four own application images. Pinned Compose config must match the normative model. |
| **Repeated proof on one endpoint, no Docker writes** | One validated literal Unix host is pinned into every subsequent call; context/TLS overrides are removed. A monotonic 60-second budget bounds the metadata calls, each at most 30 seconds. Four proof rounds repeat images/config/state checks, with network census/inspection at both ends of each round. Network/image identities and normalized network snapshots must remain equal. Calls are context resolution, projections, fixed-tag image inspections, only the two allowed network inspections, and sentinel-only Compose config. No build/pull/up/stop/create/connect/disconnect/rm/prune/exec operation is submitted. |
| **Archive and receipt, not PASS** | The original lock directory with **both** records is atomically renamed, preserving original bytes/inodes. Mode-protected exclusive records and explicit fsyncs bind endpoint, source/profile/CVE metadata, start hash/identity, pins/hash/identity, original lock/marker identities, JWT identity, four own IDs, six pins, network snapshots and nonce. The receipt says **`PARTIAL_NETWORKS_ONLY_NO_SERVICES`**, `originalOutcome: HOLD_PRESERVED`, and `operatorAttestation: LAUNCHER_RETURNED_AND_LONG_QUIESCENCE`; it does not convert the failed start to PASS. Completion links acknowledgement/original hashes. |
| **Interrupted transaction and history** | Original/audit evidence survives failures at archive checkpoints; the active guard or invalid/incomplete history blocks ordinary up/stop. Guard-release failure attempts only restoration of the same exclusion barrier, never force cleanup. A pre-intent failure may release only this call's verified empty temporary guard. Completed network history is separately schema/identity/hash/nonce/snapshot validated (`:589–643`); lost output after commit does not roll back evidence. No automatic resume, stale-guard theft or recovery by normal up is added. |

The new stand-owned Docker adapter (`:39–63`) uses bounded `execFile` argv invocation and emits fixed diagnostic categories only, discarding raw failure stdout/stderr/cmd/cause. Categories are hints, not retry/unlock authority. Its callback/timeout tests use injected executors; none spawned Docker during review. Successful raw inspection/config results remain sensitive in memory and must not be dumped by callers.

### Fresh independent evidence

With a clean child environment (`env -i`, literal PATH, `/tmp` fixture storage), bounded commands ran:

```sh
node --test scripts/test_public_image_stand.mjs
node --check scripts/public-image-stand.mjs
node --check scripts/test_public_image_stand.mjs
```

- **84 tests passed; 0 failed/cancelled/skipped/todo**, exit 0, reported duration **5.77 seconds**, 30-second outer bound. Both syntax checks passed, 10-second bound. The reported combined **260-test run was not rerun** and is not fresh reviewer evidence.
- Independent in-memory probes loaded only fixture/setup functions and imported the unchanged implementation. Their injected runner rejected all operations except projections, context resolution, known image tags, the exact two network names, and sentinel-only Compose config; it checked endpoint binding and bounded timeouts. CVE-off/on success retained both networks unchanged, preserved JWT/profile/pin identities/content, archived original directory/marker/start inodes and bytes, checked partial/HOLD/provenance/completion hashes and excluded JWT value/hash from receipts. Sixteen allowed-network inspections demonstrated the repeated two-ended network proof across four rounds.
- Twelve independent refusals covered wrong phase/endpoint/start evidence, application/initializer pins, image alias/writer references, containers/volumes/extra networks, foreign endpoint membership and custom IPAM. Original marker bytes remained unchanged and no archive completion occurred.
- Three independent exception-injected interruptions (intent durable, original lock archived, guard archived) preserved both original records and blocked ordinary up/stop/build-only clearance before any Docker call. The 84-test suite additionally covers the other archive checkpoints and history tampering. This is **not** SIGKILL, filesystem power-loss, real daemon durability or race testing.
- All executable checks used disposable synthetic roots outside the repository, injected runners/executors and `finally` cleanup. No probe source file was added. No actual Docker/network operation, private-state/key/JWT/database/environment read, actual reconciliation/startup, broad suite, staging or commit occurred.

### Coordinator disposition

The current partial-state report is a legitimate candidate for this **different** recovery path, not permission to reuse build-only recovery or remove either network. Run only after explicit authorization and quiescence/endpoint confirmation, and allow the command to independently refuse any mismatch. Preserve all original/recovery locks and receipts on refusal/interruption. Never remove a network, pin, start record or lock to make this narrow predicate pass.

A complete committed receipt records current partial-state proof plus the operator attestation. Review it before considering the operator note's **separate guarded `up` without rebuilding**. Reconciliation itself leaves both networks intact and performs no service execution. Actual start readiness, native/browser/Trivy behavior, resources/mounts, restore correctness and production acceptance remain unapproved/unproved by this source review.

**Final disposition: network-only reconciliation source QUALIFIED APPROVED at the identities above, conditional on all original-endpoint, returned-launcher/long-quiescence, no-concurrency and machine eligibility checks. No actual state was certified, no reconciliation was invoked, and no historical network deletion/release is inferred or authorized by this review.**

---

## Independent review: running services after a failed rebuild — 2026-10-18

### Clear decision

**APPROVE the source of `reconcile-running-build-only --ack-build-failed-before-start` for the narrow operator-attested build-before-start failure, at the identities below. No blocking defect was found in the assessed admission, target inspection, pin/resource preservation or archive transaction. BLOCK invocation if the original failure stage, absence of lifecycle submission, original endpoint, or daemon quiescence is uncertain.**

This is not unconditional live-state clearance. The coordinator reports a known web build failure after API/worker tags changed, while services still use their prior pins. This reviewer did not inspect the real failure, process state, private files, daemon or data. Current healthy snapshots and a build-phase marker cannot independently establish that historical account. The command's operator attestation is a necessary trust input, not machine-generated proof.

The exact separately authorized command is:

```sh
node scripts/public-image-stand.mjs reconcile-running-build-only --ack-build-failed-before-start
```

It must not be substituted for the zero-service modes, used as a generic unlock, or followed by an automatic lifecycle retry. It does not fix the failed web build, complete a deployment or qualify newly built images for execution.

### Reviewed sources and diff limitation

Independently computed SHA-256:

```text
f3d092658fd3ddce83092f4caae6c750b041b53a91fad68811dda3a404dfef60  scripts/public-image-stand.mjs
bd63d131ecc82b4f8e8385a377c8ec3e4594a917c5d9a2df984957fc31328550  scripts/test_public_image_stand.mjs
c27c1fd35cb8987c926d045ff1872433bb4923b30b219bf6af2c338a74230ba5  docs/public-image-running-build-only-operator-20261018.md
fa562e64f4feb6d9f366bc3bf14a7b0f3773fbc00e97e7e153a7ed1f52f6cc99  server/deploy/compose.public-images.yaml
```

The source/test hashes match the handoff; Compose is unchanged. Scoped Git diff/status inspection reports all three new review inputs as **untracked**, so Git supplies no tracked patch for them. This review therefore rests on the actual current implementation/test bodies and exact hashes, not a claimed clean branch diff or a claim that all surrounding code is unchanged.

The existing report before this append is **69,055 bytes**, SHA-256 `4d65a45bdcec1cfc0edb9c1daddf3938d5aa86b27262448cf0eda62486606eac`; the append preserves that exact prefix. Implementation/tests/operator note/Compose are read-only. Only this report is edited.

### Historical uncertainty: what remains unresolved by software

`runningBuildMarker()` (`public-image-stand.mjs:594–598`) requires the exact original canonical own `up` build/pull marker and a mandatory matching Unix endpoint. The operation lock may contain only `mutation.json`; any start-submission or extra record refuses. This excludes retained lifecycle evidence; it is not a durable historical `checkpoint=build` receipt. The older marker persists through later pre-start stages, and there is no prebuild container/control snapshot to compare against.

The receipt correctly preserves:

```text
operation: RUNNING_BUILD_ONLY_NO_LIFECYCLE_SUBMITTED
originalOutcome: HOLD_PRESERVED
startSubmission: ABSENT
prebuildBaseline: OPERATOR_ATTESTED
operatorAttestation: BUILD_FAILED_BEFORE_START_LAUNCHER_RETURNED_AND_QUIESCENT
```

**Do not interpret the operation name as independently proven historical non-execution.** It combines the operator's account with current validated runtime state and the fact that reconciliation itself submits no lifecycle operation. It cannot prove equality to a nonexistent prebuild snapshot, that a start record was never externally removed, or that an earlier transient resource never existed. Successful archival removes the *active* operation/recovery barrier and admits future explicitly requested lifecycle work; it preserves the historical HOLD and original bytes rather than proving all uncertainty vanished.

The operator must independently establish that the identified launcher actually returned at **build**, that this failed attempt never submitted start/stop/recreate, that pins/marker/start evidence were not externally rewritten/deleted, and that outstanding build work has settled with no concurrent builder/tagger/lifecycle/topology writer. A timeout, healthy services now, changed API/worker tags, or absence of `start-submission.json` alone is insufficient. If those assertions cannot honestly be made, this review's decision is **BLOCK**, not permission to accept a new baseline silently.

### Current-state proof and target-only inspection

- **Exact census before resource/image inspect (`:619–640`):** all name/project projections must contain exactly the six isolated containers, two own volumes and four own networks, with correct project labels. Missing/extra/foreign-name/mislabeled rows refuse before full inspection. No legacy container or environment is followed.
- **Saved runtime identities, not current tags:** the protected canonical pin file supplies the six immutable runtime image IDs. Those saved IDs are the intended image-inspection targets, including untagged prior own images; each passes independent image ownership/default policy and own-only reference checks. Both initializer pins must agree and the four application IDs must be distinct. This relies on the operator establishing that the saved pins are the original ones; format/identity fences during reconciliation cannot authenticate their prebuild provenance.
- **Substituted runtime images cannot redirect inspection (`:643–648`):** namespace image inspection is constrained to saved pin IDs or fixed own tags, and container `Image` plus `Config.Image` must equal the saved role pin. An arbitrary container image ID is refused before an image-inspect request for it. Current tag targets are checked separately by fixed own tag names.
- **Existing execution controls:** the established independent container policy still validates commands, image defaults, exact environment/own JWT match, public RO CVE binds, mounts, capabilities, resources, tmpfs, namespaces, networks and loopback port 8081. Only the actual own API environment is read to validate its own secret; raw Env is not output. JWT is removed from the cloned Config before calculating the runtime control hash.
- **Process evidence (`:601–609,650–655`):** four application services must be running with positive PIDs, successful state and no restart/dead/OOM/error flags; API health must be healthy with zero failing streak. Initializers must be successfully exited with PID zero. Container IDs, image IDs, PID/start/finish timestamps, restart counters, health status and secret-redacted control hashes are compared across proof rounds. This is Docker-reported current process identity, not an exec/host-process inspection, scanner-readiness proof or historical prebuild comparison. Dynamic health logs are deliberately excluded.
- **Storage and network membership (`:657–676`):** own volume local-driver/scope/labels, creation time and control records are checked and hashed; existing volume-consumer projections reject foreign users. Mountpoints are not opened. All four own network configurations must be default local bridges with the intended isolation and disjoint private subnets. Their exact endpoint IDs/names/network IDs must agree with the expected own container attachments, and foreign endpoints refuse. Network/volume control identities are compared repeatedly. Databases remain live; preservation means no recovery-induced write/migration/copy/reset, not frozen DB bytes or a consistent backup.
- **Partial tags stay separate (`:677–691`):** old pinned own images may legitimately be untagged after rebuilds. Both old IDs and current tag IDs pass the role/reference policy; only exact expected own consumers may reference them, so newly retargeted images must be unused. Exactly four own tag names are required; foreign tag/digest aliases refuse except the reviewed exact self-digest. The receipt stores `runtime.tagImages` separately from container images and `imagePins`. There is no pin write, retag, rollback, build continuation or tag promotion in reconciliation.

### HOLD, state and transaction behavior

The running mode has its own guard, exact acknowledgment and strict distinct receipt/history schema (`:693–783,818–994`). All recovery guards mutually exclude one another and ordinary up/stop. Build-only and network-only policies remain ineligible for this existing-services state.

Profile/JWT/pins/source/CVE bytes and inode/mode identities are repeatedly fenced on the original recorded/pinned endpoint. Pinned Compose config is rendered with the nonsecret sentinel and compared to the original normative model. Public CVE validation uses only own pinned public metadata/assets; no current activation/private signing key is loaded. Missing/linked/unsafe state is not provisioned or rotated. No live data file is opened by the runtime proof.

Four proof rounds compare the same current container/control/process/volume/network/tag snapshot. The shared transaction exclusively writes protected intent/acknowledgement/completion records, fsyncs records/directories, atomically moves the original operation directory into history preserving marker/lock inodes and bytes, and archives the recovery guard only after completion. Late drift or interruption retains the recovery barrier/incomplete history; ordinary lifecycle cannot complete it. Same-byte state replacements, original evidence tampering and incomplete/invalid history refuse. Lost output after successful commit does not erase or roll back durable records.

These are fail-closed current-state fences under a trusted/cooperative filesystem/daemon assumption. They are not an atomic transaction with Docker, proof against an administrator, proof that no event can occur between snapshots, or tested power-loss recovery. The 60-second total Docker budget and individual at-most-30-second calls have no retry/re-resolution. Reconciliation submits only context resolution, projections, known target inspections and sentinel-only Compose config—not Docker mutation, exec, start, stop, build, pull, tag, prune or data copy.

### Fresh bounded evidence

Commands used a clean child environment (`env -i`, literal tool PATH and `/tmp` fixture storage):

```sh
node --test scripts/test_public_image_stand.mjs
node --check scripts/public-image-stand.mjs
node --check scripts/test_public_image_stand.mjs
```

- **97 passed; 0 failed/cancelled/skipped/todo**, exit 0, reported duration **7.62 seconds**, 30-second outer bound. Both syntax checks passed, 10-second bound. The combined **273-test** run and author's historical red tests were not rerun.
- Independent in-memory probes, importing actual implementation but only fixture/setup functions rather than test registrations, passed CVE-off/on reconciliation with retargeted API/worker tags. They checked unchanged running resource records, unchanged profile/JWT/pin bytes and identities, original archived inodes/bytes, `OPERATOR_ATTESTED`/HOLD receipts, separate new tag IDs, linked completion hashes and exclusion of JWT value/standalone hash from receipts/output. No tag promotion occurred.
- Eight independent refusals exercised retained start evidence, start-phase marker, missing endpoint, arbitrary runtime image without following it, wrong own JWT, foreign volume consumer, foreign network endpoint and foreign image reference. Four further late changes to PID/restart/control/tag state retained the guard and blocked ordinary up. Two exception-injected interruptions after original-lock/guard archival preserved original evidence and blocked up/stop/zero-service recovery. The suite covers the remaining archival checkpoints and completed-history tampering.
- The independent runner allowed only context inspection, list projections, fixed own resource names, saved pin IDs/fixed own tags and Compose config. It checked pinned endpoint/bounded timeouts and permitted only the sentinel for config, never own JWT substitution. All other Docker operations were rejected. Generated state/canaries were confined to temporary roots outside the repository and cleaned in `finally`. No probe source file was added.

No Docker invocation/mutation, network request, actual reconciliation, actual stand/private-state/JWT/database/environment read, host-process discovery, broader suite, staging or commit was performed. All executable state/secret reads above concern synthetic fixtures. The Git commands were scoped read-only metadata/diff checks on the three public review inputs. No live eligibility or original operational evidence was certified.

### Remaining constraints and next operation

1. Use this command only for the identified, independently corroborated **build-before-start** failure, on the original endpoint and with original saved pins. Confirm returned launcher, settled daemon work, no concurrent writers and no removed/replaced evidence. Otherwise retain HOLD.
2. Leave the original stands/data/keys/JWTs and all unrelated resources untouched. Do not stop current isolated services to satisfy this mode; stopped/unhealthy/mismatched services are ineligible and require a separate review.
3. Preserve all locks/history on refusal or interruption. A complete receipt acknowledges the operator-attested build-only reconciliation; it is not PASS, a successful web build, DB restore/backup, proof of historical runtime continuity or new-image qualification.
4. **Do not run bare `up` as a supposedly harmless continuation.** Ordinary up intentionally selects current tags and can rewrite pins/recreate services using the partially rebuilt API/worker images. Recovery does not itself promote those tags, but it also does not change that later-up behavior. Fix/review the failed build and obtain separate authorization, compatibility/data-impact planning and native verification before any later lifecycle operation.

**Final decision: source APPROVED with the above operator-evidence constraints for the stated running-build-only case. Invocation is BLOCKED whenever lifecycle/build-stage or quiescence uncertainty remains. No automatic historical certification, live-state acceptance, subsequent tag promotion, deployment/native/restore/production approval is granted.**

---

## Independent review: replacement build, backup and redeployment — 2026-10-18

### Verdict: BLOCK this new command

**BLOCK `recover-build-and-redeploy --ack-unavailable-prior-images` at the reviewed hashes.** The overall replacement approach correctly distinguishes unavailable prior image evidence from freshly validated replacements, and contains substantial namespace/data/HOLD controls. However, its drain step submits new helper execution inside the unverified old worker, its backup helper starts before helper-runtime controls are validated, and its logical data fingerprint is not lossless for all SQLite integers. These gaps prevent approval of the requested trusted-helper-before-execution and full retained-data comparison guarantees.

Do not invoke this command, run a preceding unlock/reconciliation, or use ordinary up to bypass the refusal. Fix the findings in a separately authorized implementation change and re-review before live execution. This verdict concerns the new mutating replacement path at these hashes; earlier approvals were scoped to different commands and source identities and do not authorize this workflow.

### Exact reviewed inputs and preservation

```text
835687537c0fa2b0f284ae23d46fae22602f7daffd41cf0c97b57857c0965c73  scripts/public-image-stand.mjs
e650e64e914f9e6b78d569e8614ef73d218bb6931900b7afc22b57daaefb3b8d  scripts/test_public_image_stand.mjs
9a5cb470026227962309aa8281645e60301f5d34092d334eb25ff946b7d58f81  docs/public-image-recover-redeploy-20261018.md
fa562e64f4feb6d9f366bc3bf14a7b0f3773fbc00e97e7e153a7ed1f52f6cc99  server/deploy/compose.public-images.yaml
```

Hashes were independently computed and match the source/test handoff. The original report before this append is **83,438 bytes**, SHA-256 `dcd343a2cd4d283a2d6560f960ee07aa37203b4ad4521fae1efc4d50f95acaa7`; its exact byte prefix is preserved. Only this report is changed. Implementation, tests, operator note and Compose remain read-only.

### RDEP-1 — P1: drain executes unchecked old-image code before the trusted backup baseline exists

**Source:** `scripts/public-image-stand.mjs:1086,1303–1309`; operator note `:77–89`.

After stopping web and API, the controller submits:

```text
container exec <original-worker-ID> node -e RECOVERY_DRAIN
```

`RECOVERY_DRAIN` loads `better-sqlite3` from that original worker's filesystem. The stated premise is that its saved image metadata genuinely cannot be inspected. `priorRuntime()` validates the container's declared controls, but deliberately does not authenticate the old `node` executable, module loader or SQLite implementation. A readonly option and a literal SELECT constrain the *intended* driver call; they cannot establish the behavior or trustworthy result of code loaded from an unchecked image.

This introduces new code execution in the exact unverified image that the replacement workflow must stop relying on. It can also treat an unverified `{pending:0}` response as drain evidence. The existing worker is already running under the acknowledged prior-image risk; that is not independent verification of a newly submitted data-inspection helper or its effects. A mutation caused during this step would occur **before the trusted backup baseline**, so the later backup/content comparison could preserve the already altered state rather than detect it.

An independent injected probe confirmed the ordering with old worker image metadata absent: original web/API were stopped, the old-worker exec request was reached, and no backup helper/copy had yet been submitted. The probe intercepted the request; no actual executable, data mutation or Docker operation occurred.

**Required fix:** obtain drain evidence through a fresh validated immutable-image probe or another independently trusted, narrowly scoped mechanism. Do not `exec` a new Node/SQLite helper in an unavailable-prior-image container. A fresh probe must have explicit read-only/no-copy mounts, no migration/app initialization, no JWT, and its exact lifecycle/membership must be accounted for without weakening the namespace/writer predicates. Keep writer shutdown and trusted pending-work checks separate from acceptance of the old worker's own helper output.

**Regression acceptance:** when all old application image objects are absent, reaching drain must never submit any exec/helper command to an old application ID. Assert the probe's validated immutable image/control policy before execution; simulate a forged old-worker response and ensure it is not used as drain authority. On refusal, retain HOLD and do not take a supposedly clean backup/redeploy success path.

### RDEP-2 — P2: backup helper runtime rejection is after execution, not a pre-execution guard

**Source:** `:1155–1188,1315–1321`; tests `:1816–1825`.

Fresh API image metadata **is** validated before the helper submission, and the argv correctly specifies network none, read-only root, fixed user/resources, and both own volumes `readonly,volume-nocopy`. This is a positive control. The remaining timing issue is distinct: `docker run -d ... RECOVERY_BACKUP` starts the backup/import program immediately, and only afterward does `helper()` inspect and validate its actual configuration.

The existing privileged/namespace/copy-up refusal tests therefore prove post-start refusal, not absence of helper execution under a rejected runtime configuration. An independent probe confirmed the backup-program run request precedes the first helper inspection; an injected `PidMode=host` response then caused HOLD. It did not execute any real helper and is not evidence that a trusted daemon actually applied that unsafe default.

For the requested strict helper-runtime-before-execution guarantee, rejection after startup is too late. A sticky HOLD prevents false success but cannot undo code that has already executed. This finding does not negate the correctly specified read-only/no-copy argv or claim observed DB writes.

**Required fix:** create the helper without starting it, inspect its exact returned ID and verify the complete control/mount/image policy in the non-running state, then start only that verified ID. Reinspect running state before accepting readiness/copy evidence. Preserve fresh-image validation before creation and enforce read-only/no-copy mounts in the creation argv itself, so even container creation cannot populate source volumes. Refusals/uncertain create/start outcomes must remain HOLD without broad cleanup.

**Regression acceptance:** unsafe helper controls must produce zero helper start/backup-execution submissions, not merely zero subsequent application recreations. Distinguish created from running helper fixtures; assert the exact create → validated inspect → start → running inspect → backup/copy order.

### RDEP-3 — P2: logical fingerprint can equate distinct valid 64-bit integer data

**Source:** `:1058–1066,1337–1338`.

The fingerprint hashes `JSON.stringify(row)` from default better-sqlite3 row reads. It requests no lossless integer mode and rejects no unsafe numeric values. Distinct SQLite INTEGER values outside JavaScript's safe range can therefore be returned as the same Number and hashed identically. A source-level serializer probe confirmed:

```text
Number(9007199254740992n) and Number(9007199254740993n)
produce the same JSON numeric row value.
```

For example, a valid `sqlite_sequence.seq` change between those integer values is not reliably detectable by this encoding. Schema/integrity/FK checks can still pass. The exact hash of the *backup file* protects that archived file, but does not repair the live-data comparison: post-start live state is compared only through `logicalSha256`.

This is a source/serialization correctness finding, not an observation that the current stand contains such values or suffered corruption. The real installed better-sqlite3 integration could not be exercised under the available Node ABI, as detailed below; the numeric probe is not presented as that integration run.

**Required fix:** use deterministic lossless SQLite-value serialization, including exact 64-bit integer handling, or explicitly refuse any row value that cannot be compared losslessly before claiming retained-data equality. Do not silently coerce BigInts to Number. Preserve BLOB/type distinctions as part of the chosen encoding.

**Regression acceptance:** under a compatible Node/native binding, create valid adjacent INTEGER values above `2^53` (including `sqlite_sequence`), alter one between baseline and comparison, and require a different fingerprint or fail-closed refusal. Retain existing WAL, BLOB, schema, FK, pending-work and row/sequence preservation tests.

### Controls observed, without granting approval

- Exact explicit command/acknowledgment, endpoint-bound build marker and closed original-record set; start-submission evidence and competing guards refuse. The old marker and pins are captured, not recreated or certified from new tags.
- Exact runtime name/project census precedes target inspection. Prior runtime controls, own JWT match, commands/resources/mounts, membership, process identities and volume/network controls are independently checked without substituting current image tags for unavailable prior image evidence.
- All four builds occur sequentially before any stop, with only sentinel substitution. Selected fresh image metadata/reference policies and immutable candidate config are validated before application recreation. Source/Dockerfile/ignore/CVE/state fences are substantial; the remaining application source/dependency provenance is an operator trust assumption, not signed evidence.
- New helper argv uses exactly the own volumes, read-only/no-copy; no Docker socket/host mount, network or JWT is supplied. It is still subject to RDEP-2's pre-execution inspection gap.
- Backup core opens existing DBs readonly/query-only, uses SQLite online backup rather than copying DB/WAL files, checks integrity/FKs/versions/pending work, reopens/rechecks copies and verifies bounded private host bytes/modes/hashes. With all writers genuinely quiescent, sequential auth/ledger snapshots can represent that same fenced state. This source design does not establish live helper/native compatibility, and RDEP-1/RDEP-3 prevent the full requested guarantee.
- Only exact own web/API/worker IDs are stopped. Web may terminate with 143; database writers must exit zero. Egress stays live through backup and is replaced later as stateless. No retained/8080 stop, restart, deletion or request appears in the reviewed sequence.
- Original pins are preserved before the explicit authorized pin change; only own applications are force-recreated using candidate IDs, `--no-deps --no-build --pull never`, without initializer reruns. A data mismatch blocks web reopening, but the fresh API/worker may already have executed/migrated/written data at that point; the verified backups and HOLD are the recovery evidence, not an automatic rollback.
- Postflight compares retained volume/network/initializer identities, new application IDs, API/worker readiness and a credential-free 401 through only `127.0.0.1:8081`. Original failure archival occurs after postflight. Receipts explicitly say prior metadata is unverified and old-image rollback is not promised.
- Mutation stages, failure audit, original HOLD, recovery guard and incomplete-history gates survive errors in the injected tests. A failure can legitimately leave this new stand stopped/partly replaced. No automatic restart, retry, old-image rollback, backup pruning or lock erasure is approved.

### Bounded offline validation and limitations

Commands used `env -i`, literal tool PATH and `/tmp` fixture roots:

1. An initial name-filtered selection including the real SQLite recovery test **exited 1**. The native module was compiled for **NODE_MODULE_VERSION 131**, while the available Node requires **127** (`ERR_DLOPEN_FAILED`). No package install/rebuild or dependency modification was attempted. The real SQLite/WAL integration result is **not verified by this review**.
2. A separate injected-only selection:

```sh
node --test --test-name-pattern='^(replacement|completed replacement|future build failure|missing saved image|status missing runtime)' scripts/test_public_image_stand.mjs
```

   **14 passed; 0 failed/cancelled/skipped/todo**, exit 0, reported duration **11.52 seconds**, 30-second outer bound. These positive fixtures passing does not close the findings: the current mocks accept old-worker drain exec and detect helper-control rejection only after run submission.
3. Both `node --check` commands passed, 10-second bound.
4. Independent in-memory probes confirmed old-worker drain exec ordering with absent metadata, backup-program submission before unsafe-helper rejection, and the unsafe-integer JSON collision. They loaded only fixture/setup functions and imported actual orchestration unchanged; Docker calls were injected, run requests were recorded/intercepted, not executed. Temporary state was outside the repository and cleaned in `finally`.

No full/combined suite was run; the author's **288-test combined result is not fresh reviewer evidence**. No actual Docker/lifecycle/network operation, live helper, prior-image inspection, private environment/state/JWT/database read, actual recovery, staging or commit occurred. All executable state/secret reads concerned generated fixtures. Source/test/operator-note/Compose hashes remain unchanged; only this report is appended.

### Required disposition

**Do not run the replacement command at these hashes.** Fix RDEP-1/RDEP-2's trusted-helper execution ordering and RDEP-3's lossless-data comparison, add regressions that fail before the fixes, and rerun the SQLite integration under a compatible already-approved runtime. Re-review the resulting exact sources and the full mutation sequence before coordinator execution.

After fixes, remaining conditions will still include genuine original build-before-start evidence, original endpoint continuity, returned/settled clients and no concurrent source/daemon/topology/database-maintenance changes; reviewed fresh source/dependencies; protected private backup storage and adequate limits; acceptance that unavailable old images are not certified and rollback is not guaranteed; and a separate manual recovery assessment for any interrupted attempt. Never operate retained/8080 resources or delete evidence to satisfy admission.

**Final verdict: BLOCK this new recover/build/backup/redeploy workflow. Earlier metadata-only reconciliation approvals do not waive these defects or authorize live execution.**

---

## Independent re-review — RR1 and RDEP-1/2/3 corrections — 2026-10-18

### Exact disposition and scope

**QUALIFIED APPROVE for the corrected source and documented acknowledged recovery procedure at the exact hashes below.** RDEP-1, RDEP-2 and RDEP-3 from this report are closed for these inputs. This recheck also independently reproduced successful resolution of RR1's cleanly closed, nonwritable WAL-source case described in `public-image-chain-review-20261018.md`; that other report is not modified here. No additional blocking defect was established in this scoped source/fixture/native-SQLite review.

This supersedes the immediately preceding BLOCK **only for the corrected hashes and findings**, not by rewriting its history or pretending the old implementation passed. This is not a claim that a real engine accepted helper normalization, that live private state satisfies admission, that old image metadata has been certified, or that a recovery/deployment/browser/scan has succeeded. The reviewer did not invoke recovery or inspect live state. The coordinator must establish the current operational preconditions below; the acknowledgement cannot manufacture historical evidence or waive a guard.

SHA-256 reviewed inputs:

```text
858b754e8ff7f37592657db7689400a59481b8357435ac9dd458460bf6bae8d6  scripts/public-image-stand.mjs
2953613e44f4bbba6eb949ab68d74bc44ba3dc2fda7b91cb11bfaec57245df22  scripts/test_public_image_stand.mjs
b8f7d4447cbe550740ebe1b78718ed807e49d5388637c1dbce72d5fb2085cb9c  docs/public-image-recover-redeploy-20261018.md
fa562e64f4feb6d9f366bc3bf14a7b0f3773fbc00e97e7e153a7ed1f52f6cc99  server/deploy/compose.public-images.yaml
```

The report before this append was 98,085 bytes, SHA-256 `fb919c447425cbfcb667575af5fb9acf2ca9ff6bfb1b60ec06e22d16964454a5`. Its complete prefix must remain unchanged. Only this review document is written in this recheck; implementation, tests, operator notes, Compose, dependencies and other review reports remain read-only.

### Finding-by-finding recheck

| Finding | Current source and independent evidence | Disposition |
| --- | --- | --- |
| **RDEP-1: unverifiable old-worker execution** | `public-image-stand.mjs:1136–1150,1366–1401`: the drain implementation and native driver now execute in a separate helper from the freshly selected/validated immutable API image. The helper mounts only the exact own ledger volume RO/nocopy, has network none and no JWT, and stages source bytes privately. The old worker remains a writer while draining but supplies no executable/probe-result authority. `stablePrior` and `scopedRun` account for exactly this helper's ID/name/volume membership, without concealing foreign consumers. After zero pending, only the new helper is stopped/removed; then the exact old worker must exit zero. An independent orchestration probe ran with prior application metadata absent and rejected any exec against any original container ID; recovery completed without such an exec. The dedicated foreign-ledger-consumer regression also passed. | **Closed.** Old image bytes remain explicitly uncertified; this change removes new helper-code execution in them, not that provenance limitation. |
| **RDEP-2: helper code starts before validation** | `:1216–1253,1368–1390,1407–1414`: helper argv uses `create --pull never`, not `run`. Both purposes are created stopped, inspected with the exact returned ID/image and bounded control/mount policy, durably recorded, reinspected created, started by exact ID, then revalidated running with stable Config/HostConfig. Independent injected probes counted at least two created inspections before either exact-ID start. Separate drain/backup probes injected `VolumeOptions.NoCopy=false` in created metadata: each rejected helper received **zero starts**, no app recreation followed, and original marker bytes remained intact. Native SQLite/probe code was not executed through the Docker runner. | **Closed.** This relies on a trustworthy local daemon and the stated no-concurrent-interference boundary; a hypothetical malicious daemon is not made trustworthy by inspect. Uncertain creation/start remains HOLD. |
| **RR1: closed WAL source on readonly volume** | `:1043–1075,1088–1134,1136–1143`: source access is now bounded O_RDONLY/O_NOFOLLOW/O_NONBLOCK byte reads, not a SQLite open. Main plus any WAL are staged in a newly created private writable scratch directory; SHM is not copied and SQLite recreates its own sidecars there. File type/link/size and identity/time/content fences span copying, querying/backup and both sources' completion. Backup mode requires the internal quiescent flag; drain source-change results retry rather than claim zero. The online-backup API still creates the final standalone snapshot from the consistent private copy; staging files are not promoted as backups. An independent native probe closed every source connection first, confirmed main-only WAL files, set source files 0400/directory 0500, and wrapped the DB constructor to forbid SQLite opens of either original source path. Backup succeeded; source bytes/inodes/modes/sizes/mtime/ctime and the source name set remained unchanged; standalone output databases reopened with matching logical fingerprints. The committed-WAL/abrupt-writer/restore and partial-failure/source-drift tests passed too. | **Closed for source/native-host evidence.** Host permissions and temporary WAL tests are not a real Linux readonly-volume/kernel or Docker filesystem proof. No mount write authority was broadened to make it pass. |
| **RDEP-3: lossy integer/data comparison** | `:1076–1084,1098–1115`: safe integer mode and raw rows retain INTEGER values as BigInt, including selected rowids and `sqlite_sequence`. Typed framing encodes integer decimal, REAL IEEE-754 bytes, BLOB hex, TEXT and NULL separately; unsupported/oversized values refuse. An independent actual-SQLite probe changed adjacent values above 2^53 in an implicit rowid, an INTEGER column and `sqlite_sequence`, including adjacent sequence values; every fingerprint changed. Author regressions for adjacent integers/sequences and typed serialization also passed. | **Closed.** Unlike the preceding serializer-only observation, the new evidence includes the installed native SQLite driver under a compatible runtime. |

### End-to-end controls retained in the reviewed source

- Admission remains a separate explicit `recover-build-and-redeploy --ack-unavailable-prior-images` path. Ordinary up/status and metadata-certifying reconciliation do not receive a general missing-image fallback. An endpoint-bound canonical original build HOLD is required, with only the accepted closed record sets; start evidence, other recovery guards and incomplete/tampered history refuse.
- The exact current six-container/two-volume/four-network namespace is censused before resource inspection. Original saved runtime IDs, process evidence, runtime configuration/JWT, consumer sets and network identities are checked without following old own-image metadata. Prior state/profile/JWT/marker/Compose/public-CVE identities remain fenced. Endpoint validation pins subsequent Docker/Compose calls to the literal local Unix endpoint, stripping mutable context/TLS selectors. Independent orchestration assertions observed the pinned endpoint on every engine call.
- All four builds complete sequentially and fresh selected images/defaults/aliases/references/rendered configuration are validated before admission stops. A selected tag is not evidence for an old runtime pin. Original initializer image pins stay unchanged and initializers are not rerun. No lifecycle executes an unvalidated tag in place of a fresh immutable image ID.
- Web/API stop precedes fresh-helper drain; both database writers must exit zero before backup. The stateless gateway has no DB mount and remains live through backup, then is replaced only in the controlled own-service recreation phase. Foreign consumers, source drift, failed drain or writer shutdown remain refusals, not permission to clear HOLD.
- Both helpers have readonly roots, RO/nocopy exact own source mounts, no network/JWT/host binds/socket, UID 65532, dropped capabilities, no-new-privileges and bounded CPU/memory/PIDs/tmpfs/lifetimes. Helpers perform no source SQLite opens during staged drain/backup. The validated fresh API's later live comparison is intentionally a different read-only SQL path on normal app volumes.
- Verified standalone snapshots are copied only to private audit storage, checked for mode/ownership/link/type/size/hash, fsynced and retained. Source staging cleanup targets only the private scratch family. No backup publication or source checkpoint/chmod/delete path was added. No retained/8080 resource mutation or request was identified.
- Only after verified host backups does the launcher preserve old main pins and install candidate immutable pins. Own egress/worker/API then recreate with `--no-deps --no-build --pull never --force-recreate`. Fresh-image startup can write before comparison; mismatch means HOLD with backups, **not** automatic reversal or a promise that no startup write occurred. Web reopens only after retained-data equality and API/worker readiness.
- Postflight checks exact fresh app IDs, unchanged initializer/volume/network identities and membership, readiness and a credential-free request only to 127.0.0.1:8081. Original HOLD archival is after those checks, preserving its marker bytes/inode. Completion manifest/history and recovery-guard handling remain fail-closed on interruption/tampering; no automatic lock clearing, retry, old restart/rollback, restore or pruning was introduced. A committed output-delivery failure must not trigger replay.
- Audit/result language still says `RECOVERED_REDEPLOY_PRIOR_IMAGES_UNVERIFIED`, `originalImageMetadataVerified:false`, `rollbackToPriorImages:false`; legacy historical equality remains `OPERATOR_ATTESTED`, not engine proof. JWT is preserved and omitted from output/audit control hashing. Success is deployment/readiness only, not a native/browser/scan qualification result.

### Bounded offline checks actually run by this reviewer

All executable checks used `env -i`, a literal PATH and `/tmp` synthetic fixtures. The compatible **already-installed** runtime was `/Users/vsevolod/.nvm/versions/node/v23.11.0/bin/node`, reporting Node **v23.11.0**, module ABI **131**. No runtime/package install or native rebuild was performed. This resolves the prior review's ABI-127 execution limitation for these newly executed checks; it does not relabel the preceding failed attempt as a pass.

1. Focused test selection, 45-second outer bound:

```sh
node --test --test-name-pattern='^(replacement|completed replacement|future build failure|SQLite recovery core|RR1 |RDEP[123] )' scripts/test_public_image_stand.mjs
```

   **23 passed, 0 failed/cancelled/skipped/todo**, exit 0; reported duration **19.18 seconds**. Includes native temporary SQLite clean-close WAL, committed-WAL standalone restore, source mutation/partial failure, BigInt comparison and injected lifecycle/interruption/control refusals. This is not the full launcher or combined suite.

2. `node --check scripts/public-image-stand.mjs` and `node --check scripts/test_public_image_stand.mjs`: both passed within a combined 10-second bound; Node version/ABI confirmed in the same clean environment.

3. Independent in-memory probes, 20-second outer bound, exit 0. Loaded only existing fixture/setup function sections via an in-memory module; no author test registrations or probe files were written. Actual orchestration and exported SQLite functions were imported unchanged. Probe assertions covered the original trust/order defects, unsafe stopped helper refusal for both purposes, local endpoint pinning, secret-free log output, staged-only DB opens, preserved nonwritable clean WAL sources, standalone restore and >2^53 rowid/value/sequence changes. Synthetic cleanup ran in `finally`. Docker calls/request were injected and never delegated to Docker/fetch. Actual SQLite touched only generated temporary DBs.

The author's **298 combined passes** are reported author evidence, not a reviewer rerun or a substitute for these scoped checks. No full/combined suites, actual Docker command, network request, live helper, private environment/state/JWT/database access, recovery, staging or commit occurred.

### Remaining command preconditions — not verified against live state

This source-level qualified approval applies only if the coordinator can honestly attest the operator note's conditions and all current guards pass:

1. The original operation failed in build before any lifecycle/start submission; all relevant clients/builds/daemon work are terminal and settled. No start record/evidence was removed and no marker/pins were edited to manufacture eligibility. Legacy historical pre-build equality remains an explicit operator attestation, not newly proven history.
2. The recorded local endpoint and exact intended existing isolated runtime/pin/profile/JWT/storage/network baseline are the current ones. No concurrent launcher, source change, build/tagger, Docker/context/topology action, external volume writer or database maintenance is permitted. A changed or uncertain baseline is a refusal, not a reason to force the command.
3. Fresh application source/dependencies/build inputs remain reviewed and trusted. Metadata validation is not executable-content attestation. The compatible host SQLite tests do not guarantee native-module behavior, container normalization or readonly filesystem behavior inside the freshly built Linux images.
4. Private backup/audit storage remains protected, sufficiently provisioned and within the finite DB/scratch/history/time limits. Oversized/busy/slow/incompatible data or insufficient space may legitimately refuse. Do not relax the guards or prune evidence merely to pass admission.
5. The operator accepts possible isolation-stand downtime/partial replacement, unavailable old-image rollback, and the fact that comparison detects rather than undoes startup changes. Any interrupted attempt requires a new assessment of the retained state/audit; this approval does not authorize automatic retry, manual lock deletion, generic restore or ordinary up to finish an incomplete attempt.
6. Operate only the isolated 8081 stand. Retained `dip-local-full`, old `dip-auth-stand`, their port 8080/private keys/JWT/data/volumes and unrelated resources remain outside scope. Native/browser/real-scan qualification and actual recovery receipts require separate evidence afterward.

**Final scoped verdict: QUALIFIED APPROVE the RR1/RDEP-1/2/3 fixes and documented acknowledged recovery sequence at the exact hashes above; no remaining blocker established in this review. No live-state eligibility, real-daemon success, historical old-image certification or production acceptance is asserted.**

---

## Independent re-review — mount observation ordering and explicit pre-lifecycle same-audit resume — 2026-10-18

### Verdict and exact scope

**QUALIFIED APPROVE** the narrow normalization and explicit same-audit resume implementation at the hashes below. No blocking defect was established in this scoped offline review. For the coordinator's proposed operation, the reviewed command is only:

```sh
node scripts/public-image-stand.mjs resume-recover-build-and-redeploy --ack-pre-lifecycle-only --audit redeploy-a38c3a387e22331d69e7d9746baf7f27
```

This is not approval to repeat fresh recovery, run ordinary up, clear a HOLD, resume a later phase, or repair evidence to meet admission. The implementation accepts a syntactically valid audit identifier with the same strict evidence predicates; it does **not** hardcode this particular identifier. This operational review is scoped to the identifier requested above and does not approve arbitrary other audits.

The live failure, unchanged live runtime and mount-order diagnosis are **coordinator/author-reported** facts in the operator note. I did not inspect that real audit, daemon, containers, private state, Env, JWT or databases. Offline fixtures establish the reviewed behavior, not current live eligibility or real daemon success. All earlier limits concerning unverified prior images, trusted fresh source, rollback unavailability, downtime and later native/browser/scan qualification continue to apply.

SHA-256 reviewed inputs:

```text
a9c9e6780af82f78dcf24eedc562825a01a02fd9c747d8098c2a9e580f0ca582  scripts/public-image-stand.mjs
061cc7e5f35dd03553b41414e44bfabf2eb11b7d45cec35176616edbad42026e  scripts/test_public_image_stand.mjs
94a257e7657683bfbecd7a71e7e434d7229e1e99d341c5a67633b76aa5d741e2  docs/public-image-recover-redeploy-20261018.md
fa562e64f4feb6d9f366bc3bf14a7b0f3773fbc00e97e7e153a7ed1f52f6cc99  server/deploy/compose.public-images.yaml
```

Before this append the report was **113,017 bytes**, SHA-256 `913b01057cb05be04f5013b01ce51155dd3424e93a6a8a5a9bddba2539c8bcb2`. Preserve that complete prefix. Only this report is edited.

### Narrow mount normalization

`public-image-stand.mjs:1153–1172` sorts only the observed `Mounts` array by unique `Destination` for secret-redacted continuity hashing. Every complete mount record and all its fields remain hashed. It does not normalize declared `HostConfig.Mounts`, Config Env order, command/entrypoint arrays, access modes, source paths, volume names or unknown mount fields. Existing independent runtime mount validation still precedes continuity proof. Duplicate destinations refuse.

The legacy compatibility helper is used only by the explicit resume path (`:1416–1419`). It enumerates permutations of at most six already-validated current observed mount records and requires an exact old control digest match; then it compares the **entire** projected snapshot with the saved baseline. It cannot excuse changed mount contents, other controls, process evidence, volume/network identity or endpoint membership. It does not rewrite the old baseline hash or broaden ordinary image validation. Historical build evidence in other paths does not gain a blanket legacy fallback; incompatible evidence remains a refusal.

An independent synthetic resume successfully used legacy order-sensitive hashes while all inspected original-container Mounts observations were reversed. Independent changes to an otherwise-unhandled full mount field and duplicate destinations both refused before Docker mutation or resume admission. The author tests separately reject changed mount source/name and declared order. This supports a presentation-order fix, not a resource-policy relaxation.

### Resume guard boundaries actually inspected

| Boundary | Source assessment |
| --- | --- |
| Exact eligible stopped point | `:1314–1330`: existing audit/guard/private-directory identities; exact closed audit file set; empty backup directory; no resume.lock; matching canonical audit/guard intents; exactly phases 001–006 (`build-submission`, four role builds, `new-image-validation`) with monotonic timestamps; canonical guard failure at new-image-validation after phase 006; canonical candidate pins. Missing/extra/later phase, helper/backup/start/partial-resume evidence refuses. Phase 006 follows the four awaited builds, but settlement/no concurrent daemon work remains an acknowledgement condition. |
| Original HOLD and other history | `:1352–1398`: original canonical endpoint-bound build marker and accepted original record set remain required. Only the explicitly selected pending audit is exempted from completed-history parsing; other histories must validate. No original marker deletion, rewritten PASS or fresh-audit fallback exists. Existing other recovery guards refuse. |
| Original intent and live baseline | `:1360–1419`: reconstruct the full original intent, including original marker identity/hash, profile/Compose/CVE/endpoint, prior pins, reviewed Dockerfile/ignore hashes and helper policy; require exact equality with the retained intent. Independently census/validate all six containers, two volumes and four networks before comparing the full saved baseline, with only observed-mount order compatibility. Current JWT must match exact retained API runtime Env; identity/content fences protect files during continuation. |
| Honest historical limits | The prior intent did not capture a JWT inode or database-content snapshot. The new receipt records current own state-file identities without claiming historical proof. Same live volume identities and exact consumers do not mean their bytes have been frozen while API/worker remained running. Consistent data evidence is collected only after subsequent admission closure/drain/clean shutdown. Old image contents and pre-build history remain explicitly uncertified/operator-attested. |
| Candidate authority; no build/pull | `:1424–1443`: resume skips the entire build/phase-006-writing branch. `selectedImages` only inspects fixed selected tags; it does not pull. Image defaults, own references/consumers, distinct own IDs and old initializer pins are revalidated. The full selected immutable candidate must equal the existing candidate file; tags cannot silently choose replacements. Rendered candidate profile must pass before any lifecycle submission. Retargeted tags or unavailable/unsafe candidate metadata refuse, not rebuild. |
| Repeated proof before admission | `:1444–1482`: repeat full current runtime/storage/network continuity, recheck original audit file set, captured bytes/inodes and guard contents. Exclusively mkdir `resume.lock` under the retained guard, fsync its acknowledgement receipt, write matching resume.json and canonical resume-baseline.json into the same audit, then durably record resume-authorized before continuing to stop-web. Concurrent attempts cannot both acquire the same directory. |
| No evidence erasure/replay | Existing intent/baseline/prior-pins/candidate/failure/phase bytes and inodes are captured and fenced, not overwritten. Subsequent phase numbers continue after six. Any partial lock/receipt or later stage makes another resume ineligible. Failures preserve original failure and HOLD rather than converting old failure to success or creating a second audit. Ordinary fresh recovery/up remains blocked. |
| Reviewed continuation | `:1483` onward continues the already-reviewed fresh-helper create/inspect/exact-ID-start, drain, clean writer shutdown, staged main+WAL online backups, immutable no-build/no-pull recreation, retained-data comparison, readiness and original-HOLD archival. No old-image exec, initializer rerun, source-volume write authority or retained/8080 operation was added by resume. |
| Completed history and crash handling | `:1272–1310,1332–1345,1531–1547`: completion binds old failure, receipt, canonical resume baseline and all original files; archived recovery guard includes the matching resume.lock receipt. Result still leaves prior images uncertified. Missing/tampered evidence blocks ordinary lifecycle. Interrupted authorization or later mutation remains HOLD; post-archive errors attempt to restore exclusion. No automatic clear/rollback/resume loop is introduced. |

### Bounded offline evidence

Used `env -i`, explicit existing Node v23.11.0 PATH and `/tmp` generated fixtures only. No real Docker or HTTP runner was invoked, and no private/live state or ambient environment was read.

1. Focused selection, **45-second outer bound**, exit 0:

```sh
node --test --test-name-pattern='^(runtime Mounts|explicit pre-lifecycle resume|pre-lifecycle resume|resume is explicit|resume receipt|recovery reports fixed)' scripts/test_public_image_stand.mjs
```

   **31 tests passed, 0 failed/cancelled/skipped/todo**, reported duration **7.81 seconds**. Covers mount observation reorder, same-audit completion and preserved old evidence, admission-refusal variants, endpoint/candidate/runtime authority, crash/replay/identity fences, archive/history tampering and sanitized reasons. These are injected Docker/request fixtures; this selection does not rerun the full recovery/native-SQLite suite.

2. Both launcher/test `node --check` commands passed, combined 10-second bound.

3. Independent in-memory probes, **20-second outer bound**, exit 0. Imported actual orchestration unchanged and loaded only fixture/setup sections, with no test registrations/probe files. Probes established:
   - Legacy order-sensitive baseline plus reversed current observations can complete in the same synthetic audit. Every Docker mutation saw an already-written matching resume/lock receipt and resume-authorized phase. Endpoint remained literal/bound. No build/pull/retained-resource argv occurred; all original audit evidence bytes/inodes were preserved.
   - Changed full mount field, duplicate destination, later stop-web phase and retargeted candidate each refused before any Docker mutation or resume.lock admission.
   - Two concurrent synthetic resumes produced exactly one completion and one refusal, retaining one audit.

Temporary fixtures were cleaned in `finally`. The author's **329 combined passes** were not independently rerun. No full/combined suite, actual recovery/resume, Docker mutation/read, network request, live DB/JWT/Env/state access, install/rebuild, staging or commit occurred. Source/test/operator-doc/Compose hashes must remain unchanged through final verification.

### Required operational constraints

For the one proposed command, the coordinator must establish that the previous attempt returned, all builds/daemon work are settled, no lifecycle was submitted, and the retained exact audit really has the eligible closed pre-lifecycle record set. No concurrent source edits/tagging/context/topology/launcher/storage maintenance may occur. All original-image-unavailable acknowledgement conditions remain in force. The code must reject any mismatch; do not edit/remove failure, phases, locks or baseline to satisfy it.

A resume admission failure is not authority to use fresh recovery or ordinary up. Any failure after resume.lock/receipt creation is a new sticky HOLD requiring independent assessment of the exact retained state, not a second use of this one-shot continuation. The coordinator must accept possible downtime/partial deployment, lack of rollback to unavailable prior images and separate later qualification. This review does not assert byte-identical live databases since the failed attempt, historical JWT inode continuity, live audit eligibility or native Docker normalization.

**Final verdict: QUALIFIED APPROVE the narrow mount-order fix and proposed explicit pre-lifecycle same-audit continuation at the exact hashes above. No blocking defect established offline; no live command was invoked or real operational outcome certified.**

---

## Independent re-review — exact stage-10 created-drain continuation and empty DriverConfig — 2026-10-18

### Scoped verdict and inputs

**QUALIFIED APPROVE** the narrow empty-driver metadata allowance and explicit created-drain continuation at the exact hashes below. No blocker was established in this source/offline-fixture review. The proposed operation is specifically:

```sh
node scripts/public-image-stand.mjs continue-recover-created-drain --ack-created-drain-only --audit redeploy-a38c3a387e22331d69e7d9746baf7f27 --helper-id ebd3e74260e08595f44ff5e94b202650c25094c7dfcc8c4ebd556b9455b3c180
```

This is a newly reviewed, separately acknowledged continuation at phase 010, **not** permission to repeat initial recovery, repeat the earlier pre-lifecycle resume, clear locks, or force a partial transaction forward. The implementation accepts syntactically valid audit/helper identifiers with strict evidence predicates, rather than hardcoding these specific values; this operational review is scoped to the pair requested above.

The reported live state and author-run real read-only checker result are **coordinator/author evidence**, not observations made by this reviewer. I did not invoke either real checker or continuation, access Docker/network, or read live private state/Env/JWT/databases. An offline checker PASS is current-admission evidence only; it is not proof that actual helper start/drain/backups/deployment will succeed.

SHA-256 reviewed inputs:

```text
0b4c2f6d9a01d23d9ac194565032e291424d32b8d73c1a39e3d94edb3e56361d  scripts/public-image-stand.mjs
7cf146b19bd4f71fcc48e1ad43a5afad1f6c6d1efd59b631687bda79e38b4bc8  scripts/test_public_image_stand.mjs
3a2fc4fc04bb10e73b641fbccd85b26867ac9b8963a5123d799a91bee6c9bdeb  docs/public-image-recover-redeploy-20261018.md
fa562e64f4feb6d9f366bc3bf14a7b0f3773fbc00e97e7e153a7ed1f52f6cc99  server/deploy/compose.public-images.yaml
```

Before this append, the report was **124,884 bytes**, SHA-256 `e713e4b3716f9a72f07efbbe9dcbb2dff5bb211d1fb92f9e97a45d73dc8065fc`. Preserve that entire prefix. Only this review document is written; source/tests/operator docs/configuration remain read-only.

### Metadata allowance and trust boundary

`public-image-stand.mjs:1246–1279` retains exact helper image/program/Env/user/resource/network/mount validation. The VolumeOptions rule (`:1277`) requires `NoCopy === true` and permits only:

```json
{"NoCopy":true}
{"NoCopy":true,"DriverConfig":{}}
```

Null, array/scalar DriverConfig, custom driver Name/Options, extra VolumeOptions keys and false NoCopy are not normalized away. Both purposes retain source mounts readonly/nocopy. Helper observed local-driver source is additionally checked against the retained inspected volume mountpoint (`:1497,1537`). Unknown host authority, duplicate/wrong mounts, writable observed mounts, hooks and inherited JWT/provider settings remain refusals. No entrypoint/Env/resource or old-image fallback allowance was added to address this metadata mismatch.

Independent probes also rejected DriverConfig `false`, empty string, zero, `{Options:{}}` and `{Name:""}` without mutation or synthetic state changes. This is an exact-empty-object accommodation, not authorization to select a volume driver or perform copy-up.

### Exact continuation admission and execution boundaries

| Boundary | Reviewed behavior |
| --- | --- |
| Exact phase 010 evidence | `:1360–1379` requires phases 001–010 in exact order: build-submission, four role builds, new-image-validation, resume-authorized, stop-web, stop-api, drain-helper-submission. Exact closed audit/guard file sets, empty backups, canonical prior failure/intent/candidate/baselines/resume receipt, matching resume.lock receipt, monotonic phase times, no helper record/start/later phase, no continuation lock/receipt/unknown file. Original failure remains phase-006 evidence and is not fabricated as a phase-010 error receipt. |
| Prior identities and history | The original operation must contain mutation.json alone; original endpoint-bound build HOLD, marker hash/inode, original reconstructed intent, profile/source/CVE/build inputs and saved pins remain required. Prior resume receipt binds original evidence hashes/inodes, state directory and current profile/JWT/pins identities. Other histories must be complete; only the selected existing audit is pending. No new audit, adopted foreign project, JWT replacement or initializer rerun occurs. |
| Census before inspection | `:1381–1389,1461–1471` removes only the deterministic helper name/project pair from the complete name census and only the explicit helper ID from its exact ledger consumer projection. It then inspects that deterministic name and requires the requested full ID. The six original resources/consumers/networks undergo independent policy checks; foreign consumers and off-allowlist/mislabeled resources refuse rather than being inspected/adopted. No auth mount is allowed on the drain helper. |
| Never-started helper | `:1390–1392,1464–1470` requires created/nonrunning, PID 0, restart count 0, exit code 0, exact zero start/finish timestamps, no runtime error/OOM/dead/restarting state, exact executable Node/program, requested ID, deterministic own labels/name and validated fresh immutable API image. Repeated inspection requires unchanged helper Config/HostConfig and Created timestamp. A stopped previously executed helper is not equivalent to never-started. |
| Clean stopped web/API and original live writers | `:1191–1235,1493–1497` independently verifies web/API exited cleanly with retained IDs/controls/start/restart evidence. Their finish times must follow their durable stop phases and precede helper creation; helper creation must follow phase 010. API exit must be zero; the pre-existing web-only 0/143 rule remains unchanged. Worker/gateway must retain original running identities; initializer exits remain successful. The baseline comparison permits only the already-reviewed mount observation order and intended web/API stop transition. After establishing the stopped baseline, later continuity checks require exact stopped snapshot equality too. |
| Immutable candidate and endpoint | All current selected metadata/references/consumers and rendered candidate profile are independently revalidated and must match the existing immutable candidate and initializer pins. The adopted API-image consumer is allowed exactly once. Endpoint is the original literal local Unix endpoint, not a mutable context selector. There is no resume-time build/pull, tag repair or unavailable-old-image execution/inspection fallback. |
| Read-only check | `:1458,1482,1550–1551,1631–1637` restricts engine submissions to resource ls/inspect or fixed Compose config; local context resolution is read-only client metadata. It returns before authorization/recording/lifecycle and suppresses failure-record writes. All required directories already exist as a consequence of admission; no empty state/guard provisioning occurs. Independent probes observed no state file/directory byte/inode/mode/size/mtime/ctime changes and no lifecycle/exec/build submission on the checker. |
| One-shot authorization and first start | `:1552–1559` exclusively creates continue-drain.lock inside the retained recovery guard, writes/fsyncs its receipt, appends matching continue-drain.json and current baseline, then durably records continue-created-drain-authorized. Receipt binds exact current helper ID/name/image/creation/control hash and all prior audit files/identities. `:1531–1543` adopts—not creates—the drain helper, reinspects it created, records validated helper controls, durably records helper-start, reinspects, and starts **that exact existing ID once**. No repeat stop-web/stop-api/drain-create/build/pull branch is taken. |
| Historical helper identity honesty | The failed create was not followed by a durable returned-ID/helper-control receipt. The new command explicitly takes the operator-observed exact helper ID, establishes present eligibility through census/inspection, and binds it durably before its first start. It does not pretend the ID was recorded by the previous client. This remains conditional on truthful operator attestation and a trusted daemon, not retrospective cryptographic provenance. |
| Reviewed remainder | Drain exec remains in the validated fresh helper, not old apps. Only that helper is removed after drain; the original worker must then shut down cleanly, followed by no-writers proof and a **new separate backup helper** created/inspected/started under the existing policy. RR1 staged main+WAL online backups, RDEP-3 typed comparison, private copies, immutable own-app recreation, retained-data/readiness/postflight gates and final original-HOLD archival remain enforced. The prohibition on repeated helper create refers to the drain helper, not this required later backup helper. |
| Crash/failure/history | `:1394–1401,1620–1637` binds continued completion to the exact adopted helper record and matching archived continuation receipt. Original failure and all prior phases/receipts remain unchanged. Accepted failures attempt only fixed sanitized continue-failure.json, retain both prior locks plus continuation exclusion, and refuse replay/ordinary lifecycle. A partial receipt, uncertain start, later phase, backup/recreate/archive interruption is not an eligible created-drain stage. No automatic rollback/restore/cleanup/unlock exists. |

### Diagnostics recheck

`RecoveryRefusal`, `recoverySync` and `recoveryStep` preserve only fixed internal reason tokens; native/raw parse/runtime errors become fixed sanitized reasons, and Docker failures remain finite categories with output withheld. Helper conditions now distinguish state, immutable image, executable/program, environment, namespace/resources, tmpfs, unknown host authority, source and nocopy/driver failures. Continuation evidence/identity/timeline, drain/backup protocol, private-copy validation, new runtime/readiness/data/postflight and archive fences also have fixed tokens.

Passing diagnostics tests injected malformed drain/backup JSON and hostile private markers and checked both displayed error and failure receipt without raw payload/JWT leakage. An independent uncertain-start probe injected a raw private-marker error: only a sanitized HOLD/failure was returned/recorded, one start submission occurred, and another continuation refused before any Docker request. Diagnostic specificity is not evidence the daemon operation did or did not complete; an uncertain result stays HOLD.

### Executed offline validation

All checks used `env -i`, explicit already-installed Node v23.11.0 PATH and generated `/tmp` fixtures; Docker/request adapters were injected. No real checker, recovery, continuation, Docker read/mutation, network, private-state/Env/JWT/database access, install/rebuild, staging or commit occurred.

1. Focused tests, **45-second outer bound**, exit 0:

```sh
node --test --test-name-pattern='^(Docker empty DriverConfig|created-drain |helper diagnostics|remaining drain backup)' scripts/test_public_image_stand.mjs
```

   **44 passed, 0 failed/cancelled/skipped/todo**, reported duration **26.63 seconds**. Includes driver variants, created-stage admission refusals, 13 subsequent interruption boundaries, explicit parsing/replay and detailed diagnostic regressions. This is not a full/combined or native-SQLite rerun. The author's **373 combined passes** remain author evidence, not this reviewer's executed count.

2. Both `node --check` commands passed within a combined 10-second bound.

3. Independent in-memory actual-orchestration probes, **20-second outer bound**, exit 0. Loaded only fixture/setup sections, without registering author tests or writing a probe file; temporary fixture cleanup ran in finally. Verified:
   - Read-only check performs only injected read commands, leaves the full synthetic state bytes/identities/modes/times unchanged and keeps helper PID 0.
   - First continuation Docker mutation is exactly `container start <adopted-ID>` after matching durable continuation receipts; exactly one drain start, no repeated web/API stop, no drain create/build/pull/old-container exec/retained-resource argv; same audit and all original evidence bytes/inodes preserved.
   - Additional nonempty/nonobject DriverConfig variants refuse without state writes.
   - Uncertain start is a single submission, preserves sanitized failure/HOLD, and prevents replay before any further Docker calls.

### Remaining constraints and final disposition

The coordinator must still establish current exact audit/helper identity, terminal prior client/daemon work and no concurrent launcher/tagger/context/source/topology/storage changes. The reported real read-only proof does not authorize altering evidence or bypassing a refusal. Run neither old command at phase 010. Do not delete locks or repeat this continuation after any partial authorization or uncertain lifecycle outcome; obtain a separate assessment of retained evidence instead.

The worker may legitimately have drained more work while web/API remain stopped. Volume/control identity is not proof of byte-identical data since phase 006/007; consistent backups are taken after current drain and clean writer shutdown. Old image contents remain unverified; rollback is not guaranteed, startup writes are detected rather than automatically undone, and actual deployment/browser/real-scan qualification remains separate. Retained dip-local-full/old dip-auth-stand, their private material/storage and port 8080 remain outside scope.

**Final verdict: QUALIFIED APPROVE the exact empty-DriverConfig change and requested explicit same-audit/exact-helper created-drain continuation at the reviewed hashes. No blocker established offline; no actual checker/continuation or live success/eligibility is certified by this review.**

---

## Independent re-review — phase-12 started-drain recovery, V3 helper authority and expired-probe renewal — 2026-10-18

### Exact verdict

**QUALIFIED APPROVE** the current helper-control consolidation and the requested explicit phase-12 continuation at the hashes below. No actual blocking defect was established in this scoped source/offline-fixture review. For the reported clean timer-expired helper, the reviewed operation is:

```sh
node scripts/public-image-stand.mjs continue-recover-started-drain --ack-started-drain-only --audit redeploy-a38c3a387e22331d69e7d9746baf7f27 --helper-id ebd3e74260e08595f44ff5e94b202650c25094c7dfcc8c4ebd556b9455b3c180
```

This approval is scoped to that proposed audit/helper pair and eligible phase-12 evidence. The parser supports other syntactically valid pairs only when their independent evidence predicates pass; it does not hardcode the live identifiers. The old fresh recovery, pre-lifecycle resume and created-helper continuation are **not** eligible at this stage. No lock removal, generic retry or evidence repair is authorized.

Live helper expiry, the false→null diagnosis and the author-run real read-only eligibility result are coordinator/author-reported facts. This reviewer performed no real Docker/checker/continuation/network/private-state/Env/JWT/database access. Approval is not a promise of real-daemon/native backup/deployment success. The existing fail-closed guards remain authoritative if a future operation differs from its model.

SHA-256 reviewed inputs:

```text
138e81693a5ded501d4d0f17af627e45333f5e68314e34ef9abfde834182af3e  scripts/public-image-stand.mjs
318896a93a719856a91699bff801d283595e25abc79d2ee590c1959f762aecc9  scripts/test_public_image_stand.mjs
878af423eff950dec1e03c48e71824a58ed08b9571289bf0d977c557ec216413  docs/public-image-recover-redeploy-20261018.md
fa562e64f4feb6d9f366bc3bf14a7b0f3773fbc00e97e7e153a7ed1f52f6cc99  server/deploy/compose.public-images.yaml
```

The prior report is **138,813 bytes**, SHA-256 `d403cb4d98216e41b5e9bfec5805c2b0c985840cbfcefd44ef9a452b32814539`; preserve its complete prefix. Only this report is edited.

### Authority normalization: accepted, with historical proof still narrow

`public-image-stand.mjs:1246–1283,1369–1393` separates validated helper authority from volatile process observations:

- Every helper observation passes the independent sandbox validator before its projected identity is relied upon. Image/program/Path/Args, exact base Env, user, resources, root/mount access, capabilities, namespace/network/restart/kernel/log policy and forbidden hooks remain checked. Unknown **nonneutral** HostConfig values refuse; unknown neutral fields are omitted from authority identity, not allowed to grant authority.
- V3 projects only the already-approved equivalences: OOM false/null, swappiness null/-1, equivalent no-new-privileges spelling, empty capabilities/port bindings, exact-empty versus absent readonly/nocopy driver metadata, ordering of validated mount targets/tmpfs options, neutral forbidden startup metadata and validated inert ArgsEscaped. Other Config fields remain identity-bearing. No custom driver, writable source, device/namespace authority, shell/hook/Env override or missing bound is normalized away.
- ID/Created and process start/PID/restart evidence are separate from configured authority. Running helpers bind the observed epoch and reject later PID/start/restart drift; exited observations preserve the start/restart evidence with PID 0. Per-observation volume source/driver/access checks remain against the retained inspected volumes.
- **V2 historical compatibility remains only OOM false/null.** `legacyCreatedHelperProof` reconstructs the original raw Config/HostConfig digest with only that field varied. It does not use V3's broader equivalent-default projection to excuse an extra historical change. Independent mutation of swappiness null→-1—allowed in new V3 authority—still refused the legacy proof, before mutation or synthetic state writes.

An independent direct validator/projection probe confirmed equivalent V3 defaults compare equal only after validation, while nonempty DeviceRequests refuse. This closes the demonstrated false/null continuity mismatch without globally weakening ordinary image/container policy or historical evidence.

### Phase-12 eligibility, retirement and continuation

| Boundary | Source assessment |
| --- | --- |
| Exact retained chain | `:1395–1424`: exact phases 001–012, existing original/resume/created-continuation records and matching lock receipts, old helper-control record, empty backups and no later/started-continuation/unknown files. The accepted last failure must be precisely drain-helper-start / HELPER_CONTROL_IDENTITY, with its timestamp after phase 012. Prior file bytes/inodes, state/profile/JWT/pins identities, original marker/intent/input/endpoint/CVE/candidate fences remain required. Other histories must be complete. |
| Exact original runtime | `:1552–1617`: deterministic own helper census/name and explicit ID, exact selected image/control evidence, original cleanly stopped web/API and original running worker/gateway, unchanged initializers/storage/network/consumers and legacy mount-order-only baseline compatibility. Candidate tags must still select the recorded immutable IDs; metadata/own references/configuration are independently revalidated without build/pull or old-image fallback. |
| Started versus expired state | `:1439–1447`: restart count zero, no runtime error, exact executable/args; start timestamp must lie between durable phase 012 and the recorded failure. Running state requires PID >0 and no finish. Exited admission requires PID 0, exit 0, no OOM, finish no later than host-now plus tolerance, and a 355–390-second interval. This is timer-compatible current metadata under the no-concurrent-interference attestation, not forensic proof of a historical exit cause. Early exit, nonzero exit, restarted/created-again helper or changed epoch refuses. |
| Honest PID history | The prior failed client did not durably record a running PID. This continuation binds the currently inspected exact-ID epoch; it does not manufacture a saved historical PID proof. Repeated observations during admission and subsequent helper use require stable epoch/PID/restarts. Legacy authority proof and ID/start-time evidence remain independent. |
| Durable one-shot authorization | `:1649–1658`: exclusive started-drain.lock, fsynced matching receipt and same-audit started-drain.json/baseline, followed by durable continue-started-drain-authorized before any helper retirement/use. Receipt binds all previous files/inodes and exact helper image/authority/creation/epoch/current state. Prior failures and all three preceding locks remain unchanged. Partial authorization or later failure prevents replay. |
| Never restart old helper | `:1683–1694`: the old ID receives **no start**. If it is already exited or older than 30 seconds, revalidate before retirement; a running old probe is stopped by exact ID and must exit cleanly with unchanged epoch/authority. Remove only that exact helper with plain rm, **without -v**, then restore the ordinary own-runtime census. An already-cleanly-expired old helper is removed without another stop. |
| Fresh renewal | `:1622–1644`: renewal uses deterministic distinct `...-drain-next`, the same validated immutable API image and reviewed RO/nocopy sandbox. Create stopped, inspect exact returned ID/controls/source, record V3 authority, durable start phase, reinspect, start the new ID once, bind and revalidate its process epoch. Completed history requires replacement ID different from the retired ID and matching image/policy. No old application is exec'd, no admissions are stopped twice, and no initializer/build/pull path is added. |
| Still-recent running branch | A still-running helper no more than 30 seconds old can be used without another start after exact admission; its six-minute lifetime then leaves the documented drain budget margin. The coordinator-reported expired case instead takes retirement/renewal. Timeout/natural exit during a later operation is a refusal/HOLD, not a restart trigger. |
| Reviewed remainder | Existing drain, exact probe removal, clean worker shutdown, no-writers gate, newly validated backup helper, RR1 private main+WAL staging/online backup, private verified copies, immutable own-app recreation, RDEP-3 typed retained-data comparison, readiness/postflight and original-HOLD archival remain enforced. No retained/8080/private-key authority is introduced. |
| Failure and completed history | `:1313–1328,1473–1488,1740–1754`: preserve previous continue-failure; accepted new failures add only sanitized started-failure and retain exclusion/evidence. Completion includes all prior records, started receipt/lock and replacement probe record where used. Corrupted/missing history blocks lifecycle. No automatic retry, old-image rollback, restore, pruning or generic lock clear. |

### Read-only models are not execution proof

`validateRemainingEngineShapes` (`:1451–1471`) is a pure configuration-model check: copied inspected engine envelopes, the independent fixed profile and validated candidate images produce candidate-service and backup-helper shapes which are run through the same validators. It checks likely default/authority mismatches before lifecycle but does not inspect future created containers, execute native code, validate SQLite on a real Docker filesystem or establish health/backup success. The checker's output and operator note correctly retain this limitation. Actual new containers/helpers must still pass their real post-create/runtime guards.

The read-only path returns before authorization, permits only resource ls/inspect and fixed Compose config engine calls (plus read-only local context resolution), and suppresses state/failure-record writes. An independent expired-helper check compared the full synthetic state tree before/after and found no byte/inode/mode/size/mtime/ctime changes.

### Executed checks

Used `env -i`, explicit existing Node v23.11.0 PATH and disposable `/tmp` fixtures. No full/combined suite or native-SQLite rerun was needed for this scoped helper/default/continuation change.

1. Focused selection, **45-second outer bound**, exit 0:

```sh
node --test --test-name-pattern='^(engine create false|started-drain |started legacy helper|helper authority projections|expired-probe retirement)' scripts/test_public_image_stand.mjs
```

   **30 passed; 0 failed/cancelled/skipped/todo**, reported duration **31.05 seconds**. Includes false→null orchestration, V3 engine defaults, strict legacy proof, running/expired renewal, 20 admission refusals, epoch/foreign-collision checks, later uncertainty/archive and completed-history tampering. The author's **403 combined passes** are separate reported evidence, not independently rerun here.

2. Both launcher/test `node --check` commands passed within a combined 10-second bound.

3. Independent actual-orchestration probes, **15-second outer bound**, exit 0. Existing fixture/setup functions were imported through an in-memory module without registering author tests or writing probe files. Actual implementation remained unchanged; all Docker/HTTP behavior was injected. Synthetic cleanup ran in finally. Verified:
   - A legacy V2 OOM-false created digest with current null and a clean 360-second-expired helper passes the read-only checker without any state change.
   - Durable started receipts exist before every injected mutation. The expired old ID is removed exactly once without volume deletion, never started/stopped again; a distinct drain-next is created once, inspected before start and started once. No repeated web/API stops, build/pull or retained-resource argv. Same audit and all prior evidence bytes/inodes survive completion.
   - An additional legacy swappiness delta refuses even though it is a valid new V3 equivalence; refusal makes no mutation/state changes.
   - Direct V3 equivalence is stable for permitted defaults; unknown device authority still refuses validation.

Only this report was changed. No actual Docker read/mutation, network, live checker/continuation, private state/Env/JWT/DB access, install/rebuild, staging or commit occurred.

### Operational limits and disposition

Current exact audit/helper eligibility, returned prior client, settled daemon work, trusted engine/source/candidate inputs and no concurrent launcher/tagger/source/context/topology/storage operations remain coordinator responsibilities. The reported live read-only PASS is not permission to bypass a later refusal. For the current expired helper, only the new distinct acknowledgement and retirement/renewal path is reviewed—not restarting its ID or reusing an older command.

Any uncertainty after started-drain.lock admission remains a new HOLD requiring assessment of retained evidence; do not replay or delete records. Unavailable old image contents remain uncertified, rollback is not guaranteed, volumes may legitimately have changed while original worker drained, and startup-change detection is not automatic reversal. Real backups/deployment/native-browser/scan evidence remains separate. No claim of future daemon success is made.

**Final verdict: QUALIFIED APPROVE the V3 helper-authority correction, OOM-only V2 compatibility and exact requested phase-12 continuation including clean expired-probe retirement/distinct renewal, at the reviewed hashes. No actual blocker established offline; actual execution/eligibility is not certified by this review.**
