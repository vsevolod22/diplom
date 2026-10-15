# Default image-only stand — reviewed rework and actual PASS, 2026-10-15

## Current verdict / provenance

**Parent-executed actual smoke: PASS, 39.301s, `SECRETS_SBOM_CHECKED`.** The exact reviewed command below was subsequently executed by the parent on a completely new isolated project. This supersedes the earlier **NOT RUN** execution status; the historical source-only/rework/prebuild checks remain separately recorded below.

**Independent review note (parent-reported):** the rework following prior Review483… and the exact command with reviewed source hash `72af124c0a5e1d9821211f0bdd71a7f7583bb4cbb35ed6911bf754839ef9cd46` were accepted before the parent executed them, including the API-only structural no-deps alternative. This documentation pass did not query the review backend or issue a new independent approval. It reconciled the parent's statement against the own public result file; it did not rerun the harness.

**This documentation update used only bounded local public-result reads/hash/consistency checks.** No scanner, Engine/native command, browser or harness was rerun; no source changed. The credential-bearing private compose was not read (the parent reports it was removed by finally). No stage/commit.

The earlier rework pass fixed HTTP/browser/pre-create hazards, performed separately authorized web/gateway prebuilds, public image/browser-path metadata inspection and Compose **config-only** checks. It did not itself start a stand. The later parent actual run is the distinct successful execution recorded here.

BuildPASS alone still does not equal scan PASS; **this new actual receipt** supplies the narrow default secrets+SBOM smoke evidence. It is **not** old-data migration, rescue/recovery/backup preservation, a rollout of the original stand, CVE qualification or production deployment acceptance. Original HOLD/recovery and broader task acceptance remain separate. The earlier API/worker BuildPASS remains in `build-validation-20261015.md`.

## New actual result — bounded public receipt

- Project: `dip-image-stand-08faa29110d44d0f9a8b6ac610020fad`.
- Exact original result locator, relative to repository root `diplom`: `test-results/dip-image-stand-08faa29110d44d0f9a8b6ac610020fad/result.json` (**2,464 bytes**).
- SHA-256 of the original result bytes: `99d278876b7c8be5afd343e69b0159bbe119a74ca2b9e15ef58c967edfe67d6a`.
- Small sanitized sidecar: `docs/deployment/image-stand-actual-20261015.json` (**1,660 bytes**), SHA-256 `7824e4567bd4681a0c35434d024787b93102d4ee534ef1b9f7eb2536a03cf30d`; allowlisted summaries/counts/IDs/digest only, no credentials, finding/component rows or full logs. Its source locator/hash bind it to the original local result. This is not a tracker evidence seal or proof that ignored artifacts are retained indefinitely.
- Recorded baseline: `636b834fa7d3c4d8114ecb4cf4fcc9357ca075e7`; reviewed harness hash and prebuilt metadata hash match the pins below. Image mode: `PREBUILT_ONLY_NO_BUILD_PULL_HISTORY`; phase: `checks_finished`; deployment: `NOT_PRODUCTION`.
- Main scan ID: `a4629fe1-41bc-4eb8-9689-b19b09dec047`.

| Criterion | Actual result from public `result.json` | Boundary |
|---|---|---|
| Real default secrets + SBOM | **SECRETS_SBOM_CHECKED**, secrets **0**, SBOM **15**; both report datasets `pages_checked=true` | Checked zero secrets is not a safety guarantee; no synthetic finding/component rows added |
| HTTP→outbox→worker receipt | **completed**, attempts **1**, delivered **1**, checks `["secret","sbom"]` | Own fresh ledger only; not an old DB preservation/migration check |
| Target binding | `sha256:1c4eef651f65e2f7daee7ee785882ac164b02b78fb74503052a26dc061c90474`, **linux/amd64** | Target data selected by default resolver; native stand images remain arm64 |
| SSE | **PASS**, queued **1** → running **2** → completed **3**, terminal replay | Terminal exclusive replay/exhaustion, not long-idle/native reconnect/restart qualification |
| Browser + reload | **PASS**, reload **true**, LLM context disabled **true**, blocked requests **0**, browser errors **0** | Actual current report UI; no generation/chat/provider calls or OS-isolation claim |
| 429 | **PASS**, `scope=eligibility_only`, Retry-After **60s** | Not scan-admission/global-capacity acceptance |
| Cancel | **PASS**, cancel scan `8b676e87-6d2d-4407-86df-60e631bdf7a9` | Child termination explicitly **best_effort_not_proven** |
| CVE | **UNSUPPORTED_NOT_ENABLED_NO_DB_RELEASE** | No positive CVE/DB coverage claim |
| Own cleanup | **PASS**, **13 recorded resources**, `errors=[]` | Harness receipt, not a new Engine audit or authorization to clean foreign resources |
| Whole run | **PASS**, **39.301s** | Prebuilt-only finite smoke, not production qualification |

Public dataset hashes preserved in the original receipt: secrets `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945`; SBOM `f9f90fd96d401ab4be0eb4cf04946cce95243c05375d3416119aa828098e479c`. The documentation pass checked these public fields and summaries offline, without opening the owned ledger, private compose, resource journal or logs.

## Exact review pins

Product source baseline: `636b834fa7d3c4d8114ecb4cf4fcc9357ca075e7`.

```text
72af124c0a5e1d9821211f0bdd71a7f7583bb4cbb35ed6911bf754839ef9cd46  server/deploy/proof/final-image-stand.py
b8ae52178a8dd86d1ca9435036655a4f66bbfe2fa1e7cb00a6fb377bdb8f7b29  server/deploy/proof/test_final_image_stand.py
307e41943229878004438a6660ce23edc2fb255daeb6ca19b01756fe1a195889  test-results/final-image-prebuild-20261015-r2/prebuilt-images.json
```

The manifest is a public local build receipt, not a secret and not a tracker artifact/evidence seal. It records source/context hashes, image IDs/labels/build refs, successful exit/no timeout, existing public BusyBox RepoDigest and observed Chromium toolchain. The runtime requires its reviewed SHA-256 and verifies actual selected local image metadata against it; a label alone is not presented as a cryptographic source proof. Missing images cause failure, never an implicit build/pull.

## Historical Review483… blockers and rework (preserved)

### 1. nginx HTML 404 versus strict app JSON

`Http.request_raw()` is the bounded fixed-loopback raw bytes/status primitive. `expect_status()` uses it for the nginx-hidden JWT path `/api/v1/scans`: an HTML 404 is the expected denial, not a JSON payload.

`Http.request()` remains strict for application endpoints: JSON media type, UTF-8, valid structured JSON, no duplicate keys or non-finite constants. It does **not** silently fall back to raw bytes. Redirects are not followed; body/time limits and cookie/Origin guards remain unchanged. Regressions cover HTML 404, malformed app JSON and valid app 401 JSON.

### 2. Exact disabled summary context GET, no provider operations

The embedded browser policy permits the automatic Summary request **only** as the exact same-origin, same-scan `GET /api/v1/browser/scans/<scanId>/llm/context`, without query/trailing slash. Other owner report/status/events GETs and public same-origin assets remain allowed. Foreign origins/scans, POST, summary generation, chat/history/usage and prefix lookalikes are denied.

Both navigation and reload await the **real** context response; all observed exact context responses are checked for HTTP 200 + JSON, matching scan/digest/platform/report version, `enabled === false`, `policyVersion === null`, `disclosure === null`. No provider/config override is introduced to manufacture this state. The current default API has no enabled provider policy. Unexpected generation/extra LLM requests fail the smoke instead of being fulfilled/mocked or allowed.

Pure Node regressions execute just these policy/contract functions, **not** Playwright/browser/network. Full browser source also passes syntax-only `node --check`.

### 3. No replacement/adoption before the ownership guard

Immediately before each create:

- validate the constrained spec again;
- require the exact existing service→ID set (empty for initial create; the other five own services for API recreation);
- require exact project inventory IDs, no extra/orphan services;
- check all six deterministic container names using **ID-only** inspect first, so a name collision does not read a foreign container's Env/mounts;
- recheck already-recorded own IDs/nonce/project/service ownership and exact own storage identities;
- for API recreation, require own gateway/worker/web already running and own fresh init containers exited successfully.

Every create uses `--no-recreate --no-build --pull never`, with explicit targets. Post-create discovery validates exact nonce/project/name/service sets, preserves all preexisting own IDs and rejects foreign/late collisions before any start. Cleanup never adopts or removes a foreign collision. Tests cover collision after earlier discovery, collision between immediate preflight and create, extra project IDs, non-ready own dependencies, and preservation of the five existing IDs.

**Installed Compose compatibility, explicitly for reviewer:** `docker compose create --help` on this toolchain has `--no-recreate` but **does not support `--no-deps`**. Shipping that flag would only fail before scanning. Therefore API recreation is **no-deps by construction**: a separate API-only spec, passed over stdin with `--file -`, contains just the unchanged API service with `depends_on` removed after the own-dependency state checks above. Other five services are not present in that create document. No `up`, implicit dependency start, `--force-recreate` or orphan removal is used. All API image/env/network/mount/user/security/resource/health settings remain the same. Initial create explicitly targets all six fresh services in the full spec.

This is a deliberate compatibility alternative to the review's literal `create --no-deps` request, **not a claim that the unsupported flag works**. At rework time it required reviewer acceptance; the parent subsequently reported acceptance of the exact command and successful execution recorded above. The historical full/API-only validation used **`compose config` only** and created nothing; the later parent actual run is a separate execution.

Actual Compose normalization also emits `entrypoint:null` and `command:null` for inherited image defaults. Only those nulls are removed before validation. Empty or non-null overrides remain rejected (except the exact baseline fresh init command). A regression covers both null inheritance and rejection of empty/non-null overrides.

### 4. Prebuilt-only actual harness: no daemon build tail

Actual arguments select immutable web/gateway IDs plus a reviewed manifest. Runtime Docker verbs are allowlisted: selected image inspect; own container/network/volume operations; Compose config/create only. `build`, `buildx`, history, pull and image pull are refused before a subprocess starts. `prepare()` has no git archive/build/pull/history calls; only the public baseline Compose source is read from the pinned HEAD. Only the public compose plugin is linked into its empty Docker config.

The actual 900s budget now covers only preflight/new stand/checks/cleanup. It cannot leave an in-progress build daemon task. Existing BusyBox is verified by image ID and public RepoDigest and is used by ID; if it is missing or changed, actual fails without pulling.

## Separate authorized prebuilds — actual results

Credential-free work directory: `test-results/final-image-prebuild-20261015-r2/`. New `docker-config/config.json={}` (0600), HOME directed to that work directory, explicit host `unix:///var/run/docker.sock`, allowlisted CLI environment. No original Docker auth/context/env files or private workspace paths were read. Only public Docker Desktop CLI plugins were linked.

Context was `git archive --format=tar` of the explicit `PUBLIC_PATHS` at the pinned HEAD; metadata validated before sending to Docker: **401 entries, 3,409,920 bytes**, SHA-256 `ba69af8fead84d3e8ebe0b2a4316399608a900b918405330f5a014f4fc56bf8c`. Private paths, key/DB files, traversal and links/special entries are denied. No arbitrary working-tree `COPY .` context: the web Dockerfile's `COPY . .` sees only this approved archive.

Builds were strictly sequential, fresh `--load --no-cache`, no `--pull`, cap **600s/image**, external tool timeout **650000ms/image**. Target tags were absent before use. No Running BuildKit record before either build; each terminal record and final absence of Running verified.

| Role | New tag | Exit / timeout | CLI duration | BuildKit terminal ref |
|---|---|---|---:|---|
| Web | `dip-final-prebuilt-web-72e15222635a4190:636b834` | **0 / false** | **67.926s** | `default/default/jlotcm1fxvcnrr0z6uumze21z` — Completed |
| Gateway | `dip-final-prebuilt-gateway-72e15222635a4190:636b834` | **0 / false** | **2.141s** | `default/default/z41tqxllvej2m16ibutvez2dz` — Completed |

Final history check: **2026-10-15T20:11:06.884910+00:00**, both records Completed, Running **false**, recorded in `history-review-final.json`. These are local daemon observations, not registry publication or deployment.

### Immutable image IDs

| Role | Local immutable ID | Platform / image user |
|---|---|---|
| API, earlier accepted build | `sha256:70d11c11167a1bd8ecbc68901b5cd4b99efb99a2a472c69a32d769df05673878` | linux/arm64 / `65532:65532` |
| Worker, earlier accepted build | `sha256:79d8cdcdf65f8d85a93390255e457f434b6cfceac6147da019fecd499d7a7844` | linux/arm64 / `65532:65532` |
| New web | `sha256:634203d96fdc419f3018db6d8d417449423f0455c0bc48778dd603f920d45d31` | linux/arm64 / `101:101` |
| New gateway | `sha256:e899d14b4e379b6467562b9e4fd30a9181b37a5e1257125568df16b2a857e072` | linux/arm64 / `65532:65532` |
| Existing public BusyBox 1.37.0 | `sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e` | linux/arm64 / default root for exact fresh-volume CHOWN only |

Public BusyBox RepoDigest actually observed: `busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e`. Pinned reference: `busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e`. It was already present; **no BusyBox pull was needed**. This is observed public image metadata, not an invented digest or a new container run.

New web/gateway config labels bind `org.diplom.final-image-stand.source`, `.context`, `.role` to the above source/context and web/egress role; actual selected image inspection matched these labels and the manifest. In this store the web/gateway/API/worker IDs are local OCI index digests, not platform config digests.

Resolved public base refs from build logs:

- Node `24.11.1-bookworm-slim@sha256:48abc13a19400ca3985071e287bd405a1d99306770eb81d61202fb6b65cf0b57`.
- nginx `1.27.5-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`.
- Python `3.13.7-slim@sha256:5f55cdf0c5d9dc1a415637a5ccc4a9e18663ad203673173b8cda8f8dcacef689`.

Web ran the real baseline `pnpm build` successfully. Warnings: Node `DEP0169` from pnpm and Vite chunks >500kB. No warning-suppression or unrelated bundle changes were made. Gateway had no matched warnings. No build failure/timeout in these attempts.

### Safe build argv / environment actually used

The exact per-image argv arrays and exit/duration records are in `web.result.json` / `egress.result.json`; plain combined stdout/stderr logs in `web.build.log` / `egress.build.log`. Executed argv shape (web then egress), with literal role/tag/file values from the table:

```text
/opt/homebrew/bin/docker --config /Users/vsevolod/Documents/oldstartup/diplom/test-results/final-image-prebuild-20261015-r2/docker-config --host unix:///var/run/docker.sock buildx build --builder default --load --no-cache --progress plain --tag <recorded-new-tag> --iidfile <own-role.iid> --metadata-file <own-role.metadata.json> --label org.diplom.final-image-stand.source=636b834fa7d3c4d8114ecb4cf4fcc9357ca075e7 --label org.diplom.final-image-stand.role=<web-or-egress> --label org.diplom.final-image-stand.context=ba69af8fead84d3e8ebe0b2a4316399608a900b918405330f5a014f4fc56bf8c --file <server/deploy/stand.Dockerfile-or-server/deploy/gateway/Dockerfile> -
```

Stdin was the own `context-636b834.tar`; no ambient env forwarded. CLI environment was exactly PATH `/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`, HOME/work, DOCKER_CONFIG/own config, DOCKER_BUILDKIT `1`. Each build used a separate process group and bounded wait; timeout fallback would signal only that own CLI group, not certify daemon cancellation. It was not needed. Do not repeat these existing tags automatically.

```text
a7bcb63361fdf44255693e150bc04ba0e49f44861d0de8fa84ee3d1356ade812  web.build.log
255f37eee6c6bcefe8d5d5603e8c44316c814e803e419ba356830540c9129dc8  egress.build.log
```

No images/cache or preexisting tags/resources were deleted. These builds use the shared default builder; no host/build hard CPU/RAM isolation is claimed.

## Historical browser prerequisite — path resolution only

Public `@playwright/test` **1.59.1**, `chromium.executablePath()` returned:

```text
/Users/vsevolod/Library/Caches/ms-playwright/chromium-1217/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing
```

At prebuild/rework time the file existed and was executable; only the package's public path/version resolver was evaluated, without launch, browser profile read or installation. The same explicit approved toolchain path was then passed in the parent's actual command below; actual browser/reload PASS is recorded above. Host Chromium OS/network/cgroup isolation is **not** claimed; a new context/profile, read-only GET policy and bounded process are application-level controls, not an OS sandbox proof.

## Historical source/config validation before the parent actual run

```sh
python3 -B -m unittest discover -s server/deploy/proof -p test_final_image_stand.py -v
python3 -B -m unittest discover -s server/deploy -p test_dockerfile_closure.py -v
python3 -B server/deploy/proof/final-image-stand.py --plan
```

- **48/48 new harness safety/contract tests PASS**: mock Docker/HTTP/clock/topology and pure Node policy tests, no Docker lifecycle/listeners/browser/scanner/provider.
- **5/5 existing static closure tests PASS**.
- Full embedded browser `node --check --input-type=module` PASS; no import/launch.
- Actual public prebuilt manifest hash + selected image labels/IDs/BusyBox RepoDigest verification PASS, inspection only.
- Installed `compose create --help` verified flag availability, without issuing create.
- Actual installed `compose config --format json` PASS for baseline→constrained full six-service spec and API-only no-dependency spec. Synthetic JWT remained memory-only for these checks; no config/credential stdout dump. No create/start/up or resources were made.
- Default/import/`--plan` stays inert; unit test blocks subprocess/socket/filesystem writes during import and plan.

The previous source-only mock suite did not detect actual Compose's inherited null fields or the unsupported `--no-deps` flag. Those are now explicitly probed/covered rather than claiming mocks prove real runtime behavior.

## Exact accepted invocation — executed by parent; historical record, DO NOT RERUN

From repository root `diplom`, the parent reports executing exactly this previously reviewed command after acceptance. The original public result records the matching reviewed-source/prebuilt hashes and all five immutable image IDs. This documentation update **did not execute** the command:

```sh
python3 -B server/deploy/proof/final-image-stand.py \
  --execute-reviewed \
  --reviewed-sha256 72af124c0a5e1d9821211f0bdd71a7f7583bb4cbb35ed6911bf754839ef9cd46 \
  --web-image sha256:634203d96fdc419f3018db6d8d417449423f0455c0bc48778dd603f920d45d31 \
  --gateway-image sha256:e899d14b4e379b6467562b9e4fd30a9181b37a5e1257125568df16b2a857e072 \
  --init-image busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e \
  --prebuilt-metadata test-results/final-image-prebuild-20261015-r2/prebuilt-images.json \
  --prebuilt-sha256 307e41943229878004438a6660ce23edc2fb255daeb6ca19b01756fe1a195889 \
  --chromium-executable '/Users/vsevolod/Library/Caches/ms-playwright/chromium-1217/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing'
```

**The parent executed this command once for the new project and obtained the actual PASS above. Do not rerun it from this record.** Hash pins do not substitute for reviewer/human approval of future execution. Any source/manifest/toolchain/baseline change invalidates this accepted invocation; do not auto-refresh pins or fall back to mutable tags. This run consumed prebuilt images only.

## Executed smoke scope / remaining honest limits

- Baseline default image-only composition; only new random project/labels, four new networks and two new named volumes. Origin **http://127.0.0.1:18080**, all-accounts **false**, explicit account-ID enrollment. Three synthetic registered accounts: owner, enrolled foreign peer for 404 isolation, unenrolled account for 403. No old mounts, DB, keys/env, Docker socket, provider/CVE release/history/runtime/host wiring.
- Real default readiness and Alpine-only admission; no subclass, queue seeding, fake scanner, fixture gateway/CA, heartbeat forging, TLS bypass or direct egress. Target `registry-1.docker.io/library/alpine:3.21.3`, checks `secret,sbom`, scanner target linux/amd64 data on native arm64 worker. Actual target pin remains the production resolver's verified manifest.
- Current gateway exact hosts: registry-1.docker.io, auth.docker.io, production.cloudfront.docker.com, hub.docker.com; CONNECT 443 only, all DNS answers global, numeric-IP dial. Source limits: 64 connections, 64MiB/tunnel, 8192-byte header, 10s header/5s dial/35s connected socket/30s selector idle. Default Docker DNS only; no resolver workaround or allowlist expansion.
- Real HTTP create + idempotency replay, owner/foreign/anonymous reads, completed+both checked, full bounded report-v1 pagination, exact own read-only outbox receipt, terminal SSE exclusive replay/exhaustion, real frontend+disabled context+reload, fresh report comparison.
- CVE remains **unsupported/not enabled**; this run recorded default denial without release, not fresh DB/CVE coverage. SSE is terminal replay, **not** long-idle/native reconnect/restart qualification. 429 is **eligibility-only**, not scan admission/global-capacity acceptance.
- Cancellation returned **PASS in this run**, not PARTIAL_CANCEL_RACE. The reusable harness still treats a 409 terminal race as **PARTIAL_CANCEL_RACE**, nonzero exit; a 200 requires cancelled state stable on re-read. Physical child termination remains best effort, not proved by ledger cancellation. No worker pause/stop or seeded queue to force a PASS.
- Actual whole budget **900s**, normal work stops at **780s**, cleanup reserve **120s**; no build/pull/history in it. Selected scan stage source timeout 60s, harness terminal wait ≤300s, browser bounded ≤90s. Runtime services: 1CPU/128PIDs, worker1GiB/API512MiB/web+gateway+init256MiB, memswap equal RAM; read-only rootfs/drop ALL/no-new-privileges. Only two new network-none init containers receive CHOWN. Worker tmpfs512MiB, API/web64MiB.
- Own cleanup only: full recorded container/network IDs plus nonce/project labels; volumes have **no immutable Docker ID**, so exact Name+CreatedAt+labels are required. No force volume deletion, `down --volumes`, prune or image/cache removal. Immediate guards and durable own-ID journal remain; uncertain creation/ownership/cleanup gives INCOMPLETE, never broad recovery. Foreign collisions remain untouched.

**Current outcome:** reviewed command accepted and parent actual default image-only smoke **PASS**, as reconciled with the own public receipt. No new run is requested or authorized by this document. It does not migrate/recover original data, lift the original stand's HOLD or close broader CVE/runtime/host/provider/reconnect/production acceptance gates.
