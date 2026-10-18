# LOCAL public-image stand: source-only profile — 2026-10-18

## Delivered boundary

This is an **offline plan/static-validation delivery, not an activated or runtime-qualified stand**. Public-profile launch, status, stop, restart, refresh and rollback are intentionally blocked until profile-persistent lifecycle support and the reviewed rollout procedure below exist. No acknowledgement flag bypasses this block. Do not apply the overlay directly with Compose to work around it.

Only these paths belong to this slice:

- `scripts/local-stand.mjs`
- `scripts/test_local_stand.mjs`
- new `scripts/public-image-stand-profile.mjs`
- new `server/deploy/compose.local.public-images.yaml`
- this document

Previous dirty CVE activation, immutable public release/trust binding, refresh/HOLD/recovery, scheduler and launcher uncertainty-marker work is retained. No existing deployment manifest, scheduler/refresh implementation, package script, API/worker/ledger source or private configuration was edited. No Docker command, real launcher `up`/`stop`, live DB read/migration, private env/key/JWT read or rotation, old-stand operation, staging or commit was performed. Tests create only disposable fixtures, including synthetic JWT/public-key data and temporary databases; Docker/launchctl operations are injected mocks.

## Explicit composition

Default calls to `composeArguments(root, args, cve)` and `validateConfig(config, root, cve)` remain the legacy profile. Public authority requires the explicit fourth argument `'public-images'`; unknown profiles, mixed API/worker commands and implicit environment activation are not accepted. Public `composeArguments` permits only a file-order plan or `config --format json`, not lifecycle commands. No generic public admission environment flag was introduced.

| Setting | Legacy default | Explicit public profile |
| --- | --- | --- |
| API command | `node --import tsx src/oci/nginx-local.main.ts` | `node --import tsx src/oci/public-image.main.ts` |
| Worker command | `node --import tsx src/worker/nginx-local-worker.main.ts` | `node --import tsx src/worker/public-image-worker.main.ts` |
| Worker memory | 1 GiB | 4 GiB / 4,294,967,296 bytes |
| Worker memory + swap total | 1 GiB | 4 GiB: **zero additional swap** |
| Worker CPU / PIDs | 1 / 128 | 1 / 128 |
| Worker `/tmp` | Existing base/CVE behavior unchanged | 16 MiB, rw/noexec/nosuid, UID/GID 65532 |
| Worker `/tmp/trivy` | Existing CVE cache 512 MiB | 2304 MiB, rw/noexec/nosuid, UID/GID 65532 |

Public worker tmpfs is declared with `!override` (Compose 2.24.4+), not an additive list. The planned order is always:

1. `server/deploy/compose.stand.yaml`
2. `server/deploy/compose.local.full.yaml`
3. `server/deploy/compose.local.cve.yaml` **only when CVE is selected**
4. `server/deploy/compose.local.public-images.yaml` **LAST**

Putting CVE last would reset memory to 1 GiB and `/tmp/trivy` to 512 MiB. Validation rejects that resulting configuration rather than accepting an undersized public worker. No real Compose merge was executed in this source-only delivery; tests check the file ordering/override source and normalized merged fixtures.

The public overlay changes only the two commands and the worker envelope. It does not change builds/images, secrets, environment, accounts, report/ledger storage, networking or port exposure. Inherited isolation remains read-only rootfs, UID/GID 65532 (web 101), dropped capabilities and no-new-privileges. The stricter public validator checks these properties and fixed service resources/tmpfs; alternate deploy/cgroup/CPU/device/resource authorities are rejected without widening legacy validation globally.

Retained contracts:

- `dip-local-full_auth_accounts` at API `/auth` and `dip-local-full_scan_ledger` at API/worker `/data`; persisted reports remain with the ledger, not a new or old-stand volume.
- Existing dedicated JWT, issuer/audience, local cookie/account/origin guards and localhost-only `127.0.0.1:8080`; no new credential, rotation or published API port.
- With CVE enabled, API and worker receive the same pinned release at `/opt/release` and public PEM at `/opt/local-db-trust/public.pem`, read-only, with no host-path creation. Worker additionally receives the fixed release `db` at `/tmp/trivy/db` read-only beneath the larger tmpfs. No parent trust directory or private signing key is mounted.
- Public API/worker source currently selects the existing LOCAL trust helper explicitly. Production/default trust code is not changed here. Signed-release authentication/freshness and live readiness still need independent qualification.
- The public runtime is an image-only composition. An overlay does not itself authorize arbitrary registries, platforms, scope, job fields or checks. Public request/worker admission, receipt/persistence contracts and browser auth remain owned by their respective modules. No nginx LOCAL readiness marker is a public qualification substitute.

## Safe commands available now

Run from the repository root (`diplom`). Both planning commands are offline: they do not inspect `.local-stand`, read activation/JWT/env files, create locks/state, invoke Docker or contact a registry.

```sh
node scripts/local-stand.mjs plan --public-images
node scripts/local-stand.mjs plan --public-images --cve
```

Both returned exit **0**, with `profile: "public-images"`, `mode: "source-only"`, `activation: "blocked"`, exact commands/resources and the required pre-activation checklist. The first plan has three Compose files; the second has four, with the public override last. `--cve` here selects a **plan**, not the current activation: no existing release is loaded or implicitly enabled.

### Offline normalized config validation

```sh
node scripts/local-stand.mjs validate --public-images < reviewed-public-config.json
```

This is command syntax for a separately prepared **public fixture**, not a claim that `reviewed-public-config.json` exists or was generated from the live stand. Input is bounded to 1 MiB on stdin. There are exactly two top-level keys:

```json
{
  "config": { "name": "dip-local-full", "services": {}, "volumes": {}, "networks": {} },
  "cve": null
}
```

The empty service/storage maps above illustrate the envelope only and **will fail validation**. Supply the complete normalized Compose JSON fixture with the exact project topology and absolute repository build context. The API's `SCAN_JWT_SECRET` must be the validation-only sentinel: **96 ASCII zeroes, never a real JWT**. No private env file is needed or accepted. With CVE enabled, replace `null` with the five public activation metadata fields: `version: 1`, bounded `db-releases/<release>` in `release`, `manifestDigest` (`sha256:` plus 64 lowercase hex), `artifactSha256` and `publicKeySha256` (64 lowercase hex each). Paths are derived lexically under this repository; caller-provided host/key path overrides are not accepted.

Success reports `Public-image static config valid; activation BLOCKED.` and returns static-only/blocked status. Validation does **not** open/verify a real release, PEM, signature, SQLite database or backup; it does not prove Compose availability, image builds, resource enforcement or scanner readiness. Public malformed input is never echoed. Full CVE signature/public-file/permissions verification remains in the existing live release validator, not in this offline planning helper.

### Unsupported operations

The actual public `up`/`status`/`stop` CLI was not run. Fixture tests prove these opt-ins fail **before filesystem, Docker or JWT access**, even with a purported rollout acknowledgement. Public `up` remains blocked with or without `--build`.

Legacy launcher/refresh/scheduler callers do not silently adopt the profile. Shared namespace validation requires the legacy API/worker command and rejects observed worker memory or memory+swap of 4 GiB or more even if its command was replaced. Thus a public or mixed observed namespace cannot be recreated as the legacy 1 GiB worker. Ordinary legacy resource drift remains handled by refresh's existing full runtime validator at its established checkpoint, preserving HOLD/recovery diagnostics.

There is no new persistent profile JSON because no public activation is permitted yet. Legacy status/stop are not a public lifecycle backdoor: unsupported public/mixed inventory refuses instead of guessing. A manually deployed public namespace requires reviewed reconciliation; do not run a legacy recreation, delete locks, rewrite CVE activation, rotate JWT or point at old/HOLD/dev storage to get past refusal.

## Mandatory first-activation gate / follow-up

A future implementation must satisfy **all** of the following before permitting activation, including a first launch on retained volumes. This release deliberately cannot satisfy the gate with a CLI boolean:

1. **Reviewed rollout acknowledgement:** bind human approval to the exact source revision, API/worker image IDs, explicit public profile/envelope, current and intended schema, volume identities, trust/release pins, backup receipt and rollback plan. A generic “ack” is not approval of an unknown DB migration.
2. **Admission closed and writers drained:** exclude the scheduler and refresher under the shared operation lock; stop new API admission; prove no queued/running jobs, active leases, pending write work or unrelated volume writers; stop/quiesce API and worker writes in the reviewed order. Merely seeing a ready marker, an idle process or two container IDs is not a drain proof.
3. **Consistent verified backup:** preserve both account DB and ledger/report DB coherently with SQLite WAL/SHM state using a reviewed backup/checkpoint method while writers are drained. Verify integrity and a disposable restore, record hashes/schema/image/volume identity, and preserve the existing JWT privately without printing/rotating it. A copied live `ledger.sqlite` alone is not sufficient.
4. **Durable profile lifecycle:** implement versioned public profile state (or exact inspected composition detection) integrated with the shared lock, mutation-intent uncertainty markers and current activation. Up, status, stop, refresh, scheduler and recovery must all retain the selected commands and 4 GiB/2304 MiB envelope, reject mixed/unknown state, and survive interruption without falling back to legacy. Until refresh supports this, it must refuse the broad profile before any lifecycle mutation.
5. **Migration and rollback rehearsal:** inspect schema compatibility in the disposable restored DB; review any pending constructor/startup migration before running it on retained data. Never auto-migrate an existing live DB. Restoring an old binary against new-profile jobs/results/schema is not a rollback plan. Retain compatible image IDs, volumes, receipts, JWT and public trust/release pins for a consistent restore.
6. **Runtime qualification:** after approval, on an isolated restore first, verify actual image entrypoints, cgroup memory 4 GiB, swap zero, CPU 1/PIDs 128, UID and read-only/noexec/nosuid tmpfs composition, physical 2304 MiB scratch, nested RO DB mount, public-key/signature/freshness checks and public API/worker readiness. Exercise public admission, cancellation/report persistence and scheduler/refresher refusal or profile preservation. No successful fixture result substitutes for these checks.

## Validation performed

```sh
node --test scripts/test_local_stand.mjs scripts/test_refresh_local_cve.mjs scripts/test_schedule_local_cve.mjs
```

Final result: **176 tests passed, 0 failed, 0 skipped**, exit **0** (about 9.6 seconds). Coverage includes existing dirty launcher/CVE/refresh/HOLD/uncertainty/scheduler paths, explicit public profile selection, CVE on/off normalized fixtures, malicious/mixed commands and admission flags, wrong memory/swap/CPU/PIDs/tmpfs, reversed CVE overlay resources, writable/private/wrong-volume mounts, retained account/JWT guards, public static input/path/pin validation, non-mutating offline planning, unconditional activation block, and legacy lifecycle refusal of observed public namespaces.

An initial new test used the real repository build context with a disposable launcher root and was corrected to use that fixture root. The first combined regression run also caught that checking every legacy worker resource in shared inventory moved established refresh failure checkpoints; the implementation was narrowed to broad-profile detection, leaving the existing legacy runtime qualification/checkpoint protocol intact. No refresh/scheduler tests or implementation were edited to hide those failures.

```sh
node --check scripts/local-stand.mjs
node --check scripts/public-image-stand-profile.mjs
git --no-pager diff --check -- scripts/local-stand.mjs scripts/test_local_stand.mjs
```

All returned exit **0**, no output. These are syntax/whitespace checks, not builds or container validation. No Docker/Compose, live registry/scanner, live signed-release, deployed auth/report, backup, schema migration or real cgroup/tmpfs qualification was performed. Activation remains **BLOCKED**.
