# Disposable exact-pin nginx DOM proof

Run from the repository root:

```sh
python3 -B -m unittest server.deploy.proof.test_nginx_dom_path -v
```

Prerequisites: Docker, installed Playwright Chromium, the existing local stand envfile and a currently fresh published, locally attested DB release. This test never reads the private signing key or refreshes/re-signs the DB. Expired, missing or invalid DB fails closed, not with a fabricated clean result.

The harness uses BOTH `compose.stand.yaml` and `compose.stand.vuln.local.yaml`, plus a temporary overlay, unique project, fresh auth/ledger volumes, transient credentials and random test JWT. The only ingress is loopback `127.0.0.1:18080`. It compares the live envfile bytes privately and removes only its own project/volumes in `finally`. Concurrent tests competing for this fixed proof port are not supported.

The proof starts a separate Nest composition (`src/oci/nginx-proof.main.ts`) with the real auth and browser controllers and `NginxProofScansService`. Production `AppModule` does **not** import this composition/profile. There is no production nginx enable flag. The proof profile maps only an actual official nginx Docker Hub search result to the immutable candidate; create re-verifies child/config/platform through the existing bounded gateway inspector. Other tags, child pins and repositories are rejected before enqueue. Worker archive, Trivy, DB verification, resource/egress controls and fenced ledger are unchanged.

Candidate: child `sha256:0dcc88822d45581e65ae329f8be769762bf628d3b2bb7d2a077d4aa5c98b30e3`, config `sha256:dc73b49f5124cf2ee538dfbdfbd121f0b4ccdcb20fea30f3a81bd477c02e2bb5`, `linux/amd64`. No mutable tag is admitted. The old EOL candidate remains a negative in `test_nginx_archive_path.py`.

Chromium performs actual DOM login, then a separate cookie HTTP-created standalone CVE job, followed by DOM search, selection, combined scan creation, terminal report and reload. It asserts the persisted image identity, per-check outcomes, positive normalized CVEs in both jobs, 72 APK components, Alpine 3.23.3, scanner and common DB release, OS checked and Node/npm unsupported. It also tests replay, changed-check conflict, wrong Origin, other pins/repositories, anonymous and foreign-owner result isolation, two persisted jobs and scratch cleanup. No scan is seeded and no HTTP response/DB/readiness/scanner is stubbed. Credentials and raw scanner/error output are not printed; failures report only a phase and bounded server coverage snapshot.

The worker overlay now enforces **1 GiB RAM / no swap**: `mem_limit` and
`memswap_limit` are both 1g (Docker's MemorySwap is RAM+swap, not extra swap).
The wrapper checks merged both-file config, HostConfig, cgroup `memory.max`
1073741824 and `memory.swap.max` 0, CPU1/PIDs128, unchanged tmpfs16MiB/512MiB,
RO root, dropped caps, internal networks and RO/no-key/no-socket mounts. A fresh
container's before/after cgroup counters and bounded current-memory polling
attribute its peak to this positive pair, **not** to an old worker's lifetime.
It reports hard-limit reclaim (`memory.events.max`) separately from OOM. A pass
at exactly the limit is not headroom or a guarantee for other DB/image releases.
Missing/expired signed DB fails the positive proof; an authorized host refresh
may accept a genuinely fresh upstream release through the existing guards,
never re-sign stale bytes, alter time or bypass freshness.

## Memory failure and restart proof

```sh
python3 -B -m unittest server.deploy.proof.test_nginx_memory_path -v
```

This sequentially includes the positive pair above, then:

- Invokes real `recoverArchiveScratch` on one generated abandoned tree in the
  idle disposable worker and verifies RO DB inode identity is unchanged.
- Allocates bounded real pressure in a test-only exec injector with elevated
  **own** OOM score. Exit137 and cgroup oom/oom_kill increments prove injector
  OOM with the worker alive; they do **not** prove whole-worker OOM handling.
- Creates a real combined cookie HTTP job and observes/signals actual Trivy's
  CVE subprocess atomically. SIGKILL produces partial with Secrets/SBOM checked,
  CVE failed/SCAN_FAILED, DOM report reload and private scratch cleanup.
- Creates another job, observes/stops its actual CVE stage and SIGKILLs the whole
  container. Restart retains the ledger and RO DB, resets tmpfs, waits for the
  **unchanged 627s lease** and completes as attempt2. No original in-memory partial
  report existed before death. Durable attempts/report/event counts and a real
  rejected attempt1 writer show no duplicate terminal event or stale overwrite.
  A tmpfs reset is not claimed as boot deletion of files retained across restart.

The 2026-10-06 author run passed 1/1, zero skips, in779.934s: standalone209 and
combined209 normalized OS CVEs /72APK, current DB manifest
`sha256:018edd6b1a4c854dc5e47ef8303b90d219ca64a661dec52d843753fbc5e1f56a`
(fresh through2026-10-07T13:07:05.606377538Z), Trivy0.69.3. Fresh positive-pair
cgroup peak1073741824, sampled peak1073680384, max10869, oom/oom_kill0. Pressure
then raised oom/oom_kill to1 and killed only its injector; scanner kill was
partial, whole-container restart completed after631.471s (remaining lease at
kill610829ms), attempt2/one terminal event. These are dated author measurements,
not independent reviews or timeless CVE counts. One earlier positive attempt
failed terminal with no per-check report; its cause remains unclassified despite
subsequent passes. Parent OOM specifically is not certified by the SIGKILL test.

The authorized host refresh preserved the live worker's previous 2GiB RAM/4GiB
RAM+swap via a temporary explicit overlay while activating the new DB and
preserving JWT. The live resource change and nginx opt-in are **not deployed**
until fresh independent reviews. The disposable proof uses the new1GiB/no-swap
policy without such an override. Witnessed activation is not controlled rollback
or full rotation acceptance; local attestation is not publisher authentication.

After final replay/foreign-owner/visible-failure assertions were added, the last
full invocation was user-interrupted after the positive pair and pressure OOM
passed. It is **not** reported as a full final pass. The author resumed only the
negative scenarios against that exact disposable project: pressure OOM delta+1,
kill partial/visible SCAN_FAILED+unknown count after reload, restart completed
in632.203s (remaining lease611768ms), attempt2/one terminal event/old writer
rejected. The continuation finally removed that project's volumes and transient
files and verified unchanged live env bytes. Earlier full779.934s pass and this
final positive-prefix+negative-continuation evidence are distinguished.

A successful proof is **not** production qualification or whole DIP-TASK-2 acceptance. `imageProfile.qualified` remains false. Three independent security/correctness/spec reviews and explicit local operator opt-in are still required before a reviewed production profile/deployment. Remote npm positive, full provenance/conflict-preserving dedup/redaction coverage, the remaining stale/tampered/expiry matrix and actual NEW upstream rotation/rollback are separate outstanding criteria. A pass with the current DB is not rotation evidence; local attestation is not an Aqua publisher signature.
