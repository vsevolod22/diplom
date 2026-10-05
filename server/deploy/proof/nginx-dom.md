# Disposable exact-pin nginx DOM proof

Run from the repository root:

```sh
python3 -B -m unittest server.deploy.proof.test_nginx_dom_path -v
```

Prerequisites: Docker, installed Playwright Chromium, the existing local stand envfile and a currently fresh published, locally attested DB release. This test never reads the private signing key or refreshes/re-signs the DB. Expired, missing or invalid DB fails closed, not with a fabricated clean result.

The harness uses BOTH `compose.stand.yaml` and `compose.stand.vuln.local.yaml`, plus a temporary overlay, unique project, fresh auth/ledger volumes, transient credentials and random test JWT. The only ingress is loopback `127.0.0.1:18080`. It compares the live envfile bytes privately and removes only its own project/volumes in `finally`. Concurrent tests competing for this fixed proof port are not supported.

The proof starts a separate Nest composition (`src/oci/nginx-proof.main.ts`) with the real auth and browser controllers and `NginxProofScansService`. Production `AppModule` does **not** import this composition/profile. There is no production nginx enable flag. The proof profile maps only an actual official nginx Docker Hub search result to the immutable candidate; create re-verifies child/config/platform through the existing bounded gateway inspector. Other tags, child pins and repositories are rejected before enqueue. Worker archive, Trivy, DB verification, resource/egress controls and fenced ledger are unchanged.

Candidate: child `sha256:0dcc88822d45581e65ae329f8be769762bf628d3b2bb7d2a077d4aa5c98b30e3`, config `sha256:dc73b49f5124cf2ee538dfbdfbd121f0b4ccdcb20fea30f3a81bd477c02e2bb5`, `linux/amd64`. No mutable tag is admitted. The old EOL candidate remains a negative in `test_nginx_archive_path.py`.

Chromium performs actual DOM login, search, selection, combined scan creation, terminal report and reload. It asserts the persisted image identity, per-check outcomes, positive normalized CVEs, 72 APK components, Alpine 3.23.3, scanner and DB release, OS checked and Node/npm unsupported. It also tests replay, changed-check conflict, wrong Origin, other pins/repositories, anonymous and foreign-owner result isolation, one persisted job and scratch cleanup. No scan is seeded and no HTTP response/DB/readiness/scanner is stubbed. Credentials and raw scanner/error output are not printed; failures report only a phase and bounded server coverage snapshot.

The effective worker memory cap is the existing local overlay's **2 GiB**, not
the base stand/judge's 1 GiB. The wrapper asserts that effective cap alongside
CPU/PID/rootfs/network/mount constraints. It does not change caps or certify the
1-GiB target; a separately reviewed memory/resource-contract decision is still
needed before production opt-in. Missing/expired signed DB must fail the positive
proof; do not refresh/re-sign/bypass freshness merely to manufacture a pass.

A successful proof is **not** production qualification or whole DIP-TASK-2 acceptance. `imageProfile.qualified` remains false. Three independent security/correctness/spec reviews and explicit local operator opt-in are still required before a reviewed production profile/deployment. Remote npm positive, full provenance/conflict-preserving dedup/redaction coverage, the remaining stale/tampered/expiry matrix and actual NEW upstream rotation/rollback are separate outstanding criteria. A pass with the current DB is not rotation evidence; local attestation is not an Aqua publisher signature.
