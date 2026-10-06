# Exact-pin nginx DB qualification — author iteration 4

## Scope and implementation

Dated evidence: 2026-10-06, run `8efaa51b-2b21-4ce9-b56b-5940796d1200`, author work `f9608e4a-e3ed-476d-9843-8d29eda4a483`, agent `agentrun8ef:author:4`, parent commit `50e040e`.

This is a bounded proof/DB-failure classification slice, **not whole DIP-TASK-2 acceptance or production qualification**. Production nginx remains OFF/unqualified, task remains in_progress/70%, and the mixed future spec is unapplied.

- `archive-scan-worker.ts` classifies rejection/identity change at the postscan DB-only verification boundary as `DB_UNAVAILABLE`. Scanner, archive identity, malformed output and scratch errors remain `SCAN_FAILED`; cancellation remains timeout. Independent successful checks survive.
- The strict browser CVE failure contract retains an allowlisted, error-code-consistent reason. The report displays `DB_UNAVAILABLE` and unknown vulnerability count, never zero or checked after expiry.
- Separate proof-only API/worker entrypoints use the existing exact supported child/config policy, actual authentication/readiness, real archive/Trivy execution and attempt-fenced SQLite. No production module imports these compositions. Test configuration rejects the production public-key fingerprint and any clock override.
- Host-only disposable keys sign fixtures copied from a genuinely verified usable DB. The private fixture key is never mounted into containers. Fixture metadata times are fabricated for tests; expiry is actual elapsed wall clock, not an injected clock. Schema/malformed negatives intentionally differ from normal signer policy, without weakening that signer.
- Operator-only queued and precommit filesystem barriers, and identity-checked SIGSTOP/SIGCONT of the actual fixed-argv CVE subprocess, establish phase ordering. No seeded jobs, fabricated scanner findings or readiness/HTTP stubs.
- Immutable DB/bundle bytes may be hard-linked **only between the harness's own copied snapshot and non-mutating cases**, never to the live release. Mutating cases get separate copies. This last disk-pressure improvement has syntax validation only; its subsequent Docker rerun stopped before fixture initialization.

## Fixed identities and guards

- Supported child: `sha256:0dcc88822d45581e65ae329f8be769762bf628d3b2bb7d2a077d4aa5c98b30e3`.
- Config: `sha256:dc73b49f5124cf2ee538dfbdfbd121f0b4ccdcb20fea30f3a81bd477c02e2bb5`; `linux/amd64`, Trivy `0.69.3`.
- Copied upstream DB manifest: `sha256:018edd6b1a4c854dc5e47ef8303b90d219ca64a661dec52d843753fbc5e1f56a`.
- DB SHA-256: `9cc5366f2b39f4be91a78e77b2c0311eaa8f62dea163767764579752a6a026c6`.
- Bundle SHA-256: `6884dfca8da15fc0fc17819b7e8dd956302b7758d9a17f3e3c3cde2028dd8a79`.
- Runtime cases assert RAM and total RAM+swap `1073741824`, `swap.max=0`, CPU1/PIDs128, existing 16MiB and 512MiB tmpfs, RO root/DB, dropped capabilities, internal networks, unique auth/ledger volumes, no socket or private-key mount. Archive, output, freshness and lease budgets are unchanged.

A local/test signature is **not Aqua publisher authentication**. These tests do not prove a new production DB activation or rollback. Nginx OS evidence is not remote npm-positive evidence; Node remains unsupported/NODE_INVENTORY_ABSENT.

## Evidence matrix — separate invocations, NOT one full PASS

The full DB proof was **USER-CANCELED**, without a final unittest verdict. Its completed cases and separate continuations below are dated evidence only. Do not combine their results into an uninterrupted successful full run.

| Matrix unit | Observed result | Evidence boundary |
|---|---|---|
| 4 HTTP-created launch sets: Secrets, SBOM, CVE, combined | All completed; actual Chromium owner report/reload; CVE-bearing sets 209 normalized OS CVEs, SBOM-bearing sets 72 APK/Alpine3.23.3 | Completed prefix of canceled full call; ledger/log redaction checks passed |
| 9 invalid-admission fixtures: signed stale, missing DB, DB/bundle/metadata tamper, bad signature, schema, signed malformed metadata, noncanonical descriptor | Each standalone/combined HTTP POST and actual DOM launch rejected 503; no new scan/outbox/report | Same canceled prefix; new redaction checks passed |
| Expired DB, independent Secrets and SBOM | 2 completed jobs; SBOM72 APK | Same canceled prefix; no false dependency on CVE DB |
| Signed/hash-consistent malformed DB content | Standalone failed, combined partial; CVE SCAN_FAILED, independent Secrets/SBOM retained | Same canceled prefix; actual Trivy failure, strict HTTP/DOM, new redaction checks passed |
| Queued expiry, standalone CVE and combined | Standalone failed / combined partial, CVE DB_UNAVAILABLE, unknown count; owner report/reload, one terminal write, fencing/cleanup/redaction | Both completed in later expiry-only invocation, which **failed overall** on four subsequent fixture preparations |
| During actual CVE process, standalone and combined | Standalone failed / combined partial; DB_UNAVAILABLE, ordering and HTTP/DOM/fencing/cleanup passed | Earlier expiry invocation: both passed; later added ledger/log redaction probes were NOT yet present |
| Precommit actual checked report, standalone and combined | Standalone failed / combined partial; DB_UNAVAILABLE; real report before expiry, fenced write after expiry | Earlier expiry invocation: both passed; later added ledger/log redaction probes were NOT yet present |

Earlier queued-combined failed once with an unclassified terminal outcome. An isolated reproduction passed `1/1` in **184.756s**, then the latest queued pair passed with new redaction checks; neither diagnoses the earlier failure. Earlier positive terminal failure, parent kernel-OOM proof and intermittent SSE remain unresolved, not silently certified by subsequent passes.

Final queued pair ordering (UTC epoch milliseconds):

| Checks | HTTP admission | Observed queued | NextUpdate | Operator release |
|---|---:|---:|---:|---:|
| CVE | 1791306478462 | 1791306478625 | 1791306548493 | 1791306548653 |
| Combined | 1791306617981 | 1791306618129 | 1791306689201 | 1791306689361 |

Public test-key fingerprints distinguish separate runs: canceled full prefix `5c21f587fc9ec963a9cb5eada509ced5144ebf5a76ffeec325eeec8d9b7d5161`; latest queued pair `35ac33c49fac39df807f5ec9302749674afb17e5bf98eee78281ea14cf2c5221`.

## Latest failures and cleanup

- Expiry-only invocation: **1 unittest method, 4 subtest failures, 323.920s**. Both queued cases completed; during/precommit fixture preparation failed before execution. A subsequent bounded four-case diagnostic run confirmed `case-copy/ENOSPC` (4 failures, 50.134s). Failed mints now remove only their own partial case and emit allowlisted stage/I/O code, not secrets or exception strings.
- Subsequent four-case recheck after the immutable-snapshot sharing change: **0 executed tests, setUpClass ERROR, 600.010s** — disposable Docker build timed out. A separate `docker info` timed out at10s. Docker security suite was therefore not rerun; historical7/7 is not a fresh result. No Docker restart, shared-image prune, resource widening or production refresh was attempted.
- Canceled residual project `dip-nginx-db-a016b314cbb4` was inspected: one queued job, attempts0, reports0, barrier absent. It was **cleaned, not completed** using both base Compose files, existing envfile and exact `valid-queued-combined-257765ae` overlay. Only that project's containers/volumes and `.local-auth/nginx-db-proof-uo91w33x` were removed. Live env bytes were unchanged.
- Normal subsequent cases cleaned their own project in finally. The timed-out setUpClass had not started scenario containers. A final Docker inventory is unavailable while the engine is unresponsive. No live auth/JWT/key/volume reset, nginx enablement, spec application or task closure.

## Latest non-Docker validation

- API focused9-file selection **36/36 PASS**, zero skips; API typecheck PASS.
- API broad recheck **191/191 PASS**, zero skips. Earlier190/191 SSE67 failure remains unresolved; this passing run is not an SSE fix.
- UI focused **75/75 PASS**, full UI **98/98 PASS**, both zero skips; UI typecheck and build PASS.
- JS syntax, Python AST and diff checks PASS. Older trust15/15, Node4/4 and Docker7/7 results remain predecessor evidence, not new reruns.

## Reproduction and next review

From the repository root, with working Docker and enough disk for an owned snapshot plus a mutable case:

```sh
python3 -B -m unittest server.deploy.proof.test_nginx_db_path -v
python3 -B -m unittest server.deploy.proof.test_nginx_db_path.NginxDbPath.test_03_real_expiry_matrix -v
```

Logs are local, gitignored: `run8ef-author4-db-final.log`, `run8ef-author4-db-expiry.log`, `run8ef-author4-db-queued-combined.log`, `run8ef-author4-db-expiry-final.log`, `run8ef-author4-db-remaining-final.log`, `run8ef-author4-db-remaining-recheck.log` under `.local-auth/`. Preserve failed/canceled logs. Share only sanitized evidence, not credentials, env, scanner dumps or private fixtures.

Three genuine NEW-change security/correctness/spec reviews follow author completion. Remaining validation: independently review the classification and proof-only trust/barriers; rerun the four during/precommit cases with the newest ledger/log probes and validate snapshot-sharing/mutation separation when Docker is responsive. Then separately reviewed compiled local opt-in and actual existing-account UI flow under fresh production trust. Full TASK-2 still needs remote npm-positive, complete two-source provenance/conflict-preserving dedup/redaction across applicable sinks, and controlled new-release rotation/rollback. No full task closure or future-spec application from this slice.
