# Protected Alpine/secret slice — not release accepted

`compose.yaml` keeps the API and worker exclusively on `scan_internal`; no API port is published, no Docker socket or direct external route is mounted. The gateway is the only dual-homed process. TLS verification and the exact three-host allowlist remain enabled; lab fixtures and insecure TLS are not production configuration.

`scan-readiness.ts` deliberately refuses **new** jobs with 503. Operational heartbeat and TCP checks do not prove the complete production boundary. An already committed job can still be replayed by subject/key before readiness and processed by the isolated worker. Do not change the release gate to an environment-only flag or publish an ingress to bypass it.

Validation:

- `pnpm --filter @diplom/scan-api test`, `pnpm --filter @diplom/scan-api typecheck` and migration/backup/restart tests.
- `python3 -m unittest discover -s server/deploy -p 'test_*.py' -v` runs fail-closed and actual API/worker direct-connect, daemon, TLS and Trivy NO_PROXY denial probes. The positive 202 and outage-replay acceptance cases in `test_api_docker.py` are **expected failures until the release gate is lifted**; they must become real passes, not skips or permanent expected failures.
- `python3 -m unittest discover -s server/security-lab -p 'test_*.py' -v` checks the separate lab fixture. Its self-signed CA, private test DNS and `--insecure` cannot stand in for the production policy.

Still required before removing the hardcoded gate: production-path controlled TLS OCI manifest/blob/token redirect scenarios, upstream hit/canary assertions on denied destinations, mixed-DNS and rebind on actual CONNECTs from the API and real worker/Trivy, and a controlled reassignment of the **same** tag between 202 and worker/replay/restart. Run them with Docker Engine, no skipped cases, without adding private-address or permissive TLS exceptions to the production gateway. Confirm existing finding/coverage/event endpoints, then repeat all three independent spec/correctness/security reviews. Only after approval should an authenticated non-forwarding ingress be considered. Full CVE/SBOM, cancel, UI and live SSE heartbeat are outside this Alpine/secret slice.
