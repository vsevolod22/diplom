# Protected Alpine/secret slice — pending independent acceptance

`compose.yaml` keeps the API and worker exclusively on `scan_internal`; no API port is published, no Docker socket or direct external route is mounted. The gateway is the only dual-homed process. TLS verification and the exact three-host allowlist remain enabled; lab fixtures and insecure TLS are not production configuration.

`scan-readiness.ts` refuses new jobs with 503 when worker heartbeat, gateway or isolated network connectivity are unavailable. Operational heartbeat and TCP checks alone do not prove the complete production boundary; deployment must use the verified Compose topology. An already committed job can still be replayed by subject/key before readiness. Do not replace runtime checks with an environment-only flag or publish an ingress without separate review.

Validation:

- `pnpm --filter @diplom/scan-api test`, `pnpm --filter @diplom/scan-api typecheck` and migration/backup/restart tests.
- `python3 -m unittest discover -s server/deploy -p 'test_*.py' -v` checks the public-policy gateway, actual API/worker direct-connect and daemon denial, TLS, Trivy NO_PROXY denial, positive 202→terminal and outage-replay; require zero skips and zero expected failures.
- `python3 -m unittest server/deploy/proof/test_production_path.py -v` uses disposable trusted-CA OCI fixtures with the same gateway handler and actual API/worker/Trivy. It verifies same-tag mutation, forbidden redirects, mixed DNS and rebinding with upstream-hit counters. The test-only exact fixture-IP policy and CA must never be deployed with the public gateway.
- `python3 -m unittest discover -s server/security-lab -p 'test_*.py' -v` checks the separate lab fixture. Its self-signed CA, private test DNS and `--insecure` cannot stand in for the production policy.

The controlled proof suite and public-policy Docker smoke must both pass before three fresh independent spec/correctness/security reviews and task-level acceptance. No public ingress is currently configured; adding one requires separate review. Full CVE/SBOM, cancel, UI and live SSE heartbeat are outside this Alpine/secret slice.
