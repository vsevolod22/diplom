# DIP-TASK-37 — prepared free integration; live activation blocked

Run `82fc78eb-0027-4236-84fe-07b993ab4600`, author work `57712a6a-18f2-4fb1-b219-704b144af873`, stable ID `run82fc:author:57712a6a`, base HEAD `a55a6c5`. Client has no subagent-spawn; lead/architect/author sequential fallback only. Parent must supply genuinely independent reviewers, then own integrator/deploy/closure. TASK14 blocked run1728dc24 is untouched.

## Boundaries

- Write scope `server/**` only. No UI `src/**`/`tests-vite/**` or foreign notice-file edits, commit, Docker change, real model call, spec APPLY, or task closing by author.
- Only reviewed free request `liquid/lfm-2.5-2.6b:free`, provider `liquid`, explicit free mode and all prompt/completion/request/budget caps zero. No paid fallback, router, retry or arbitrary canonical-model alias.
- Public endpoint catalog checked 2026-10-07: Liquid JSON/reasoning supported, token prices0. Catalog does not prove live JSON conformance, request fees, privacy or a successful summary. Parent's bounded real **synthetic** host probe is still authoritative acceptance evidence; no private report in that probe. Nonzero/missing reported cost refuses after a call, not retrospective zero-call.
- `reasoning.exclude=true` only in the verified profile. Nonconforming model output still fails strict envelope/plain-text/current-report/citations; don't relax it to manufacture success.
- Cookie/Origin/authorization, existing scans/users/JWT, zero-evidence refusal, current report/policy/consent publication fences, signed RO DB and host-only private signing key are unchanged.

## Network and key injection

Fixed production Node HTTP CONNECT to `llm-egress:8080`, authority `openrouter.ai:443`; end-to-end TLS verifies `openrouter.ai`, then POST to exact `/api/v1/chat/completions`. No native fetch/env-proxy assumption, direct-connect fallback, endpoint override, redirect or automatic retry. Abort/30s hard deadline/262144-byte request/65536-byte response bounds apply; TLS is verified before Bearer is sent. Provider's smaller policy limits remain applicable.

Dedicated Python gateway reuses the audited CONNECT-only Handler with an immutable only-OpenRouter policy, validates **all** DNS answers as public and dials numeric addresses. Its own `llm_internal` network is internal, with only API+gateway attached; only the gateway joins `llm_uplink`. API has no new uplink, worker has neither this network nor key, and worker's original registry gateway allowlist is unchanged. No published gateway port, socket or key/private-key mount.

Fixed overlay `compose.stand.openrouter.free.yaml` uses Compose `env_file: ../.env.local` on API **only**, not shared `--env-file`, browser, worker or build. Do not `cat`, file-tool-read, print env, Docker inspect/config, raw stderr, or log that secret. Source file must remain ignored, owner0600, regular/no symlink and <=8192 bytes; selector checks metadata only. Compose injects it, productionProvider validates the named key only after owner/consent checks. `.dockerignore` excludes nested env files and `.local-auth`. Do not add the key to `stand.env`.

## Parent deployment — NOT executed by author

1. Get three independent new-diff reviews and the parent's bounded synthetic candidate result. If the candidate's strict output fails, keep disabled; never relax citations/identity/response shape.
2. Follow `nginx-local.md`: ensure already accepted LOCAL descriptor/worker, consistent **online backups** of auth+scan SQLite/WAL and previous image IDs for recovery. Preserve existing JWT/accounts/scans/volumes, both bases, signed DB pins and the host-only private signing key. No prune/down-volumes/reset. This helper does not enable LOCAL itself and does not back up or prove image rollback.
3. Privately add only non-secret operator decisions to existing `.local-auth/stand.env`, preserving every existing entry: `LLM_ENABLED=true`, `LLM_ROUTING_APPROVED=true`, `LLM_REGION=global`, and explicitly approved `LLM_RETENTION=no-training` or `no-storage`. Do not infer supported retention from free prices; `no-storage` requires actual ZDR support or fails closed. These are human decisions; without them the overlay remains disabled. The key remains only in `server/.env.local`.
4. From repository root, **parent only after reviews/backups**:

   ```sh
   python3 server/deploy/trust/deploy-openrouter-free.py --deploy-after-review
   ```

   Helper obtains the same `.trivy-refresh.lock`, requires existing `nginx-local`, writes only `llm: "openrouter-free"` through its live capability, selects one frozen four-file composition, runs `config --quiet`, builds API/web/dedicated gateway, and `up --no-build --no-deps --wait --wait-timeout 90 llm-egress api web`. Worker/JWT/DB pins/volumes/private key are not changed. Captured Compose output/raw diagnostics are never printed. It checks nginx syntax and both chain+LOCAL readiness, **not** a real model call or whole acceptance.
5. Before any up attempt, a build/config failure restores the previous selection. After an up attempt the helper retains the selected descriptor and emits a sanitized failure, requiring private operator recovery from prior images/backups. Rebuilt image tags do not establish a rollback. Don't remove someone else's stale lock automatically. Timer refresh preserves this fourth overlay through pin switch/readiness/rollback.
6. Parent checks actual health, existing-account login/report/scans preservation, API-only network/key boundary and one bounded real synthetic free smoke. Browser verification/UI integration belongs to the parallel UI agent and parent. No live success is claimed here. Spec application/task close only after independent reviews and actual acceptance.

## Parent result — 2026-10-08, default-off deployment only

- Two explicitly initiated bounded synthetic host requests used the saved private key, exact `liquid/lfm-2.5-2.6b:free`, provider `liquid`, no-training routing and all-zero caps. Both returned HTTP404, categorized as no endpoints / data policy / privacy / model. No real report, raw response or credential was published. This is attempted egress, not zero-call; successful model conformance, citations and billing remain unproved. No paid fallback or privacy relaxation was performed. Resolve the account/provider policy at `https://openrouter.ai/settings/privacy` before another authorized probe; do not blindly enable training/publication or claim that changing a setting alone proves compliance.
- Backend and UI had three independent reviews each. Corrections received independent supplemental reviews. An actual default-off deployment exposed missing LLM route registration in `NginxLocalModule`; both attempted deployments were rolled back rather than accepting 404 as success. The correction directly binds the LLM controller/providers to the one existing LOCAL scan service, without importing the default scan module. Actual-Nest LOCAL tests and independent security/correctness rechecks passed.
- Final API+web recreation used the existing **three-file** LOCAL composition under the shared refresh lock; the free overlay/gateway/key injection remain **inactive**. Nginx syntax, chain+LOCAL readiness and signed DB host/API/worker preflight passed at deployment time. This does not guarantee future DB freshness.
- WAL-safe online auth/ledger backups and previous image IDs were retained privately. Before/after full-table/schema hashes, including auth sessions and CVE advisory data, matched: **34 accounts, 28 scans**. JWT/env, descriptor, mounts/volumes and the running worker/registry gateway stayed unchanged. No account login was manufactured, reset or created on LIVE; existing-user browser login was not independently exercised.
- Actual published ingress: anonymous auth/me, context GET and canonical summary POST returned401; private JWT scans returned404. API policy was null and the OpenRouter key absent. UI build passed. A headless Chromium check loaded the actual published bundle with explicitly mocked synthetic browser API responses: the summary panel rendered, its generation button was disabled, one context GET and zero POSTs were observed. This is compiled-UI evidence, not existing-user login or live report/model acceptance. AI readiness stays disabled, not represented as a successful generation.
- Private sanitized deployment evidence: `.local-auth/summary-default-off-deploy.json`; backup databases remain private. Task37 stays blocked85% on external provider/privacy and remaining actual activation acceptance. Task38 is the separate narrow UI contract, not full streaming chat/cache/accounting. DOC8 free-activation delta remains unapplied.

## Focused verification (no expensive full/CVE suite)

```sh
pnpm --filter @diplom/scan-api exec tsx --test --test-concurrency=1 src/llm/tests/free-policy.test.ts src/llm/tests/openrouter-provider.test.ts src/llm/tests/openrouter-transport.test.ts src/llm/tests/llm.http.test.ts
pnpm --filter @diplom/scan-api run typecheck
python3 -m unittest server.deploy.gateway.test_proxy server.deploy.gateway.test_openrouter server.deploy.trust.test_stand_composition server.deploy.trust.test_refresh_local_stand server.deploy.trust.test_openrouter_free_deploy
```

Transport tests use real loopback CONNECT+HTTPS, a disposable test-only CA and synthetic key; they never use the real private file. Deploy tests mock Docker and use disposable source/env fixtures. Source ingress/topology fences are **not** actual nginx/container proof. No full API/CVE/Docker suite is run. Existing TASK13 report/auth/citation fence tests remain part of the focused Nest verification.
