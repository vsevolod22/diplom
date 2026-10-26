# Native public automation browser candidate — 2026-10-26

**PREPARED / OFFLINE ONLY. No READYGO received, browser launched, live/runtime/provider request, deployment, native scan, account creation or new live evidence.** This document is a source handoff, not acceptance. The last coordinator receipt in `public-finalization-20261026.md` describes the **412-file stand source**; the concurrent preference/automation/structured-response source changes are **not established as deployed** by this work. The `--ack-source-deployed` flag is an operator acknowledgement, not an image/source verification mechanism.

## Scoped implementation

- New `tests-e2e/public-automation-live.mjs` and `.test.mjs`: bounded native candidate, not a new browser framework. Imports the existing exact API GET allowlist, eligibility fence, single-use mutation permit, native browser read/navigation helpers, owner/fresh-login checks, frontend decoders/NDJSON parser, fixed-policy assertions, finite guard ledger and sanitized evidence projection.
- `public-ai-translation-live.mjs`: synchronize `DIAGNOSTIC_PHASES` / `DIAGNOSTIC_REASONS` with backend `provider-diagnostic.ts`, including both translation field phases and all seven new reasons. Full-array offline equality tests remain mandatory. Diagnostics enter evidence only from finite response headers, never body-forged diagnostics/raw payloads.
- Additional authorized scope: `public-product-live.mjs` / `.test.mjs` admit **only** the exact known-scan `GET /llm/summary` (no query/body/other LLM methods), update the product chat helper for the auto-open composer, and execute the real progress JSX/estimate module offline with the live-session hook boundary inert. Shared DOM checks retain state/count/remaining/completion/unknown-ETA assertions while accepting the current explicitly labeled bounded estimate. The three superseded shared-helper failures are fixed.
- The legacy AI runner's manual “Открыть чат” / “Перевести на русский” workflow is **not** the new UI qualification. Its regression test now explicitly records that selector mismatch rather than pretending those controls still exist. Do not use the legacy live command for this candidate.

## One later authorized attempt

Exactly one fresh disposable owner account and one native fixed Node `linux/amd64` public-image scan, selecting **secret, sbom, vuln, config** through real UI eligibility/consent. A 202 receipt preserves the scan UUID but is not scan completion. Worker deadline **660 seconds**, total runner deadline **20 minutes**. No scan retry, cancellation/lifecycle operation, key access/activation, quota reset/refund, saved auth or historical continuation token.

1. Register through native UI. On `/account`, explicitly save **Original + autoSummary=true**, after the visible disclosure; reload the account settings and verify their saved values. No storage/cookie injection or credential artifacts.
2. Before report navigation/completion can dispatch its effect, arm the exact one-use **summary** permit. Observe the client's native **passive GET first**: only exact owner `404 {errorCode:'LLM_SUMMARY_MISSING'}` is a cache miss, not foreign `404 SCAN_NOT_FOUND`, an ingress403/HTML error or another failure. Admission requires that observed miss, native completed status with all four checks checked, current report binding, exact summary context/body and schema-valid fixed free-profile readiness. GET consumes no permit/provider-call count. The summary is automatic, not a manual retry.
3. During the scan observe at least two bounded approximate running estimates, an increase without regression, honest unknown ETA, then server-confirmed completed100% with no active progress element. Too-fast/unobserved running progress is BLOCKED, not invented. After completion click each coverage tile's native technical disclosure and the coverage-help accordion; verify opening/closing without generation.
4. Verify the always-open chat textbox and absence of the old open-chat control. Inspect the successful rendered summary and citations against current scan findings, in process memory only. Send **chat1** by the explicit send button; send **chat2 only after chat1 has validated delivery, matching durable completed history and rendered current citations**. No successful response is inferred from HTTP200: parse the actual completed-reply NDJSON terminal frame.
5. Reload: observe a new native passive GET and require unchanged chat history and **no additional generation**. Compare the returned **entire enriched DTO** with the original successful POST response in memory, verify `X-LLM-Summary-Retention: process-lifetime`, JSON/no-store headers and rendered restored hypotheses. Browser storage still contains only preferences/opaque attempt hashes, not answers. If the API instance restarted/replaced, policy/report changed or the entry was evicted, `summary_reload_restore` stays **BLOCKED / SUMMARY_NOT_RESTORED**; never clear an attempt marker or request another summary to fill the cache.
6. Navigate to account settings and explicitly save **Russian + autoSummary=true**. Return to the report while all advisory cards remain closed. Read the exact selected context/readiness and arm the single translation permit **before opening** one card. Choose only an eligible visible card with **one assessment**: opening a multi-assessment card mounts several automatic effects, which cannot be authorized by this one-request plan. No eligible single-assessment card means BLOCKED, not broader permission.
7. Open that one card to trigger **one automatic selected-advisory translation**; no translate/retry button. Inspect the returned Russian-script text and rendered fields in memory, check binding/source identity, null/identifier retention, unchanged original, original/translation toggle and no extra POST. These checks do not prove semantic fidelity.
8. A fresh empty browser context verifies anonymous denial, including passive summary GET. A separate new empty context then performs native owner login with the original in-memory credentials/subject, own report/history retrieval and browser-local default preferences (Original/autoSummary=false). Passive recovery does **not** require automation opt-in: the subsequent native GET must restore the same summary DTO and UI without any POST. `summary_fresh_login_restore` is independent of history restoration. No auth/header/storageState injection. Final original scan/finding counts, bytes-in-memory fingerprint, history and zero-cost usage are checked.

### Hard generation fence

Maximum **four admitted browser generation POSTs total**: summary1, chat1, chat2, translation1. One global in-flight lane plus exact known-scan operation paths, exact operation bodies/CAS/source/policy consent and consumed permits; no API-prefix/suffix authorization. Automatic summary and selected-card translation use the same gate as manual chat. Unknown/duplicate/foreign/hidden/queued POSTs are aborted and fail safety; they are not silently allowed.

HTTP **429 or503**, upstream429/503 in an HTTP/NDJSON error, or `LLM_PROVIDER_RATE_LIMITED` permanently halts every generation lane. The lane remains locked until the response has been inspected, so queued effects cannot escape during body parsing. Failures/unknown delivery also fail closed; there is no wait/retry/fallback. Finite status/kind/header predicate metadata survives even if a hidden queued POST terminates the workflow. Absent retry hints remain absent. “Admitted browser POST” does not independently prove provider dispatch or invoice cost.

Unchanged required profile: **OpenRouter / xingchen-agi/xing4.0-29b-a4b:free / phala**, no paid/automatic fallback, no-storage declaration, zero-price routing. Every POST is gated on the actual frontend readiness schema and matching report/provider metadata. Summary/translation additionally require exact disclosure keys/data/privacy/zero-price parameters, compared offline with the current `allowAutomationDisclosure` implementation. A mismatch never authorizes LLM dispatch. Server egress, provider compliance and billing are not independently observed by this runner.

### Passive summary cache and ingress prerequisite

The inspected backend implementation (`server/api/src/llm/SUMMARY-RESULTS.md`, service/controller/cache) retains validated results **in one API service instance only**, up to64 entries /2MiB aggregate accounted bytes /65536 result bytes per entry. GET returns the same DTO without a wrapper. It survives browser reload/new owner login only while that instance/entry/current binding remain; this is not durable storage or an API-restart guarantee. No provider/key/quota/history initialization is part of that GET contract.

At source inspection for this handoff, the **exact public nginx `/llm/summary$` location still has `limit_except POST { deny all; }`**. Coordinator must change only that existing location to `limit_except GET POST { deny all; }`, preserve its exact UUID path/body/time/privacy restrictions, and deploy/verify the resulting source. This scope does not edit nginx or infer readiness from backend-only tests. Repeated identical `Cache-Control: no-store` headers from API+proxy are accepted; conflicting/unknown cache directives are rejected.

## Explicit qualification limits

- **Single-account scope cannot prove settings isolation from a different authenticated owner.** `settings_owner_isolation` is explicitly **BLOCKED / SECOND_OWNER_NOT_AUTHORIZED**. Same-owner settings persistence, empty-context defaults, fresh owner login and anonymous denial do not substitute for foreign-owner isolation. This runner does not quietly create a second account or reuse another person's credentials. Cross-owner native proof needs a separately scoped coordinator decision; do not expand this attempt automatically.
- **Summary restoration can now pass through passive server retrieval without storing private browser outputs or another POST.** No-extra-call verification remains separate. Missing/invalid/stale retrieval stays blocked; process lifetime/eviction is not durability.
- **Semantic accuracy/fidelity stays unverified.** The runner compares successful answers with the rendered UI and current source IDs only in memory, and checks Russian-script plausibility/nulls/identifiers. Regex, schemas, citation membership and a server-accepted result are not proof of meaning, factual correctness or faithful translation. Any authorized substantive semantic review must inspect the successful outputs and source meaning in memory, without dumping conversations/source strings to tool output or disk. This runner emits no semantic PASS.
- Consequently this candidate cannot claim complete acceptance solely from a generation success. Every named case remains required; any BLOCKED case yields exit2, any FAIL yields exit1. Summary reload and fresh-login restoration can now pass. The unchanged single-account cross-owner limitation still prevents claiming full acceptance; this handoff does not authorize a second account.

## Evidence and privacy

Only after actual native contact: exclusive mode0600 files `docs/public-automation-<fresh-v4-UUID>.json` and `.md`. A UUID already present in **any** docs evidence filename is rejected before browser contact, including historical namespaces. No `attempt2`, old IDs, replayed results or overwrite. Evidence has fixed fields/codes, finite response-header predicates, IDs/hashes/counters and all case statuses; it includes admitted summary/chat/translation counts.

No request/response bodies, successful answers, original/translated selected strings, conversations, passwords, JWTs, cookies, keys, screenshots, HAR, trace, storageState or private runtime/settings payloads are artifacts. Credentials exist only in process/browser memory. Created runtime data is **not automatically deleted**; no cleanup/destructive runtime action is implied. Partial/failed evidence writing and nonzero exit are not acceptance.

## Validation actually run (offline)

From `oldstartup/diplom`:

```sh
node --test tests-e2e/public-automation-live.test.mjs tests-e2e/public-ai-translation-live.test.mjs tests-e2e/public-product-live.test.mjs
node tests-e2e/public-automation-live.mjs --preflight
pnpm exec eslint tests-e2e/public-automation-live.mjs tests-e2e/public-automation-live.test.mjs tests-e2e/public-ai-translation-live.mjs tests-e2e/public-ai-translation-live.test.mjs tests-e2e/public-product-live.mjs tests-e2e/public-product-live.test.mjs
```

- Current three runner suites: **122/122 PASS**, no skips. Includes the earlier guards plus exact GET summary scope, passive missing/denial distinction, same enriched DTO restoration, actual updated `existing()` client against synthetic Response objects, actual current disclosure-helper parity, profile mismatch denial, real progress JSX/estimate rendering, auto-open chat and strict negative DOM samples.
- Offline `--preflight`: **PASS**, `actuallyRun:false`, `browserLaunched:false`, `networkRequests:0`, `evidenceWritten:false`.
- Targeted ESLint, `node --check` and `git diff --check`: **PASS**.
- Historical preparation had owned45/45 and broader68/71 with three obsolete UI/renderer expectations. This new handoff explicitly authorized the shared helper/test edits; those three failures are now fixed rather than skipped. No full UI/API build/test, backend cache-test execution or deployed UI compatibility is claimed.

## Coordinator READYGO needed — not granted here

Coordinator must separately review/test and deploy the intended source by the ordinary approved preservation procedure, verify actual served image/source binding (not merely the historical412-file receipt), fixed routing/privacy/quotas/readiness and no concurrent qualification/key activation, and authorize **ONE new native attempt / ONE disposable account / ONE Node four-check scan / at most FOUR generation POSTs** with immediate429/503 stop. Resolve the exact ingress GET prerequisite and review the remaining single-account cross-owner limit above before spending the attempt. Flags do not manufacture human authorization or live acceptance.

Safe command **now**, offline only:

```sh
node tests-e2e/public-automation-live.mjs --preflight
```

After actual coordinator READYGO, this **non-live command only prints** the future exact command with a newly generated UUID; it does not launch a browser:

```sh
node --input-type=module -e 'import { randomUUID } from "node:crypto"; console.log("node tests-e2e/public-automation-live.mjs --run --ack-coordinator-readygo --ack-four-generation-posts --ack-source-deployed --attempt-id " + randomUUID())'
```

Only the coordinator may then execute the printed command once under that authorization. No command printed above was used for a live attempt in this work.
