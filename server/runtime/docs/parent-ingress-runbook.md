# Parent runtime/history ingress R2 candidate — source only, default off

## Scope and status

This supplement records the authorized R2 root fixes after reading FULL independent DIP-ARTF-228 (R1–R5), following DIP-ARTF-202/205/210 and candidate217/218. It does not replace the runtime author's operator runbook, independent review or integrated acceptance. Four formerly reviewed runtime snapshot files are now intentionally changed (identity, intake, service descriptor, browser transport); the original40-file manifest is historical, not a current R2 approval.

R2-owned files: canonical `main.ts`, selected `oci/nginx-local.main.ts` and additive `oci/nginx-local.module.ts`; NEW shared `parent-ingress.ts` and narrow `runtime/runtime-http.ts`; runtime intake/identity/service descriptor; the matching runtimeTransport leaf; stand.nginx.conf; this runbook and parent-ingress tests. No auth store/controller, LLM/history backend, AppModule, ledger/quota/schema, LOCAL image/broker/egress policy, compose activation, actual flags, persistent data, notices, CVE14 files or deployment was edited. No DB was initialized, enrolled or opened; no real socket/listener, Engine, host collector, provider, build, secret file, commit, spec application or task closure was performed. LLM framing is separately owned and must be coordinated, not patched here.

## Bootstrap contract and history coordination

- The documented LOCAL composition selects `oci/nginx-local.main.ts`, NOT canonical main. Both now create Nest with immutable `bodyParser: false` BEFORE initialization and call the same simple `configureParentIngress` helper before listen. LOCAL retains logger:false, existing JWT/bind checks, shutdown handlers, every LOCAL controller/provider and the ScansService factory using NginxLocalScansService(LedgerStore,OciResolver). Only RuntimeApiModule is added to LOCAL imports. No compose command is changed to generic main; no LOCAL policy is discarded.
- `app.select(RuntimeApiModule).get(RuntimeIdentity, { strict: true })` selects the existing configured module's identity. That identity is backed by its injected `AuthStore`; no second identity/auth/runtime store is constructed. `RuntimeApiModule` exports `RuntimeApiService`, not `RuntimeIdentity`; strict module selection intentionally avoids a guessed global/exported provider seam.
- `createRuntimeIntake(req => identity.resolve(req, true))` precedes JSON. Namespace classification is case-insensitive, bounded by a real slash/end boundary, includes queries and separately identifies decoded/absolute-form targets without rewriting URL/dot segments. Only original canonical origin-form mutation URLs are admitted; mixed case, encoded namespace/route variants, query, trailing-slash and unknown mutations fail before ordinary JSON/data listeners. Prefix siblings remain unrelated. Presence of ANY Authorization header, including empty/duplicate/case-varied raw headers, denies in both intake and read/mutation identity BEFORE cookie lookup; empty content-encoding/transfer-encoding/expect also denies. Origin/cookie authentication precedes scarce slots/runtime parsing. Controllers still use the raw WeakMap exclusively.
- `registerHistoryIngress(app)` is retained in the shared initializer between runtime intake and ordinary parsers, now consumed by LOCAL too. Its implementation remains owned by the separate framing author; no LLM/backend edit is made here. Runtime tests preserve history8192/chat+decision stream ownership, not whole NDJSON/history acceptance. Other history/provider/consent/privacy and framing findings remain separate.
- Explicit `app.useBodyParser('json')` and `app.useBodyParser('urlencoded', { extended: true })` preserve the prior Nest/Express defaults for unrelated routes. Installed Nest11.2.6/body-parser2.3.0 skips already-finished raw streams. Tests use that real adapter/parser behavior rather than assuming parsed streams can be read again. Existing controller-level auth512 and image/summary1024 checks are untouched; the default ordinary parser is not represented as a new global1KiB cap.
- Missing/wrong/locked/uninitialized runtime DB continues to yield the configured module's undefined store/unavailable behavior. Main does not initialize/migrate a DB, infer a path, install a live port, or bypass runtime consent/enrollment. Authentication alone does not grant target rights.
- The configured RuntimeApiService defaults to rawIntake:`parent-bootstrap-required`. Only after registering both raw hooks and ordinary parsers does the initializer mark it `authenticated-pre-json`. The browser leaf accepts both exact literals, preserving unconfigured/older compatibility and rejecting invented qualification values. This reports in-process wiring only, NOT nginx activation, DB health, source qualification or LIVE capability. Unconfigured store/live remain unavailable/false; default RUNTIME_LIVE is still undefined.

## Nginx candidate (not activated)

`set $runtime_ingress_enabled 0;` and `set $history_ingress_enabled 0;` are explicit defaults. Four runtime and three new history/chat proxy locations return404 until separately reviewed parent activation. Nothing here edits compose or deployed flags. Direct/private API access is not controlled by this nginx gate; topology must keep that API private. Historical admission separately requires the explicitly configured runtime DB; runtime LIVE remains undefined/off regardless of nginx gate or DB availability.

Only the documented routes are allowlisted:

- POST `/imports`: complete body <=65536 bytes inclusive.
- POST `/consents`, `/consents/<32hex>/revoke`, `/captures/<32hex>/cancel`, `/captures/<32hex>/image-links`: <=1024 bytes inclusive.
- GET/POST exact `/captures`: <=1024-byte request; GET owner history, POST conditional capture.
- GET `/capabilities`, `/targets`, `/captures/<32hex>`, `/captures/<32hex>/results`, `/captures/<32hex>/events`: bounded runtime reads. GET implicitly permits HEAD under nginx `limit_except GET` semantics; no other method is admitted.
- Bare namespace and unmatched children return404. No generic runtime child proxy, enrollment/key endpoint, application IPC or Engine route exists.

Runtime locations have request rate60/IP/min and120/server/min, each with burst2/no-delay; per-IP connections2,429 refusals; body inactivity timeout5s, connect2s, upstream-send5s/read10s and downstream-send5s. Mutation buffers equal their body caps, with request buffering on. Nginx's inherited finite header/connection defaults remain unchanged for unrelated routes. Nginx timeouts are inactivity budgets, not an absolute client upload deadline; buffering also means the application's absolute5s intake timer starts when nginx forwards the request. Independently review slow-client/header/memory/temp-file behavior before activation; these static settings do not prove aggregate resource bounds.

Runtime and new chat/history locations use proxy_pass_request_headers:on WITHOUT overriding Authorization, Cookie, Origin or Content-Type. `$http_authorization` overrides erase empty-header presence; leaving the incoming header unmodified retains empty values/multiplicity under stock proxy forwarding (or nginx itself rejects a duplicate). Conflicting Bearer must reach the backend rejection, not be cleared into cookie-only authority. Mutation TE/Content-Encoding/Expect nonempty guards precede proxy buffering; runtime API additionally rejects empty presence. Actual edge empty/duplicate/framing normalization and backend framing-author behavior still require wire qualification; no source test substitutes for it.

Runtime/new history-chat access logs are off; inherited error logging still needs URI/canary review. No body/header/evidence logging is added. Existing auth/image/summary limits and locations are unchanged. New exact closed UUID routes: GET `/llm/history`, `/llm/chat/context`, `/llm/chat/usage` (implicit HEAD); POST `/llm/chat` and `/llm/history/decision` <=8192 bytes inclusive, read timeout45s, body5s/connect2s/send5s. Chat has proxy_buffering:off, proxy_cache:off and gzip:off; response Content-Type/body are not rewritten, preserving the backend's NDJSON once separately qualified. Summary stays1KiB/35s, legacy summary context/usage unchanged. Backend-generated NDJSON, provider streaming and successful integrated chat are NOT proven by these nginx directives.

### Explicit API rate policy behind nginx

The old socket-peer60 bucket was a shared nginx aggregate, not browser-client IP. R2 replaces it with a deliberately conservative process-global PRE-AUTH60/min bucket for protected canonical-prefix POST attempts, including unauthenticated/invalid attempts before body admission. All peers/owners compete for it; a new socket peer or forged X-Forwarded-For cannot reset it. After authentication, owner12/min, active2 global/owner1/zero queue,5s complete-body deadline and bounded1024 rate keys remain. Nginx client60/min and server120/min (burst2) are separate edge policies;120 is NOT effective API throughput above the global60 ceiling. No trusted proxy/forwarded-IP feature is configured or claimed. Future relaxation needs separate explicit proxy/source policy and independent acceptance.

## Explicit separate `RUNTIME_DB_PATH` — operator procedure, NOT executed

All following operands are documentation metavariables. Do not paste them as literal shell commands. No path, account, key or enrollment is provisioned by this runbook.

### Preflight and quiescence

1. Obtain separate parent authorization for backup, initialization, enrollment, configuration and eventual activation. Keep nginx runtime gate0 and LIVE off throughout preflight. Inventory the ACTUAL current topology/flags/pins, including enabled summary/quota liabilities, rather than rerunning old stand scripts.
2. Capture a WAL-consistent all-table/all-column preservation baseline and restorable backups for existing auth, scan, quota and history stores. Preserve users, sessions, scans, immutable reports, provider liabilities and all existing files/columns. No reset, prune, implicit migration or reinitialization of those stores.
3. Stop/quiesce every API/runtime writer before init/enrollment. Enforce exactly ONE serving API writer for this runtime file: no replicas, cluster/fork processes, overlapping restarts or sidecar enrolling while serving. Coordinate other volume writers/backup consumers with the parent; don't assume merely stopping one container proves quiescence.
4. Choose a NEW absolute canonical runtime file on the approved durable auth volume in a dedicated directory owned by the actual API/operator UID with mode0700; file0600, single link. Verify no symlink, hardlink, canonical-path or device/inode alias to auth, scan, quota, history, private caller journal or other application files. Reserve writer/WAL/SHM paths as well. Init must fail if the file already exists; never delete an existing DB to retry.
5. Supply the existing approved `AUTH_DB_PATH` and `SCAN_LEDGER_PATH` to the operator process for implemented alias checks, WITHOUT dumping environment/secret files. Current CLI/provider checks only these two other paths automatically: quota/history/caller independence requires explicit operator verification, not an invented broader guarantee.

### Init/enroll commands (only under new explicit operator authorization)

Working directory: `server/api`, using installed `tsx`:

```text
node --import tsx src/runtime/runtime-init.ts init <absolute-new-runtime.sqlite> --authorize-runtime-store
node --import tsx src/runtime/runtime-init.ts enroll <absolute-runtime.sqlite> --authorize-runtime-store <absolute-owned-public-enrollment.json>
```

Enrollment requires quiesced runtime serving and canonical owned0600 public JSON under directory0700, <=65536 bytes. Exact closed fields: `subject` (existing account ID), `target` (targetId32hex, full containerId64hex, context/contextVersion/version, importAllowed/liveAllowed), signerId32hex, canonical Ed25519 SPKI DER base64 `publicKey`, SHA256 DER `fingerprint`, `sourceVersion: operator-runtime-v1`. See the author's runbook and source for exact constraints. Account authentication is not enrollment. There is no public enrollment route. Verify actual source and owner trust independently; a signature is not source completeness or current liveness.

Set only separately approved `RUNTIME_DB_PATH` to this exact canonical file for the single serving API. Preserve other environment paths/flags/provider pins and existing stores. This candidate does not configure that value. Boot opens an existing application-ID/schema1 store, obtains exclusive `<file>.writer`, uses WAL/FULL, and reconciles interrupted captures to failed `INDETERMINATE`; it never recaptures automatically. Missing/bad/busy store remains unavailable. A stale lock may only be reconciled after independently proving no writer remains; serving never steals it.

### Recovery and eventual acceptance

- Gracefully stop the API before reenrollment/maintenance; increasing target version invalidates that target's old NEW-work authority. Preserve owner terminal replay and immutable evidence. Never infer global consent invalidation from the epoch allocator.
- After crash, establish topology/quiescence, reconcile only a proven stale runtime lock, recover with the existing DB and compare preserved data. Test interrupted capture, exact terminal replay, changed intent409, foreign owner denial, consent/revoke/cancel fences and append-only image associations against the integrated API. No recapture/retry or restore to a fresh empty DB.
- Keep runtime rollout disabled if data preservation, durable restart recovery or original reviewed hashes cannot be verified. Disable ingress/stop the runtime writer rather than erase evidence. Parent owns actual backup/rollback operations; this text is not an executed recovery proof.
- Private caller journal initialization/credential provisioning and genuine isolated Linux Engine1.47/application protocol qualification are separate, still pending gates. Do not install `withQualifiedCapture`, mount Engine sockets, enable host collection, claim native macOS coverage or treat signed historical `running:true` as live evidence.

## Source validation and independent review requirements

Socket-free focused command, from `server/api`:

```sh
node --import tsx --test ../runtime/docs/parent-ingress.test.cjs
node node_modules/typescript/bin/tsc -p tsconfig.json --noEmit --incremental false
```

R2 focused suite:17/17 passed. It transpiles canonical/LOCAL entrypoints, the shared initializer and LOCAL module metadata in memory with mocked NestFactory/import tokens; uses actual RuntimeIdentity with fake token lookup, actual store-unconfigured RuntimeApiService, real raw/ordinary middleware and streams. Node IncomingMessage._addHeaderLines probes actual empty/duplicate normalization with an EventEmitter (no real socket). Fresh isolated real intake source closures test global preauth60/owner12/global2-owner1 without resetting production state or patching real time. Metadata checks preserve LOCAL providers/factory but do NOT prove a full real Nest container. Browser descriptor parser is actual code; no React rendering/HTTP/browser was run. No application/store/DB/listener/net.Socket is created or opened. NDJSON backend/history framing remains separately owned and must be independently reviewed against its final exact dependency hash. Static nginx tests are not native syntax or wire proof.

Scoped browser leaf no-emit validation, from repository root:

```sh
node node_modules/typescript/bin/tsc -p server/runtime/tsconfig.ui.json --noEmit --incremental false
```

Before any rollout, the parent must obtain independent specification, correctness and security reviews of this exact hash manifest and the READ-ONLY dependency snapshot, without crediting the author's own tests as independent review. Required checks:

1. Re-review exact R2 hashes BEFORE source freeze/proof. Immutable options and shared canonical/selected-LOCAL initializer; additive real DI with exactly one AuthStore/LOCAL ScansService/runtime graph; no accidental second store; header/path/global-preauth/owner ordering and descriptor compatibility. Full actual DI boot remains separately authorized disposable acceptance, not a metadata test.
2. Actual integrated runtime + history + ordinary parsers, exact caps/lexical negatives, anonymous partial requests, query/framing/duplicate headers, expiry/revocation between intake and controller, absent/locked store and preserved auth/image/summary/history semantics. No imported historical evidence mislabeled as live.
3. Native nginx syntax/version/includes and separately authorized wire tests with BOTH gates0 and isolated synthetic activation, actual runtime1KiB/64KiB and history8KiB/45s/NDJSON, summary1KiB/35s unchanged, path normalization/HEAD, empty/duplicate/Bearer/Cookie/Origin/body-header preservation and framing-author refusal. Check conservative API global60 across multiple real clients/owners/nginx peers, separate owner12, slow client/header/temp-memory behavior and sensitive log canaries. Static assertions prove none of this on wire.
4. Separate nonalias explicit initialization/enrollment/env, single-API/quiesced maintenance, WAL-safe backup/preservation and actual interrupted/terminal recovery; no existing quota/history/auth/scan store reset or changed flags. Coordinate pending history deployment separately.
5. Retain all205/210 gates: actual integrated acceptance, genuine TASK5/new application qualification for LIVE, independent host authorization, appropriate task-sourced specification handling and human-authorized rollout. This author does not review/approve itself, apply specs or close/cascade TASK5/6.

DIP-ARTF-228 source findings R1–R5 have targeted R2 implementations/tests or explicit conservative policy, NOT an independent approval. If re-review requires a seam outside this expanded authorized scope, stop for new authority. Do not edit LLM/history backend/framing author's files, AuthStore/AppModule/quota/schema/compose, infer a parsed-body bypass, enable flags, provision a DB or weaken topology to manufacture green acceptance.
