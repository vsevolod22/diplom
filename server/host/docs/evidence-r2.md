# TASK8 R2 author rework / test evidence / independent review handoff

Source-only 2026-10-09; project520a0059-d0f2-4f86-8d93-fc15035a5715, DIP-TASK-8. Exact full DIP-ARTF-236 read, current task comments and policy read. Parent scope server/host/** ONLY; no actual host collector/public-fact/native-binary/signal/tree/Engine/Docker/LIVE/private/secret/settings/provider/commit/close operation authorized or performed. Task read blocked and left blocked; no status/progress change, task/parent closure, run/claim, strict-spec apply or no-impact declaration. This is author rework, not independent approval.

## Exact R2 snapshot

12 source/docs/test paths in source-manifest-r2.json, SHA256:
`ff2c8d2d9aae0614ab524055fd54bf05ced55b5730a547d4d2f5d62898520980`.
Six revised original paths (README,assessment,safety-plan,cli,collector,host.test); four new paths (capture-authority,supervisor,rework.test,supervisor-proposal-r2); contract/intake unchanged with original hashes. R1 manifest/evidence remain historical and are explicitly excluded, along with generated R2 manifest/evidence, rather than silently counted as current source. Original source identity and ARTF-219/220/221/236 review history not overwritten. No shared source/API/page/private files/notices/package/config writes.

## Rework against exact review236

### R1 single observation authority

CaptureAuthority synchronously consumes BOTH consent ID and nonce BEFORE calling the first runner, shared by default collectors in the loaded module/process. No repeat/concurrent repeated observation, even through another collector; changing owner/target/version/either ID cannot reuse the other consumed ID. Consumption never rolls back after partial/unavailable/failed/spawn-error/expired/aborted attempts. Initial invalid/unsupported/pre-aborted/busy distinct non-admission does not consume. Fixed128 attempts/no pruning. Original test expecting ten sends from repeated identical authority replaced with denial/5 sends and genuinely distinct consent after busy non-admission.

Process/module-local only. Explicit fresh authority fixture demonstrates reset/new-process boundary. NOT durable authorization, crash replay prevention or parent account proof. External authority owner must reserve exactly one invocation before launch and never relaunch that consent/nonce after crash/uncertainty. Existing independent intake one-use guard preserved; it does not grant observation.

### R2 runnable revocation and finite cleanup

New supervisor.mjs: owned SIGINT/SIGTERM handlers -> AbortController -> main -> collect(consent,{signal}); cleanup removes handlers/timers, prevents next dispatch/publication and maps clean cancellation exit130/143. Repeated signals do not bypass cleanup. CLI additionally requires --single-invocation and --parent-reviewed-supervisor native-macos-fixed-leaf-supervisor-v2; wrong assertion blocked, bare old proposal denied. Assertions do not certify actual independent review.

Tracked child stop: <=750ms timer or output-limit/abort/error, single SIGKILL request,100ms close grace. False/throwing kill or absent close never certifies cleanup; finite blocked/cleanup_unconfirmed result, only owned pipe/child destroy/unref, sticky runner/collector denial, no next command/evidence/overlap/retry/re-enable after late close. Delayed known close retains slot; unexpected runner failure also blocks. Late child/stream errors safely ignored without raw logging. Detaching handles is NOT proof a child died.

Supervisor5500ms invocation timer +150ms shutdown fallback; uncooperative callback settles blocked by maximum5650ms scheduled promise budget, no late captured output. Responsive-event-loop bounds, NOT OS real-time/process-exit guarantees. Fake virtual timers exercise exact deadlines without actual signals/processes/host commands. No SIGKILL/parent-death/kernel/event-loop/stdio-stall/full-process-tree guarantee invented.

### Explicit remaining fixed-leaf gate

Detailed docs/supervisor-proposal-r2.md is a CANDIDATE for independent review, not a reviewed/approved supervisor. Source controls only the tracked leaf ChildProcess. child.close is not absence-of-descendants proof. No native binary/tree qualification performed and no process enumeration/arbitrary PID/group kills/settings introduced. Independent reviewer/operator must establish specific unchanged ordinary-user fixed-native-command leaf assumptions and accept that limited boundary. Otherwise actual launch remains BLOCKED; a required full-tree/parent-death containment guarantee needs a separate qualified OS supervisor outside this patch. Source flags cannot fill that gap or grant consent.

Even after source acceptance, actual operator must separately name exact reviewed manifest/supervisor, one native-host invocation, subject/target/version/consent/nonce/short times and usable SIGINT/SIGTERM revocation. Generic continue-host request is not this consent. No such real grant is supplied. Historical signatures, fake tests and source hashes are not native-host qualification. Native macOS!=Desktop Linux VM; all prior exclusions/unsupported scanner decisions remain.

## Actual final validation

`node --test server/host/tests/host.test.mjs server/host/tests/rework.test.mjs`
Exit0;41 tests,41 passed,0 failed/cancelled/skipped/todo, duration167.695625ms. This is the final single run of revised24 originals +17 new R2 tests, not combined with author/reviewer prior runs to inflate distinct test count.

Added cases: consume-before-first-observation; repeat/changed-ID/binding/cross-collector/concurrent denial; busy distinct non-consumption; partial revoked and failed unavailable consumption; shared default collector authority; capacity128/reset boundary; kill false/throw/true but no close bounded resolution; delayed close/active slot; output/child/stream errors; unknown cleanup/runner exception sticky blocked/no next evidence; CLI explicit assertions/signal forwarding; actual executable runCli with FAKE SIGINT/SIGTERM, fake tracked child and output suppression/exit/handler cleanup; false kill via CLI blocked exit1; uncooperative supervisor callbacks/late success/repeated signals;5500+150ms fake invocation fence; pure plan and cleanup of fake handlers.

Every collector/public-command runner and process was fake/injected. Original suite ephemeral signing keys stay in memory; no key/private-file reads. Fake stream/timer/OS strings are not host facts, timings are not native resource benchmarks or real process-tree proof. No actual CLI/collector command, native signal, scanner, host/manual, network/provider, Docker/LIVE or broader suite/build/E2E was run.

Syntax checks passed for all SIX source modules and both test files. Scoped Prettier checks passed for ten revised/new paths; contract/intake were not reformatted or edited. Exact12 current source hashes/sizes and R2 manifest are checked separately. No TypeScript/global settings check or untracked git-diff check is offered as proof of these new .mjs sources.

## Independent reviewer handoff

Recheck current R2 manifest and source against DIP-ARTF-236 R1/R2. Run the two pure test files only; preserve no real spawn/signal/source collection/keys/Engine/Docker/LIVE. Verify observation admission precedes first runner and remains consumed for failed/revoked attempts, concurrent repeats deny, busy non-admission is not widened, process-local reset is disclosed. Verify executable supervision actually supplies AbortSignal, normal signal/failedkill/delayedclose/no-close/late-response fences are finite and sticky without overlapping observation. Independently assess the explicit leaf-only proposal; do not claim full-tree qualification from fake tests. Return approval/request-changes in SOURCE-ONLY scope. Actual capture and production adoption remain BLOCKED pending independent reviewed supervisor and separate actual single-invocation scope consent, not waived by this author handoff.
