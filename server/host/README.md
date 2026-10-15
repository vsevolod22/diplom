# TASK8 standalone host public-facts PoC

**Source-only; no actual host capture, production enrollment, API integration or live qualification.** Actual collection awaits parent safety review and independent explicit host consent. TASK6 remains testing90; no harness run/claim is created here.

Only native macOS descriptive facts are proposed: product/kernel versions, reported execution architecture, total physical memory and logical CPUs. Docker Desktop Linux VM is not the host. No Engine access even when opted in. Linux/whole-host/security posture/OS CVE/packages/files/processes/network/Dockerfile/IaC/Cosign/optional scanners are unsupported or skipped, not checked.

## Files

- `src/collector.mjs`: five fixed ordinary-user public commands, default-deny consent/review assertions, sanitized facts, bounded tracked-child cleanup and sticky blocked state on uncertainty.
- `src/capture-authority.mjs`: BOTH consent and nonce consumed before first observation, including partial/revoked attempts; bounded shared module/process-local state, NOT durable across processes/restarts.
- `src/supervisor.mjs`: candidate single-invocation SIGINT/SIGTERM-to-AbortSignal supervisor with finite shutdown; NOT independently reviewed or a process-tree/parent-death guarantee.
- `src/contract.mjs`: closed evidence/binding/time/values, canonical-only bounded raw wire.
- `src/intake.mjs`: in-memory-key signing and independently injected PUBLIC Ed25519 trust, binding/signature/freshness validation, historical sanitized artifact and bounded process-local one-use nonce/consent guard. No key-file reader, HTTP endpoint, durable store or restart assurance.
- `src/cli.mjs`: pure plan/default denial; explicit post-review capture proposal to unsigned sanitized stdout only. Flags do not certify independent review or authority. No file reads/writes, signing/provisioning/upload facility.
- `tests/host.test.mjs` and `tests/rework.test.mjs`: synthetic facts/fake subprocesses, signals/timers and ephemeral in-memory keys only.
- `docs/safety-plan.md` and `docs/supervisor-proposal-r2.md`: R2 exact commands/budgets/single-invocation proposal, reviewed fixed-leaf constraint required BEFORE separate actual scope consent.
- `docs/assessment.md`: accepted scope, licensing/compatibility/resources/duplicates assessment and unsupported/skipped decisions.

## Safe validation (repository root)

```sh
node --test server/host/tests/host.test.mjs server/host/tests/rework.test.mjs
```

Tests never use the real subprocess runner: its process behavior is tested with fake EventEmitters. Signing tests generate disposable in-memory Ed25519 keys, not production credentials. No actual facts about this macOS machine are emitted.

## Library composition

`HostCollector.collect(consent, {signal})` denies absent/invalid or consumed independent consent, unsupported platforms and concurrent collection. BOTH consent ID and nonce consume before the FIRST runner call, never after intake; repeat/concurrent-repeated and partial/aborted retries deny. Busy distinct non-admission does not consume. Default state is shared by collectors in this module/process; new processes/modules reset it. External authority must reserve one invocation before launch and prohibit replay after crash/restart. Unconfirmed kill/close makes the runner/collector sticky blocked with no later observations or evidence. Successful capture returns `{host:'captured',provenance:'local_capture_unsigned',liveQualified:false,engineQueried:false,exclusions,evidence}`. Individual unavailable facts carry fixed reasons; captured is not a completeness/security verdict.

A separately authorized operator may sign closed evidence via `createSignedEnvelope(evidence, signerId, inMemoryPrivateKey)`. `new HostIntake(publicEnrollment).accept(canonicalWireBytes, separateHostConsent, now)` validates it and returns `host:'historical_import'`, never current host/live qualification. Both nonce and consent consume only on successful validation, max128 imports per instance, without pruning. New instances reset guards: NOT durable replay protection or production readiness. Real trust provision, authenticated/revocable authority, durable publication/replay and safe transport need parent ownership and separate review.

R2 resolves tracked-child command promises after750ms+100ms close grace and supervises normal SIGINT/SIGTERM cancellation; unconfirmed cleanup stays blocked. Runnable CLI requires explicit single-invocation/supervisor-review assertions. Those flags do NOT establish leaf-process qualification. Full process-tree/SIGKILL/parent-death/kernel/event-loop/real-time process-exit guarantees are not established; actual launch stays blocked unless independent review accepts the fixed-command leaf-only boundary and separate operator scope consent. See the R2 supervisor proposal.

No existing runtime/host capability response is changed, no public host endpoint/page is mounted, and no task/parent is closed. This PoC's separate scope cannot waive runtime Linux qualification or claim the user's whole host was scanned.
