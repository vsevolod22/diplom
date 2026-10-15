# TASK8 R2 single-invocation / fixed-leaf supervisor proposal

**CANDIDATE FOR INDEPENDENT REVIEW, NOT an approved supervisor or permission to capture.** Addresses DIP-ARTF-236 R1/R2 in source-only scope. No actual collector command, host observation, process-tree probe, native binary inspection, signal delivery or private data access was performed. Fake process/timer tests are not qualification.

## Authority before observation

`CaptureAuthority` reserves BOTH opaque consent ID and nonce synchronously before invoking the first command runner, not at signing/intake/publication. Every admitted attempt stays consumed, including unavailable/failed/spawn-error/partial/aborted/expired attempts; no rollback/retry. Reusing either ID, even with changed owner/target/version/the other ID, denies without observations. Initial invalid/unsupported/pre-aborted/busy distinct non-admission does not consume. Concurrent repeats deny before another observation. Default collectors and CLI invocations in the same loaded module share this bounded authority:128 attempts, no pruning.

This is MODULE/PROCESS-LOCAL, NOT durable single-use authorization. New process/reloaded module/explicit new test authority resets it. Never reconstruct authority to retry a real consent. The external operator authority MUST mark the invocation consumed before launch and must not launch the same consent/nonce again after crash/uncertainty. No durable supervisor/store/recovery service is supplied or claimed. Intake's independent successful-import replay guard is retained and is not the observation guard.

## Runnable supervision and normal revocation

Executable `cli.mjs` uses `runCli` -> `supervise` -> `main` -> `HostCollector.collect(consent,{signal})`. It creates an AbortController and registers owned SIGINT/SIGTERM handlers. Either signal aborts current observation; the runner requests SIGKILL only on its tracked ChildProcess, further dispatch/publication is refused, and clean cancellation returns not_authorized (exit130/143). These handlers are removed and owned timers cleared at terminal result. Repeated signals do not authorize work or bypass cleanup. No process/global configuration is changed by importing modules; tests use fake EventEmitters, not the actual process signal handlers.

The operator's revocation channel is SIGINT/SIGTERM delivered to the owned Node invocation. Library callers must supply and retain their own AbortController; the pure `main` parser is not a replacement for the runnable supervisor. Do not rely on terminal process-group propagation. No raw diagnostics or evidence are emitted on cancelled/blocked outcomes.

Per tracked child:750ms max observation/kill timer; timeout/output-limit/abort/error starts a100ms close grace and requests SIGKILL once. Failed/throwing kill requests or absent close by deadline cannot certify cleanup. Runner resolves finitely to blocked/cleanup_unconfirmed, destroys/unrefs only owned stdio/child handles and permanently denies further launches through that runner; collector latches blocked and publishes no evidence. It does NOT convert a failed kill into clean termination, release uncertainty for retry, or re-enable after late close. Known delayed close within grace retains the active slot until close and returns fixed unavailable. Late child/stream errors are swallowed without raw logging.

Supervisor invocation timer5500ms; shutdown budget150ms after signal/deadline, sufficient for the runner's100ms grace on a responsive event loop. An uncooperative callback resolves to blocked by the bounded fallback; late successful completion cannot be published. Maximum scheduled promise budget5650ms, NOT hard real-time elapsed completion/Node process-exit assurance. Event-loop/OS stalls, parent SIGKILL, uninterruptible kernels and blocked stdout are not cured by JavaScript timers. No CPU/RSS OS sandbox is claimed.

## Process-tree limitation and mandatory launch gate

There is NO established process-tree or parent-death guarantee. `child.close` describes the tracked child's lifecycle/stdio, NOT absence of descendants. No process enumeration, arbitrary PID/group kill, host root access, launch daemon or global settings is added. We do not claim sw_vers/uname/sysctl were observed to fork or not fork. Unref/destroy permits a finite supervisor result, NOT proof a failed-kill child stopped.

The proposal is restricted to the unchanged five fixed absolute command/argv sources as **ordinary-user leaf processes**: no shell/helper/descendant launching, wrappers, replaced binaries, service/interactive tools, discovery or inherited environment. Before actual launch, an independent reviewer/operator must establish the specific native executable/source/platform leaf assumptions and accept this limited tracked-child boundary. If leaf assumptions or cleanup guarantees required by the operator cannot be established, actual capture remains BLOCKED; do not broaden to fictional full-tree guarantees or unrelated kill/process inventory commands. If full-tree/parent-death containment is required, a separately designed and qualified OS supervisor is necessary and is outside this source-only patch.

CLI additionally requires `--single-invocation` and `--parent-reviewed-supervisor native-macos-fixed-leaf-supervisor-v2`. This is an explicit operator review assertion, NOT a cryptographic certificate, physical topology proof or independent qualification service. Missing/wrong assertion does not grant observation. Bare R1 CLI proposal is superseded. No source flag supplies genuine review or actual scope consent on its own.

## Revised runnable proposal — DO NOT EXECUTE here

Only after independent R2 supervisor/source review AND separately explicit single-invocation scope consent naming exact manifest, native host, operator/subject/target/version, consent/nonce, issue/expiry and signal-based revocation:

```text
node server/host/src/cli.mjs --capture --host-opt-in --single-invocation --parent-reviewed-supervisor native-macos-fixed-leaf-supervisor-v2 --parent-reviewed-plan native-macos-public-facts-v1 --subject SUBJECT32HEX --target TARGET32HEX --version POSITIVEINTEGER --consent CONSENT32HEX --nonce NONCE32HEX --issued-at UTC_MILLISECOND_TIME --expires-at UTC_MILLISECOND_TIME
```

Uppercase operands are documentation metavariables, not invented enrollment or runnable authority. External authority grants exactly ONE invocation, not repeat invocations for the whole <=300s consent window. Output is local sanitized UNSIGNED evidence only; no automatic signing/upload/storage, Engine/root/files/secrets or broader host access. All original exclusions and historical-only intake truth boundaries remain. Actual host capture is still prohibited until separate consent; TASK8 stays blocked, not closed. Return this exact R2 source/tests/manifest to an independent reviewer before any launch decision.
