# TASK8 native-macOS public-facts capture proposal — NOT executed

Parent safety review and separate host opt-in are REQUIRED before actual collection. This source-only PoC is not a deployment, independent source qualification, machine enrollment or whole-host scan. Runtime run `d18c354c-0705-417b-990a-b4a273569e75` is terminal completed after blocked closure; TASK6 stays testing90. No duplicate run/claim.

## R2 gate superseding the bare R1 proposal

Exact independent review DIP-ARTF-236 requested R1 single-use capture admission and R2 runnable revocation/finite cleanup. Source-only rework consumes BOTH nonce/consent before first observation, shares bounded process/module-local authority and wires normal SIGINT/SIGTERM through the runnable supervisor's AbortController. No durable restart protection or process-tree/parent-death guarantee is claimed. See [supervisor-proposal-r2.md](supervisor-proposal-r2.md), a CANDIDATE for independent review, not approval. Actual capture remains BLOCKED until independent R2 supervisor review accepts specific fixed-leaf source assumptions AND the actual operator gives separate single-invocation scope consent. External authority must reserve the invocation before launch and prevent repeats across processes. No such actual authority is supplied.

## Proposed exact sources

Ordinary operator, locally on the actual native macOS host; never Docker/SSH/sudo. Darwin platform detection is an execution prerequisite, NOT hardware identity/topology proof. Docker Desktop Linux VM is not this target. Linux returns unsupported/zero commands after authorization; missing authorization always returns not_authorized first.

| Fixed executable and arguments      | Single fact retained                 | Does NOT establish                                                     |
| ----------------------------------- | ------------------------------------ | ---------------------------------------------------------------------- |
| `/usr/bin/sw_vers -productVersion`  | Product version token                | CVEs, patch sufficiency or package inventory                           |
| `/usr/bin/uname -r`                 | Kernel release token                 | Effective configuration or kernel CVEs                                 |
| `/usr/bin/uname -m`                 | Reported execution architecture      | Physical architecture under Rosetta, hardware identity or VM exclusion |
| `/usr/sbin/sysctl -n hw.memsize`    | Reported total physical memory bytes | Free memory or scanner capacity                                        |
| `/usr/sbin/sysctl -n hw.logicalcpu` | Reported logical CPU count           | Available CPU, benchmark or scanner throughput                         |

Conventional command/key meanings above are a proposed contract, NOT freshly observed facts. Reference manuals: [sw_vers](https://www.manpagez.com/man/1/sw_vers/), [uname](https://www.manpagez.com/man/1/uname/), [sysctl](https://www.manpagez.com/man/8/sysctl/). References were not fetched; host manuals/commands were not executed. Availability/output compatibility/topology require actual consented testing. Unexpected output stays unavailable. No serial/UUID/hostname/user/address collection. Opaque target ID is operator assigned, not hardware attested. These descriptive facts are not a security verdict.

## Proposed boundaries

- Exactly five fixed absolute commands, sequential; no shell, arbitrary arguments, discovery, sudo, Docker/Engine client/socket, mount/root traversal, filesystem/process/network inventory, environment dump or secret/key reader.
- Ignored stdin, piped stdout/stderr. Environment replaced by constant PATH/LC_ALL/LANG, never copied into telemetry. HOME/credentials/proxy variables not inherited.
- Each child <=750ms observation/kill timer, <=1024 combined stdout/stderr bytes inclusive. Stop requests tracked-child SIGKILL once, then allows100ms close grace. Failed/throwing kill or absent close resolves finitely to sticky blocked/cleanup_unconfirmed: detach only owned handles, no later launches/publication/retry, no claim the child stopped. Known delayed close holds the slot until close. Only fixed sanitized value/reason survives, no raw diagnostics.
- Per collector instance active1/queue0; <=5000ms monotonic and wall-time publication fence. Timers are not real-time scheduling guarantees. JS/process RSS/CPU are NOT OS-enforced limits and real resource use is unmeasured. A stuck child/kernel/event loop may delay close; replacement work stays denied while busy.
- Separate consent <=300s, exact opaque owner/target/version/consent/nonce, canonical UTC timestamps, ONE invocation. BOTH IDs consume before first runner call; partial/failed/revoked attempts stay consumed. Capacity128/no pruning, shared module/process-local ONLY, resets across processes/modules, not durable. Initial invalid/unsupported/pre-aborted/busy distinct non-admission does not consume. Check expiry/AbortSignal before commands/publication. Runnable supervisor forwards SIGINT/SIGTERM through AbortController; library caller retains its revocation controller. No durable consent service.
- Exact five fact keys; bounded version/architecture tokens and safe positive integers only. Fixed unavailable reasons never become checked. No filesystem/browser/API/persistence/provider/notice writes or transmission.
- Intake complete canonical UTF8 JSON <=8192 bytes inclusive; unknown/duplicate/prototype keys, noncanonical numeric lexemes/strings/whitespace/BOM, invalid UTF8 and unsafe integers reject. Depth is limited by closed shallow shape before recursive canonicalization.
- One explicitly injected PUBLIC Ed25519 enrollment: subject,targetId,targetVersion,signerId,sourceVersion,publicKeyDer,fingerprint. Signature uses domain `host-evidence-v1` plus canonical payload. Public DER/fingerprint/owner/target/source/nonce/consent/time all match; envelope never supplies trust.
- Intake reports historical_import even for recently captured/signed evidence. Signature proves enrolled provenance, not fact truth, completeness, machine identity, present liveness or qualified collection. Digest alone is never signature evidence.
- Successful imports consume nonce AND consent, capacity128 per intake instance; no pruning. This is process-local, NOT durable restart/idempotency/history/security-service readiness. New instances reset guards. Production integration needs parent-owned authenticated authority, current/revocable enrollment, atomic durable nonce/report commit and bounded raw ingress before JSON parsing. No shared routes are installed.

## Runnable proposal, not permission

From repository root, pure plan: `node server/host/src/cli.mjs --plan`. Pure tests: `node --test server/host/tests/host.test.mjs server/host/tests/rework.test.mjs`. Neither executes host commands. No opt-in CLI prints not_authorized with zero commands.

Only AFTER parent reviews exact manifest and separately consents to these five facts, the operator may invoke the existing CLI with actual opaque bindings/times:

```text
node server/host/src/cli.mjs --capture --host-opt-in --single-invocation --parent-reviewed-supervisor native-macos-fixed-leaf-supervisor-v2 --parent-reviewed-plan native-macos-public-facts-v1 --subject SUBJECT32HEX --target TARGET32HEX --version POSITIVEINTEGER --consent CONSENT32HEX --nonce NONCE32HEX --issued-at UTC_MILLISECOND_TIME --expires-at UTC_MILLISECOND_TIME
```

Uppercase operands are documentation metavariables, not executed values/enrollment. CLI emits sanitized UNSIGNED evidence to stdout, reads no keys/files and uploads nothing. Flags record operator assertions: they cannot prove actual independent parent review or account authority. Do not treat them as a qualification certificate. Never execute this proposal in this assessment.

Signing is a separate library operation, `createSignedEnvelope(evidence, signerId, inMemoryPrivateKey)`, with the operator's independently managed Ed25519 key; no key-file/secret reader or production provisioning supplied. Tests use fresh ephemeral keys only. Parent must approve enrollment/provenance/transport/retention before any real key use or artifact upload. Do not redirect real evidence to public tracker artifacts without separate disclosure approval.

## Fixed-leaf supervision limit

The supervisor applies only to the five fixed ordinary-user native commands reviewed as leaf processes, without shell/helper/descendant launches or replaced binaries. No actual leaf/source/process-tree qualification was performed. Child close is not proof of absent descendants. Full tree/parent SIGKILL/OS/kernel/event-loop/stdio-stall cleanup cannot be guaranteed by this source alone. If specific leaf assumptions or the required cleanup boundary cannot be independently established, actual launch remains BLOCKED, not fictional full-tree qualification. No process discovery/group-PID killing or global settings introduced.

Supervisor5500ms invocation timer plus150ms shutdown fallback suppresses late output and returns blocked on uncooperative work. Child750ms+100ms finite promise budget and supervisor5650ms maximum scheduled promise budget are not real-time/OS-process-exit guarantees. Unref/destroy is handle detachment, not successful termination evidence. No automatic retries/reinitialization after uncertain cleanup. Review exact R2 supervisor and external single-invocation authority before any separate capture consent.

## Approval requested

Review exact sources/manifest, five-command scope, OS-specific meanings, fixed resource/abort limits, empty inherited environment, closed sanitization and provenance limits. Approve or narrow an explicit single capture separately, with owner/target/time/nonce and operator-managed revocation. Existing runtime/image authority does not authorize host collection. Real host qualification, real capture and production intake remain BLOCKED pending that decision and subsequent acceptance.
