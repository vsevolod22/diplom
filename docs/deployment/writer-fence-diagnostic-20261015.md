# Independent correctness review: current writer-fence diagnostic

## Decision and literal

**APPROVE ONE parent invocation of the frozen diagnostic, subject to separate independent security acceptance. No concrete source correctness blocker found. NOT EXECUTED by reviewer.**

- Literal: `docs/deployment/writer-fence-diagnostic-20261015.sh`
- Literal SHA256: `561709bc44d133b352df343b86fb33b116b8c62477c3eb09d6d3a5904bb4a96b`
- Required cwd: `/Users/vsevolod/Documents/startup/diplom`.
- Parent invocation: `/bin/sh` of that exact file, caller `timeout_ms=75000`.
- Shared60s/client10s, at most6 metadata clients. No invocation, Docker query, import or tests by this reviewer.

Parent separately executes the already correctness-approved seven-image cleanup only after its security approval, then assesses this diagnostic. This document does not execute, renew, expand or report completion of cleanup. Do not overlap this packet with other daemon operations. No rollout/R4 or retry of any spent command is granted.

## Verified public pins

All hashes below were independently measured and match the actual sources and embedded dependencies.

| Public source | SHA256 |
|---|---|
| `server/deploy/trust/diagnose_writer_fence.py` | `637211f9551dd655743f1ff7252bbfc8738b4b0dcbe22da95ad057f1505fc047` |
| `server/deploy/trust/test_diagnose_writer_fence.py` | `82a085938cc40cd43c2c8e82d701a38d1b3cfc428a6bc7c544e7bc487a044446` |
| `server/deploy/trust/recreate_openrouter_key.py` | `9b62bcadcf70f0f42178fda4a3f19040601185eaf325f68ddfe5f9218fbe7b7c` |
| `server/deploy/trust/test_recreate_openrouter_key.py` | `a173bb9cac0514430a6fe26669a39075643f867def1310144968c1d3a11464cd` |
| `server/deploy/trust/stand_composition.py` | `97283889749a4413d5e27f9b0ce828927f56b56ef507cb220a3c607fd3d23f5a` |
| `server/deploy/trust/discover_preservation_holder.py` | `4afb0bc484d34aca428fee956bd939d7b322727285eef0f721425849bb32a1f4` |
| `server/deploy/trust/test_discover_preservation_holder.py` | `cc1a168804cb9a07f9c53724730bfbbaae7596c44c88743b0dc169f26a1bf312` |

## Read boundary and bounds

The allowlist permits only this packet:

1. One projected inspect of the two exact auth/data volume names: names, local driver/scope/options, project label and internal mountpoints.
2. One projected daemon ID.
3. Complete all-container full-ID census, bounded to32; no filters.
4. One projected inspect of exactly the complete valid nonempty census: `{id,running,mounts}`. Empty census uses an empty batch. Invalid, duplicate or oversized census skips the batch, never truncates/samples or queries a subset.
5. One projected inspect of fixed retained ID `d9433f7ed0fc504a3521574668f15b7b3a0e8d283d61b9aa33d1e97187708a4f`: image/config-image, name, lifecycle flags/counters/timestamps, entrypoint/command/path/args. No Env, labels, State.Error or logs. Expected image is `sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c`.
6. One projected daemon ID again.

Combined stdout/stderr client caps: batch2MiB; volume/retained65536B each; daemon/census4096B each, maximum2240512B allocated across the six clients. Public source files<=512KiB, mounts<=64/container and checked source strings<=4096B. Individual JSON rows also inherit the transport decoder's65536B bound; exceeding it refuses classification rather than silently sampling. Receipt<=4096B, at most32 active IDs.

The real pinned transport verifies the fixed executable metadata/hash before each child, uses the explicit fixed socket and isolated child environment, bounds each child to10s/shared deadline, and discards raw stderr. Its main/discovery/private-directory methods are not called. Diagnostic source loading checks absence of adjacent `config.json` by metadata only. Stable no-follow owner/single-link public-source reads and pin checks precede module loading; final source rehash follows classification. The controller's fixed public selector bootstrap is source-pinned; its selector functions and lifecycle are not invoked. No tests or app code are loaded by this diagnostic.

Only diagnostic/client process descriptors and console output are handled; no private content, SQL, host evidence writes, lock operations, holder creation/start/pause/removal, volume/image/network mutations, HTTP or provider work is present. Fixed retained projected arguments are compared internally, never exported.

## Predicate correctness and honest interpretation

- The authoritative touch decision is the actual pinned controller `protected_store_touch`, not a replacement approximation. It preserves literal named-volume, exact source, descendant and ancestor/root overlap behavior, without normalization/realpath or a Darwin-prefix rewrite. Explanation bits are separately cross-checked against that decision.
- This packet corresponds only to current no-holder/empty-permitted writer checks. Any observed running container touching either protected store is a violation, including read-only touches, foreign actors and either egress ID. The two egress identity bits are annotations, not exemptions. Stopped touches are not labeled active writers. Paused containers whose `Running` remains true are treated by that actual boolean, matching the controller predicate.
- Batch decode/schema/ID/duplicate/count/completeness groups remain independent. Invalid or incomplete mounts/batches cannot produce a positive all-clear: otherwise-true mount/touch groups become null when unobserved; an already observed violation stays false. Oversized batches are not prefix-classified. The active rows are IDs plus finite aggregate bitmasks, not raw mounts/paths; a zero mask is not by itself an all-clear when shape/completeness failed.
- Fresh volume identity/policy/path checks are current inputs, not equality to an unavailable captured volume record. Fresh daemon-before/after equality is not historical daemon equality or continuous exclusion. Retained identity/created/flags/counters/timestamps/argv/name-shape groups are current projected checks, not full sandbox qualification or equality to a historical cached inspect.
- `notObserved` explicitly retains `HISTORICAL_DAEMON`, `RETAINED_CACHE`, `DEFAULT_LABELS`, `HISTORICAL_HOLD`. No historical lock/HOLD data is read or reconstructed. No full retained label/default/security qualification, adoption, permission to reuse, or historical failure cause is inferred.
- Exit0 / `code:CLASSIFIED` / `ok:true` means a bounded packet was obtained and classified, even when predicates mismatch. Read `groups`, `currentMatch`, `firstMismatch`, `notObserved`; `currentMatch` is true only if every current group is exactly true. Even that remains `fullQualification:NOT_CLAIMED`, never readiness, migration or continuation authority. A nonzero client/source/output failure stops without retry or later client calls; groups not obtained are null. A final source-drift refusal can preserve obtained classifications but forces `currentMatch:false`.

## Validation and limits

Read the full new diagnostic/test pair and relevant actual controller writer/predicate/bootstrap, public selector and transport source. Tests inspected cover real pinned pure-function use, exact six-call packet, invalid census/no subset, independent mismatch groups, malformed mounts, no reader/egress exemption,32-row receipt bounds, sticky client failure, final source drift and mutation/repetition refusal. They were NOT executed or imported here; no independent test-PASS claim is made.

Only public reads/hash operations and these two new owned docs were performed. No runtime/private queries, source/Git changes or historical commands were run. The existing deployment HOLD remains unresolved; this approval is for one new read-only diagnostic only.
