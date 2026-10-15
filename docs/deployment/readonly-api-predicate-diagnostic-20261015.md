# Independent correctness review / frozen read-only predicate diagnostic

Project: `520a0059-d0f2-4f86-8d93-fc15035a5715`; repository: `startup/diplom`; 2026-10-15.

## Verdict

**ACCEPT the narrow present-bind representation correction and ONE source-bound full continuing read-only diagnostic attempt; frozen literal approved by this correctness review, pending the separately required independent security approval of the resulting exact file. DO NOT invoke yet.** No production controller command, migration retry, cleanup or follow-up query is approved. Both prior actual diagnostic invocations are SPENT; no old approval is renewed or repinned automatically.

| Spent diagnostic/test pair | Parent-attributed actual result |
|---|---|
| 451eeb… / 449d7… | exit1, D_MODEL_API / PREDICATE_REFUSED / NO_ACTIVATION |
| fccf0d… / 3071d5… | exit1, D_P_API__MODEL_BIND_OPTIONS / PREDICATE_REFUSED / NO_ACTIVATION |

The interim606b95…/e344ea… source candidate was superseded; this review does not invent an invocation of it. These receipt facts do not supply private operands or prove systemwide unchanged state. This reviewer performed no runtime mutation or operation.

Frozen public literal:

`docs/deployment/readonly-api-predicate-diagnostic-20261015.sh`

Actual SHA256 of that file:

`52cd2f7a8aa5fa84d0f998ce3454b2ba6d11a3a198207d5e37d3725e7fea27b1`

Relative to the preceding frozen literal, ONLY the FOUR controller/controller-test/diagnostic/diagnostic-test pin values changed in this revision. All five original container/image bindings, three candidate images, aggregate29c3…, evidence502/502/491/463 and other seven source pins remain unchanged. The shebang/comments document review/caller conditions and add no command, retry, cd, wrapper, redirection or activation. Required cwd remains `/Users/vsevolod/Documents/startup/diplom`.

The command uses exactly the requested environment/interpreter prefix:

```text
DOCKER_CONTEXT= DOCKER_HOST=unix:///Users/vsevolod/.docker/run/docker.sock PYTHONDONTWRITEBYTECODE=1 /Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B
```

The frozen script merely formats that single command across continued lines. It does not enforce an external timeout or one-shot counter itself: the parent/security-approved execution envelope must do that.

## Actual public byte verification

One bounded `shasum -a 256` read computed the command file hash and independently confirmed all FOUR current public source hashes exactly match the user-supplied values:

| Public file | Actual SHA256 |
|---|---|
| server/deploy/trust/recreate_openrouter_key.py | 578614762e0d52e285500e59039ff20b3ae827b7505847f53e5bb888d4d969d1 |
| server/deploy/trust/test_recreate_openrouter_key.py | 33138e47e31533ceb470865554402c2a4c28f14158113451b10659f146daac95 |
| server/deploy/trust/diagnose_preservation_preflight.py | 1ec5e2c9db05df2770540e7ec6ac77d205fe19fcd9e0fb38e581bf0d56be8bd2 |
| server/deploy/trust/test_diagnose_preservation_preflight.py | fa94539abfa9f7775dc241a440ed27eb853e56b3a7c346f75963f97c98dda085 |

No diagnostic/project script, imports, tests, Docker/daemon/plugin/native/app/HTTP/provider/history operation or private file read was executed. Hashing public bytes is not a script invocation. No source/Git/tracker/harness mutation. Local writes are limited to this new paired review and its new `.sh` literal; no executable permission change was made. Flownix is offline; no artifact ID is claimed.

## Inspected semantics

Read the actual changed public controller predicate inventory/observer wrapper, env/policy/key/runtime view, duration/health/memory support and full model comparison; diagnostic source pins, observer stack, API preparation, dispatch and related focused test source. Reused the continuing review of unchanged read-runner/CLI/identity/private-flow constraints. Focused test sources were inspected, NOT run; this report makes no independent test PASS claim.

- `predicate(observer, gate, operation)` validates a finite public ID, calls ENTER before evaluation, calls PASS only after operation success, ignores callback return values and returns the original operation result. Callback failures become message-free Refusal; operation exceptions propagate without being converted into acceptance. With observer=None, the same operation is evaluated. No alternative comparator or data-derived gate is introduced.
- Instrumented env_map/policy/key_only/runtime/model predicates retain the reviewed operands and comparisons. The separate diagnostic refinement is not a replacement for full original model matching. Model config, health/time parsing, restart, resources, mount/bind, network, ports, LOCAL command and exact API-volume checks remain present. No operand/value/Env-key/path/count is passed to the observer.
- Diagnostic observer accepts only the finite predicate set, ENTER/PASS and fixed role names. Its bounded stack distinguishes outer preparation/model operation and deepest active subgate. A nested PASS restores its parent; an operation failure has no PASS and therefore retains the active failing context. Output checkpoint consists only of fixed role/predicate identifiers, not operands, ordinals or passed-gate history. Callback faults fail closed.
- Duplicate OLD Env preparation now distinguishes `D_P_API__API_PREP_ACTUAL_ENV__API_OLD_ENV_ENTRY_UNIQUE` from config comparison such as `D_P_API__MODEL_USER`. Nested memory/health/env/runtime checks likewise report fixed context without a second client query. After each successful role comparison, stack emptiness is required.
- Serialized Compose model compilation/full roundtrip and raw inspect/image defaults/AUTH equality remain the reviewed boundaries. This observer change grants no normalization, re-escaping, JWT/non-key exception, label/resource change, WAL/helper/timer adjustment or migration authority.

Focused test source covers ENTER/evaluate/PASS order and ignored returns, unknown gate refusal, sanitized ENTER/PASS callback errors, preserved operation exception identity, observed/unobserved result and first-refusal parity across model gates, API preparation/config separation, nested parent restoration, fixed output schema/privacy, and no later client after refusal. These are inspected assertions, not newly executed evidence.

### Security-requested observer deadline correction — RESOLVED

Inspected the revised diagnostic source and focused tests directly. Diagnostic-owned `deadline_expired` is initialized false, reset at the beginning of each observation result, and set true BEFORE the observer raises its deadline exception. `result()` gives that recorded expiry final precedence as CLIENT_TIMEOUT/REFUSED even if the unchanged controller callback boundary sanitizes the exception to Refusal. ENTER and PASS expiry therefore retain the fixed active checkpoint and correct timeout category without exposing exception text or weakening generic callback sanitization.

Resetting the flag does NOT reset/extend `self.deadline`, the120s budget, client limits or operation scope. The flag is set only by the actual diagnostic observer deadline check; an unrelated Refusal is not promoted to timeout. Fail-fast unwinding prevents a subsequent read client after observer expiry. No controller/test changes were needed for that earlier deadline-only fix; this revision changes their pins for the separate bind predicate correction below. The deadline flag/reset/precedence code remains present in the current inspected diagnostic.

Inspected tests cover expiry at MODEL_USER ENTER and PASS, exact CLIENT_TIMEOUT/REFUSED/NO_ACTIVATION output and fixed checkpoint, no network/volume/exec/up/stop follow-on, plus stale-flag reset preserving the shared deadline and an unrelated refusal. User reports5 selected inert tests PASS; this is author-attributed, not independently executed here. The previously reported observer-timeout misclassification caveat is closed for these exact revised bytes. Ordinary non-timeout observer faults remain intentionally fail-closed; a fixed context is not, by itself, proof of historical cause or a false comparison.

### Present-bind false/omitempty correction — ACCEPTED

Inspected the current MODEL_BIND_OPTIONS predicate, surrounding mount equality, focused BindRepresentationTests, inert compose_json oracle, diagnostic bind fixture/tests and revised PINS. The new predicate requires `type(mount.get('bind')) is dict`, keys a subset of exactly `{'create_host_path'}`, and, if that key is present, its value `is False`. Thus exactly the two supported representations pass: present `{}` or present `{'create_host_path': False}`. Missing/nil bind, null, booleans, numeric0/1, strings/lists, true, null-valued key and unknown/extra options refuse. Python truthiness or equality-to-zero is not substituted for the boolean identity check.

User/security reports independent inspection of tagged Compose v2.34.0 and compose-go v2.4.9: false is omitted from JSON, but a non-nil Bind object retains the Mount API path with CreateMountpoint false, unlike the nil/legacy path. This external tagged-contract finding is security-attributed, not an upstream fetch or actual private operand observation by this reviewer. It supports accepting the PRESENT empty object, not defaulting an absent bind object to false. The narrow inspected predicate implements that distinction.

The correction neither inserts/deletes bind/options in the production serialized model nor creates host paths. Exact source/target/read-only mount equality remains mandatory after the bind-options check. Compilation still writes the serialized model directly and requires full rendered equality; no mutation, re-escaping, label/resource, AUTH, WAL/helper/timer or runner change is accepted here. The test-only compose_json oracle deep-copies synthetic input before omitting only an exact false flag, keeping the bind object; it does not mutate the raw fixture.

Inspected focused assertions cover both accepted forms with observed/unobserved comparator parity and no model mutation; absent/null/numeric/true/extra-option refusal at the fixed bind gate; source/target/read-only drift refusal at MODEL_MOUNTS; unchanged normalized-empty compilation/full roundtrip; and full diagnostic read-subset completion versus immediate bind/mount refusal with no next client. Selected8+7 inert tests PASS is author-attributed, NOT independently run here. No public render/plugin/private stand probe or diagnostic was repeated.

This source correction is consistent with the reported fixed-gate failure and independently supplied contract. It does not invent the actual bind operand from the private render, claim whole parser/Engine compatibility or certify runtime readiness.

### Full continuing read-only preflight scope — NOT API-only

The unchanged accepted observation continues after successful API preparation/config matching: remaining worker/web/egress/llm-egress model checks; model restrictions and image-only in-memory substitution; four-setting compatibility-input validation in memory; derived network topology/two named-volume metadata; host disk/Engine capacity/public helper-access predicates; all-container writer mount projection; final original/resource/source/secret/selector stability; API socket and lock-absence guards; then D_COMPLETE. All use the existing restricted read runner and caps. This revision neither stops at API success nor adds a new operation. It still omits the write/helper/migration/serving gates listed below.

## Required security/parent envelope

Before any invocation, security must independently approve the exact `.sh` hash above and current four-source packet. Parent must preserve:

- ONE foreground diagnostic invocation, external `timeout_ms=150000`; internal shared120s, each client≤15s/remaining, failed-client reap≤5s. Host/kernel blocking is not a hard cancellation guarantee; client termination is not daemon cancellation.
- Exact cwd and command bytes. No interpreter substitution, env-i/PATH rewrite, private sourcing, xtrace/tee/output dump/local report, extra query/fallback/retry/background continuation or cleanup.
- Existing exclusive/scheduling-disabled posture. Existing lock means refusal without adoption/read/removal. Read runner only; fixed original/image/render/network/volume/info/census/projection operations and existing both-stream caps. Foreign metadata stays id/running/mounts-only; trusted fixed actor Env/render stays private memory.
- No backup/compiled/coordination/source/private-data write, DB/recovery/log inspection, native/app/helper/provider/history operation, init, stop/start/up/create/cp/rm or migration. Authorization-named CLI flags are intended-profile comparison assertions only.
- STOP after either result. No failed/partial receipt rescue or automatic follow-up. A completed observation requires exit0 plus exact `mode=preflight-readonly-v1`, `checkpoint=D_COMPLETE`, `outcome=READ_SUBSET_PASS`, `category=NONE`, `boundary=NO_ACTIVATION` (JSON key order immaterial).

READ_SUBSET_PASS still omits lock acquire/release, backup/compiled allocation/write/fsync/roundtrip, live store/version/WAL/ALL-state, helper/native/migration/holder/app-startup/readiness/provider qualification. It neither diagnoses the spent invocation nor authorizes production. No new runtime result exists in this review.
