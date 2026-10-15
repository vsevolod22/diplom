# Independent source/literal review — model classification, 2026-10-15

## Decision

**APPROVE source and frozen literal for ONE classification-only observation, conditional on separate independent security approval of these exact command bytes. NOT EXECUTED.** No concrete correctness blocker found in the focused change. This is not approval of production activation, migration, full preflight, or any retry of a spent command.

Literal: `docs/deployment/readonly-model-classification-20261015.sh`

SHA-256: `e386f15c64173cff3e4ed07970d78b8b565bd06844b4b8d45a24d0696f0d05e1`

Required cwd: `/Users/vsevolod/Documents/startup/diplom`. Required external caller `timeout_ms=150000`; shared diagnostic deadline 120s, each read client at most 15s, unsuccessful child reap at most 5s. These are caller conditions, not a timeout enforced by the shell file. ONE foreground invocation after security approval; STOP on success, refusal, timeout, or incomplete output. No follow-up query, retry, cleanup, or activation authorized by this packet.

## Actual public pins verified by SHA-256

| Public file under `server/deploy/trust/` | SHA-256 |
| --- | --- |
| `recreate_openrouter_key.py` | `578614762e0d52e285500e59039ff20b3ae827b7505847f53e5bb888d4d969d1` |
| `test_recreate_openrouter_key.py` | `33138e47e31533ceb470865554402c2a4c28f14158113451b10659f146daac95` |
| `diagnose_preservation_preflight.py` | `4bd4ece7992e8ddce67e88a073420ba4296ddf64f2409c740c852104f863d2f3` |
| `test_diagnose_preservation_preflight.py` | `0e81c89a1e475df6cfee2c5002c2261b3c6841b8b12df8985764a62b95704be5` |

The controller pair is unchanged. The literal preserves all original/candidate IDs, aggregate, evidence bindings `502/491/463`, nine production source pins, isolated interpreter and explicit Docker environment from the spent literal. Only the diagnostic pair pins and `--classify-models-only` change its operational arguments. The seven other production pins are preserved and matched against the diagnostic's public `PINS`; they were not independently rehashed in this focused review.

## Focused findings

- `observe()` retains existing ancestry/lock-absence, public-source verification, plan/protocol, secret **metadata**, Compose selector/version, original identity/bounds and image checks before the same single render capture. It does not acquire/remove a lock or write backups/compiled files. Existing private client output remains bounded in memory; it is not emitted. The literal does not grant arbitrary read commands.
- Immediately after render/model-shape validation, classification calls `classify_captured()` then **returns**, including all-pass. It cannot reach subsequent network/volume/Engine/census clients, image substitution, AUTH-input construction, final rechecks, compiled roundtrip, DB/helper, lifecycle or serving operations. The class still contains the legacy full-read path; the frozen exact flag selects the early-return path.
- Fixed order is API, worker, web, egress, llm-egress. Each reached authoritative `model_matches()` is called at most once and fails fast internally. A whole-model decoder failure blocks all roles. API Env preparation failure blocks the API comparator, not the other roles. Continuing to other roles is in-memory classification of the captured snapshot, not a client retry. Observer state resets between roles; serialized model and actual inspect/image Env are not normalized or rewritten.
- The first failure checkpoint/category is retained. A later deadline takes top-level `CLIENT_TIMEOUT` precedence while retaining the earlier `firstFailure`; it aborts remaining work. The deadline latch remains effective when the controller sanitizes observer exceptions. It is not a new 120s budget per role.
- Mount projection uses the same expected/actual four-tuples as production, excludes actual tmpfs consistently, requires list bounds of 256 and string/string/string/bool rows, and emits only eight fixed flags. Duplicate or unmatched target sets block dependent field comparisons. Type mismatch blocks source comparisons. Bind source and named-volume name comparisons are exact, with no alias/path equivalence, operand output, or guessed matching. These flags diagnose structure; they do not override the authoritative comparator or establish store provenance.
- Fixed flags: `MALFORMED`, `CARDINALITY_MISMATCH`, `DUPLICATE_TARGETS`, `UNMATCHED_TARGETS`, `TYPE_MISMATCH`, `BIND_SOURCE_MISMATCH`, `NAMED_VOLUME_SOURCE_MISMATCH`, `RW_MISMATCH`; values `YES/NO/BLOCKED`. Model values are `PASS/FAIL/BLOCKED`. Valid classification result has eight fixed top-level fields, mode `model-classification-readonly-v1`, boundary `NO_ACTIVATION`, and a closed JSON payload bounded to 4096 bytes. No mount paths, aliases, Env values/keys, source hashes, image/container IDs or raw child stderr are included.
- All-pass means `MODELS_CLASSIFIED`, category `NONE`, checkpoint `D_MODELS_CLASSIFIED`, null `firstFailure`; it does **not** mean `READ_SUBSET_PASS` or `D_COMPLETE`. Any recorded failure yields refusal. Argument/bootstrap or catastrophic handling may return a closed legacy-mode refusal; that is not successful classification and grants no continuation.

## Validation and spent boundary

Reviewed public implementation, the authoritative comparator, and focused test source for all-role single calls/early stop, multirole first-failure retention, API-preparation blocking, decoder blocking, timeout precedence, projection flags/dependency blocking/bounds and strict CLI selection. Author reports 13 selected inert tests PASS; **this reviewer did not execute/import code or run tests**. Only public-file SHA-256 commands were run. No Docker, native, provider, private file, DB, Env, log or recovery access by this reviewer.

Prior `readonly-api-predicate-diagnostic-20261015.sh` SHA-256 `52cd2f7a8aa5fa84d0f998ce3454b2ba6d11a3a198207d5e37d3725e7fea27b1` is **SPENT**, user-reported actual `D_P_API__MODEL_MOUNTS` refusal, `PREDICATE_REFUSED/NO_ACTIVATION`. It was hash-checked and left untouched, as was its paired review. No result from that attempt is reinterpreted as success or renewed authority. This review makes no runtime readiness, real-state preservation, migration, full-provider or history qualification claim.
