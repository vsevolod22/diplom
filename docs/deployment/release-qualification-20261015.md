# Independent source/literal review — release qualification, 2026-10-15

## Actual parent observation — SPENT, no reuse

The user reports that the exact shell file SHA-256 `8f328726d2ded19c531b1851bf0426e93098b07157a62f90f83a8f16024727c8` was invoked ONCE via `/bin/sh`, external caller180000ms, exit0, returning:

```json
{"migrationApplied":false,"mode":"release-qualification-only-v1","ok":true,"providerCalled":false,"releaseAuthenticated":true,"standServicesRecreated":false}
```

This is attributed parent evidence, not an independent reviewer runtime observation. No follow-up query or mutation is reported. The qualification literal is **SPENT: do not rerun it**. The frozen shell bytes remain untouched, including their historical pre-execution comments. This PASS covers release qualification only, not personal-store compatibility, migration, deployment readiness or provider operation. The separately reviewed production candidate is `docs/deployment/preserving-rollout-20261015.sh`; its source/literal review does not convert qualification into production success.

## Historical pre-invocation disposition

**CORRECTNESS APPROVAL for ONE bounded qualification attempt, conditional on independent final security source/literal approval. NOT EXECUTED BY THIS REVIEWER.** The HOLD-order finding and subsequent isolated-entry sibling-import finding are closed in the current controller source. No additional concrete correctness blocker was found in the focused bootstrap/integration/qualification route. This is not approval of activation/deployment or a retry, and the shell file alone is not execution authority.

Frozen literal: `docs/deployment/release-qualification-20261015.sh`

SHA-256: `8f328726d2ded19c531b1851bf0426e93098b07157a62f90f83a8f16024727c8`

This revision changes ONLY the two controller/source-test pin arguments in the shell file, from `5661356c.../5571d385...` to `40a9f3db.../04034bb4...`. All other arguments/comments, the other nine source pins, original/candidate identities, interpreter/environment and budgets are unchanged. Prior `fb497414...` is superseded; that earlier comment-only reconciliation had superseded `69654c4e...`. None of these review candidates was executed by this reviewer.

### Reconciled focused validation evidence

- Earlier 17 integration/controller tests: author-reported clean process PASS on the prior reviewed integration revision.
- Final four HOLD persistence-failure tests: author-reported **exit0, four PASS in 0.063s**, with guards closed and no non-main threads. These target the final functional correction: establish OWN HOLD before retained-identity validation/mkdir/write/fsync. Source inspection covers the correction and its failure-injection tests.
- The combined 21-test invocation printed `OK` in approximately 3.2s but its process timed out at 30s. Its cause remains **UNKNOWN** and that invocation is **NOT a clean PASS**. The two clean observations above must not be relabeled as a clean combined 21-test run or proof of the timeout's cause.
- Seven diagnostic tests on the prior revision: author-reported clean process PASS; the diagnostic is not invoked by this qualification literal.
- Current isolated-entry correction: author reports **five bootstrap tests, eight loader/HOLD/qualification tests, and eleven selected diagnostic tests**, each selection with clean exit0 under `-I -B`, guards closed and no non-main threads. These are separately attributed selected-test observations, not an independently rerun suite and not an explanation or reclassification of the older 21-test timeout.

**Decision:** the separate clean integration/final-HOLD observations and current bootstrap/loader/qualification observations, together with the reviewed isolated qualification route and verified current pins, are sufficient for ONE bounded qualification. The concrete isolated sibling-import defect is now source-corrected and covered by focused author-reported clean selections. No concrete source defect linking the unexplained older combined-run exit to this route has been identified. Solving that historical cause is no longer a prerequisite to this one observation; no additional inert test is requested. This narrows/revises the prior overbroad execution blocker, not the historical test result.

The route still fails closed, never enters stand activation/migration, and remains subject to shared150s/actor90s/caller180000ms plus private retained-actor/HOLD handling. These bounds do not prove daemon cancellation or universal process-exit behavior. Independent final security acceptance of the exact source/literal is still required before parent execution. Refusal/timeout/incomplete receipt remains STOP, with no automatic retry or cleanup.

All test observations are attributed to the author/user, not executions by this reviewer. Verifier final-source security ACCEPT is attributed to its independent reviewer and is distinct from final approval of this literal. All eleven command source pins were rehashed during this reconciliation and match. Any source/pin changes require corresponding literal revision and review.

## Actual public hashes

These six public files were hashed directly without executing/importing them:

| File under `server/deploy/trust/` | SHA-256 |
| --- | --- |
| `recreate_openrouter_key.py` | `40a9f3db0b0f46f6a8460bfc4ccc25765dc85c42002a16397c9ff7d18e178213` |
| `test_recreate_openrouter_key.py` | `04034bb4e66d45266f2feb7ef6dd0f6324f0f30c8a42cc4acda2881ca765b4cc` |
| `diagnose_preservation_preflight.py` | `77c37d817a8d7fcde5bd05f06bc6f62aa25109c9f9de680530ab0aecc78b4db4` |
| `test_diagnose_preservation_preflight.py` | `38a2fb76394deeff5803748d76927fe9ee8bd3239c6e190f4638a8eee6fba538` |
| `verify_preservation_release.py` | `13a0c971ae89c63ef97fee71bbc456c7e95c3be9781ba8c4a47580490444a2c6` |
| `test_verify_preservation_release.py` | `ee74c313b0522b899221a2ea825647ac02d700773320c9f91e4e755e30f9ac0f` |

The seven unchanged production files (MJS helper/test, selector, four Compose files) were also individually hashed and match their full hashes in the literal. Thus all eleven command source pins match actual public files at review time. The diagnostic pair is recorded for context but is neither invoked nor passed as command source pins.

The literal preserves all five original container/image bindings, three candidate image IDs, source aggregate `29c3ca5bd186d625cc102e2f7e43b4f1e8e168ba3372cabd7840cc21b6676a37`, and evidence bindings `DIP-ARTF-502/491/463`. These are requested bindings, not newly observed live state.

## Focused source findings

1. **HOLD ordering corrected.** `retain_release_failure()` marks uncertainty first, attempts OWN HOLD before retained-identity validation, backup creation, private identity write or backup fsync. Subsequent persistence failures therefore no longer skip an already-established HOLD. The added test source injects mkdir, detail-write, backup-fsync and HOLD-directory-fsync failures and checks closed uncertainty/marker retention and no stand-service actions. Initial HOLD creation itself can still fail under filesystem failure; no universal durability guarantee is claimed.
2. **Source before import.** The verifier loader validates the eleven-source profile, captures and hashes all sources before executing only captured verifier-module bytes, never test bytes. The exact factory receives the same runner/deadline and fresh attempt ID. The returned gate must match the fixed verifier pair, expose verify/recheck and have no retained actor initially. There is no missing-gate fallback. Seal acceptance requires exactly 32 bytes. Separately, the corrected controller bootstrap supports the literal isolated `-I -B` entry: it captures the fixed `stand_composition.py` sibling, validates ancestry/owner/regular-single-link/64KiB bounds and stable FD/path identity, checks SHA-256 `97283889749a4413d5e27f9b0ce828927f56b56ef507cb220a3c607fd3d23f5a`, then compiles/executes only those captured bytes. It neither modifies `sys.path` nor imports a canonical/installed selector; canonical and bootstrap preloads refuse before source open. Only its OWN temporary module entry is removed. Direct bootstrap failure exits1 with closed preflight JSON and no raw traceback before main/clients/lock acquisition. The diagnostic no longer injects a selector; it verifies captured controller/selector pins, executes the controller and relies on that same independent sibling capture. Focused test source covers verification-before-exec, tampering, preload refusal, owned cleanup and closed direct-entry failures.
3. **Qualification cannot fall through.** CLI action selection is mutually exclusive. `Plan.validate()` requires alignment and preservation-migration bindings for qualification. `operate()` immediately returns `qualify_release()`, which performs bounded original/candidate/model checks, calls the unchanged authoritative comparators with the narrow source exception in shape-only mode, then authenticates the selected release once and returns. It does not enter compiled-model generation, migration/preflight remainder, personal-store access, SQLite helper execution, holder creation, app startup, live-service stop/up, readiness/provider calls or production rechecks. Migration authorization arguments satisfy the shared plan but do not select migration execution here.
4. **Exception remains narrow.** Selected API source must equal modeled/actual worker release; worker release/cache mounts and four CVE settings remain bound. Only the two exact API release-source fields are masked in old/new configuration identity. Other HostConfig fields, propagation, personal-state mounts, and non-key Env are not dropped. This is an explicitly authorized source change, not old-source adoption or provenance by shape alone.
5. **Verifier boundary.** The final verifier disables inherited healthchecks, guards that state, bounds directory enumeration, and uses its pinned release-authentication/policy dependency path rather than an application/scanner entrypoint. Its public release hash/signature/freshness work is distinct from personal SQLite access. One newly owned actor may be created/started; exact guarded exited success cleanup is internal. Failure retention is private, with controller uncertainty/HOLD and no stand fail-stop before stand mutation. No parent cleanup/retry is authorized. Detailed verifier dependency-chain security acceptance remains attributed to its separate reviewer.
6. **Budgets remain bounded.** Qualification uses shared runner150s; verifier work is limited by actor90s and that same outer deadline. Required external caller is `timeout_ms=180000`, required cwd `/Users/vsevolod/Documents/startup/diplom`, interpreter/environment exactly as frozen. No holder240s or production deadline is widened. Cooperative host I/O checks do not prove preemption/cancellation of kernel or daemon work. Shell comments do not enforce caller timeout or prevent an unauthorized invocation.

## Source-selected result scope

The parent-reported receipt above matches the expected source-selected qualification fields. On successful source-selected qualification, the controller returns `ok:true`, `mode:release-qualification-only-v1`, `releaseAuthenticated:true`, `standServicesRecreated:false`, `migrationApplied:false`, `providerCalled:false`. This would establish only the selected signed release's qualification at that observation, not CVE/scanner coverage, personal-state preservation/migration, serving readiness, provider operability, or future freshness. Refusal/timeout/incomplete output requires STOP and reconciliation as indicated; it is not permission to rerun.

The frozen command contains no diagnostic flags/pins and no activation flag. It permits the existing OWN coordination lock lifecycle and private retained-actor/HOLD persistence on failure. It is not an entirely no-write operation and is not described as one. Existing spent diagnostic/classification command files and reviews are untouched.

Reviewer activity for this qualification review was public-source/test inspection, public SHA-256 hashing, and creation/update of these two authorized documentation files only. The initial evidence reconciliation changed only shell comments and this review. The current isolated-bootstrap revision changes only the two controller/source-test pin arguments in the shell file and updates this review. No production source was edited by this reviewer; all other operational arguments and budgets remain unchanged. No test/import/script invocation, Docker/HTTP/native/provider action, private Env/DB/log/recovery read, source/Git/tracker write or new qualification was performed.
