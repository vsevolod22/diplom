# Independent source/literal review — preparation only, 2026-10-15

## Decision

**CORRECTNESS APPROVE ONE new bounded preparation attempt, conditional on independent final security source/literal approval. NOT EXECUTED by this reviewer.** No concrete correctness blocker was found in the inspected preparation route, observer, failure boundaries or literal. This is explicitly **NOT READONLY**, not activation/migration approval and not renewal of the spent production command.

- Frozen literal: `docs/deployment/rollout-preparation-only-20261015.sh`.
- SHA-256: `b6acc1ff41ffc297e8f5dda0dc688a1a99189aa32f1d1422b904603ff2495e52`.
- Required cwd: `/Users/vsevolod/Documents/startup/diplom`.
- After independent security acceptance only, parent invocation: `/bin/sh docs/deployment/rollout-preparation-only-20261015.sh`, ONE foreground attempt, external caller `timeout_ms=180000`.
- Shared preparation deadline150s, verifier actor90s, other Engine/Compose read clients capped15s. Caller bound is a parent obligation, not enforced by comments. Host filesystem work/checkpoints are cooperative; these bounds do not prove daemon cancellation or universal wall-time completion.

The new literal preserves the production command's interpreter/socket/environment, all original/candidate bindings, aggregate, evidence, verifier paths and grants. Only operational action becomes `--prepare-rollout-only`, and the two controller source/test pins are updated. Comments describe this new scope. The other nine command source pins are unchanged; diagnostic files are neither invoked nor included among the eleven command pins. No old-worker-profile confirmation or deadline-widening option is added.

## Spent operation attribution

User reports production script SHA-256 `47ce625cdd38de59e5236c92b7c0a11f3d39892daf7759c381d5d06843ea2896` was invoked ONCE and failed exit1, phase preflight, `manualReconciliationRequired:false`, `uncertain:false`. Its cause remains **UNKNOWN**. This review does not infer a root cause or certify unchanged runtime state from that receipt. Its authority is **SPENT**. Its shell and review files are untouched; the shell was rehashed and still matches that exact SHA.

This separate preparation route was explicitly requested to observe the shared preflight with fixed failure attribution; it is not a production retry. Earlier release-only qualification PASS is not preparation or deployment PASS.

## Source findings

1. **Separate CLI action and mandatory trust bindings.** The action group is mutually exclusive with activation and release-only qualification. Validation requires alignment, the preservation-migration profile, complete existing grants, exactly eleven sources and the fixed verifier pair. The existing isolated sibling bootstrap remains hash-before-exec with no installed-selector fallback. The gate loader captures/verifies all pinned public source bytes before executing only the verifier module bytes, never its tests.
2. **Shared preflight, no shortened replacement comparator.** `operate()` runs the same authoritative `preflight()`: original/candidate image and identity checks, render, fresh release verification, all role comparators with the existing narrow API source exception, image-only substitution equality, private compilation and exact full rendered-model equality. Four-field raw auth-input equality, resource/capacity/writer/stability checks, final source/secret/selector checks and API socket exclusion remain active. There is no alias normalization, alternate acceptance comparator, journal repair or baseline adoption added here.
3. **Hard return before activation.** After preflight, the preparation branch performs `FIRST_RELEASE_RECHECK` and returns. It precedes `operate_migration()`, `close_ingress`, activation HOLD, touched=true, all stand stops/starts/up, storage holder creation, SQLite capture/compatibility/plan/apply, exports and readiness/provider calls. `migration_protocol()` in preflight checks an in-memory peer contract; it does not run the helper. `compatibility_input()` checks captured environment values privately; it does not open a DB. The preparation route does not install the pending migration timer.
4. **Explicit allowed writes.** OWN coordination lock lifecycle, fresh0700 private directory,0600 compiled/alignment records, their fsync and ONE isolated release-verifier actor are permitted. These private records can contain sensitive model/authority material and are not public output or migration backups. Existing verifier success cleanup remains internal to that verifier; preparation does not grant parent cleanup. If verification leaves an uncertain retained actor, existing retention sets uncertainty before filesystem work and attempts OWN failure HOLD before private identity persistence. No live stand fail-stop runs while touched=false. Filesystem failure can still prevent durable HOLD; this is not a universal durability claim.
5. **Fixed first-failure attribution.** `PreparationObservation` uses a finite checkpoint inventory, ENTER before evaluation and PASS after success, including bootstrap, argument/gate loading, lock ownership, every preflight group, first recheck, lock exit and final root fsync. Nested predicate failures retain the innermost active fixed gate. Observer return values have no authority; callback failures fail closed. First failure is not overwritten by later lock/retention errors. Public categories are closed: `NONE`, `PREDICATE_REFUSED`, `CLIENT_TIMEOUT`, `OBSERVER_REFUSED`, `IO_REFUSED`, `UNEXPECTED`; the receipt is capped4096 bytes without raw operands/exception text. Nonzero clients may classify as predicate refusal; this is not a raw stderr diagnostic or root-cause proof.
6. **Deadline and cleanup separation.** Bootstrap and main share one observation deadline; Runner's deadline is no later. Read calls are capped15s while verifier mutation calls retain their bounded actor/shared-deadline contract. Timeout classification is recorded before a client failure is sanitized, including subprocess timeout/global deadline precedence. After a first failure, subsequent clients refuse. OWN lock exit is attempted even after observation failure/deadline, preserving first attribution; final root fsync and COMPLETE cannot silently be skipped on a reported successful actual route. With observer=None the stage wrappers yield directly and existing non-preparation runner/action budgets remain unchanged.

## Exact verified pins

All thirteen files below were actually SHA-256 hashed without execution/import. The first eleven are the command's exact public source set.

| Public file | SHA-256 |
| --- | --- |
| `server/deploy/trust/recreate_openrouter_key.py` | `006cb83119c8bc78c7ac92df3e3cd021779a225e13f3ad791282e3f24c0dd341` |
| `server/deploy/trust/test_recreate_openrouter_key.py` | `47d7277544aadd7773a75d284f6c295f83be0b550b097059fc0e3f7c7b7b7c10` |
| `server/deploy/trust/sqlite_state_snapshot.mjs` | `323ca629483f92896634ada79d2c8f098d9ff885464eb24ba9d86bb75e563dee` |
| `server/deploy/trust/sqlite_state_snapshot.test.mjs` | `f9668e4f288a712969bf50199f38464b3d854d28d3dc4d4e58647c9c7d59453e` |
| `server/deploy/trust/stand_composition.py` | `97283889749a4413d5e27f9b0ce828927f56b56ef507cb220a3c607fd3d23f5a` |
| `server/deploy/compose.stand.yaml` | `da5c96aaa959e10b32868a458e9cc53e7a819596a33e9ac913f8f2966f552509` |
| `server/deploy/compose.stand.vuln.local.yaml` | `80ec2a655f661cfa5f51fcea0b99e216ae048b356a9c67e830e01d34bcdbe275` |
| `server/deploy/compose.stand.nginx.local.yaml` | `f6587a7a355ac1c51610d65f1851223a72b9e0e64e09f548c3e8faca0ab0e3a6` |
| `server/deploy/compose.stand.openrouter.free.yaml` | `6dcb3afd60363998e98d3ac1629d25c5a166ba00455d1cc735c26d2d686fb326` |
| `server/deploy/trust/verify_preservation_release.py` | `13a0c971ae89c63ef97fee71bbc456c7e95c3be9781ba8c4a47580490444a2c6` |
| `server/deploy/trust/test_verify_preservation_release.py` | `ee74c313b0522b899221a2ea825647ac02d700773320c9f91e4e755e30f9ac0f` |
| `server/deploy/trust/diagnose_preservation_preflight.py` — context only | `dd4ef864b964081f92f71b3a4483b2ffecff419ae52c827668a1e847bf440d63` |
| `server/deploy/trust/test_diagnose_preservation_preflight.py` — context only | `bcf8ff110fe066b6f646282932530d1ab4e491f42b586b57cacca5026bcf5023` |

The diagnostic pair's controller pins match the new pair. Its focused test source explicitly rejects selecting preparation through the readonly diagnostic and checks that its constructed plan remains non-preparation. The frozen new command calls the controller directly, not that diagnostic.

Candidate bindings remain API `sha256:4b3a3d4b3c2658ec9a36209afcac69eda2b64cef6e055a5e2716e2602e5338d1`, worker `sha256:891b5adccbe469345cea585e75dc71c6d3bf93405c5a18386795af1b012b314d`, web `sha256:3d14f3d9e7347a9609fe3ae53b46efd70293aacae64da48c001ed6e826155817`; aggregate `29c3ca5bd186d625cc102e2f7e43b4f1e8e168ba3372cabd7840cc21b6676a37`; evidence502/491/463. Full five original container/image pairs remain literal-bound, not newly observed live state.

## Validation and result limits

Inspected focused public test source covers separate CLI validation, shared-preflight success, compilation-roundtrip refusal, first-recheck refusal, ENTER deadline/no-next-client, PASS observer failure, retained-actor timeout/HOLD, final root fsync failure, lock-exit failure, argument/bootstrap failures and read15/actor90/shared150 behavior. User attributes **17+3+12 focused inert selections with clean zero exit** to the author. Those observations were not rerun by this reviewer and do not resolve or relabel older historical test timeouts.

Expected successful public receipt (NOT OBSERVED): `ok:true`, `mode:"rollout-preparation-only-v1"`, `checkpoint:"COMPLETE"`, `category:"NONE"`, `preparationOnly:true`, `standServicesRecreated:false`, `migrationApplied:false`, `providerCalled:false`. It proves only this attempt's preparation checkpoints, not real storage compatibility, migration preservation, serving readiness or provider/history/scanner operation, and does not activate or authorize automatic continuation.

Reviewer activity was public-source/test inspection, public-file hashing and creation of these two new authorized documentation files only. No tests/imports/scripts, Docker/HTTP/native/provider operations, private Env/DB/log/recovery reads or source/Git/tracker writes. Prior spent files remain untouched.

**Disposition:** after independent security acceptance of this exact hash/source, ONE parent preparation invocation is source-approved under the existing consent. Stop after its result. Any refusal, timeout or incomplete receipt is not permission to rerun, inspect private retained material, clean up or activate. Any changed source/binding/literal needs corresponding review.
