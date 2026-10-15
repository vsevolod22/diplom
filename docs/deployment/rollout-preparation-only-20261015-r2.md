# Independent correctness review — preparation-only R2, 2026-10-15

## Frozen decision

**CORRECTNESS APPROVE ONE new R2 preparation attempt, conditional on independent final security approval of these exact sources/literal. NOT EXECUTED by this reviewer.** No concrete blocker was found in the focused directory/seal ordering correction, exact-class verifier adapter, closed failure attribution or preparation return boundary. This is NOT READONLY and does not authorize activation, migration, a production retry or automatic continuation.

- Literal: `docs/deployment/rollout-preparation-only-20261015-r2.sh`.
- SHA-256: `fc54194d5b8d1f4ede96dc393dcb6d8fa27ac0608c6b0787160c2dfd00668b22`.
- Required cwd: `/Users/vsevolod/Documents/startup/diplom`.
- After independent security acceptance only: parent may invoke `/bin/sh docs/deployment/rollout-preparation-only-20261015-r2.sh` ONCE, foreground, caller `timeout_ms=180000`.
- Shared150s, verifier actor90s; read-client15s applies only to the selected Engine/Compose prefixes in Runner. Verifier create/start/stop/rm retain the existing actor/shared-deadline contract. No resource/timer widening. Cooperative filesystem checks do not guarantee preemption or daemon cancellation.

Actual public-file diff confirms that executable command arguments differ from the spent preparation literal ONLY in the four controller/verifier source/test pins. Action stays `--prepare-rollout-only`; isolated interpreter, explicit socket/environment, five original pairs, three candidates, source aggregate, evidence502/491/463, verifier paths and grants are unchanged. Only two header comments additionally identify R2 and spent observations. No diagnostic flag/pin or old-worker-profile flag is introduced.

## Spent observations, not redefined

The user reports the prior exact preparation script `b6acc1ff41ffc297e8f5dda0dc688a1a99189aa32f1d1422b904603ff2495e52` failed at `FIRST_RELEASE_RECHECK`, category `UNEXPECTED`, after prior preparation gates passed, with no other operations. This is attributed parent evidence, not an independent runtime inspection or proof of a specific underlying exception. The opaque production47ce failure also remains a failure. Both authorities are SPENT. Neither is renewed here, and their files were not edited. The prior preparation shell was rehashed and remains exact b6acc.

## Focused source findings

1. **The self-induced ancestor mutation is removed without weakening the seal.** Shared preflight now creates a fresh0700 OWN backup directory and sets its compiled path BEFORE `verify_release()`. It requires backup/compiled to be absent, never adopts an old output, and still performs release authentication before allowing the API source exception. Later compiled/alignment writes are children of that backup, not new entries in the sealed release's `.local-auth` ancestor. Verifier inventory still captures/reopens and compares the full ancestor chain, exact release entries, file identities/hashes and clock bounds; no ancestor field or comparison was dropped. The supported-layout tests cover preparation's first recheck and production's three boundaries; verifier tests show a post-seal sibling mkdir still refuses while a pre-seal scratch directory permits recheck. This establishes a concrete static defect and correction, not certainty that it was the only cause of the spent failure.
2. **Adapter identity is source-authenticated, not name/text based.** The loader verifies all eleven public sources before compiling captured verifier bytes, obtains that module's exact `ReleaseRefused` class, validates its module and exact stage/category inventories, and passes the retained class object to `PinnedReleaseGate`. Only `type(failure) is captured_class` is translated. Subclasses, same-named types, unknown exceptions and invalid/missing attributes propagate to closed generic failure rather than earning a typed category. Verify/factory mapping requires both attributes None; recheck mapping requires exact string allowlists. No message, repr, traceback, suppressed exception context or `last_recheck_stage` property is read by the adapter for attribution.
3. **Attribution remains closed and first-failure only.** Verifier recheck emits only one of six fixed stages: `CAPABILITY_REQUEST`, `SOURCE_PINS`, `CLOCK_BEFORE`, `INVENTORY_READ`, `INVENTORY_EQUALITY`, `CLOCK_AFTER`; categories are `PREDICATE_REFUSED` or `UNEXPECTED`. It still marks the gate failed on refusal, allows at most three checks of the same capability and never reruns an actor in recheck. Controller exposes the validated suffix only under `FIRST_RELEASE_RECHECK__<fixed-stage>`. Its global deadline classification takes precedence, first failure survives later lock-exit errors, and output stays bounded4096 bytes. The stale gate property cannot override this exception's attributes. This does not claim every internal verifier error has a separately distinguishable public cause.
4. **Preparation remains separate and non-activating.** CLI mutual exclusion and complete plan/source/grant validation remain. `operate()` runs shared preflight and one first release recheck, then returns before migration dispatch, close_ingress, activation HOLD/touched, service stop/up, storage holder, DB reads/writes, SQLite helper commands, readiness or provider calls. Preparation still permits fresh lock/private compiled/alignment records/fsync and ONE verifier actor. Existing verifier failure retention can set uncertainty and OWN HOLD before private persistence; touched=false does not invoke stand fail-stop. No parent cleanup or retry is authorized.
5. **No new accepted baseline or predicate bypass.** Original/candidate model comparators, API narrow source exception, four raw auth fields, full compiled/render equality, mounts/env/resources, writer/stability and final source/selector guards remain. The new directory ordering is shared with production, but this literal approves only preparation. Production must receive separate current-source/literal review; its spent old script cannot be used with these new pins.

## Exact public pins verified

All eleven command sources and the diagnostic context pair were hashed directly without importing/executing them. The four changed command pins match both the new literal and controller's fixed verifier profile:

| File under `server/deploy/trust/` | SHA-256 |
| --- | --- |
| `recreate_openrouter_key.py` | `b34dcd63a77d06d997b4c6bf61a36bc7fbe67d8129aa12f444d055a1b9f50438` |
| `test_recreate_openrouter_key.py` | `b34b1f14483ee7f5a280181042e5eb11bbdc8459e42c247c7c72cd4b0cb914cb` |
| `verify_preservation_release.py` | `c93ced26d68140f2afe3201db16b373ecc5260a9212fd2075d2e978c1d898533` |
| `test_verify_preservation_release.py` | `04c1748f6f5180225584e0f06e4e80f0e0598f2390a0bbd60296374b504fbd39` |
| `diagnose_preservation_preflight.py` — context only | `401a3aa3aa86debc40a06825fd63a8a83460bc2ab1c86b83d768fb3413c732cb` |
| `test_diagnose_preservation_preflight.py` — context only | `2211d8f813a9f6963b43039172aa8004e513593d7a39bf419b43c5a482c54e80` |

The other seven command sources—MJS helper/test323ca/f9668, selector972838 and four Compose files da5c/80ec/f658/6dcb—were individually rehashed and match their full unchanged pins in the literal. Diagnostic files are not invoked or command-pinned. No obsolete13a0/ee74 verifier pin remains in the new command or controller fixed verifier pair.

## Validation and expected scope

Public test inspection covers full ancestor seals and supported layout, fresh-directory/no-adoption, exact type versus subclass/same-name errors, all six stages/two categories, invalid/missing attributes, stale property rejection, deadline precedence and first failure retention. User attributes final-pin **21+8 focused inert selections with clean exit and five verifier tests** to the author; this reviewer did not run tests, imports or any operation. These observations do not rewrite prior historical failures/timeouts.

Expected successful receipt, NOT OBSERVED: `ok:true`, `mode:"rollout-preparation-only-v1"`, `checkpoint:"COMPLETE"`, `category:"NONE"`, `preparationOnly:true`, `standServicesRecreated:false`, `migrationApplied:false`, `providerCalled:false`. This is preparation evidence only, not personal-state compatibility, migration preservation, application readiness, provider/history/scanner proof or permission to activate afterward.

Only these new R2 shell/review files were written. No production source, prior spent files, Git or tracker changes; no Docker/HTTP/native/provider operations, scripts/tests/imports or private Env/DB/log/recovery reads. After independent security approval, ONE parent preparation invocation is accepted under existing consent. Stop after the result; refusal/timeout/incomplete receipt grants no follow-up query, cleanup, repair, retry or activation.
