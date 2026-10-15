# Independent correctness review — production rollout R2, 2026-10-15

## Decision and literal

**CORRECTNESS APPROVE ONE deliberate R2 production attempt under the existing consent, conditional on independent final security approval of the exact current source/literal. NOT EXECUTED by this reviewer.** No additional concrete source/literal blocker was found. This is not a prediction of successful migration/deployment or permission to bypass runtime admission, retry, repair or restore.

- Frozen literal: `docs/deployment/preserving-rollout-20261015-r2.sh`.
- SHA-256: `2904862c344cfa3cbe520ff4dc5a7e84e362549a5fd6631c84eb778cc0b0ba4f`.
- Required cwd: `/Users/vsevolod/Documents/startup/diplom`.
- After independent security acceptance only, parent invocation: `/bin/sh docs/deployment/preserving-rollout-20261015-r2.sh`, ONE foreground attempt, caller `timeout_ms=660000`.
- Internal default600s, holder240s, pending160s, existing pre-pending cleanup45s and anchored pending cleanup20s remain unchanged. The caller budget does not widen these internal bounds. Existing holder2GiB/resource/admission caps remain. Filesystem/daemon work is not universally preemptible; timeout does not prove cancellation.

A direct public-file diff against current preparation R2 confirms ONLY the executable action changes from `--prepare-rollout-only` to `--activate-existing-api`; header comments describe production and its budgets. All eleven source pins, five original container/image pairs, three candidates, aggregate, evidence502/491/463, verifier paths, grants, isolated interpreter and explicit socket/environment are byte-identical. No diagnostic or original-worker-profile flag is added. Existing exclusive-window, additive migration, durable preservation backup, coordinated API/worker/web replacement and explicit narrow API CVE release-source alignment consent apply.

## Actual preparation observation — narrow and spent

User reports ONE invocation of exact preparation R2 SHA-256 `fc54194d5b8d1f4ede96dc393dcb6d8fa27ac0608c6b0787160c2dfd00668b22` via `/bin/sh`, caller180000ms, exit0, closed receipt:

```json
{"category":"NONE","checkpoint":"COMPLETE","migrationApplied":false,"mode":"rollout-preparation-only-v1","ok":true,"preparationOnly":true,"providerCalled":false,"standServicesRecreated":false}
```

STOP was observed with no further operations reported. This is attributed parent evidence, not a new reviewer runtime query. It supports that preparation observation only; it does not establish real store versions/compatibility, preservation migration, serving readiness or provider operation. Preparation R2 is SPENT and must not be rerun. Prior failed preparationb6acc and production47ce remain failed/SPENT; no causes or runtime state are inferred beyond their reported receipts. All three spent shell hashes were checked unchanged. Their shell/review files were not edited.

## Current production-path review

1. **Default observer=None is intentional.** The production literal contains no preparation flag, so direct bootstrap/main do not create a `PreparationObservation`; stage wrappers yield directly and lock handling uses the original refresh-lock context. Runner selects default600s, not preparation150s. Preparation-only selected-prefix read15s caps and checkpoint/suffixed-stage receipts are not active in production; existing explicit per-client timeouts remain. Failure output may therefore still be the ordinary sanitized production phase/uncertainty receipt, not a granular preparation diagnostic. No observer is required for the release safety checks themselves.
2. **Scratch before seal, exact typed adapter.** Shared preflight creates fresh OWN0700 backup scratch before release authentication/sealing, then writes0600 compiled/alignment children. It never adopts prior preparation output. Full ancestor/file/hash/freshness equality is unchanged. The pinned source-before-import loader retains the verified module's exact exception class; adapter allowlists fixed attributes and neither parses text nor uses stale `last_recheck_stage`. Translated exceptions remain failures without observation; no fallback or new acceptance path is introduced.
3. **Fresh gate and three boundaries.** This invocation obtains a fresh verifier actor/capability, not a preparation seal. `operate_migration()` rechecks immediately before activation HOLD/first stop. `migration_up()` rechecks immediately before API/worker replacement and before web replacement. Source pins, model equality, candidate identities, resources, writer/stability fences and export revalidation remain mandatory. Only the explicitly authorized API read-only CVE source exception is admitted; personal-state mounts/non-key environment remain constrained.
4. **Durable preservation before original RW.** OWN HOLD precedes touched/stand mutations; ingress is stopped/drained, API/worker stopped and writers fenced. Original raw capture is read-only through the bounded holder. Durable PRE export and private-clone plan export, plus inventory/hash/fsync revalidation, precede original auth/ledger RW. The unchanged MJS helper retains checked auth/ledger WAL provenance/private recovery without original journal-mode conversion, strict read-only MAIN/DELETE quota and full old-state/additive comparisons. Real-state size, DDL, versions, in-flight work and capacity can still refuse; none is invented from preparation PASS.
5. **Strict POST precedes replacement.** After apply, separate POST capture, exact migrated all-state comparison, CURRENT sealed-POST compatibility and durable POST/migration material exports must succeed. Holder removal follows those gates. NEW API/worker replace together, then local readiness/anonymous checks, then NEW web and final fences/readiness/ingress checks. OLD worker/web are not resumed. Result durability and HOLD release are still acceptance steps, not inferred from running containers.
6. **Failure and timers are unchanged.** Pending160/cleanup20 remains anchored inside holder240; the existing non-pending best-effort45 cleanup branch is unchanged, not a new allowance. Ambiguous apply/copy retains qualified OWN holder/material as applicable; touched failures preserve HOLD and stop attributable replacements best-effort. No automatic old-worker rollback or private recovery read/restore is authorized by this review. Auth and ledger commits are **not cross-file atomic**: partial additive commit is possible and requires HOLD plus separately reviewed manual reconciliation, not retry.

## Source identity

All eleven public command files were individually rehashed during this reconciliation and match the frozen literal. The four updated pins are:

| File under `server/deploy/trust/` | SHA-256 |
| --- | --- |
| `recreate_openrouter_key.py` | `b34dcd63a77d06d997b4c6bf61a36bc7fbe67d8129aa12f444d055a1b9f50438` |
| `test_recreate_openrouter_key.py` | `b34b1f14483ee7f5a280181042e5eb11bbdc8459e42c247c7c72cd4b0cb914cb` |
| `verify_preservation_release.py` | `c93ced26d68140f2afe3201db16b373ecc5260a9212fd2075d2e978c1d898533` |
| `test_verify_preservation_release.py` | `04c1748f6f5180225584e0f06e4e80f0e0598f2390a0bbd60296374b504fbd39` |

Other seven files match their full unchanged literal pins: MJS helper323ca629/testf9668e4f, selector97283889, Compose da5c96aa/80ec2a65/f6587a7a/6dcb3afd. Hardcoded verifier pins agree with CLI; bootstrap selector pin is unchanged. No stale prior verifier pair is used by the new literal.

Candidate bindings remain:

- API `sha256:4b3a3d4b3c2658ec9a36209afcac69eda2b64cef6e055a5e2716e2602e5338d1`.
- Worker `sha256:891b5adccbe469345cea585e75dc71c6d3bf93405c5a18386795af1b012b314d`.
- Web `sha256:3d14f3d9e7347a9609fe3ae53b46efd70293aacae64da48c001ed6e826155817`.
- Aggregate `29c3ca5bd186d625cc102e2f7e43b4f1e8e168ba3372cabd7840cc21b6676a37`.
- Startup/candidate `DIP-ARTF-502`, migration `DIP-ARTF-491`, web `DIP-ARTF-463`.

These are preserved evidence/identity bindings, not newly inspected images or native/app-body proof. The old-API read-confirm argument remains tied to applicable prior source review; it is not supported merely by a shape, import success or preparation receipt. No old-worker-profile assertion is made.

## Limits and next gate

Expected production success fields, **NOT OBSERVED**: `ok:true`, `preservationCompared:true`, `comparisonMode:"additive-scan-auth"`, `keyConfigured:true`, `providerOperabilityProven:false`, `postResumeStateCompared:false`. Preservation comparison certifies fenced stopped POST before new application writes, not a second full equality after resumed writes. Local readiness does not establish real provider operation, scanner/history coverage, or enable source-disabled functional flags.

This was focused public-source/literal inspection and SHA-256/diff validation, not tests/imports or runtime qualification. No Docker/HTTP/native/provider operation, private Env/DB/log/recovery read, source/Git/tracker change or repeat qualification was performed. Only the two NEW production R2 documentation files were written.

**Next:** independent security approval of this exact current source and shell hash, then ONE deliberate parent invocation under existing consent/caller660000ms. Stop after its result. Refusal/failure/timeout/incomplete receipt requires STOP/HOLD as applicable and truthful attribution, with no automatic retry, follow-up inspection, cleanup, repair or rollback. Changed sources/bindings/literal require corresponding review.
