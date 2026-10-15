# Independent source/literal review — preserving rollout, 2026-10-15

## Decision and frozen literal

**CORRECTNESS APPROVE ONE source-bound production attempt, conditional on independent final security approval of this exact source/literal. NOT EXECUTED by this reviewer.** No additional concrete correctness or stale-source-pin blocker was found in the focused production lifecycle review. This is not observed deployment success, a universal preservation/completion guarantee, permission to retry, or permission to bypass any runtime refusal.

- Literal: `docs/deployment/preserving-rollout-20261015.sh`
- SHA-256: `47ce625cdd38de59e5236c92b7c0a11f3d39892daf7759c381d5d06843ea2896`
- Required cwd: `/Users/vsevolod/Documents/startup/diplom`.
- Parent invocation, only after independent final security acceptance: `/bin/sh docs/deployment/preserving-rollout-20261015.sh`, foreground, external caller `timeout_ms=660000`.
- Internal controller default600s, holder240s, pending160s and anchored cleanup20s remain unchanged. The 2GiB holder limit is not widened. Caller timeout is a parent obligation, not enforced by a shell comment.
- Existing exclusive-window, coordinated replacement, additive scan/auth migration, durable preservation backup and explicit API read-only CVE source-alignment consent apply. No additional consent is presumed for retries or recovery.

Compared with the spent qualification literal, the only operational argument change is `--qualify-release-only` to `--activate-existing-api`; comments describe the new scope. The isolated interpreter, explicit socket/environment, eleven source pins, five original container/image bindings, three candidates, aggregate, evidence references, verifier paths and migration grants are unchanged. There are no diagnostic flags/pins, no original-worker-profile flag, no widened deadline argument, no extra wrapper or output redirection.

## Prior observation — qualification only

The user reports ONE invocation of qualification script SHA-256 `8f328726d2ded19c531b1851bf0426e93098b07157a62f90f83a8f16024727c8` via `/bin/sh`, caller180000ms, exit0, with:

```json
{"migrationApplied":false,"mode":"release-qualification-only-v1","ok":true,"providerCalled":false,"releaseAuthenticated":true,"standServicesRecreated":false}
```

This is attributed parent evidence, not a fresh reviewer runtime observation. That command is **SPENT; do not rerun it**. It authenticates the selected release in its narrower route, not personal-state compatibility, migration, application startup or provider operation. Production obtains a fresh release verification/seal and performs its own rechecks; it does not adopt the prior qualification's seal.

## Exact source and candidate binding

All eleven public source files were individually rehashed during this review and matched the following command pins. No production source was edited.

| Public file | SHA-256 |
| --- | --- |
| `server/deploy/trust/recreate_openrouter_key.py` | `40a9f3db0b0f46f6a8460bfc4ccc25765dc85c42002a16397c9ff7d18e178213` |
| `server/deploy/trust/test_recreate_openrouter_key.py` | `04034bb4e66d45266f2feb7ef6dd0f6324f0f30c8a42cc4acda2881ca765b4cc` |
| `server/deploy/trust/sqlite_state_snapshot.mjs` | `323ca629483f92896634ada79d2c8f098d9ff885464eb24ba9d86bb75e563dee` |
| `server/deploy/trust/sqlite_state_snapshot.test.mjs` | `f9668e4f288a712969bf50199f38464b3d854d28d3dc4d4e58647c9c7d59453e` |
| `server/deploy/trust/stand_composition.py` | `97283889749a4413d5e27f9b0ce828927f56b56ef507cb220a3c607fd3d23f5a` |
| `server/deploy/compose.stand.yaml` | `da5c96aaa959e10b32868a458e9cc53e7a819596a33e9ac913f8f2966f552509` |
| `server/deploy/compose.stand.vuln.local.yaml` | `80ec2a655f661cfa5f51fcea0b99e216ae048b356a9c67e830e01d34bcdbe275` |
| `server/deploy/compose.stand.nginx.local.yaml` | `f6587a7a355ac1c51610d65f1851223a72b9e0e64e09f548c3e8faca0ab0e3a6` |
| `server/deploy/compose.stand.openrouter.free.yaml` | `6dcb3afd60363998e98d3ac1629d25c5a166ba00455d1cc735c26d2d686fb326` |
| `server/deploy/trust/verify_preservation_release.py` | `13a0c971ae89c63ef97fee71bbc456c7e95c3be9781ba8c4a47580490444a2c6` |
| `server/deploy/trust/test_verify_preservation_release.py` | `ee74c313b0522b899221a2ea825647ac02d700773320c9f91e4e755e30f9ac0f` |

Candidate immutable image bindings, not newly observed image contents or runtime identities:

- API: `sha256:4b3a3d4b3c2658ec9a36209afcac69eda2b64cef6e055a5e2716e2602e5338d1`.
- Worker: `sha256:891b5adccbe469345cea585e75dc71c6d3bf93405c5a18386795af1b012b314d`.
- Web: `sha256:3d14f3d9e7347a9609fe3ae53b46efd70293aacae64da48c001ed6e826155817`.
- Production source aggregate: `29c3ca5bd186d625cc102e2f7e43b4f1e8e168ba3372cabd7840cc21b6676a37`.
- Startup/candidate review: `DIP-ARTF-502`; migration review: `DIP-ARTF-491`; web review: `DIP-ARTF-463`.

The full five original container/image pairs remain frozen in the shell file. `--confirm-old-api-db-reads-reviewed` carries the existing source-review evidence; it is not inferred from native/import success or the latest release qualification. No old-worker-profile confirmation is asserted. Bootstrap selector and verifier hardcoded pins agree with these CLI pins; no additional obsolete controller pin was found in the reviewed path.

## Focused lifecycle findings

1. **Pre-stop gate and identity.** Production captures/pins source before verifier execution, obtains a fresh authenticated release, applies original/candidate/model comparators and only the authorized narrow API CVE release-source exception. Personal-state mounts and non-key environment identity remain bound. Serialized model equality is checked after reversing the selected image substitutions; private compilation/render checks remain active. Release rechecks occur before HOLD/first live stop and immediately before each API/worker and web replacement. The API source exception is explicit alignment, not old-source adoption.
2. **Fence, capture, durable PRE before original RW.** OWN HOLD precedes live mutation; web is stopped/drained, then API/worker stopped and writer fences checked. The exact isolated, bounded OWN holder captures original storage through read-only raw readers. Durable host PRE export and a private-clone migration plan export, with inventory/hash validation and fsync, precede original auth/ledger SQL writes. Plan/admission/apply guards cannot be skipped by qualification PASS.
3. **WAL and full old-state preservation.** Genuine checked auth/ledger WAL state is admitted through raw main/WAL/SHM provenance and private recovery; raw extent and recovered extent remain distinct, working SHM is advisory, and original journal modes are not converted merely to qualify. Quota must remain strict MAIN/DELETE with no WAL/SHM and is never opened RW by the helper. Unexpected DDL/triggers, incompatible state/versions or in-flight work refuse. Expected PRE auth0/0, ledger0/13 or0/14, quota1145655601/1 and CURRENT ledger0/14 are source predicates, **not observed real DB values**.
4. **Bounded original apply.** The helper opens only existing original auth/ledger RW with stable identity/file guards and immediate transactions, checks their logical baselines against sealed PRE, and permits only exact planned additive state. Old tables, typed rows/multiplicity/rowids, schema objects, optional stores, quota and ordinary files remain covered by strict comparison. The four-field private auth authority protocol remains exact; no full environment/JWT/key output is introduced.
5. **Strict POST before replacement.** Separate POST capture, exact migrated comparison, CURRENT-profile compatibility on sealed copies and durable POST/applied/attempt exports must pass. All required exports are revalidated before holder removal. Only then can NEW API/worker be replaced together, followed by readiness/anonymous401 checks, then NEW web and final stable/writer/readiness/ingress checks. Replacement paths revalidate sources, resources, compiled model, exports and release seal. No OLD worker/web resume is selected.
6. **Capacity and failure remain rejection-oriented.** Actual small-state/header/sidecar forecasts, free-space and cgroup checks remain admission gates: current holder memory <=768MiB and computed peak <=1536MiB under the existing 2GiB cap. These are conservative rejection checks, not a worst-case fit or timing proof. Pending160s/cleanup20s are anchored inside holder240s. Ambiguous apply/copy retains the qualified OWN holder/material and HOLD instead of destroying evidence; attributable replacements are stopped best-effort. No automatic repair, migration retry or old-worker rollback is authorized.

### Important accepted limitation

Auth and ledger commits are **not a single cross-file atomic transaction**. Failure after the first commit can leave an additive partial migration. The safety response is HOLD and retained durable PRE/plan/available POST/attempt evidence for separately reviewed manual reconciliation, **not** automatic retry, journal-mode repair, restore or startup of old consumers. Likewise, a host/daemon timeout does not prove cancellation; a missing/incomplete success receipt is not success.

## Acceptance limits and next action

No new tests/imports, runtime commands, Docker/HTTP/native/provider calls, private files/logs or original DB reads were performed by this reviewer. Earlier combined21 printed-OK/process-timeout evidence remains UNKNOWN/not a clean PASS; separately attributed clean focused bootstrap/HOLD/qualification selections are not relabeled as a combined-suite PASS. This review does not request another broad qualification campaign.

If every production guard succeeds, the source-selected success receipt includes `ok:true`, `preservationCompared:true`, `comparisonMode:"additive-scan-auth"`, `keyConfigured:true`, `providerOperabilityProven:false`, `postResumeStateCompared:false`. **This receipt has not been observed.** Preservation comparison covers the fenced stopped-state POST before new applications write; it is not a second full comparison after resumed writes. Local readiness/anonymous checks do not prove real provider operation, history/scanner coverage or enable source-disabled functional gates.

**Next required gate:** independent security acceptance of the exact script SHA and current source. Then the parent may perform ONE invocation with caller660000ms under the existing exclusive window. Any preflight refusal, runtime failure, timeout or incomplete receipt requires STOP/HOLD as applicable and truthful attribution; this document grants no follow-up query, cleanup, retry or recovery operation. Any source/literal/binding change requires review rather than reusing this hash.
