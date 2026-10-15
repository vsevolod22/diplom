# Continuation handoff — 2026-10-15

## Current result and authority

**NOT DEPLOYED / NOT READY.** Latest user request prioritized deleting excess Docker containers/images. Cleanup below completed; qualification/activation did not run. OpenRouter staged protected env remains unread and unactivated. No provider request, native-history retry, scanner proof rerun, migration, personal-store read/reset, stand-service recreation, commit, branch or staging occurred.

Flownix MCP remains unavailable (`server shut down` on policy/node/artifact reads). No remote comment/artifact publication is claimed. Reconcile this local record to DIP-TASK-41 when service returns. Do not invent run/work/artifact IDs. Existing historical STOPs and failures remain valid.

User already authorized exclusive maintenance, coupled recreation/deployment, additive scan/auth migration with verified durable backups, and removal of obsolete images. Independent security reviewer accepted deliberate replacement of ONLY API's read-only CVE release bind source with the modeled/current worker source as within that consent. This is **not** path normalization, preservation of the unknown old source, or reset of user data. New implementation and execution still require their applicable independent review.

## Actual Docker cleanup

Before: system df reported 41 images / 4.653 GB, 34 containers / 5 active, 24 volumes / 2.99 MB, build cache 0.

1. Four untagged images were inspected but **not deleted**: they are parent chains of the preserved API/worker candidates.
2. One reviewed exact-ID `image rm --no-prune` attempt retired 18 historical rollback images, exit 0. Fresh guards verified exact tags, absence of all container references, and exclusion from the parent closure of every non-target image. Current original/candidate/proof images remained. Historical identity receipts do not provide recoverability of the retired image bytes.
3. One reviewed exact-ID `container rm` attempt retired 17 exited containers: 15 failed CVE-proof containers in namespaces `0a0c92726b8cd4e1`, `9bef4d56d7aad6d7`, `832cb6115c24c136`, and the two exited stand BusyBox initializers. No force or volume-removal flag. Each ID/name/immutable-image/state/project/service tuple matched the frozen plan before deletion.
4. One reviewed exact-ID `image rm --no-prune` attempt retired the corresponding three now-unreferenced proof images, exit 0. Other image tags, all retained container identities/statuses, volume names and network IDs reconciled unchanged.

Frozen 17-container plan: `docs/deployment/stopped-container-retirement-20261015.json`, SHA256 `f10faf23061825f60c498e135facd400424ed1f4321972037494f983b30a429f`.

Three retired proof image IDs:
- `sha256:918fb7c6c651c8ab2f94bdf1648a0f99edf1ec2fd70c37d6179e932ede8816ea`
- `sha256:9c1f3e686fd0f49646a336cde7e0259b63e882bbbb7fbd7ccccc874f49038fcf`
- `sha256:7e25e7ad63be12517bd8fb88d88339b90a4bcd8344e2280f0146f7a7819020b1`

Final system df: **20 images / 3.102 GB / 11 active**, **17 containers / 5 active**, **24 volumes / 2.99 MB**, cache 0. Stopped container writable layers: 258 kB. Image-size reduction is approximately **1.55 GB as accounted by Docker**, not a measurement of macOS disk-image shrinkage or physical free-space return. `image ls --all` also includes four intermediate parent images, so that count differs from system df.

All five running original containers, candidates and their required parents remain. No volume, network, host evidence, recovery material or private data content was read/deleted. Container retirement intentionally discarded the specified writable layers and Docker-managed logs without reading them; it does not make failed operations successful or clear HOLDs.

**12 stopped containers remain protected**: four history resources have inherited stand project/worker labels rather than the presumed isolated ownership tuple; eight qualification/public-source actors lack independently rebound full OWN-label expectations in this continuation. Do not copy observed labels into new authority or delete them by prefix. They require a separate checked exact-ownership plan. No broad prune or force removal.

A preliminary Python wrapper for the final three-image cleanup had an IndentationError before executing any Python statements or Docker operation. It did not invoke removal; the subsequent corrected wrapper made the single authorized removal call and completed all reconciliation guards.

## Development and actual diagnostics in this continuation

All operational diagnostics were independently reviewed by correctness and security agents before one invocation each. Only closed receipts were reported. No private Env/model/DB values or logs were printed.

1. Initial approved diagnostic (controller416199 / diagnostic451eeb): exit1, `D_MODEL_API / PREDICATE_REFUSED / NO_ACTIVATION`. This checkpoint was ambiguous.
2. Added fixed predicate observation to the original comparator, not a duplicate comparator. Default fail-fast acceptance preserved. Fixed a review-found callback-timeout attribution defect so deadline expiry stays CLIENT_TIMEOUT.
3. One reviewed tagged diagnostic: exit1, `D_P_API__MODEL_BIND_OPTIONS / PREDICATE_REFUSED`. Confirmed static serialization defect: compose-go v2.4.9 bool omitempty can serialize explicitly false create_host_path as present `bind:{}`. Present non-nil bind matters for Compose Mount API; absent/null bind was NOT accepted.
4. Narrow correction accepts ONLY present plain `{}` or `{"create_host_path":false}` with strict boolean identity, rejecting missing/null/type/numeric/true/extra options. No serialized-model mutation.
5. One reviewed diagnostic after correction: exit1, `D_P_API__MODEL_MOUNTS / PREDICATE_REFUSED`.
6. Added bounded classification-only mode over the same captured operands. One reviewed actual classification: API FAIL at MODEL_MOUNTS, worker/web/egress/llm-egress PASS. API only `BIND_SOURCE_MISMATCH=YES`; all other seven API flags NO, all eight flags for every other role NO. No clients after capture, no activation. This establishes a source-string discrepancy, not path equivalence or release authenticity. No generic Docker Desktop alias contract was established.

Every above invocation is **SPENT**. Frozen diagnostic files are historical and must not be run again under those approvals. Source hashes evolved afterward.

## Implemented but NOT natively qualified: explicit release alignment

Controller optional `--align-api-cve-release` profile:
- Coupled API/worker/web preservation-migration only; no API-only shortcut.
- Exactly existing nine sources plus approved verifier module/test pair, verified before loading captured module bytes.
- Candidate API /opt/release source must equal modeled and actual worker release source; worker /db cache remains exact.
- Existing four release Env settings match between original API, original worker and model. JWT/AUTH and all other non-key Env remain exact.
- Original API comparison admits ONLY the one source difference in a transient projection, not arbitrary captured-config adoption.
- Replacement identity masks only validated corresponding API /opt/release `Source` fields in `Mounts` and `HostConfig.Mounts`; all other mount/options/config fields remain exact.
- Verification precedes production exception admission; three host-only rechecks precede first stand stop, API+worker replacement, web replacement.
- Retained verifier actor attribution remains private; uncertainty is set first and OWN HOLD is attempted before detail persistence. Missing gate fails closed. Failure of initial HOLD creation cannot guarantee a persistent marker; directory fsync failure cannot prove crash durability.

New disjoint verifier pair:
- One fresh candidate-API actor, no app startup: existing signed-release `preflightVulnDbBundle()` and current policy, exact source-pinned dependencies/public trust anchor.
- UID/GID65532, net none, readonly root and release, cap-drop ALL, NNP, explicit no-healthcheck, memory/swap total2GiB, CPU1, PIDs64, tmpfs128MiB, actor90s within parent budget.
- Only readonly release data, no personal-store volumes/socket/private Env/provider/Trivy.
- Host and actor exact bounded layout enumeration; no-follow streaming hash/stability/permission checks; opaque private32-byte seal and at most three host-only rechecks; clock rollback/expiry/content or inode drift refuse.
- One-shot actor ownership guards, success-only non-force removal, failures retain attribution rather than discovery/adoption/retry.
- Security review accepted the final verifier source. It independently checked that production metadata hashing plus exact timestamp equality binds actual metadata UpdatedAt to signed identity, and current policy is used before/after hashing. This is SOURCE evidence only, not actual release authentication.

Qualification-only route `--qualify-release-only` is mutually exclusive with activation. It acquires coordination lock and performs bounded capture/model checks plus ONE isolated release verifier then returns. No compiled-private write, user DB/store/helper/holder, live-service stop/recreation, migration or provider continuation. Failure may leave private HOLD/actor material. Proposed envelope: shared150s / actor90s / caller180000ms.

**This route has NOT RUN.** Correctness prepared `docs/deployment/release-qualification-20261015.sh`, SHA256 `69654c4e41f93d70473bb3d5ca3d58e96b62d1056b81056affd15371282df091`, and paired `.md`. Correctness source/literal review accepted subject to test/process evidence and final security approval. Security has not yet approved this complete integrated qualification literal. User cleanup interrupted before that step. Do not execute merely because the file exists.

## Current public source pins

Paths relative to server/deploy/trust:

```
5661356c6a2d49fe67cab678b2b136daa7191c5127b6bb7da3d0b7e066c784b2  recreate_openrouter_key.py
5571d385394217304fe5184b841b21770da912f8b012e7e1e87f356564709264  test_recreate_openrouter_key.py
bb4b7a952527043c6aa7310178cc8618b8e6e97fbd696e29600a066a2332a513  diagnose_preservation_preflight.py
e388d83567c0be5595c991025c50e2bc35dec41b676dc5544daee0cfc68cac77  test_diagnose_preservation_preflight.py
13a0c971ae89c63ef97fee71bbc456c7e95c3be9781ba8c4a47580490444a2c6  verify_preservation_release.py
ee74c313b0522b899221a2ea825647ac02d700773320c9f91e4e755e30f9ac0f  test_verify_preservation_release.py
```

Other seven production source pins unchanged from prior handoff:

```
323ca629483f92896634ada79d2c8f098d9ff885464eb24ba9d86bb75e563dee  server/deploy/trust/sqlite_state_snapshot.mjs
f9668e4f288a712969bf50199f38464b3d854d28d3dc4d4e58647c9c7d59453e  server/deploy/trust/sqlite_state_snapshot.test.mjs
97283889749a4413d5e27f9b0ce828927f56b56ef507cb220a3c607fd3d23f5a  server/deploy/trust/stand_composition.py
da5c96aaa959e10b32868a458e9cc53e7a819596a33e9ac913f8f2966f552509  server/deploy/compose.stand.yaml
80ec2a655f661cfa5f51fcea0b99e216ae048b356a9c67e830e01d34bcdbe275  server/deploy/compose.stand.vuln.local.yaml
f6587a7a355ac1c51610d65f1851223a72b9e0e64e09f548c3e8faca0ab0e3a6  server/deploy/compose.stand.nginx.local.yaml
6dcb3afd60363998e98d3ac1629d25c5a166ba00455d1cc735c26d2d686fb326  server/deploy/compose.stand.openrouter.free.yaml
```

## Test evidence and limits

Authors ran selected inert tests only, with real subprocesses/signals blocked. Various increment suites passed cleanly as reported above in agent responses. Independent reviewers inspected assertions and source, not repeated native proof.

Final controller21-test run printed OK after3.202s but process later timed out at30s: **NOT clean process PASS; cause unknown**. One subsequent authorized small run of the four new HOLD-failure tests exited0 (4/4,0.063s), no non-main threads, guards closed. It does not rewrite/diagnose the earlier timeout. Final diagnostic7 selected tests clean PASS0.073s. Final verifier6 selected tests clean PASS0.046s plus AST checks. These are not native crypto/actor/deployment proof.

Coordinator ran `git diff --check` successfully, index diff empty; HEAD `741e4aaf4b6c41dd176ddfe6ff175781958f8f73`. Foreign notice files untouched. No commits/staging/branches. No private env/key/signing/recovery/DB contents read. Source/test/module pins in this section are author/reviewer measurements, not fresh runtime storage guarantees.

## Resume safely

1. Keep cleanup results separate from release/deployment acceptance. No cleanup retry or blanket retained-resource prune.
2. Read current public qualification literal and paired review; give security final integrated-source/literal review, including the narrow source exception, pinned loader, pre-stop verification, failure HOLD/uncertainty and explicit ONE actor ownership bounds. Supply honest clean four-test evidence; old21 timeout cause remains unknown.
3. Only after that review, run ONE qualification-only literal under exact supervision. Stop after either result; no automatic activation. Source/fixture approvals cannot replace actual actor qualification.
4. If qualification passes, assemble/review a fresh coupled production literal and perform existing coordinated WAL-safe ALL-table/ALL-column PRE/durable backups/additive migration/POST gates. Never resume old worker after ledger14. Recheck signed-release identity and actual freshness. No data preservation claim from unchanged image IDs or resource inventories.
5. Actual rollout and browser/owner/provider acceptance remain separate. No automatic provider call, history initialization/retry, host/runtime capture or scanner proof rerun. CVE historical UpdatedAt Oct7/usableUntil Oct21 is not a fresh current release measurement.

Reusable independent agents (none running an operation): controller author `397e00cd-0545-45cc-8de4-4d24304e1d3d` owns four controller/diagnostic files; verifier author `f5ed4627-3eec-447b-a014-d9100a47ec99` owns new verifier pair; correctness `0067f07f-cb85-4902-b040-830a5ddc2689` owns its command/review documents; security `d6280373-8069-451a-afea-5ebf24a13b0e` readonly. Preserve disjoint scopes and independent review.
