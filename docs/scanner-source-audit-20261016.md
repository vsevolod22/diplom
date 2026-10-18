# Scanner source audit and inert security regressions — 2026-10-16

## Disposition and authority

**Partial evidence gap closed; no task acceptance or R10 equivalence claimed.** This is an offline source/evidence audit and regression-test report, not a behavioral specification, approval, deployment instruction or applied exception to cancellation requirements.

User-authorized repository writes are only this NEW document and NEW tests under `server/api/src/worker`. Added `secrets-publication-boundary.test.ts`; production scanner/ledger code and historical evidence were read-only. MCP was not called or bypassed. No proof script was imported/executed, including its plan/self-test modes. No Docker/Engine, scanner executable, network/provider, private Env/keys/state, `.local-auth`, `.local-stand`, old holders/recovery operations, staging, commit or branch changes. Tests use synthetic strings, injected fake processes/runners and newly created temporary SQLite files, deleted by their fixtures. The test process had an explicitly empty inherited environment except PATH and disabled tsx cache. Public source hash checks did not read key files, even public trust-anchor bytes.

Inputs read: `docs/testing-followup-20261016.md`, `docs/deployment/rollout-evidence-update-20261010.md`, `docs/acceptance-final-20261015.md:65–71`, and `docs/TZ.md` image coverage, normalization, cancellation, confidentiality and acceptance scope. Tracker criteria/status/applied history remain unavailable; the historical testing queue is not a freshly queried queue.

## 1. What historical evidence was actually accessible

Search was bounded to public `docs/` and `server/deploy/proof/` filenames and the referenced public files. It did not search private directories or operator storage. Packet331 and the complete R10 per-path map/snapshot were **not located in these inspected public roots**. This does not assert that no other copy exists elsewhere. No Artifactory/network lookup was attempted.

### Independently hashed local bytes

| Public file | Bytes | SHA-256 measured here | Meaning |
|---|---:|---|---|
| `server/deploy/proof/cve14-combined-proof.py` | 134387 | `945404d04957c86523de0490b5a65f17787010f6733a9a7ead1f76dfcfb4adc0` | Matches the historical R10 runner identity recorded by the rollout addendum. Read/hash only, not execution. |
| `server/deploy/proof/cve-advisory-evidence.json` | 120414 | `60cabda3a67bcaf706b49b9cff786649ae8b338f1267b7762b41bca84f034567` | Matches the runner's `PROOFS` literal at lines91–94. **Earlier Stage2** packet, dated 2026-10-07 11:02:26–11:06:52 UTC, not packet331. Contains 85 `sourceHashes` entries. |
| `server/deploy/proof/nginx-local-evidence.json` | 4384 | `cd14137e36a853f6870060f88dca96416fcb8f8071f4a8b01a35d23c1134fcb9` | Also matches `PROOFS`; earlier LOCAL evidence, testedAtUtc 2026-10-07T07:18:24.671310+00:00, with 16 `testedSourceSha256` entries. Not R10. |
| `docs/deployment/public-source-observation-20261009.json` | 3711 | `6469aad7c5c595ad00ee42ffd62423fc53783699438d1df9f97b05216c403d50` | Explicitly non-atomic, incomplete, non-release-freeze observation at 2026-10-09T11:48:10.051078+00:00; predates the final R10 runner. |
| `docs/task16-r5-backend-source.json.gz` | 26677 | `d07ddcefec7e3d7bc4eea8132193b05f80a694aab4e6035488b19ea9f9b8e72f` | Public five-file TASK16 snapshot, not a TASK40/R10 source closure. |
| Same TASK16 snapshot, expanded in memory only | 129315 | `64120448d10ffa29126480aa1c9d4521240f55c07d942477a0624365fe87783e` | All five embedded content lengths/hashes verified internally. Four match current source; `llm/tests/history-delivery.test.ts` differs. This cannot fill the missing scanner map. |

Matching a file to a hash literal in another local file establishes byte consistency, **not an independent execution attestation or reviewer authenticity**. The embedded Stage1/Stage2 per-source hashes are historical assertions; the historical source bytes themselves were not recovered from those hash-only maps. Current file hashes were recomputed from regular, non-symlink public paths.

### R10 assertions retained, not independently verified here

The rollout addendum lines7–12 records packet **DIP-ARTF-331**, reviews **330/332**, 210 CVE / 72 SBOM / **0 Secrets**, owner-cookie/native OWN nginx HTTP↔SQL agreement and same-ledger API recreation. It records cleanup0/0/0, wholeAcceptance=false/liveTouched=false, one-run authority329 spent. These remain attributed historical evidence, not fresh observations.

Unavailable here for direct verification:

- Packet331 gzip: 4737 bytes, recorded SHA-256 `3134e1232557a6bda68a3bce3c8348533dfb487c22f6d8c8d0de029acce4b044`.
- Expanded331: 15870 bytes, recorded SHA-256 `c120ea5e89559c8edf56f4aa8800de7df9e62b2552ef76b7fc0141eb1cf9ed49`.
- Recorded payload seal `b30a57b3a2e0c38aa9c8f4840c782e9e7fb742048b3f7a75388f176e1b69519c`.
- Complete 244-public-input R10 map `e4efad5ff9ef56040e1d341311599d8bb19da874af94b5bf1eaffa97b7ed6334` and its 238-file embedded selection; exact reviewed old bytes for changed files.
- Full independent reviews330/332 and their scope/limitations, beyond the local addendum's summary.

The later 247-file `e157f25a7e7b767e9b1e50a4149cbcc461a46797cc033ff86f513feeae83662b` inventory and history-specific five-file freeze are different times/scopes, **not replacements for e4efad**. No fresh whole-source R10 map was generated, reconstructed by inserting asserted hashes, or repinned. The runner's inventory includes tests and multiple source trees (`cve14-combined-proof.py:87–104,210–238`); the new test also changes such a future inventory. Hashing only scanner production files would not reproduce its closure.

Historical DB UpdatedAt/usableUntil, overdue warnings, image digests and memory peak remain exactly the addendum's assertions. The 1GiB peak at the ceiling is not headroom. Zero secret findings are not positive-secret detection. No DB date freshening, image inspection, capacity conclusion or new execution authority follows from this audit.

## 2. Verified current drift against accessible older maps — NOT R10 drift attribution

### Earlier Stage2 map: exact 85-path comparison

Every one of its 85 recorded paths exists: **55 same hashes, 30 different, 0 missing**. Canonical map hashing used UTF-8 `json.dumps(map, sort_keys=True, separators=(',', ':'), ensure_ascii=False)`:

- Recorded Stage2 85-entry map: `e68b5f550456b99278af20f75b1813883bc3bb6d8e9d52f505422292e4c8d9b5`.
- Current hashes of **those same 85 paths only**: `13a700655992e6d9b816e24ac06e630ec559125d5897009ec8742d8fb2a22662`.

Neither is e4efad, a complete current repository inventory, an execution freeze or a semantic-equivalence verdict. Current additions outside those paths are excluded. Reads were sequential, not a globally atomic checkout snapshot.

Relevant changed source identities (paths relative to `server/api/src/`; old hash is the Stage2 packet assertion, current hash is measured):

| Path | Stage2 recorded SHA-256 | Current SHA-256 |
|---|---|---|
| `ledger/ledger.ts` | `9b0b3cce477da38aa91aeba2946a9b1ab334615f9b3f3a5d8273a45b36c14626` | `d2b6993b0de701a543315dfddd542c51cee3fbc6b18bb982eb972f0f3c5f33d4` |
| `ledger/schema.ts` | `9c3d13432ae04d6c3693ca46f774823f9acafad5ba04ba3321062d087d72e0bf` | `ce70c6b9c3291ec87c09e5b1a6c687ede57768f1b8452468c554f43986efcddd` |
| `worker/outbox-consumer.ts` | `98a1a46a02daad0df0a4234330efff12c57a584ea076392b4cf3be0e10dbcb51` | `85294e11118ba945b63851d1bf5cec2816e5bf4802106636f24f19d0c3c63df0` |
| `worker/archive-result-contract.ts` | `7f27a684a8c699c7d4acd30bf21930e4165bec3947c4acded9aaa85e643521a9` | `2938068d62a13f7d16aab7bbea912faceb4ceffa21ec3e099b6c5b05e6ec6e16` |
| `worker/archive-scan-worker.ts` | `4967c0468cd8f60403e6211787d2712a56779e7ab4a1c718f2d0c38a793f4fb8` | `ad1306f9bd3491c4b5b3df3ac12a408e89dfb1ffb953a5aba9ce1a1007a17b90` |
| `worker/vuln-db-bundle.ts` | `405e7929635c00096f7edac7ce6306d1fb4071ebc0e0e4ebf95d362e4fb2b981` | `fc5501614adf7f421b1e06e7e25a61976141ffb1466917c7e1ee41fa36338f67` |
| `worker/vuln-worker.ts` | `ca0d08e90622335ad12dac536e738545f98d22ab59bbd0308cb9feb85408c670` | `d056b9752267a7c381260dd5a455ba3133c68d68f259a1e9abab1970058e0812` |
| `worker/worker-runtime.ts` | `79b5c7e9659a98203faef37b41a773746f202583ca0cb1ea0e2abfe508c8f61e` | `0acb4819a0bb6a4747271c62ce8902c5aec9d7511f2646df760eb27626490900` |
| `oci/archive-qualification.ts` | `9cb403f3be3ef023eed48c7492792895b303876df70d29ed8a1311d9e173a102` | `c5702453fd1583402e1c1b0b513813a7bff8225915e81f313c1a1a3bef865343` |
| `oci/layer-tar-validator.ts` | `9b0aa363dcc1befcbf7a346fe985c664fd5f1226df15af2c0f8165fb62e2e886` | `4c7fe95da18edfd2d1d7081de0a69fcf97a00494e478a494c25e585ef3954170` |
| `oci/nginx-local-profile.ts` | `186858f50343a595329cb962a54b7e78a558333be23bee4e3d72cface237062c` | `9e5df347cda518c5045953093c165433e1ce2c1e6892ee24e5be6bfa07925cb7` |
| `oci/nginx-local.module.ts` | `48ad0e2c4bf308be683c82652d2170cd40dee8be5a7efcfa30bb09c16fcc01f6` | `3ee635dafddd05b46039a2244ed3763dfcdd91072328906dfc6ab4a865604728` |

Other changed entries, completing the 30-path set: `app.module.ts`, `auth/auth.controller.ts`, `auth/auth.store.ts`, `main.ts`, `oci/nginx-local.main.ts`, `scans/browser-scans.controller.ts`, `scans/scans.controller.ts`, `scans/scans.module.ts`, `scans/scans.service.ts`, `worker/nginx-local-worker.main.ts`, `worker/verify-vuln-db-release.ts`, `worker/vuln-advisory.ts`, `worker/vuln-findings.ts`; plus root-relative `server/deploy/proof/cve-advisory-browser.mjs`, `src/pages/scans/ScanCreatePage.tsx`, `src/pages/scans/ScanDetailPage.tsx`, `src/pages/scans/VulnAdvisoryCard.tsx`, `src/shared/api/scans/scanTransport.ts`.

Useful unchanged byte anchors against Stage2:

| Root-relative path | Recorded and measured SHA-256 |
|---|---|
| `server/api/src/worker/scan-worker.ts` | `7c4ee653061cccd59cc763ec826e0bb1579ff167d4630f981c5f92cb54a5fea9` |
| `server/api/src/worker/secret-findings.ts` | `260db40620b9eb498fc12c31eb281118030e1cc6492f5452192442d60e9767d9` |
| `server/api/src/worker/scanner-errors.ts` | `2e64385e73cf7100a985e0d028a6f8e468bfd973ab04b072317c0d437b5744d5` |
| `server/api/src/worker/archive-process.ts` | `ab3de1a564cb6f4ab90dea421ed8f212cdcb0a98ef7c52859698730c428ab0f1` |
| `server/api/src/worker/image-config-runner.ts` | `e667c4fcb1bcb2c272b3731310f68dcfa54d6f03d86c9efa7e0ddd497096af5f` |

Current non-test TS/MJS/MTS files in the worker directory absent from the Stage2 map are `cve-db-evidence.ts`, `cve-db-policy.d.mts`, `cve-db-policy.mjs`, `vuln-db-trust.ts`. Absence means **not covered by that older map**, not proven new since R10. Relevant current identities:

- `cve-db-policy.mjs`: `685829a0c33509dbf115bd8cd60489ee72358f8181c44649448baa6408088207`.
- `cve-db-evidence.ts`: `7a47feea80c0c4a9db8cbe3cde94f93546eed9123ff687625067553274191967`.
- `vuln-db-trust.ts`: `792837b8bc360a8ed20188f06f1e3c08c6e4603f6bf6142d583f5182b0116ae9`.

Current source inspection, not an inferred old→new semantic diff: `cve-db-policy.mjs:33–51` separates legacy freshness from nanosecond UpdatedAt+14d usability with overdue warnings; `archive-scan-worker.ts:105–157` parses independent checks, validates DB identity before/after CVE, and attaches policy evidence; `outbox-consumer.ts:89–118` and `ledger.ts:745–845` recheck policy/publication at finalization. Old source bytes are needed to decide which of these behaviors changed **after R10**, rather than before it.

### Other public observations

- Earlier LOCAL 16-path map: **4 same / 12 changed / 0 missing**. Again not the R10 map.
- Selected scanner/deployment subset of the October9 public observation: **7 same / 6 changed** across 13 paths. Same: `scripts/stand-auth.mjs`, the three `compose.stand{,.vuln.local,.nginx.local}.yaml` files, `server/api/src/main.ts`, `app.module.ts`, `oci/nginx-local.main.ts`. Changed: `.gitignore`, `.dockerignore`, `server/deploy/api.Dockerfile`, `server/deploy/stand.nginx.conf`, `server/api/src/oci/nginx-local.module.ts`, and the proof runner itself. The remaining observation entries were not used for this comparison.
- Current nginx config SHA-256 `52a2aef79bafa3da69fcc2e6a6b86867d4f9fb662003791a5531394a8a35344a` matches the retained R10 runner's `INGRESS_CONFIG_SHA` literal at line57, although it differs from the earlier October9 observation. This is a concrete example of why drift against an older map must **not** be labeled post-R10 drift.

## 3. Coverage gap and new tests

Existing tests already cover `secret-findings.test.ts` parser-only canaries, adapter abort/stuck-pipe/byte limits in `scan-worker.cancel.test.ts`, normalized findings/count storage in `outbox-result.test.ts`, and empty-success cancellation/attempt replacement in `outbox-cancel.test.ts` and `outbox-combined.test.ts`. They did not combine positive untrusted Secrets output with adapter parsing, durable publication/reopen and cancellation after a positive result, nor demonstrate a positive runner resolving strictly after the consumer has returned from cancellation.

New file: `server/api/src/worker/secrets-publication-boundary.test.ts` (12109 bytes; SHA-256 `1e81cf25f00fba8bdedf9b448bd76ae5b4a0cf1033c2a086aad2481ab486938b`). Six regression cases:

1. Two synthetic positive findings pass through actual `scanPinned` → parser → `consumeOne` → SQLite → close/reopen. Exact safe IDs, hashed rule, numeric/null line and evidence refs survive; raw Match/Title/path/Code/metadata strings and raw RuleID do not. Owner reads succeed and foreign dataset/findings/events reads refuse.
2. Truncated positive JSON cannot publish a prefix or checked coverage; only the existing safe failure projection persists.
3. Nonzero exit with otherwise valid positive JSON cannot publish findings; failure persists across reopen.
4. Cancel after complete positive stdout but before close: fake SIGKILL/stopWorker observed, consumer returns without close, eventual close0 still fails, and cancellation/results/events remain unchanged after reopen.
5. Runner ignores abort and resolves positively **only after** the consumer returns: no late publication, direct old-attempt `finishCombined` also refuses, repeat cancel is idempotent, one terminal event remains.
6. Positive Secrets complete, SBOM is still pending, then cancel wins: the completed in-memory Secrets are not published, configured fake CVE never starts, late SBOM settlement cannot create sibling/config results, and reopen preserves cancellation.

Leak checks inspect all tables (including audit/events) and the main/WAL/SHM bytes **of the fixture's own temporary SQLite only**. They are not universal logging, filesystem-forensics, retention, HTTP/UI/LLM sink or real scanner-detection qualification. No positive native Trivy detection was exercised. These new tests use the ordinary Alpine consumer path, not an executed nginx archive proof. The shared parser is used by the archive path too, but that does not transfer acceptance to it.

### Commands and observed results

Working directory `server/api`, Node **v23.11.0**, existing installed dependencies; no install or download. Shell runtime bound30s for tests and60s for typecheck. New tests each have a5s bound; fake processes do not invoke subprocesses.

```sh
env -i PATH=/Users/vsevolod/.nvm/versions/node/v23.11.0/bin:/usr/bin:/bin TSX_DISABLE_CACHE=1 node --import tsx --test src/worker/secrets-publication-boundary.test.ts src/worker/secret-findings.test.ts src/worker/scan-worker.cancel.test.ts src/worker/outbox-cancel.test.ts src/worker/outbox-combined.test.ts src/worker/outbox-result.test.ts
```

**20 PASS / 0 FAIL / 0 skipped / 0 cancelled**, duration3445.00075ms, including all six new cases and14 existing tests. This is a focused subset, not the full API suite. The existing stuck-pipe regression intentionally waits about3.2s with an injected process.

```sh
env -i PATH=/Users/vsevolod/.nvm/versions/node/v23.11.0/bin:/usr/bin:/bin node node_modules/typescript/bin/tsc --noEmit --incremental false
```

**PASS**, exit0. No generated build output. Node23 local validation does not establish production Node22/24/native-addon compatibility.

Disclosed intermediate failure: the first six-test run was **2 PASS / 4 FAIL** because the new fixture incorrectly expected `ledger.pending()` to be numeric0 rather than an empty array. Verified `ledger.ts:476–479`, corrected only the new assertions, then ran the successful20-test command above. This was not a discovered production defect or a production fix. No production changes were made to make tests pass.

## 4. Cancellation decision — recommended safe direction, NOT a contract change

The conflict remains real: `docs/TZ.md:105–110` requests preservation of incomplete results, while `server/api/src/ledger/README.md:9,11` documents no in-memory intermediate publication. Passing the new tests characterizes the latter; it cannot satisfy or waive the former.

Actual current linearization points:

- `outbox-consumer.ts:76,121–156` accumulates normalized outcomes in memory; it polls attempt authority before stages and before the single final write. Abort is raced against each runner. No durable per-check checkpoint is written there.
- `scan-worker.ts:54–87` kills/stops on cancellation and rejects even a successful close after cancellation. Publishing a JSON prefix before validated close would bypass this safety boundary.
- `ledger.ts:503–516` cancels in one transaction: owner/state update, delivered outbox + cleared lease, one cancelled event. There is no partial-result snapshot operation in that transaction.
- `ledger.ts:527–535,745–845` validates running/current attempt, non-null lease when using config context, exact outcomes/config, then commits results/config/outbox/state/event atomically. `retry():1061–1066` clears the lease without incrementing the attempt, so attempt number alone is insufficient for a future checkpoint design. Current context checks non-null lease, **not wall-clock lease expiry**.
- `archive-scan-worker.ts:92–159` similarly holds its report in memory; final abort invalidates check outcomes, while independent CVE failure can leave other checks for a normal partial finalization. That is distinct from cancellation preservation.

**Recommendation to the product/spec owner, with scanner/ledger and security owners reviewing:** choose an explicit split-scope disposition now (optionC from the acceptance report): retain the current atomically published slice for its supported behavior, keep the original partial-cancel preservation criterion OPEN, and plan durable per-check checkpoints if the original requirement is retained. Do not implement UI-only preservation, publish raw stdout, or reinterpret `checked`/empty cancelled reports as fulfillment. No named assignee is invented; the parent must identify the responsible humans.

Concrete proposed checkpoint design for that separate decision:

1. Persist only a fully completed, bounded, validated and sanitized per-check outcome after process close/identity checks; never partial JSON, raw Match/path/Code/stderr or an in-memory promise result. Preserve pinned digest/platform, exact requested-check identity, scanner/checks versions and relevant DB/receipt evidence.
2. Key each checkpoint by scan + attempt + check + immutable evidence identity; owner is derived from the ledger, never supplied by a runner. Each checkpoint write rechecks running state, current attempt, undelivered outbox and non-revoked lease under a short transaction. Specify expiry semantics explicitly rather than assuming the current non-null test is a clock check. Reject stale attempts, retry-revoked leases, mismatched targets and already-terminal scans. Do no network/hash acquisition inside transactions.
3. Cancellation and final completion must compete at **one SQLite transaction boundary**. Cancel revokes publication authority, selects only already committed checkpoints of the winning attempt, validates their evidence, writes a final immutable snapshot, acknowledges outbox and emits exactly one terminal event. If a checkpoint transaction wins first, it is eligible; if cancel wins, the late checkpoint is refused. Old attempts never join a new attempt's report.
4. Owner must choose the visible semantics: `cancelled` with preserved findings versus `partial` with an explicit cancellation reason, and the outcome/reason for checks not started/interrupted. Define how DB expiry affects a preserved historical checkpoint without refreshing its dates or claiming current freshness. Do not silently add a new coverage state, reuse an unrelated failure reason, or change existing completed reports. Result readers, pagination/report-version binding, SSE/snapshot and UI copy must agree on that choice.
5. Require synthetic tests for checkpoint-before/after-cancel, cancel-vs-finalize, lease revocation/replacement, crash/reopen before/after checkpoint and cancel, DB expiry, ownership, exact redaction through all intended sinks, sibling atomicity and retention of checkpoint rows. Migrations/compatibility need a separate approved plan; no existing store is touched here.

If the owner instead explicitly narrows the product contract to atomic-only publication (optionA), reconcile current applied history and approve a task-sourced spec/ТЗ change before claiming acceptance. A no-spec-impact declaration or this audit is not a substitute. This recommendation does not itself select/approve either new behavior.

## 5. Exact remaining unblocking actions for the parent

| Gate | Next required action | What this audit closes / leaves open |
|---|---|---|
| TASK40 evidence availability | Obtain an explicitly PUBLIC sanitized export of packet331, full reviews330/332 and the original R10 244-path source map +238-file embedded-selection description, ideally exact historical bytes for changed paths. Use an owner-provided export now or restored MCP later; do not bypass the unavailable server or inspect private proof scratch. | Existing public predecessor files/runner hashes verified; original full R10 evidence still unavailable. |
| TASK40 historical integrity | On those exported bytes, independently verify recorded compressed/expanded hashes and payload canonical seal. Runner `canonical():150–152` and packet construction `1852–1854` define the payload hash. A valid content seal still is not an execution signature. Verify the original map hashes to e4efad with its exact serialization and scope. | No rerun, repin, substitution of e157 or current85 hash, date freshening, proof build or historical edit is needed/authorized. |
| TASK40 current applicability | Compare every original map entry to current bytes; separately enumerate current added/removed inputs and production versus test-only drift. Review actual changed historical/current source, bind each changed boundary to targeted evidence and review330/332 exclusions. Retrieve current task AC/applied delta when MCP returns. | Earlier-map drift is concrete but cannot locate changes temporally relative to R10. An unchanged runner/config alone is insufficient to close TASK40. |
| Positive Secrets | Parent/reviewer can accept these six cases for the **synthetic adapter/storage/cancel boundary only**. If AC requires actual scanner detection, request a separately authorized new disposable positive-canary qualification with pinned fixture/scanner and bounded sink/redaction checks. | The new tests close the identified regression gap, not real Trivy detection, whole TASK2, network isolation or all-sink/retention coverage. Do not rerun R10 to get a positive result. |
| Partial cancellation | Product/spec owner explicitly chooses narrowed atomic-only scope or retained partial-preservation requirement; scanner/ledger + security owners review the design above. Reconcile applied spec history, then approval/planning in the normal workflow. | Current integrity/fencing behavior tested; original partial-preservation criterion remains unresolved. No acceptance invented. |
| Tracker completion | Once available, reread policy, current nodes/AC/comments/components/deltas and record criterion-by-criterion PASS/FAIL/BLOCKED with these bounded results. Close only a genuinely accepted slice through the required human process. | No status, progress, delta or parent closure performed here. Parent owns synthesis of existing followup docs. |

Historical history STOP and all ungranted operational boundaries remain intact. None of the unblocking actions authorizes a historical proof retry, private-state inspection or deployment.
