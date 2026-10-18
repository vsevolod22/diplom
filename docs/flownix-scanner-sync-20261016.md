# DIP-TASK-40 — official MCP reconciliation, 2026-10-16

## Disposition

**Leave DIP-TASK-40 in testing / 90.** No demonstrated new CVE implementation defect was found in the inspected policy seams. Historical R10 is accepted narrow LOCAL evidence, not a missing/failed proof. However, the requested independent packet-byte verification and full original-map/current-source reconciliation remain incomplete because the available binary transfer interfaces did not yield lossless bytes without placing a signed capability URL in a shell command. Current source is not certified equivalent to the historical execution snapshot.

This is an evidence handoff, not a spec change, execution authorization, replacement proof or widened acceptance criterion. No parent or doc-node mutation, production edit, historical edit, proof import/run/self-test, Docker/Engine/lifecycle operation, private-state/key/environment read, stage, commit or branch operation occurred.

## Fresh tracker facts

Official MCP reads, not inferred from old local reconciliation:

- Project `520a0059-d0f2-4f86-8d93-fc15035a5715`: full / strict / approval=false / spec_first=false / direct / parallel.
- DIP-TASK-40 ID `e02d0617-04fc-4a94-a564-8e7abb74d17c`: testing, progress90. Full content and all returned comments read.
- Parent DIP-PLAN-1 `f035bae2-7357-4b28-a542-6ac6fc0fca39` and feature DIP-FEAT-1 `b2039c7d-0c93-45a0-b2de-a619bd7fb2ae` read, untouched.
- Existing component DIP-COMP-3 `f3afb799-0bf2-47b0-a1f8-7bf0fcd68490` is the correct server binding. Its descriptive text is stale (still says implementation absent); not changed under this authority.
- Full DIP-DOC-12 `678e3835-c5c7-44fa-a4a7-1b6139653ca0`, version2, read.
- Task40-sourced delta **`2a437ff0-ab33-46a7-8a9a-acc40e4e5467` is applied**, applied_at `2026-10-15 17:26:16.454111+00`, approved. Earlier comments saying UNAPPLIED are historical, not the current gate. No new delta/no-impact waiver is needed or proposed by this review. The doc retains target-stage wording; application alone is not acceptance.

## Original evidence recovered through MCP

Read complete official artifact text: DIP-ARTF-330, 332, 328, 186, 196, 197, 200. These are artifact reports, not `get_review` review IDs.

- **331**: `28397a2e-6d43-45c2-b142-ea33e776d394`, version1, `proof/cve14/actual/cve14-r10-sanitized-evidence-actual.json.gz`, explicitly sanitized/public packet, 4737 bytes in metadata.
- **330** accepts exact R10 isolated LOCAL CVE/SBOM execution and owner HTTP/SQL persistence, not whole acceptance. It independently checked original packet hash and canonical payload seal historically; its source-at-execution match relies on preceding source review.
- **332**: `d9b0cb33-8362-431e-a58d-80284e4760f6`, version1. Accepts one bounded R10 actual packet, preserves wholeAcceptance=false/liveTouched=false and SPENT329 authority. It historically checked all244 public hashes/238 embedded selection and packet consistency; this is not a current-tree certificate.
- **326**: `81247aa4-7096-4879-9583-dc20e256cff4`, version1, `proof/cve14/cve14-r10-memory-gate-candidate.json.gz`, 96535 bytes. **The original R10 full244-path map is available in this artifact**, alongside complete controller/test candidates, plan and diffs. Not missing from Flownix.
- **299**: `a7f4ad6e-591f-498d-93a7-f359605f45fa`, version1, public R7 bundle; metadata identifies the same244-map seal `e4efad…`. It is an alternate map source, not the R10 controller version.

### Lossless-transfer limitation

`artifact_download_url(331, version=1)` returned the official short-lived S3 URL. `fetch` reached that URL but returned gzip as text with replacement characters, not a byte-preserving download. Those characters were **not saved, reconstructed, hashed or treated as JSON**. `artifact_read_text(326)` explicitly refused `application/gzip` and directed use of the download URL. The URL contains temporary signing credentials/capability parameters; it was not copied to a shell command, source file or evidence log. No unofficial endpoint or MCP bypass was used.

Consequently the following packet/map values are **server metadata and independently reviewed historical assertions, NOT hashes recomputed from original bytes in this session**:

| Object | Size / SHA256 assertion |
|---|---|
|331 gzip|4737; `3134e1232557a6bda68a3bce3c8348533dfb487c22f6d8c8d0de029acce4b044`|
|331 expanded JSON|15870; `c120ea5e89559c8edf56f4aa8800de7df9e62b2552ef76b7fc0141eb1cf9ed49`|
|331 canonical payload|`b30a57b3a2e0c38aa9c8f4840c782e9e7fb742048b3f7a75388f176e1b69519c`|
|326 gzip|96535; `ca7cdae62d78cff6073b29bf24086857654c2f92598d096dc4401fb859712201`|
|326 expanded JSON, review328|`36ac67374275badb6762ec3207cf92e76f7ccd8aad95f8757f78a485670eb7ed`|
|Historical244-map|`e4efad5ff9ef56040e1d341311599d8bb19da874af94b5bf1eaffa97b7ed6334`|

A content hash is not an execution signature. No absent private release, scanner stdout, SQL or image bytes were independently authenticated here.

## What was independently hashed now

Two stable reads of the current public inventory were performed with an independent reader, **without importing/executing the proof controller**. Paths were reproduced from its explicit inputs/source trees/suffix selection at `server/deploy/proof/cve14-combined-proof.py:87–104,210–238`. Reads reject symlinks/nonregular files, hidden path components, oversized files and changing fd metadata. Inventory was bounded to2048 files/32MiB; individual files to4MiB.

Current selection: **258 files**, canonical map SHA256 **`5612b4d735d19d43bca6d0c515695575cdce99023585b48cb07d33eb0f295bdb`**, observed `2026-10-16T14:36:34.118889+00:00`; both reads identical. This is a fresh observation, **not a repin**, R10 plan, source-closure/import qualification or execution certificate. Without the decoded original map, 258 vs244 does **not** establish exactly14 added files or identify changed/removed original paths. The later247-map and earlier85-map remain different scopes and are not substituted.

| Current public file | Bytes | Independently computed SHA256 |
|---|---:|---|
|`server/deploy/proof/cve14-combined-proof.py`|134387|`945404d04957c86523de0490b5a65f17787010f6733a9a7ead1f76dfcfb4adc0`|
|`server/deploy/proof/cve-advisory-evidence.json`|120414|`60cabda3a67bcaf706b49b9cff786649ae8b338f1267b7762b41bca84f034567`|
|`server/deploy/proof/nginx-local-evidence.json`|4384|`cd14137e36a853f6870060f88dca96416fcb8f8071f4a8b01a35d23c1134fcb9`|
|`server/deploy/stand.nginx.conf`|13541|`52a2aef79bafa3da69fcc2e6a6b86867d4f9fb662003791a5531394a8a35344a`|

These match the historical reported anchors. Unchanged controller/config is not unchanged application source.

### Complete34-file implementation-manifest comparison

The complete34-entry public manifest was transcribed from freshly read DIP-ARTF-186. It is the snapshot reviewed by all three implementation reviewers196/197/200, **not the R10 execution map**. Results at `2026-10-16T14:35:32.199893+00:00`: **29 same /5 changed /0 missing**.

| Changed path | Current SHA256 |
|---|---|
|`server/api/src/ledger/ledger.ts`|`d2b6993b0de701a543315dfddd542c51cee3fbc6b18bb982eb972f0f3c5f33d4`|
|`server/api/src/scans/scans.service.ts`|`096f6ea58e1777b30c04008fb3e7896df1ff34b58bc7df9b0e13ad4796ad81c9`|
|`server/api/src/scans/scans.vuln.http.test.ts`|`55714474f16b87eb1bf034dec20d6e58118afc7dd38543505e2f56b808226390`|
|`server/api/src/worker/archive-scan-worker.test.ts`|`4bbb3a1cc340eb59ecf5a267f65d47bad8e3da4cb5e33a6a3f18e3f7a60f888b`|
|`server/api/src/worker/vuln-worker.test.ts`|`67186bc60b24cc130f9775155a4908857f4d79164984f251bde0e81b64e576d2`|

Two production files and three tests differ. Policy evaluator/declarations/test, evidence helper, bundle verifier/test, archive contract/worker, standalone worker, outbox consumer, schema, ledger policy regression, signer, release-verifier entrypoint and historical refresh implementation/tests all match186. Exact original/current hashes for every row are in the new comparison JSON. These are comparisons against hashes published in186, not a reconstruction of historical source preimages.

Current service/ledger inspection finds request-local authenticated identity and post-async real-clock checks (`scans.service.ts:25–28,74–85,122–135,193–200`), current-attempt fenced final evaluation (`ledger.ts:670–690,755–778`), durable anti-downgrade/evidence join (`:905–949`) and closed metadata projection (`scans.service.ts:340–355`) still present. Report-dataset/paging structure is visibly different from historical review descriptions; full original/current diff is not proven from descriptions alone.

## Criterion-by-criterion review

| Actual TASK40 criterion | Disposition and evidence |
|---|---|
|Unified policy for admission, worker per-job preflight, release verifier/refresh and historical readers; exact14days from data date, no download rejuvenation|**PASS for inspected core policy/seams; full current-source reconciliation incomplete.** `cve-db-policy.mjs:33–74` retains exact integer-ns v2 and frozen legacy; current API identity/post-async checks above, bundle post-hash `vuln-db-bundle.ts:146–155`, evidence finalization `cve-db-evidence.ts:29–42`, verifier `verify-vuln-db-release.ts:14–24`, Python delegation `cve_db_policy.py:12–22`/`evaluate-db-metadata.mjs:3–15`. Relevant implementation anchors match186; ledger/service do not. Historical readers validate saved clocks, not today.|
|stale-but-usable ≤14days with honest warnings; >14days/unknown/bad signature,digest,schema,source refuses, never checked0|**PASS for inspected source and bounded test evidence.** Exact-ns evaluator and four newly run pure tests pass; Ed25519/canonical/metadata/artifact/DB/time checks at `vuln-db-bundle.ts:97–159` unchanged from186. Fenced age crossing fails only CVE (`ledger.ts:684–690,773–778`); policy tests cover publication equality, age±1ns/+1ms, no rejuvenation, future+1ns, calendar/order and receipt corruption. Historical signed-fixture negatives196/197/200 and current parentAPI645 are attributed, not reexecuted here. No authentic release was read.|
|Isolated positive LOCAL combined CVE/SBOM proof and targeted boundary/tamper/future negatives; LIVE/quotas/users parent-owned|**Historical positive PASS per complete330/332; independent byte/drift bridge BLOCKED.** Reviews accept exact331 with210 CVE/72 SBOM/0 Secrets and owner HTTP→SQL/reload/API recreation. Original packet bytes/full244-map could not be losslessly decoded with the permitted tool route. Current LOCAL zero-CVE scans/API645 cannot replace or repin R10. No LIVE-preservation requirement is invented for this reviewer.|
|Narrow task-sourced full OpenSpec delta and three independent reviews; do not close broad TASK2|**PASS for existence/scope:** applied2a437ff0→DOC12v2; full196 spec,197 security,200 correctness approve the34-file186 implementation, with acceptance exclusions. **Not a blanket approval of later drift.** Current5 changed files/full244-map bridge must be dispositioned before extending those source approvals. TASK2/parents untouched.|

No AC has been edited or waived. Positive native Secrets, Node/npm inventory, provider/history/runtime-host/LIVE, full browser/DOM deployment, exhaustive scanner-output reproduction and disaster recovery remain outside this narrow task's R10 proof. Do not turn every broad product gate into a TASK40 gate; equally, do not turn an old source approval into current-source acceptance.

### Historical R10 limits retained

According to330/332, actual execution was2026-10-10T13:01:01.995094Z–13:02:15.280491Z. API image `sha256:c09ce4c8e6185784fad2c263b462952092fa89058d16363ebd543e0cd4bbd50d`; UpdatedAt `2026-10-07T07:38:55.515026687Z`; inclusive usableUntil `2026-10-21T07:38:55.515026687Z`. Saved worker/policy clocks differ41ms, both inside the run; both stale warnings are expected. These are historical reviewed receipts, not freshly measured runtime facts. Worker peak1GiB exactly at cap, memory.events.max10524, OOM0: no headroom claim. Reported cleanup0/0/0 is historical OWN scope only. `wholeAcceptance=false`, `liveTouched=false`, SPENT329 and old history STOP remain unchanged.

## Validation this session

Only:

```sh
# cwd: server/api
env -i PATH=/Users/vsevolod/.nvm/versions/node/v23.11.0/bin:/usr/bin:/bin TSX_DISABLE_CACHE=1 node --import tsx --test src/worker/cve-db-policy.test.ts
```

**4/4 PASS**,0fail/skip,116.053084ms. Pure synthetic temporal tests; no SQLite, network, scanner, signing or private reads. Hash/inventory verification described above also passed. No broad suite/build/typecheck rerun. Current **API645/645**, host191, UI554 and report integration121pages are the coordinator's evidence in `docs/testing-followup-20261016.md:68–78`, not this session's executions. Earlier six positive synthetic Secrets/cancel regressions remain synthetic and are not R10/native positive detection.

## Separate cancellation design recommendation — no contract change

Actual `docs/TZ.md:105–110` requires preserving incomplete results. Current `outbox-consumer.ts:76,121–156` accumulates completed child outcomes only in memory until one final publication; abort returns without publishing them. `ledger.ts:503–515` atomically marks cancel/delivers the outbox; attempt checks at519–535 and final commits at670–700/745–845 prevent late replacement. Retry after terminal is fenced at1061–1066. CVE expiry preserving sibling outcomes is not whole-job cancellation preserving partial results.

**Recommended owner decision:** retain the safety of atomic publication now, explicitly keep the broader partial-cancel criterion open, and commission a separately reviewed durable-checkpoint design if the TZ requirement is retained. Product/spec owner chooses semantics; scanner/ledger owner owns implementation; security/correctness reviewers qualify it. Only independently completed, parsed, sanitized and size-bounded per-check results may become durable checkpoints, keyed by owner+scan+attempt+check and bound to immutable target/scanner/policy evidence. A cancel transaction should select only current authorized checkpoints and atomically publish the terminal cancelled/partial snapshot with outbox/event changes. No raw/incomplete stdout; fence cancel-vs-complete/reclaim/revoke/lease races, preserve historical CVE times, reject late writes and mismatched attempts, and test restart/redaction/retention/owner isolation. Do not simply flush the existing in-memory array on abort. If the owner instead chooses atomic-only cancellation, that requires explicit reviewed spec/TZ change, not a no-impact waiver. Neither option is enacted here, and this separate conflict is **not used as the TASK40 blocker**.

## Exact unblocking actions

1. **Evidence owner/tool operator:** use the official Flownix download UI or a binary-to-file tool that keeps signed capability URLs out of shell/logs to place immutable public version1 **331** and **326** under `test-results/scanner-sync-20261016/`. Alternatively expose lossless base64/text through an authorized official artifact interface. Do not send private scratch siblings, release bytes/keys/state or credentials.326 contains the map;299 is a fallback for the same map only. No proof execution is needed.
2. **Offline reviewer:** bound compressed bytes (331=4737,326=96535), verify gzip seals, bound expansion (331 exact15870;326 conservative cap such as4MiB), reject trailing/multiple gzip members and duplicate/nonfinite JSON; verify expanded seals above. Recompute331 payload canonical seal and326's exact244-entry map seal using the controller's JSON canonical convention (sort_keys, compact separators, ensure_ascii=false, allow_nan=false). Parse only; do not import candidate code or run its plan.
3. Compare that exact original244-map against current paths, enumerate same/changed/missing and separately new public paths. Separate test-only from production changes. Seek hash-matching public preimages/reviewed successor diffs for changed production seams; do not infer a byte diff from review prose. The fresh258 map and186 comparison are leads, not replacements.
4. Record task-specific disposition of each consequential source change and its existing current tests/reviews. Retain historical R10 as historical. If the original evidence plus offline drift review covers all task-specific criteria, close **TASK40 only** using the already applied delta; no approval wait/new waiver/old proof rerun is needed. If a genuine current behavior gap remains, name that exact unmet requirement and owner, without importing unrelated whole-product gates.

### New local outputs

- This document.
- `test-results/scanner-sync-20261016/artifact186-manifest-transcription.sha256` — transcribed public map, not an original artifact byte copy.
- `test-results/scanner-sync-20261016/artifact186-current-comparison.json` — measured comparison, all34 rows.
- `test-results/scanner-sync-20261016/current-public-inventory.json` — stable current258-map and independently hashed anchors.

No original gzip or decoded packet was saved because no lossless binary bytes were obtained. No signed URL is stored in these outputs.
