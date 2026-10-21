# Public image specifications — reconciliation, updated 2026-10-21

## Deliverable and authority

**All three complete resulting bodies delivered through MCP, not patches or another handoff.** The `*-result-20261020.md` files are the complete submitted `body` values; immutable `*-base-20261020.md` captures remain untouched. DOC1 **v5→v6**, revision `8096b344-f848-4d8b-b1be-7953cee30c49`, and DOC6 **v2→v3**, revision `e613a565-dfe1-4ce6-8bc1-daa710fef535`, are applied from **DIP-TASK-2**. DOC2 **v7→v8**, revision `b5a758c5-af6d-4fdf-b78b-2c268653ed31`, is applied from **DIP-TASK-9**. Each actual entire resulting body was submitted literally to MCP validate/propose/apply; fresh whole-body manual base comparison and independent full readback PASS. This completes document delivery, not task acceptance, runtime recovery or source qualification.

Project `DIP`, UUID `520a0059-d0f2-4f86-8d93-fc15035a5715`; repository `diplom`; inspected HEAD `7c47bc5e5b09419378e70c80d59a8c310f662261`. Source working-tree hashes below, not HEAD alone, identify this delivery. Requested document date is 2026-10-20; the terminal's observed UTC clock at hash capture was **2026-10-19T21:56:10Z**. No invented later execution timestamp is asserted.

The original authoring timestamp above is historical, not the clock of this continuation. At 2026-10-21T19:00:20.298144+00:00 the continuation reread handoff FIRST, `flownix-basics`, `flownix-write-spec`, `review-work`, `.flownix` and fresh MCP policy. Policy remains full/strict/approval=false/spec_first=false/parallel/direct (policy updated_at 2026-09-27 15:29:32.870297+00). Approval is not a blocker; no extra human approval cycle is invented. Document validation/propose/apply is user-authorized only after exact fresh base and delta checks. All tracker access uses MCP, not REST/credentials/config search. In the initial read-only/draft pass no tracker mutation occurred. The later authorized document pass created/applied exactly the three new document deltas identified above; authorized evidence/AC comments to TASK2/TASK9 are recorded below. No policy, pre-existing delta, source, task status/progress or closure was mutated. TASK2 history is not repeatedly fetched; its four original AC remain authoritative, not expanded into invented blanket native qualification of every ecosystem enum.

Initial authoring created six captures/results plus this manifest. **This continuation writes ONLY** `docs/public-image-doc1-result-20261020.md`, `docs/public-image-doc2-result-20261020.md`, `docs/public-image-doc6-result-20261020.md`, `docs/public-spec-reconciliation-20261020.md`. Base captures, handoff, original evidence, source, foreign notices, LLM work and pre-existing dirty changes remain untouched. No nested agents, Docker/checker/continuation/native scanner/registry/launchctl commands, lifecycle or protected8080 access, private holders/env/key/JWT/account/ledger inspection, source/build changes, staging, branch or commit.

## Exact live bases and full results

SHA-256 is over exact UTF-8 file bytes, including the final LF. These are **body hashes**, not hashes of the MCP JSON envelope/title/metadata.

| MCP document | Pre-delivery base version / updated_at | Immutable base capture | Bytes | Local capture SHA-256 |
| --- | --- | --- | ---: | --- |
| DIP-DOC-1 `5409b5a8-982e-4027-8c73-310d6aebc0fb` | v5 / `2026-10-15 17:24:56.526557+00` | `public-image-doc1-base-20261020.md` | 30513 | `a04a8d75b7eef33c65da1d7beb5b0bad8e9fcd13594717b6e94a5340e8b9c1a4` |
| DIP-DOC-2 `dc029ab5-1a3a-4c6f-8604-6e08d14521e6` | v7 / `2026-10-15 17:25:12.622314+00` | `public-image-doc2-base-20261020.md` | 47202 | `e2a4b6641d757c81141e127c8737611ebce73eb11917ccad906a2cf8d682b016` |
| DIP-DOC-6 `13bf8ba0-23e9-4c3e-ba8f-6dd91382ec30` | v2 / `2026-10-15 19:22:54.459189+00` | `public-image-doc6-base-20261020.md` | 33921 | `af9dca00f23c55cb34593345e3e5e7a66bbacf922eee4e80b391030b8cf236cf` |

Historical capture attribution: DOC-1 was reconstructed from the saved 20261018 draft by reversing documented changes, with a hash matching the previously recorded v5 body hash. DOC-2/6 captures were transcribed from full MCP bodies, not stale pending targets. Fresh MCP reads in this continuation returned v5/v7/v2 and the updated_at values above; no newer requirement/content change was identified in the textual read. **The hashes in this table are independently computed LOCAL CAPTURE hashes, NOT freshly computed remote-content hashes. Exact fresh MCP-content→capture byte equality has NOT been independently established.** Matching versions alone is not a substitute. The user subsequently explicitly authorized whole-body manual comparison without a bridge/hash claim. For DOC2 this comparison was completed against fresh v7: title, Purpose, all 28 requirements and every scenario, and all eight Non-goals paragraphs matched the base capture; no intervening changes were identified. Its v8 readback was likewise compared manually against the full resulting file. No machine remote hash or byte-exact automated comparison is claimed. DOC1 v5 and DOC6 v2 were subsequently reread in full immediately before their delivery, and whole-body manual comparison against their captures PASS: title, Purpose, all original requirements/scenarios, Non-goals and dated trailing sections. Their v6/v3 full readbacks were manually compared with the entire resulting files, not only changed fragments. This is manual textual comparison, not a machine-exact remote hash claim; approval=false introduced no human gate.

| Full body to send, relative to repo root | Bytes | SHA-256 | Requirements / scenarios |
| --- | ---: | --- | ---: |
| `docs/public-image-doc1-result-20261020.md` | 69277 | `614eae92fc4b9511c86c3749c5d1221d772490c2014da175eaa4c097241f02ef` | 39 / 52 |
| `docs/public-image-doc2-result-20261020.md` | 49647 | `d92649c2069a1a5e8e44d5afdd21d59a13ea42054ef046d28548bf7f46d8a5d8` | 29 / 45 |
| `docs/public-image-doc6-result-20261020.md` | 46454 | `cf2a0b9e127dd0f41ca1595a200d99ad4680303050dabf14d5feb4b705284116` | 29 / 34 |

Titles and current component associations are preserved; no metadata/component mutation is needed for these body reconciliations. DOC-1 component DIP-COMP-3; DOC-2 DIP-COMP-1; DOC-6 DIP-COMP-1/3.

## Delta inventory and precise dispositions

MCP `state` and `review_status` are independent. Historical `state:applied, review_status:pending` is **not** a pending unapplied delta to duplicate. Text saying “unapplied/do not apply” inside a document does not override actual MCP state.

### DOC-1

| Delta | Observed disposition | Coordinator handling |
| --- | --- | --- |
| `db14160a-85f5-42f6-b112-a9b2138dc466` | **applied**, approved, base4→v5, source DIP-FEAT-1 | Already the current baseline. Do not apply again or use its mixed target as a new implemented claim. Preserve history. |
| `ae9a5147-73c3-4c28-8f99-0821bd6319f7` | applied, pending review label, base3→v4, source DIP-TASK-2 | Historical SBOM baseline; no new action/duplicate. |
| `35ba99ea-4424-4f33-991b-6cabac3d912a` | applied, pending review label, base2→v3, source DIP-TASK-3 | Preserve historical list/status baseline. |
| `fb8b741e-b6a7-4169-974e-a1289b085be4` | applied, pending review label, base1→v2, source DIP-TASK-1 | Preserve secret-only history. |
| `b6ce7feb-870f-4370-9abc-31fdbd2783c2` | applied v1 initial empty registration | Preserve history; its inherited no-requirements issue is not present in current v5. |
| `f3e9da43-1136-457a-98f9-43cf84f2e186` | **proposed/approved**, stale base2, source DIP-FEAT-1 | Do not apply: would drop current SBOM/list/status/nginx/public requirements. Record semantic supersession only: current v5 already preserves later requirements and the new reconciliation must start there. No discard/delete/update of this approved stale delta is requested or performed. |
| `5b4f6a0a-759d-4dac-a3a8-5ebaacce1c8c` | **proposed/approved**, stale base1, source DIP-FEAT-1 | Same: stale full replacement is semantically superseded by current v5 and the fresh-base reconciliation. Leave the approved row/state/body untouched; no discard is necessary. |
| `ff65f2bb-2623-4da3-9b01-e4aa6fb8c533` | discarded, pending review label, base1 | Leave discarded. |

Immediately before delivery, `list_doc_deltas(source_node_slug=DIP-TASK-2,state=proposed)` returned no revisions; DOC1 proposed list held only the two historical approved stale rows above. New full-body reconciliation `8096b344-f848-4d8b-b1be-7953cee30c49` was created at `2026-10-21 19:31:34.070739+00`, applied at `2026-10-21 19:31:37.831503+00`, base5→v6. Ops: **1 modified,16 added,0 removed/renamed**. It semantically supersedes both stale base1/base2 wholesale targets without changing their rows, approval, body or state.

### DOC-2

| Delta | Observed disposition | Coordinator handling |
| --- | --- | --- |
| `6ce90e3e-10fc-4364-b7bb-3184a1ecca15` | **applied/approved**, base6→v7, source DIP-FEAT-3 | Baseline used for reconciliation v7, not pending future content despite old purpose wording. Superseded as current version by the new v8 receipt below. |
| `302d79a2-d1d4-438d-853f-86376ea9477b` | applied, base5→v6, source DIP-TASK-22 | Preserve. |
| `6146b579-95f6-43c0-9d1b-64c92aaf519d` | applied, base4→v5, source DIP-TASK-22 | Preserve. |
| `d6c2335a-a7cb-469e-91f7-47bc769e61d4` | applied, base3→v4, source DIP-TASK-22 | Preserve landing history. |
| `913dec08-be0a-4c1c-9543-29216a7afe77` | applied, base2→v3, source DIP-TASK-20 | Preserve design history. |
| `21f816de-c3ef-4976-8dae-31193209935f` | applied/approved, base1→v2, source DIP-FEAT-3 | Preserve audit history. |
| `b87ef4da-fdb9-4e2a-b87a-40c0dad49d7c` | applied initial v1 | Preserve. |
| `414234f5-a878-40dc-80cd-9a6f731c4846` | **proposed/approved**, stale base2, source DIP-TASK-12 | Unrelated PoC target; do not apply/rewrite for public work. Coordinator disposition must preserve its independent rationale and rebase separately if still wanted; recommend superseding the stale full replacement, not dropping its intended work silently. |
| `3e049e61-3462-4ff0-bd02-da80ed385fe7` | **proposed/approved**, stale base1, source DIP-TASK-9 | Do not apply: drops audits/landing/discovery/current requirements and asserts obsolete missing routes. Superseded as a wholesale TASK9 replacement by applied `b5a758c5-af6d-4fdf-b78b-2c268653ed31` (v7→v8). Old approved row/state/body remains untouched; no discard/delete or rewrite. |

Before mutation, fresh DOC2/source TASK9 proposal lists contained only the two historical approved stale replacements (TASK9 list only its base1 proposal); no matching current-base reconciliation existed. New `b5a758c5-af6d-4fdf-b78b-2c268653ed31` was then created at `2026-10-21 19:12:40.851022+00` and applied at `2026-10-21 19:12:52.411171+00`, base7→v8. It is **applied**, even though review_status remains pending under approval=false. Server ops: exactly seven modified requirements and one added TEMP partition, zero removed/renamed. Independent TASK12 intent was not appropriated or accepted.

### DOC-6

- `e7711385-d8af-4a45-add1-bc7daa93611d`: **applied/approved**, base1→v2, source DIP-FEAT-1, current mixed LOCAL/advisory target. Preserve history; do not reapply it wholesale.
- `5a3d2ee7-ee8f-43d9-b9cb-cdf0bf88ad35`: applied initial v1; preserve.
- Fresh DOC6 and source TASK2 proposed lists were empty before this delivery. New `e613a565-dfe1-4ce6-8bc1-daa710fef535` was created at `2026-10-21 19:27:45.324495+00`, applied at `2026-10-21 19:27:49.823969+00`, base2→v3, source DIP-TASK-2. Ops: **7 modified,3 added,0 removed/renamed**; all26 baseline requirement identities remain.

**Fresh checks reconfirmed** DOC1's two approved base2/base1 proposals, DOC2's independent TASK12 base2 and TASK9 base1 proposals, no DOC6 proposal and no TASK2 proposal. No matching fresh reconciliation existed before creating the three receipts. Supersession is recorded here without changing old rows; none has been discarded/deleted/rewritten. Doc/source-node delta lists were reread before mutation. If another agent has created a matching pending reconciliation, stop and use its workflow rather than duplicate. A newly approved text cannot be silently rewritten in place.

## Semantic reconciliation and preservation audit

No current requirement name was removed or renamed; counts increased 23→39, 28→29, 26→29. Full bodies retain unaffected scenarios rather than sending an appended fragment to replace the document.

### DOC-1

- **22/23 original requirement blocks byte-identical.** The only original block change is the explicit legacy-policy qualification of NextUpdate in “Свежая locally-attested DB”; it does not weaken legacy freshness.
- Existing standalone SBOM, authorization/idempotency/status/list, TLS/DNS/realm/no-daemon, qualified exact-nginx/proof gates, provenance/redaction and forward-only durability remain.
- Added the separately scoped public contract, shared original-claim/cancel lifecycle, and Debian TEMP partition. Existing nginx/Alpine inventory/1GiB constraints are explicitly legacy-only, not contradictory universal limits.
- Numeric public bounds are finite and source-derived. Delivered-body metrics are not physical wire; logical scratch audits are not kernel/global quota; 4GiB/2304MiB does not rewrite legacy 1GiB/512MiB.
- Dates/status prose corrected: current v5 already applied; later native evidence exists; old source-only/HOLD assertions are historical. Two targets do not prove blanket native/production/full-task acceptance.

### DOC-2

**21/28 original blocks byte-identical**, including all unrelated P1 audit/license/accessibility/design/source/landing requirements and scoped cursor/search security/saved-selection controls. Only these seven original blocks changed:

1. “Текущая подтверждённая граница discovery”: old Alpine-only first-page baseline → current profile/eligibility distinction.
2. “Bounded discovery следующего среза”: actual process-local limits, continuation/expiry/error behavior; no cluster-global claim.
3. “Будущий авторитетный image admission”: current optional canonical Hub public admission; default/legacy not widened.
4. “Будущие числовые scan bounds и registry-only изоляция”: precise public acquisition/runtime/output/serialized caps, not future unspecified limits.
5. “Независимые coverage и freshness будущего scan”: 11 ecosystems/receipt marker, DB v2 warnings/expiry and public OS/Node boundaries.
6. “Однозначный future terminal reducer”: source uses selected secret/sbom/vuln/config, not independent OS/Node selectable checks. Checked vuln + unsupported/NODE_INVENTORY_UNKNOWN can be completed without claiming Node checked. Selected vuln unsupported/failed plus checked secret gives partial. No invented NO_EXECUTED_CHECKS production error code.
7. “Cancellation, fence и scoped snapshot”: cancelled with saved subset, all/no-checkpoint cases, immutable final race, original token/time fence, historical timestamps, unknown missing reports and subject-safe paging/reload.

One added block handles authoritative CVE/TEMP partitions and no invented links. Existing requirement names containing “future” are retained as stable identities; their new bodies, not old names, define the current bounded contract.

### DOC-6

**19/26 original blocks byte-identical**: baseline/identity guards, refresh principle, shared Findings, independent pages/totals, unknown-not-zero, UTF-8 metadata budget, redaction, conflict-preserving CVSS, vector validity, canonical navigation/user-only links/BDU/calculator, legacy metadata and stage-specific acceptance remain. Modified seven blocks (the continuation additionally scopes the existing host-only refresh requirement with a public maintenance scenario):

- LOCAL exact activation explicitly excludes the separate public composition; protected/default deployment remains legacy.
- Saved eligibility selects its own profile, not a hardcoded public-to-LOCAL binding.
- Existing 1GiB budgets explicitly scoped legacy.
- Honest OS/check outcomes reconcile public OS_UNKNOWN/EOL/Node unknown and selected-check reducer.
- Forward-only durability adds shared checkpoints/cancellation/token/clock/storage-error semantics.
- Advisory intake stays CVE-only for legacy with a narrowly scoped public Debian TEMP exception.

Added three blocks: receipt-scoped public bounds/11 ecosystems; TEMP identity/partition/no fabricated mapping; DB v2 current-time final fence versus historical cancellation evaluation. Unrelated stage A/B, CVSS/BDU/link requirements remain constraints and acceptance obligations, not newly asserted PASS. Existing LLM sink restrictions were preserved where already in the base; no LLM implementation/docs were inspected or accepted in this reconciliation.

## Source-to-contract anchors

| Contract | Current source anchors | What is explicitly NOT inferred |
| --- | --- | --- |
| Separate canonical public Hub admission, immutable target and replay | `scans/public-image-scans.service.ts:24-67`; base `scans.service.ts`; `oci/public-image-inspection.ts`; `public-image-policy.ts` | Discovery/scannable hint, arbitrary profile/env/client flag, default admission expansion |
| Actual acquisition/resource bounds | `public-image-policy.ts:3-14`; public inspection/archive/config-data; `worker-runtime.ts`; `compose.public-images.yaml` | All formats/OS/sizes; physical-wire accounting; actual current cgroup observation |
| 11 normalized ecosystems, actual package/OS evidence | `worker/public-image-evidence.ts:2-53`; `cyclonedx-components.ts`; `vuln-findings.ts:87-129`; `archive-scan-worker.ts:156-172` | Native certification of every enum value; absence of npm from no analyzer; checked zero from missing inventory |
| Debian TEMP exact ID and partition | `public-image-evidence.ts:43-45`; `vuln-findings.ts:113-160`; archive result validator; `scans/public-vulnerability-identifiers.ts`; browser identifiers | TEMP is CVE; GHSA/BDU intake; invented CVE/NVD/BDU/FIRST mapping |
| Two-source dedup/provenance and honest optional fields | `vuln-findings.ts:145-166`; `vuln-advisory.ts:96-170`; tests | Universal all-sink certification; translating/filling missing metadata/fixed version |
| Current token, strict lease inequality and current final clock | `ledger.ts:539-615,617-679,938-1000`; `outbox-consumer.ts:69-153` | Fresh context lookup authorizes old caller; equality is live; reason string proves DB expiry |
| Durable completed checks and cancellation | `ledger.ts:703-805`; retry/reclaim; `archive-scan-worker.ts:197-247`; consumer callbacks | Running public report from internal checkpoint; cancellation becomes partial/completed; retry/old/new attempt union |
| Consistent final vs accepted checkpoints | `ledger.ts:718-766,938-1000` | Arbitrary final overwrite; replacement DB downgrades accepted evidence; optional metadata omission drops core rows |
| DB v2 usability and historical evidence | `cve-db-policy.mjs:33-69`; `cve-db-evidence.ts`; ledger captured fence | Local attestation = Aqua signature; DownloadedAt rejuvenates DB; cancel/reload refreshes checkedAt |
| Owner HTTP, actual null/missing outcomes and receipt profile | `scans.service.ts:208-293`; `public-image-scans.service.ts:69-104`; strict `scanTransport.ts`/`reportView.ts` | Missing report route/null coverage means checked zero; endpoint alone grants public grammar |
| UI saved results after cancel, scoped partitions/pages | `ScanReportSections.tsx` terminal/enabled/unknown handling; `publicVulnerabilityIdentifiers.ts`; existing report controls | SSE close means 100%; page count equals total; subject change can retain old cache |
| Operational refresh boundary | `docs/public-cve-refresh.md` source contract; later `docs/public-product-handoff-20261021.md` author maintenance receipts | Prepare/migration/fresh activation are dated executed evidence, not a new scanner proof here. Scheduler/native install and post-LLM refresh remain pending; no unwired-bridge claim remains. |

### Source fingerprints (working-tree bytes)

The following are public source/evidence hashes, not hashes of JWTs, keys, real accounts, database contents or other private state. Modules affected by concurrent LLM implementation are deliberately not used as proof of LLM behavior.

```text
6ec5c11aae122e78a20de7544629ad514d080c15e1182e77f786bc3f457cbbbe  server/api/src/oci/public-image-policy.ts
74d9c0bc3b1efc3ea282d8b2a3c2a4a72b594b646b4a770b938c2e1628a16b6a  server/api/src/oci/public-image-archive.ts
b008ac2631d7fd6a132063d38e44db1c0fdaf302bbd4f44565dff3ee770f8d6c  server/api/src/oci/public-image-inspection.ts
39ff745e3be7d3673733c1dd8b3b051472ca21a8ac21f2cc1ce96f76f6fd804e  server/api/src/oci/public-image-config-data.ts
f6de742a7f899fbc4b6816cf28187960bbba843476c274c4d53a20e0e52bde8f  server/api/src/oci/pinned-image-config.ts
f916c55c9c1693f8c5592054d4eaa225fa585186de1094d6db2047df76331101  server/api/src/worker/worker-runtime.ts
deb5e30dd87043f597f4fa29dfce0d23231983472aca8ecb954291070019edc0  server/api/src/worker/public-image-evidence.ts
497984d5f29e8502ef0fdeed0b9ca0a7ffe9488275b911cb4c4918e95ecdadd7  server/api/src/worker/archive-scan-worker.ts
b8a7ef93c3580402a12d6e5089789a6bbe5574a6972127dceb08bf34989f6aec  server/api/src/worker/archive-result-contract.ts
46f286816453535109318e93bab6ac95837979274877d0c127901abc68fc01fe  server/api/src/worker/outbox-consumer.ts
6bc32d018f4164aa7aefb795319eb5d34f2e83b6a62b2de11dc78513ca3d6827  server/api/src/worker/image-config-runner.ts
685829a0c33509dbf115bd8cd60489ee72358f8181c44649448baa6408088207  server/api/src/worker/cve-db-policy.mjs
7a47feea80c0c4a9db8cbe3cde94f93546eed9123ff687625067553274191967  server/api/src/worker/cve-db-evidence.ts
d9c940e8c502434e02cdd7d9e1573db011633b081c69f932df6c735839b7fc02  server/api/src/worker/vuln-findings.ts
47bc418807796612788a72c90d0e0f6172b54308c7a89cbb8f957d1aae0ef670  server/api/src/worker/vuln-advisory.ts
8419946730996df6404b75aed26c38774aaaab005c79f37adb9bd664f2885ba3  server/api/src/worker/cyclonedx-components.ts
b18c856d0f6e80d7fb656d3ae935072d3025121f93f9beaf8c4e05f521e30d08  server/api/src/ledger/ledger.ts
cf908a0befcbdf0c3d3c89b9b75f48f8352ba0e3c6794b90a0731e9cc827bf9e  server/api/src/scans/public-image-scans.service.ts
c0d572963fbcb33d13fcd2fd53e35680371fd41a11cb501f9b6fb13744c851fe  server/api/src/scans/public-vulnerability-identifiers.ts
4626b1b018ab6e52f21499f640ba15407d3a1e3b61975e5c5601b289f6a99549  server/api/src/scans/image-search.ts
13a92c515837b77d6edde45f8030cda514d40a513ab10ae1272e7d0bee19d9f9  server/api/src/scans/scans.service.ts
d4465854fd6267de0b7c961c933e7aba16014d8842682d85b3e4558a02ae19c2  src/shared/api/scans/publicImageProfile.ts
1422c91e0d89d35d058ede1fe818dfa149e5f99cd40eafa0271ed38d2d91f5ec  src/shared/api/scans/publicVulnerabilityIdentifiers.ts
6a9d4d9852aa98f08a42365a750db8bca7d2901306afe9f8a27a92c4aed4a737  src/shared/api/scans/scanTransport.ts
feffab12ca6123dedd1f10a4525ef7dafc4501117ea806464c742d13262cd70b  src/shared/api/scans/reportView.ts
a1204f671a5a3ef6634be47c126f4697911433d090736514f98c2544e7bc0e09  src/pages/scans/ScanReportSections.tsx
fa562e64f4feb6d9f366bc3bf14a7b0f3773fbc00e97e7e153a7ed1f52f6cc99  server/deploy/compose.public-images.yaml
5d11e46303abc5502f00f4ead591b5fe958546fa9fe9d0ae1fe0aca313ebeb0b  scripts/public-image-stand-profile.mjs
ac1f88f208c76090ecd4eb7607a5297a618d0123e3cff69b1064e37a877fca1d  scripts/public-image-stand.mjs
a8ed32d044a0493d306cc5317cffe98527f9765d906432478aa35c4cc2fc630d  docs/public-image-final-20261018.md
0c6faba134ef6b0622e78b9fe8f6017d7b7f210c8d90528d91cb7b8a2aab2cc2  docs/public-image-node-native-20261018.json
49fca4788b40d5ed98358244a41f52046b60cd8f3cc20f8035da042355b018c5  docs/partial-cancel-implementation-20261016.md
27de6d03ae9ee02217709c1da0ca0e9e804de5d90a9d5196176d348d8d9293fd  docs/partial-cancel-http-ui-20261016.md
6c460fa76d0bfcbfad5180277b1c79d2fc52cbf659887db1cd16ab6d8e9c6259  docs/public-cve-refresh.md
```

## Historical validation from the initial authoring pass (not rerun here)

1. **Full local structural validation of all three resulting files: PASS.** Exactly one Purpose/Requirements; every requirement has an RFC2119 keyword in its contract and at least one named scenario with GIVEN/WHEN/THEN; no duplicate names, dropped base requirements, trailing whitespace or missing final LF. Full preservation audit counted byte-identical/modified/added blocks above. An initial helper used an over-greedy regex for block-name extraction and rejected its own preservation comparison; correcting that helper to a non-newline name match passed without changing documents or source to hide a validation failure.
2. MCP `validate_spec(doc_slug=...)` on each **current live base DOC-1/2/6**: all returned `{"valid":true}`.
3. MCP `validate_spec(doc_slug=DIP-DOC-6,body=<scoped exact changed lifecycle/outcome and new public blocks>)`: `{"valid":true}`. This call deliberately validated a scoped OpenSpec body, **not the entire local DOC-6 replacement**. It was not proposed or stored. At that historical authoring point full resulting-body server validation was still outstanding; it was subsequently completed for all three actual bodies as recorded in the delivery table below. Local full-body validation and base/scoped MCP validation are separate receipts.
4. Socket-free targeted source tests (disposable synthetic temp SQLite/fixtures, no HTTP/API listeners, Docker, native scanner or live DB):

```sh
# cwd server/api; invocation timeout 90000 ms
pnpm exec tsx --test src/worker/native-debian-normalization.test.ts src/worker/public-image-worker.test.ts src/worker/cve-db-policy.test.ts src/worker/vuln-findings.test.ts src/worker/vuln-advisory.test.ts src/ledger/ledger.checkpoint.test.ts src/ledger/ledger.archive-consistency.test.ts src/ledger/ledger.public-debian-temp.test.ts src/worker/public-image-checkpoint-recovery.test.ts src/oci/public-image-policy.test.ts
```

**236 passed, 0 failed/cancelled/skipped/todo, duration 1288.119375 ms**. This covers targeted normalizer/provenance/TEMP/DB-policy/checkpoint/final/cancel/resource-policy source behavior, not full API/UI/native/production qualification. No typecheck/build/full suite/new browser/native proof was run; docs-only changes do not require writing build outputs.

5. Scoped tracked `git diff --check`: PASS. These new files were untracked at delivery, so full-file whitespace checks above, not Git's tracked-only check, validate their actual content.

### Reproducible full local body/preservation check

Run from repository root, read-only (prints result and body hash; does not touch any state):

```sh
python3 - <<'PY'
from pathlib import Path
import hashlib, re
for n in (1, 2, 6):
    base = Path(f'docs/public-image-doc{n}-base-20261020.md').read_text()
    path = Path(f'docs/public-image-doc{n}-result-20261020.md')
    body = path.read_text()
    names = re.findall(r'^### Requirement: ([^\n]+)$', body, re.M)
    old = re.findall(r'^### Requirement: ([^\n]+)$', base, re.M)
    assert names and len(names) == len(set(names)) and set(old) <= set(names)
    assert body.count('## Purpose\n') == body.count('## Requirements\n') == 1
    assert body.endswith('\n') and not body.endswith('\n\n')
    assert all(line == line.rstrip() for line in body.splitlines())
    for block in re.split(r'^### Requirement: ', body, flags=re.M)[1:]:
        contract, *scenarios = re.split(r'^#### Scenario: [^\n]+$', block, flags=re.M)
        assert re.search(r'\b(SHALL|MUST|SHOULD|MAY)\b', contract) and scenarios
        for scenario in scenarios:
            assert all(re.search(r'^- ' + step + r'\b', scenario, re.M)
                       for step in ('GIVEN', 'WHEN', 'THEN'))
    print(path, len(names), hashlib.sha256(path.read_bytes()).hexdigest(), 'VALID')
PY
```

## Evidence boundaries and remaining acceptance

- Full safe Node native receipt was read: `PASS_SINGLE_NATIVE_TARGET`, nativeExecution true, mockedHttp false, injectedOciOrScanner false, wholeSystemQualification false, imageProfile.qualified false; target digest `sha256:01393fe5a51489b63da0ab51aa8e0a7ff9990132917cf20cfc3d46f5e36c0e48`, config `sha256:33544e83793ca080b49f5a30fb7dbe8a678765973de6ea301572a0ef53e76333`, linux/amd64; 158 CVE, 217 SBOM components including 200 npm, zero Secrets, config checked1. Time 2026-10-18 14:05:06.605Z→14:06:18.591Z. Not rerun here; not evidence that every one of those CVEs is an npm advisory.
- Debian native 236 CVE + 5 TEMP/88 components, Debian12.15, scan `b2c8f335-f1e8-4c0e-be33-561bd0cda1a6`, is **coordinator-reported in the dated final handoff**. Its full original JSON was not available there; no digest/config/raw evidence is invented. The synthetic 241-row fixtures test partition correctness, not actual native execution.
- Public DB receipt UpdatedAt `2026-10-16T01:13:54.947090392Z` and usableUntil `2026-10-30T01:13:54.947090392Z` are historical values. Neither these dates nor old passed readiness assert current live DB/signature/mount health. Current-source v2 has an inclusive 14-day equality boundary; operational expiry and historical reads are distinct.
- Two-source dedup/provenance and source-associated conflicts are preserved requirements with targeted fixture verification, not blanket whole-product/sink certification. Secrets redaction, safe errors/no raw output and checked-not-safe remain non-negotiable. EOL/unknown/failed/countless outcomes are not rewritten into clean results.
- Preserved legacy exact qualification, stage A/B actual workflows, link/CVSS/BDU verification, complete negative/resource/backup/restore/retention acceptance still require their own evidence. Public single-target native PASS is not automatic proof of all those gates, full TASK2, or other tasks.
- The old unwired-bridge statement is superseded: concrete default public bridge/provision/refresh is delivered. Later 20261021 handoff reports actual prepare, guarded migration and fresh upstream activation. This does not infer controlled rollback, scheduler installation/native qualification, post-LLM refresh or a fresh live check in this documentation pass.
- LLM implementation is underway independently and ignored for this scope. Do not interpret old historical “LLM not enabled” source-stage prose as a current assertion or use this reconciliation to accept/reject its work.

## Delivery protocol followed (historical checklist, not outstanding work)

1. Read live DOC-1/2/6 via MCP again; compare the complete returned `content` manually with base captures as explicitly authorized, without claiming a machine-exact remote hash. If any base drifted, rebase the **complete** corresponding result, preserving all still-valid requirements; do not blindly apply a prepared body to a newer version.
2. Recheck source fingerprints for relevant contracts, not just Git HEAD; concurrent changes (especially report/ledger/DB) require review/revalidation before using this snapshot.
3. Read document and chosen source-node delta lists. Do not duplicate an existing matching pending/draft/rejected reconciliation. Old approved stale replacements cannot be edited in place or used wholesale; record their disposition separately without destroying history.
4. Through MCP call `validate_spec(doc_slug=<DOC>,body=<entire matching result file>)` for **each full resulting body**. Correct any new/inherited issues intentionally; verify no unwanted removed requirements. Do not send a file path, manifest, diff, scoped validation excerpt or base file as `body`.
5. If no matching proposal exists, coordinator may propose the validated full body from the actual responsible node: DIP-TASK-2 for DOC-1/6 and DIP-TASK-9 for scan-UI DOC-2, as explicitly authorized. Fresh task listing confirms both existing source nodes and their component bindings. The existing independent DIP-TASK-12 proposal must not be appropriated for public work. Include precise implemented-scope reason and these evidence/hash references. Feature-source spec history is not task-level strict closure evidence.
6. Recheck live approval/policy/base state and apply only the new accepted scope through MCP when coordinator judges it appropriate. This handoff does not authorize old mixed-target wholesale apply or bypass validation/approval/version gates.
7. **No statuses/closure from this work.** Full task acceptance is a separate coordinator decision against original AC; no no-spec-impact declaration, invented full qualification, additional human-gate policy or task reopen/cascade is requested.

## Continuation receipts and exact-base boundary — 2026-10-21

| Document | Fresh live base | Authorized existing source | Full-result MCP validation | New proposed / applied revision | Live version after this pass |
| --- | --- | --- | --- | --- | --- |
| DIP-DOC-1 | v5, updated_at as above; full manual base comparison PASS | DIP-TASK-2 `73aa09d5-84f4-4a89-8021-33c29cd206bd` | Entire updated body submitted literally, `{"valid":true}` | `8096b344-f848-4d8b-b1be-7953cee30c49` / same ID **applied** | **v6**, full readback PASS; updated_at `2026-10-21 19:31:37.831503+00` |
| DIP-DOC-2 | v7, updated_at as above; full manual base comparison PASS | DIP-TASK-9 `84f0cc26-81a2-4697-b8e5-5ed074006644` | Entire resulting body submitted literally, `{"valid":true}` | `b5a758c5-af6d-4fdf-b78b-2c268653ed31` / same ID **applied** | **v8**, full readback PASS; updated_at `2026-10-21 19:12:52.411171+00` |
| DIP-DOC-6 | v2, updated_at as above; full manual base comparison PASS | DIP-TASK-2 `73aa09d5-84f4-4a89-8021-33c29cd206bd` | Entire updated body submitted literally, `{"valid":true}` | `e613a565-dfe1-4ce6-8bc1-daa710fef535` / same ID **applied** | **v3**, full readback PASS; updated_at `2026-10-21 19:27:49.823969+00` |

DOC6 was revalidated after the latest owner-attribution correction: all29 requirements/34 scenarios plus full Purpose, Non-goals and evidence were sent, not a path/excerpt/base. DOC1 likewise sent all39 requirements/52 scenarios and every trailing section. Both validators returned valid:true. Proposal echoes, ops, apply responses and independent `flownix_get_node` reads confirmed the complete resulting texts and v3/v6, unchanged titles/references/components. The TEMP scenario label is `TEMP и count-preserving durable чтение`. All three deltas have **state:applied, review_status:pending**; under fresh approval=false this is applied, not an outstanding human gate. Local hashes identify actual file bytes; no machine-computed server checksum is asserted.

**Manual-comparison authorization and completed DOC2 pass:** absence of a server checksum/file-transfer handle is no longer treated as a blocker. The user permits full textual manual comparison, without claiming a machine exact remote hash, and one document at a time for context size (DOC2 priority). Fresh DOC2 v7/base capture and v8/result comparison covered the whole bodies, not just requirement names/counts or changed fragments. Literal full-result `validate_spec` returned valid:true; `propose_doc_delta` returned base_version7 and expected ops; fresh policy immediately before apply remained approval=false; `apply_doc_delta` returned state applied/version_no8; `flownix_get_node` independently read back v8, full body, unchanged title/COMP1 and the applied timestamp. The local result remains 49,647 bytes, SHA-256 `d92649c2069a1a5e8e44d5afdd21d59a13ea42054ef046d28548bf7f46d8a5d8`. This is a LOCAL byte hash, not a remotely computed checksum. No backend size refusal occurred, no shortened/file-path body or local-only validation substitute was used. DOC1/6 were subsequently delivered in the same full-body manner, with real receipts in the table. No backend size refusal occurred for either body; no truncation or local-only validation substitute was used.

Fresh document/source delta checks found no current-base duplicate. Old approved DOC1 base1/base2 and DOC2 TASK9 base1 replacements are stale against the present live versions; current live baselines already supersede their wholesale targets. For DOC2 the actual applied reconciliation `b5a758c5-af6d-4fdf-b78b-2c268653ed31` now supersedes the stale TASK9 wholesale target. DOC1 now has applied fresh-base superseding revision `8096b344-f848-4d8b-b1be-7953cee30c49` (v6). Independent TASK12/PoC intent is not appropriated or declared implemented. All old rows remain unchanged.

## Frozen source and permitted-write proof

The four allowed Markdown paths are outside `capturePublicLlmSource` fixed paths and recursive roots (`src`, `public`, `server/api/src`, `server/runtime/src`), outside all 15 `PUBLIC_LLM_EXECUTION_MODULES`, and outside explicit COPY closures of `public-stand.Dockerfile`/source-build helper. No launcher/checker was imported or executed to establish this; definitions were read statically. This verifies that these doc edits are **not execution/build/fence dependencies**; it does not authorize source or runtime continuation.

At 2026-10-21T19:00:20.298144+00:00, union = 405 public source/build/execution files. Digest over sorted rows `[path,sha256(bytes),st_dev,st_ino,st_size,st_mtime_ns,st_ctime_ns]`, Python `json.dumps(rows,separators=(',',':')).encode()`: `0abc022e376d55adc2b43553223fbc0498cd80729a54cd767091b169f170e96a`. This exactly matches the earlier 18:57:17.912559+00:00 snapshot from this work. No private state/hash/token/key material participates. Final recapture at **2026-10-21T19:05:57.478312+00:00** returned the same 405-file digest: **UNCHANGED**. All 39 current public source/evidence anchor hashes (34 original entries plus 5 continuation anchors) matched; all 8 original historical artifact fingerprints matched. No launcher/checker or live action was run.

Public anchors of the historical19:05:57 snapshot (owner-reviewed current maintenance fingerprint recorded below):

```text
17c5989f2331dfbea10b0d05fd78a9b50d9da3fb7c7bba967969f4a6f3a18bef  scripts/public-llm-stand.mjs
f058e08990f01c05795e0bae4939ea01c1a6ee38c187757832d1dfd9c1fa8148  scripts/public-llm-build-continuation.mjs
b496a4d54220eac5efddb6f862b3340253dba477a88a556eeba612e2358d2c63  scripts/public-llm-source-build.mjs
c5cf1badd28d440d990edb69cd784e15e60014caadc108fe70010f676b361549  server/deploy/public-stand.Dockerfile
b55f39b3d7adfd410adc47f39f70d61f8463d18b48a2edee7b4adffaa0cec168  docs/public-product-handoff-20261021.md
```

Of the original 34 source/evidence fingerprints, 31 matched and 3 changed before the initial continuation: public stand profile, public stand launcher and public CVE source handoff. Their then-current hashes replace the old values in the fingerprint table; the delivered bridge/public workflow was reread instead of treating old tests as verification of the changed source. Scanner/normalizer/ledger/report anchors did not drift. No source file was changed by this agent.

### Owner-reviewed maintenance fix observed after DOC2 apply

At **2026-10-21T19:14:06.390858+00:00**, static recapture still enumerated 405 files but returned composite digest **`1bf8831a9fc3f05eb513347a3d2dd400309a7471cfbada2176a05ac5f4a39727`**, no longer the earlier `0abc022e…e96a`. The newer closure member is **`scripts/public-llm-build-continuation.mjs`**, 25,554 bytes, mtime/ctime **2026-10-21T19:09:21.610447+00:00**; current byte SHA-256 **`70e1c9f45a2c342814018844a9b784f9f04400d986a2feebf1a99d6ed5f5173e`**, previously `f058e08990f01c05795e0bae4939ea01c1a6ee38c187757832d1dfd9c1fa8148`. Of the 39 recorded anchors, only this one now differs; all other 38 still match. The agent edited only this manifest during the DOC2 MCP delivery and did not edit that module. Metadata alone did not establish authorship; the owner subsequently explicitly clarified this as their intentional mount-order normalization-only fix, independently reviewed GO with29 targeted PASS. Static source confirms `mounts: [...v.Mounts].sort((a, b) => a.Destination.localeCompare(b.Destination))`. The accepted current module fingerprint is70e1…5173e; the old f058…8148 fingerprint remains historical, not current.

The closure is **not unchanged relative to the pre19:09 snapshot**; the one reviewed maintenance delta is attributed, not unknown drift and not a reason to refuse DOC1/6. Current module bytes were rehashed at delivery and match70e1…5173e. DOC1/6 dated evidence now records the owner's correction before full-body validation/proposal/application. No execution/test-binding claim is extended from the old fingerprint to this fix. DOC2's discovery/normalizer/ledger/API/browser anchors remain the recorded matching slice. None of the three applied docs certifies current deployment/readiness, provider generation, full native matrix or whole-task acceptance. No launcher/checker was imported or run.

DOC2 result/base hashes remained unchanged after apply/readback; all 28 baseline requirement names are retained in 29 resulting requirements/45 scenarios. Fresh task listing confirms TASK9 still **regression85**, same updated_at `2026-10-04 14:06:57.156272+00`. No task status/progress mutation, source edit, checker/lifecycle execution or private data access occurred.

## Dated operational evidence, not permanent incident behaviour

Author handoff `public-product-handoff-20261021.md` supersedes the earlier `public-cve-refresh.md` source-only operational status, not its implemented guards:

1. Public `prepare` copied the already-pinned signed bytes into public-owned assets without resigning or reading the old private key; dedicated future signer provisioned.
2. Actual guarded v1→v2 migration PASS.
3. Fresh upstream staging and actual guarded activation PASS with accounts/reports/JWT preservation. This is native maintenance evidence reported by the author, not a new scanner invocation or live inspection here.
4. Scheduler **not installed/native-qualified**. Source/tests four-store LLM support is delivered, but **post-LLM refresh/preservation has not executed**. Controlled rollback remains separately unaccepted.

Last author-recorded public release (NOT freshly verified live): manifest `sha256:5903d201b3dc68dda334b9a9397ed51bd7956d834f43ab4edae6844a18912ced`; UpdatedAt `2026-10-20T19:12:26.430296739Z`; NextUpdate `2026-10-21T19:12:26.430296358Z`; DownloadedAt `2026-10-20T22:54:18.765315Z`; usableUntil `2026-11-03T19:12:26.430296739Z`. Local operator attestation, **not Aqua publisher signature**; usable is not fresh, and these timestamps do not assert today's readiness.

At the handoff's18:46:42Z check public8081 was HTTP000 during the original build HOLD, audit `deploy-8d83a8806715c2f0fa575efedee1b0af`; that is historical, not the latest continuation phase. **Owner correction2026-10-21:**70e1… is the intentional reviewed mount-order maintenance fix (independent GO/29 targeted PASS); fresh token **a0faa…** was stable and the **only actual continuation ended in NEW HOLD, phase=initialize,exit1**. Only the supplied token abbreviation is recorded, no full value is invented/reused. The earlier 'unknown drift/token investigation/continuation not run' interpretation is superseded. Initialize failure cause is not inferred. This is dated owner-reported operational evidence, not independently executed here and not permanent normative product behaviour. No new checker/continuation/lifecycle ran in this spec pass. Provider key absent remains handoff metadata, not env/key inspection; real generation is unaccepted. Recovery/browser/provider/scheduler/post-LLM remain distinct follow-ups, not substitute original TASK2/9 AC.

## Sanitized evidence security and attribution

- Packet `docs/public-secrets-qualification-20261020.dedup.json`: SHA-256 `82517fd0f215802a4201e98c5bb83277c0909b7f21eeb3f02e78a83e7a9390a9`.
- Companion `.dedup.validation.json`: SHA-256 `b444a79b6b6f82e73222b6c44be17964351c9fa3a935a489c027373457f6b2d4`.
- Original `.validation.json`: SHA-256 `12a159cd44ead48337f6980e1efa20ad4f7db8c67588d218c993d569f4cc2919`.
- Packet records 4 actual native scanner invocations, 2 never-issued canary findings each; 61 named checks all true, 4 JSDOM tests, cleanup remaining containers0. Not rerun here. The derived duplicate case explicitly injects 4 rows into 2 unique findings, preserving FIRST original positional IDs; it is **harness mutation**, not observed Trivy duplicate output or evidence of CVE two-source provenance. IDs are report-local positional, not content-addressed/global/reorder-stable identifiers.
- Real adapter/consumer/temp SQLite/owner HTTP/SSE/reopen/logical-retention paths follow native output. Transport/readiness/cancel barriers are controlled synthetic boundaries. No production browser E2E, provider/LLM sink, preinvoke private verifiedArchive wrapper or CVE qualification is inferred.
- Companion validation anchors: all 8 executable source hashes and 2 artifact hashes match current bytes. The packet's 313-source snapshot has 309 matches / 4 LLM-only drifts / 0 missing: `server/api/src/llm/llm-exception.filter.ts`, `src/shared/api/scans/llmChatClient.ts`, `src/shared/api/scans/llmChatContract.ts`, `src/shared/api/scans/llmPublicContract.ts`. Thus the historical packet cannot certify current LLM sinks. Its 8 historical artifact fingerprints are preserved and checked separately below.
- Earlier in this continuation,19 public evidence/result/handoff files were statically screened for private PEM, JWT, GitHub/AWS token, Basic payload and signed credential URL patterns: **0 pattern hits**, no matched values/snippets printed. After final delivery/manifest correction the three complete result bodies, this manifest and `.dedup.json` were screened again (**5files,0hits**). These scoped screens are not universal DLP or proof that every credential form is absent. The independent23-untracked-file screen is historical. Original public packets were read but not edited; private holders/env/keys were neither opened nor screened.

## Original acceptance mapping — recommendations only, no closure

Fresh task listing still shows TASK2 in_progress70, TASK3 in_progress75, TASK4 in_progress35 and TASK9 regression85. TASK40/41 remain done; neither is reopened. Existing component bindings remain TASK2→COMP1/3, TASK9→COMP1 and DOC1→COMP3 / DOC2→COMP1 / DOC6→COMP1/3.

| Original scope | Genuinely supported slice | Unaccepted / untouched boundary and recommendation |
| --- | --- | --- |
| TASK2 AC1: success/stale/unavailable DB/EOL/duplicates have honest outcomes/reasons | Historical native target receipts; targeted DB/normalizer/ledger tests; source reducer and typed unknown/failed/unsupported distinctions | Not a fresh full applicable outcome matrix or current live readiness certification. Keep TASK2 open; no invented native requirement for each of 11 enum values. |
| TASK2 AC2: same-CVE two-source provenance | Accepted advisory/conflict-preserving slices and source fixtures remain retained | Full applicable identity/count/storage/read/reload/retention provenance mapping remains open. Secrets duplicate proof is not CVE two-source proof. |
| TASK2 AC3: secrets absent from outputs | NEW positive native never-issued canary packet supports scoped sanitizer→temporary durable/owner HTTP/SSE/UI and dedup evidence, not merely Secrets0/synthetic scanner | Universal current log/LLM/provider/preinvoke sink matrix not certified; current LLM drift explicitly excluded. Recommend accepting only the bounded evidence slice, not whole AC/task closure. |
| TASK2 AC4: checked does not mean safe | PASS in the verified report/UI contract and historical tested slice; preserved requirements distinguish checked0/filter-empty/unknown | Not a new universal production browser run. No task lifecycle action. |
| TASK2 prior remote npm-positive concern | Oct18 single-target Node receipt has 217 SBOM components including 200 npm, 158 CVE = 97 apk + 61 npm | This is no longer wholly missing. Do not demand a repeat solely because earlier drafts said pending; do not generalize to every image/ecosystem. |
| TASK3 durable/list/SSE/cancel | Durable subset/reopen/replay/cancel evidence is relevant, including cancelled with all/no saved checkpoints | Does not close complete heartbeat/list/concurrency/original acceptance. No status change. |
| TASK9 scan UI | Source/controlled tests support bounded discovery/admission/count partition and actual terminal cancelled semantics | Full browser list→create→detail/status/events/native counts/filter/pages/cancel/reload/fresh login/ownership/error acceptance remains open. Oct16 owner chose durable checkpoint/atomic cancelled subset; do not invent required fake `cancelling` or partial-on-cancel. |
| TASK4 security | Narrow sanitized-publication/redaction evidence useful | Full audit/LLM/SSRF/injection original matrix not accepted by this packet. Remains open. |
| TASK40/41 | Already accepted DB v2 and saved-report filtering/paging baseline | Leave done; today's operational HOLD is not grounds for reopening. |

Separate follow-ups remain: owner-reported NEW initialize/exit1 HOLD resolution through separately authorized reviewed lifecycle (not unknown token drift), current browser qualification, real provider key provisioning/generation, native scheduler install/status, actual post-LLM refresh/four-store preservation, controlled rollback and unrelated legacy stage A/B/link/BDU/calculator acceptance. None is silently closed by a spec delta; no cascade, reopen, policy mutation, no-spec-impact declaration or new tracker task is performed.

Final local checks: DOC1 39 requirements/52 scenarios, DOC2 29/45, DOC6 29/34; no removed or renamed baseline requirement, full GIVEN/WHEN/THEN structure, unique names, final LF and no trailing whitespace all PASS. Scoped `git diff --check` returned no error, but these files are untracked and were additionally checked in full rather than relying on Git's tracked-only result. These are documentation checks, not a new source test/build/native/browser run. Final MCP reads/listing confirm DOC1v6/DOC2v8/DOC6v3 and applied timestamps above with unchanged component bindings; earlier draft/read-only passes made no mutations. The complete delivery produced exactly three new full-body proposals and three applies. Authorized TASK2/TASK9 evidence/AC comments are recorded separately below. No source/task-status/progress/closure/cascade/policy or pre-existing-delta mutation occurred.

## Authorized task-comment receipts

Full original TASK2/TASK9 content and history were read before commenting; no status/progress transition was used. Added exactly two `[progress]` comments after successful document delivery/readback:

| Source node | Comment ID | created_at | Scope |
| --- | --- | --- | --- |
| DIP-TASK-2 | `3117e84b-187d-47a4-a523-1ff531e3f8a9` | `2026-10-21 19:33:15.351266+00` | Actual DOC1v6/DOC6v3 receipts/local hashes, all4original AC recommendations, scoped native canaries/npm evidence, owner-reviewed70e1 fix/NEW initialize HOLD and remaining blockers; not done. |
| DIP-TASK-9 | `241d4350-6c46-4099-a4a2-cba747c09c27` | `2026-10-21 19:33:15.555995+00` | Actual DOC2v8 receipt plus related DOC1/6, preserved browser/cancel/count criteria, fresh operational attribution and unaccepted full browser matrix; not done. |

Latest read-only task listing before comments reconfirmed TASK2 **in_progress70** (`updated_at2026-10-18 16:43:15.413902+00`) and TASK9 **regression85** (`updated_at2026-10-04 14:06:57.156272+00`); TASK40/41done unchanged. Comment creation is the only authorized task mutation, not a task content/acceptance/status rewrite. Final local whole-file structure/preservation checks PASS: baseline blocks unchanged DOC1=22/23,DOC2=21/28,DOC6=19/26, no dropped/renamed identities, all scenarios GIVEN/WHEN/THEN, final LF/no trailing whitespace. Results retain the local hashes in the delivery table. No source tests/build/native/browser/lifecycle execution was performed in this final documentation delivery.
