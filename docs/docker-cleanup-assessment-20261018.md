# Docker cleanup assessment — 2026-10-18

**Chronology:** the image assessment below is the initial read-only snapshot. The appended **Network extension and coordinator update** records the later coordinator-reported image removals and the current nine-network assessment; it supersedes any implication that the four image candidates are still awaiting removal. No Docker mutation was performed by this assessing agent in either pass.

## Decision and authorization boundary

**Read-only Docker/repository assessment; no resources removed, stopped, started, retagged or otherwise changed.** Only this document was written. The current request permits assessment, not execution by this agent. Historical cleanup/rollout approvals are not reused.

Among the five explicitly requested tags, **four exact tags are eligible cleanup candidates**, subject to the coordinator's fresh pre-deletion checks below. All five are currently unreferenced according to successful Docker all-lifecycle `ancestor` listings, but the fifth is **PROTECTED** because its immutable ID is a documented retained HOLD rollout candidate. Unused does not mean disposable.

No container is approved for deletion. All other images/tags, all containers, volumes, networks, build cache, HOLD/locks, backups and private files are outside this candidate set. No prune, old R10/history/scanner-proof repeat, recovery attempt or retained-holder operation is authorized.

## Exact tag assessment

Each `ancestor` check below returned **zero rows**, with successful CLI completion. `-a` includes running, paused, stopped/exited and Created containers. Checks used immutable image IDs, not just display-tag matching. The general all-container listing also showed no requested tag or matching image ID. Each requested image's inspected `RepoTags` contained exactly its one tag below.

| Exact tag | Observed immutable image ID | Existing container references | Disposition |
| --- | --- | --- | --- |
| `dip-final-prebuilt-gateway-72e15222635a4190:636b834` | `sha256:e899d14b4e379b6467562b9e4fd30a9181b37a5e1257125568df16b2a857e072` | 0 | **CANDIDATE — exact tag only** |
| `dip-final-prebuilt-web-72e15222635a4190:636b834` | `sha256:634203d96fdc419f3018db6d8d417449423f0455c0bc48778dd603f920d45d31` | 0 | **CANDIDATE — exact tag only** |
| `dip-final-check-worker:636b834` | `sha256:79d8cdcdf65f8d85a93390255e457f434b6cfceac6147da019fecd499d7a7844` | 0 | **CANDIDATE — exact tag only** |
| `dip-final-check-api:636b834` | `sha256:70d11c11167a1bd8ecbc68901b5cd4b99efb99a2a472c69a32d769df05673878` | 0 | **CANDIDATE — exact tag only** |
| `diplom-web:report-v1-overlay-arm64-20261012` | `sha256:3d14f3d9e7347a9609fe3ae53b46efd70293aacae64da48c001ed6e826155817` | 0 | **PROTECTED — retained HOLD candidate, not disposable** |

### Why the four candidates are distinguishable from retained recovery images

This decision is based on exact provenance and completed-run evidence, **not** tag age, naming, labels alone or zero references alone:

- [Build validation](deployment/build-validation-20261015.md), lines 5–28 and 30–66, records fresh, separately authorized API/worker public-source builds at `636b834fa7d3c4d8114ecb4cf4fcc9357ca075e7`, their exact IDs, successful immutable-image smoke, and automatic removal of the two disposable smoke containers. No old private data was used. That pass explicitly did not release HOLD/recovery.
- [Image-stand validation](deployment/image-stand-validation-20261015.md), lines 92–119, binds the two exact prebuilt tags/IDs to successful public-source web/gateway builds. Current source/context/role labels agree with the public prebuild receipt.
- Public [prebuild manifest](../test-results/final-image-prebuild-20261015-r2/prebuilt-images.json) records those exact web/gateway tag/ID/label bindings, exit 0 and no timeout. Its documented SHA-256 is `307e41943229878004438a6660ce23edc2fb255daeb6ca19b01756fe1a195889` (historical documented pin, not newly recomputed here).
- Public [completed smoke result](../test-results/dip-image-stand-08faa29110d44d0f9a8b6ac610020fad/result.json) names all four exact IDs under `images`, records `status=PASS`, `phase=checks_finished`, `deployment=NOT_PRODUCTION`, `image_mode=PREBUILT_ONLY_NO_BUILD_PULL_HISTORY`, and own cleanup PASS with no errors. It is a textual receipt, not a new execution.
- [Independent acceptance](deployment/image-stand-independent-acceptance-20261015.md), lines 31–39 and 61–81, confirms the same selections and completed own-resource cleanup, separately preserving old HOLD/recovery restrictions. Its resource journal is historical, not a list of surviving resources. This assessment did not open the journal, generated compose or credentials.
- Exact tag/ID searches in existing deployment documentation found these four as successful build/completed isolated-smoke inputs, **not** as retained/frozen recovery bindings. In contrast, the report-v1 web ID is explicitly retained by the HOLD documents below.

The four are historical smoke inputs: removing their sole local tags can make the recorded prebuilt-only smoke invocation fail for missing images. That is an expected loss of immediate local rerun capability, not erasure of the saved textual receipts and not permission to rebuild/rerun the proof. No requirement to retain these four as recovery/frozen fixtures was found in the reviewed evidence. This finding does not generalize to other proof images or grant deletion of any source, result or manifest.

### Public labels observed (limited image inspection)

- Gateway and prebuilt web: `org.diplom.final-image-stand.source=636b834fa7d3c4d8114ecb4cf4fcc9357ca075e7`, `.context=ba69af8fead84d3e8ebe0b2a4316399608a900b918405330f5a014f4fc56bf8c`; `.role=egress` and `web`, respectively. Web also has the standard NGINX maintainer label.
- API and worker `636b834`: labels `null`; their ID/provenance evidence comes from the build documentation and completed smoke receipt, not inferred ownership labels.
- Protected report-v1 web: `org.opencontainers.image.revision=741e4aaf4b6c41dd176ddfe6ff175781958f8f73`, plus the standard NGINX maintainer label. Its HOLD binding overrides the empty reference check.

No full image/container inspection, Env projection, logs, exec, cp, mount/volume read, private key/config read or holder probe was performed. Historical statements about lifecycle or data preservation were not promoted to current facts.

## Protected groups — no deletion authority

1. **Active `dip-local-full`**, including its four application image tags and all containers (also the exited BusyBox init containers), volumes, networks and local state. The public inventory showed API healthy, worker/web/egress Up. Observed image tags/IDs:
   - `dip-local-full-api:local` → `sha256:4c2db076be6adfb574cf1a45d7aa9dd6705cfd6e8af0ee80b195278a51cbabba`.
   - `dip-local-full-worker:local` → `sha256:bad8575ddb599af1b77e9c82c1d708ed72494c70a819e0dc8209b0dd9a3cd5c1`.
   - `dip-local-full-web:local` → `sha256:9329512e9f213f3d05c51d9799e8b62e59677b62f186cdef3ab3f2d8dbcfedae`.
   - `dip-local-full-egress:local` → `sha256:a5b2b90d9e0793a3b4d0694586bf9c52a0ff9c3cf01915ecbd0d660776694988`.
   - [LOCAL documentation](local-full-stand.md), lines 15–23, preserves accounts/reports/secret and old-stand separation. No health or database qualification was run in this assessment.
2. **New `dip-public-images` qualification namespace**, all present/future `dip-public-images-{api,worker,web,egress}:local` tags and selected immutable images, init dependencies and state. None of those four tags or project containers appeared in this snapshot; absence is not cleanup permission or evidence that a launch failed. [Isolated-stand documentation](public-image-isolated-stand-20261018.md), lines 56–76, defines its separate namespace. No `.local-public-images` contents were opened.
3. **All eight original/candidate HOLD image IDs**, explicitly preserved in [HOLD handoff](deployment/hold-handoff-20261015.md), lines 14–29, and [prior cleanup preservation boundary](deployment/unused-docker-cleanup-batch-20261015.md), lines 94–100:

   | Binding | Protected image ID |
   | --- | --- |
   | Original API; also observed `dip-auth-stand-api:latest` / `dip-ai-quota-candidate:20261008T134534Z-bb9189080fdb` aliases | `sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c` |
   | Original worker and observed CVE base aliases | `sha256:8748cbebba753603d79f320c2fb476c46ab676ce12e0aa08bee0021a3e14e57a` |
   | Original web | `sha256:1659b39c98d5183c91feae78a8d9eb1d4c6ee527d541c1e1d74dfe842adee8c0` |
   | Original egress | `sha256:2b9eff3b381979c82bf42c310fcd7941805d42adeda67c8814143d6503490655` |
   | Original LLM egress | `sha256:3ccbd5a6c3348b7b1c99e23b29d9bdca485dfd48f690a408a119e06163a59a8d` |
   | Candidate API, `diplom-api:report-v1-overlay-arm64-20261012-gpt61-r2` | `sha256:4b3a3d4b3c2658ec9a36209afcac69eda2b64cef6e055a5e2716e2602e5338d1` |
   | Candidate worker, `diplom-worker:report-v1-overlay-arm64-20261012-gpt61-r2` | `sha256:891b5adccbe469345cea585e75dc71c6d3bf93405c5a18386795af1b012b314d` |
   | Candidate web, `diplom-web:report-v1-overlay-arm64-20261012` | `sha256:3d14f3d9e7347a9609fe3ae53b46efd70293aacae64da48c001ed6e826155817` |

4. **Retained history/R10 base** `dip-cve14-snapshot-9ea6698d1e19cb8f:local` → `sha256:c09ce4c8e6185784fad2c263b462952092fa89058d16363ebd543e0cd4bbd50d`, plus all history-wire actors. Explicitly protected even if an individual resource becomes unreferenced. No R10/history command was repeated.
5. **Every retained actor**: `dip-auth-stand-*`, `dip-preservation-*`, `dip-key-snapshot-*`, `dip-history-wire-*`, `dip-old-api-*`, including `207709f0f2992532af3331e0e2b38878c08a8d157ad074956f78c895aa5380e4` and `d9433f7ed0fc504a3521574668f15b7b3a0e8d283d61b9aa33d1e97187708a4f`. These appeared only in the permitted public list. No inspect/exec/cp/lifecycle operation targeted them. The retained PRE holder remains protected regardless of its currently displayed status; no inference of safe disposal, tmpfs survival/loss or recovery completion is made. HOLD handoff lines 47–60 explicitly reject extending the separate old `4dc…` retirement consent to `207709…`.
6. **All remaining shared/base/untagged images and aliases**, including BusyBox `1.37.0`, nginx-unprivileged, Python and Trivy, and all CVE base aliases. No eligibility assessment or removal permission beyond the four exact candidate tags above. All private Env/keys/volumes, backups, locks and HOLD material remain untouched and protected.

Prior cleanup scripts/plans are historical and SPENT, not a way to expand this request. [Prior cleanup result](deployment/unused-docker-cleanup-result-20261015.md), lines 65–108, preserves these exclusions and distinguishes explicitly disposable successful outputs from intentionally retained proof/history/recovery fixtures.

## Executed evidence commands

Working directory: repository root `oldstartup/diplom`. Docker calls were bounded to 10 seconds and used only the following public metadata surfaces. No Docker build/history/pull, compose, inspect of any container, volume/network operations, logs or lifecycle commands were run.

### General public inventory

```sh
docker container ls -a --no-trunc --format '{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}'
docker image ls --no-trunc --format '{{.ID}}\t{{.Repository}}:{{.Tag}}'
```

### Requested image ID/RepoTags/labels only

```sh
docker image inspect --format '{{.Id}}\t{{json .RepoTags}}\t{{json .Config.Labels}}' dip-final-prebuilt-gateway-72e15222635a4190:636b834 dip-final-prebuilt-web-72e15222635a4190:636b834 dip-final-check-worker:636b834 dip-final-check-api:636b834 diplom-web:report-v1-overlay-arm64-20261012
```

### All-lifecycle reference fences, including derived-image references

These five commands were first issued sequentially and then each repeated independently to confirm individual successful completion and empty output. No resource was accessed beyond list/filter fields.

```sh
docker container ls -a --no-trunc --filter ancestor=sha256:e899d14b4e379b6467562b9e4fd30a9181b37a5e1257125568df16b2a857e072 --format '{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}'
docker container ls -a --no-trunc --filter ancestor=sha256:634203d96fdc419f3018db6d8d417449423f0455c0bc48778dd603f920d45d31 --format '{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}'
docker container ls -a --no-trunc --filter ancestor=sha256:79d8cdcdf65f8d85a93390255e457f434b6cfceac6147da019fecd499d7a7844 --format '{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}'
docker container ls -a --no-trunc --filter ancestor=sha256:70d11c11167a1bd8ecbc68901b5cd4b99efb99a2a472c69a32d769df05673878 --format '{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}'
docker container ls -a --no-trunc --filter ancestor=sha256:3d14f3d9e7347a9609fe3ae53b46efd70293aacae64da48c001ed6e826155817 --format '{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}'
```

## Coordinator handoff — not an execution script

- The **only candidate set is the first four exact tag/ID pairs** in the assessment table. The report-v1 web tag is excluded even though its filter was empty. No containers are candidates.
- Before any separately authorized removal, coordinate against concurrent image/container changes and repeat the permitted inventory, exact image ID/RepoTags/label check and all-container ancestor fences. Require the same exact ID and sole RepoTag for every candidate, no protected-namespace overlap, no references, and no new retention evidence. Any error, drift, reference, ambiguous ownership or uncertainty means **protect/STOP**, not force, repin, retry or broader inspection of holders.
- Any coordinator removal must target exact candidate **tags**, non-force, without parent pruning (`--no-prune`); never delete by broad prefix, image-ID batch, all-unused selection or prune. This assessment supplies no executable removal command and performs no deletion. Removal conflicts must not be resolved by deleting/stopping containers.
- Retain all textual manifests/results/docs. Deletion of a tag's sole local image may prevent replay of the historical prebuilt smoke; no replay/rebuild of historical commands is authorized by this cleanup task.
- These observations are a non-atomic 2026-10-18 snapshot of the daemon selected by the Docker CLI, not a durable lease, endpoint attestation, forensic data-preservation proof or post-cleanup report. No physical disk/GB reclamation claim or current public-stand qualification claim is made. Application tests/builds were not run: this is a documentation-only inventory assessment.

## Network extension and coordinator update — 2026-10-18

### Attributed execution report — not execution by this agent

The coordinator reports that the four eligible `636b834` image tags listed above were **actually removed**, after fresh checks, non-force and with `--no-prune`:

- `dip-final-prebuilt-gateway-72e15222635a4190:636b834`
- `dip-final-prebuilt-web-72e15222635a4190:636b834`
- `dip-final-check-worker:636b834`
- `dip-final-check-api:636b834`

This is the coordinator's execution claim supplied in the follow-up request, not a removal performed or independently reverified here. No new image query was made in this extension; no physical disk-reclamation amount is asserted. The protected report-v1 web tag remains excluded.

The coordinator also reports that new public-stand creation stopped after **two own networks**, with **zero own containers/volumes**, and suspects default address-pool exhaustion with **30 bridge networks** and no explicit pool. These are attributed observations/hypothesis, not fresh global inventory or daemon-configuration findings by this agent. Only the nine exact requested networks were inspected. Image removal does not release Docker network subnet allocations.

### Network verdict

**Confirmed empty: 9/9. Confirmed disposable/released from retention: 0/9. Deletion candidate subset: empty. All nine are PROTECTED / RETENTION UNCERTAIN pending an explicit, separately reviewed network-retention release.**

These are identifiable remnants of three failed isolated CVE attempts whose containers and corresponding proof images were later retired. However, their receipts deliberately retained failure resources, and the later container-retirement plan explicitly preserved **all networks**. The evidence does not show a subsequent network-specific release. This prevents promoting empty/old/isolated topology to disposable topology under the present fail-closed assessment. The current broad old-unused cleanup request is not interpreted as silently clearing that retention boundary or any HOLD.

This is not a finding that any of these nine currently serves a live holder: all nine public endpoint maps are empty. It is a finding that **empty topology and authority to discard retained topology are separate questions**. No retained-holder inspection or broader discovery is needed or authorized to make this conservative decision.

### Exact current network snapshot

The single bounded command succeeded and returned nine records. For **every** record:

- `Containers={}` (zero attached endpoints in the permitted network view).
- `com.docker.compose.project` equals the full `dip-cve14-proof-<suffix>` in the exact name.
- `com.docker.compose.network` equals the final role in the exact name.
- `com.docker.compose.version=2.34.0`.
- `IPAM.Driver=default`, `IPAM.Options=null`, with exactly the one IPv4 subnet/gateway below.
- The remaining label is the per-network `com.docker.compose.config-hash`, recorded in the next table. There are no additional labels in the observed projection.

| Exact network Name | Exact network Id | Internal | IPAM subnet | IPAM gateway | Decision |
| --- | --- | --- | --- | --- | --- |
| `dip-cve14-proof-0a0c92726b8cd4e1_auth_internal` | `1f4e6084684dd24988ed2e7f900b34a9ff4bca39a9ccc79732d6b650fef00507` | true | `192.168.96.0/20` | `192.168.96.1` | PROTECTED / retention uncertain |
| `dip-cve14-proof-0a0c92726b8cd4e1_scan_internal` | `3256d7769f48db44f913bc30a9d4f7b772dce6074f021a80ce1c213f037e01a1` | true | `192.168.112.0/20` | `192.168.112.1` | PROTECTED / retention uncertain |
| `dip-cve14-proof-0a0c92726b8cd4e1_registry_uplink` | `9e4e08c7a10cff28c2a9e1f25778b967a6fba5034259c0f417bf34e0e059fdf2` | false | `192.168.80.0/20` | `192.168.80.1` | PROTECTED / retention uncertain |
| `dip-cve14-proof-9bef4d56d7aad6d7_auth_internal` | `b8a2e77985cf8c06fb1b3c601d8f9f14e36dfcc4ff5def7e5387761fadaba216` | true | `192.168.32.0/20` | `192.168.32.1` | PROTECTED / retention uncertain |
| `dip-cve14-proof-9bef4d56d7aad6d7_scan_internal` | `0899d5fae165ac68b2861022f405a5244357ec254a36f0739a221dca247f0acc` | true | `192.168.16.0/20` | `192.168.16.1` | PROTECTED / retention uncertain |
| `dip-cve14-proof-9bef4d56d7aad6d7_registry_uplink` | `a746f31096438318121706b4565353e9f1d2763fd3ed3b34a49a5ecb6f45342b` | false | `192.168.48.0/20` | `192.168.48.1` | PROTECTED / retention uncertain |
| `dip-cve14-proof-832cb6115c24c136_auth_internal` | `54160ee84163515cd1f311f60f0766f1aa44cdbb58e1b12832e831f531680d29` | true | `172.31.0.0/16` | `172.31.0.1` | PROTECTED / retention uncertain |
| `dip-cve14-proof-832cb6115c24c136_scan_internal` | `5fa1cf191a4210f96e6642537d52cfdd57e70cd83486b43092da3daa2783b8fa` | true | `172.30.0.0/16` | `172.30.0.1` | PROTECTED / retention uncertain |
| `dip-cve14-proof-832cb6115c24c136_registry_uplink` | `de4f2ce5206ffc4ab301c0fb0ae78f96c21d799f6dad00ffe491d029f1bb9bdb` | false | `192.168.0.0/20` | `192.168.0.1` | PROTECTED / retention uncertain |

| Project suffix / network role | Observed Compose config-hash label |
| --- | --- |
| `0a0c92726b8cd4e1 / auth_internal` | `c1dd8fe5b003c97fa1068847b9775471413c2bc2dc2ba30f03d4c2ceffbc2b31` |
| `0a0c92726b8cd4e1 / scan_internal` | `ecaec72ae14a91aa61df618f750026fd6210e43f68db2ca087072a3ebbff9957` |
| `0a0c92726b8cd4e1 / registry_uplink` | `a185495585827583aca5558d44d1e02ca25c710c88e59a10e83146c635b3a609` |
| `9bef4d56d7aad6d7 / auth_internal` | `a95491277245d1fbafd240d01e1e06f11ef8e86b08939fb2826f1f7fa1d37ecc` |
| `9bef4d56d7aad6d7 / scan_internal` | `5a684b86b4e50107c78434292fa70a953fb8bd667c37ef765760ce570c5ce17d` |
| `9bef4d56d7aad6d7 / registry_uplink` | `3cf617f0a9ddfedc516946da7b5fb96df769e2edc7ac3799b1578ef48ad57c21` |
| `832cb6115c24c136 / auth_internal` | `c8a2ecac8504f39c2e783062b914167633540515b6016b39a1c126c75854809b` |
| `832cb6115c24c136 / scan_internal` | `3f749b590839cd394b0691eae4490c27a781695cfa823602582e8041c7a6a2ad` |
| `832cb6115c24c136 / registry_uplink` | `f62b5cddbeebe992bf2e49cd973810f937bf79d46bbf5a7543bf65fa22e2d877` |

The names, labels, internal flags and allocations are consistent with distinct isolated Compose projects, not the protected project names. Labels are current metadata, **not independently sealed historical custody**; the reviewed historical documents do not bind these nine full network IDs individually. This is a further reason not to infer a network discard release from retired container identities.

### Historical provenance and retention evidence

1. [Exact stopped-container plan](deployment/stopped-container-retirement-20261015.json), lines 3–21, binds five exited containers in each of the three exact namespaces to the following proof images. Its scope says: **“Preserve all volumes, networks, images, host evidence and recovery material.”** It separately excludes history/qualification/source actors and keeps prior failures/HOLDs unresolved. A container-only retirement plan is not network-retirement authority.
2. [Continuation handoff](deployment/continuation-handoff-20261015.md), lines 15–31, records actual retirement of those 15 failed-proof containers plus two init containers, then the three corresponding proof images. It records network IDs reconciled unchanged and no networks/recovery material deleted. This supersedes the old container-retention counts for the retired actors, **not** the preserved-network scope.
3. Sanitized proof receipts were read as text/selected public JSON fields only. Exact namespace → image binding comes from the container plan; image → attempt binding comes from the receipts (the sanitized receipts do not themselves expose a network-ID inventory):

   | Exact namespace suffix | Historical attempt / sanitized receipt | Bound historical image ID | Receipt retention |
   | --- | --- | --- | --- |
   | `0a0c92726b8cd4e1` | `run-20261010-proof-r6/sanitized-evidence.json` | `sha256:918fb7c6c651c8ab2f94bdf1648a0f99edf1ec2fd70c37d6179e932ede8816ea` | failed; retainedOnFailure=true; removed=false; 5 containers / 3 networks / 2 volumes |
   | `9bef4d56d7aad6d7` | `run-20261009-proof-r5/sanitized-evidence.json` | `sha256:9c1f3e686fd0f49646a336cde7e0259b63e882bbbb7fbd7ccccc874f49038fcf` | failed; retainedOnFailure=true; removed=false; 5 / 3 / 2 |
   | `832cb6115c24c136` | `run-20261009-proof-r4/sanitized-evidence.json` | `sha256:7e25e7ad63be12517bd8fb88d88339b90a4bcd8344e2280f0146f7a7819020b1` | failed; retainedOnFailure=true; removed=false; 5 / 3 / 2 |

   Receipt paths are under workspace directory `oldstartup/cve14-proof-workspaces/`, outside the `diplom` repository. All three say `kind=isolated-cve14-combined-proof`, `passed=false`, `liveTouched=false`. These are historical scope reports, not a current private-state preservation guarantee. No `own.env`, `own-recovery.json`, generated compose, raw logs, database or context contents were opened.
4. For distinction from R10, `run-20261010-proof-r10/sanitized-evidence.json` reports image `sha256:c09ce4c8e6185784fad2c263b462952092fa89058d16363ebd543e0cd4bbd50d`, passed=true, removed=true, retainedOnFailure=false and 0/0/0 remaining. [Rollout evidence addendum](deployment/rollout-evidence-update-20261010.md), lines 5–12 and 55–57, explicitly distinguishes accepted R10 from failed retained CVE attempts. These nine must not be described as R10's successful cleanup leftovers or use its cleanup result as their disposal authority. No R10/history proof was run.
5. No reviewed document/receipt found here releases the nine networks after the container/image retirement. Earlier blanket protection is not silently erased because their endpoint maps are now empty. This is a scoped uncertainty finding, not proof that no release can exist elsewhere.

Two additional sanitized receipts, r7 and r8, were read during attribution checking; both report different image IDs and zero remaining network counts. Neither supplies a release or identity binding for the requested nine. Their workspaces were not executed or modified.

### Executed network evidence command

Working directory `oldstartup/diplom`, timeout 10 seconds. **Only** Name/Id/Labels/Internal/IPAM/Containers were requested; no full network JSON or other network fields, no global network list, Docker info/config read, or container inspection was used in this extension.

```sh
docker network inspect --format '{{json .Name}} {{json .Id}} {{json .Labels}} {{json .Internal}} {{json .IPAM}} {{json .Containers}}' dip-cve14-proof-0a0c92726b8cd4e1_auth_internal dip-cve14-proof-0a0c92726b8cd4e1_scan_internal dip-cve14-proof-0a0c92726b8cd4e1_registry_uplink dip-cve14-proof-9bef4d56d7aad6d7_auth_internal dip-cve14-proof-9bef4d56d7aad6d7_scan_internal dip-cve14-proof-9bef4d56d7aad6d7_registry_uplink dip-cve14-proof-832cb6115c24c136_auth_internal dip-cve14-proof-832cb6115c24c136_scan_internal dip-cve14-proof-832cb6115c24c136_registry_uplink
```

For r4/r5/R10, a read-only Python standard-library JSON projection read the three exact `sanitized-evidence.json` files, selecting only `kind`, `imageId`, `passed`, `phase`, `liveTouched`, `cleanup`, `startedAt`, `finishedAt`. r6/r7/r8 used textual sanitized-receipt reads. No proof module was imported, no proof command repeated, and no private recovery file read.

### Safe address-pool handoff and protected scope

- **No confirmed disposable network IDs are handed off for deletion.** Coordinator-only deletion remains blocked on a narrowly reviewed release of the exact retained network topology above, including acknowledgement that it will no longer be available for the historical failed attempts. Broad unused-resource consent, empty endpoint maps and retired containers alone do not resolve the evidence gap.
- If that separate release is established, the coordinator must freshly recheck each exact Name/Id pair, expected project/role/full labels, Internal/IPAM and `Containers={}` under exclusive mutation coordination before considering a finite exact-ID removal. Identity/metadata drift, new endpoint, command error, unexpected retention or uncertainty means STOP/protect. No disconnect, stop, container deletion, prune or retry to overcome a conflict. This document supplies no removal command or execution approval.
- **All `dip-auth-stand`, `dip-history-wire`, `dip-local-full`, `dip-public-images` networks are protected**, including the two newly created public-stand networks reported by the coordinator. They were not inspected in this extension. All retained holders/actors, every volume, HOLD/lock/backup/private Env/key and R10/history dependency remain untouched. No unknown network is a fallback candidate.
- The nine inspected IPAM records show nine subnet allocations; releasing eligible networks would ordinarily return their allocations to Docker IPAM, but this assessment released none. It does not verify the host's full default pool, prove exhaustion as the cause, guarantee that any particular deletion would permit public-stand creation, or authorize a Docker restart/address-pool reconfiguration/new stand retry. No daemon setting or protected resource was changed to test that hypothesis.
- Validation in this extension: successful projected inspection of exactly nine networks, all endpoint maps empty; successful public sanitized-receipt parsing and cross-reference to the historical container-retirement plan. No application tests/builds/native proof/lifecycle commands were run. **Outcome: assessment complete; safe pool reclamation is not yet proved or executed.**
