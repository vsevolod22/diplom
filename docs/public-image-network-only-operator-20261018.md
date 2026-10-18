# Isolated public-image stand: network-only reconciliation handoff — 2026-10-18

## Status and boundaries

**Source/tests ready for independent review; live reconciliation NOT performed and NOT yet approved by an independent reviewer.** No Docker command, live private-state read, secret rotation, launch, network deletion, staging or commit was performed for this change. Test launcher calls use injected Docker fixtures and temporary roots; Docker-adapter tests inject the subprocess implementation.

The following is **coordinator-reported state, not independently observed by this agent**:

- Original `dip-local-full` remains running and must remain untouched.
- Isolated `dip-public-images` has an endpoint-bound `.local-public-images/.operation.lock/mutation.json` with phase `start-outcome-unconfirmed`, plus `start-submission.json` and `compose.images.json`.
- No isolated containers (including stopped containers) or volumes exist; exactly two own empty networks remain: `dip-public-images_auth_internal` and `dip-public-images_registry_uplink`.
- The four own built image IDs have already been validated by the coordinator.

The coordinator's separately approved deletion of **nine exact retained CVE networks** is outside this implementation. This command neither performs nor authorizes that deletion. It does not inspect legacy network objects, containers, volumes, environments or JWTs. Namespace census uses names/project-label projections; only the two exact isolated network names are inspected.

## Reviewed invocation required

From the `diplom` repository root, **after independent review accepts these exact sources**, the coordinator may invoke:

```sh
node scripts/public-image-stand.mjs reconcile-network-only --ack-no-services
```

Do not invoke this command while any prior launcher/client or other host operation can still be running. The acknowledgement explicitly attests that the original launcher command has returned, outstanding work has settled after a **long operator-observed quiescence**, and no concurrent launcher/resource writer is active. This is an operator prerequisite, not something that a few Docker snapshots can prove. A timed-out client alone does not establish daemon quiescence. No host process environment is inspected.

This is **not** `reconcile-build-only`, a force-unlock, an automatic retry, or retained-stand activation. It is intentionally restricted to the exact two-network partial-start case above. A missing network, any additional own network, any container/volume, or any identity/configuration mismatch refuses the operation. Do not edit markers, erase locks, reset state or widen the predicates to make a refusal pass.

On successful reconciliation, a later **separate** coordinator invocation can resume ordinary guarded startup without rebuilding:

```sh
node scripts/public-image-stand.mjs up
```

Reconciliation itself cannot start/build/pull/stop/delete services or mutate networks. Ordinary `up` does not auto-reconcile any HOLD. The later startup still needs its own real runtime/postflight and native/browser/Trivy proof; no such proof is claimed here. Accounts are new and separate at `http://127.0.0.1:8081`; this remains isolated qualification, **not production acceptance**. No old database is copied or migrated. Existing refresh/scheduler tooling must not control this stand; its public CVE release is pinned and manual refresh remains unsupported.

## Closed admission policy

The new command requires all of the following on every relevant proof round:

1. Existing owned private state only; no secret/profile/state creation. Both root ignore guards and Dockerfile-specific ignore-override guards remain mandatory. Only exact start marker/submission fields, phases and canonical bytes are accepted, with a mandatory matching local Unix endpoint. Build-only eligibility is unchanged and still refuses start evidence, pins and networks.
2. One resolved local Unix Docker endpoint pinned into **every subsequent Docker command**, including Compose; context/TLS selector overrides are removed. No real JWT or inherited provider/scanner/hook environment is supplied for config rendering: only the nonsecret placeholder is used.
3. Exact original lock records and stable profile/JWT/source/CVE/pin file bytes and identities. Public CVE assets, when enabled, are reverified from the already-pinned public release/trust files; current activation and private signing keys are not consulted.
4. Projection-only census with zero isolated containers (including stopped) and volumes. Misleading project labels on foreign names also cause refusal, without container/volume inspection.
5. Exactly the two expected own network names before any network inspection. Their inspected IDs must remain unchanged, labels owned and recognized, endpoints empty, bridge/local/isolation flags correct, custom options absent, and default IPAM restricted to disjoint canonical private IPv4 subnet/default-gateway pairs. Dynamically assigned subnets are validated and snapshotted, not hardcoded. Both networks are retained byte-for-byte at the control-snapshot level; no connect/disconnect/remove/recreate command is issued.
6. Exactly four own local tags, independently validated image execution policy, no foreign tag/digest aliases or container references, and exact agreement with the four pinned own IDs. Reviewed exact containerd self-digests remain accepted. All six fixed service tag selections, including the reviewed BusyBox initializer tag, must equal the saved pins. Untrusted pin IDs are never used as inspection targets. BusyBox is allowed to be shared with unrelated initializers; that does not authorize references to the four own built images.
7. Compose's rendered pinned configuration still matches the independent normative profile. Existing reviewed Node/Python Linux boolean `ArgsEscaped` metadata, gateway base environment, web root working directory and empty/null Compose normalization allowances are preserved without allowing new startup hooks or arbitrary environment entries.

A snapshot does not prove that the original failed attempt never briefly executed a subsequently removed service. The receipt records current repeated proofs **plus the operator attestation**, never retrospective native success.

## Durable outcome and HOLD handling

The command uses its own `.reconcile-network-only.lock`, excludes the build-only guard, and shares only the existing bounded archival transaction/fences with build-only recovery. A total 60-second Docker-call budget applies, without retries. Proofs run before preparation, before/after original-lock archival and at guard release.

A completed record is stored under:

```text
.local-public-images/reconciliations/network-only-<32-hex-nonce>/
  acknowledgement.json
  completion.json
  original-operation.lock/
    mutation.json
    start-submission.json
  reconciliation-operation.lock/
    intent.json
```

The original operation directory and both original records are atomically moved, preserving their bytes/inodes. The durable receipt uses operation **`PARTIAL_NETWORKS_ONLY_NO_SERVICES`** and `originalOutcome: HOLD_PRESERVED`, **not PASS**. It binds the endpoint, source/profile/CVE hashes, file identities, start-submission hash/identity, original lock/marker identities, six image pins/hash/identity, four own image IDs, network snapshots and transaction nonce. The JWT is retained by identity checks; its value and hash are not included or printed. No nonce is injected into the pin file.

The completion hashes the acknowledgement and links it to the original mutation record. Files/directories are synced around archival boundaries. Interrupted preparation/commit retains the recovery guard and/or incomplete history; regular `up`/`stop` refuses such history. Failures before the durable archive intent can release only the newly created empty recovery guard, leaving the original HOLD intact. A precommit error after guard archival attempts to restore the exclusion barrier, without deleting original evidence. A console/output failure after durable completion does not roll back or rewrite completed receipts. Valid completed network-only history is accepted by later ordinary lifecycle operations.

If any command refuses or is interrupted, stop and return its **sanitized stage/category only** for review. Do not manually remove a lock. No generic recovery of incomplete reconciliation history is provided.

## Sanitized next-start diagnostics

A stand-owned bounded Docker adapter now drops raw exception/output/cause fields on failure. It returns only fixed categories: `network_pool`, `resources`, `image`, `runtime_health`, `timeout`, `docker_unavailable`, or `unclassified`. Mutation HOLD messages include a fixed `checkpoint` and `failure` category (`guard` for launcher policy refusal). These are troubleshooting hints, **never unlock/retry authority**. Raw Docker stderr, Compose config, container Env and JWTs must not be pasted into the handoff.

## Offline verification and review inputs

Initial network-only/adapter regression fixtures were run before the implementation and failed for the missing command/adapter; the completed fixture suite passes. Extended refusal fixtures cover wrong phase/endpoint/submission, unknown state entries, foreign/mislabeled/stopped resources, exact-name prefiltering, network authority/IPAM drift, arbitrary pins/unsafe image defaults/references, source/profile/JWT/CVE/pin/record/directory replacement, every archival checkpoint, altered original inodes, tampered/incomplete receipts, ordinary lifecycle refusal, completed-history acceptance and sanitized failure categories.

Executed from `diplom` (all bounded):

```sh
node --test scripts/test_public_image_stand.mjs
# 84 tests passed, 0 failed; approximately 5.7 s; 30 s command bound.

node --test scripts/test_public_image_stand.mjs scripts/test_local_stand.mjs scripts/test_refresh_local_cve.mjs scripts/test_schedule_local_cve.mjs
# 260 tests passed, 0 failed; approximately 15.6 s; 60 s command bound.

node --check scripts/public-image-stand.mjs
node --check scripts/test_public_image_stand.mjs
# Both passed; combined 10 s command bound.
```

Independent reviewer inputs:

- `scripts/public-image-stand.mjs`: owned sanitized adapter, new network-only validators, closed shared archive transaction, strict separate history schema, CLI and guard integration.
- `scripts/test_public_image_stand.mjs`: coordinator regressions retained plus adversarial network-only/diagnostic fixtures.
- This operator note. Read existing Compose/profile/legacy helpers as reference only; none was edited for this change.

SHA-256 of the exact source/test inputs after the passing checks:

```text
3dd8fb9116c1f33d9acca50aecb29eb46d796cedbcb62f9dd5f5dcadb700f761  scripts/public-image-stand.mjs
fb1289dea4a811cace49f161b77db92d7506c1e7d1c2f3e88111ec5b5750accf  scripts/test_public_image_stand.mjs
```

**Handoff gate:** independent source review first; coordinator-observed quiescence and the explicit acknowledgement second; live reconciliation only then. No real Docker/native/browser outcome has been established by this change.
