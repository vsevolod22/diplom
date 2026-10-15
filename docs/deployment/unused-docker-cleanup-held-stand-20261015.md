# Exact held-stand unused-image cleanup — 2026-10-15

## Current authority and status

Source/literal candidate for independent review; NOT EXECUTED here. USER reports
R3 failed at HOLDER_WRITERS_PRE before new-holder creation. Deployment is NOT
complete. STOP the prior post-deployment cleanup plan/literal; do not assert its
completed-deployment attestation. Historical docs remain unchanged. This version3
helper rejects version2 plans and the former consent flags outright.

USER now prioritizes exact unused-image cleanup independently of deployment.
The ONLY removal authorization flag is:
`--authorize-exclusive-held-stand-unused-images`.
It explicitly authorizes discarding the selected exact allowlisted images if the
fresh immutable all-container check finds no references, under continuing exclusive
maintenance HOLD and with NO concurrent daemon mutation. It is NOT a claim that
deployment completed, that historical custody was proved, or that names prove
ownership. No deployment completion assertion exists in the plan/code.

Parent owns the exclusive daemon-operation interval: no controller, deployment,
retirement or other daemon mutation may overlap cleanup preflight through final
removal. This helper neither reads/adopts/removes HOLD/locks nor establishes a new
locking framework. The flag asserts the operator's exclusive held-stand authority;
it does not probe private coordination state. Existing HOLD remains after cleanup.
No runtime/daemon query, mutation, private read or runner execution occurred here.
Inventory8c53 remains PASS/SPENT as reported; do NOT rerun it.

## Source scope and provenance distinction

The seven exact ID/tag pairs remain the ONLY allowlist; no namespace discovery or
name-based deletion selector exists. All five original and three candidate pins,
full c09ce4 history base, untagged parents, other base images, ALL containers and
ALL volumes remain outside deletion scope.

Pinned public source `server/deploy/proof/cve14-combined-proof.py`, SHA256
`945404d04957c86523de0490b5a65f17787010f6733a9a7ead1f76dfcfb4adc0`,
confirms the intended rebuildable public-source build dataflow: `public_read` /
`inventory` allowlisted source -> `context_files` / `make_context` -> `dockerfile`
-> `Runner.build`; `execute` creates the combined snapshot namespace and
`diagnose_build` the diagnostic snapshot namespace. Generated private runtime
env/storage/accounts/evidence are subsequent runtime work, not context inputs.
The runner is only read/hash/AST checked, never executed/imported.

This source evidence does NOT prove historical per-ID custody/content. Two IDs,
4ca80cff... (r3) and d060e223... (r2), are individually documented in the public
`evidence-register-20261009.md`; independent historical custody for the other five
was NOT established. The operative basis for discarding all seven is the explicit
USER authorization of those exact IDs plus the new authoritative zero-reference
check, not a false custody attestation or names alone. Namespace/source fields
constrain scope and document intended dataflow, not image-content proof.

If independent review accepts only the two publicly documented identities, select
the exact two-entry plan below BEFORE any execution. This is a manual review choice,
NOT automatic fallback after a failed seven-entry attempt.

## Actual operation (unchanged narrow batch mechanics)

1. Fresh complete image listing; ALL selected immutable IDs must exist, each with
   exactly its one literal expected tag. Any missing/changed/multiple/untagged
   binding refuses the ENTIRE batch before mutation.
2. Fresh all-container listing, ALL lifecycles, no filter; then one projection of
   ONLY `.Id` and immutable `.Image` for EVERY listed full ID. Complete unique
   membership required. A reference to ANY selected ID blocks ALL removals, even
   if display tags moved. Empty daemon skips the inspect. This is independent of
   spent8c53's non-authoritative displayed-tag relations.
3. Serial single-ID `image rm --no-prune <immutable-ID>`, non-force, in plan order.
   No multi-ID rm (Docker could continue after failure), prune, build, volume or
   container removal. `--no-prune` prevents cascading untagged-parent deletion;
   Docker's child/reference conflict checks are never bypassed.

Limits:80 containers/100 image rows; shared60s/client10s/external75s;
<=3 metadata calls x16384B + <=7 removal calls x2048B, INCLUDING discarded stderr:
<=10 calls/63488 transport bytes; receipt<=65536B. Captured verified discovery
transport, fixed binary/endpoint/config isolation and all source pins unchanged.

STOP on FIRST nonzero, timeout, cap or unexpected/ambiguous acknowledgement. No
later member, retry, fallback, rollback, compensation or post-query. Strict success
requires only the exact expected Untagged and Deleted lines. Partial receipt:
`planSha256`, `attemptedImages`, `confirmedRemovedImages`, `uncertainImage`,
`notAttemptedImages`. After any attempted/possibly attempted removal failure,
manual reconciliation/HOLD is required. Never reexecute the same spent invocation.

## Reviewed-code candidate hashes and validation

- `server/deploy/trust/cleanup_unused_docker.py`:
  `8ffe4d3a4566ed30d969ce7b4c49857d275fc09882322fe3d98e82d47e339526`
- `server/deploy/trust/test_cleanup_unused_docker.py`:
  `5a4bdf17fd4a5f6a67ea58febf12264ae3da9194f05ee03f28fd8c50d6381a6d`
- `python3 -I -B server/deploy/trust/test_cleanup_unused_docker.py`:
  **23 inert tests PASS**, author-attributed; process creation blocked. Includes
  new-only flag, old-plan/attestation refusal, exact two-ID subset, whole-batch
  reference fence, preservation guards, seven removals, bounds and partial STOP.

## Exact seven-image held-stand literal — independent review, NOT RUN here

Canonical JSON is1361 ASCII bytes with NO final newline. Plan SHA256
`3f46f8ec5076453e7efb2ec9a44703cbadf3f04cb7ba94af7f2a2d69ae4d1775`.
Required cwd `/Users/vsevolod/Documents/startup/diplom`, external
`timeout_ms=75000`. Parent only, exclusive maintenance HOLD/no concurrent daemon
mutation. NO deployment completion prerequisite. No approval is claimed by this doc.

```sh
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
server/deploy/trust/cleanup_unused_docker.py \
--remove-exact-batch-once \
--source-sha256 8ffe4d3a4566ed30d969ce7b4c49857d275fc09882322fe3d98e82d47e339526 \
--test-sha256 5a4bdf17fd4a5f6a67ea58febf12264ae3da9194f05ee03f28fd8c50d6381a6d \
--authorize-exclusive-held-stand-unused-images \
--plan-sha256 3f46f8ec5076453e7efb2ec9a44703cbadf3f04cb7ba94af7f2a2d69ae4d1775 \
--plan-json '{"images":[{"image":"sha256:15197100f752c1fe10615a85b1b33633dd35eb716dce1789320791de86693032","namespace":"combined-source-build","tag":"dip-cve14-snapshot-c68e78d102921bfc:local"},{"image":"sha256:23ffa5aa37f93186a943c5c92b47d2d6eec2df4da37729057c86ab3dd6fb790a","namespace":"combined-source-build","tag":"dip-cve14-snapshot-db0036568330ec7e:local"},{"image":"sha256:4ca2b8083033b718f490ae08ff614c3f593e35d782130e2e5c7f46acc86dcf40","namespace":"combined-source-build","tag":"dip-cve14-snapshot-d8fdd66d9bf40de5:local"},{"image":"sha256:4ca80cff07620171413cdd48c7697547f04829089c5937430e970fc20ac64b5d","namespace":"combined-source-build","tag":"dip-cve14-snapshot-50a215ff36203a77:local"},{"image":"sha256:63602c1f062b998107d827faaadfb9acc486f445d9775a587f5ccfbb65864d25","namespace":"diagnostic-source-build","tag":"dip-cve14-diag-snapshot-7c6ab13aed49881d:local"},{"image":"sha256:d060e223a5e927c134ffbc5c885eea6a0cd9bdbaf1bf218eefc6478b20c6eb25","namespace":"combined-source-build","tag":"dip-cve14-snapshot-50c9f4bae2cec49b:local"},{"image":"sha256:edc9f4875438b5caba2722a67ccf1508fa001db4199b0ef3362bf1b767ce1260","namespace":"combined-source-build","tag":"dip-cve14-snapshot-4b5a7fbb46389420:local"}],"source":{"path":"server/deploy/proof/cve14-combined-proof.py","sha256":"945404d04957c86523de0490b5a65f17787010f6733a9a7ead1f76dfcfb4adc0"},"version":3}'
```

## Optional two-ID plan, ONLY if independently selected instead

Same helper/source/test/authorization flag. Replace BOTH plan hash and entire
plan-json argument before execution. No command is run automatically on rejection
or failure. Canonical plan (no newline) SHA256:
`6a46b0c6125b517cc9a62269b7d00b97af7435a58158102e4fdc57f62c1f9a7e`.

```json
{"images":[{"image":"sha256:4ca80cff07620171413cdd48c7697547f04829089c5937430e970fc20ac64b5d","namespace":"combined-source-build","tag":"dip-cve14-snapshot-50a215ff36203a77:local"},{"image":"sha256:d060e223a5e927c134ffbc5c885eea6a0cd9bdbaf1bf218eefc6478b20c6eb25","namespace":"combined-source-build","tag":"dip-cve14-snapshot-50c9f4bae2cec49b:local"}],"source":{"path":"server/deploy/proof/cve14-combined-proof.py","sha256":"945404d04957c86523de0490b5a65f17787010f6733a9a7ead1f76dfcfb4adc0"},"version":3}
```
