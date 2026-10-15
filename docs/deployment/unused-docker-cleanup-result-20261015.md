# Actual exact unused-image cleanup result — 2026-10-15

## Closed result and attribution

**Cleanup completed: parent reports ONE execution, exit0, all seven exact selected
images attempted and confirmed removed. Authority SPENT. Do not rerun.**

This is a documentation-only record of the actual parent-reported result, not an
independent daemon observation or a newly captured raw receipt. No runtime query,
private read, mutation, source/test change, or repeat execution occurred in this
result-document session. The cleanup source pair remains frozen.

Executed identities:

- Source `server/deploy/trust/cleanup_unused_docker.py` SHA256
  `8ffe4d3a4566ed30d969ce7b4c49857d275fc09882322fe3d98e82d47e339526`.
- Test `server/deploy/trust/test_cleanup_unused_docker.py` SHA256
  `5a4bdf17fd4a5f6a67ea58febf12264ae3da9194f05ee03f28fd8c50d6381a6d`.
- Exact version3 seven-image batch plan SHA256
  `3f46f8ec5076453e7efb2ec9a44703cbadf3f04cb7ba94af7f2a2d69ae4d1775`.
- Actual parent wrapper identifier SHA256 prefix `3bd321` as supplied; the full
  wrapper digest was not supplied in this result report and is not invented here.
- Removal authorization was the exclusive-held-stand unused-image scope, NOT a
  deployment-completed attestation. See
  [the held-stand plan](unused-docker-cleanup-held-stand-20261015.md).

## Actual reported closed receipt

The following records the supplied receipt fields and exact batch binding, not a
claim to reproduce every field or byte of the original output:

```json
{
  "ok": true,
  "planSha256": "3f46f8ec5076453e7efb2ec9a44703cbadf3f04cb7ba94af7f2a2d69ae4d1775",
  "attemptedImages": [
    "sha256:15197100f752c1fe10615a85b1b33633dd35eb716dce1789320791de86693032",
    "sha256:23ffa5aa37f93186a943c5c92b47d2d6eec2df4da37729057c86ab3dd6fb790a",
    "sha256:4ca2b8083033b718f490ae08ff614c3f593e35d782130e2e5c7f46acc86dcf40",
    "sha256:4ca80cff07620171413cdd48c7697547f04829089c5937430e970fc20ac64b5d",
    "sha256:63602c1f062b998107d827faaadfb9acc486f445d9775a587f5ccfbb65864d25",
    "sha256:d060e223a5e927c134ffbc5c885eea6a0cd9bdbaf1bf218eefc6478b20c6eb25",
    "sha256:edc9f4875438b5caba2722a67ccf1508fa001db4199b0ef3362bf1b767ce1260"
  ],
  "confirmedRemovedImages": [
    "sha256:15197100f752c1fe10615a85b1b33633dd35eb716dce1789320791de86693032",
    "sha256:23ffa5aa37f93186a943c5c92b47d2d6eec2df4da37729057c86ab3dd6fb790a",
    "sha256:4ca2b8083033b718f490ae08ff614c3f593e35d782130e2e5c7f46acc86dcf40",
    "sha256:4ca80cff07620171413cdd48c7697547f04829089c5937430e970fc20ac64b5d",
    "sha256:63602c1f062b998107d827faaadfb9acc486f445d9775a587f5ccfbb65864d25",
    "sha256:d060e223a5e927c134ffbc5c885eea6a0cd9bdbaf1bf218eefc6478b20c6eb25",
    "sha256:edc9f4875438b5caba2722a67ccf1508fa001db4199b0ef3362bf1b767ce1260"
  ],
  "notAttemptedImages": [],
  "uncertainImage": null,
  "postInventory": false
}
```

No container or volume removal occurred in this IMAGE batch, as reported by the
parent. The exact4dc holder retirement was a SEPARATE earlier parent-acknowledged
success; it is not part of these seven image acknowledgements and was not queried
or reverified here.

## Limits: what this completion does NOT establish

- **No GB/bytes freed claim.** Image sizes, shared layers, build cache and physical
  disk reclamation were not measured. Seven deletion acknowledgements are not a
  measurement of recovered storage.
- **No post-inventory.** `postInventory:false`; no current global container/image
  counts, final daemon graph, absence of other unused objects, or fresh state of
  preserved resources is claimed. The earlier18-container/24-image inventory is
  historical and SPENT, not a current observation or basis for subtracting counts.
- Scope excluded all eight original/candidate pins, retained c09ce4, untagged
  parents, other base images, all containers and volumes. This is the executed
  plan's preservation boundary, NOT a new post-cleanup integrity qualification.
- Source-build namespace/dataflow evidence did not establish historical custody
  or contents of every individual image. Exact USER discard authorization and the
  helper's fresh immutable all-container reference fence were the removal basis;
  tag names alone were not ownership proof.
- **No deployment closure.** R3 was reported failed at HOLDER_WRITERS_PRE before
  new-holder creation; deployment was NOT complete when cleanup was prioritized.
  Successful image cleanup does not complete deployment, qualify a holder, prove
  DB preservation/migration/readiness, start services, or activate a provider.
- No HOLD/lock/backup release, restore, additional cleanup, query, retry or
  automatic continuation is authorized by this result. Existing maintenance
  constraints remain; all execution authority for this batch is SPENT.

## Future accumulation prevention — recommendation ONLY

A small, separately reviewed lifecycle change in the PUBLIC runner
`server/deploy/proof/cve14-combined-proof.py` would address the source of this
accumulation: its documented policy retains unique build tags/cache even after
successful own-resource cleanup.

Record each run's exact built image ID, tag and source seal as soon as build
identity is obtained, rather than rediscovering ownership later by tag prefix.
After successful cleanup of that run's own containers, remove only its explicitly
disposable, freshly unreferenced built image with non-force `image rm --no-prune`.
Keep failed-run resources and intentionally retained proof/history/recovery
fixtures (including c09ce4) until separately reviewed release; never auto-delete
protected dependency bases, volumes or untagged parents. Stop/report on conflict
or uncertainty; do not introduce blanket prune or force.

Apply the same explicit disposable-versus-retained decision to diagnostic-build
outputs. Recording exact identities at creation would avoid the historical-custody
ambiguity encountered here. This is a recommendation, not implemented behavior,
a new cleanup grant, or permission to rerun the proof/diagnostic runner. No runner
source or unrelated files were changed.
