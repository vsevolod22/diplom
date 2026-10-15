# Independent correctness review — ONE unused-Docker inventory ONLY

## Decision / exact literal

**CORRECTNESS APPROVE ONE inventory-only invocation, conditional on independent final security acceptance of this exact source/literal. NOT EXECUTED.** No concrete blocker found in the selected two-listing route. The source's separate removal branch is NOT approved and no deletion candidate/plan is selected or authorized by this inventory.

- Source `server/deploy/trust/cleanup_unused_docker.py`: `ec6ae691cc31eed7dd049cb80299e45c3ba2c5b280713b88a297db740a04dfcd`.
- Test `server/deploy/trust/test_cleanup_unused_docker.py`: `51f1890f2acb655a88ac730ae6536e7ebfed523b866a0f5e08be8bc027293bb5`.
- Frozen literal: `docs/deployment/unused-docker-inventory-20261015.sh`.
- Literal SHA-256: `8c53cfcc5b46ef9732a28117b86ed2378057a07fd689de1e985a4dea4271c822`.
- Required cwd `/Users/vsevolod/Documents/startup/diplom`.
- After independent security acceptance only: parent `/bin/sh docs/deployment/unused-docker-inventory-20261015.sh`, ONE foreground invocation, caller `timeout_ms=75000`.
- Shared60s/client10s; <=2 fixed clients; <=80 containers/100 image ROWS,32768 combined stdout/stderr bytes per client, <=65536 aggregate transport bytes and <=65536 public output bytes including newline. External fence remains necessary for uninterruptible host/daemon I/O; no guaranteed runtime or cancellation claim.

## Reachable route and safe fields

Exact five-argument CLI selects --inventory-once and returns no plan; main dispatches ONLY Cleanup.inventory. It cannot select the separate remove route without changing the reviewed literal and adding its different action/consent/plan arguments. No automatic candidate selection, age/name heuristic or fallback occurs. No removal CLI/plan is frozen here.

Only clients are fixed:

1. container ls --all --no-trunc --size, projecting ID, listed Image string, State, Names and Size.
2. image ls --all --no-trunc, projecting ID, Repository, Tag and Size.

No container/image inspect, Env, commands/args, labels, mounts, logs, State.Error, exec, HTTP, SQL, provider, host private files or content are read. --size asks the Engine for size information; it may be slow and can timeout/refuse within this envelope. No volumes/networks/build-cache listing, write, resource removal or prune. Source code contains a removal implementation, but it is unreachable from this literal's selected branch and is outside this acceptance.

Each listing is bounded, strict UTF-8 JSON-line parsed with duplicate object keys, floating/non-finite JSON, malformed/extra fields, duplicate IDs/names/rows/tags, unknown states and inconsistent image sizes rejected. Container IDs/full image IDs and safe name/text fields are validated before public output. Untagged image rows are explicitly represented as no tags; no untagged eligibility is inferred. Multiple tag rows are grouped by image identity, with row count capped before grouping. Receipt amplification from listedReferences remains subject to the final64KiB output cap and can refuse safely, with no mutation.

## Source loading / privacy / attribution

Only the exact public source/test plus frozen transport pair are read, with bounded owned single-link regular-file/no-follow stable FD/path/ancestry checks. All four hashes were independently measured. Frozen transport pins are `4afb0bc484d34aca428fee956bd939d7b322727285eef0f721425849bb32a1f4` / `cc1a168804cb9a07f9c53724730bfbbaae7596c44c88743b0dc169f26a1bf312`. Its captured verified bytes execute definitions only; its historical controller/source gate/discovery/private-metadata/main functions are not called. No controller, app, helper or test is executed by this path.

Transport verifies the fixed canonical Docker binary/hash before each child, uses the explicit socket and clean child environment/config directory. Source-directory config.json existence, including symlink, refuses metadata-only before loading and before EACH child. Ambient Docker config/contexts are not selected. Raw child stderr is capped/drained/discarded; failure output contains fixed checkpoint/category only, never raw exceptions or client streams. No retry or compensating mutation follows a failure. Source pins are loaded once before calls, not a claimed final on-disk rehash.

## Do NOT infer unused/deletable resources

Container ls Image can be a mutable tag or image display string, NOT authoritative immutable reference evidence. listedReferences uses listed ID/tag matching only and may be stale/incomplete even when it matches. Results explicitly carry referencesAuthoritative=false and removalAuthorized=false. Empty matches, stopped actors, dangling/intermediate images and virtual sizes do NOT establish deletability or reclaimable-byte totals. No parent-layer closure, ownership/proof/recovery role or actual non-use is qualified by these two listings. Separate exact-plan review/fresh guards are required before any later removal; no blanket prune consent is inferred.

## Validation / relation to retirement

Read full public helper source, selected inventory/parsing/source-loading/output test sections and frozen transport context. Tests cover two calls, row/byte caps, bad/private extra fields, tag ambiguity, duplicate rows/tags, safe projections and source-gate-before-child failures. No tests/imports/runtime/private reads were run; inspected test source is not PASS evidence. No remote artifact ID claimed.

This is independent of the ONE exact paused-holder retirement. Do not chain either script automatically. In particular this inventory approval is NOT a follow-up-query exception after an ambiguous removal; STOP/manual review still governs that outcome. Successful inventory grants no retry, new query, deletion, migration or provider operation. Only this NEW report/literal and the separately owned retirement review/literal were written; no source/previous command/Git/tracker changes.
