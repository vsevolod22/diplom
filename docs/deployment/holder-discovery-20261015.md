# Independent correctness review — bounded holder discovery, 2026-10-15

## Decision / frozen literal

**CORRECTNESS APPROVE ONE metadata-only discovery attempt, conditional on independent final security source/literal approval. NOT EXECUTED by this reviewer.** No concrete blocker was found in the inspected source/test pair or literal. Discovery is NOT qualification, adoption, recovery, a migration retry or permission to change the held state.

- Literal: `docs/deployment/holder-discovery-20261015.sh`.
- SHA-256: `e24a2dfcaceda1921aa5c53f670a853e5b8e99f6fb3561935acfc35f8606f568`.
- Required cwd: `/Users/vsevolod/Documents/startup/diplom`.
- After independent final security acceptance only: ONE parent `/bin/sh docs/deployment/holder-discovery-20261015.sh`, foreground, caller `timeout_ms=75000`.
- Shared60s, each metadata client<=10s, at most8 fixed calls. Transport stdout+stderr combined cap65536B per call, listing4096B, final closed public JSON<=4096B. No automatic fallback, second listing or retry. Filesystem calls are cooperative; the caller bound is required and does not prove kernel/daemon cancellation.

The user reports production script290486 failed in phaseholder with uncertain/manual true, then STOP. That operation is SPENT. This review makes no inference about holder identity, presence, lifecycle or underlying cause and authorizes no query by this reviewer. All prior spent files remain untouched.

## Actual source hashes

Public-file SHA-256 hashing matched:

| Source | SHA-256 |
| --- | --- |
| `server/deploy/trust/discover_preservation_holder.py` | `674dbe2f279a05b1263ae28cd2d62913fdcad608d90442fc7e47b506a571419d` |
| `server/deploy/trust/test_discover_preservation_holder.py` | `fcc460c988057d50c7a51138fa7ca64522aaa1b0b24f615582aea12e444085af` |
| Bound controller, hash-only | `b34dcd63a77d06d997b4c6bf61a36bc7fbe67d8129aa12f444d055a1b9f50438` |

The discovery source validates its source/test CLI pins and controller hash before Engine queries; it never imports or executes the controller. Isolated `-I -B` and bytecode-disabled operation are required. The frozen literal uses the requested fixed interpreter/socket prefix and exactly the five CLI arguments required by the source.

## Focused findings

1. **Bounded candidate selection, not known identity.** One `container ls --all --no-trunc` uses the exact namespace regex and ownership-label filter. Listing accepts only zero-to-two unique lowercase full IDs not in the fixed17 baseline; a third, duplicate, malformed or baseline ID refuses before image/original/candidate queries. Five original ID/image pairs agree with the accepted production bindings. The baseline is a fixed exclusion set, not a new live census or current-state guarantee.
2. **Fixed query set.** At most eight calls: filtered listing, old API image projection, five individually bound original container projections and one batch candidate projection. Zero candidates uses seven. The new candidates are explicitly unknown resources: their projected names/image/labels/command/security/resources/mounts are compared into fixed observation flags, not adopted. No caller-supplied arbitrary IDs, shell, SQL, exec/cp/logs/stats, create/start/stop/rm or resource mutation is reachable through the CLI path.
3. **Public output boundary.** Formats select individual metadata fields, not full Config/State or Env/State.Error. Child stderr is counted privately and never printed. Public JSON includes candidate IDs, normalized fixed state flags, old-role image-match flags and fixed comparison groups; it omits image hashes, names, labels, paths, commands, raw stderr and exception text. `Env:"NOT_OBSERVED"` and `fullQualification:"NOT_CLAIMED"` remain explicit. Original API mount metadata supplies any materialized-volume baseline; no private volume filesystem is probed or path alias guessed.
4. **Created versus materialized is kept distinct.** Host-declared mounts and actual materialized mounts are separate flags. Created/no-mount/no-network state can be observed without claiming actual mount/network qualification. Group mismatch does not turn discovery into adoption or prevent reporting other bounded observations. The fixed envelope omits Env and other full-qualifier checks deliberately; even all true flags are insufficient to resume or execute anything.
5. **Directory metadata only.** At most one unambiguous grammar-checked label-derived backup name is used. Multiple names produce `AMBIGUOUS_NOT_OBSERVED`; no labels produce `NOT_OBSERVED`. The source checks `.local-auth` and that one directory via owner0700, nofollow directory FDs and stable FD/path stamps, without enumeration or file/content reads. A metadata refusal is returned as `REFUSED` while discovery can still complete; this is not proof of a safe recovery directory. The directory name is not output, no lock/recovery file is inspected, and no directory is created/chmodded/adopted.
6. **Endpoint/config and failures.** Each child receives a clean fixed five-key environment, explicit socket argument and empty context. Docker config points at the public source directory only after source gate refuses any existing config.json there; ambient private Docker config is not selected. Transport failure has closed category/checkpoint output and no fallback. Client process-group kill is CLIENT-only cancellation, not a container action. One-shot guards prevent reuse within the process.

The holder constants used for comparisons match the pinned controller's public holder contract (namespace/label, old API image, node timeout command, security, resources and fixed source mounts). Matching those constants establishes an envelope observation, not ownership/adoption authority for an unknown candidate.

## Evidence and limits

Read the full discovery/test source in bounded sections. User attributes eleven inert tests with PASS to the author; this reviewer ran none. Inspected tests cover listing bounds/exclusions, zero/two candidates, no-follow directory-only reads, output privacy, mismatched groups, materialized-baseline refusal, clean transport environment/caps, source-before-client checks and closed argument failures.

Expected successful code is `DISCOVERED_NOT_ADOPTED`, not QUALIFIED, recovered or migrated. No actual discovery result or ID is claimed. Stop after this one result; refusal/timeout/incomplete receipt grants no further query, cleanup, lifecycle action, holder adoption, private read or production retry. Existing HOLD/manual reconciliation remains in force regardless of discovery success.

Reviewer activity was public source/test inspection, public hashing and creation of ONLY this new shell/review pair. No tests/imports/scripts, Docker/HTTP/native/provider operations, private Env/DB/log/recovery reads, source/Git/tracker writes or held-state changes were performed.
