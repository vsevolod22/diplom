# Independent correctness review — holder discovery R2, 2026-10-15

## Decision / frozen literal

**CORRECTNESS APPROVE ONE new bounded metadata-only discovery attempt, conditional on independent final security approval of the exact source/literal. NOT EXECUTED by this reviewer.** No concrete blocker was found in the fixed executable guard, transport changes or retained discovery boundary. This is not holder qualification/adoption, recovery, retry authority for a spent command or permission to change held state.

- Literal: `docs/deployment/holder-discovery-20261015-r2.sh`.
- SHA-256: `27410e3a82d2b3e87ea77ac2a566cd23fedc3cf32c90a2a733b1a8881dfd061c`.
- Required cwd: `/Users/vsevolod/Documents/startup/diplom`.
- After independent final security approval only: ONE parent foreground `/bin/sh docs/deployment/holder-discovery-20261015-r2.sh`, caller `timeout_ms=75000`.
- Shared60s, client10s, at most8 fixed metadata clients; transport65536B per call/listing4096B, public receipt4096B. Executable hashing is charged to shared60s, not a new budget. No search, fallback, second listing or retry. Cooperative filesystem checks do not prove universal completion/preemption; external caller bound remains required.

Direct diff confirms executable arguments differ from the spent discovery literal ONLY in the source/test hashes. Two header comments identify R2/spent attribution. Interpreter/socket/environment, action, argument order and scope remain unchanged. Old spent shell SHA e24a remains exact and its files were not edited.

## Attributed observation, not inferred state

User reports the prior e24a invocation failed at LIST/UNEXPECTED, yielding no actual states. Production290486 remains SPENT after reported phaseholder/uncertain/manualtrue. STOP/HOLD/manual reconciliation are not lifted. No resource identity, absence, lifecycle, mount materialization or production failure cause is inferred.

User separately reports harmless host command-location observation `/opt/homebrew/bin/docker`, resolving to canonical `/opt/homebrew/Cellar/docker/28.1.1/bin/docker`, with stable public hash/metadata. The prior source's restricted PATH omitted that location, a concrete static launch defect. This reviewer did not query, read, hash or execute the actual host binary; the measurement is attributed to the user/author, not fabricated independent evidence.

## Exact source binding

Actual public source hashing matched:

| Public source | SHA-256 |
| --- | --- |
| `server/deploy/trust/discover_preservation_holder.py` | `4afb0bc484d34aca428fee956bd939d7b322727285eef0f721425849bb32a1f4` |
| `server/deploy/trust/test_discover_preservation_holder.py` | `cc1a168804cb9a07f9c53724730bfbbaae7596c44c88743b0dc169f26a1bf312` |
| Bound controller, hash-only | `b34dcd63a77d06d997b4c6bf61a36bc7fbe67d8129aa12f444d055a1b9f50438` |

Source hardcodes canonical Docker path above and SHA-256 `5cfddb229b6278953fdbb5016619e0f786ac8291969183fb28e3717a92f8bd52`. Its full expected stamp is `(16777233,1321905,0o100555,1,501,80,28011650,1744969487000000000,1746429174027377498)` (device, inode, mode, nlink, uid, gid, size, mtime_ns, ctime_ns). This is an exact refusal-oriented host binding; a changed installation must refuse, not be silently resolved/adopted.

## Focused findings

1. **No executable search.** Before EACH child, `verify_executable()` checks exact lstat stamp, nofollow/stable single-link public-file hash through nofollow directory traversal, then exact lstat again and shared deadline. Popen receives that literal canonical path, not `docker` or the Homebrew symlink. No PATH fallback/ambient-context resolution is added. Exact binary checks reduce drift risk but are not an atomic FD-bound exec or adversarial host-race guarantee.
2. **Closed execution failures.** Missing/denied/OS spawn failures and executable-identity mismatch map to fixed categories without path/error text. Binary verification occurs before child launch; failure launches no child. Popen failure does not attempt to kill a nonexistent process. Any successful child still uses explicit fixed socket, stdinDEVNULL, clean five-key child environment and public config-directory absence guard; no ambient private Docker config is intentionally selected.
3. **First failure survives cleanup.** Output-cap/nonzero/timeout failures remain primary even if client kill/wait/close also fails. Client timeout is explicit; remaining selector/wait time is clamped and zero refuses before a negative wait. Client process-group cleanup is not a container action. Close-only failure refuses rather than returning successful output. No cleanup error enables further queries or fallback.
4. **Discovery-only scope preserved.** One fixed namespace+label listing, <=2 unique new non-baseline IDs (third refuses), old image projection, five original ID projections and at most one candidate batch remain. No full Config/State, Env, State.Error, logs, SQL, exec/cp or container lifecycle/resource operation is added. Projected metadata stays private except safe candidate IDs/normalized states/fixed groups. Directory work remains at most one unambiguous label-derived owner0700 directory plus root metadata, nofollow/stable and without enumeration/content/lock/recovery reads. A directory/group mismatch remains an observation, not qualification.
5. **No claims from flags.** Success remains `DISCOVERED_NOT_ADOPTED`, `fullQualification:"NOT_CLAIMED"`, `Env:"NOT_OBSERVED"`. Created-not-materialized and materialized mount/network observations remain separate. Even every true group gives no authority to adopt, run, resume, repair or remove anything.

## Validation / next boundary

Inspected current source including complete transport/discovery route and focused new inert test source for fixed binary/hash/stat checks, symlink/content/metadata refusal, closed spawn errors, no fallback, cleanup-first-failure preservation and deadline crossing. User attributes sixteen inert tests PASS to the author; this reviewer ran none and did not import any source.

Only this new R2 shell/review pair was written. Reviewer activity was public-source/test reads, public source hashing and literal diff/hash; no runtime/Docker/native/provider/script/test execution, host-binary read, private Env/DB/log/recovery read, source/Git/tracker write or held-state change.

After independent security acceptance, ONE parent discovery invocation is source-approved. Stop after its result. No actual discovery receipt or candidate ID is claimed. Refusal/timeout/incomplete receipt grants no extra query, fallback, cleanup, adoption or production retry; existing HOLD remains.
