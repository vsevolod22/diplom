# Independent correctness review — ONE holder qualification metadata diagnostic

## Decision / frozen literal

**CORRECTNESS APPROVE ONE new no-persistent-write diagnostic attempt, conditional on independent security acceptance of these exact sources and literal. NOT EXECUTED by this reviewer.** This is classification of observable metadata, not holder qualification, adoption, migration or renewed production authority.

- Literal: `docs/deployment/holder-qualification-diagnostic-20261015.sh`.
- Literal SHA-256: `aa6a199f0499a6afce9556cfa724d5daa2de5b4e4974630a013fb8ffd8d5fe07`.
- Required cwd: `/Users/vsevolod/Documents/startup/diplom`.
- After independent security acceptance only: `/bin/sh docs/deployment/holder-qualification-diagnostic-20261015.sh`, ONE foreground parent invocation, caller `timeout_ms=75000`.
- Shared60s; each client <=10s; fixed flow <=6 clients; combined stdout/stderr <=65536 bytes/client (listing4096); encoded receipt <=4096 bytes plus newline. No polling, fallback or retry. The external wall fence remains necessary for uninterruptible host/daemon I/O; client termination is not daemon cancellation.

User reports successor-R2 shell59fe was executed ONCE and failed holder / MIGRATION / PREDICATE_REFUSED, uncertain=true. Its authority is SPENT; no subsequent query is inferred. This review does not identify its cause, prove no prior SQL ran, or resolve any HOLD. Existing locks, journals, retained actors, backups and uncertain state must remain untouched.

## Exact public sources verified by SHA-256

All paths below are under `server/deploy/trust/`:

| File | SHA-256 |
| --- | --- |
| `diagnose_holder_qualification.py` | `e7af4d28088bb8b2ae1849887816d4b83f649125a9735d1c844734bc63c3ea44` |
| `test_diagnose_holder_qualification.py` | `63ff7df336db440511c0a716b8a4bccc65578bf1d220e4f22b0a0036e793d264` |
| `recreate_openrouter_key.py` | `72f6393d97b0a946bf2bb607e7f1d0c216d91fb36cfecf20fba9b83fd2c12994` |
| `test_recreate_openrouter_key.py` | `3abf97290344e9d18add867e07a378346922407885da373c43fde2f8a6c19ea2` |
| `discover_preservation_holder.py` | `4afb0bc484d34aca428fee956bd939d7b322727285eef0f721425849bb32a1f4` |
| `test_discover_preservation_holder.py` | `cc1a168804cb9a07f9c53724730bfbbaae7596c44c88743b0dc169f26a1bf312` |

The first four hashes are literal arguments; transport pair hashes are fixed in diagnostic source. Public file reads use bounded single-link owned non-group/world-writable regular files, no-follow directory/file descriptors, stable file FD/path metadata and final rehash. Controller/test caps512KiB, other public files64KiB. The controller is read/hash-only, NEVER imported or executed. Captured, verified transport bytes are compiled in an isolated module: its top level defines constants/functions/classes only; its main/discovery/private-metadata/source-gate routines are not called. Its stale historical controller pin is therefore not an active check in this diagnostic.

## Read boundary / privacy

The only Engine flow is:

1. ONE exact label `dip.key-preservation` plus anchored holder-name namespace listing, full IDs, cap4096. Fourth ID, duplicate, malformed ID or unterminated listing refuses before further queries. Empty listing returns an empty classification, not a global absence claim.
2. ONE exact OLD API image inspect for `sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c`: projected Id and Config Env/Labels/WorkingDir; image ID checked.
3. ONE inspect of ONLY `dip-auth-stand_auth_accounts` and `dip-auth-stand_scan_ledger`: projected volume metadata; exact two names/local driver+scope/no options/project label/distinct bounded absolute mountpoints establish the comparison baseline. Invalid baseline is NOT_AVAILABLE, dependent groups null; no path guessing or host volume probe.
4. At most three individually inspected full IDs from that listing, explicit Config/HostConfig/State/mount/network projection only; returned full ID must match. No generic inspect, State.Error, logs, exec, cp, create, start, stop, remove, SQL or application command.

Transport invokes only the fixed canonical Docker binary, verifying its frozen public metadata/hash before EACH child. Explicit socket and clean child environment/config directory avoid ambient Docker config; an existing source-directory config.json refuses without content read. Client stderr is drained, bounded and discarded, never parsed into public text. Timeout/error cleanup targets only its own CLI process group, not a container/resource. No host private metadata/content/Env/DB/recovery reads, journal writes, locks, pycache or backup creation are reachable. Output redirection to /dev/null and child pipes are not persistent state writes.

Config.Env from the image and matching-namespace candidates remains in memory for exact list/order/null equality, with bounded shape validation. Only true/false/null is emitted: no names, values, counts, lengths or hashes. Other projected operands also remain internal. Public results contain validated full IDs, closed state/receipt identifiers and 37 boolean/null groups only; no raw labels, names, paths, commands, exception operands or client streams escape. The main wrapper suppresses incidental stdout/stderr and emits a bounded JSON result.

## Comparison to current authoritative qualifier

Reviewed diagnostic source/test in full, frozen transport in full, and current `Controller.qualify_holder` (lines2305–2390), holder construction context and relevant instrumentation tests. Its 37 independent groups cover observable identity/image/config-label inheritance/UID, exact Env/CWD, Node argv, health/volumes, security/network/resources/tmpfs/restart/stop, running/unpaused state, declared mounts/bind options, actual mounts and actual tmpfs.

For this stopped-reconciliation migration profile the comparisons retain auth/data RW, exact volume names and fresh metadata mountpoints, helper RO, only literal host path or single `/host_mnt` prefix, exact declared/actual helper source agreement, no extra non-tmpfs destinations, and the same allowed tmpfs subset/uniqueness rule. It does not require two materialized tmpfs entries when the authoritative predicate does not. RUN_FALSE and RUN_TRUE are mutually exclusive observations, not an aggregate all-groups-pass requirement. UNPAUSED corresponds to the ordinary allow_paused=false call; it is not the relaxed paused variant.

**Not full predicate equivalence or qualification:** private journal metadata/helper ownership, exact intended helper name/backup label, in-process capabilities, stored historical volume/image baselines, prior HOLD/lock state and full surrounding fences are NOT observed. ID_IMAGE/LABELS validate namespace/form and observable defaults, not those private exact bindings. The diagnostic also applies bounded shape/type validation; malformed/missing operands can yield null rather than the controller's refusal/exception. Contemporary metadata equality is not proof of equality to the failed invocation's cached baselines. Never interpret all observable matches as permission to adopt/run/remove a holder, or infer which predicate first failed historically.

Success vocabulary is `HOLDERS_CLASSIFIED_NOT_QUALIFIED`, `fullQualification=NOT_CLAIMED`, `privateBindings=NOT_OBSERVED`, `adopted=false`, `Env=EQUALITY_ONLY_PRIVATE`. Success means the bounded diagnostic completed, not that any candidate passed qualification. Refusal is a closed stage/category, never raw error text. No actual diagnostic result is claimed here.

## Validation and next boundary

Static public-source/test inspection and public SHA-256 commands only. Inspected inert tests cover independent drift, private canaries, Env order/null, mount aliases, absent baseline, exact six-client flow, fourth/duplicate/malformed listing refusal and source-gate-before-clients. **No tests/imports/runtime/Docker/private reads were performed; inspected tests are not PASS evidence.** No complete historical controller byte-diff is claimed. No concrete blocker found to this narrow diagnostic; no broader controller/production acceptance is implied.

After final security acceptance, ONE parent invocation only under the stated fence, then STOP and record its closed receipt. No follow-up query, retry, source repinning, cleanup, repair, adoption or production operation follows automatically from any result. Changed source bytes/literal require fresh review. Sole writes by this reviewer are this NEW report and paired NEW shell; all spent command files/source/Git/tracker state remain unchanged. No remote artifact ID is claimed.
