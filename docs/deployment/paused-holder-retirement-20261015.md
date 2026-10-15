# Independent correctness review — exact paused-holder retirement

## Final decision: CORRECTNESS APPROVE ONE exact retirement

**APPROVE ONE parent invocation under the informed exact-target discard consent, conditional on independent final security acceptance of the exact source/literal and continued exclusive maintenance. NOT EXECUTED.** The prior TARGET_FINAL mount-order false-refusal is corrected; no concrete blocker remains in this reviewed path. This grants no migration/general-cleanup/retry authority.

- Final source SHA-256: `552c98e77a9ce6192ba05454566e32478a24b294f188ca1f0179049c3377bcc5`.
- Final test SHA-256: `5032740eb0998eb48e84a0e53caee5424d6aa515fbb1f6623ddd95266b55130c`.
- Frozen NEW literal: `docs/deployment/paused-holder-retirement-20261015.sh`.
- Literal SHA-256: `f46dfa1599c6224501981e6901d11387fb4b827c4847f92d41fa78a9f5d76c1d`.
- Required cwd: `/Users/vsevolod/Documents/startup/diplom`; parent `/bin/sh docs/deployment/paused-holder-retirement-20261015.sh`, ONE foreground invocation, caller `timeout_ms=75000`.
- Shared60s/client10s/<=5 fixed clients; combined streams65536B/client (remove4096); closed public JSON4096B plus newline. Host I/O is not universally interruptible; external fence remains necessary. No follow-up on attempted-removal ambiguity.

Historical review below rejected source `ba03e8fdc1cb1526d73c5a8325adacf2e244a58dfaa72c5da20d50f1dfa21710` / test `667560a5fc87a8f232dea917782a8917f05cb8b012d812dc870b449195749f1b` for this specific false refusal. No previous retirement shell was created or executed. That rejection record is preserved; it is not an additional spent operation.

User now explicitly consents to deletion of exact paused actor `4dc55f9708f1537fa369ea165aadd050c1f44a6570f0adccb93043d1467d1769`, including informed loss of rootfs/logs and possibly sole tmpfs recovery material. That closes the discard-consent issue; no repeated consent campaign is requested. It does not authorize arbitrary cleanup/prune or private reviewer reads. General unused-resource cleanup is outside this exact-target source/literal review.

## Historical requested correction — now resolved

In rejected sourceba03, lines248–250, run obtained a second exact-target projection and required:

`transport.canonical(final) == transport.canonical(initial)`

Transport canonical JSON sorts dictionary keys but preserves array order. Therefore otherwise identical target projections with a permutation ONLY of the outer `Mounts` array fail TARGET_FINAL. The correction just accepted in controller8ed5 handles precisely this representational dependency, but this new retirement comparator does not use equivalent multiset semantics. Actual Engine reordering here is NOT observed or claimed; source proves the conditional false refusal. It would occur safely BEFORE removal, not justify any retry.

Minimal correction: compare the complete remainder of both target projections exactly, and compare their actual `Mounts` arrays as sorted canonical bytes of COMPLETE records, preserving multiplicity, cardinality, every field/type/null/empty distinction and nested-list order. Validate list-of-dictionaries. Do not drop the mount comparison, use a set/subset/destination-only projection, normalize paths, adopt defaults, execute/import the controller, or weaken either qualify/custody check. Keep Env and every other projected field exact. Do not normalize unrelated arrays as a side effect.

Add ONE focused inert full-run fixture where ONLY the second target inspect permutes complete actual mount records and retirement reaches its single mocked remove. Retain census-independent changed-field/duplicate/drop rejection and no-more-calls-on-ambiguity checks. The existing final-drift tests cover name/paused/restart changes, but no actual Mounts permutation; the real source-gate/other tests do not cover this path. A comparator-only toy test is not a substitute. No broad suite/runtime reproduction is requested. Final changed pair requires new pin/literal review.

## Other reviewed boundaries — no concrete blocker found

- Exact argument shape and explicit discard flag precede source/private reads and clients. Target ID and OLD API image are hardcoded; no listing/newest/name fallback or arbitrary target argument exists.
- Public source-before-execution captures verified profile/transport bytes. Controller/test8ed5/f887 and helper323ca629 are hash-only, not executed. Their full pins and both profile/transport pairs were independently rehashed and match source PINS.
- Profile requires every observable sandbox group with explicit paused lifecycle substitutions, then strict PAUSED/running/paused/no-restart/no-OOM/no-dead/zero-int-exit predicates. Env stays internal/exact and rejects NODE_OPTIONS/NODE_PATH/duplicate/malformed settings. No config keys/values/hashes escape.
- Two journals, and ONLY those private files, are opened under the single validated label-derived directory. Label alone is not accepted as custody. Exact schemas bind BOTH records to actual target name, ID, fixed image, backup label, helper source/hash and migration profile; safe owned/no-follow stable directories/files,0700 child/0600 single-link leaves,4096-byte limits, distinct leaf inodes and matching ancestry are required. Both complete seals are reread/rechecked just before removal. This establishes the reviewed custody predicate if it passes; actual journals were NOT read by this reviewer and their existence/truth is not asserted. No namespace/directory enumeration, DB/backup/log content or HOLD writes.
- ExactClient limits ONE image inspect, ONE two-volume inspect, TWO exact-target inspects and ONE `rm --force FULL_ID` without -v. Fixed binary/socket/clean environment and byte/timeout limits inherited from the frozen transport. Marking removal_attempted before launch is conservative on binary/client failures.
- Source pins rechecked; final target/custody rechecked; only then removal. After any attempted remove there is NO further client, including on wrong acknowledgement/timeout/nonzero/output error. No unpause/start/stop/exec, restore, retry, fallback, extra cleanup or migration.
- Exact successful acknowledgement yields REMOVAL_ACKNOWLEDGED, NOT a post-inventory/preservation proof. preservationVerified=false/manualReconciliationRequired=true remain explicit. Ambiguous attempted removal reports uncertain=true and STOP. Partial output failures never manufacture certainty. Raw operands/stderr/paths/Env/journal hashes remain private.
- Limits remain shared60s/client10s/<=5 clients/caller75000ms; external fence necessary, no universal host I/O/daemon-cancellation guarantee. General unused-resource cleanup must receive its own finite exact plan; no prune authority implied.

This implementation intentionally has no post-inventory, on success or ambiguity. The earlier retirement draft's proposed postguard is therefore NOT supplied or claimed; the fixed mutation surface is only exact-target rm without volume deletion. All historical/current HOLDs, journals/backups and all other actors/images/volumes/network definitions are non-targets, not independently post-verified resources in this protocol.

## Final correction verification / validation limits

Final `target_metadata_signature` lines208–213 requires a dictionary and an actual Mounts list of <=8 dictionaries. It returns canonical bytes of the COMPLETE remainder of the record plus sorted canonical bytes for EACH complete actual mount. Thus only actual Mounts outer order and dictionary-key order are ignored. Duplicates/cardinality, unknown fields, missing/null/empty/type distinctions, literal paths and nested-list order remain significant. All other fields, including HostConfig.Mounts declaration order and Env order, remain exact. Current TARGET_FINAL lines255–258 compares those signatures AND reruns the paused sandbox qualifier before final journal-seal recheck/removal. No custody/access/identity check was dropped and no controller is executed.

Inspected added TargetMetadataTests and full-run fixtures: second-inspect-only actual mount permutation reaches exactly one mocked remove; changed complete records, unknown-field/drop/duplicate/nested-list differences and declared-mount reorder still refuse before removal. Earlier full source/journal/ambiguity test review remains applicable. User reports 13 selected inert tests PASS; this is attributed author evidence, not a reviewer execution. No tests/imports were run here and no Engine/native cause is established.

All seven fixed public dependency pins were independently rehashed and match PINS: controller8ed5/testf887, profile8e051/teste25c, transport4afb/testcc1a, helper323ca629. Final source/test and literal hashes also measured. Public file inspection/hash only; no Docker/native/HTTP/provider/history/private operations. The only writes in this follow-up are this owned report, its NEW shell and the separately scoped inventory review/literal. No source/previous command/Git/tracker changes.

After independent final security approval, ONE exact retirement invocation only; then record its closed receipt and STOP. REMOVAL_ACKNOWLEDGED is not a post-inventory/preservation claim. Attempted-removal failure/timeout/wrong acknowledgement/output ambiguity means HOLD/manual review, no further query/retry/fallback, including no automatic inventory script. All prior production/diagnostic authorities remain SPENT. The separately reviewed inventory literal is independent and must not be chained as an ambiguity follow-up. New source bytes require fresh review; no remote artifact ID claimed.
