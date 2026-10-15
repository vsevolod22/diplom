# Independent static finding — holder writer-fence mount ordering

## Disposition

**SOURCE ACCEPT — final narrow full-record canonical-multiset correction. No migration, recovery, retirement execution, new command or retry authority.** The original order-sensitive source defect is corrected in the final pair below; historical incident causation remains unproved.

Final controller SHA-256 `8ed5b4994997437afc5ff6d1bdcaecc19fc593f92940f2a7d7f6aed309ffa86c`, test `f8872067b4003d17e84a8dbb1bc25e4a7a74cc332b0f720cdae213b72f584d17`, independently measured during this follow-up. Original finding was made against controller `72f6393d97b0a946bf2bb607e7f1d0c216d91fb36cfecf20fba9b83fd2c12994`, test `3abf97290344e9d18add867e07a378346922407885da373c43fde2f8a6c19ea2`. No complete historical-controller byte diff is claimed.

## Attributed actual diagnostic evidence — SPENT

User reports ONE execution of diagnostic shell SHA-256 `088458ea480023c0e8a211adb7618e5ea53d53c86e6d7f0c2ad0ae0370fecdea`, now SPENT, returned two actors:

- `d9433f7ed0fc504a3521574668f15b7b3a0e8d283d61b9aa33d1e97187708a4f`: CREATED.
- `4dc55f9708f1537fa369ea165aadd050c1f44a6570f0adccb93043d1467d1769`: PAUSED.
- Reported non-lifecycle classifier groups matched; ENV exact equality true. No raw per-group receipt is reconstructed. RUN_TRUE/RUN_FALSE are alternative observations, never both required true.

This is parent-attributed evidence, not a fresh reviewer query. The diagnostic does not observe exact private holder journal/intent/backup bindings, adopt either actor, establish actual DB state, capture/export durability or SQL execution/non-execution. PAUSED does not establish who paused it, why, or when. All existing HOLDs, journals, actors, volumes, tmpfs and backups remain untouched. Production successor-R2 shell59fe is separately SPENT with holder/MIGRATION/PREDICATE_REFUSED, uncertain=true.

## Defect and precise mechanism

Original reviewed `Controller.writers` at source72f6393d, lines1981–2027 (historical defect, not the corrected current implementation):

1. Rechecks retained-created state and daemon identity.
2. If an in-process holder exists, `qualify_holder(running=True)` binds its exact ID, private journal metadata, identity/config/security/resources/state, declared mounts and materialized mounts; saves `qualified['Mounts']`.
3. Separately lists ALL container IDs and obtains projected id/running/Mounts through census inspect.
4. For the same holder ID requires `item['running'] is True and item['mounts'] == holder_mounts` (line2013).

Python list equality is positional. Two arrays `[auth, data, helper, ...]` and `[helper, auth, data, ...]` containing exactly the same full records fail that predicate. There is no intervening source-level guarantee establishing mount-array order as an identity property. An Engine response permutation across these separate calls would therefore cause a false refusal even though every full mount record is unchanged. This conditional failure mechanism is definite from source; **actual Engine reordering in this incident was NOT observed or proved**. JSON object key ordering already does not affect dictionary equality; the defect is the OUTER array order.

## Minimal safe correction contract

Accepted correction contract: replace ONLY that snapshot mount-array equality with order-independent equality of a **multiset of complete canonical records**:

- Validate both operands as bounded lists of mount dictionaries; malformed/uncanonicalizable inputs refuse closed, without raw operands in errors/output.
- Canonicalize each entire dictionary using deterministic JSON with sorted dictionary keys, finite JSON values, no field dropping/coercion. Compare sorted canonical record byte sequences (or an equivalent count-preserving multiset). The existing `encoded` serializer has sorted keys/allow_nan=false; any reuse must keep exceptions on the closed refusal path.
- Ignore ONLY order of entries in the OUTERMOST Mounts array and dictionary-key serialization order. Preserve ordering in any nested lists. Preserve types, missing-vs-null, empty-vs-null, case, exact path spelling and every field, including unknown/additional fields. Do not normalize paths, /host_mnt aliases, access flags or defaults here.
- Preserve multiplicity and cardinality. No set/frozenset conversion, subset comparison, destination-keyed dictionary, allowlist field projection, digest-only substitute or treating a missing array as empty.
- Keep exact holder ID membership, `running is True`, full `qualify_holder` and private-journal checks, source/daemon/retained-holder guards and ALL-container census unchanged.
- Retain the later per-mount touches/alias checks and the holder's exact volume/RW exception. No foreign same-label actor may borrow it; no enlargement of permitted IDs or extra mounts. No relaxing paused-state admission.

This removes a representation-order dependency, not a security/access/ownership condition. An identical permutation can pass, but added/removed/duplicated records or any changed field must still refuse. Canonical records stay internal; no new private strings/digests or raw census output may be published.

## Where this could explain a failure — and where it cannot

`create_holder` (lines2392–2448) does fresh create/ID journaling -> qualification with running=false -> start -> qualification with running=true -> final `HOLDER_WRITERS_POST` -> return. Only after return does `operate_migration` set phase=capture (lines2998–3002).

Consequently **a mount-order mismatch at the final post-start writer fence is consistent with phase=holder and a later paused actor**. It is a specific plausible location, not an established root cause. `fail_stop` (lines2661–2675) can pause only an exact holder admitted by `qualify_holder(True, allow_paused=True)` and does NOT call this writer-array equality; thus pausing after that mismatch is source-consistent. The subsequent metadata diagnostic itself neither checks that census equality nor observes the historical journal capability.

The same writers method is used repeatedly around capture, export, migration guards/apply and removal. A reordering there could also falsely refuse, but would have that operation's phase/context. The holder-phase receipt narrows the compatible source location to the creation path; it does not establish later capture/apply execution, nor prove their absence without the exact incident source/stage evidence. This finding does NOT explain failures in journal/identity/config/Env/health/security/resources/network/declared-mount qualification, create/start clients or other writer-fence conditions. Later matching metadata is not a reconstruction of earlier call results. No claim that all other possible causes were eliminated.

## Focused patch validation contract, not a new campaign

The final source/test review below is assessed against narrow inert tests that exercise the REAL writers path with different responses for qualification inspect and census inspect:

1. Same complete records permuted only in the second response passes, including dictionary-key order variation.
2. Mutations ONLY in the census response to Source/Name/Destination/Type/RW or other complete-record fields, added/removed entries and duplicate multiplicity refuse; exact absent/null/empty distinctions remain.
3. Malformed list/record values refuse closed; no raw operands leak. Any nested-list ordering is preserved.
4. Existing exact-ID/running qualification, foreign same-label writer, bind alias and read-only/RW exceptions still refuse or pass exactly as before.

Reading tests is not PASS evidence; no tests/imports were run here. A standalone comparator-only test is insufficient to demonstrate that the integration actually stopped using list equality. No broad suite, Docker reproduction, private reads or repeated diagnostic is requested by this review.

## Scope and next boundary

Only public source/test reads and public SHA-256 were used. Sole write is this NEW public review document; source, prior shell/report files, Git/tracker and runtime state are unchanged. No Docker/HTTP/native/provider/history/test/import/private operations. No remote artifact ID claimed.

Final patch/pins review is now SOURCE ACCEPT as detailed below, not another blind production attempt. The accepted comparator patch cannot adopt/unpause/restart/delete the new PAUSED actor, reuse its journal/tmpfs/backup, bypass retained-created admission or reuse either spent production/diagnostic authority. Any recovery design must explicitly account for the newly observed actor and existing HOLDs without assuming private ownership/provenance from these public metadata matches.

## Final implementation review — SOURCE ACCEPT

`full_mount_entries` (current lines1538–1541) requires a list of dictionaries and returns `sorted(encoded(mount) for mount in mounts)`. Existing `encoded` serializes the ENTIRE record with sorted dictionary keys, compact ASCII JSON and allow_nan=false. Sorting the resulting byte sequence ignores only outer mount ordering; duplicates remain as repeated entries. Complete values/extra keys, absent/null/empty distinctions, bool-versus-int distinctions, literal paths and nested-list order are retained. No field projection, set/destination-index conversion, path normalization, digest publication or private output was added. The helper inherits the existing bounded inspect/decode inputs; it is not a new arbitrary unbounded ingestion API. Unsupported serialization refuses through the existing closed controller error path; it need not have the same internal exception type as every shape refusal.

Both integration lines were inspected: the qualified holder's Mounts become `full_mount_entries(qualified['Mounts'])` at line2000, and the census holder branch requires running is True plus `full_mount_entries(item['mounts']) == holder_mounts` at line2019. All surrounding exact-ID/census/daemon/retained-holder qualification and per-volume access/alias predicates remain in the inspected writers method. No paused exemption or foreign-holder permission was added. No concrete blocker found in this correction.

Inspected all three new `WriterMountOrderTests` methods (lines4760–4834). They exercise real `writers` with an independently permuted census response, refuse census-only field/removal/addition/duplicate changes, and check complete serialization/key order/multiplicity/type/path/nested-order semantics and malformed inputs. The integration test requires only read clients and no capture. Earlier inspected foreign-reader/foreign-writer and synthetic R2 cases remain applicable. User attributes five selected focused tests PASS, including synthetic R2/unknown writer; this is author-reported, NOT a reviewer execution or native/Engine reproduction. No tests/imports were run here. Source acceptance fixes a conditional false-refusal mechanism; it does not certify this as the actual failure cause.

## Finite exact-ownership retirement draft — NOT executable approval

This is a deliberate ONE-target recovery-resource retirement design, not migration continuation or a repeated diagnostic. Target ONLY `4dc55f9708f1537fa369ea165aadd050c1f44a6570f0adccb93043d1467d1769`, expected OLD API image `sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c`, last observed PAUSED. Missing, changed or ambiguous target => STOP; no replacement selection or namespace adoption. Preserve d9433f7e CREATED actor, every other container, all images/volumes/network definitions, all historical/current locks/HOLDs, host journals and backups.

1. **Freeze exact custody before any destructive operation.** Parent must identify the already-known failed-attempt root from its authorized handoff, NOT discover one by label/path enumeration. A separately reviewed coordinator would validate bounded owned0700 ancestry and regular single-link0600 no-follow stable `holder-intent.json`/`holder-id.json` records there, requiring exact complete known schemas, id=target, matching intended exact name, image, backup root, helper source/hash and preservationMigration=true against the actual executed source/literal. These private predicates stay internal and are NOT performed or authorized by this document. Matching public name/label/image shape alone is insufficient. If this custody evidence is unavailable, STOP; do not manufacture/adopt a fresh capability or synthesize a journal.
2. **Resolve the potentially sole tmpfs recovery copy BEFORE removal.** Require either an existing independently verified durable-preservation record covering whatever recovery material exists, or explicit informed permission to discard this exact actor's rootfs/logs AND potentially sole /backup/tmpfs state. The uncertain holder-phase receipt and comparator fix alone are not such a record or discard grant. Do not read DBs, export/execute/unpause to manufacture evidence under this draft. If preservation is needed rather than discard, that is a separate narrowly reviewed operation, not an automatic branch here. Named volumes and host evidence must remain preserved regardless.
3. **One bounded fresh metadata preguard, not diagnosis/polling.** After both gates above are satisfied, a new frozen coordinator must bind exact target ID/name/image/own label to that custody record, verify paused/running state, fixed argv/security/resources and exact complete named-volume/RO-helper/tmpfs declarations/materialization, and seal non-target container identities/states plus volume/image/network sets for preservation comparison. No Env/logs/State.Error/store content; closed booleans only. Any mismatch refuses before mutation. This is a removal-specific ownership check, not a claim that the paused actor passes running-unpaused migration qualification.
4. **One exact destructive removal, no recovery execution.** A PAUSED running actor cannot be treated as an ordinary stopped-container non-force retirement. If and only if separately authorized and reviewed, removal must target this single FULL ID without -v, never a name/list/prune, with no explicit unpause/start/exec/stop-then-resume sequence. Any required force-removal semantics, timer/output bounds and private retained-state loss must be explicit in that future literal/approval. No retry, fallback actor or compensating mutation after refusal/timeout/uncertain response.
5. **One bounded postguard, then STOP.** Confirm target absence and protected identities/states/volume-image-network sets unchanged; retain all locks/HOLDs/journals/backups regardless. Failure/uncertainty means HOLD/manual review, not permission to remove further resources or continue rollout. Freeze the exact coordinator source/test pins, one-shot CLI and finite client/shared/caller limits before any execution approval. Do not reuse a spent shell or create a new migration attempt as part of retirement.

The two actual unresolved retirement gates are exact private custody binding and durable-preservation-or-explicit-tmpfs-discard authorization. This finite draft is ready for parent/security refinement, but does not approve deletion, new private reads or another diagnostic. No retirement or migration command was created; previous command documents were not edited.
