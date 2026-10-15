# Independent correctness review — ONE retained host-PRE diagnostic

## Decision / frozen literal

**CORRECTNESS APPROVE ONE parent invocation of the exact diagnostic below, conditional on independent security acceptance and continuing exclusive maintenance. No concrete source correctness blocker found. NOT EXECUTED by this reviewer.**

- Literal: `docs/deployment/retained-pre-diagnostic-20261015.sh`.
- SHA256: `8996b5201f4678d6f8d9e632fe2e40a3fc9267fbf6ea6b8e092581ad6eeaa2ec`.
- Required cwd: `/Users/vsevolod/Documents/startup/diplom`.
- After security acceptance: parent `/bin/sh docs/deployment/retained-pre-diagnostic-20261015.sh`, ONE foreground invocation, caller `timeout_ms=110000`.
- Shared90s, clients<=10s, <=5 metadata clients; no polling/retry. Receipt<=4096B. Listing4096B, other clients65536B each, aggregate transport ceiling266240B including discarded stderr. Private host inventory payload<=256MiB; separately bounded repeated manifest/journal/header reads are additional, not included in that payload count.

## Incident boundary — do not discard the potentially sole PRE

User reports R4 shellba3d is SPENT: failed `export_pre` / `MIGRATION` / `PREDICATE_REFUSED`, uncertain=true, after capture returned. No exact export substage or cause is inferred. Capture success is not a durable export receipt. The new helper MAY retain the sole PRE copy. Preserve ALL holders, tmpfs baselines, journals, host materials, historical locks/HOLDs and backups. There is no disposal, stop/unpause, recovery/adoption, original-store query, repeat export, migration retry or new production approval here. The new controller instrumentation cannot retroactively identify the old failure substage.

## Selection and custody findings

- ONE fixed label/name namespace listing, <=4096B, <=4 unique full IDs including the two fixed exclusions. Excludes only retained CREATED d943 and retired4dc. More than2 eligible refuses; exactly2 returns AMBIGUOUS before candidate/private reads. No eligible returns a closed observation with host PRE NOT_OBSERVED. Exactly1 is required to proceed; no newest/name-derived preference, fallback or retry.
- Fixed OLD API image-default projection, two exact-volume metadata baselines, then the selected immutable container ID. Its PAUSED/CREATED/EXITED state, exact image/config-image, zero exit, boolean lifecycle flags, user, commands, image-default Env equality, no preloads, resources, network-none key, security, complete declared/actual mounts and label are checked against the pinned37-group profile. These are stricter current observable checks, not a lifecycle action or historical qualification claim. Source-volume paths are comparison inputs only, never opened on the host.
- Config.Env is observed internally only for the selected sandbox and fixed image defaults, with exact equality and NODE_OPTIONS/NODE_PATH refusal; no original-service Env/private env file is read. Values, key names, lengths and hashes are not exported. Volume/mount paths, names, labels, args/defaults remain internal.
- Label must be a single fixed-format basename. Only then read the selected backup directory's exact `holder-intent.json` and `holder-id.json`, each<=4096B. Owner/group0700 directory,0600 regular single-link files, no-follow stable FD/path/full ancestry checks. Strict schemas bind both journals to the exact candidate ID/name/image/backup, frozen helper path/hash and preservationMigration=true; version is an integer1. The seals must share ancestry but not file identity. No directory enumeration or historical lock content reads outside this selected host pre tree.
- Final candidate inspect requalifies the same ID and compares complete metadata: ONLY actual outer Mounts order is ignored via full canonical multiset. Duplicate/cardinality/field/type changes, declared array order and all other projected values stay exact. Both journal seals and all public source hashes are rechecked. This is observed internal custody consistency, not authority to adopt the actor or attribute it to the historical R4 failure by guesswork.

## Host PRE boundary and controller changes

Only existing `pre/` below that bound backup folder is traversed. Missing pre is observed `ABSENT`; it neither creates a directory nor guesses which export gate failed. Non-directory/symlink/unsafe material refuses without repair.

The actual pinned `backup_inventory(pre,durable=False,byte_limit=256MiB,deadline=shared_deadline)` is used. It preserves ownership/group,0700 directories/0600 single-link files, ancestry/no-follow/stability, duplicate-inode, depth/path, file/directory count and per-file limits. Cumulative stat size refuses the next file before hashing if the256MiB bound would be exceeded. Traversal and chunk hashing charge the same deadline. File and directory fsyncs are absent in this mode; directory descriptor/identity checks still run. Default `durable=True`, default original export byte limit and deadline=None preserve existing production behavior; production export/revalidation calls still use that default. `sync_directory` also defaults to durable=True.

Before manifest parsing, inventory must contain manifest.json<=4MiB and a separately sealed bounded read must match its observed inventory hash. Then the real pinned `validate_manifest(migration=True)` uses independent PUBLIC expected version sets, followed by reject-only `small_snapshot` and raw-export header reads through `Controller.small_headers(None,...)`. That method uses no Controller instance/state or SQL; only the already selected host raw copies are opened. The manifest is read/sealed again after these validators. The existing manifest validator has its own32MiB read ceiling; normal sealed manifest is<=4MiB, but256MiB is explicitly not a total repeated-read bound. Validators are clock-bracketed, not universally interruptible; the external110s fence remains required for blocked filesystem I/O.

New fixed EXPORT_/INVENTORY_ controller stages preserve separate copy/inventory/equality/manifest/admission/fsync/certification checkpoints. The diagnostic never calls `export`, `holder_inventory`, `migration_exec`, `activate`, a controller constructor, or the MJS helper. This review does NOT renew the spent R4 command with the new pins or approve current-controller production execution.

## Result interpretation / privacy

The closed receipt emits only candidate full IDs (<=2), finite state/hostPre/checkpoint/category/status fields. Raw paths, labels, journal/manifest/file content, row values/counts, versions, sizes and hashes never leave memory. Raw stdout/stderr from modules/clients is suppressed; the fixed receipt alone is emitted. Output overflow fails closed.

`OBSERVED/ok:true` can mean no eligible candidate, ABSENT pre, or host `VALIDATED_READ_ONLY`; inspect the actual fields. `VALIDATED_READ_ONLY` means this host tree passed these current read validators, not SQLite execution, native recovery, ALL-state recomputation, historical fsync durability or a certified export. Working-file hashes have no independently observed in-holder inventory to compare here. The receipt ALWAYS says historicalDurability=NOT_OBSERVED, inHolderInventory=NOT_OBSERVED, fullQualification=NOT_CLAIMED, ownership=NOT_ADOPTED, mutation=false. On a later final-check failure a prior hostPre observation may remain in a failed receipt; it must not be promoted into complete qualification.

First client failure stops further clients. Predicate/shape/IO/deadline failures return fixed stages/categories without raw exceptions; no cleanup/fallback follows. This diagnostic cannot repair a copy, extend a holder timer, preserve an expiring tmpfs by magic, or grant permission to discard any holder/material even on success.

## Exact verified public pins

All were independently hashed; the new diagnostic/controller pairs were rehashed when freezing the literal. Embedded dependencies are fixed, not dynamically repinned.

| Public file | SHA256 |
|---|---|
| `server/deploy/trust/diagnose_retained_pre.py` | `659bf64ffdf5536a317e44eda8b3794574afaaf418b3a80c2eb8ac3262f76519` |
| `server/deploy/trust/test_diagnose_retained_pre.py` | `ef02e01aebdc7781c3e5283baaa1e07334bc2e63e058f0ba1ebdcf417c503aa0` |
| `server/deploy/trust/recreate_openrouter_key.py` | `76153d2cd7d0452c14149a367cde4bb934d973380a7e10e22ebb798f95893857` |
| `server/deploy/trust/test_recreate_openrouter_key.py` | `15b0460d1faefa31112f67cbfa86cd1d0db90046ecb2f74b110ba6e90629ac60` |
| `server/deploy/trust/stand_composition.py` | `97283889749a4413d5e27f9b0ce828927f56b56ef507cb220a3c607fd3d23f5a` |
| `server/deploy/trust/diagnose_holder_qualification.py` | `8e051eeb3c7a4fa913d93a50e19dc21bf32884780d3102fe3cfe36897dce3eb8` |
| `server/deploy/trust/test_diagnose_holder_qualification.py` | `e25c7a9e1e7ec78c7a91d83c4f0c6e72b5e40fe42400d9f9f9f37b606a4ca8a0` |
| `server/deploy/trust/discover_preservation_holder.py` | `4afb0bc484d34aca428fee956bd939d7b322727285eef0f721425849bb32a1f4` |
| `server/deploy/trust/test_discover_preservation_holder.py` | `cc1a168804cb9a07f9c53724730bfbbaae7596c44c88743b0dc169f26a1bf312` |
| `server/deploy/trust/sqlite_state_snapshot.mjs` | `323ca629483f92896634ada79d2c8f098d9ff885464eb24ba9d86bb75e563dee` |

Read the full new diagnostic/test and relevant actual profile, controller inventory/validators/header/export-stage code and test source. Tests cover source loading, unique selection, ambiguous/empty discovery, profile/Env/preload refusal, bound journals, absent PRE, actual no-fsync validators, hash/version/small/header gates, unsafe links/modes, final journal/candidate/manifest drift, deadline and client allowlist/first failure. Controller tests inspected cover durable-default equivalence, no-write inventory, pre-open cumulative limits, stability and deadlines. NO tests/imports were run by reviewer; test source is not an independent PASS.

## Final scope

Sole writes: these two NEW public diagnostic documents. No daemon/HTTP/native/test/provider operation, private recovery/Env/DB/log read, source/Git/tracker change, R4 retry or cleanup by reviewer. No actual candidate ID/state, host PRE existence/validity, durability, migration result or root cause is invented. No remote artifact ID claimed.
