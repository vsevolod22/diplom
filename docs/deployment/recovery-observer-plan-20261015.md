# Recovery custody observer — BLOCKED privacy-consent/source-only plan, 2026-10-15

## Concrete next step and execution boundary

**BLOCKED — separate informed privacy consent unresolved; NOT natively executed and NOT approved.** Reviewer `ced1…` correctly blocked the earlier no-read claim: Docker CLI `--format` projects stdout only, while the CLI internally receives full Engine records, including container Env/labels. The observer cannot meet a strict Engine-field no-read constraint with this CLI. This revision explicitly corrects that claim; it does not silently reinterpret consent or authorize old/private metadata reads.

The immediate next step is an explicit operator decision on the trusted-local-filtering privacy boundary described below, plus renewed independent correctness/security review of these changed source/test bytes. Maintenance/preservation consent, this request to fix the sources, fake-test PASS and a matching source hash are **not** that consent. No native observation may run until both consent and independent acceptance exist. No alternative API/client infrastructure is introduced to evade the limitation.

Only three NEW files belong to this change:

- `server/deploy/trust/observe_recovery_custody.py`
- `server/deploy/trust/test_observe_recovery_custody.py`
- `docs/deployment/recovery-observer-plan-20261015.md`

Frozen controllers, diagnostics, pins and existing runbooks are untouched. No stage/commit/MCP, native Docker request, private metadata observation or recovery action was performed in preparing this change. The source-only tests described below use fake client/process/filesystem metadata.

The prior maintenance/preservation consent does not authorize reset/delete or unknown-resource adoption. This observer never creates/removes/adopts locks, containers, volumes or backups. It does not start Docker Desktop or a stand. Historical SPENT scripts and their approvals are not reused. `207709…5380e4`, CREATED `d943…08a4f`, original resources and every historical HOLD remain protected.

## Exact source identity and proposed invocation

| File | SHA-256 |
|---|---|
| `server/deploy/trust/observe_recovery_custody.py` | `be0c589672ea4341dd280f7bb119f2efc7a4d9f13bc1d16c02311af415c0631a` |
| `server/deploy/trust/test_observe_recovery_custody.py` | `fe1729d1eb2fc3b8570c30f63273a641b3ce97808b9afc02087e0f723088451a` |

Required working directory: `/Users/vsevolod/Documents/oldstartup/diplom`.

**Blocked/default-refusal command only — NOT a ready-to-run observation and NOT executed.** The distinct consent flag is deliberately **absent** below; the command would return `PRIVACY_CONSENT / CLI_FULL_METADATA_CONSENT_REQUIRED` before public source hashing, private-root metadata access or constructing a Docker client. Do not append the flag automatically. A future consent-bearing invocation must be explicitly chosen by the operator after informed consent and separately reviewed. Any future native parent must impose `timeout_ms=110000`, without private-output redirection or retry/polling loops:

```sh
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
  server/deploy/trust/observe_recovery_custody.py \
  --observe \
  --source-sha256 be0c589672ea4341dd280f7bb119f2efc7a4d9f13bc1d16c02311af415c0631a \
  --test-sha256 fe1729d1eb2fc3b8570c30f63273a641b3ce97808b9afc02087e0f723088451a
```

No source/test hash substitution at runtime. Changes to either source require new hashes and review of the new invocation. The new program is *repeatable*: it has no one-shot journal or spent-operation state, no writes, cached discovery, lock allocation or adoption. Each invocation starts a new bounded observation from scratch. This property does **not** authorize automatic retries or a polling service; the reviewer/coordinator determines the accepted invocation scope and continues exclusive maintenance.

Native entry first requires a distinct literal trailing `--allow-cli-full-metadata` operator acknowledgement. It is never inferred from environment, existing maintenance/preservation grants, labels, source pins or test fixtures. The source gate also requires it, and `DockerClient` independently refuses by default before executable checks/config access/spawn. Providing a truthy non-boolean to the internal client is not consent. The CLI flag is a technical acknowledgement, not proof that a human has granted permission; the coordinator must establish the informed decision externally. **No such consent is established in this plan.**

After that gate, native entry requires isolated Python, bytecode disabled and the exact current checkout path. It rehashes only the two new public source files at entry and before releasing positive Docker observations. It imports no frozen controller/helper or application module. Public source files are each capped at 512 KiB per hash read; at most two reads each (2 MiB accepted total payload). One extra byte may be read to detect a growing over-cap file, then the operation refuses immediately. Hashing uses no-follow/stable FD/ancestry checks.

### Unresolved trusted-local-filtering privacy boundary

Docker inspect endpoints return full records to the trusted local native CLI. This includes Env/labels and other Config/State fields for the known old originals and **every foreign container** in the bounded fence. Volume inspect also receives full volume records (including labels/options); daemon info/list can receive more metadata than their stdout format emits. The Go templates are output filters, **not server-side field selection**. Therefore the guarantee is only that unselected sensitive fields such as Env/labels are not included in CLI stdout/Python input and are not emitted to the agent receipt—not that the CLI never receives/reads them internally. Selected mount paths do enter Python through filtered CLI stdout but are withheld from the agent receipt. No logs endpoint or private host leaf file is opened by the observer, but that is not an Engine-record no-read guarantee.

The operator must explicitly consent to those full responses being processed transiently inside the pinned trusted local CLI for this finite known/foreign-resource scope, while only filtered metadata reaches Python and only closed flags reach the agent. Otherwise native execution stays blocked. CLI stdout/stderr caps do **not** bound full Engine response bytes, the CLI's HTTP decoding allocations or internal memory. Time/resource assumptions below must not be mistaken for full-response data minimization. No network/server-side projection capability is invented to close this gap.

### Docker client identity/configuration

The client path is literal `/opt/homebrew/Cellar/docker/28.1.1/bin/docker`, SHA-256 `5cfddb229b6278953fdbb5016619e0f786ac8291969183fb28e3717a92f8bd52`, inherited as a **public historical CLI identity** from `discover_preservation_holder.py`, not freshly measured or executed here. There is no PATH lookup, symlink/version fallback or automatic pin update. Missing/replaced/unsafe binary refuses before spawning. The public binary is rehashed before every client (64 MiB/file cap; at most 11 reads, 704 MiB accepted worst-case payload plus at most one overflow-detection byte before immediate refusal), charged to the shared deadline. This is not a claim of atomic hash-to-exec exclusion against a hostile concurrent host process.

All children are core read-only Docker commands, `shell=False` by default, stdin `/dev/null`, new client process session, with explicit socket `unix:///Users/vsevolod/.docker/run/docker.sock`. Their entire environment is fixed: PATH `/usr/bin:/bin`, HOME `/var/empty`, DOCKER_HOST that socket, empty DOCKER_CONTEXT, DOCKER_CONFIG the checkout's public `server/deploy/trust` directory. CLI `--host` and `--config` are explicit too. Existing `config.json` there refuses (metadata existence check only) before any client; ambient private Docker config/contexts/credentials are not selected. The native precondition remains a trusted/exclusive maintenance host; this does not defeat arbitrary host races.

## Conditional read-only request envelope — inactive pending consent/review

The following is a conditional envelope, not execution approval. Shared monotonic deadline **90 seconds**, each spawned CLI **8 seconds maximum**, no retry, maximum **11 clients**. Hashing/metadata checks share the 90-second budget. A blocked filesystem syscall is not universally preemptible; the parent's 110-second wall fence is mandatory. The sum of worst-case client/hash costs is not a successful-completion guarantee.

| Order | Request | Maximum stdout |
|---|---|---:|
| Before clients | Both fixed roots: directory metadata only | No client output |
| 1 | Docker daemon ID projection | 4 KiB |
| 2 | Exactly two named-volume metadata projections | 16 KiB |
| 3 | Complete all-container ID census A, `--all --no-trunc` | 4 KiB |
| 4 | Present known exact targets, limited STATE/MOUNTS + image/tmpfs projection | 128 KiB |
| 5 | ALL census-A IDs, limited state/mount projection | 1 MiB |
| 6 | Complete census B; must equal A | 4 KiB |
| 7 | ALL same IDs, second limited state/mount projection | 1 MiB |
| 8 | Same known targets, second exact projection | 128 KiB |
| 9 | Same two named volumes, second metadata projection | 16 KiB |
| 10 | Complete census C; must equal A/B | 4 KiB |
| 11 | Daemon ID projection; must equal first | 4 KiB |
| Final | Recheck new public source/test pins and config absence | No client output |

Empty census skips batch/known queries; a census with no known targets skips only known queries. It is reported as missing targets, not successful original qualification. Nonempty census must be unique full lowercase IDs and **at most 32**. No truncated prefixes, sampling, repeated discovery or batching a partial set. Each inspect row count/ID set must exactly match its requested set; duplicates, omissions, extras or malformed rows refuse. A 33rd container, 65th mount/container, unknown mount type or cap overflow refuses completeness. No ID from a label/name search is selected.

These are CLI **pipe-output** bounds, not full Engine-response/CLI-memory bounds. Stdout/stderr are drained separately in bounded chunks; stdout has the caps above, stderr is **discarded**, capped at 4 KiB/client. Aggregate accepted stdout+stderr maximum is **3 MiB** across the invocation. Reads are sized to the minimum remaining stream/aggregate budget plus one overflow-detection byte (never an arbitrary extra chunk); receiving that extra byte refuses immediately. The individual accepted ceilings sum to at most 2,457,600 bytes including stderr. The final public receipt is at most **16 KiB**, with no raw Docker output/errors. A failed/expired/over-cap client terminates the observation; only its local CLI process group may be killed/reaped, never any Docker resource. No fallback or subsequent client follows a failure.

## Metadata scope and meanings

### Known exact targets

Literal full IDs and expected images are embedded from the authoritative handoff: original API/worker/web/egress/llm-egress plus retained `207709…5380e4` and CREATED `d943…08a4f`. Presence comes from complete census membership; absent targets are not substituted. No unknown container is adopted or given writer exemption.

Known-target **CLI stdout** selects only ID/image; status, running/paused/restarting/dead/OOM booleans and exit integer; projected actual mounts; HostConfig.Tmpfs. The CLI internally receives full records, including Env, Config.User/commands/labels and full State/Config/HostConfig, even though those other fields are not selected into Python input or emitted to the agent receipt. No logs API is invoked. Public results use fixed logical role names, closed states, ZERO/NONZERO and booleans, not raw IDs/images/paths/tmpfs options. Image equality is a narrow binding observation, not full startup/security qualification or privacy consent.

### Original volumes and access/ownership distinction

The only inspected volume names are `dip-auth-stand_auth_accounts` and `dip-auth-stand_scan_ledger`. Volume projections contain name, driver, scope, options-present boolean, mountpoint and creation timestamp. Both must be returned exactly once, local driver/local scope, no options, absolute canonical non-overlapping mountpoints. Their full projected records must remain equal across the two reads. Labels are not selected into CLI stdout or the agent receipt, but the CLI internally receives them in the full record; they confer no authority. A missing-volume client error reports a closed refusal, not a fabricated present/absent result.

For original API `/auth` and `/data`, original worker `/data`, and holder `/source/auth` and `/source/data`, the result distinguishes:

- `MATCH_RO` / `MATCH_RW`: exact expected named volume, target and literal source mountpoint, with observed RW boolean;
- `MISSING_TARGET` / `WRONG_BINDING`;
- `NOT_OBSERVED` when that exact target container was absent.

**RW is not silently turned into RO and RO is not inferred from ReadonlyRootfs.** The historical originals/holder may legitimately declare RW volume access. The observer does not remount anything. `originalBindingsMatch` checks the three original API/worker bindings, independently of whether their access is RO or RW; inspect each access result and image flag separately.

Docker metadata cannot establish filesystem UID/GID ownership of source DB files, possession of historical PRE, or that a volume name was never reused. Accordingly `sourceFilesystemOwnership=NOT_OBSERVED`, `ownership=NOT_ADOPTED`, `preCustody=NOT_PROVEN` remain unconditional. There is no source-volume host filesystem probe or private leaf read. Future preservation copier RO mounts and genuine custody evidence must be reviewed separately; this observer is not that copier.

### Complete bounded container-metadata fence

Foreign-container **CLI stdout** selects only ID, lifecycle fields and projected mounts (type/name/source/destination/RW/propagation). The CLI still internally receives full foreign inspect records, including image/config/Env/labels; these extra fields are not selected into Python input or the agent receipt. No logs API is called. Every observed row is shape checked, with strict booleans/integers. Both state/mount sweeps must match, as must known projections and their corresponding common batch fields, volumes, daemon ID and three complete censuses. Only outer mount-list order is ignored; projected field changes, duplicate destinations, missing fields, multiplicity changes and type confusion refuse. Unknown mount types refuse rather than bypass touch classification.

A protected attachment is classified conservatively by protected volume name, protected name as an exact source-path component, or literal source equality/ancestor/descendant overlap with either inspected volume mountpoint. No path is normalized to excuse a mismatch. Suspicious noncanonical sources (`..`, duplicate separators, double-leading slash) refuse. A bind of `/` or the volume parent is therefore a protected attachment.

`noActiveProtectedAttachments=true` requires **no** potentially active container with any protected attachment, even RO. Running/paused/restarting/dead/removing states are not exemptions. This includes holders, original services, egress and every foreign container. No stopped-state whitelist grants future startup authority.

`completeStableMetadataFence=true` means the described finite observations agreed. It does **not** establish continuous exclusion, detect a container that appeared/disappeared between censuses, resolve arbitrary host/VM symlink aliases, attest external host writers, or prevent future starts. `aliasCoverage=NAMED_AND_LITERAL_SOURCE_OVERLAP_ONLY` and `continuousWriterExclusion=NOT_PROVEN` are explicit. Exclusive maintenance and separately reviewed acquisition-time writer fencing are still required. A successful no-active-attachment result is a useful stronger conservative observation than merely no observed RW attachment, not a universal no-writes proof.

### Host roots: explain predicates, never repair them

Only these directory chains are examined:

- Current checkout `.local-auth` under `/Users/vsevolod/Documents/oldstartup/diplom`.
- Literal historical `.local-auth` under `/Users/vsevolod/Documents/startup/diplom`.

Each component is lstat-equivalent `stat(..., dir_fd=parent, follow_symlinks=False)`. Traversal uses directory-only O_RDONLY/O_DIRECTORY/O_NOFOLLOW FDs and fstat identity; ancestor/root path metadata is rechecked before closing all descriptors. No `resolve`, symlink traversal, enumeration, leaf open/read/hash, lock-marker stat, backup traversal or search for alternate locations. Roots are classified independently, not equated by matching flags.

| Closed field/category | Meaning |
|---|---|
| `DIRECTORY_METADATA` | Final root directory metadata obtained, **not** private custody qualification. |
| `uidMatch`, `gidMatch` | Final root matches effective observer UID/GID separately. Numeric IDs are not printed. |
| `mode700`, `mode755` | Exact separate mode predicates. Raw modes are not printed. |
| `noGroupWorldWrite` | Neither group nor world write bit set. |
| `ownerAllowed` | Owner is root or effective observer UID; permits bounded directory metadata access, not adoption. |
| `private700Matches` | Conjunction of observer UID, observer GID and exact 0700 on final root. Never waived. |
| `ABSENT` + `atRoot` | One fixed component missing; `atRoot` distinguishes final root from an ancestor, never prints component name. |
| `SYMLINK_REFUSED`, `NOT_DIRECTORY`, `UNSAFE_ANCESTOR` | Traversal stopped at that boundary; no follow/fallback. |
| `stable` | Metadata agreed within that root's own short FD/path observation, not throughout subsequent Docker calls. |

Ancestors must be directories owned by root/current UID and not group/world writable before opening. **Ordinary 0755 ancestors are permitted for metadata traversal; they were never required to be private 0700.** A final 0755 root is classified with `mode755=true`, `mode700=false`, `private700Matches=false`; this makes the prior aggregated failure actionable without falsely declaring it harmless or private. Final unsafe-owner/writable directories are classified without opening them. Different GID is reported without reading descendants. The historical frozen owner/group/0700 comparator is not edited, bypassed or relabeled PASS. No chmod/chown, new root, symlink alias or lock adoption is proposed by a predicate mismatch.

## Closed results and interpretation

Only fixed checkpoint/category strings, fixed logical keys, enum states and boolean/null flags are printed. Raw paths, names, daemon IDs, creation timestamps, images, exception text, mount options and source payloads stay internal. Roots may be classified even when Docker later refuses; **all positive Docker/fence results are suppressed (`docker:null`) after any failure**, including final pin drift. Exit 0/`ok:true` means the bounded packet was classified, not that every predicate is favorable or recovery is authorized.

Checkpoints identify arguments, the separate `PRIVACY_CONSENT` gate, public sources/roots and each request stage from the table through `CLASSIFY`, `SOURCE_FINAL`, `COMPLETE` or `OUTPUT`. Categories distinguish `ARGUMENT_REFUSED`, `CLI_FULL_METADATA_CONSENT_REQUIRED`, `SOURCE_REFUSED`, executable identity/not-found/denied/IO, command allowlist refusal, client timeout/nonzero/pipe IO, output cap, JSON decode, shape/mount/volume/census refusal, observation drift, host IO and unexpected failure. No raw error bucket is printed to explain a refusal. A valid packet can contain missing originals, wrong image/bindings, RW mounts, unsafe root flags or active protected attachments: review actual fields, not just `ok`.

Every receipt declares `cliMetadataBoundary=FULL_RECORDS_TRUSTED_LOCAL_FILTERING` and `sensitiveFieldsEmittedToAgentReceipt=false`; this is an emission boundary, not a no-read claim or proof of consent. It also explicitly denies mutation/adoption/recovery authority, PRE custody, historical durability, actual DB integrity, continuous exclusion and full qualification. No DB version is read. When the exact retained holder is observed EXITED, `holderTmpfs=EXITED_NOT_RESTORABLE_BY_START` records ordinary Docker tmpfs semantics: **start cannot restore the former tmpfs contents**. It is not forensic proof of which bytes were lost or whether another durable PRE exists. PAUSED/running metadata or matching tmpfs declaration likewise does not prove PRE custody. No start/unpause/exec/cp/SQL/stop/rm/commit/export is offered for the holder.

### Guarded receipt delivery and failed-pipe shutdown

The one newline-terminated packet is written once with `sys.stdout.buffer.write`, its exact byte count checked, and `sys.stdout.buffer.flush()` explicitly called inside the same guarded block. Write errors (including BrokenPipeError), short/None/non-integer writes and flush failures return dedicated exit code **74**. There is no output retry, second receipt, stderr exception or raw traceback. Native entry uses `os._exit(74)` on that code, skipping Python finalization so a partly buffered broken stream is not flushed again with an unraisable shutdown traceback. This only exits the observer process, not Docker resources; it does not create fallback infrastructure or open a replacement output file. Normal complete delivery retains exit 0/1 semantics.

On exit 74, **any visible prefix or even a full JSON packet is an unaccepted delivery**, not success; the receiver must check the process result. No claim is made that already-written bytes can be recalled. Fake tests exercise write/flush errors and the immediate-exit control path without terminating a real interpreter or spawning a child process.

## Source-only validation performed

Executed only:

```sh
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
  server/deploy/trust/test_observe_recovery_custody.py -v
```

**48 tests PASS (0.071s final run).** Tests import only the new public observer definitions. Docker replies, subprocesses/selectors/pipes and private-directory stat/FD metadata are fake; no native CLI, private host filesystem or SQLite is used. Coverage includes repeatability/no authority, failure at every request/no retry, complete census limits and drift, all-target/foreign/RO/paused writer denial, source overlaps and bindings, mount ordering vs field changes, types/duplicates/JSON caps, source-final failure, 0755 vs private0700 predicates, symlink/absence/unsafe ancestors/metadata drift and descriptor cleanup, transport caps/clean environment/errors/client-only cleanup, and fully faked native-entry dependencies. Additional regressions verify default consent refusal before all source/root/client access, the independent client guard, exact distinct flag handling, fake acknowledged entry, guarded write/flush/short-write failures, no stderr/retry and immediate-exit shutdown control. Test-only fake acknowledgements are not operator consent. PASS is not native Engine compatibility, privacy consent or independent source acceptance.

## Reviewer decision requested / what follows a packet

**Still BLOCKED: privacy consent unresolved; no approval/ready claim.** Reviewer: evaluate these exact revised sources/tests, the explicit full-record trusted-local CLI boundary, consent refusal, guarded output/shutdown behavior, finite scope and any subsequently proposed consent-bearing literal invocation with its 110-second wall fence. The command printed above intentionally lacks consent and is not an executable observation proposal. No independent acceptance is claimed by the author. Only after a separate informed operator decision and renewed independent acceptance of the actual invocation may the coordinator execute it, retain the closed result and stop—no automatic continuation.

If separately consented and independently accepted, a future packet could answer whether exact originals and named-volume/source bindings are currently observable, how their access is declared, which root predicate differs, and whether the bounded metadata fence found an active protected attachment. It cannot prove an existing backup complete/durable, genuine historical ownership or all-state preservation.

If identity/binding/writer predicates are unfavorable or any request refuses, resolve that exact observation through review; do not repair permissions, delete HOLD or retry a deployment. If favorable, the next **separate** reviewed operation is preservation-only durable acquisition of the existing sources (no original SQL/application startup, verified destination, private payload confined to the approved process), followed by validation on derived copies. If historical PRE is unavailable, a new rescue baseline must be explicitly identified as new—not silently substituted for R4 PRE. Reset/delete/new empty stand are not fallback recovery. Product/provider/history/scanner acceptance remains separate.
