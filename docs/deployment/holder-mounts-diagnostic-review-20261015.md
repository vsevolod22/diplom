# Independent correctness approval — exact holder mount diagnostic, 2026-10-15

## Decision

**CORRECTNESS APPROVE ONE invocation of the exact literal below, under the requested metadata-only scope.** No concrete blocker was found in the source/test pair, pinned transport reuse or CLI binding. This approval is diagnostic-only, not recovery, adoption, cleanup, production retry, ownership/full qualification or authority to alter HOLD. Any separate final security approval requirement remains in force. NOT EXECUTED by this reviewer.

Required cwd `/Users/vsevolod/Documents/startup/diplom`, foreground parent caller `timeout_ms=45000`:

```sh
DOCKER_CONTEXT= DOCKER_HOST=unix:///Users/vsevolod/.docker/run/docker.sock PYTHONDONTWRITEBYTECODE=1 /Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B server/deploy/trust/diagnose_holder_mounts.py --diagnose-once --source-sha256 8166310172c1ff6c02b833d1cb135f38de7fb0e0b126d0a4c2233286553fbb71 --test-sha256 09b32e69e1425be859802516bbf0375d263ea5b46b3cd00dd4120b5473f98aae
```

Shared30s; ONE child inspect<=10s; stdout+stderr transport<=65536B; closed public receipt<=4096B. Executable hashing/source reads consume the shared deadline. Cooperative filesystem checks do not prove kernel preemption or daemon cancellation; caller45s remains required. No repeat, fallback or follow-up client is authorized.

## Exact public source checks

All five source identities were hashed directly, without importing/executing them:

| File under `server/deploy/trust/` | SHA-256 |
| --- | --- |
| `diagnose_holder_mounts.py` | `8166310172c1ff6c02b833d1cb135f38de7fb0e0b126d0a4c2233286553fbb71` |
| `test_diagnose_holder_mounts.py` | `09b32e69e1425be859802516bbf0375d263ea5b46b3cd00dd4120b5473f98aae` |
| `discover_preservation_holder.py` | `4afb0bc484d34aca428fee956bd939d7b322727285eef0f721425849bb32a1f4` |
| `test_discover_preservation_holder.py` | `cc1a168804cb9a07f9c53724730bfbbaae7596c44c88743b0dc169f26a1bf312` |
| `recreate_openrouter_key.py` | `b34dcd63a77d06d997b4c6bf61a36bc7fbe67d8129aa12f444d055a1b9f50438` |

The source verifies its own/test CLI pins and all three fixed dependency pins before compiling only captured discovery-library bytes into a non-main module. Controller and test bytes are hash-only, never executed. The already reviewed library is definition-only outside its main guard; this route uses only its Client/decode, not Discovery or private directory_metadata. Public config.json presence refuses before launch. The fixed canonical Docker path/hash/full-stamp checks, explicit socket, clean five-key child environment, bounded private stderr and first-failure transport handling are preserved.

## Exact target and classification boundary

Read the complete current `docs/deployment/hold-handoff-20261015.md`. Its last-known observations are attributed historical evidence, not a fresh inventory. New diagnostic constants agree with its exact candidate and original API bindings:

- Holder candidate: `d9433f7ed0fc504a3521574668f15b7b3a0e8d283d61b9aa33d1e97187708a4f`.
- Original API: `5cbe0936a5f09d663a77960749e687fbd41fbef52c8990b063362b9363d3e9ec`.
- Both must report image `sha256:487c3909d3eeee08d60840a81c1adeb61c292aee0a31df17b2a8cf92f6dbb58c`.

ONE batch `container inspect --format` targets only those two full IDs. Exact schema/identity/image and clean flags are checked before output classification; API must remain exited and holder created, both non-running/not-paused/not-restarting/not-OOM/not-dead. Drift refuses rather than discovering/rebinding another resource. There is no ls/image/volume/network query, lifecycle mutation, SQL, helper, HTTP or fallback. This narrow identity check is not an ownership or full-container qualifier.

The projection includes only selected identity/state/mount metadata. It omits Env, labels, State.Error, full Config/State, logs and container file contents. Original API actual volume metadata supplies any AUTH/DATA source baseline; absent/ambiguous baseline is reported incomplete, never guessed. No host private-directory/store/recovery probe occurs. Raw names, paths, options, labels, commands and stderr do not appear in the public receipt.

Declared and materialized views stay separate. Output reports finite slot presence, exact type/source relations, boolean value/type/omission, finite option names/types/flags and bounded unknown counts. Duplicate/missing targets, wrong field types, null/empty arrays and extra options are observations rather than accepted guard variants. A candidate can therefore receive classification success with mismatches; success is not a passing mount qualifier.

`HOST_MNT_PREFIX` means only literal equality to `/host_mnt` plus the expected helper source string. It does not normalize a path, establish filesystem equivalence or permit relaxing the authoritative controller. `helperSourceAcrossViews` is raw cross-view equality, not independently typed/authorized source acceptance; read it alongside each slot's type/source fields, never as a standalone passing guard.

Expected successful code, NOT OBSERVED: `MOUNTS_CLASSIFIED_NOT_QUALIFIED`, `Env:"NOT_OBSERVED"`, `fullQualification:"NOT_CLAIMED"`. No actual mount discrepancy/cause is claimed by this review. Existing held state and all spent authorities remain unchanged.

## Review validation and limits

Read the complete diagnostic and paired test source. Inert test source covers finite output/privacy, exact-prefix discrepancy without normalization, option/type/unknown-key classification, null/empty/duplicate/extra targets, incomplete baselines, exact identity/state refusal, one inspect/no follow-up, closed transport/decode failures, source pins before captured-library execution and receipt size. No tests or imports were run; no test PASS is invented.

Reviewer activity: public handoff/source/test reads, public source SHA-256 hashing and creation of this optional public review only. No runtime/Docker/native/provider/script/test operation, private Env/DB/log/recovery read, source edit, Git/tracker change or prior spent file modification occurred.

After the single parent result: STOP. Failure/timeout/incomplete receipt permits no follow-up query or repeat; successful classification also grants no holder adoption, mount-guard change, cleanup, lock/HOLD removal or recovery/startup operation.
