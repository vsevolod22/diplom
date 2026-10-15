# Independent correctness review — ONE no-write held-preflight diagnostic

## Decision / frozen literal

**CORRECTNESS APPROVE ONE diagnostic-only parent invocation, conditional on independent security acceptance of this exact pair/literal. NOT EXECUTED by this reviewer.** No concrete blocker remains in the inspected version. This is not production-source approval, rollout/reconciliation authority, release authentication, or lock adoption.

- Literal: `docs/deployment/held-preflight-diagnostic-20261015.sh`.
- Literal SHA-256: `d773c16600ff4f6b5e2ef423e72dda422fd68da18c9661f89992cffd3cf579c2`.
- Required cwd: `/Users/vsevolod/Documents/startup/diplom`.
- After security acceptance only: `/bin/sh docs/deployment/held-preflight-diagnostic-20261015.sh`, ONCE foreground, caller `timeout_ms=110000`.
- Shared cooperative90s from observation creation; each allowed child<=15s; at most12 exact read commands, consumed before launch with no retry. Kernel/filesystem/process-creation work is not universally preemptible; the independent caller fence remains required.

The literal retains the isolated Python3.13 interpreter, `-I -B`, bytecode disabled, empty Docker context and exact explicit socket. It supplies only the diagnostic action and two full pair hashes; the diagnostic itself binds all eleven controller dependencies and exact incident identities.

## Final public identities

| Source under `server/deploy/trust/` | SHA-256 |
| --- | --- |
| `diagnose_held_preflight.py` | `b593d0930a081608157296e5f7dc6f5619b61bb972887ca2826dcf23381e29a8` |
| `test_diagnose_held_preflight.py` | `c51b4461f191889b0dd6a2ad0fb1702ff1943e38c868e1610da846c52759192a` |
| `recreate_openrouter_key.py` | `e07bc714b8d2aa8f3175f3b07ca51ed7a0154691cebd2992518d4312c140239b` |
| `test_recreate_openrouter_key.py` | `511906937d4f57208d3c0702bbef79312d5902eb91e103091b6b5400db99e539` |

All eleven dependency files were individually rehashed against the diagnostic's PINS. Other nine remain MJS323ca629/testf9668e4f, selector97283889, verifierc93ced26/test04c1748f and Compose da5c96aa/80ec2a65/f6587a7a/6dcb3afd with their unchanged full hashes. Initial stale controller pins were observed during author integration, but are NOT in this final source. The final version also includes `ReadRunner.observation=obs` and allows the exact `GATE_ROOT_METADATA` / `GATE_SOURCE_PINS` stage identifiers. Rehash after literal creation still matched the final diagnostic pair.

## Reviewed boundary

1. **Source before execution.** Strict five-token CLI requires isolated/no-bytecode execution at the fixed source path. Stable no-follow, owned/single-link, non-writable public reads are bounded2MiB/file. Self/test and all eleven dependency hashes precede controller execution or private metadata observation. Controller executes captured bytes under a private temporary module, rejects preloaded sibling namespaces and loads its fixed hash-verified selector. Paired tests are hashed, never imported by the diagnostic.
2. **Five coordination paths, metadata only.** Root, prior lock/HOLD and reconciliation lock/HOLD get fixed closed classifications. Ancestors are checked; directory-relative NOFOLLOW descriptors and stable linked metadata are used; unsafe parent prevents child observation. Marker files are not opened/read, directories are not enumerated. Prior root/lock/HOLD must be safe before continuation. A reconciliation lock may be present, missing or refused: it is only reported, never created, removed, adopted or required absent. Existing unknown lock state is not inferred from the spent preflight failure.
3. **Real factory, no release actor.** The actual pinned `load_release_gate()` captures/verifies sources before executing the verifier definition and calling its real factory. The factory constructor reads public source hashes and initializes in-memory capability/identity fields; it invokes no Docker client. The diagnostic never calls gate.verify/recheck or Controller.activate/coordination/preflight/operate. It assigns only observed prior metadata, not lock ownership, then calls the actual `capture_preflight_model()` directly. An unconditional return plus no-backup/no-compiled/no-touch/no-capability/no-seal/no-verification/retained-none assertions end the diagnostic.
4. **Exactly twelve possible clients.** One Compose version query; one combined full inspect of the five exact original IDs; five exact original image inspections; one exact retained CREATED-holder projected inspect; three exact candidate image inspections; one fixed four-file Compose JSON render. No ps/info/volume/network query, arbitrary inspect target, exec/log/create/start/stop/pause/rm/up/build/pull/cleanup or stdin is allowed. The render tuple matches the actual pinned selector's file order, env-file path and project/project-directory arguments. Unknown, repeated or thirteenth requests refuse before subprocess creation.
5. **Transport and privacy.** Each child uses the fixed canonical Docker binary plus explicit `--host`; exact stored metadata/hash are checked before every child, with binary read<=128MiB. Version cap4096B; retained projection65536B; other combined stdout+stderr caps2MiB. Both streams are privately captured/drained; only stdout enters internal parsing. No raw stream, exception text, traceback, Env/key/DB/log data is printed. Stdin is DEVNULL, process-local group cleanup is kill/reap of the read client only, and cleanup failures do not replace the original category. No daemon resource cleanup is authorized.
6. **No-write is not metadata-only overall.** The actual capture prefix processes existing selector/Compose configuration and bound original inspect Env privately in memory. Secret paths receive existing metadata checks, not direct key-file content reads by Python; Compose resolves the trusted existing environment configuration. There is no SQL/store access, release inventory verification, application import/start, holder/HTTP/provider/native command, lock acquisition, mkdir, compiled/backup write or lifecycle action on this route. This is the narrowly requested existing capture-prefix diagnosis, not permission for an agent to inspect those private values.
7. **Failure attribution and honest success.** Fixed stage IDs cover imports/plan, coordination metadata/prior snapshot, actual factory root/source stages, every capture-prefix group, and explicit prefix return. Sticky first/deepest failure survives outer unwinding; deadline wins when actually expired. Unknown exceptions map UNEXPECTED without text. Public output is bounded4096B and closed fields/classifications only. Success code is `CAPTURE_PREFIX_PASS`, `capturePrefixOnly:true`, `fullQualification:"NOT_CLAIMED"`, `releaseActorInvoked:false`, `coordinationAdopted:false`, `mutationAttempted:false`, `manualReconciliationRequired:true`; NONE/COMPLETE denotes this prefix only. It does not run original-model comparisons or release authentication, full preflight, writer census, store compatibility/migration or readiness.

## Evidence limits / next boundary

The handoff records spent shell04f35 exited1 at preflight with manual reconciliation required. That is not proof no lock/HOLD/scratch writes occurred. Root/lock state and original services are NOT freshly observed by this reviewer. Existing HOLD remains and all prior authorities stay SPENT.

Reviewed the complete final diagnostic/test source and relevant actual controller/selector/verifier load/capture paths. The inert integration test source uses the real factory with synthetic private metadata/read-client outputs and forbids mutation paths; it also asserts the twelve-command set and sticky factory-stage failures. **Tests were not executed or imported here; no test PASS is claimed.** Public hashing/static reading only; no Docker/runtime/private original-file reads or source edits.

After independent security approval, ONE parent diagnostic only, then STOP even on PASS. No follow-up query, retry, production continuation, lock/HOLD change, adoption, cleanup or repair is implied. Changed pins/source/literal need fresh review. Only these two NEW diagnostic documentation files were written; spent files were preserved. Flownix is offline; no remote artifact ID is claimed.
