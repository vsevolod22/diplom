# TASK8 source-only assessment evidence — 2026-10-09

## Assignment and exact source

Direct independent scope, project520a0059-d0f2-4f86-8d93-fc15035a5715, DIP-TASK-8. NEW server/host/** only. No duplicate runtime run or claims. Existing d18c354c-0705-417b-990a-b4a273569e75 read as terminal completed; TASK6 stays testing90, not done. Read .flownix, basics, local and full execute-task, full DIP-ARTF-202/210, TASK8/PLAN2, get_dependencies (no recorded edges), runtime runbook and selected runtime source. Node reads exposed no prior comments; scoped action log exposed creation only. Existing server component DIP-COMP-3 retained; no new component/spec/pages/routes.

`source-manifest.json` exact eight-file source/docs/tests snapshot SHA256:
`5a8f96996a3a8917a99e1fbc47e284981fa497eb3cb45b3bd8ba02ea9f05a222`.
Generated manifest and this evidence report are excluded from their own source manifest by explicit design, not silently omitted source. Hashes are source identity, not host-source qualification.

## Implemented slice

- Separate explicit host consent/review assertions bound to opaque owner/target/version/consent/nonce; default no opt-in host=not_authorized with zero commands. Runtime/image consent does not grant host authority.
- Native-macOS-only public-facts collector proposal: product version, kernel release, reported execution architecture, physical memory, logical CPU count; fixed absolute ordinary-user command table, no shell/discovery/Engine/socket/root/files/env/secret inventory.
- Active1/zero queue per collector,750ms/1024 combined output bytes per child and5s monotonic/wall-time publication fences, abort/expiry kill/fence, no raw diagnostics persisted. Not an OS CPU/RSS sandbox or real-time scheduling guarantee.
- Closed sanitized observed/unavailable facts, canonical raw wire<=8192 bytes; duplicate/prototype/noncanonical numeric/string/whitespace/BOM/UTF8/value/source/identity rejects.
- Separately injected PUBLIC Ed25519 enrollment and domain-separated signature/hash/binding/time validation; local signing accepts an in-memory key, never reads a key file. Digest alone is not signature evidence.
- Validated bounded historical intake artifact only, never live qualification/current machine/whole-host/completeness proof. One-use nonce AND consent, fixed128 admissions per instance; process-local only, not durable restart/idempotency/auth/report service.
- Runnable explicit post-review CLI proposal and safety/limitations/adoption assessment. Unsigned local stdout only; no automatic sign/upload/file writes/provisioning. Operator review flags/assertions cannot prove independent approval.

## Actual validation

Final command from startup/diplom:
`node --test server/host/tests/host.test.mjs`

Exit0;24 tests,24 pass,0 fail,0 cancelled,0 skipped,0 todo. Reported duration195.891ms. Previous interim22-test pass is superseded by this final24-test run, NOT added to it. No full backend/UI/build/E2E suite rerun or claimed.

All24 tests use synthetic fixed fact tokens, fake subprocess EventEmitters/injected runners/platform/clocks and ephemeral in-memory test keys. The actual public-command spawning function was exercised only with fake spawn streams. Zero actual host collector/public fact commands, Engine/Docker/registry/socket/provider/LIVE/network/private-key-file operations. The test-runner Node process itself and static hash/format tools are not host collection.

Cases: missing/runtime-like/malformed/reviewless/expired consent zero commands; Linux unsupported; precisely5 synthetic facts/exclusions/unsigned provenance; timeout/diagnostic/value sanitization; active1/queue0 and in-flight binding clone; abort/expiry/clock rollback; wall/monotonic5s fences; exact1024/excess1025 output kill; fixedargv/shellfalse/stdinignored/constantenv; fake timeout/failedexit/UTF8; separately enrolled signatures and historical-only artifacts; intake default deny beforeparse; bad enrollment/key/fingerprint; digest-only/wrongkey/changedfact/signer rejection; exact owner/target/version/consent/nonce/source; raw history/environment/source refusal; duplicate/prototype/numeric/escapedkey/BOM/UTF8/oversize/deep-shape rejection; freshness/skew/capture interval; bounded nonce/consent replay/capacity; pure CLI plan/default and explicit consent handoff.

`node --check` passed for all four source modules and the test file. Scoped Prettier write/check passed for the eight owned source/docs/test paths. `git --no-pager diff --check -- server/host` exited0, but these are new untracked files, so it is NOT evidence of inspecting their content; syntax/Prettier/tests/hash checks provide the actual new-source validation. No TypeScript check claimed: standalone modules are .mjs and use Node built-ins.

## Assessment decisions and gates

Linux host/VM/daemon/whole-host/posture/OS CVE unsupported. Dockerfile/IaC skipped without separately selected supplied original source; image history is not Dockerfile. Cosign unsupported: trusted image identity/issuer/key absent; host receipt signatures are not image/Cosign verification. Syft/Docker Bench/other scanners not installed/implemented/run; exact release/license compatibility, native-source semantics, resources and duplicate comparison unresolved. No optional-scanner entitlement or deployment promised. Root package private/no license field does not imply distribution compatibility; notices untouched.

TASK8 remains blocked, not full acceptance/done. Parent must review exact manifest and safety-plan, then separately authorize at most the five bound native-macOS observations. Genuine native-source compatibility/topology/capture/signing enrollment and independent evidence verification remain unperformed. Production intake would additionally need authenticated current/revocable authority, durable atomic nonce/report commit and bounded raw ingress; no existing API/page/store integrated. No fixture or signed historical statement can stand in for real host proof.

No shared source,API/page/notices/private files/package/config/stand writes; no commits/branches/Docker/LIVE/host-root/production enrollment/keys/model/rollout/spec apply/no-impact declaration/task or parent closure. Tracker comments/status and public requested artifacts are the only non-file bookkeeping changes. TASK6 testing90 and its default-live-off/integrated gates preserved. This author assessment is not an independent review approval.
