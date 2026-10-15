# TASK16 R5 narrow Chromium supplemental — failed harness precondition

**No current-candidate browser PASS claimed. Exactly ONE targeted Chromium run was executed; no rerun/full suite.** Historical DIP-ARTF-258 remains the prior320/375/1280 baseline, not fresh R5 evidence. Read full268/274/275 and actual current server codec. No runtime/backend source writes, provider/LIVE/Docker/secrets/commits/taskclose/specapply.

## Candidate identity

DIP-ARTF-275 v1 / docs/task16-chat-manifest.json:10457bytes SHA256 `a72207c147823b819da851a9ad58028b8bd314581d0a1d229c3fe2fdf41f3261`. Local/upload match. All19 payloads plus7 supplements verified before the run and unchanged afterward. Current CopyText2176bytes SHA256 `2d40a0c93c23f629864a3beca84009f2ff24a60ed9acf091bb6377ed372ba9ce`; current codec9868bytes SHA256 `f7232a36c0285a1354e5ae63f3d72215ffaf9f759ce14c7e7b05dc8f4700b0e4`. No curated graph recomputation/pin substitution/write/actual proof.

## Single execution and root cause

From startup/diplom:
`node --check tests-e2e/task16-chat-browser.r5.mjs && node --check tests-e2e/task16-chat-browser.r5-managed.mjs && node tests-e2e/task16-chat-browser.r5-managed.mjs`

Exit1. Child6032ms; manager7576ms; manager31s deadline, child27s cleanup watchdog/30s hard stop, terminal38s. Actual375x800 ScanDetailPage/scanner findings loaded, then manual chat-open metadata was correctly rejected by the strict frontend schema. No chat POST occurred (request log contains7GETs only). Requested copy, error-only terminal and delayed scan/account checks did NOT execute. No findings/coverage byte-preservation PASS for those unexecuted stages.

**Harness error, not established production defect:** newly authored fixture shortened disclosure.localRetention to 'Durable owner+scan history until separately authorized operator lifecycle; context cache only.' Actual llmChatContract.ts185–202 requires the exact literal including 'capacity can refuse; ... not output cache.' Saved DOM shows safe invalid-response alert; requests stop at chat/context. Corrected ONLY that test string to the exact contract after preserving executed source as ignored attempted-r5.mjs.txt. Prepared corrected runner has NOT been Chromium-validated; second execution requires parent authorization.

Separate no-browser static preflight exited0: actual chatContextSchema rejects old fixture with exactly disclosure.localRetention issue, accepts corrected disclosure; current actual encodeDelivery emits one error seq0 receipt unavailable with no usage. Syntax check passed. These are preflight assertions, NOT browser checks/backend provenance or service/controller/writer tests and not a full unit suite.

## Cleanup and scope

Child awaited browser.close/server.close, destroyed owned sockets; browserClosed/serverClosed/listenerClosed all true. Parent listener probe also closed=true for own127.0.0.1:59315. Child exited/reaped; timeout=false. Post-exit group signal returned sandboxEPERM, disclosed rather than claiming ESRCH/no remaining OS process group. No forced-hang/deadline fault test executed.

Child environment allowlisted PATH/HOME/TMPDIR/LANG/NODE_ENV, no values dumped; envDir=false/proxy disabled, no backend bootstrap. Browser service workers blocked/non-own-origin routes aborted. Browser/fixture errors[] and egress attempts[]. One local ignored failure screenshot only, NOT34 regenerated images. Historical258 evidence untouched.

Only NEW tests-e2e/task16-chat-browser.r5.mjs, .r5-managed.mjs, .r5-review.md authored; existing own config/session helper reused unchanged. Exact manifest distinguishes archived executed runner from corrected unexecuted current runner, hashes raw failure results/requests/DOM/screenshot/manager evidence. HEAD baseline741e4aaf4b6c41dd176ddfe6ff175781958f8f73 unchanged. Parent retains full source/backend/deployment/spec acceptance; no source issue/fix or task closure inferred from this fixture failure.
