# TASK16 R4 — historical C16-SEC-R3-01 admitted-failure fix

R5 documentation correction: archived R4 patch263 contains NINE paths, not the earlier superseded seven-path pre-copy patch. Current R5 code/evidence/manifest identify a different R4→R5 delta with its own measured path list/count. This R4 report describes historical behavior; review269's unavailable-receipt P2 is being fixed under separate R5 authority. Do not use R4 source pin265/262 or parent ac2d proof pin as current R5 identity.

## Authority and disposition

Parent-authorized narrow fix after reading full independent security report **DIP-ARTF-253 v1**, SHA256 `03c98dd45df9c653ab99402c883711e77d78d5ef442d1ce4ab2bf5cb139b1bfa`. Finding253 is a P2 protocol-conformance gap, not an established exploit. Contract234 remains controlling; this is a source fix, not a silent contract amendment or independent approval.

Task/project: DIP-TASK-16 / `520a0059-d0f2-4f86-8d93-fc15035a5715`; existing context run `6ad60d60-18c5-4a6c-860f-9d8bece7232d`, no new run/work claim. Task remains testing85; no done/100/specapply/declaration/commit. HEAD unchanged `741e4aaf4b6c41dd176ddfe6ff175781958f8f73`; uncommitted file hashes, not HEAD alone, identify the fix. Source frozen at this R4 handoff pending independent security recheck; no subsequent source changes without explicit authorization.

## Exact change and sealed provenance

Before the later separately authorized copy-feedback spacing fix, seven R3 payloads changed: `server/api/src/llm/llm.controller.ts`, `history.service.ts`, `history-delivery.ts`, `tests/history-delivery.test.ts`, `tests/history.http.test.ts`, `TASK14.md`, and `docs/task16-chat-ui.md`. At that earlier backend handoff, twelve other original payloads matched R3 manifest249. The later copy-feedback fix changes only safeMarkdown.tsx and its existing test; current manifest comparison is nine changed / ten unchanged original payloads. Client/panel/policy/renderer/Summary and raw R3 frontend report remain unchanged. New packaging payloads are this evidence, raw R4 backend TAP and the exact R3-to-R4 patch.

Controller passes its existing negotiated representation to generate; default is JSON for direct consumers. Legacy invalid script reply still returns502 JSON `{errorCode:'LLM_INVALID_RESPONSE'}`. Only opt-in NDJSON can receive a sealed admitted failure.

The local receipt variable is assigned only after this invocation's bound QuotaLedger.observe returns true. The failure catch uses that variable, never cumulative counters, historical receipts, provider exception properties or a fabricated zero. Existing guardSession/current/guardPending verifies original epoch/revision/turn/session generation/access incarnation/policy/request hash/reservation. It durably terminalizes that exact pending turn as failed and verifies exact next revision, absent pending/reply and original mutation/input/request hash. A frozen delivery contains ONLY report/head/mutation/turn binding, outcome failed and frozen valid receipt. No invalid raw reply/source/diagnostic reaches the delivery result.

The unchanged fresh write closure checks session/access/report/policy/head at header, usage, error and end, including after drain. The same existing owner/global lease is transferred through finish, with once-only release. Encoder accepts only the exact failed shape and valid free receipt, preflights all bounds, and emits usage seq0 then error seq1; no citation/delta/done. Loss of authority/abort/socket/deadline closes without stale error or accepted-usage retraction. A failed replay stays done-only duplicate, without borrowed usage or resend.

If a valid current receipt/exact live failed head cannot be established, the existing safe exception path remains; this change does not synthesize unavailable/zero usage or certify every possible engine failure. Missing usage with earlier settled attempts is explicitly tested as safe502 JSON LLM_PROVIDER_UNAVAILABLE with no framed receipt. No store/schema/quota/auth/provider/engine redesign was made.

## Literal admitted-failure wire

Synthetic fixture, not actual provider usage or real owner data. LF after each line and clean EOF; mode still denotes the completed-reply delivery protocol, nativeProviderStream:false. This failed outcome contains no completed answer.

```ndjson
{"v":1,"deliveryMode":"validated-completed-reply","nativeProviderStream":false,"scanId":"00000000-0000-4000-8000-000000000016","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"linux/amd64","reportVersion":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","epoch":"00000000-0000-4000-8000-000000000001","revision":2,"mutationId":"00000000-0000-4000-8000-000000000003","turnId":"00000000-0000-4000-8000-000000000002","type":"usage","seq":0,"usage":{"input":500,"output":32,"costMicros":0,"source":"server-validated-provider-reported-not-invoice"}}
{"v":1,"deliveryMode":"validated-completed-reply","nativeProviderStream":false,"scanId":"00000000-0000-4000-8000-000000000016","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"linux/amd64","reportVersion":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","epoch":"00000000-0000-4000-8000-000000000001","revision":2,"mutationId":"00000000-0000-4000-8000-000000000003","turnId":"00000000-0000-4000-8000-000000000002","type":"error","seq":1,"errorCode":"LLM_UNAVAILABLE","receipt":"accepted"}
```

Bounds unchanged:8192 encoded bytes/line including LF;196608 aggregate;52 frames including error reserve;1024 UTF8 delta;5000ms delivery. Exact free provider wire/output<=2048/no paid fallback/stream:false remains unchanged. Cancellation never claims refund/deletion; client error is terminal, no assistant publication or automatic resend.

## Checks actually run

1. RED before production fix: `pnpm exec tsx --test --test-name-pattern R4 src/llm/tests/history.http.test.ts`, one expected failure502!==200 reproducing253.
2. Final backend, cwd `server/api`:
   `pnpm exec tsx --test --test-reporter=tap --test-name-pattern R4 src/llm/tests/history-delivery.test.ts src/llm/tests/history.http.test.ts`
   **4PASS/0FAIL**:3 new codec/writer tests + updated focused cookie/service/controller fixture. Raw runner output `docs/task16-r4-backend-tests.tap`,1233bytes, SHA256 **`960096687fea996ee13530f73ce77ebfcbe37c291c8c347ae913971487c73bb5`**. Final command's subsequent `pnpm exec tsc --noEmit` PASS. Both failed intermediate test commands short-circuited before typecheck, not all-green claims.
3. Unchanged frontend compatibility only:
   `pnpm exec vitest run tests-vite/ui/scans/llmChatClient.test.ts -t '^framed terminal error after accepted usage' --reporter=verbose`
   **1PASS/42 intentionally deselected**,43 discovered; no raw R3 JSON overwrite. Client/parser source needed no change. No full frontend typecheck/build/old R3/Markdown/Summary/heavy repeats.
4. R3 baseline hashes matched249 before snapshot. All12 unchanged original payload hashes matched after edits. The initial seven-path diff was generated before the copy fix; archived CURRENT-R4 diff263 contains nine paths. Neither is a HEAD/peer diff; R5 has its own separately measured delta. Scoped tracked whitespace PASS; HEAD unchanged.

Tests establish script and malformed-message admitted failure frames, exact same-attempt settled receipt/request hash at EVERY actual write, durable failed head and absent invalid reply, JSON legacy502, failed duplicate/no resend, failed-head invalidation after usage forbidding stale error/end, and no current valid receipt refusing earlier-settled receipt borrowing. Unit writer tests cover guarded header/usage/error/end, drain/finish lease retention and authority/abort/deadline closure/listener cleanup; encoder refuses content/extras/invalid usage. Existing success/default JSON/Summary invalid-DTO and completion stale/disconnect assertions run inside this small updated fixture; no old heavy TASK14 tests ran.

Disclosed corrections: two intermediate runs were3PASS/1 fixture assertion failure at the newly added missing-usage check. First assumed503 instead of actual502; second assumed LLM_INVALID_RESPONSE instead of actual LLM_PROVIDER_UNAVAILABLE. Inspected existing provider catch, corrected only test expectations, and final4PASS. No provider/filter implementation was edited to satisfy assertions.

## Exact diff and exclusions

`docs/task16-r4-diff.patch` is regenerated at authorized packaging to include the nine changed original payloads, including the separately authorized copy fix and updated handoff. Its current bytes/SHA256 and deterministic gzip wrapper are pinned in the new manifest; the earlier pre-copy seven-path patch (47976bytes, SHA256 `5d98b92c8663abea1919e121b9ecebacf8a0c43bba2c59fb0076cbebf112e098`) is historical, not today's patch. Baseline manifest249 SHA256 `7cbcfb597e175356ae4df53459f35b13a759303a63d355773c9d46a995443de0`. Current manifest files[] pins exactly the original19 current payloads; packaging bytes are pinned separately in supplemental[]. It excludes itself and peer graph.

No main/runtime/nginx/history DB/store/schema/quota/auth/provider/prepared-wire/API flags/lockfiles/dependency/pages/styles/report39/notices edits. No actual provider/LIVE/Docker/secrets/private data/actual-main proof/deploy/commit/branch/taskclose/specapply/declaration/new run/work claim. Tests use disposable synthetic cookies/stores and loopback fixture only, not deployment or native provider streaming. Existing receipt is not invoice/privacy compliance evidence.

## Authorized packaging and separate LOW copy-feedback fix

Parent authorized packaging only of the already-validated backend bytes after the source freeze, plus ONE frontend LOW spacing fix. safeMarkdown.tsx inserts one explicit JSX space between the copy button and its existing role=status feedback; copied text, renderer/policy, URLs, content handling and callback behavior are unchanged. One focused regression verifies separated success/failure feedback and exact clipboard input. Command:

`pnpm exec vitest run tests-vite/ui/scans/safeMarkdown.test.tsx -t '^R4 copy feedback' --reporter=default --reporter=json --outputFile=docs/task16-r4-copy-tests.json`

**1PASS/0FAIL/35 intentionally deselected**,36 discovered. Scoped ESLint on safeMarkdown.tsx and its test PASS. No full old Markdown/R3 suites or frontend typecheck repeated. The R4 backend4PASS/API typecheck and client1PASS/42 deselected above are earlier validation of unchanged frozen bytes, not reruns during packaging and not a combined all-green suite.

Read full independent257: its five curated backend drift identities exactly match the frozen current controller/service/delivery/two tests. Parent-reported current curated hash `ac2d1be63aa4dcb4346df347dc9469cf3ee40d2f7a814675de20209cade2cf34`;257 explicitly does NOT approve an execution command or automatically substitute that pin. This author has not recomputed/executed the curated proof, modified its manifests/script, or approved OFF/main/nginx/runtime deployment. New TASK16 manifest must not be confused with the curated hash. R3 manifest249 and reviews253/255 remain historical identities only.

A deterministic gzip JSON snapshot contains the exact five current backend file texts, byte lengths and SHA256s. Independent reviewers can inspect these exact bytes without relying on HEAD or the stale R3 manifest. The raw unified diff is reconstructed against pre-edit R3 text; both separately authorized frontend preimages are verified against249 before use. gzip mtime=0 makes packaging reproducible; compressed and uncompressed identities are pinned separately. No backend file is rewritten by packaging. Temporary baseline JSON is deliberately retained during the freeze; it is not an authority/manifest payload.

## Security recheck requested

Recheck253 C16-SEC-R3-01 against the new exact R4 hashes: current successful observation provenance, exact pending→failed transition, content-free frozen outcome, fresh per-write/drain/end guards, same capacity lease/deadline/disconnect cleanup, safe fallback when no current receipt/head exists, JSON502 compatibility and duplicate/no refund/no resend.253 and correctness255 are R3-only, not R4 approval. Parent retains runtime/nginx/main/operator/browser320/375/accessibility/activation gates and task/spec authority. Return findings against frozen source; do not treat this author report as independent security acceptance.
