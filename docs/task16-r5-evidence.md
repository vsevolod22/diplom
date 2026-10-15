# TASK16 R5 — admitted unavailable-receipt failure security recheck

## Authority and disposition

Parent ended the proof freeze and authorized the minimal unavailable-receipt branch in response to independent **DIP-ARTF-269 v1**, SHA256 `833cb67c035681acc9fd512b28fdff5abd54c3bf6daa7ba7928b3c1af3b113e1`, residual **C16-SEC-R4-01 P2**. Contract234 is implemented, not amended: admitted failure uses usage→error only when this invocation established a validated persisted receipt; otherwise a proven admitted failed attempt uses error-only. This is author evidence for independent recheck, not independent approval/full acceptance.

Project `520a0059-d0f2-4f86-8d93-fc15035a5715`, DIP-TASK-16, components DIP-COMP-1/3; existing context run `6ad60d60-18c5-4a6c-860f-9d8bece7232d`, no new run/work claim. Task remains **testing85**. HEAD observed unchanged `741e4aaf4b6c41dd176ddfe6ff175781958f8f73`; exact uncommitted payload hashes, not HEAD alone, identify this fix. No close/specapply/commit.

## Minimal source change and accounting

Only `history.service.ts` and `history-delivery.ts` change runtime behavior. Controller, client/parser/panel/Markdown/Summary runtime bytes are unchanged from manifest265. Original pending identity, session generation/access incarnation, report/policy, reservation/request hash, mutation/input hash, epoch/revision and durable failed-head proof are retained. Existing storage/private fingerprints, store/schema/quota/provider/auth/main/runtime/nginx/prepared wire are not redesigned or changed by this fix.

The service no longer requires observation to enter the existing admitted-failure seal. It STILL requires actual admission/turn identity, nonaborted internal controller, trusted current session/report/policy, the exact original pending identity, successful durable fail, and the exact next failed head with no pending/reply. If these proofs fail, no delivery is synthesized; the existing safe exception path remains. A committed completed turn cannot be downgraded through the pending seal.

Successful bound durable observe from THIS invocation remains the sole usage provenance. With no validated current observation, the frozen outcome contains only public attempt/report/head binding, outcome failed and receipt unavailable—no usage, zero receipt, raw reply, source or provider diagnostic. Invalid paid usage may leave an existing fault row; transport/missing usage may leave dispatched accounting. Neither is relabeled settled, refunded or borrowed from an earlier receipt. A nonnull untrusted/fault receipt is not accepted usage.

The same trusted write(action) closure rechecks fresh session/access/report/policy/head at headers, the error write and end; post-drain authority remains guarded. The same existing capacity lease transfers through finish, absolute 5000ms delivery deadline and once-only cleanup. Cancellation/disconnect never retracts accepted accounting or claims refund. Failed replay remains status-only/no resend. Default JSON502 and actual pre-admission JSON403 denial remain unchanged; Summary1KiB route is untouched.

Encoder accepts only the exact unavailable variant and emits one safe error seq0. Extras/usage/content/accepted marker without usage are rejected. Bounds stay8192 bytes/line including LF,196608 aggregate,52frames,1024UTF8delta,5000ms delivery. Provider remains stream:false, exact free profile/output<=2048/zero caps/no paid fallback. This is finite completed-reply delivery, **NOT native provider token streaming**.

## Literal v1 unavailable wire

Synthetic binding, not real owner/provider data. Exactly one LF-terminated line followed by clean EOF. No usage/citation/delta/done/content:

```ndjson
{"v":1,"deliveryMode":"validated-completed-reply","nativeProviderStream":false,"scanId":"00000000-0000-4000-8000-000000000016","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"linux/amd64","reportVersion":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","epoch":"00000000-0000-4000-8000-000000000001","revision":2,"mutationId":"00000000-0000-4000-8000-000000000003","turnId":"00000000-0000-4000-8000-000000000002","type":"error","seq":0,"errorCode":"LLM_UNAVAILABLE","receipt":"unavailable"}
```

Accepted-current-receipt failure remains usage seq0→error seq1/receipt accepted. Success remains usage→citation→delta→done. The unchanged actual client treats unavailable error as terminal failure after clean EOF, never an answer/retry; no partial publication or fake progress.

## Focused checks actually executed before packaging

Backend cwd `server/api`:

```sh
pnpm exec tsx --test --test-reporter=tap --test-name-pattern R5 src/llm/tests/history-delivery.test.ts src/llm/tests/history.http.test.ts
pnpm exec tsc --noEmit
```

**4PASS/0FAIL**,829.9835ms: three NEW unavailable codec/writer tests and one NEW disposable synthetic-cookie/Nest/service/controller HTTP test. Subsequent API typecheck PASS. Raw TAP1184bytes SHA256 `cba2eeef3add04bfe40bedc6c883ce01bbee150dbf51597948248594ca2cdf77`.

Coverage: rejected dispatched attempt before valid receipt; missing usage after an earlier settled attempt; invalid paid receipt retaining fault accounting/no accepted usage; exact failed turn/head and request hash; legacy JSON502; pre-admission consent403 with zero turns/reservations/provider sends; failed duplicate/no resend; capacity held at actual writes and released afterward; fresh actual session/policy/report/head loss after headers suppresses error. Unit tests cover exact shape/content refusal, guarded header/error/end, drain/finish lease, preheader/error-write/after-header/before-end/abort/drain deadline/finish deadline faults and listener cleanup.

Frontend cwd repo:

```sh
pnpm exec vitest run tests-vite/ui/scans/llmChatClient.test.ts -t '^R5 unavailable' --reporter=default --reporter=json --outputFile=docs/task16-r5-client-tests.json
pnpm exec eslint tests-vite/ui/scans/llmChatClient.test.ts
```

**1PASS/0FAIL/43 intentionally deselected**,44 discovered. Production encoder→unchanged actual client handles error-only and rejects forged accepted marker without usage. Scoped test-file ESLint PASS. Raw JSON11338bytes SHA256 `c476b42038ea948b77287fbb154c6300488dfaaa867af10ceb4c51bbc9ca69dd`.

Disclosed failures: RED before production edit reproduced502!==200. First post-fix backend command passed3 units then failed the NEW HTTP instrumentation counter0!==3: optional-call argument `afterWrite?.(++writes)` skipped increment without a hook. Fixed only instrumentation to unconditional increment; final4PASS/API typecheck followed. Failed intermediate command's && typecheck did NOT run. Older R4 missing-usage assertion was updated for the new contract but NOT rerun; raw264 remains historical. No old R3/R4/heavy/Markdown/Summary suites, full frontend typecheck/build or packaging test repeats. Prior accepted-path independent approvals are historical, not fresh R5 validation.

## Exact package and LOW documentation correction

Baseline manifest **DIP-ARTF-265**,9749bytes SHA256 `ed67eae070aa0b5a98f10b8f6f27921be966a039ad537798e650cceb25882e8b`, verified before packaging. Current original19 payload comparison: **7 changed /12 unchanged**. Changed: service, delivery, both backend tests, frontend client test, TASK14.md, chat handoff. Historical R4 evidence is one additional changed supplemental document. Corrected LOW268 seven→nine chronology; archived R3→R4 patch263 remains nine paths, not the new R5 patch.

Current R4→R5 patch has **8 measured paths**, all preimage byte/hash identities verified against265 including supplemental R4 evidence. It is NOT a HEAD→dirty/peer graph diff. Paths: the seven above plus docs/task16-r4-evidence.md.

- Raw patch49404bytes SHA256 `d3a0fc119c140e95593dcbc777ed8913fcacd6266abde81677d7177cbf711bd2`.
- Deterministic gzip patch14512bytes SHA256 `623988e1812e5cb2c160c85a9c015d9fe0f724bf26c5066302d55f10bf31fbb8`; decoded exactly raw patch.
- Current FIVE-backend full-text JSON gzip26677bytes SHA256 `d07ddcefec7e3d7bc4eea8132193b05f80a694aab4e6035488b19ea9f9b8e72f`; decoded129315bytes SHA256 `64120448d10ffa29126480aa1c9d4521240f55c07d942477a0624365fe87783e`. Controller unchanged, service/delivery/HTTP+delivery tests changed; every source text matches current file bytes. gzip mtime0.

New manifest pins original19 current payloads and R5 supplements separately; excludes itself, temporary baselines and peer curated graph. R3manifest249/R4manifest265/source262 and parent ac2d graph pin are historical, not current R5 identity/proof execution approval. Curated graph NOT recomputed/substituted/executed.

## Independent recheck requested and exclusions

Return to269 security reviewer: prove admitted no-receipt provenance, exact pending→durable failed transition, no raw/untrusted/borrowed usage, unavailable exact shape, accepted branch preserved, fresh header/error/end/post-drain guards, capacity/deadline/abort cleanup, JSON/pre-admission compatibility, duplicate/no resend and unchanged actual parser terminal behavior. This author report does not resolve the finding independently.

No actual provider/LIVE/Docker/private/secrets/notices/proof/selected-main/browser/deploy execution, source graph pin substitution, dependency/lockfile/APIflags/pages/styles/report39/runtime/nginx/store/schema/auth/quota/provider/prepared-wire edits, commits/branches/specapply/declaration/taskclose/new run/work claim. Only synthetic disposable cookie/SQLite/loopback tests and own authorized Artifactory upload network. Parent retains independent security/correctness, selected-main/native nginx/topology/history-init/operator/integrated-browser/accessibility/provider compliance/full acceptance/task/spec gates. Task remains testing85.
