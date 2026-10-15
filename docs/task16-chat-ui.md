# TASK16 R5 — bounded validated-completed-reply NDJSON handoff

Direct parent-assigned source implementation in `startup/diplom`, project `520a0059-d0f2-4f86-8d93-fc15035a5715`; existing context run `6ad60d60-18c5-4a6c-860f-9d8bece7232d`, no new run/work claim. Parent agreed proposal **DIP-ARTF-234** and authorized exact controller/service/delivery/tests/TASK14 documentation plus original owned UI paths after the diagnostic freeze ended.

**R5 implements parent-authorized review269 C16-SEC-R4-01: a proven admitted failure with no valid current receipt emits exactly error seq0/receipt unavailable, without usage or content.** Same pending identity/durable failed head/fresh write guards/shared lease as R4; nonadmission/parser faults and unsealable authority/head remain safe JSON, default JSON502 unchanged. No client runtime/quota/provider/store/schema/main changes. Independent R5 security recheck is pending; earlier253/269 approvals identify older bytes, not current R5.

Historical R4: **R4 fixes review253 C16-SEC-R3-01: a sealed admitted invalid-reply failure with this attempt's valid persisted receipt now emits guarded usage→error for opt-in NDJSON. Legacy JSON502 remains unchanged.** Exact pending identity and failed-head transition must be proven; no failed content, exception-derived receipt, refund or replay. R4 changes only controller/service/delivery/two backend tests/TASK14 docs and this handoff; no frontend source change. Independent R4 security recheck remains pending. Later parent authorization permits packaging frozen backend bytes and ONLY a LOW copy-feedback spacing change in safeMarkdown.tsx plus one focused regression; that change does not affect the curated backend proof.

**Framing is source-implemented and focused-tested, not independently accepted or deployed.** Provider remains `stream:false`. No task done, spec application/declaration or commit. Original JSON/R2 evidence remains in artifacts222/223/232/233/234 and independent reviews227/229/237; those historical hashes do not identify this R3 source.

## Owned files and exclusions

Original dedicated panel/client/contract/safe Markdown and focused tests/docs remain owned. The current manifest adds these six authorized backend payloads:

- `server/api/src/llm/llm.controller.ts`
- `server/api/src/llm/history.service.ts`
- NEW `server/api/src/llm/history-delivery.ts`
- `server/api/src/llm/tests/history.http.test.ts` (one focused TASK16 test appended; old heavy tests excluded)
- NEW `server/api/src/llm/tests/history-delivery.test.ts`
- `server/api/src/llm/TASK14.md`

The historical R3 increment changed original `ScanChatPanel.tsx`, `llmChatClient.ts`, `llmChatContract.ts`, fixtures/client/panel tests and existing handoff/report/manifest. R2 safeMarkdown policy/test and original safe wrapper/renderer/Summary hook remain unchanged. `ScanSummaryPanel.tsx` retains the previously reviewed narrow AI-only mount; no further hook changes.

**No store/schema/auth/quota/provider/prepared-wire/main/nginx/runtime/API-flag/lockfile/dependency/pages/scans/styles/report39/notices edits.** No actual provider call, LIVE/Docker, secret/private file inspection, deployment, actual-main/curated-graph startup proof, spec apply/declaration, branch or commit. Focused API tests use disposable synthetic storage/cookies and loopback ephemeral Nest listeners, not operator activation or deployed proof. Concurrent parent/peer source is excluded from the manifest and not certified.

## Actual request/transport contract

Existing base `/api/v1/browser/scans/<lowercase UUID>/llm` and five method/path pairs remain:

| Method | Suffix | Result |
| --- | --- | --- |
| GET | `/chat/context` | Strict current report/policy/disclosure/epoch/revision/pending metadata; existing `deliveryMode:completed-response` JSON shape unchanged |
| GET | `/history` | All confirmed public turns/decisions and original historical source tuples |
| GET | `/chat/usage` | Existing owner+scan counters, unknown admission until exact full wire |
| POST | `/chat` | Exact consent/CAS DTO; opt-in finite NDJSON below, default JSON unchanged |
| POST | `/history/decision` | Exact manual decision CAS mutation, no provider |

Chat DTO exactly `{epoch,revision,mutationId,reportVersion,question,consent:{accepted:true,policyVersion}}`; decision DTO exactly `{epoch,revision,mutationId,reportVersion,text,findingIds}`. Owner/session/access-generation fields never go on the wire. Same-origin cookies/no-store/redirect refusal remain. Question/decision<=2048 UTF8 bytes; mutation<=8192 actual serialized bytes, exact ingress length and existing2s body deadline. No new endpoint, query flag, API flag, body field or mutation-fingerprint change.

Accept negotiation is deliberately exact: absent, `*/*`, `application/json` => legacy JSON; exact `application/x-ndjson` => v1 completed-reply framing. Empty/other/mixed/parameterized forms refuse406 before provider admission. Summary ignores this negotiation and remains unchanged. Its existing1KiB/35s ingress requirement is **preserved in source, not newly certified against deployed nginx**; nginx is excluded/not edited.

Successful framed response:

```http
Content-Type: application/x-ndjson; charset=utf-8
Cache-Control: no-store, no-transform
X-Content-Type-Options: nosniff
```

Ingress/pre-admission and failures without proven admitted identity/current durable failed head use the existing bounded safe JSON exception filter/status; no unvalidated provider exception text or raw diagnostic is returned. R5 seals an authorized admitted failure after the exact guarded durable failed-turn transition: this invocation's successful durable observe yields usage→error; absent valid observation yields only error seq0/receipt unavailable, with no usage object. Both use the existing NDJSON writer. JSON callers retain their original invalid-reply502. The writer owns failures after headers and never appends HTTP JSON to NDJSON.

## Receipt, commit, authority and lease ordering

Existing exact free profile remains `apodex/apodex-1.1-mini:free / novita/bf16 / no-storage / deny+ZDR / zero caps / no paid fallback or retry / immutable guarded full wire / output<=2048 or configured stricter ceiling`. Provider wire remains `stream:false`. Reported zero usage is not invoice verification; declarations do not prove provider privacy/compliance.

`HistoryService.generate()` keeps existing dispatch/admission/accounting/reply validation/store commit logic. The accepted receipt is persisted by the existing bound `QuotaLedger.observe` before content validation; completed delivery outcome is returned only after full validated reply/source projections and durable completion. For opt-in NDJSON, an admitted failure returns a frozen content-free outcome with exact report/head/mutation/turn binding after fresh pending session/request/reservation/policy proof, durable failed transition and exact final failed revision. R5 includes this invocation's normal accepted receipt ONLY if observation succeeded; otherwise it includes only receipt:'unavailable', never fabricated zero/earlier receipt/usage. No invalid reply/source/diagnostic enters that outcome. Receipt provenance comes from that invocation, **not cumulative counters or exception properties**. No boolean authorization permission is returned: existing `HistoryResult.write(action)` freshly checks trusted session/access, report/policy and durable epoch/revision at every actual write.

The service transfers its existing shared one-owner/eight-global capacity release to the controller on successful completion; idempotent release covers preflight failure, JSON write, framed finish, abort/deadline/socket failure. The framed writer holds it through socket finish; it never holds auth/history transactions over drain/socket awaits. Existing ledger cleanup remains unchanged; delivery failure cannot retract settled receipt or downgrade committed history. Direct service consumers must dispose the returned optional `release`; production controller always does so.

The complete frame plan is preflight validated before headers. Fresh trusted guards wrap writeHead, every frame write and end, including after each awaited drain. Loss of session/report/head authority closes rather than emitting a stale receipt/error. Abort/disconnect after accepted receipt/commit cannot undo either; no automatic resend/refund is claimed.

Hard encoded limits: **8192 UTF8 bytes/line including LF; 196608 aggregate bytes; 52 frames with reserved error room; 1024 UTF8 text bytes/codepoint-safe delta**. Existing reply16384/source32/source2048/whole-envelope bounds remain. Absolute **5000ms delivery** covers preflight/backpressure/finish within provider<=30000ms/client40000ms/whole UI45000ms budgets. Synchronous DB/CPU scheduling can add wall-clock overhead; this is not hard realtime. No artificial timer reveal, unbounded queue or second capacity pool.

## Literal v1 wire

Below is actual `encodeDelivery()` output for a synthetic fixture, **not a provider observation or real owner's data**. Every line ends LF; a success requires clean EOF after done.

```ndjson
{"v":1,"deliveryMode":"validated-completed-reply","nativeProviderStream":false,"scanId":"00000000-0000-4000-8000-000000000016","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"linux/amd64","reportVersion":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","epoch":"00000000-0000-4000-8000-000000000001","revision":2,"mutationId":"00000000-0000-4000-8000-000000000003","turnId":"00000000-0000-4000-8000-000000000002","type":"usage","seq":0,"usage":{"input":500,"output":32,"costMicros":0,"source":"server-validated-provider-reported-not-invoice"}}
{"v":1,"deliveryMode":"validated-completed-reply","nativeProviderStream":false,"scanId":"00000000-0000-4000-8000-000000000016","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"linux/amd64","reportVersion":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","epoch":"00000000-0000-4000-8000-000000000001","revision":2,"mutationId":"00000000-0000-4000-8000-000000000003","turnId":"00000000-0000-4000-8000-000000000002","type":"citation","seq":1,"index":0,"source":{"scanId":"00000000-0000-4000-8000-000000000016","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"linux/amd64","reportVersion":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","finding":{"check":"secret","findingId":"secret-0-1","severity":"UNKNOWN","ruleId":"rule-0123456789abcdef","line":1,"evidenceRef":"result-0-secret-1"}}}
{"v":1,"deliveryMode":"validated-completed-reply","nativeProviderStream":false,"scanId":"00000000-0000-4000-8000-000000000016","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"linux/amd64","reportVersion":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","epoch":"00000000-0000-4000-8000-000000000001","revision":2,"mutationId":"00000000-0000-4000-8000-000000000003","turnId":"00000000-0000-4000-8000-000000000002","type":"delta","seq":2,"index":0,"text":"Safe hypothesis"}
{"v":1,"deliveryMode":"validated-completed-reply","nativeProviderStream":false,"scanId":"00000000-0000-4000-8000-000000000016","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"linux/amd64","reportVersion":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","epoch":"00000000-0000-4000-8000-000000000001","revision":2,"mutationId":"00000000-0000-4000-8000-000000000003","turnId":"00000000-0000-4000-8000-000000000002","type":"done","seq":3,"outcome":"completed","kind":"hypothesis","textBytes":15,"citationCount":1,"deltaCount":1}
```

Normal order: usage→citation1..32→delta1..17→done. Common version/mode/nativeProviderStream/report/epoch/revision/mutationId/turnId tuple is fixed; seq/index are monotonic and exact. Source objects are original validated server projections, not arbitrary model facts/URLs. Done has exact reconstructed byte/source/delta counts and hypothesis kind.

A recoverable failure after delivered usage may replace the remaining sequence with one guarded bounded terminal `error`, common tuple plus `{type:'error',seq:<next>,errorCode:'LLM_UNAVAILABLE',receipt:'accepted'}`; no done follows. If usage itself failed to write, socket/authority/deadline is gone, or terminal was already queued, close without fabricating a receipt/terminal. R4 admitted invalid-reply failure with a sealed valid current receipt/head uses exactly usage seq0→error seq1 (accepted receipt), never citation/delta/done/invalid content. R5 proven admitted failure without valid current receipt uses exactly one common-tuple frame `{type:'error',seq:0,errorCode:'LLM_UNAVAILABLE',receipt:'unavailable'}`, with no usage/citations/deltas/done/reply. Actual nonadmission/ingress/parser and unsealable identity/authority/head failures remain safe HTTP JSON. This is the existing client v1 unavailable-error variant, not a new endpoint or native stream.

Replay is exact done-only `{...common,type:'done',seq:0,outcome:'duplicate',state:<public state>}`, no reply/citations/counts/usage. Client rejects duplicate as generated success and requires manual history reread; no automatic resend or fabricated historical/zero receipt.

## Client/UI publication and safety

The chat POST explicitly opts into NDJSON. Successful JSON fallback is refused, not mislabeled as framed delivery; error HTTP JSON is still safe. A bounded LF byte buffer handles arbitrary UTF8/JSON/LF chunk boundaries with fatal decoding, exact strict per-type schemas and magic-key refusal. Parser checks request mutation nonce, version/mode/native false, seq/order/index, stable tuple, receipt<=2048/zero cost, source projections/tuple, line/aggregate/count, terminal counts, reconstructed whole reply and LF/clean EOF. Extra/truncated/trailing/unknown/reordered/duplicate frames fail closed. Internal reconstruction has `deliveryMode:validated-completed-reply`; context/default JSON retain their existing modes.

**No partial preview or progress simulation is shipped.** Partial frames never enter Markdown, rich DOM, copy or citation navigation. After validated done+EOF, the panel verifies citations against authorized scanner ID/check membership, rereads current context/durable history/usage, and matches saved completed turnId/mutationId/question/report/reply and exact final revision before publishing. No optimistic assistant/decision; no false native generation claim. All retained history/decisions remain visible after authorized manual reads; historical sources keep original tuples and unresolved labels.

Consent is separately manual/current-question/report/policy/history-bound; generation is never a mount/focus effect. Cancel/error/timeout/scan A→B→A/same-owner reauth/generation changes abort waiting, hide stale snapshot/receipt/consent and require manual history recovery. Accepted accounting remains backend truth even when local receipt is hidden. Existing scanner coverage/findings remain outside the panel and survive failures.

R2 exact unfinished list/blockquote/nested-fence policy remains unchanged and independently approved in237. The wrapper now has a separately authorized explicit space between copy label and status feedback; the existing test file adds one regression, so its old whole-file hash is historical. Real lazy Streamdown still disables rawHTML/default plugins/incomplete repair/images/mermaid/highlighter/executable code, allows only explicit safe HTTPS, copies text/plain, and falls back to exact escaped text on incomplete/HTML-like input or lazy failure. New framed panel test verifies partial nested fence is unpublished and final unfinished text is exact inert pre content.

## Historical verification — R3, not repeated for R4

Frontend final changed-scope command:

```sh
pnpm exec vitest run tests-vite/ui/scans/llmChatClient.test.ts tests-vite/ui/scans/ScanChatPanel.test.tsx -t 'framed|status-only|actual five|resets consent|manual-only' --reporter=default --reporter=json --outputFile=docs/task16-chat-tests.json
```

**46 PASS / 0 FAIL / 27 intentionally deselected**, two files: client30/panel16 selected from73 discovered tests. Name filter also selects five existing consent-preflight cases. Raw current report is `docs/task16-chat-tests.json`, SHA256 `464ba050b292b4b66984185e6c13fc6b3d676d35aa7790a4af4b77af75ec8337`. A prior same focused run passed46 before test-only compiler/import cleanup; final run above is the pinned raw report. No full/heavy/safeMarkdown35/Summary24 repeat.

Backend final focused command (cwd `server/api`):

```sh
pnpm exec tsx --test --test-name-pattern TASK16 src/llm/tests/history-delivery.test.ts src/llm/tests/history.http.test.ts
pnpm exec tsc --noEmit
```

**11 PASS / 0 FAIL**, 10 new codec/writer tests plus one actual cookie/service/controller synthetic-provider test; prior heavy TASK14 tests excluded by name. Covers persisted settled receipt before each write, no unguarded/provider network, free wire stream:false/caps, default JSON unchanged, exact opt-in/unsupported negotiation, status-only duplicate/no redispatch, summary's safe JSON invalid-DTO path, invalid reply accounting, actual revision/report/cookie invalidation stopping after headers+usage, capacity held after commit/released after delivery, disconnect after commit preserving receipt/history. Unit sockets cover drain/finish deadline/abort, every-write guard, source/reply/UTF8/escaping/count bounds, prewrite exception path, first-usage failure without unverifiable error, later safe terminal error. Backend tested synthetic AppModule composition, not actual-main/LOCAL activation/topology/nginx/startup proof.

`pnpm exec tsc -b --noEmit` frontend PASS; API typecheck PASS; scoped frontend ESLint PASS; tracked owned diff whitespace PASS. Prettier only owned frontend files and NEW delivery/unit files; existing compact backend/controller/service/HTTP suite not wholesale reformatted. No build, full/backend-heavy suite, actual provider/browser/320/375/accessibility/gateway or main proof.

Disclosed corrections: first new HTTP fixture used a noncanonical temporary history filename and refused before assertions; fixed to `llm-history.sqlite`/`llm-usage.sqlite`. One new escaping fixture accidentally had20000 text bytes, correctly refused; fixed to16384 and passed final11. A direct test import crossed backend decorator source into the frontend compiler; switched this production seam to runtime-only cross-project import, removed an unused import, and both project compilers/lint passed. No peer server files were changed to silence diagnostics. An earlier backend9PASS/1fixtureFAIL command also ran a succeeding typecheck after `;`; it is NOT claimed all-green. Final backend command uses `&&` and passed11.

## R4 verification and independent security recheck

Parent authorized the finding253 fix, not a redesign or contract exception. RED: the new HTTP regression reproduced502 JSON where admitted failure now requires200 NDJSON. GREEN final R4-only backend command (cwd `server/api`):

```sh
pnpm exec tsx --test --test-reporter=tap --test-name-pattern R4 src/llm/tests/history-delivery.test.ts src/llm/tests/history.http.test.ts
pnpm exec tsc --noEmit
```

**4PASS/0FAIL**:3 new codec/writer tests + the updated focused cookie/service/controller test. Raw final runner output: `docs/task16-r4-backend-tests.tap`. Current-attempt reservation row/request hash/settled receipt matched at each actual write; script and malformed JSON-message failures emit usage/error only; durable failed head/CAS and absent reply verified; failed replay is status-only/no resend; legacy script failure remains502 JSON; failed-head invalidation after usage suppresses stale error/end; no current valid usage cannot borrow previous settled receipts. Unit tests verify exact failure shape/bounds/no content, guard at header/usage/error/end, drain/finish lease retention, and authority/abort/deadline cleanup. No actual provider invoked.

Unchanged client compatibility: `pnpm exec vitest run tests-vite/ui/scans/llmChatClient.test.ts -t '^framed terminal error after accepted usage' --reporter=verbose`: **1PASS/42 intentionally deselected**. No frontend source edits or raw R3 report overwrite. API typecheck PASS; no R4 full frontend typecheck/build/heavy/R3/old Markdown/Summary suite repeats.

Disclosed test corrections: two intermediate runs passed3 unit tests and stopped only on my new missing-usage fixture expectations: initially503 (actual502), then LLM_INVALID_RESPONSE (actual LLM_PROVIDER_UNAVAILABLE). Read the existing provider catch to confirm the bounded502 mapping and corrected only the assertions. Provider/exception-filter code was not changed. Final4PASS and typecheck are separate from those failed intermediate commands.

Historical `docs/task16-r4-diff.patch` and artifact263 contain the exact R3→R4 delta for NINE changed owned paths (the earlier seven-path pre-copy patch was superseded), generated from pre-edit content whose hashes matched249; it is NOT a HEAD→dirty diff or a peer/runtime/nginx diff. New evidence/raw TAP and current manifest also identify the frozen review baseline. Request security recheck of253 C16-SEC-R3-01 against the R4 hashes; prior253/255 approvals describe R3 only. Only the later explicitly authorized frontend copy-feedback spacing fix was applied: one JSX space, one focused regression1PASS/35 intentionally deselected and two-file ESLint PASS. No backend source was rewritten or backend/typecheck suite rerun during packaging. Current manifest keeps the19 original payloads current and pins additional raw evidence/diff/five-file snapshot separately. Parent-reported curated hash ac2d1be63aa4dcb4346df347dc9469cf3ee40d2f7a814675de20209cade2cf34 is NOT proof execution approval; independent257 confirms exactly five backend drift entries. No further source edits without explicit authorization.

## R5 focused validation and current patch identity

Review269 approved the exact R4 accepted-receipt fix but retained P2 C16-SEC-R4-01 for admitted unavailable receipt. Parent ended the proof freeze and authorized the minimal branch, not a contract exception. Only service/delivery + focused existing tests/docs changed; controller and all client/panel/Markdown runtime code are unchanged. History/quota/provider/storage/private fingerprint formats are unchanged.

Final R5-only backend command, cwd `server/api`:

`pnpm exec tsx --test --test-reporter=tap --test-name-pattern R5 src/llm/tests/history-delivery.test.ts src/llm/tests/history.http.test.ts`

**4PASS/0FAIL**, three new codec/writer tests and one NEW disposable synthetic-cookie HTTP test; historical heavy/R3/R4 tests excluded by name, not rerun. Subsequent `pnpm exec tsc --noEmit` API PASS. Covers admitted rejection before any valid receipt, no valid usage after an earlier settled attempt, invalid receipt retaining fault accounting without accepted-usage claims, exact failed turn/head/CAS, default JSON502, pre-admission403 with zero turns/reservations/provider dispatch, duplicate/no resend, lease retention/release and actual header→error session/policy/report/revision guard loss. Unit tests include error-only shape/content rejection, pre-header/error-write/end authority faults, abort and absolute drain/finish deadline/listener cleanup. Accepted-receipt runtime path remains structurally unchanged; historical accepted-path approvals/passes are not claimed as fresh R5 validation.

New production encoder→unchanged actual client test: `pnpm exec vitest run tests-vite/ui/scans/llmChatClient.test.ts -t '^R5 unavailable' --reporter=default --reporter=json --outputFile=docs/task16-r5-client-tests.json`: **1PASS/43 intentionally deselected**,44 discovered. It treats the valid error-only wire as terminal LLM_UNAVAILABLE/no reply/retry and rejects a forged accepted receipt without usage. Scoped test-file ESLint PASS. No full frontend typecheck/build/old client/panel/Markdown/Summary repeat.

RED reproduced502!==200 before production edit. One intermediate backend run was3PASS/1 new fixture counter failure: `afterWrite?.(++writes)` skipped increment when hook absent. Corrected only test instrumentation to increment unconditionally; final4PASS and API typecheck followed. Raw current evidence is in task16-r5-backend-tests.tap and task16-r5-client-tests.json. The older R4 missing-usage regression assertion was updated to the new contract but not rerun; raw264 remains historical.

Current `docs/task16-r5-diff.patch` is R4 manifest265→R5, with its actual changed path list/count pinned by the new manifest/evidence after generation. Do not label it the old seven/nine-path R3→R4 patch. Manifest files[] still pins19 current original payloads; supplements pin R5 evidence/diff/raw tests/current five-backend snapshot. The former ac2d parent proof pin identifies the older graph only: this source change is not any proof execution approval, and this agent neither runs nor substitutes a curated pin.

## Historical evidence and independent review still needed

- Initial41 client/panel/Markdown pass and separate historical Summary24:223, not current R3 runs.
- R2 targeted31PASS/4 deselected plus independent fence30PASS:233v2/237; approved policy/test hashes remain unchanged.
-227 source-only security approval and229 original major framing gap refer to older JSON payloads; neither automatically approves this new backend/parser/lease protocol.

Request independent security and correctness/spec reviews against the new exact manifest: receipt/commit provenance, per-write and post-drain authority, deadline/lease cleanup, JSON/summary compatibility, source projection/nonce/ordering/EOF validation, partial/error/duplicate/cancel/scan/session publication and complete durable equality. Actual authorized main/backend/client integration, real320/375 keyboard/screen-reader/visual acceptance, nginx buffering/ingress activation and operator topology/init remain parent gates. No provider invoice/privacy/live acceptance claim.

Task remains **testing85**, not done/100 or independently accepted. Spec deltas remain unapplied. Current R5 manifest files[] retains19 original owned payloads and supplemental[] pins the R5 raw evidence/diff/current five-file snapshot, excluding itself and peer/source-graph/nginx work; source hashes, not HEAD alone, identify this uncommitted delivery.
