# Public report chat UI — 2026-10-20

## Current status / historical scope — 2026-10-26

This implementation/test report is **historical; superseded for current status by [public-progress-20261026-final.md](public-progress-20261026-final.md)**. Preserve the source proofs and synthetic test results below; they are not current deployed UX or native AI acceptance. In particular, the historical checkbox-based consent descriptions below are superseded by the final summary's explicit buttons/visible egress notes without permission-checkbox.

- Public **http://127.0.0.1:8081 — HTTP200**, no maintenance in progress, per the current handoff; no new probe was made here.
- Latest native attempt `324479cf-07ee-4d99-983b-2be9d6c000eb`: **12 PASS / 6 BLOCKED / 0 FAIL**, not full AI success. Chat returned HTTP200 failed NDJSON with `LLM_PROVIDER_RATE_LIMITED`, provider `rate_limited/status429`, no retry hint. Translation returned application HTTP502 `LLM_INVALID_RESPONSE`, `content/invalid_content`; exact predicate UNKNOWN, not established upstream HTTP502. Successful grounded reply, second turn, successful history reload/fresh-login persistence and translation/toggle remain blocked. Owner login PASS is not successful conversation persistence PASS.
- Separate native progress/cancel qualification is **10 PASS / 0 BLOCKED / 0 FAIL**, not AI-generation evidence. Current progress is indeterminate with durable counts, no invented percent or ETA.
- Changed CVE release `e1af977c…` is active with aggregate four-store preservation. Scheduler is installed/loaded and separately status-qualified at **6 hours**; a successful periodic run remains unproven. See the [CVE receipt](public-progress-20261025-cve-receipt.md) and final summary for evidence limits.

**No new attempts, retries, maintenance or token replay are authorized.** This finalization changes documentation only and reruns no tests or runtime checks.

## Historical scope and status

Implemented in the existing chat, not a second chat system. Code/test writes stay in `src/**` and `tests-vite/**`. After explicit user permission in the P1 follow-up, this report was moved from `tests-vite/ui/scans/` to `docs/public-chat-ui-20261020.md`. No backend/scripts/deploy edits, Docker operations, private-state access, 8080 requests, deployment, commits or provider/live-8081 requests were performed by this UI work. Concurrent backend/scripts changes belong to other agents and were not reverted or included as UI-owned work.

Read the juniors-best-practice and vercel-react-best-practices skills, existing summary/chat clients, panel, source collector, owner-session scope, strict NDJSON parser, TASK16 contract and current public report contract.

## Implementation

- `src/pages/scans/ScanDetailPage.tsx`: explicit chat link on an authorized terminal owner report, pointing to a focusable named chat section. No chat entry for active/demo report navigation. Summary failure does not remove the existing chat.
- `src/features/scans/ScanChatPanel.tsx`: separate accessible connection/read/wait/ready/server-pending/disabled/recovery status; semantic send form, UTF-8 input help and invalid-input state; one-request consent stays tied to the current question/report/policy/history; failed-turn retry only fills/focuses the composer and requires fresh consent and explicit send. Cancellation stops browser waiting, not necessarily the server/provider or accounting. History refresh is manual, never implicit generation.
- `src/shared/api/scans/llmChatClient.ts`: safe distinct configuration/key-policy, provider-unavailable, quota, no-evidence, report, session and access errors. Configuration errors do not assert a missing key as proven, expose diagnostics, solicit a user key, or bypass consent. HTTP 401/403/404 fail closed even for non-JSON errors. A denied usage read cannot be downgraded into unknown quota while showing history.
- `src/shared/api/scans/llmChatContract.ts`: matches the concurrently implemented public citation projection: existing `cveId` field plus `identifierKind: cve | debian-temp`. TEMP must be bounded uppercase Debian TEMP, ecosystem `deb`, explicit kind `debian-temp`; mismatched kinds, extra raw evidence and malformed identifiers are rejected. Existing CVE projections remain accepted. No new endpoint implementation, consent DTO, stream version or alternate transport. The client additionally reads the backend-owned owner-bound `GET /llm/readiness` contract.
- `src/shared/api/scans/llmSummaryClient.ts`: existing shared source collector still reads every checked legacy scanner page, independent of report filters/UI pagination. Public page profile and whole-report CVE/TEMP partition must agree with authoritative status, and accumulated identifiers must match the totals. TEMP source labels explicitly say Debian advisory, not CVE.
- `src/pages/scans/scan-detail-a1.css`: new chat alone spans its parent grid; its new navigation item spans the existing four-column grid. Existing composer styles are reused without restyling accepted report controls.

## Preserved safety and truthfulness

The provider remains `stream:false`. NDJSON is bounded framing of an already validated completed response, not native token streaming. No partial delta, artificial timer reveal or optimistic assistant content is published. Done + clean EOF + source checks + current report/policy/history reread + exact durable reply equality are still required. Existing malformed-frame, late response, timeout, session/owner switch, A→B→A, reauthentication and pending guards remain tested.

GET-only opening/refresh does not call the provider. Send/continue needs an explicit question, current manual consent and pre-dispatch context/CAS recheck. Double submit is guarded synchronously. Duplicate-only delivery does not become a generated answer. Cancel/error/timeout resets snapshot/receipt/consent; the owner can explicitly reread durable history before another send. No automatic resend, refund or server cancellation is claimed. Manual decisions retain their existing no-provider path.

Public totals distinguish CVE from Debian advisories, including TEMP. Missing counts, quota and coverage remain unknown rather than zero, checked is not a safety guarantee, and `NODE_INVENTORY_UNKNOWN` does not establish absence of Node packages. Scanner findings/coverage stay outside the chat and survive chat errors.

## Contract coordination

Initial source inspection found public deb/TEMP and NODE_INVENTORY_UNKNOWN unsupported by the old backend ReportReader. This was returned as a contract question. During the work, the parallel backend source added the concrete `identifierKind` public citation discriminator and public report handling; frontend validation and tests were aligned with those observed source changes. These source observations do not certify backend deployment or live provider behavior. The actual five existing chat/history route/method pairs and exact CAS/consent DTOs remain unchanged; the P1 follow-up also consumes the backend-owned `GET /llm/readiness` route without introducing a second chat transport.

## P1 follow-up — public wire and readiness (2026-10-21)

The reviewer correctly identified that the earlier frontend disclosure only admitted Apodex/Novita and strict context rejected actual public metadata. The original 128-test result below is historical, not evidence that those omissions were correct.

- Disclosure now admits exactly the two production policy pairs: `xingchen-agi/xing4.0-29b-a4b:free` + `phala`, or `apodex/apodex-1.1-mini:free` + `novita/bf16`. Mixed pairs, extra providers, arbitrary models and paid caps remain rejected. Recognition of Apodex's legacy policy does not claim a current catalog endpoint.
- `llmPublicContract.ts` strictly validates `findingCount`, `findingCounts.byCheck/bySeverity`, optional checked-vulnerability `identifierCounts`, complete four-check sanitized `coverage`, nested saved DB/config evidence and the JSON chat result's actual `contextSelection` omission shape. Public counts must agree internally; unknown is not checked zero. Metadata is retained, not stripped; arbitrary fields are not accepted with passthrough. Legacy context without public fields remains supported, but the public UI requires the group. Public-marked JSON replies cannot silently drop all metadata; framed delivery retains its existing metadata-free frame contract.
- `backendChatWire.test.ts` calls the **actual** `HistoryService.context()` implementation using in-memory report/head/auth/result seams and the production disclosure function, then passes that returned wire through `createChatClient.context()`. This is not an HTTP/backend-store integration test. JSON chat-result regression uses the actual public field shape including a TEMP citation, whole counts and selected-vs-omitted IDs. Pair and malformed metadata mutations exercise both context and result validators.
- Public UI fixtures no longer borrow the old Apodex-only context: public cases use production Xing/Phala disclosure, full public metadata and the production `publicReadiness()` function. Legacy non-public cases intentionally retain backward-compatibility fixtures.
- The existing cookie client reads owner-bound `GET /api/v1/browser/scans/<id>/llm/readiness`. The UI exposes only allowlisted setup blockers, distinguishes missing/unsafe key, quota/history store and unavailable provider/configuration, accepts no key input and shows `generationVerified: false` explicitly. Catalog/local metadata is not provider success. Malformed/offline readiness is unknown, not permission; owner/access denial fails closed.
- Readiness can be displayed even when history/context cannot be read. Conversely, missing generation configuration does not hide an otherwise valid history or prevent manual no-provider decisions. Public send requires local readiness **and** current explicit consent; readiness is rechecked before dispatch and report/model/provider pairing is fenced against context. A key becoming missing after opening yields zero POST. No provider probing or automatic retry was added.
- No backend or sanitizer changes were made in this P1 follow-up. No live calls were performed.

## Validation

Targeted, serial, one-worker run (no full heavy suite):

```sh
pnpm exec tsc --noEmit --incremental false
pnpm exec vitest run \
  tests-vite/ui/scans/backendChatWire.test.ts \
  tests-vite/ui/scans/publicChatUi.test.tsx \
  tests-vite/ui/scans/ScanChatPanel.test.tsx \
  tests-vite/ui/scans/llmChatClient.test.ts \
  tests-vite/ui/scans/llmSummary.test.tsx \
  tests-vite/ui/scans/llmSummaryPage.test.tsx \
  tests-vite/ui/scans/publicVulnerabilityIdentifiers.test.tsx \
  --maxWorkers=1 --no-file-parallelism
```

Historical P1 follow-up result: typecheck PASS; 7 files / **145 tests PASS** (35 panel, 44 client, 24 summary, 5 page, 28 public-chat UI, 4 public-identifier, 5 backend-wire regressions). Earlier pre-review result was 6 files / 128 tests, superseded by this run. New focused coverage includes explicit wait and continuation, repeated submit, failed-question preparation, manual error recovery with renewed consent, non-JSON 401/403 usage denial, unknown quota, duplicate-only recovery, all public source pages and whole-report partition mismatch, honest unknown coverage, public TEMP response + durable reload and malformed public source projections. Existing panel tests continue to cover cancellation, timeout, pending, historical/current citations and owner/session/report/policy fences.

Scoped ESLint passed. Whitespace checks cover `src`, `tests-vite` and this report. An initial own type narrowing error was fixed; an added error case exposed an ambiguous test selector, fixed by selecting the exact retained scanner report text. No unresolved failure from those intermediate runs remains.

All network/provider fixtures here are synthetic; the new context regression executes the production context method with isolated in-memory seams, not a live server. Real browser visual layout, current 8081 images/flags/routes, native provider availability, backend store initialization and a funded/approved provider call are **not certified**. No full build, full suite, E2E stand or deployment was run. Typecheck deliberately uses `tsc --noEmit --incremental false`, avoiding writes to the out-of-scope root build-info file.
