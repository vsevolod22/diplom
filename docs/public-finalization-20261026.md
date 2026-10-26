# Public8081: finalization and lazy translation read correction — 2026-10-26

## Current runtime

Coordinator executed exactly one ordinary `node scripts/public-llm-stand.mjs up --build --ack-public-maintenance` after targeted source review and validation. It returned **READY / exit0**, accounts/reports/JWT/history/quota preserved. Audit **`deploy-01afbdfce0770b3e9d4cd41c89be274b`** has aggregate completion `{version:1,project:'dip-public-images',preserved:true}`. `.operation.lock` is absent. All **412** recorded build-source file SHA-256 values match current bytes in a separate read-only comparison. No historical checker/continuation token was replayed.

Post-rollout root probes: **8081 HTTP200 / protected8080 HTTP200**. Public scheduler status: **loaded, every6hours**. Neither periodic execution success nor a new CVE refresh is claimed by this finalization. Launcher postflight requires seven services/six networks, API healthy, immutable pins, API-only readonly key mount and bounded worker resources before READY. No protected-environment Docker operation was performed.

## Independent P2 and correction

Final independent review found translation context/readiness GET fan-out: native collapsed advisory details mounted every translation panel, so a25-row page with one assessment per row could issue50 extra GETs; focus repeated them. A relationship to the two known report-paging test timeouts was **not established**.

`src/pages/scans/VulnAdvisoryCard.tsx` now mounts translation panels only while native details is open. Closing unmounts/aborts pending metadata or translation work and removes focus revalidation. Reopening reads fresh metadata and never replays a POST or publishes an old response. Original advisory/source content remains unchanged. Existing explicit per-request buttons, transfer notes, session/source/policy/readiness/ownership/accounting and before-POST/after-response guards remain unchanged. This is an implementation correction within the applied translation contract, not a change to provider policy, egress or wire format; no spec-waiver declaration or task closure was made.

A separate reviewer returned scoped GO/noP1/P2 after inspecting lazy mount, regression cases and existing abort/session fences. The browser runner now awaits exact translation-region visibility after the native toggle instead of relying on synchronous mounting. No new browser/provider/native scan attempt was performed for this correction. Its frontend proof is controlled UI regression, not new production-browser acceptance.

## Fresh finalization validation

- UI translation/card/identifier/progress/decoder tests: **140/140 PASS**, five test files, serialized.
- API durable progress/owner HTTP/finite diagnostics: **27/27 PASS**, concurrency2.
- Both bounded offline browser runner suites: **100/100 PASS** (agent-run); delayed translation-region mount and timeout/no-retry cases included.
- Coordinator: root typecheck, root lint, main build, admin build and `git diff --check`: **PASS**.
- Vite chunk>500kB warning remains. Previous full UI **842/844** with two known report-paging timeouts remains **not green/not fixed**. Full API **1386PASS** predates the final diagnostic extension; it was not rerun or relabeled here.
- Static secret/private-evidence review covered91candidates before the late correction, no blockers. Final candidate scan is required before staging; only source/tests/docs may be committed, never ignored/private state, keys, DBs, backups, locks, HAR or storageState.

## AI acceptance remains blocked

The actual native scan/cancel/ownership/progress and last AI evidence remain in [public-progress-20261026-final.md](public-progress-20261026-final.md). No old result was rewritten. Chat's latest real attempt returned provider429 without retry hint; translation returned application `LLM_INVALID_RESPONSE`, diagnostics `content/invalid_content`, exact rejecting predicate UNKNOWN. No successful Russian grounded chat, second turn/successful conversation persistence, translation fidelity or successful derivative toggle is claimed.

Fixed profile remains OpenRouter **`xingchen-agi/xing4.0-29b-a4b:free` → `phala`**, no paid/automatic fallback, privacy weakening, retries or quota reset/refund. The key is provisioned; do not request or reimport it. Native provider `stream=false`; NDJSON carries a completed validated response, not native token streaming. Remaining external action is checking availability/limits of this exact free pair (or separately authorizing a profile change); translation additionally needs safe identification of its rejecting validator before a justified correction/new attempt. No arbitrary retry interval or repair ETA is known.

TASK9 remains regression, TASK42 blocked; no parent cascade or accepted-task reopening. Current and historical operator docs were reconciled without erasing past failure evidence. All runtime/source claims above are separate from AI acceptance.
