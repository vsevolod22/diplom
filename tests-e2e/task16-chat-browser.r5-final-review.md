# TASK16 — fresh current R5 targeted375 supplemental

## Verdict and exact scope
**PASS: THREE fresh targeted375 Chromium checks only. NOT full TASK16/browser320/375-all/backend acceptance.**
Direct independent parent authorization after failed DIP-ARTF-278. Exactly ONE corrected Chromium execution, no rerun. Current candidate DIP-ARTF-275 v1: 10457 bytes, SHA256 a72207c147823b819da851a9ad58028b8bd314581d0a1d229c3fe2fdf41f3261; all19 payloads+7 supplements matched before/after and again during packaging. Extra actual page/usage/session/config/helper/executed-script hashes matched before/after. HEAD baseline741e4aaf4b6c41dd176ddfe6ff175781958f8f73 unchanged; candidate uncommitted, hashes identify it, not HEAD alone.

Actual mounted ScanDetailPage via test-only Vite, real Chromium 147.0.7727.15, 375×800 viewport, actual frontend fetch/NDJSON parser and Clipboard API. Synthetic owner/history/findings/context/usage/HTTP middleware. Imported current actual encodeDelivery v1 ONLY; no backend service/writer/bootstrap or provider execution. Completed-reply framing, stream:false/nativeProviderStream:false, not native tokens.

## Static preflight BEFORE launching
Commands:
- node --check tests-e2e/task16-chat-browser.r5-final.mjs
- node --check tests-e2e/task16-chat-browser.r5-final-managed.mjs
- node --import ./server/api/node_modules/tsx/dist/loader.mjs tests-e2e/task16-chat-browser.r5-final.mjs --preflight-only

All exited0, NO Chromium/Vite/backend launched. Actual chatContextSchema/chatHistorySchema/chatReplySchema/usageSchema and actual codec→createChatFrameParser checked exact shared served builders, ownerA/B empty/completed/failed histories, both usage variants, complete reply, literal disclosure, LF framing/nonce/revision, terminal error and forged accepted/no-usage rejection. Runtime also repeated this static preflight before its launch. Separate schema/protocol preflight, NOT backend acceptance.

Own failed fixture in278 shortened localRetention; preserved278/279 and old output/archive unchanged. Corrected disclosure is the exact literal required by current schema. Additional preflight correction confined to own mock: usage requires integrationEnabled/quotaEnabled and false variant reason:unavailable (no admission). Previous mock was invalid and client treated it as unknown; final mock now schema-valid. No production defect/fix attributed to these corrections.

## Exactly one bounded browser execution
Command: node tests-e2e/task16-chat-browser.r5-final-managed.mjs
Terminal timeout38000ms; manager fixed31000ms deadline, child watchdog27000ms/hardstop30000ms. Exit0; child 4733ms, manager 5324ms, timeoutfalse. Three standalone scenario groups, not a fabricated framework test count. Two new PNGs, one ARIA snapshot only. Requests: 51 GET / 3 POST: A success for real copy; A held unavailable error for one account fence; B unavailable error final. No automatic retry observed.

1. **C16-BROWSER-01 LOW resolved in measured current375 copy feedback.** Explicit DOM space, visible “Скопировать код Скопировано”; measured horizontal gap 4.453125px. Real focus/Enter/Clipboard read exact echo synthetic-only + LF; button stays focused. Screenshot inspected, status distinct and focus outline visible. No copied-text/runtime source changes by reviewer.
2. **One stale-account fence PASS.** Hold entire current codec error-only terminal, confirm aria-busy=true, change synthetic cookie A→B plus actual transitionScanSession observable injection. Old error released after scope change: no alert, article or old consent published; findings/coverage unchanged. Explicit reload recovers actual auth query/transport. This is NOT actual backend login integration and not a fresh scan-switch/cancel matrix.
3. **Unavailable usage/error-only PASS.** Before submit, valid unavailable usage displays “Учёт недоступен, не ноль”. Final codec sends exactly one error seq0/receipt unavailable; no usage/citation/delta/done/content. Actual client shows safe role=alert and aria-busy=false, no article/hypothesis/receipt/zero-usage claim/old consent; exactly one manual POST. Final ARIA contains disclosure, refresh button and safe error only. No accepted-usage/accounting inference from this error.

Coverage/findings outerHTML compared byte-for-byte after copy, stale account and final error against original375 baseline, including across explicit reload. CVE-2026-10001 remains visible. Final fingerprints:
[
  {
    "region": "coverage",
    "bytes": 3779,
    "before": "d5307ea175694de985a397aed433f3e613de3c6602d572dab81c4e42a911aaf5",
    "after": "d5307ea175694de985a397aed433f3e613de3c6602d572dab81c4e42a911aaf5"
  },
  {
    "region": "findings",
    "bytes": 30758,
    "before": "f7743e92d1562e278e0388badc511aa79fef35eb9428d0cf925e4608b5cfc915",
    "after": "f7743e92d1562e278e0388badc511aa79fef35eb9428d0cf925e4608b5cfc915"
  }
]

## Exact terminal wire (synthetic identifiers; actual current server codec)
```ndjson
{"v":1,"deliveryMode":"validated-completed-reply","nativeProviderStream":false,"scanId":"00000000-0000-4000-8000-000000000016","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":"linux/amd64","reportVersion":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","epoch":"eacdc940-67a7-465d-b5bf-2556ccbe7106","revision":2,"mutationId":"c225673a-bfd7-4b01-b064-14c6dca026c7","turnId":"c0ed8411-9526-46e9-a4c6-5c440ed73731","type":"error","seq":0,"errorCode":"LLM_UNAVAILABLE","receipt":"unavailable"}
```

## Cleanup / isolation
Browser.close and Vite.close awaited in finally; own sockets destroyed. Child and manager independently found 127.0.0.1:59500 closed. Child exited/reaped, code0/signalnull. Post-exit process-group SIGKILL attempt returned sandbox EPERM; disclosed, NOT ESRCH/full OS-level descendant proof. Live-child fallback exists but not needed in this normal exited run. No deadline fired. Clean child env only PATH/HOME/TMPDIR/LANG/NODE_ENV; envDir=false/no proxy, no service workers, external-origin routes blocked; errors[]/egress[].

## Source issues and assurance limits
No new production issue established within these three measurements. C16-BROWSER-01 current375 visual check passes; prior fixture failure remains historical, not a source failure. No production/backend/pages/LLM/source-curated/notices/spec edits. Only NEW tests-e2e/task16-chat-browser.r5-final* runner/manager/packager/report and ignored test-results output authored; existing config/session helper reused unchanged. No dependencies installed, secrets/private data/provider/LIVE/Docker/host scans/commits/branches/task status/progress/close/specapply.

DIP-ARTF-258/259 remain historical full mock baseline (320/375/1280,10groups/34PNG), NOT freshly repeated. DIP-ARTF-268/274/275 are source/candidate references, not browser evidence borrowed as fresh PASS. No real backend provenance/durable receipt/writer/lease/selected-main/DI/native nginx/topology/history-init/deployment/provider/privacy/full WCAG/screen-reader/integrated login approval. Parent retains those gates and task/spec authority.

## Local evidence / exact manifest
Ignored output: test-results/task16-chat-browser-r5-final/{results.json,preflight.json,requests.json,wire-1.ndjson,wire-2.ndjson,wire-3.ndjson,manager.json,manager.log,375-final-chat-aria.yaml,375-r5-copy-feedback.png,375-r5-error-only.png,manifest.json}.
Supplemental exact compact manifest uses file tuples [path, bytes, SHA256], includes current candidate26, extra observed code/config/scripts, raw browser/preflight/wires/ARIA/cleanup/two PNGs, this report and packaging script; self excluded. All listed identities verified after run; screenshots/results confirmed gitignored, no commit.
