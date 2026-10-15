# TASK16 independent Chromium mocked-frontend review — 2026-10-09

## Verdict

PASS for the measured frontend browser checks, **not full TASK16/backend/deployment/accessibility certification**. Ten browser scenario groups passed: actual ScanDetailPage at 1280/320/375 × 800; one persisted owner/scan isolation group; three in-flight scope groups; three actual SafeMarkdown adversarial groups. These are scenario groups in a standalone script, not ten Playwright Test cases or a fabricated Vitest total.

One LOW visual source issue is reported below. No blocking correctness/security defect established in this bounded frontend scope. Parent retains task/spec/rollout authority. No source fix, task-close/status/progress/spec application or commit.

## Assignment and source identity

Workspace `startup/diplom`, HEAD baseline `741e4aaf4b6c41dd176ddfe6ff175781958f8f73` (implementation is uncommitted, not contained in HEAD). Read full Flownix basics, .flownix/policy, TASK16/comments, DIP-ARTF-202/249/250/255. Existing browser runner and renderer files were read/reused but not modified.

Only NEW files authored:

- `tests-e2e/task16-chat-browser.independent.mjs`
- `tests-e2e/task16-chat-browser.independent.vite.mjs`
- `tests-e2e/task16-chat-browser.managed.mjs`
- `tests-e2e/task16-chat-browser.session.ts`
- this review document

The runtime panel, client, parser, Markdown policy/wrapper/renderer and Summary hook match the corresponding reviewed R3 identities in249. Current server codec is later R4 source: `history-delivery.ts`, 9343 bytes, SHA256 `05e79575b16a60d2d8fd6c4f2753ca8ddd485d045475e1952e7a7c10226bb2e8`, not the historical R3 hash. We import its **actual encodeDelivery** for approved v1 completed-reply wire and current failed usage/error wire. This browser run does not independently approve R4 service/controller/writer provenance or backend behavior. It executes no backend server/service/store/provider/writer. Relevant source samples were identical before/after the final run; no curated graph or peer source writes.

## Execution and cleanup

Command from diplom:

```sh
node tests-e2e/task16-chat-browser.managed.mjs
```

Final command exit0. Child duration30259ms; manager duration30851ms; manager deadline125000ms, internal child cleanup watchdog115000ms/hard stop120000ms. External terminal timeout140000ms. Parent launches a detached bounded child, records its origin through IPC, attempts termination of its own process group after exit and on deadline (with live-child fallback when sandbox denies group signals). Child finally closes held response, Chromium, owned sockets and Vite. Final group probe ESRCH (no owned process group remaining); final child and manager listener probes both closed=true for ephemeral127.0.0.1:58240. No timeout. This confirms the successful-run teardown, not an executed forced-hang/deadline fault injection.

Child environment is allowlisted PATH/HOME/TMPDIR/LANG/NODE_ENV only (values not dumped). Test Vite config sets envDir=false, no proxy/checker/app bootstrap, own strict ephemeral port and cache under ignored test-results. Browser context blocks service workers and routes non-own-origin requests to abort; browser/fixture errors and external-egress attempts all empty. No native external network requests/services, provider/LIVE/host scan/Docker/secrets/dependency installation.

Earlier failed runs are retained and disclosed, not claimed green:

1. 1280 script reached cancel recovery but a text locator matched both draft textarea and saved paragraph. Test-only locator narrowed to article. Cleanup listener closed/source samples unchanged. Manager's post-exit negative-PID signal returned EPERM in the terminal sandbox; error reporting/fallback corrected in the NEW manager.
2. Three viewport groups and persisted owner isolation passed; raw session-observable injection then wrongly expected automatic auth/query/transport replacement. Corrected test checks stale output/consent clearing first, then explicit real auth/me reload and manual history read for recovery. This was not established as a source defect. Original attempt results/DOM/manager evidence remain local in the manifest.
3. Final complete run passed every scenario group, with no browser/fixture errors, egress attempts or runtime edits.

## Measured checks

| Width | Document width | Top/bottom CVE scroll | Pager target/font |
| --- | --- | --- | --- |
| 1280 | 1280 | 2186 / 5646 | 44px / 14px |
| 320 | 320 | 4292 / 11663 | 44px / 14px |
| 375 | 375 | 3954 / 9961 | 44px / 14px |

- Actual mounted route, source-transformed React/CSS and real browser fetch/HTTP/NDJSON parsing, not static mock-up, jsdom or production dist.
- No chat reads or mutation on mount/focus. Manual open performs metadata/history/usage/scanner reads, not generation. Question→Tab reaches named consent checkbox; Space consents; Enter submits exactly one mutation. Changed question resets consent; disabled/enabled states and aria-busy checked.
- Actual codec produces usage→citation→delta→done; done with no clean EOF stays busy/unpublished. No partial answer/copy publication. Release EOF then matching authorized context/scanner membership/history reread permits rich reply. Limits: v1/nativeProviderStream=false,8192 bytes/line,196608 total,52 frames,1024-byte deltas,5000ms delivery contract. Provider remains stream:false; no provider-native streaming claim.
- Completed history reply includes late-page scanner source; keyboard citation activation focuses its tabindex=-1 target. Exact plain code and nested unfinished fence text copied through the real Chromium Clipboard API, not a clipboard stub.
- Safe accepted-receipt error (current codec), quota429 and deliberately corrupted hostile wire refuse publication, do not autoresend and preserve coverage/findings. Hostile wire is explicitly an adversarial mutation of codec output, NOT output a conforming backend would emit.
- Exhausted quota and unavailable usage shown as unknown/not zero. Cancel hides local snapshot/receipt/consent and pending output, then manual reread can recover a synthetic already-committed turn without refund/server-cancel claims.
- Decision sends only manual history-decision POST, no additional chat generation, and survives explicit history reread.
- Scanner report coverage/results outerHTML byte-identical across chat success/error/quota/cancel/decision operations. Actual CVE three-page36/12-row paging/back/next/retry and independent Secrets/SBOM pages also checked.
- Same-document router A→B→A during held HTTP response hides old output; manual reread recovers only requested scan. Cookie owner A→B→A through real auth/me/reload separates saved history. In-flight account test injects actual transitionScanSession observable only, verifies clearing before delayed old completion, then explicitly reloads for auth transport recovery. This is not real backend authentication or a full login integration proof.
- Standalone actual SafeMarkdown renderer at320/375/1280: HTML/script/image input inert exact pre; javascript/data/file links inactive; safe HTTPS link only with noopener noreferrer nofollow; nested backtick/tilde fallback exact copy; closed executable-looking code inert; execution marker=false; no dialog/external request.
- 111 keyboard activation observations checked focus and a nonzero outline or box-shadow. Three chat ARIA snapshots retained; textbox/checkbox/button/region names, busy/status/alert states and citation focus tested. This is not VoiceOver or full WCAG/axe/contrast certification.

## Source issue — no fix performed

**C16-BROWSER-01 LOW: copy-success status visually joins its button label at375px.** Confirmed in `test-results/task16-chat-browser-independent/375-chat-confirmed-citation.png`: “Скопировать кодСкопировано” has no visible separation. At320 the success text wraps onto its own line. `src/features/scans/safeMarkdown.tsx:10–27` renders bare adjacent button/status span; `SafeMarkdownRenderer.tsx:28–31` reuses it. Copy and role=status semantics work; this is a readability/layout issue, not an XSS/copy/focus failure. Suggested separately authorized fix: explicit gap/separate status placement with mobile regression. No runtime/style changes made.

## Evidence and remaining gates

Ignored local evidence directory: `test-results/task16-chat-browser-independent/`.

- `results.json`: complete final raw script results, source samples,111 focus observations, stage timestamps,34 screenshots and limits.
- `manager.json` / `manager.log`: final process exit/deadline/cleanup evidence.
- three `*-requests.json`, three `*-chat-accessibility.yaml`, codec-produced `.ndjson` samples,34 final screenshots.
- earlier `attempt1-results.json`, `attempt2-results.json`, `attempt2-dom.txt`, `attempt2-manager.json` plus retained failure diagnostics are historical, not final failures.
- manifest: exact relative path, bytes and SHA256 for source samples/test files/evidence; self excluded. Screenshot/test-results are git-ignored, not committed.

No backend suite run or backend acceptance borrowed from author/review reports. Selected actual main/LOCAL DI/raw ingress/history init/topology, nginx buffering/compression/size/timeouts/disconnect, integrated authorized backend+browser and actual provider compliance/invoice remain independent parent gates. Native screen-reader/contrast/full WCAG and aesthetics remain unverified. No backend/runtime/pages/LLM source, source-curated snapshots, private state, notices, specs or existing tests edited; no branch/commit/taskclose/specapply.
