import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';

// Packaging only: no Vite, browser, HTTP, backend or provider imports/execution.
const output = 'test-results/task16-chat-browser-r5-final';
const reportPath = 'tests-e2e/task16-chat-browser.r5-final-review.md';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
async function identity(path) {
  const bytes = await readFile(path);
  return [path, bytes.length, sha(bytes)];
}
const evidence = JSON.parse(await readFile(`${output}/results.json`, 'utf8'));
const manager = JSON.parse(await readFile(`${output}/manager.json`, 'utf8'));
const requests = JSON.parse(await readFile(`${output}/requests.json`, 'utf8'));
const preflight = JSON.parse(await readFile(`${output}/preflight.json`, 'utf8'));
const browserManifest = JSON.parse(await readFile(`${output}/manifest.json`, 'utf8'));
assert.equal(evidence.status, 'passed');
assert.equal(manager.code, 0); assert.equal(manager.timedOut, false);
assert.equal(evidence.results.length, 3);
assert(evidence.results.every(result => result.status === 'passed'));
assert.equal(evidence.candidate.beforeAfterMatch, true);
assert.deepEqual(evidence.observedBefore, evidence.observedAfter);
assert.equal(preflight.status, 'passed');
assert.equal(evidence.cleanup.browserClosed && evidence.cleanup.serverClosed && evidence.cleanup.listenerClosed && manager.listener.closed, true);
assert.deepEqual(evidence.egress, []); assert.deepEqual(evidence.errors, []);
const posts = requests.filter(request => request.method === 'POST');
assert.deepEqual(posts.map(request => [request.owner, request.fixtureMode, request.frameTypes]), [
  ['A', 'success', ['usage', 'citation', 'delta', 'done']], ['A', 'held-unavailable', ['error']], ['B', 'unavailable', ['error']],
]);
for (const file of browserManifest.files) assert.deepEqual(await identity(file.path), [file.path, file.bytes, file.sha256]);
const candidate = JSON.parse(await readFile('docs/task16-chat-manifest.json', 'utf8'));
assert.equal(sha(await readFile('docs/task16-chat-manifest.json')), evidence.candidate.sha256);
for (const file of [...candidate.files, ...candidate.supplemental]) assert.deepEqual(await identity(file.path), [file.path, file.bytes, file.sha256]);
const unavailableWire = await readFile(`${output}/wire-3.ndjson`, 'utf8');
assert.equal(unavailableWire.split('\n').length, 2);
const terminal = JSON.parse(unavailableWire);
assert.equal(terminal.type, 'error'); assert.equal(terminal.seq, 0); assert.equal(terminal.receipt, 'unavailable');
assert(!['usage', 'text', 'reply', 'source'].some(key => key in terminal));
const copy = evidence.results[0], failed = evidence.results[2];
const report = `# TASK16 — fresh current R5 targeted375 supplemental

## Verdict and exact scope
**PASS: THREE fresh targeted375 Chromium checks only. NOT full TASK16/browser320/375-all/backend acceptance.**
Direct independent parent authorization after failed DIP-ARTF-278. Exactly ONE corrected Chromium execution, no rerun. Current candidate DIP-ARTF-275 v1: 10457 bytes, SHA256 ${evidence.candidate.sha256}; all19 payloads+7 supplements matched before/after and again during packaging. Extra actual page/usage/session/config/helper/executed-script hashes matched before/after. HEAD baseline741e4aaf4b6c41dd176ddfe6ff175781958f8f73 unchanged; candidate uncommitted, hashes identify it, not HEAD alone.

Actual mounted ScanDetailPage via test-only Vite, real Chromium ${evidence.browserVersion}, 375×800 viewport, actual frontend fetch/NDJSON parser and Clipboard API. Synthetic owner/history/findings/context/usage/HTTP middleware. Imported current actual encodeDelivery v1 ONLY; no backend service/writer/bootstrap or provider execution. Completed-reply framing, stream:false/nativeProviderStream:false, not native tokens.

## Static preflight BEFORE launching
Commands:
- node --check tests-e2e/task16-chat-browser.r5-final.mjs
- node --check tests-e2e/task16-chat-browser.r5-final-managed.mjs
- node --import ./server/api/node_modules/tsx/dist/loader.mjs tests-e2e/task16-chat-browser.r5-final.mjs --preflight-only

All exited0, NO Chromium/Vite/backend launched. Actual chatContextSchema/chatHistorySchema/chatReplySchema/usageSchema and actual codec→createChatFrameParser checked exact shared served builders, ownerA/B empty/completed/failed histories, both usage variants, complete reply, literal disclosure, LF framing/nonce/revision, terminal error and forged accepted/no-usage rejection. Runtime also repeated this static preflight before its launch. Separate schema/protocol preflight, NOT backend acceptance.

Own failed fixture in278 shortened localRetention; preserved278/279 and old output/archive unchanged. Corrected disclosure is the exact literal required by current schema. Additional preflight correction confined to own mock: usage requires integrationEnabled/quotaEnabled and false variant reason:unavailable (no admission). Previous mock was invalid and client treated it as unknown; final mock now schema-valid. No production defect/fix attributed to these corrections.

## Exactly one bounded browser execution
Command: node tests-e2e/task16-chat-browser.r5-final-managed.mjs
Terminal timeout38000ms; manager fixed31000ms deadline, child watchdog27000ms/hardstop30000ms. Exit0; child ${evidence.durationMs}ms, manager ${manager.durationMs}ms, timeoutfalse. Three standalone scenario groups, not a fabricated framework test count. Two new PNGs, one ARIA snapshot only. Requests: ${requests.filter(r => r.method === 'GET').length} GET / ${posts.length} POST: A success for real copy; A held unavailable error for one account fence; B unavailable error final. No automatic retry observed.

1. **C16-BROWSER-01 LOW resolved in measured current375 copy feedback.** Explicit DOM space, visible “Скопировать код Скопировано”; measured horizontal gap ${copy.geometry.gap}px. Real focus/Enter/Clipboard read exact echo synthetic-only + LF; button stays focused. Screenshot inspected, status distinct and focus outline visible. No copied-text/runtime source changes by reviewer.
2. **One stale-account fence PASS.** Hold entire current codec error-only terminal, confirm aria-busy=true, change synthetic cookie A→B plus actual transitionScanSession observable injection. Old error released after scope change: no alert, article or old consent published; findings/coverage unchanged. Explicit reload recovers actual auth query/transport. This is NOT actual backend login integration and not a fresh scan-switch/cancel matrix.
3. **Unavailable usage/error-only PASS.** Before submit, valid unavailable usage displays “Учёт недоступен, не ноль”. Final codec sends exactly one error seq0/receipt unavailable; no usage/citation/delta/done/content. Actual client shows safe role=alert and aria-busy=false, no article/hypothesis/receipt/zero-usage claim/old consent; exactly one manual POST. Final ARIA contains disclosure, refresh button and safe error only. No accepted-usage/accounting inference from this error.

Coverage/findings outerHTML compared byte-for-byte after copy, stale account and final error against original375 baseline, including across explicit reload. CVE-2026-10001 remains visible. Final fingerprints:
${JSON.stringify(failed.fingerprints, null, 2)}

## Exact terminal wire (synthetic identifiers; actual current server codec)
\`\`\`ndjson
${unavailableWire}\`\`\`

## Cleanup / isolation
Browser.close and Vite.close awaited in finally; own sockets destroyed. Child and manager independently found 127.0.0.1:${manager.listener.port} closed. Child exited/reaped, code0/signalnull. Post-exit process-group SIGKILL attempt returned sandbox EPERM; disclosed, NOT ESRCH/full OS-level descendant proof. Live-child fallback exists but not needed in this normal exited run. No deadline fired. Clean child env only PATH/HOME/TMPDIR/LANG/NODE_ENV; envDir=false/no proxy, no service workers, external-origin routes blocked; errors[]/egress[].

## Source issues and assurance limits
No new production issue established within these three measurements. C16-BROWSER-01 current375 visual check passes; prior fixture failure remains historical, not a source failure. No production/backend/pages/LLM/source-curated/notices/spec edits. Only NEW tests-e2e/task16-chat-browser.r5-final* runner/manager/packager/report and ignored test-results output authored; existing config/session helper reused unchanged. No dependencies installed, secrets/private data/provider/LIVE/Docker/host scans/commits/branches/task status/progress/close/specapply.

DIP-ARTF-258/259 remain historical full mock baseline (320/375/1280,10groups/34PNG), NOT freshly repeated. DIP-ARTF-268/274/275 are source/candidate references, not browser evidence borrowed as fresh PASS. No real backend provenance/durable receipt/writer/lease/selected-main/DI/native nginx/topology/history-init/deployment/provider/privacy/full WCAG/screen-reader/integrated login approval. Parent retains those gates and task/spec authority.

## Local evidence / exact manifest
Ignored output: test-results/task16-chat-browser-r5-final/{results.json,preflight.json,requests.json,wire-1.ndjson,wire-2.ndjson,wire-3.ndjson,manager.json,manager.log,375-final-chat-aria.yaml,375-r5-copy-feedback.png,375-r5-error-only.png,manifest.json}.
Supplemental exact compact manifest uses file tuples [path, bytes, SHA256], includes current candidate26, extra observed code/config/scripts, raw browser/preflight/wires/ARIA/cleanup/two PNGs, this report and packaging script; self excluded. All listed identities verified after run; screenshots/results confirmed gitignored, no commit.
`;
await writeFile(reportPath, report);
const paths = [...new Set([...browserManifest.files.map(file => file.path), `${output}/manifest.json`, reportPath, 'tests-e2e/task16-chat-browser.r5-final-package.mjs'])];
const files = await Promise.all(paths.map(identity));
const manifest = { label: evidence.label, candidate: evidence.candidate, schema: ['path', 'bytes', 'sha256'],
  historical: ['DIP-ARTF-258', 'DIP-ARTF-259', 'DIP-ARTF-278', 'DIP-ARTF-279'],
  backendAcceptance: false, providerCalls: 0, files, selfExcluded: true };
const manifestPath = `${output}/upload-manifest.json`;
await writeFile(manifestPath, JSON.stringify(manifest));
for (const file of files) assert.deepEqual(await identity(file[0]), file);
console.log(JSON.stringify({ report: await identity(reportPath), manifest: await identity(manifestPath), entries: files.length, status: 'verified', browserRerun: false }, null, 2));
