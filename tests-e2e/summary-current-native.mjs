// Parent-run only. Importing this module does not launch Chromium or perform HTTP.
// This authorization is a NEW summary-only intent, not a reset of any earlier runner.
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  SCAN, BASE, MODEL, ORIGIN, contracts, fingerprint, disableAutomationUi,
  policyMatches, readinessMatches, allowedRead, OneShotGate, collectVulnCorpus,
} from './native-h7v3-paid-sol.mjs';
import { BROWSER_ARGS } from './public-product-live.mjs';
import { diagnosticContracts, captureResponseDiagnostics, safeRunnerFailure } from './native-h7v3-finite-diagnostics.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const DIR = join(ROOT, 'test-results/summary-current-native');
export const INTENT = 'summary-current-explicit-v1';
export const AUTH_FLAG = '--current-authorization-one-summary';
export const CAP = 5_000_000;
export const LIMITS = Object.freeze({ totalMs: 235_000, closeMs: 4_000, requests: 380, manualGets: 40, proofMs: 900_000, armMs: 30_000 });
const DIGEST = 'sha256:abe13b25e07ccaedcc8797120c37781f0462a0f0682105cf2d8b8d6f99070d55';
const BINDING = ['scanId', 'digest', 'platform', 'reportVersion'];
const same = (a, b) => BINDING.every(k => a?.[k] === b?.[k]);
class AcceptanceFailure extends Error { constructor(code) { super(code); this.code = code; } }
const check = (value, code) => { if (!value) throw new AcceptanceFailure(code); };

export function modeOf(args) {
  if (!args.length) return 'inert';
  if (JSON.stringify(args) === JSON.stringify(['--readonly'])) return 'readonly';
  if (JSON.stringify(args) === JSON.stringify(['--generate-one', AUTH_FLAG])) return 'generate-one';
  throw new AcceptanceFailure('INVALID_ARGUMENTS');
}
export function currentPolicy(c) {
  return policyMatches(c) && c.disclosure.lifetimeUserCostMicros === CAP &&
    c.scanId === SCAN && c.digest === DIGEST && c.platform === 'linux/amd64';
}
// Called only after the actual current usageSchema parser. Daily/token statistics
// are not reinterpreted as lifetime budgets; /llm/usage is exact SUMMARY admission.
export function summaryAdmission(u, c) {
  if (!currentPolicy(c) || !same(u, c) || !u?.available || !u.integrationEnabled || !u.quotaEnabled ||
      u.monetaryLimit !== 'uncapped' || !['ready', 'warning'].includes(u.reason) ||
      u.lifetimeBudget?.limitMicros !== CAP || u.admission?.status !== 'fits' ||
      u.admission.signals.length !== 0) return false;
  const reserve = u.admission.reserve, price = c.disclosure.estimatedPrice;
  if (![reserve.input, reserve.output, reserve.costMicros, price?.input, price?.output].every(x => Number.isSafeInteger(x) && x > 0)) return false;
  const estimate = (BigInt(reserve.input) * BigInt(price.input) + BigInt(reserve.output) * BigInt(price.output) + 999_999n) / 1_000_000n;
  return BigInt(reserve.costMicros) === estimate && reserve.costMicros <= u.lifetimeBudget.remainingMicros;
}
export function allowedSummaryRead(url) {
  if (!allowedRead(url)) return false;
  // Normal report/chat display metadata is read-only, but translation is outside this intent.
  return !new URL(url).pathname.includes('/llm/translation');
}
export function proofHash(c, history, summaryHash) {
  return fingerprint({ binding: BINDING.map(k => c[k]), policy: c.policyVersion, disclosure: c.disclosure,
    historyHash: fingerprint(history), summaryHash });
}
export function freshProof(p, now = Date.now()) {
  return p?.status === 'READONLY_READY_MISSING' && /^[a-f0-9]{64}$/.test(p.hash ?? '') &&
    Number.isSafeInteger(p.at) && now >= p.at && now - p.at <= LIMITS.proofMs;
}
// Exclusive, flushed files are intentionally NEVER removed, including on failure.
export async function exclusiveRecord(path, value) {
  const file = await open(path, 'wx', 0o600);
  try { await file.writeFile(JSON.stringify(value)); await file.sync(); } finally { await file.close(); }
  const dir = await open(dirname(path), 'r');
  try { await dir.sync(); } finally { await dir.close(); }
}
export class SummaryGate extends OneShotGate {
  constructor(mode, persist, now = Date.now) {
    super({ summary: 0, chat: 0, summarySucceeded: false }, persist);
    this.mode = mode; this.now = now; this.halted = true; this.clicked = false; this.armed = false; this.blocked = false;
  }
  armCurrent(c) {
    check(this.mode === 'generate-one' && !this.armed && !this.blocked && currentPolicy(c), 'SUMMARY_AUTHORIZATION_REQUIRED');
    this.armed = true; this.halted = false;
    this.arm('summary', c);
    this.armedAt = this.now(); this.clicked = true;
  }
  async consume(path, body) {
    if (!this.clicked || this.mode !== 'generate-one' || path !== BASE + '/llm/summary' ||
        this.now() - this.armedAt < 0 || this.now() - this.armedAt > LIMITS.armMs) {
      this.blocked = true; this.halted = true; return false;
    }
    const result = await super.consume(path, body);
    // No invalid attempt can be followed by a corrected request in this run.
    this.halted = true; this.clicked = false;
    if (!result) this.blocked = true;
    return result;
  }
}
export async function usageContract() {
  const require = createRequire(join(ROOT, 'server/api/package.json'));
  const manifest = require('tsx/package.json');
  const { tsImport } = await import(pathToFileURL(join(dirname(require.resolve('tsx/package.json')), manifest.exports['./esm/api'].import.default)).href);
  return tsImport(join(ROOT, 'src/shared/api/scans/llmUsageClient.ts'), { parentURL: import.meta.url, tsconfig: join(ROOT, 'tsconfig.json') });
}
export async function paidDisclosureUi(panel) {
  const disclosure = panel.getByLabel('Условия OpenAI', { exact: true }); await disclosure.waitFor({ state: 'visible' });
  const details = disclosure.locator('details');
  if (await details.getAttribute('open') === null) await details.locator(':scope > summary').click();
  const text = await disclosure.innerText();
  check(text.includes(MODEL) && text.includes('$5 на аккаунт за всё время') && text.includes('это не бесплатный режим') &&
    text.includes('без сброса со сменой суток') && text.includes('Денежные лимиты запроса и суток не установлены') &&
    text.includes('ZDR') && text.includes('не подтверждён'), 'CURRENT_PAID_DISCLOSURE_UI_REQUIRED');
}
const usageCounts = u => ({ lifetime: { ...u.lifetimeBudget }, reserve: { ...u.admission.reserve }, admission: u.admission.status, reason: u.reason });

export async function run(mode) {
  check(['readonly', 'generate-one'].includes(mode), 'INVALID_ARGUMENTS');
  process.umask(0o077);
  await mkdir(DIR, { recursive: true, mode: 0o700 });
  // Shared only by THIS new runner. Do not inspect/change any old runner's ledgers.
  const lock = await open(join(DIR, 'runner.lock'), 'wx', 0o600);
  const runHash = fingerprint(randomUUID()), record = join(DIR, runHash + '.json');
  const log = { intent: INTENT, mode, hash: runHash, at: Date.now(), status: 'PREPARING', phase: 'prepare',
    requests: 0, manualGets: 0, mutationAttempts: 0, dispatched: 0, denied: 0, pageErrors: 0 };
  const deadline = Date.now() + LIMITS.totalMs;
    let browser, page, tools, diagnostic, usage, timer, timedOut = false, cleanupNeeded = false, recordCreated = false;
  const save = async () => {
    if (!recordCreated) return;
    const f = await open(record, 'r+');
    try { await f.truncate(0); await f.writeFile(JSON.stringify(log, null, 2)); await f.sync(); } finally { await f.close(); }
  };
  const gate = new SummaryGate(mode, () => exclusiveRecord(join(DIR, INTENT + '.dispatch-spent.json'), {
    intent: INTENT, at: Date.now(), status: 'DISPATCH_SPENT_NO_RETRY', hash: runHash,
  }));
  let priorProof;
  async function work() {
    if (mode === 'generate-one') {
      priorProof = JSON.parse(await readFile(join(DIR, 'readonly-ready.json'), 'utf8'));
      check(freshProof(priorProof), 'FRESH_READONLY_FIRST_REQUIRED');
      // Spends this entire authorization BEFORE browser startup / ANY network.
      // A crash, timeout, policy failure, or uncertain dispatch does not restore it.
      await exclusiveRecord(join(DIR, INTENT + '.authorization-spent.json'), {
        intent: INTENT, at: Date.now(), status: 'AUTHORIZATION_SPENT_NO_RETRY', hash: runHash,
      });
    }
    [tools, diagnostic, usage] = await Promise.all([contracts(), diagnosticContracts(), usageContract()]);
    const { chromium } = await import('@playwright/test');
    const env = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'SystemRoot'].filter(k => process.env[k] !== undefined).map(k => [k, process.env[k]]));
    browser = await chromium.launchPersistentContext(join(ROOT, 'test-results/native-h7v3-sol/browser'), {
      headless: true, timeout: 20_000, args: [...BROWSER_ARGS], env,
      serviceWorkers: 'block', acceptDownloads: false, viewport: { width: 1280, height: 960 }, reducedMotion: 'reduce',
    });
    check(!timedOut, 'TOTAL_TIMEOUT');
    await browser.routeWebSocket('**/*', socket => { log.denied++; gate.halted = true; socket.close(); });
    await browser.route('**/*', async route => {
      const r = route.request();
      const deny = async () => { log.denied++; gate.halted = true; await route.abort(); };
      try {
        const u = new URL(r.url());
        if (++log.requests > LIMITS.requests || timedOut || log.denied || !page || r.frame().page() !== page ||
            u.origin !== ORIGIN || u.username || u.password || u.hash || r.redirectedFrom()) return await deny();
        if (r.method() === 'GET') return allowedSummaryRead(r.url()) ? await route.continue() : await deny();
        log.mutationAttempts++;
        if (r.method() !== 'POST' || u.search || u.pathname !== BASE + '/llm/summary' ||
            !await gate.consume(u.pathname, r.postDataJSON())) return await deny();
        log.dispatched++;
        await save(); // Both dispatch-spent marker AND evidence precede dispatch.
        if (timedOut || log.denied || gate.blocked || Date.now() - gate.armedAt > LIMITS.armMs) return await deny();
        return await route.continue();
      } catch { await deny(); }
    });
    for (const old of browser.pages()) await old.close();
    page = await browser.newPage(); page.setDefaultTimeout(12_000); page.setDefaultNavigationTimeout(15_000);
    page.on('pageerror', () => { log.pageErrors++; });
    page.on('dialog', dialog => { log.denied++; gate.halted = true; void dialog.dismiss(); });
    const clean = () => check(!timedOut && log.denied === 0 && log.pageErrors === 0, 'PAGE_OR_REQUEST_GUARD');
    // Browser fetches use the real session and the SAME guarded network as the UI.
    const get = async path => {
      check(++log.manualGets <= LIMITS.manualGets, 'MANUAL_GET_BOUND');
      const r = await page.evaluate(async path => {
        const response = await fetch(path, { credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(12_000) });
        const reader = response.body.getReader(), chunks = []; let bytes = 0;
        try {
          for (;;) { const part = await reader.read(); if (part.done) break; bytes += part.value.length;
            if (bytes > 2_097_152) throw Error('GET_BOUND'); chunks.push(part.value); }
          const all = new Uint8Array(bytes); let offset = 0;
          for (const chunk of chunks) { all.set(chunk, offset); offset += chunk.length; }
          return { status: response.status, value: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(all)) };
        } finally { await reader.cancel().catch(() => {}); }
      }, path);
      clean(); return r;
    };
    const ok = async suffix => { const r = await get(BASE + suffix); check(r.status === 200, 'CURRENT_GET_FAILED'); return r.value; };
    const session = async () => {
      const r = await get('/api/v1/auth/me');
      check(r.status === 200 && typeof r.value?.id === 'string' && r.value.id.length > 0, 'AUTHENTICATED_SESSION_REQUIRED');
      return r.value.id; // Ephemeral only; never log identity, cookie, email, or headers.
    };
    const preferencesOff = async () => {
      await disableAutomationUi(page);
      await page.reload(); // Prove persisted through normal account UI, not just selected DOM values.
      const details = page.locator('details.demo-auth__preferences'); await details.waitFor({ state: 'visible' });
      if (await details.getAttribute('open') === null) await details.locator(':scope > summary').click();
      const prefs = details.getByRole('region', { name: 'Настройки отчётов', exact: true });
      check(await prefs.getByLabel('ИИ-разбор', { exact: true }).inputValue() === 'off' &&
        await prefs.getByLabel('Язык исходных описаний уязвимостей', { exact: true }).inputValue() === 'original', 'AUTOMATION_NOT_OFF');
      log.automation = 'OFF_ORIGINAL_PERSISTED'; cleanupNeeded = false; clean();
    };
    log.phase = 'automation-off-before-report';
    await preferencesOff(); const owner = await session();
    check(log.mutationAttempts === 0, 'INITIAL_AUTOMATIC_SEND_FORBIDDEN');
    log.session = 'AUTHENTICATED';
    log.phase = 'initial-report';
    await page.goto(`${ORIGIN}/scans/${SCAN}`); await page.locator('.scan-report-overview').waitFor({ state: 'visible' });
    const panel = page.locator('.scan-a1__ai'); await panel.waitFor({ state: 'visible' });
    const state = await ok('');
    check(state.state === 'completed' && state.scanId === SCAN && state.digest === DIGEST &&
      state.perCheck?.vuln?.findingCount === 440 && state.perCheck?.config?.findingCount === 1 &&
      state.perCheck?.secret?.findingCount === 0 && state.config?.findings?.length === 1, 'OWN_NODE440_CONFIG1_REQUIRED');
    log.findings = { vuln: 440, config: 1, secret: 0 };
    const current = async () => {
      const c = tools.summary.summaryContextSchema.parse(await ok('/llm/context'));
      const r = tools.chat.chatReadinessSchema.parse(await ok('/llm/readiness'));
      const u = usage.usageSchema.parse(await ok('/llm/usage'));
      const h = tools.chat.chatHistorySchema.parse(await ok('/llm/history'));
      check(currentPolicy(c) && readinessMatches(r, c) && summaryAdmission(u, c) &&
        usage.usageMatchesDisclosure(u, c.disclosure) && same(h, c) && !h.pending, 'CURRENT_POLICY_OR_READINESS');
      return { c, r, u, h };
    };
    const first = await current();
    log.policyHash = first.c.policyVersion; log.disclosureHash = fingerprint(first.c.disclosure);
    log.readiness = 'LOCALLY_CONFIGURED_UNPROBED'; log.usageBefore = usageCounts(first.u);
    log.history = { turns: first.h.turns.length, decisions: first.h.decisions.length, hash: fingerprint(first.h) };
    const initial = await get(BASE + '/llm/summary');
    let summary = null;
    if (initial.status === 200) summary = tools.summary.summaryReplySchema.parse(initial.value);
    else check(initial.status === 404 && initial.value?.errorCode === 'LLM_SUMMARY_MISSING', 'SUMMARY_GET_UNAVAILABLE');
    const hashBefore = summary ? fingerprint(summary) : null;
    log.initialSummary = summary ? 'PRESENT' : 'MISSING';
    const initialProof = proofHash(first.c, first.h, hashBefore);
    const corpus = new Map(state.config.findings.map(f => [f.findingId, { ...f, check: 'config' }]));
    const native = await collectVulnCorpus(ok, 440);
    for (const [id, f] of native.findings) { check(!corpus.has(id), 'CORPUS_DUPLICATE'); corpus.set(id, { ...f, check: 'vuln' }); }
    log.corpus = { pages: native.pages, findings: corpus.size };
    const render = async reply => {
      check(same(reply, first.c) && reply.findingCount === 441 && reply.contextSelection, 'CURRENT_SUMMARY_BINDING_OR_SCHEMA');
      check(reply.scannerFacts.length > 0 && reply.contextSelection.totalFindings === corpus.size &&
              reply.contextSelection.selectedFindingIds.every(id => corpus.has(id)), 'SUMMARY_CITATIONS_REQUIRED');
      for (const f of reply.scannerFacts) {
        const raw = corpus.get(f.findingId); check(raw, 'CITATION_NOT_NATIVE');
        for (const k of ['check', 'cveId', 'ecosystem', 'severity', 'packageName', 'installedVersion', 'fixedVersion', 'provenanceRef', 'ruleId', 'classification', 'location'])
          if (k in f) check(f[k] === raw[k], 'CITED_SCANNER_FACT_MISMATCH');
      }
      const output = page.getByLabel('ИИ-разбор отчёта', { exact: true });
      await output.waitFor({ state: 'visible' });
      const details = output.locator('details.scan-summary-explanation');
      if (await details.getAttribute('open') === null) await details.locator(':scope > summary').click();
      for (let i = 0; i < reply.hypotheses.length; i++) {
        const p = reply.hypotheses[i], facts = reply.scannerFacts.filter(f => p.citations.includes(f.findingId));
        check(!tools.language.publicReportLanguageFailure(p.text, facts), 'RUSSIAN_LANGUAGE_GUARD');
        const paragraph = details.locator(':scope > div').nth(i).locator(':scope > p');
        await paragraph.waitFor({ state: 'visible' });
        check((await paragraph.innerText()).trim() === p.text.trim(), 'SUMMARY_TEXT_NOT_VISIBLE');
        const sources = details.getByLabel(`Источники абзаца ${i + 1}`, { exact: true });
        await sources.waitFor({ state: 'visible' });
                check(await sources.locator(':scope > ul > li').count() === p.citations.length, 'SUMMARY_SOURCE_CARDS_NOT_VISIBLE');
      }
      clean(); log.summary = { hash: fingerprint(reply), paragraphs: reply.hypotheses.length,
        sources: reply.scannerFacts.length, selected: reply.contextSelection.selectedFindings,
        omitted: reply.contextSelection.omittedFindings, render: 'ACTUAL_DOM_VERIFIED' };
    };
    if (summary) await render(summary);
    else await panel.getByRole('status').filter({ hasText: 'Сохранённого ИИ-разбора пока нет.' }).waitFor({ state: 'visible' });
    await paidDisclosureUi(panel); log.disclosureUi = 'CURRENT_LIFETIME_PAID_TERMS_VISIBLE';
    check(log.mutationAttempts === 0, 'INITIAL_AUTOMATIC_SEND_FORBIDDEN');
    if (mode === 'generate-one') {
      log.phase = 'fresh-paid-consent';
      check(priorProof.hash === initialProof, 'READONLY_PROOF_CHANGED');
      check(!summary, 'SUMMARY_ALREADY_PRESENT_NO_SEND');
      const fresh = await current();
      check(proofHash(fresh.c, fresh.h, null) === initialProof && await session() === owner, 'PRE_DISPATCH_BINDING_OR_HISTORY_CHANGED');
      log.usageBefore = usageCounts(fresh.u);
      await paidDisclosureUi(panel);
      const help = await panel.locator('#scan-summary-send-help').innerText();
      check(help.includes('платный') && help.includes('Старое бесплатное согласие не применяется'), 'CURRENT_PAID_CONSENT_UI_REQUIRED');
      const cta = panel.getByRole('button', { name: 'Включить платный авторазбор OpenAI', exact: true });
      await cta.and(page.locator('button:enabled')).waitFor({ state: 'visible' }); clean();
      const responseWait = page.waitForResponse(r => r.request().method() === 'POST' && r.url() === ORIGIN + BASE + '/llm/summary', { timeout: 105_000 }).catch(() => null);
      log.phase = 'one-summary'; cleanupNeeded = true;
      gate.armCurrent(fresh.c); // Only this deliberate normal UI click can consume the armed permit.
      await cta.click();
      const response = await responseWait; gate.halted = true; gate.clicked = false;
      check(response, 'DISPATCH_UNKNOWN_NO_RETRY');
      const captured = await captureResponseDiagnostics(response, diagnostic, async finite => { log.diagnostics = finite; await save(); });
      check(response.status() === 200, 'SUMMARY_HTTP_FAILED_NO_RETRY');
      summary = tools.summary.summaryReplySchema.parse(JSON.parse(captured.raw));
      log.phase = 'summary-dom'; await render(summary);
      check(fingerprint(tools.summary.summaryReplySchema.parse(await ok('/llm/summary'))) === fingerprint(summary), 'SUMMARY_NOT_DURABLE');
      log.phase = 'automation-off-after-summary'; await preferencesOff();
      await page.goto(`${ORIGIN}/scans/${SCAN}`); await render(summary);
    }
    log.phase = 'reload';
    const attempts = log.mutationAttempts;
    await page.reload(); await page.locator('.scan-report-overview').waitFor({ state: 'visible' });
    const durable = await get(BASE + '/llm/summary');
    if (summary) {
      check(durable.status === 200 && fingerprint(tools.summary.summaryReplySchema.parse(durable.value)) === fingerprint(summary), 'RELOAD_SUMMARY_CHANGED');
      await render(summary);
    } else {
          check(durable.status === 404 && durable.value?.errorCode === 'LLM_SUMMARY_MISSING', 'RELOAD_SUMMARY_CHANGED');
          await panel.getByRole('status').filter({ hasText: 'Сохранённого ИИ-разбора пока нет.' }).waitFor({ state: 'visible' });
        }
    const history = tools.chat.chatHistorySchema.parse(await ok('/llm/history'));
    check(fingerprint(history) === fingerprint(first.h) && await session() === owner, 'HISTORY_OR_SESSION_CHANGED');
    const after = usage.usageSchema.parse(await ok('/llm/usage'));
    check(same(after, first.c) && after.available && usage.usageMatchesDisclosure(after, first.c.disclosure), 'USAGE_AFTER_UNAVAILABLE');
    log.usageAfter = { lifetime: { ...after.lifetimeBudget }, reason: after.reason };
    check(log.mutationAttempts === attempts && log.dispatched === (mode === 'generate-one' ? 1 : 0) &&
      log.mutationAttempts === log.dispatched, 'RELOAD_EXTRA_POST');
    log.reload = 'SAME_SUMMARY_ZERO_EXTRA_POST'; log.session = 'AUTHENTICATED_UNCHANGED'; log.history.verification = 'UNCHANGED';
    if (summary) {
      log.phase = 'masked-summary-only-screenshots';
      const output = page.getByLabel('ИИ-разбор отчёта', { exact: true });
      for (const width of [375, 1280]) {
        await page.setViewportSize({ width, height: 960 });
        const explanation = output.locator('details.scan-summary-explanation');
        if (await explanation.getAttribute('open') !== null) await explanation.locator(':scope > summary').click();
        // Crop to summary output only; mask all prose/source cards. No account/header/full-page capture.
        await output.screenshot({ path: join(DIR, `${runHash}-${width}.png`), mask: [explanation], timeout: 8_000 });
      }
      log.screenshots = 'SUMMARY_ONLY_SOURCE_TEXT_MASKED'; log.screenshotCount = 2;
    }
    // Confirm preferences still OFF after both report navigation and reload.
    log.phase = 'final-preferences'; await preferencesOff(); clean();
    check(log.mutationAttempts === attempts, 'RELOAD_EXTRA_POST');
    log.status = mode === 'generate-one' ? 'ONE_SUMMARY_VERIFIED' : summary ? 'READONLY_EXISTING_VERIFIED' : 'READONLY_READY_MISSING';
    log.phase = 'complete';
    if (mode === 'readonly' && !summary) {
      const proof = { at: Date.now(), status: 'READONLY_READY_MISSING', hash: initialProof };
      const tmp = join(DIR, runHash + '.proof.json'); await exclusiveRecord(tmp, proof);
      await rename(tmp, join(DIR, 'readonly-ready.json')); // Snapshot, not an attempt ledger. Immutable run evidence remains.
    }
  }
  try {
    await exclusiveRecord(record, log); recordCreated = true;
    await Promise.race([work(), new Promise((_, reject) => {
      timer = setTimeout(() => { timedOut = true; gate.halted = true; reject(new AcceptanceFailure('TOTAL_TIMEOUT')); }, LIMITS.totalMs);
    })]);
  } catch (e) {
    gate.halted = true; gate.clicked = false;
    log.status = 'BLOCKED_OR_PARTIAL';
    log.failure = { phase: log.phase, reason: e instanceof AcceptanceFailure ? e.code : e?.code === 'EEXIST' ? 'CURRENT_INTENT_ALREADY_SPENT' : safeRunnerFailure(e).code };
    // Best-effort ONLY local preference UI cleanup, with no generation gate and no retries.
    if (cleanupNeeded && page && !timedOut) {
      try {
        let cleanupTimer;
        try {
          await Promise.race([disableAutomationUi(page), new Promise((_, reject) => {
            cleanupTimer = setTimeout(() => reject(new AcceptanceFailure('CLEANUP_TIMEOUT')), Math.max(1, Math.min(15_000, deadline - Date.now())));
          })]);
          log.automation = 'OFF_ORIGINAL_SAVED'; cleanupNeeded = false;
        } finally { clearTimeout(cleanupTimer); }
      } catch { log.automation = 'CLEANUP_UNCONFIRMED'; }
    }
  } finally {
    gate.halted = true;
    // Keep the deadline armed during cleanup too. CLI exits after bounded close.
    await Promise.race([browser?.close().catch(() => {}), new Promise(resolve => { const t = setTimeout(resolve, LIMITS.closeMs); t.unref(); })]);
    clearTimeout(timer);
    if (timedOut) { log.status = 'BLOCKED_OR_PARTIAL'; log.failure = { phase: log.phase, reason: 'TOTAL_TIMEOUT' }; }
    if (cleanupNeeded) log.automation = 'CLEANUP_UNCONFIRMED';
    if (log.status !== 'BLOCKED_OR_PARTIAL' && (log.denied || log.pageErrors || log.mutationAttempts !== log.dispatched)) {
      log.status = 'BLOCKED_OR_PARTIAL'; log.failure = { phase: log.phase, reason: 'LATE_PAGE_OR_REQUEST_GUARD' };
    }
    log.at = Date.now(); await save(); await lock.close(); await unlink(join(DIR, 'runner.lock'));
    console.log(JSON.stringify(log));
  }
  return log.status === 'BLOCKED_OR_PARTIAL' ? 1 : 0;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const mode = modeOf(process.argv.slice(2));
    if (mode === 'inert') console.log('INERT: --readonly first; then --generate-one ' + AUTH_FLAG + '. Current intent is spent before browser/network; never reset markers.');
    else process.exit(await run(mode));
  } catch { console.log(JSON.stringify({ status: 'BLOCKED', reason: 'ARGUMENT_OR_EXCLUSIVE_RECORD_FAILURE' })); process.exitCode = 1; }
}
