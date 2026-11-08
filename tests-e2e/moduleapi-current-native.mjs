// Parent-run only; import/default are inert. Never reset this or any historical marker.
// After deployment: --readonly, then --generate-one --moduleapi-current-authorization-one-summary.
// No chat, translation, login, new scan, provider HTTP, private-file inspection or retry.
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { constants } from 'node:fs';
import { mkdir, open, lstat, rename, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { contracts, fingerprint, disableAutomationUi, allowedRead, collectVulnCorpus } from './native-h7v3-paid-sol.mjs';
import { BROWSER_ARGS } from './public-product-live.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const DIR = join(ROOT, 'test-results/moduleapi-current-native');
export const INTENT = 'moduleapi-current-one-summary-v1';
export const AUTH_FLAG = '--moduleapi-current-authorization-one-summary';
export const SCAN = '305a55de-6d94-4af6-a653-2bd117e1ec85';
export const ORIGIN = 'http://127.0.0.1:8081';
export const BASE = `/api/v1/browser/scans/${SCAN}`;
export const MODEL = 'gpt-5.4-mini';
export const COST_BASIS = 'moduleapi-server-estimated-configured-rates-not-invoice';
export const CAP = 5_000_000;
export const LIMITS = Object.freeze({ totalMs: 235_000, closeMs: 4_000, requests: 380, manualGets: 45, proofMs: 900_000, armMs: 30_000 });
const DIGEST = 'sha256:abe13b25e07ccaedcc8797120c37781f0462a0f0682105cf2d8b8d6f99070d55';
const HASH = /^[a-f0-9]{64}$/;
const BINDING = ['scanId', 'digest', 'platform', 'reportVersion'];
const same = (a, b) => BINDING.every(k => a?.[k] === b?.[k]);
const exact = (v, keys) => !!v && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).sort().join(',') === [...keys].sort().join(',');
class Refused extends Error { constructor(code) { super(code); this.code = code; } }
const check = (v, code) => { if (!v) throw new Refused(code); };
export function modeOf(args) {
  if (!args.length) return 'inert';
  if (JSON.stringify(args) === JSON.stringify(['--readonly'])) return 'readonly';
  if (JSON.stringify(args) === JSON.stringify(['--generate-one', AUTH_FLAG])) return 'generate-one';
  throw new Refused('INVALID_ARGUMENTS');
}
// All production callers first use the actual closed browser schemas.
export function currentPolicy(c) {
  const d = c?.disclosure;
  return c?.enabled === true && c.scanId === SCAN && c.digest === DIGEST && c.platform === 'linux/amd64' &&
    HASH.test(c.reportVersion ?? '') && HASH.test(c.policyVersion ?? '') && d?.provider === 'ModuleAPI' &&
    d.model === MODEL && d.retention === 'unknown' && d.tariffVerified === false &&
    d.operatorApprovedRouting === true && d.providerComplianceNotProvenByDeclaration === true &&
    d.zeroDataRetentionVerified === false && d.costBasis === COST_BASIS && d.monetaryLimit === 'uncapped' &&
    d.lifetimeUserCostMicros === CAP && d.requestBudgetMicros === null && d.userBudgetMicros === null && d.scanBudgetMicros === null;
}
export function readinessMatches(r, c) {
  return same(r, c) && r.localReady === true && r.status === 'locally-configured' && r.blockers.length === 0 &&
    r.costBasis === COST_BASIS && r.provider.name === 'ModuleAPI' && r.provider.model === MODEL &&
    r.provider.status === 'configured-unprobed' && r.provider.liveVerified === false &&
    r.provider.retention === 'unknown' && r.provider.tariffVerified === false && r.provider.zeroDataRetentionVerified === false &&
    r.provider.operatorApprovedRouting === true && r.credential === 'environment-valid' && r.accounting === 'configured' &&
    r.history === 'available' && r.quota === 'available' && r.requiresConsent === true && r.acceptsCredentials === false && r.generationVerified === false;
}
export function summaryAdmission(u, c) {
  if (!currentPolicy(c) || !same(u, c) || !u?.available || !u.integrationEnabled || !u.quotaEnabled ||
      u.monetaryLimit !== 'uncapped' || !['ready', 'warning'].includes(u.reason) || u.lifetimeBudget?.limitMicros !== CAP ||
      u.admission?.status !== 'fits' || u.admission.signals.length !== 0) return false;
  const p = c.disclosure.estimatedPrice, r = u.admission.reserve;
  if (![p?.input, p?.output, r.input, r.output, r.costMicros].every(n => Number.isSafeInteger(n) && n > 0)) return false;
  const estimate = (BigInt(r.input) * BigInt(p.input) + BigInt(r.output) * BigInt(p.output) + 999_999n) / 1_000_000n;
  return estimate === BigInt(r.costMicros) && r.costMicros <= u.lifetimeBudget.remainingMicros;
}
export function allowedModuleApiRead(url) {
  return allowedRead(url) && !new URL(url).pathname.includes('/llm/translation');
}
export function proofHash(c, h, u, owner) {
  return fingerprint({ intent: INTENT, binding: BINDING.map(k => c[k]), policy: c.policyVersion,
    disclosure: c.disclosure, history: fingerprint(h), usage: fingerprint(u), owner: fingerprint(owner), summary: 'MISSING' });
}
export function freshProof(p, now = Date.now()) {
  return exact(p, ['intent', 'at', 'status', 'hash']) && p.intent === INTENT && p.status === 'READONLY_READY_MISSING' &&
    HASH.test(p.hash ?? '') && Number.isSafeInteger(p.at) && now >= p.at && now - p.at <= LIMITS.proofMs;
}
// Append-only, durable spend records; a failed flush/crash consumes authorization too.
export async function exclusiveRecord(path, value) {
  const f = await open(path, 'wx', 0o600);
  try { await f.writeFile(JSON.stringify(value)); await f.sync(); } finally { await f.close(); }
  const d = await open(dirname(path), 'r'); try { await d.sync(); } finally { await d.close(); }
}
async function readProof(path) {
  const f = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const s = await f.stat(); check(s.isFile() && s.nlink === 1 && s.size <= 1024 && (s.mode & 0o777) === 0o600 && s.uid === process.getuid(), 'UNSAFE_PROOF');
    const p = JSON.parse(await f.readFile('utf8')); check(freshProof(p), 'FRESH_MODULEAPI_READONLY_FIRST_REQUIRED'); return p;
  } finally { await f.close(); }
}
export class SummaryGate {
  constructor(mode, persist, now = Date.now) { this.mode = mode; this.persist = persist; this.now = now; this.armed = false; this.blocked = false; this.spent = false; }
  armCurrent(c) {
    check(this.mode === 'generate-one' && !this.armed && !this.spent && !this.blocked && currentPolicy(c), 'MODULEAPI_AUTHORIZATION_REQUIRED');
    this.armed = true; this.at = this.now(); this.context = structuredClone(c);
  }
  async consume(path, body) {
    const c = this.context;
    const valid = this.mode === 'generate-one' && this.armed && !this.spent && !this.blocked &&
      this.now() >= this.at && this.now() - this.at <= LIMITS.armMs && path === BASE + '/llm/summary' &&
      exact(body, ['reportVersion', 'consent']) && body.reportVersion === c.reportVersion &&
      exact(body.consent, ['accepted', 'policyVersion']) && body.consent.accepted === true && body.consent.policyVersion === c.policyVersion;
    this.armed = false;
    if (!valid) { this.blocked = true; return false; }
    this.spent = true; // Synchronous before awaiting disk: concurrent calls cannot both send.
    try { await this.persist(); } catch { this.blocked = true; throw new Refused('DISPATCH_LEDGER_WRITE_FAILED'); }
    return !this.blocked;
  }
}
export async function usageContract() {
  process.env.TSX_DISABLE_CACHE = '1';
  const require = createRequire(join(ROOT, 'server/api/package.json')), m = require('tsx/package.json');
  const { tsImport } = await import(pathToFileURL(join(dirname(require.resolve('tsx/package.json')), m.exports['./esm/api'].import.default)).href);
  return tsImport(join(ROOT, 'src/shared/api/scans/llmUsageClient.ts'), { parentURL: import.meta.url, tsconfig: join(ROOT, 'tsconfig.json') });
}
export async function paidDisclosureUi(panel) {
  const disclosure = panel.getByLabel('Условия ModuleAPI', { exact: true }); await disclosure.waitFor({ state: 'visible' });
  const details = disclosure.locator('details');
  if (await details.getAttribute('open') === null) await details.locator(':scope > summary').click();
  const text = (await disclosure.innerText()).replace(/\s+/g, ' ');
  for (const required of [MODEL, '$5 на аккаунт за всё время', 'это не бесплатный режим', 'без сброса со сменой суток',
    'Денежные лимиты запроса и суток не установлены', 'Стороннему провайдеру ModuleAPI передаются',
    'Условия хранения и использования данных для обучения неизвестны.',
    'Отсутствие обучения, хранения и Zero Data Retention (ZDR) не подтверждены.',
    'Тариф аккаунта и группы ModuleAPI не проверен.', 'не гарантия эквивалентности прямому OpenAI.',
    'Учитываются исторические расходы всех провайдеров и резервы, включая неопределённый расход;',
    'смена провайдера или политики не сбрасывает этот бюджет.']) check(text.includes(required), 'MODULEAPI_UNKNOWN_PRIVACY_PAID_UI_REQUIRED');
}
export function consentHelpMatches(text) {
  return text.replace(/\s+/g, ' ').includes('Включение разрешает платный авторазбор только для показанных ModuleAPI, политики и денежного режима. Согласие для другого провайдера или бесплатного режима не применяется.');
}
export function assertReload(before, after, attempts, dispatched, expected) {
  check(fingerprint(before) === fingerprint(after), 'RELOAD_SUMMARY_CHANGED');
  check(attempts === dispatched && dispatched === expected, 'RELOAD_EXTRA_POST');
}

export async function run(mode) {
  check(['readonly', 'generate-one'].includes(mode), 'INVALID_ARGUMENTS');
  process.umask(0o077);
  await mkdir(DIR, { recursive: true, mode: 0o700 });
  const dir = await lstat(DIR); check(dir.isDirectory() && !dir.isSymbolicLink() && dir.uid === process.getuid() && (dir.mode & 0o777) === 0o700, 'UNSAFE_RUNNER_DIRECTORY');
  const lock = await open(join(DIR, 'runner.lock'), 'wx', 0o600);
  const id = fingerprint(randomUUID()), record = join(DIR, id + '.json');
  const log = { intent: INTENT, mode, status: 'PREPARING', phase: 'prepare', requests: 0, manualGets: 0, attempts: 0, dispatched: 0, denied: 0, pageErrors: 0 };
  const deadline = Date.now() + LIMITS.totalMs;
    let browser, page, timer, pendingProof, timedOut = false, cleanupNeeded = false, recordCreated = false;
  const save = async () => {
    if (!recordCreated) return;
    const f = await open(record, 'r+'); try { await f.truncate(0); await f.writeFile(JSON.stringify(log)); await f.sync(); } finally { await f.close(); }
  };
  const gate = new SummaryGate(mode, () => exclusiveRecord(join(DIR, INTENT + '.dispatch-spent.json'), { intent: INTENT, status: 'DISPATCH_SPENT_NO_RETRY', at: Date.now(), hash: id }));
  const clean = () => check(!timedOut && !log.denied && !log.pageErrors && !gate.blocked, 'PAGE_OR_REQUEST_GUARD');
  async function work() {
    let prior;
    if (mode === 'generate-one') {
      prior = await readProof(join(DIR, 'readonly-ready.json'));
      await exclusiveRecord(join(DIR, INTENT + '.authorization-spent.json'), { intent: INTENT, status: 'AUTHORIZATION_SPENT_NO_RETRY', at: Date.now(), hash: id });
    }
    const [tools, usage] = await Promise.all([contracts(), usageContract()]);
    const { chromium } = await import('@playwright/test');
    const env = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'SystemRoot'].filter(k => process.env[k] !== undefined).map(k => [k, process.env[k]]));
    browser = await chromium.launchPersistentContext(join(ROOT, 'test-results/native-h7v3-sol/browser'), {
      headless: true, timeout: 20_000, args: [...BROWSER_ARGS], env, serviceWorkers: 'block', acceptDownloads: false,
      viewport: { width: 1280, height: 960 }, reducedMotion: 'reduce',
    });
    clean();
    await browser.routeWebSocket('**/*', socket => { log.denied++; gate.blocked = true; socket.close(); });
    await browser.route('**/*', async route => {
      const r = route.request(), deny = async () => { log.denied++; gate.blocked = true; await route.abort(); };
      try {
        const u = new URL(r.url());
        if (++log.requests > LIMITS.requests || timedOut || log.denied || !page || r.frame().page() !== page ||
            u.origin !== ORIGIN || u.username || u.password || u.hash || r.redirectedFrom()) return await deny();
        if (r.method() === 'GET') return allowedModuleApiRead(r.url()) ? await route.continue() : await deny();
        log.attempts++;
        if (r.method() !== 'POST' || u.search || u.pathname !== BASE + '/llm/summary' || !await gate.consume(u.pathname, r.postDataJSON())) return await deny();
        log.dispatched++; await save(); clean();
        check(Date.now() - gate.at <= LIMITS.armMs, 'ARM_EXPIRED');
        return await route.continue();
      } catch { await deny(); }
    });
    for (const old of browser.pages()) await old.close();
    page = await browser.newPage(); page.setDefaultTimeout(12_000); page.setDefaultNavigationTimeout(15_000);
    page.on('pageerror', () => { log.pageErrors++; gate.blocked = true; });
    page.on('dialog', dialog => { log.denied++; gate.blocked = true; void dialog.dismiss(); });
    const get = async path => {
      clean(); check(++log.manualGets <= LIMITS.manualGets, 'MANUAL_GET_BOUND');
      const result = await page.evaluate(async path => {
        const response = await fetch(path, { credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(12_000) });
        const reader = response.body.getReader(), chunks = []; let bytes = 0;
        try {
          for (;;) { const p = await reader.read(); if (p.done) break; bytes += p.value.length; if (bytes > 2_097_152) throw Error('GET_BOUND'); chunks.push(p.value); }
          const all = new Uint8Array(bytes); let offset = 0; for (const c of chunks) { all.set(c, offset); offset += c.length; }
          return { status: response.status, value: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(all)) };
        } finally { await reader.cancel().catch(() => {}); }
      }, path);
      clean(); return result;
    };
    const ok = async suffix => { const r = await get(BASE + suffix); check(r.status === 200, 'CURRENT_GET_FAILED'); return r.value; };
    const session = async () => { const r = await get('/api/v1/auth/me'); check(r.status === 200 && typeof r.value?.id === 'string' && r.value.id.length > 0, 'AUTHENTICATED_OWN_SESSION_REQUIRED'); return r.value.id; };
    const preferencesOff = async () => {
      await disableAutomationUi(page); await page.reload();
      const d = page.locator('details.demo-auth__preferences'); await d.waitFor({ state: 'visible' });
      if (await d.getAttribute('open') === null) await d.locator(':scope > summary').click();
      const p = d.getByRole('region', { name: 'Настройки отчётов', exact: true });
      check(await p.getByLabel('ИИ-разбор', { exact: true }).inputValue() === 'off' &&
        await p.getByLabel('Язык исходных описаний уязвимостей', { exact: true }).inputValue() === 'original', 'AUTOMATION_NOT_OFF');
      clean(); cleanupNeeded = false; log.automation = 'OFF_ORIGINAL_PERSISTED';
    };
    log.phase = 'automation-off'; await preferencesOff(); const owner = await session();
    await page.goto(`${ORIGIN}/scans/${SCAN}`); await page.locator('.scan-report-overview').waitFor({ state: 'visible' });
    const panel = page.locator('.scan-a1__ai'); await panel.waitFor({ state: 'visible' });
    const state = await ok('');
    check(state.state === 'completed' && state.scanId === SCAN && state.digest === DIGEST && state.platform === 'linux/amd64' &&
      state.perCheck?.vuln?.findingCount === 440 && state.perCheck?.config?.findingCount === 1 &&
      state.perCheck?.secret?.findingCount === 0 && state.config?.findings?.length === 1, 'OWN_NODE440_CONFIG1_REQUIRED');
    const current = async (requireAdmission = true) => {
      const c = tools.summary.summaryContextSchema.parse(await ok('/llm/context'));
      const r = tools.chat.chatReadinessSchema.parse(await ok('/llm/readiness'));
      const u = usage.usageSchema.parse(await ok('/llm/usage'));
      const h = tools.chat.chatHistorySchema.parse(await ok('/llm/history'));
      check(currentPolicy(c) && readinessMatches(r, c) && same(u, c) && u.available && u.integrationEnabled && u.quotaEnabled &&
              (!requireAdmission || summaryAdmission(u, c)) && usage.usageMatchesDisclosure(u, c.disclosure) && same(h, c) && !h.pending, 'CURRENT_MODULEAPI_POLICY_OR_ADMISSION');
      return { c, u, h };
    };
    const first = await current(false), initialHash = proofHash(first.c, first.h, first.u, owner);
    const readSummary = async () => {
      const r = await get(BASE + '/llm/summary');
      if (r.status === 200) return tools.summary.summaryReplySchema.parse(r.value);
      check(r.status === 404 && r.value?.errorCode === 'LLM_SUMMARY_MISSING', 'SUMMARY_GET_UNAVAILABLE'); return null;
    };
    let summary = await readSummary();
        if (!summary) check(summaryAdmission(first.u, first.c), 'SUMMARY_SNAPSHOT_DOES_NOT_FIT');
    const corpus = new Map(state.config.findings.map(f => [f.findingId, { ...f, check: 'config' }]));
    const native = await collectVulnCorpus(ok, 440);
    for (const [id, f] of native.findings) { check(!corpus.has(id), 'CORPUS_DUPLICATE'); corpus.set(id, { ...f, check: 'vuln' }); }
    const render = async reply => {
      check(same(reply, first.c) && reply.findingCount === 441 && reply.contextSelection?.totalFindings === corpus.size &&
        reply.contextSelection.selectedFindingIds.every(id => corpus.has(id)) && reply.scannerFacts.length > 0, 'SUMMARY_BINDING_OR_CITATIONS');
      for (const f of reply.scannerFacts) {
        const raw = corpus.get(f.findingId); check(raw, 'CITATION_NOT_NATIVE');
        for (const k of ['check', 'cveId', 'ecosystem', 'severity', 'packageName', 'installedVersion', 'fixedVersion', 'provenanceRef', 'ruleId', 'classification', 'location'])
          if (k in f) check(f[k] === raw[k], 'CITED_SCANNER_FACT_MISMATCH');
      }
      const output = page.getByLabel('ИИ-разбор отчёта', { exact: true }); await output.waitFor({ state: 'visible' });
      const details = output.locator('details.scan-summary-explanation');
      if (await details.getAttribute('open') === null) await details.locator(':scope > summary').click();
      for (let i = 0; i < reply.hypotheses.length; i++) {
        const p = reply.hypotheses[i], facts = reply.scannerFacts.filter(f => p.citations.includes(f.findingId));
        check(!tools.language.publicReportLanguageFailure(p.text, facts), 'RUSSIAN_LANGUAGE_GUARD');
        const text = details.locator(':scope > div').nth(i).locator(':scope > p'); await text.waitFor({ state: 'visible' });
        check((await text.innerText()).trim() === p.text.trim(), 'SUMMARY_TEXT_NOT_VISIBLE');
        const sources = details.getByLabel(`Источники абзаца ${i + 1}`, { exact: true }); await sources.waitFor({ state: 'visible' });
        check(await sources.locator(':scope > ul > li').count() === p.citations.length, 'SUMMARY_SOURCES_NOT_VISIBLE');
      }
      clean();
    };
    if (summary) await render(summary);
    else await panel.getByRole('status').filter({ hasText: 'Сохранённого ИИ-разбора пока нет.' }).waitFor({ state: 'visible' });
    await paidDisclosureUi(panel); clean(); check(log.attempts === 0, 'INITIAL_AUTOMATIC_SEND_FORBIDDEN');
    if (mode === 'generate-one') {
      log.phase = 'fresh-moduleapi-consent';
      check(freshProof(prior) && prior.hash === initialHash && !summary, 'READONLY_PROOF_CHANGED_OR_SUMMARY_EXISTS');
      const fresh = await current();
      check(proofHash(fresh.c, fresh.h, fresh.u, await session()) === initialHash && await readSummary() === null, 'PRE_DISPATCH_BINDING_OR_SUMMARY_CHANGED');
      await paidDisclosureUi(panel);
      const help = (await panel.locator('#scan-summary-send-help').innerText()).replace(/\s+/g, ' ');
      check(consentHelpMatches(help), 'FRESH_MODULEAPI_CONSENT_UI_REQUIRED');
      const cta = panel.getByRole('button', { name: 'Включить платный авторазбор ModuleAPI', exact: true });
      await cta.and(page.locator('button:enabled')).waitFor({ state: 'visible' }); clean();
      const pending = page.waitForResponse(r => r.request().method() === 'POST' && r.url() === ORIGIN + BASE + '/llm/summary', { timeout: 105_000 }).catch(() => null);
      log.phase = 'one-summary'; cleanupNeeded = true; gate.armCurrent(fresh.c); await cta.click();
      const response = await pending; gate.armed = false;
      check(response, 'DISPATCH_UNKNOWN_NO_RETRY'); log.summaryHttpStatus = response.status(); await save();
      check(response.status() === 200, 'SUMMARY_HTTP_FAILED_NO_RETRY');
      const raw = await response.text(); check(Buffer.byteLength(raw) <= 196_608, 'SUMMARY_WIRE_BOUND');
      summary = tools.summary.summaryReplySchema.parse(JSON.parse(raw)); await render(summary);
      check(fingerprint(await readSummary()) === fingerprint(summary), 'SUMMARY_NOT_DURABLE');
      await preferencesOff(); await page.goto(`${ORIGIN}/scans/${SCAN}`); await render(summary);
    }
    log.phase = 'reload'; gate.armed = false;
    await page.reload(); await page.locator('.scan-report-overview').waitFor({ state: 'visible' });
    assertReload(summary, await readSummary(), log.attempts, log.dispatched, mode === 'generate-one' ? 1 : 0);
    if (summary) await render(summary);
    const final = await current(false);
    check(fingerprint(final.h) === fingerprint(first.h) && proofHash(final.c, final.h, first.u, await session()) === initialHash, 'POLICY_HISTORY_OR_SESSION_CHANGED');
    check(final.u.lifetimeBudget.usedMicros >= first.u.lifetimeBudget.usedMicros &&
      (mode === 'generate-one' || fingerprint(final.u) === fingerprint(first.u)), 'LIFETIME_ACCOUNTING_REGRESSED_OR_READONLY_CHANGED');
    log.usageBefore = { lifetime: first.u.lifetimeBudget, reserve: first.u.admission.reserve };
    log.usageAfter = { lifetime: final.u.lifetimeBudget }; log.summaryHash = summary ? fingerprint(summary) : null;
    await preferencesOff(); clean(); assertReload(summary, summary, log.attempts, log.dispatched, mode === 'generate-one' ? 1 : 0);
    log.status = mode === 'generate-one' ? 'ONE_MODULEAPI_SUMMARY_VERIFIED' : summary ? 'READONLY_EXISTING_GET_VERIFIED' : 'READONLY_READY_MISSING';
    log.generationVerified = mode === 'generate-one'; log.privacyAndTariffVerified = false; log.phase = 'complete';
    if (mode === 'readonly' && !summary) pendingProof = { intent: INTENT, status: 'READONLY_READY_MISSING', at: Date.now(), hash: initialHash };
  }
  try {
    await exclusiveRecord(record, log); recordCreated = true;
    await Promise.race([work(), new Promise((_, reject) => { timer = setTimeout(() => { timedOut = true; gate.blocked = true; reject(new Refused('TOTAL_TIMEOUT')); }, LIMITS.totalMs); })]);
  } catch (e) {
    gate.armed = false; gate.blocked = true; log.status = 'BLOCKED_OR_PARTIAL';
    log.failure = e instanceof Refused ? e.code : e?.code === 'EEXIST' ? 'MODULEAPI_INTENT_ALREADY_SPENT' : 'UI_SCHEMA_OR_IO_FAILURE';
    // No failure cleanup can generate: permit is permanently closed. No retry/recovery.
    if (cleanupNeeded && page && !timedOut) {
      let cleanupTimer;
            try {
              await Promise.race([disableAutomationUi(page), new Promise((_, reject) => {
                cleanupTimer = setTimeout(() => reject(new Refused('CLEANUP_TIMEOUT')), Math.max(1, Math.min(15_000, deadline - Date.now())));
              })]);
              cleanupNeeded = false; log.automation = 'OFF_ORIGINAL_SAVED';
            } catch { /* Finite cleanup status below. */ } finally { clearTimeout(cleanupTimer); }
    }
  } finally {
    gate.armed = false; gate.blocked = true;
    let closed = !browser, closeTimer;
    await Promise.race([browser?.close().then(() => { closed = true; }).catch(() => {}), new Promise(resolve => { closeTimer = setTimeout(resolve, LIMITS.closeMs); })]);
    clearTimeout(closeTimer); clearTimeout(timer);
    if (timedOut || !closed || log.denied || log.pageErrors || log.attempts !== log.dispatched) {
      log.status = 'BLOCKED_OR_PARTIAL'; log.failure = timedOut ? 'TOTAL_TIMEOUT' : 'LATE_PAGE_REQUEST_OR_CLOSE_GUARD';
    }
    if (cleanupNeeded) log.automation = 'CLEANUP_UNCONFIRMED';
    if (pendingProof && log.status === 'READONLY_READY_MISSING') {
      const tmp = join(DIR, id + '.proof.json'); await exclusiveRecord(tmp, pendingProof);
      await rename(tmp, join(DIR, 'readonly-ready.json')); // Publish only after clean bounded browser close; never a spend marker.
    }
    await save(); await lock.close();
    if (closed) await unlink(join(DIR, 'runner.lock')); // Uncertain close retains lock; never clear manually/retry.
    console.log(JSON.stringify(log));
  }
  return log.status === 'BLOCKED_OR_PARTIAL' ? 1 : 0;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { const mode = modeOf(process.argv.slice(2));
    if (mode === 'inert') console.log('INERT: --readonly first; then --generate-one ' + AUTH_FLAG + '. Never reset markers; failures/uncertain dispatch are no-retry.');
    else process.exit(await run(mode));
  } catch { console.log(JSON.stringify({ status: 'BLOCKED', reason: 'ARGUMENT_OR_EXCLUSIVE_RECORD_FAILURE' })); process.exitCode = 1; }
}
