// Synthetic only: never calls run(), launches a browser, reads retained/private state or uses HTTP/Docker.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  modeOf, currentPolicy, readinessMatches, summaryAdmission, allowedModuleApiRead, proofHash,
  freshProof, SummaryGate, exclusiveRecord, usageContract, paidDisclosureUi, consentHelpMatches,
  assertReload, SCAN, ORIGIN, BASE, MODEL, COST_BASIS, CAP, AUTH_FLAG, INTENT, LIMITS,
} from './moduleapi-current-native.mjs';
import { contracts } from './native-h7v3-paid-sol.mjs';

const context = () => ({
  scanId: SCAN, digest: 'sha256:abe13b25e07ccaedcc8797120c37781f0462a0f0682105cf2d8b8d6f99070d55',
  platform: 'linux/amd64', reportVersion: 'b'.repeat(64), enabled: true, policyVersion: 'c'.repeat(64),
  disclosure: { provider: 'ModuleAPI', model: MODEL, retention: 'unknown', tariffVerified: false,
    operatorApprovedRouting: true, providerComplianceNotProvenByDeclaration: true, zeroDataRetentionVerified: false,
    monetaryLimit: 'uncapped', lifetimeUserCostMicros: CAP, requestBudgetMicros: null, userBudgetMicros: null, scanBudgetMicros: null,
    costBasis: COST_BASIS, estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 750000, output: 4500000 },
    data: 'Sanitized scanner findings and coverage; no raw evidence or credentials.' },
});
const body = () => ({ reportVersion: context().reportVersion, consent: { accepted: true, policyVersion: context().policyVersion } });
const readiness = () => {
  const { scanId, digest, platform, reportVersion } = context();
  return { scanId, digest, platform, reportVersion, localReady: true, status: 'locally-configured', blockers: [],
    credential: 'environment-valid', quota: 'available', history: 'available', accounting: 'configured', costBasis: COST_BASIS,
    provider: { name: 'ModuleAPI', model: MODEL, status: 'configured-unprobed', liveVerified: false,
      retention: 'unknown', tariffVerified: false, operatorApprovedRouting: true, zeroDataRetentionVerified: false },
    generationVerified: false, requiresConsent: true, acceptsCredentials: false, setupAction: 'operator-server-environment-configuration' };
};
const vector = n => ({ input: n, output: n, costMicros: n });
const scope = () => ({ limits: { input: 1, output: 1, costMicros: null }, used: vector(100), held: vector(0), carried: vector(0),
  remaining: { input: 0, output: 0, costMicros: null }, warning: true, exhausted: true });
const usage = () => {
  const { scanId, digest, platform, reportVersion } = context();
  return { scanId, digest, platform, reportVersion, available: true, integrationEnabled: true, quotaEnabled: true, monetaryLimit: 'uncapped',
    lifetimeBudget: { limitMicros: CAP, usedMicros: 100, heldMicros: 0, remainingMicros: CAP - 100 },
    admission: { status: 'fits', reserve: { input: 2000, output: 1000, costMicros: 6000 }, signals: [] }, reason: 'ready',
    window: { start: 0, end: 86400000 }, signals: [], user: scope(), scan: scope() };
};

test('import/default CLI are inert; only distinct exact ModuleAPI authorization is accepted', () => {
  assert.equal(modeOf([]), 'inert'); assert.equal(modeOf(['--readonly']), 'readonly');
  assert.equal(modeOf(['--generate-one', AUTH_FLAG]), 'generate-one');
  for (const args of [['--generate-one'], [AUTH_FLAG], ['--readonly', AUTH_FLAG], ['--generate-one', AUTH_FLAG, AUTH_FLAG],
    ['--generate-one', '--current-authorization-one-summary'], ['--generate', '--ack-coordinator-paid-go'], ['--readonly', '--scan', SCAN]]) assert.throws(() => modeOf(args));
  assert.equal(INTENT, 'moduleapi-current-one-summary-v1'); assert.ok(LIMITS.totalMs + LIMITS.closeMs < 240000);
  const cli = fileURLToPath(new URL('./moduleapi-current-native.mjs', import.meta.url));
  assert.match(execFileSync(process.execPath, [cli], { encoding: 'utf8', timeout: 5000 }), /^INERT: --readonly first;/);
});
test('exact provider/model/own report/unknown privacy/separate cost basis/$5 policy only', () => {
  assert.equal(currentPolicy(context()), true);
  for (const patch of [{ provider: 'OpenAI' }, { provider: 'OpenRouter' }, { model: 'gpt-5.4-mini-2026-03-17' },
    { retention: 'no-training' }, { tariffVerified: true }, { zeroDataRetentionVerified: true }, { operatorApprovedRouting: false },
    { providerComplianceNotProvenByDeclaration: false }, { costBasis: 'server-estimated-configured-rates-not-invoice' },
    { lifetimeUserCostMicros: undefined }, { lifetimeUserCostMicros: CAP + 1 }, { monetaryLimit: 'capped' },
    { requestBudgetMicros: 1 }, { userBudgetMicros: 1 }, { scanBudgetMicros: 1 }]) {
    const c = context(); Object.assign(c.disclosure, patch); assert.equal(currentPolicy(c), false, JSON.stringify(patch));
  }
  for (const patch of [{ scanId: '00000000-0000-4000-8000-000000000001' }, { digest: 'sha256:' + 'a'.repeat(64) },
    { platform: 'linux/arm64' }, { enabled: false }, { policyVersion: null }, { reportVersion: 'bad' }]) assert.equal(currentPolicy({ ...context(), ...patch }), false);
});
test('actual closed context/readiness schemas parse ModuleAPI and reject unknown fields and false privacy', async () => {
  const t = await contracts(), c = t.summary.summaryContextSchema.parse(context()), r = t.chat.chatReadinessSchema.parse(readiness());
  assert.equal(currentPolicy(c), true); assert.equal(readinessMatches(r, c), true);
  assert.equal(t.summary.summaryContextSchema.safeParse({ ...context(), extra: true }).success, false);
  const bad = context(); bad.disclosure.extra = true; assert.equal(t.summary.summaryContextSchema.safeParse(bad).success, false);
  const untrue = context(); untrue.disclosure.retention = 'no-training'; assert.equal(t.summary.summaryContextSchema.safeParse(untrue).success, false);
  for (const patch of [{ name: 'OpenAI' }, { model: 'gpt-5.4-mini-2026-03-17' }, { liveVerified: true },
    { tariffVerified: true }, { retention: 'no-training' }, { zeroDataRetentionVerified: true }]) {
    const v = readiness(); Object.assign(v.provider, patch); assert.equal(t.chat.chatReadinessSchema.safeParse(v).success, false);
  }
  for (const patch of [{ credential: 'unavailable' }, { requiresConsent: false }, { costBasis: 'wrong' }, { reportVersion: 'd'.repeat(64) }])
    assert.equal(readinessMatches({ ...readiness(), ...patch }, c), false);
});
test('actual usage decoder admits exact SUMMARY reserve under shared lifetime, not exhausted daily stats', async () => {
  const t = await usageContract(), u = t.usageSchema.parse(usage());
  assert.equal(t.usageMatchesDisclosure(u, context().disclosure), true);
  assert.equal(u.user.exhausted, true); assert.equal(summaryAdmission(u, context()), true);
  for (const change of [u => { u.admission.reserve.costMicros++; }, u => { u.admission.status = 'insufficient'; },
    u => { u.lifetimeBudget.limitMicros++; }, u => { u.lifetimeBudget.remainingMicros = 5999; },
    u => { u.integrationEnabled = false; }, u => { u.quotaEnabled = false; }, u => { u.reason = 'policy_fault'; },
    u => { u.admission.signals.push({ reason: 'insufficient' }); }, u => { u.reportVersion = 'd'.repeat(64); }]) {
    const v = usage(); change(v); assert.equal(summaryAdmission(v, context()), false);
  }
  const c = context(); c.disclosure.estimatedPrice.input = 0; assert.equal(summaryAdmission(usage(), c), false);
  const rounded = usage(); rounded.admission.reserve.input = 2001; rounded.admission.reserve.costMicros = 6001;
  assert.equal(summaryAdmission(rounded, context()), true);
  const bad = usage(); bad.lifetimeBudget.remainingMicros--; assert.equal(t.usageSchema.safeParse(bad).success, false);
  const fabricated = usage(); fabricated.lifetimeBudget.usedMicros = CAP - 1; fabricated.lifetimeBudget.remainingMicros = 1;
  assert.equal(t.usageSchema.safeParse(fabricated).success, false);
  assert.equal(t.usageSchema.safeParse({ ...usage(), extra: true }).success, false);
});
test('UNKNOWN/historical held liabilities consume lifetime, never reinterpreted as free funds', async () => {
  const t = await usageContract(), u = usage();
  u.lifetimeBudget.heldMicros = CAP - 200; u.lifetimeBudget.remainingMicros = 100;
  u.admission.status = 'insufficient'; u.admission.signals = [{ scope: 'user', dimension: 'costMicros', reason: 'insufficient', required: 6000, remaining: 100 }];
  assert.equal(t.usageSchema.safeParse(u).success, true); assert.equal(summaryAdmission(u, context()), false);
});
test('GET allowlist confines own session/report; never provider/auth mutation endpoints/translation/other scans', () => {
  for (const path of ['/account', `/scans/${SCAN}`, '/api/v1/auth/me', BASE, BASE + '/llm/context', BASE + '/llm/usage',
    BASE + '/llm/readiness', BASE + '/llm/history', BASE + '/llm/summary', BASE + '/vuln?cursor=400&limit=50'])
    assert.equal(allowedModuleApiRead(ORIGIN + path), true, path);
  for (const url of ['https://moduleapi.pro/v1/models', 'https://moduleapi.pro/v1/chat/completions', 'https://api.openai.com/v1/chat/completions',
    ORIGIN + '/api/v1/auth/login', ORIGIN + '/api/v1/browser/scans', ORIGIN + BASE + '/llm/summary?retry=1',
    ORIGIN + BASE + '/llm/translation/context?findingId=vuln-' + 'a'.repeat(64) + '&assessmentIndex=0',
    ORIGIN + '/scans/00000000-0000-4000-8000-000000000001', 'http://u:p@127.0.0.1:8081/account']) assert.equal(allowedModuleApiRead(url), false, url);
});
test('proof is new-namespace, closed, missing-only, finite and bound to policy/report/history/usage/session', () => {
  const h = { turns: [] }, hash = proofHash(context(), h, usage(), 'synthetic-owner');
  const p = { intent: INTENT, at: 100, status: 'READONLY_READY_MISSING', hash };
  assert.equal(freshProof(p, 101), true);
  for (const bad of [{ ...p, intent: 'summary-current-explicit-v1' }, { ...p, status: 'READONLY_EXISTING_GET_VERIFIED' },
    { ...p, extra: true }, { ...p, hash: 'bad' }]) assert.equal(freshProof(bad, 101), false);
  assert.equal(freshProof(p, 99), false); assert.equal(freshProof(p, 100 + LIMITS.proofMs + 1), false);
  const changed = context(); changed.disclosure.estimatedPrice.input++;
  for (const v of [proofHash(changed, h, usage(), 'synthetic-owner'), proofHash({ ...context(), policyVersion: 'd'.repeat(64) }, h, usage(), 'synthetic-owner'),
    proofHash(context(), { turns: [{ state: 'failed' }] }, usage(), 'synthetic-owner'),
    proofHash(context(), h, { ...usage(), window: { start: 86400000, end: 172800000 } }, 'synthetic-owner'),
    proofHash(context(), h, usage(), 'other-owner')]) assert.notEqual(v, hash);
});
test('read-only and unarmed automatic generation cannot dispatch/rearm', async () => {
  for (const mode of ['readonly', 'generate-one']) {
    let writes = 0; const g = new SummaryGate(mode, async () => { writes++; });
    if (mode === 'readonly') assert.throws(() => g.armCurrent(context()));
    assert.equal(await g.consume(BASE + '/llm/summary', body()), false); assert.equal(writes, 0);
    assert.throws(() => g.armCurrent(context()));
  }
});
test('fresh ModuleAPI CTA permit allows exactly one strict consent-bound summary', async () => {
  let writes = 0; const g = new SummaryGate('generate-one', async () => { writes++; }); g.armCurrent(context());
  assert.equal(await g.consume(BASE + '/llm/summary', body()), true); assert.equal(writes, 1);
  assert.equal(await g.consume(BASE + '/llm/summary', body()), false); assert.throws(() => g.armCurrent(context()));
  const old = context(); old.disclosure.provider = 'OpenAI';
  assert.throws(() => new SummaryGate('generate-one', async () => {}).armCurrent(old));
});
test('wrong/old consent, extra fields, chat/translation/auth/new-scan attempts permanently terminate permit', async () => {
  const invalid = [{ ...body(), extra: true }, { ...body(), question: 'no chat' }, { ...body(), reportVersion: 'd'.repeat(64) },
    { ...body(), consent: { accepted: false, policyVersion: context().policyVersion } },
    { ...body(), consent: { accepted: true, policyVersion: 'd'.repeat(64) } },
    { ...body(), consent: { ...body().consent, extra: true } }, { ...body(), legacyFreeConsent: true }];
  for (const b of invalid) {
    const g = new SummaryGate('generate-one', async () => assert.fail('no ledger write')); g.armCurrent(context());
    assert.equal(await g.consume(BASE + '/llm/summary', b), false);
    assert.equal(await g.consume(BASE + '/llm/summary', body()), false); assert.throws(() => g.armCurrent(context()));
  }
  for (const path of [BASE + '/llm/chat', BASE + '/llm/translation', '/api/v1/auth/login', '/api/v1/browser/scans']) {
    const g = new SummaryGate('generate-one', async () => assert.fail('no dispatch')); g.armCurrent(context());
    assert.equal(await g.consume(path, body()), false); assert.equal(await g.consume(BASE + '/llm/summary', body()), false);
  }
});
test('arm expires and clock reversal fails closed', async () => {
  for (const after of [0, 1 + LIMITS.armMs + 1]) {
    let now = 1; const g = new SummaryGate('generate-one', async () => assert.fail('expired'), () => now);
    g.armCurrent(context()); now = after; assert.equal(await g.consume(BASE + '/llm/summary', body()), false);
    assert.throws(() => g.armCurrent(context()));
  }
});
test('durable flush precedes dispatch; racing duplicate poisons permit instead of sending twice', async () => {
  let release, writes = 0; const wait = new Promise(resolve => { release = resolve; });
  const g = new SummaryGate('generate-one', async () => { writes++; await wait; }); g.armCurrent(context());
  const pending = g.consume(BASE + '/llm/summary', body()); assert.equal(g.spent, true); assert.equal(writes, 1);
  assert.equal(await g.consume(BASE + '/llm/summary', body()), false); release(); assert.equal(await pending, false);
  assert.equal(writes, 1); assert.throws(() => g.armCurrent(context()));
});
test('flush failure is permanently spent and never returns dispatch permission', async () => {
  const g = new SummaryGate('generate-one', async () => { throw Error('synthetic disk failure'); }); g.armCurrent(context());
  await assert.rejects(g.consume(BASE + '/llm/summary', body()), /DISPATCH_LEDGER_WRITE_FAILED/);
  assert.equal(g.spent, true); assert.equal(await g.consume(BASE + '/llm/summary', body()), false); assert.throws(() => g.armCurrent(context()));
});
test('exclusive spend markers never overwrite or reset prior intent; synthetic temp files only', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'moduleapi-runner-offline-'));
  try {
    const old = join(dir, 'summary-current-explicit-v1.authorization-spent.json');
    const fresh = join(dir, INTENT + '.authorization-spent.json');
    await exclusiveRecord(old, { spent: true }); const before = await readFile(old);
    await exclusiveRecord(fresh, { intent: INTENT, spent: true }); const newBefore = await readFile(fresh);
    await assert.rejects(exclusiveRecord(fresh, { spent: false }), { code: 'EEXIST' });
    assert.deepEqual(await readFile(old), before); assert.deepEqual(await readFile(fresh), newBefore);
    assert.equal((await stat(fresh)).mode & 0o777, 0o600);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
const privacyText = `${MODEL} $5 на аккаунт за всё время это не бесплатный режим без сброса со сменой суток
Денежные лимиты запроса и суток не установлены Стороннему провайдеру ModuleAPI передаются
Условия хранения и использования данных для обучения неизвестны.
Отсутствие обучения, хранения и Zero Data Retention (ZDR) не подтверждены.
Тариф аккаунта и группы ModuleAPI не проверен. не гарантия эквивалентности прямому OpenAI.
Учитываются исторические расходы всех провайдеров и резервы, включая неопределённый расход;
смена провайдера или политики не сбрасывает этот бюджет.`;
test('actual ModuleAPI paid UI must expand unknown privacy/tariff/shared lifetime, not inherit OpenAI claims', async () => {
  async function verify(text) {
    let expanded = false;
    const panel = { getByLabel: (label, options) => {
      assert.equal(label, 'Условия ModuleAPI'); assert.deepEqual(options, { exact: true });
      return { waitFor: async () => {}, locator: () => ({ getAttribute: async () => null,
        locator: () => ({ click: async () => { expanded = true; } }) }),
        innerText: async () => { assert.equal(expanded, true); return text; } };
    } };
    return paidDisclosureUi(panel);
  }
  await verify(privacyText);
  for (const phrase of ['$5 на аккаунт за всё время', 'Условия хранения и использования данных для обучения неизвестны.',
    'Отсутствие обучения, хранения и Zero Data Retention (ZDR) не подтверждены.', 'Тариф аккаунта и группы ModuleAPI не проверен.',
    'не гарантия эквивалентности прямому OpenAI.', 'смена провайдера или политики не сбрасывает этот бюджет.'])
    await assert.rejects(verify(privacyText.replace(phrase, 'invalid')), /MODULEAPI_UNKNOWN_PRIVACY_PAID_UI_REQUIRED/);
});
test('fresh consent helper matches actual provider-specific UI; old OpenAI/free wording rejected', () => {
  const text = 'Включение разрешает платный авторазбор только для показанных ModuleAPI, политики и денежного режима. Согласие для другого провайдера или бесплатного режима не применяется.';
  assert.equal(consentHelpMatches(text), true); assert.equal(consentHelpMatches(text.replace('ModuleAPI', 'OpenAI')), false);
  assert.equal(consentHelpMatches('Старое бесплатное согласие не применяется'), false);
});
test('GET reload requires identical summary and no extra POST even after a successful generation', () => {
  const summary = { hypotheses: [{ text: 'synthetic', citations: ['synthetic'] }] };
  assertReload(null, null, 0, 0, 0); assertReload(summary, structuredClone(summary), 1, 1, 1);
  assert.throws(() => assertReload(summary, null, 1, 1, 1), /RELOAD_SUMMARY_CHANGED/);
  assert.throws(() => assertReload(summary, summary, 2, 1, 1), /RELOAD_EXTRA_POST/);
  assert.throws(() => assertReload(summary, summary, 2, 2, 1), /RELOAD_EXTRA_POST/);
});
