// Offline only: no browser launch, Docker, server, provider, or retained-profile reads.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  modeOf, currentPolicy, summaryAdmission, allowedSummaryRead, proofHash, freshProof,
  exclusiveRecord, SummaryGate, usageContract, paidDisclosureUi, AUTH_FLAG, CAP, INTENT, LIMITS,
} from './summary-current-native.mjs';
import { SCAN, BASE, MODEL, ORIGIN, contracts, fingerprint } from './native-h7v3-paid-sol.mjs';
import { diagnosticContracts, captureResponseDiagnostics } from './native-h7v3-finite-diagnostics.mjs';
const context = () => ({
  scanId: SCAN, digest: 'sha256:abe13b25e07ccaedcc8797120c37781f0462a0f0682105cf2d8b8d6f99070d55',
  platform: 'linux/amd64', reportVersion: 'b'.repeat(64), enabled: true, policyVersion: 'c'.repeat(64),
  disclosure: { provider: 'OpenAI', model: MODEL, monetaryLimit: 'uncapped', lifetimeUserCostMicros: CAP,
    requestBudgetMicros: null, userBudgetMicros: null, scanBudgetMicros: null,
    retention: 'no-training', zeroDataRetentionVerified: false, operatorApprovedRouting: true,
    providerComplianceNotProvenByDeclaration: true, costBasis: 'server-estimated-configured-rates-not-invoice',
    data: 'Sanitized scanner findings and coverage; no raw evidence or credentials.',
    estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 750000, output: 4500000 } },
});
const body = () => ({ reportVersion: context().reportVersion, consent: { accepted: true, policyVersion: context().policyVersion } });
const vector = n => ({ input: n, output: n, costMicros: n });
function scope() {
  return { limits: { input: 1, output: 1, costMicros: null }, used: vector(100), held: vector(0), carried: vector(0),
    remaining: { input: 0, output: 0, costMicros: null }, warning: true, exhausted: true };
}
function usage() {
  const c = context();
  return { scanId: c.scanId, digest: c.digest, platform: c.platform, reportVersion: c.reportVersion,
    integrationEnabled: true, quotaEnabled: true, available: true, monetaryLimit: 'uncapped',
    lifetimeBudget: { limitMicros: CAP, usedMicros: 100, heldMicros: 0, remainingMicros: CAP - 100 },
    admission: { status: 'fits', reserve: { input: 2000, output: 1000, costMicros: 6000 }, signals: [] },
    reason: 'ready', window: { start: 0, end: 86400000 }, signals: [], user: scope(), scan: scope() };
}
test('import/default are inert; exact current single-summary authorization required', () => {
  assert.equal(modeOf([]), 'inert'); assert.equal(modeOf(['--readonly']), 'readonly');
  assert.equal(modeOf(['--generate-one', AUTH_FLAG]), 'generate-one');
  for (const args of [['--generate-one'], [AUTH_FLAG], ['--generate'], ['--readonly', AUTH_FLAG],
    ['--generate-one', AUTH_FLAG, AUTH_FLAG], ['--generate-one', '--ack-coordinator-paid-go']]) assert.throws(() => modeOf(args));
  assert.equal(INTENT, 'summary-current-explicit-v1'); assert.ok(LIMITS.totalMs + LIMITS.closeMs <= 240000);
});
test('current policy requires exact own scan/model/additive lifetime5M with uncapped request/day', () => {
  assert.equal(currentPolicy(context()), true);
  for (const patch of [{ model: 'gpt-4' }, { lifetimeUserCostMicros: undefined }, { lifetimeUserCostMicros: 5000001 },
    { monetaryLimit: 'capped' }, { requestBudgetMicros: 1 }, { userBudgetMicros: 1 }, { scanBudgetMicros: 1 }]) {
    const c = context(); Object.assign(c.disclosure, patch); assert.equal(currentPolicy(c), false);
  }
  assert.equal(currentPolicy({ ...context(), scanId: '0d724000-0000-4000-8000-000000000001' }), false);
  assert.equal(currentPolicy({ ...context(), enabled: false }), false);
});
test('actual current context and usage schemas load offline; lifetime admission ignores exhausted daily statistics', async () => {
  const [tools, u] = await Promise.all([contracts(), usageContract()]);
  const c = tools.summary.summaryContextSchema.parse(context()), parsed = u.usageSchema.parse(usage());
  assert.equal(u.usageMatchesDisclosure(parsed, c.disclosure), true);
  assert.equal(parsed.user.exhausted, true); assert.equal(summaryAdmission(parsed, c), true);
  assert.equal(summaryAdmission({ ...parsed, reportVersion: 'd'.repeat(64) }, c), false);
});
test('exact SUMMARY reserve, positive server price and lifetime balance required (no chat admission substitution)', () => {
  for (const change of [u => { u.admission.status = 'unavailable'; }, u => { u.admission.status = 'insufficient'; },
    u => { u.admission.reserve.costMicros++; }, u => { u.lifetimeBudget.remainingMicros = 5999; },
    u => { u.lifetimeBudget.limitMicros++; }, u => { u.monetaryLimit = 'capped'; },
    u => { u.admission.signals.push({ reason: 'insufficient' }); }, u => { u.reason = 'policy_fault'; },
    u => { u.integrationEnabled = false; }]) {
    const u = usage(); change(u); assert.equal(summaryAdmission(u, context()), false);
  }
  const c = context(); c.disclosure.estimatedPrice.input = 0; assert.equal(summaryAdmission(usage(), c), false);
  const u = usage(); u.admission.reserve.input = 2001; u.admission.reserve.costMicros = 6001;
  assert.equal(summaryAdmission(u, context()), true); // One total BigInt ceiling, no floating rounding.
});
test('current usage parser rejects fabricated fits/incorrect balances, not merely trusting status', async () => {
  const t = await usageContract();
  const u = usage(); u.lifetimeBudget.remainingMicros--;
  assert.equal(t.usageSchema.safeParse(u).success, false);
  const v = usage(); v.lifetimeBudget.usedMicros = CAP - 1; v.lifetimeBudget.remainingMicros = 1;
  assert.equal(t.usageSchema.safeParse(v).success, false);
});
test('allowlist confines all reads to own normal UI and report metadata; translations/unrelated reads forbidden', () => {
  for (const path of ['/account', `/scans/${SCAN}`, '/api/v1/auth/me', BASE,
    BASE + '/llm/context', BASE + '/llm/usage', BASE + '/llm/readiness', BASE + '/llm/history', BASE + '/llm/summary',
    BASE + '/vuln?cursor=400&limit=50']) assert.equal(allowedSummaryRead(ORIGIN + path), true, path);
  for (const url of ['https://api.openai.com/v1/chat/completions', ORIGIN + '/api/v1/browser/scans',
    ORIGIN + '/api/v1/auth/login', ORIGIN + '/api/v1/browser/scans/0d724000-0000-4000-8000-000000000001',
    ORIGIN + BASE + '/llm/translation/context?findingId=vuln-' + 'a'.repeat(64) + '&assessmentIndex=0',
    ORIGIN + BASE + '/llm/summary?retry=1', 'http://u:p@127.0.0.1:8081/account']) assert.equal(allowedSummaryRead(url), false, url);
});
test('read-only gate never arms or dispatches even with current policy', async () => {
  let writes = 0; const g = new SummaryGate('readonly', async () => { writes++; });
  assert.throws(() => g.armCurrent(context())); assert.equal(await g.consume(BASE + '/llm/summary', body()), false);
  assert.equal(writes, 0);
});
test('generation gate rejects automatic send before deliberate current CTA, then permits exactly one', async () => {
  let writes = 0; const automatic = new SummaryGate('generate-one', async () => { writes++; });
  assert.equal(await automatic.consume(BASE + '/llm/summary', body()), false); assert.equal(writes, 0);
  assert.throws(() => automatic.armCurrent(context()));
  const g = new SummaryGate('generate-one', async () => { writes++; }); g.armCurrent(context()); assert.equal(await g.consume(BASE + '/llm/summary', body()), 'summary');
  assert.equal(writes, 1); assert.equal(await g.consume(BASE + '/llm/summary', body()), false);
  assert.throws(() => g.armCurrent(context()));
});
test('wrong/old/free consent or extra body fields terminate permit; no corrected send/rearm', async () => {
  for (const patch of [{ consent: { accepted: false, policyVersion: context().policyVersion } },
    { consent: { accepted: true, policyVersion: 'd'.repeat(64) } }, { legacyFreeConsent: true }, { question: 'never chat' },
    { consent: { ...body().consent, extra: true } }, { reportVersion: 'd'.repeat(64) }]) {
    let writes = 0; const g = new SummaryGate('generate-one', async () => { writes++; }); g.armCurrent(context());
    assert.equal(await g.consume(BASE + '/llm/summary', { ...body(), ...patch }), false);
    assert.equal(await g.consume(BASE + '/llm/summary', body()), false); assert.equal(writes, 0);
    assert.throws(() => g.armCurrent(context()));
  }
});
test('chat/translation/new scan/auth mutations never consume permit; stale arm fails closed', async () => {
  for (const path of [BASE + '/llm/chat', BASE + '/llm/translation', '/api/v1/browser/scans', '/api/v1/auth/login']) {
    const g = new SummaryGate('generate-one', async () => assert.fail('must not persist dispatch')); g.armCurrent(context());
    assert.equal(await g.consume(path, body()), false); assert.equal(await g.consume(BASE + '/llm/summary', body()), false);
  }
  let now = 1; const g = new SummaryGate('generate-one', async () => assert.fail('expired'), () => now);
  g.armCurrent(context()); now += LIMITS.armMs + 1; assert.equal(await g.consume(BASE + '/llm/summary', body()), false);
});
test('spend flush precedes permit return; concurrent repeat cannot dispatch twice', async () => {
  let release, writes = 0; const barrier = new Promise(r => { release = r; });
  const g = new SummaryGate('generate-one', async () => { writes++; await barrier; }); g.armCurrent(context());
  const first = g.consume(BASE + '/llm/summary', body());
  assert.equal(g.state.summary, 1); assert.equal(writes, 1);
  assert.equal(await g.consume(BASE + '/llm/summary', body()), false); release(); assert.equal(await first, 'summary');
  assert.equal(writes, 1); assert.equal(g.halted, true);
});
test('failed durable dispatch flush never allows network and remains consumed', async () => {
  const g = new SummaryGate('generate-one', async () => { throw Error('disk'); }); g.armCurrent(context());
  await assert.rejects(g.consume(BASE + '/llm/summary', body()), /DISPATCH_LEDGER_WRITE_FAILED/);
  assert.equal(g.state.summary, 1); assert.equal(g.halted, true);
  assert.equal(await g.consume(BASE + '/llm/summary', body()), false); assert.throws(() => g.armCurrent(context()));
});
test('new exclusive persistent intent is independent of old spent markers and never overwritten', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'summary-current-offline-'));
  try {
    const old = join(dir, 'old-ledger.json'), marker = join(dir, INTENT + '.authorization-spent.json');
    await exclusiveRecord(old, { summary: 1, chat: 1 }); const before = await readFile(old);
    await exclusiveRecord(marker, { at: 1, status: 'AUTHORIZATION_SPENT_NO_RETRY', hash: 'a'.repeat(64) });
    const spent = await readFile(marker);
    await assert.rejects(exclusiveRecord(marker, { at: 2 }), { code: 'EEXIST' });
    assert.deepEqual(await readFile(old), before); assert.deepEqual(await readFile(marker), spent);
  } finally { await rm(dir, { recursive: true, force: true }); } // Only synthetic temp fixtures, never real ledgers.
});
test('readonly-first proof binds current policy/report/history/summary and expires', () => {
  const hash = proofHash(context(), { turns: [] }, null), proof = { at: 100, status: 'READONLY_READY_MISSING', hash };
  assert.equal(freshProof(proof, 101), true); assert.equal(freshProof(proof, 99), false);
  assert.equal(freshProof(proof, 100 + LIMITS.proofMs + 1), false);
  assert.equal(freshProof({ ...proof, status: 'READONLY_EXISTING_VERIFIED' }, 101), false);
  assert.notEqual(hash, proofHash({ ...context(), policyVersion: 'd'.repeat(64) }, { turns: [] }, null));
  assert.notEqual(hash, proofHash(context(), { turns: [{ state: 'failed' }] }, null));
  assert.notEqual(hash, proofHash(context(), { turns: [] }, 'a'.repeat(64)));
});
test('summary failures preserve finite outer phase/reason and provider status/code/param, never bodies/secrets', async () => {
  const diagnostic = await diagnosticContracts(), snapshots = [], secret = 'PRIVATE_SENTINEL';
  const headers = { 'x-llm-failure-phase': 'headers', 'x-llm-failure-reason': 'http_error',
    'x-llm-provider-status': '429', 'x-llm-provider-error-code': 'rate_limit_exceeded', 'x-llm-provider-error-param': 'messages' };
  const response = { status: () => 502, headerValue: async name => {
    assert.notEqual(name, 'set-cookie'); return name === 'content-type' ? 'application/json' : headers[name] ?? null;
  }, text: async () => JSON.stringify({ errorCode: 'LLM_INVALID_RESPONSE', message: secret, source: secret }) };
  await captureResponseDiagnostics(response, diagnostic, async v => { snapshots.push(v); });
  assert.equal(snapshots[0].bodyInspection, 'not-read'); const last = snapshots.at(-1);
  assert.equal(last.headers['X-LLM-Failure-Phase'], 'headers'); assert.equal(last.headers['X-LLM-Failure-Reason'], 'http_error');
  assert.equal(last.headers['X-LLM-Provider-Status'], '429'); assert.equal(last.headers['X-LLM-Provider-Error-Code'], 'rate_limit_exceeded');
  assert.equal(last.headers['X-LLM-Provider-Error-Param'], 'messages'); assert.equal(last.applicationFailure.errorCode, 'LLM_INVALID_RESPONSE');
  assert.equal(JSON.stringify(snapshots).includes(secret), false);
});
test('paid UI disclosure is expanded and requires lifetime additive terms, not old unlimited text', async () => {
  const text = `${MODEL} $5 на аккаунт за всё время это не бесплатный режим без сброса со сменой суток Денежные лимиты запроса и суток не установлены ZDR не подтверждён`;
  async function verify(value) {
    let expanded = false;
    const panel = { getByLabel: (name, options) => {
      assert.equal(name, 'Условия OpenAI'); assert.deepEqual(options, { exact: true });
      return { waitFor: async () => {}, locator: () => ({ getAttribute: async () => null,
        locator: () => ({ click: async () => { expanded = true; } }) }),
        innerText: async () => { assert.equal(expanded, true); return value; } };
    } };
    await paidDisclosureUi(panel);
  }
  await verify(text);
  await assert.rejects(verify(text.replace('$5 на аккаунт за всё время', 'без локального денежного лимита')));
  await assert.rejects(verify(text.replace('ZDR не подтверждён', 'ZDR гарантирован')));
});
test('success diagnostic evidence excludes generated prose, sources and identity', async () => {
  const diagnostic = await diagnosticContracts(), snapshots = [], secret = 'PRIVATE_SENTINEL';
  await captureResponseDiagnostics({ status: () => 200, headerValue: async n => n === 'content-type' ? 'application/json' : null,
    text: async () => JSON.stringify({ hypotheses: [{ text: secret }], email: secret, cookie: secret }) }, diagnostic, async v => { snapshots.push(v); });
  assert.equal(JSON.stringify(snapshots).includes(secret), false);
  assert.equal(fingerprint({ a: 1, b: 2 }), fingerprint({ b: 2, a: 1 }));
});
