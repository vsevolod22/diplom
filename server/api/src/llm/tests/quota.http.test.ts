import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NestFactory } from '@nestjs/core';
import { HttpException } from '@nestjs/common';
import { AppModule } from '../../app.module.js';
import { LedgerStore } from '../../ledger/ledger-store.js';
import { LlmRuntime } from '../llm.service.js';
import { LlmQuotaRuntime } from '../quota-runtime.js';
import { FixtureQuotaLedger as QuotaLedger } from './quota-fixtures.js';
import { quotaUnavailable, usageObservation } from '../quota-policy.js';
import { prepareSummary } from '../prepared-request.js';
import { productionProvider } from '../openrouter-provider.js';
import { policyFromEnvironment } from '../policy.js';
import { fixtureEnv, fakeKey, digest, reply, fixtureReport } from './fixtures.js';
import { quotaPolicy } from './quota-fixtures.js';

const freePolicy = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'apodex/apodex-1.1-mini:free',
  LLM_PROVIDER_ALLOWLIST: 'novita/bf16', LLM_RETENTION: 'no-storage', LLM_REQUEST_BUDGET_USD: '0',
  LLM_INPUT_PRICE_PER_MILLION_USD: '0', LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' })!;

test('immutable wire +1024/current ceiling; independent bounded usage known floors and malformed dimensions', () => {
  const prepared = prepareSummary({ ...fixtureReport, omittedEvidence: fixtureReport.omittedEvidence }, freePolicy);
  assert.equal(prepared.reserve.input, Buffer.byteLength(prepared.body) + 1024);
  assert.equal(prepared.reserve.output, 256); assert.equal(JSON.parse(prepared.body).max_tokens, 256);
  assert.equal(prepared.reserve.costMicros, 0); assert.ok(Object.isFrozen(prepared));
  const normal = usageObservation({ prompt_tokens: 500, completion_tokens: 32, cost: 0 }, prepared.reserve, quotaPolicy);
  assert.equal(normal.normal, true);
  for (const patch of [{ cost: undefined }, { cost: NaN }, { prompt_tokens: '500' }, { prompt_tokens: -1 },
    { completion_tokens: 1.2 }, { completion_tokens: Infinity }, { total_tokens: 99 }])
    assert.equal(usageObservation({ prompt_tokens: 500, completion_tokens: 32, cost: 0, ...patch }, prepared.reserve, quotaPolicy).normal, false);
  const overage = usageObservation({ prompt_tokens: 500, completion_tokens: 300, cost: 0.0001 }, prepared.reserve, quotaPolicy);
  assert.equal(overage.normal, false); assert.equal(overage.output, 300); assert.equal(overage.costMicros, 100);
});

test('actual Nest owner usage GET, no context mutation, precall quota and publication-independent real adapter receipt', { timeout: 20000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'quota-http-'));
  const names = ['AUTH_DB_PATH', 'SCAN_LEDGER_PATH', 'AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP', 'SCAN_BROWSER_ALLOWED_USER_IDS', 'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'];
  const prior = names.map(name => process.env[name]);
  const origin = 'http://127.0.0.1:8080';
  process.env.AUTH_DB_PATH = join(dir, 'auth.sqlite'); process.env.SCAN_LEDGER_PATH = join(dir, 'ledger.sqlite');
  process.env.AUTH_ORIGIN = origin; process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true'; process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS = 'true';
  const app = await NestFactory.create(AppModule, { logger: false });
  let quota = new QuotaLedger(join(dir, 'llm-usage.sqlite'), { ...quotaPolicy, scan: { ...quotaPolicy.scan, output: 256 } });
  const runtime = app.get(LlmRuntime); const quotas = app.get(LlmQuotaRuntime);
  runtime.policy = () => freePolicy; quotas.ledger = () => quota;
  let calls = 0, providerReads = 0, invalidContent = false, stale = false, completion = 32;
  const scans = app.get(LedgerStore).ledger!;
  runtime.provider = () => { providerReads++; return productionProvider({ OPENROUTER_API_KEY: fakeKey }, (async (_url, init) => {
    calls++;
    const wire = JSON.parse(String(init?.body)); const report = JSON.parse(wire.messages[1].content);
    if (stale) runtime.policy = () => null;
    const content = invalidContent ? { ...reply(report), hypotheses: [{ text: 'CANARY-provider', citations: ['foreign'] }] } : reply(report);
    return new Response(JSON.stringify({ model: freePolicy.model, usage: { prompt_tokens: 500, completion_tokens: completion, cost: 0 },
      choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: JSON.stringify(content) } }] }), { headers: { 'content-type': 'application/json' } });
  }) as typeof fetch); };
  try {
    await app.listen(0, '127.0.0.1');
    const base = `http://127.0.0.1:${app.getHttpServer().address().port}/api/v1`;
    const register = async (email: string) => {
      const r = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' }, body: JSON.stringify({ email, password: 'temporary-test-password-1234' }) });
      assert.equal(r.status, 201); return { cookie: r.headers.get('set-cookie')!.split(';')[0], id: (await r.json() as { id: string }).id };
    };
    const owner = await register('quota-owner@example.com'), other = await register('quota-other@example.com');
    const scan = (key: string) => {
      const id = scans.enqueue({ subject: owner.id, idempotencyKey: key, registry: 'registry-1.docker.io', repository: 'library/alpine', digest: digest as `sha256:${string}`, platform: 'linux/amd64', scope: 'image', checks: '["secret"]' }).scanId;
      const job = scans.claim()!;
      assert.equal(scans.finishCombined(id, job.attempts, [{ check: 'secret', outcome: 'checked', scannerVersion: '0.69.3', findings: [{ findingId: 'secret-0-1', ruleId: 'rule-0123456789abcdef', line: 1, evidenceRef: 'result-0-secret-1' }] }]), true);
      return id;
    };
    const id = scan('normal');
    const url = (scanId: string, endpoint: string) => `${base}/browser/scans/${scanId}/llm/${endpoint}`;
    const get = (scanId: string, endpoint: string, cookie = owner.cookie) => fetch(url(scanId, endpoint), { headers: { cookie } });
    const context = async (scanId: string) => (await get(scanId, 'context')).json() as Promise<{ reportVersion: string; policyVersion: string }>;
    const generate = async (scanId: string, extra = {}) => { const c = await context(scanId); return fetch(url(scanId, 'summary'), { method: 'POST', headers: { cookie: owner.cookie, origin, 'content-type': 'application/json' }, body: JSON.stringify({ reportVersion: c.reportVersion, consent: { accepted: true, policyVersion: c.policyVersion }, ...extra }) }); };
    const before = await context(id);
    const usage = await get(id, 'usage'); assert.equal(usage.status, 200); assert.equal(usage.headers.get('cache-control'), 'no-store');
    assert.equal(calls, 0); assert.equal(providerReads, 0);
        const firstUsage = await usage.json() as { available: boolean; admission: { status: string; reserve: { output: number } } };
        assert.equal(firstUsage.available, true); assert.equal(firstUsage.admission.status, 'fits'); assert.equal(firstUsage.admission.reserve.output, 256);
        runtime.policy = () => ({ ...freePolicy, findings: 0 });
        const unknown = await (await get(id, 'usage')).json() as { available: boolean; admission: unknown };
        assert.equal(unknown.available, true); assert.deepEqual(unknown.admission, { status: 'unavailable' });
        assert.equal(providerReads, 0); runtime.policy = () => freePolicy;
    assert.equal((await fetch(url(id, 'usage'))).status, 401);
    const foreign = await get(id, 'usage', other.cookie), missing = await get('00000000-0000-4000-8000-000000000000', 'usage', other.cookie);
    assert.equal(foreign.status, 404); assert.equal(missing.status, 404); assert.equal(await foreign.text(), await missing.text());
    assert.equal((await generate(id, { usage: { input: 0 } })).status, 400); assert.equal(calls, 0);
    quotas.ledger = () => { throw quotaUnavailable(); };
    assert.equal((await generate(id)).status, 503); assert.equal(calls, 0);
    const unavailable = await get(id, 'usage'); assert.equal((await unavailable.json() as { available: boolean }).available, false);
    quotas.ledger = () => quota;
    assert.equal((await generate(id)).status, 200); assert.equal(calls, 1);
    assert.deepEqual(await context(id), before); // mutable usage never enters consent contextFence
    assert.equal(quota.snapshot(owner.id, id).scan.used.output, 32);
    const denied = await generate(id); assert.equal(denied.status, 429); assert.equal(calls, 1);
        assert.equal(denied.headers.get('cache-control'), 'no-store');
        const refusal = await denied.json() as { admission: { signals: unknown[] } };
        assert.deepEqual(refusal.admission.signals, [{ scope: 'scan', dimension: 'output', reason: 'insufficient', required: 256, remaining: 224 }]);
        const ownerView = await (await get(id, 'usage')).json() as { admission: unknown };
        assert.deepEqual(ownerView.admission, refusal.admission);
    invalidContent = true;
    const invalid = scan('bad-content'); assert.equal((await generate(invalid)).status, 502);
    assert.equal(quota.snapshot(owner.id, invalid).scan.used.output, 32);
    invalidContent = false; stale = true;
    const changed = scan('stale'); assert.equal((await generate(changed)).status, 409);
    assert.equal(quota.snapshot(owner.id, changed).scan.used.input, 500);
    const disabled = await get(changed, 'usage'); assert.equal(disabled.status, 200);
    assert.deepEqual((await disabled.json() as { integrationEnabled: boolean; admission: unknown }).admission, { status: 'unavailable' });
        // Exact reviewed baseline: positive headroom below 80% still cannot fit 2048.
        stale = false; completion = 1575;
        const fullPolicy = { ...freePolicy, outputTokens: 2048 };
        runtime.policy = () => fullPolicy;
        quota.close(); quota = new QuotaLedger(join(dir, 'llm-usage.sqlite'), quotaPolicy);
        const baseline = scan('envelope-baseline'); const baselineContext = await context(baseline);
        for (let i = 0; i < 4; i++) assert.equal((await generate(baseline)).status, 200);
        const beforeDenial = quota.snapshot(owner.id, baseline);
        assert.equal(beforeDenial.scan.used.output, 6300); assert.equal(beforeDenial.scan.remaining.output, 1892);
        assert.equal(beforeDenial.reason, 'ready');
        const callsBefore = calls;
        const blocked = await generate(baseline); assert.equal(blocked.status, 429);
        const expected = { scope: 'scan', dimension: 'output', reason: 'insufficient', required: 2048, remaining: 1892 };
        const body = await blocked.json() as { errorCode: string; admission: { status: string; reserve: { input: number }; signals: unknown[] } };
        assert.equal(body.errorCode, 'LLM_QUOTA_EXCEEDED'); assert.equal(body.admission.status, 'insufficient');
        assert.deepEqual(body.admission.signals, [expected]); assert.equal(calls, callsBefore);
        assert.deepEqual(quota.snapshot(owner.id, baseline), beforeDenial);
        const readsBefore = providerReads;
        const snapshot = await (await get(baseline, 'usage')).json() as { admission: unknown };
        assert.deepEqual(snapshot.admission, body.admission); assert.equal(calls, callsBefore); assert.equal(providerReads, readsBefore);
        assert.deepEqual(quota.snapshot(owner.id, baseline), beforeDenial);
        assert.deepEqual(await context(baseline), baselineContext);
        // Only branded refusal metadata survives the filter, not an arbitrary exception.
        const reserve = quota.reserve.bind(quota);
        quota.reserve = () => { throw new HttpException({ errorCode: 'LLM_QUOTA_EXCEEDED',
          admission: { status: 'insufficient', signals: [{ scope: 'CANARY-secret' }] }, raw: '/auth/private' }, 429); };
        const spoof = await generate(baseline); assert.equal(spoof.status, 429);
        assert.deepEqual(await spoof.json(), { errorCode: 'LLM_QUOTA_EXCEEDED' });
        quota.reserve = reserve;
        // Actual HTTP redaction also delivers user+scan input shortage from one atomic check.
        quota.close(); quota = new QuotaLedger(join(dir, 'llm-usage.sqlite'), { ...quotaPolicy,
          user: { ...quotaPolicy.user, input: beforeDenial.user.used.input + body.admission.reserve.input - 1 },
          scan: { ...quotaPolicy.scan, input: beforeDenial.scan.used.input + body.admission.reserve.input - 1, output: 16384 } });
        const inputBlocked = await generate(baseline); assert.equal(inputBlocked.status, 429);
        const inputBody = await inputBlocked.json() as { admission: { signals: Array<{ scope: string; dimension: string }> } };
        assert.deepEqual(inputBody.admission.signals.map(s => [s.scope, s.dimension]), [['user', 'input'], ['scan', 'input']]);
        assert.equal(calls, callsBefore); assert.equal(quota.snapshot(owner.id, baseline).user.held.input, 0);
        assert.deepEqual(await context(baseline), baselineContext);
    assert.doesNotMatch(readFileSync(join(dir, 'llm-usage.sqlite')).toString(), /CANARY|temporary-test-password|sk-or-|hypotheses|demo_session/);
  } finally {
    quota.close(); await app.close(); rmSync(dir, { recursive: true, force: true });
    names.forEach((name, index) => { if (prior[index] === undefined) delete process.env[name]; else process.env[name] = prior[index]; });
  }
});
