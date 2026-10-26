import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NestFactory } from '@nestjs/core';
import Database from 'better-sqlite3';
import { AppModule } from '../../app.module.js';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { AuthStore } from '../../auth/auth.store.js';
import { LedgerStore } from '../../ledger/ledger-store.js';
import { PublicImageModule, configurePublicImageIngress } from '../../oci/public-image.module.js';
import { ScansService } from '../../scans/scans.service.js';
import { publicVulnerabilityFixture } from '../../scans/public-vulnerability.fixture.js';
import { CURRENT_DB_POLICY } from '../../worker/cve-db-policy.mjs';
import { LlmRuntime, LlmService } from '../llm.service.js';
import { OpenRouterProvider } from '../openrouter-provider.js';
import { policyFromEnvironment, type LlmPolicy } from '../policy.js';
import { LlmQuotaRuntime } from '../quota-runtime.js';
import { SUMMARY_CACHE, SummaryResultCache } from '../summary-result-cache.js';
import { fakeKey, fixtureEnv } from './fixtures.js';
import { FixtureQuotaLedger, quotaPolicy } from './quota-fixtures.js';

const policy = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'xingchen-agi/xing4.0-29b-a4b:free',
  LLM_PROVIDER_ALLOWLIST: 'phala', LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0',
  LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' })!;

test('public summary POST retains only guarded validated results; passive owner GET survives reload/login, never restart', { timeout: 60000 }, async t => {
  const directory = mkdtempSync(join(tmpdir(), 'summary-result-')), origin = 'http://127.0.0.1:8081';
  const env = { AUTH_DB_PATH: join(directory, 'auth.sqlite'), SCAN_LEDGER_PATH: join(directory, 'ledger.sqlite'), AUTH_ORIGIN: origin,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true', SCAN_BROWSER_ALLOWED_USER_IDS: '' };
  const previous = Object.keys(env).map(key => process.env[key]); Object.assign(process.env, env);
  const quota = new FixtureQuotaLedger(join(directory, 'llm-usage.sqlite'), { ...quotaPolicy,
    user: { input: 1000000, output: 100000, costMicros: 0 }, scan: { input: 1000000, output: 100000, costMicros: 0 } });
  let app: NestExpressApplication | undefined, base = '', sends = 0, factories = 0, invalid = false, rateLimited = false;
  let currentPolicy: LlmPolicy | null = policy;
  const start = async () => {
    app = await NestFactory.create<NestExpressApplication>(PublicImageModule, { logger: false, bodyParser: false });
    configurePublicImageIngress(app);
    const runtime = app.get(LlmRuntime);
    runtime.policy = () => currentPolicy;
    runtime.provider = () => { factories++; return new OpenRouterProvider(fakeKey, (async (_url, init) => {
      sends++;
      if (rateLimited) return new Response('private-provider-body', { status: 429 });
      const report = JSON.parse(JSON.parse(String(init!.body)).messages[1].content);
      const value = { scanId: report.scanId, digest: report.digest, platform: report.platform, reportVersion: report.reportVersion,
        hypotheses: [{ text: invalid ? 'CANARY-private' : 'Сканер сообщил о находке; эксплуатация не установлена.', citations: [report.findings[0].findingId] }] };
      return new Response(JSON.stringify({ model: policy.model, usage: { prompt_tokens: 500, completion_tokens: 32, cost: 0 },
        choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: JSON.stringify(value) } }] }),
      { headers: { 'content-type': 'application/json' } });
    }) as typeof fetch); };
    app.get(LlmQuotaRuntime).ledger = () => quota;
    await app.listen(0, '127.0.0.1');
    base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
  };
  try {
    await start();
    const credentials = (name: string) => ({ email: `${name}@example.invalid`, password: 'summary-fixture-only-1234' });
    const register = async (name: string) => {
      const response = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify(credentials(name)) });
      assert.equal(response.status, 201);
      return { id: (await response.json() as { id: string }).id, cookie: response.headers.get('set-cookie')!.split(';')[0] };
    };
    const owner = await register('owner'), other = await register('other');
    let cookie = owner.cookie;
    const renew = () => { cookie = `demo_session=${app!.get(AuthStore).createSession(owner.id)}`; };
    const seed = (key: string, subject = owner.id) => {
      const report = publicVulnerabilityFixture();
      if (report.vuln?.outcome === 'checked') report.vuln.findings = report.vuln.findings.slice(0, 1);
      const ledger = app!.get(LedgerStore).ledger!;
      const id = ledger.enqueue({ ...report.receipt, subject, idempotencyKey: key, scope: 'image', checks: '["sbom","vuln"]', cvePolicy: CURRENT_DB_POLICY }).scanId;
      const job = ledger.claim()!;
      assert.equal(ledger.finishArchive(id, job.attempts, report, undefined, job.leaseToken), true);
      return id;
    };
    const id = seed('initial'), foreign = seed('foreign', other.id), missing = seed('missing');
    const path = (scanId: string) => `${base}/browser/scans/${scanId}/llm`;
    const get = (scanId = id, token = cookie) => fetch(`${path(scanId)}/summary`, { headers: { cookie: token } });
    const post = async (scanId = id) => {
      const context = await (await fetch(`${path(scanId)}/context`, { headers: { cookie } })).json();
      return fetch(`${path(scanId)}/summary`, { method: 'POST', headers: { cookie, origin, 'content-type': 'application/json' },
        body: JSON.stringify({ reportVersion: context.reportVersion, consent: { accepted: true, policyVersion: context.policyVersion } }) });
    };
    const assertMissing = async (scanId = id) => {
      const response = await get(scanId); assert.equal(response.status, 404);
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.deepEqual(await response.json(), { errorCode: 'LLM_SUMMARY_MISSING' });
    };
    const assertCached = async (scanId: string, value: unknown) => {
      const response = await get(scanId); assert.equal(response.status, 200, await response.clone().text());
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.equal(response.headers.get('x-llm-summary-retention'), 'process-lifetime');
      assert.deepEqual(await response.json(), value);
    };

    await t.test('explicit missing, validated enriched POST contract, browser reload and fresh-login retrieval', async () => {
      await assertMissing(missing);
      assert.equal((await fetch(`${path(id)}/summary`)).status, 401);
      const response = await post(); assert.equal(response.status, 200, await response.clone().text());
      const value = await response.json();
      assert.equal(response.headers.get('x-llm-summary-retention'), 'process-lifetime');
      assert.ok(value.scannerFacts.length); assert.ok(value.contextSelection); assert.equal(value.findingCount, 1);
      assert.equal(value.hypotheses[0].kind, 'hypothesis');
      const before = sends;
      await assertCached(id, value); await assertCached(id, value);
      const login = await fetch(`${base}/auth/login`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify(credentials('owner')) });
      assert.equal(login.status, 200); cookie = login.headers.get('set-cookie')!.split(';')[0];
      assert.notEqual(cookie, owner.cookie); await assertCached(id, value); assert.equal(sends, before);
    });

    await t.test('GET never touches provider/key metadata/quota/history; foreign404 precedes cache and policy', async () => {
      const runtime = app!.get(LlmRuntime), quotas = app!.get(LlmQuotaRuntime), llm = app!.get(LlmService);
      const provider = runtime.provider, credential = runtime.credentialStatus, ledger = quotas.ledger, history = llm.history;
      const before = quota.snapshot(owner.id, id), beforeSends = sends, beforeFactories = factories;
      let forbidden = 0;
      const denied = (): never => { forbidden++; throw new Error('private-unreachable'); };
      runtime.provider = denied; runtime.credentialStatus = denied; quotas.ledger = denied; llm.history = denied;
      const lookup = t.mock.method(SummaryResultCache.prototype, 'get');
      try {
        assert.equal((await get()).status, 200); await assertMissing(missing);
        const count = lookup.mock.callCount();
        runtime.policy = denied;
        for (const [scanId, token] of [[id, other.cookie], [foreign, cookie]]) {
          const response = await get(scanId, token); assert.equal(response.status, 404);
          assert.equal(response.headers.get('cache-control'), 'no-store');
          assert.deepEqual(await response.json(), { errorCode: 'SCAN_NOT_FOUND' });
        }
        assert.equal(lookup.mock.callCount(), count);
        assert.equal(forbidden, 0); assert.equal(sends, beforeSends); assert.equal(factories, beforeFactories);
        assert.deepEqual(quota.snapshot(owner.id, id), before);
      } finally {
        lookup.mock.restore(); runtime.policy = () => currentPolicy;
        runtime.provider = provider; runtime.credentialStatus = credential; quotas.ledger = ledger; llm.history = history;
      }
    });

    await t.test('public-only read and synchronous final publication fences do not initialize generation or permit competing writers', async () => {
      const llm = app!.get(LlmService), read = llm.readSummary.bind(llm);
      llm.readSummary = (...args) => {
        const result = read(...args);
        return { value: result.value, write: action => result.write(() => {
          for (const path of [env.AUTH_DB_PATH, env.SCAN_LEDGER_PATH]) {
            const db = new Database(path, { fileMustExist: true, timeout: 0 });
            try { assert.throws(() => db.exec('BEGIN IMMEDIATE'), error => error instanceof Error && 'code' in error && error.code === 'SQLITE_BUSY'); }
            finally { db.close(); }
          }
          action();
        }) };
      };
      try { assert.equal((await get()).status, 200); } finally { llm.readSummary = read; }
      const legacy = await NestFactory.create<NestExpressApplication>(AppModule, { logger: false });
      try {
        legacy.get(LlmRuntime).provider = () => assert.fail('legacy GET cannot construct a provider');
        legacy.get(LlmQuotaRuntime).ledger = () => assert.fail('legacy GET cannot construct a quota ledger');
        await legacy.listen(0, '127.0.0.1');
        const port = (legacy.getHttpServer().address() as { port: number }).port;
        const response = await fetch(`http://127.0.0.1:${port}/api/v1/browser/scans/${id}/llm/summary`, { headers: { cookie } });
        assert.equal(response.status, 404); assert.equal(response.headers.get('cache-control'), 'no-store');
        assert.deepEqual(await response.json(), { errorCode: 'SCAN_NOT_FOUND' });
      } finally { await legacy.close(); }
    });

    await t.test('current policy/report and disabled policy produce missing, never stale cached results', async () => {
      currentPolicy = { ...policy, version: 'e'.repeat(64) }; await assertMissing();
      currentPolicy = policy; await assertMissing();
      assert.equal((await post()).status, 200);
      const scans = app!.get(ScansService), status = scans.status.bind(scans);
      scans.status = (...args) => ({ ...status(...args), summaryTestRevision: 1 });
      try { await assertMissing(); } finally { scans.status = status; }
      await assertMissing(); assert.equal((await post()).status, 200);
      currentPolicy = null; await assertMissing(); currentPolicy = policy; await assertMissing();
    });

    await t.test('unsafe failed POST is charged but never retained; successful result is not replaced by a failure', async () => {
      const scanId = seed('unsafe'), used = quota.snapshot(owner.id, scanId).scan.used.input;
      invalid = true;
      try { const response = await post(scanId); assert.equal(response.status, 502); assert.doesNotMatch(await response.text(), /CANARY/); }
      finally { invalid = false; }
      assert.equal(quota.snapshot(owner.id, scanId).scan.used.input, used + 500); await assertMissing(scanId);
      const response = await post(scanId); assert.equal(response.status, 200); const value = await response.json();
      invalid = true;
      try { assert.equal((await post(scanId)).status, 502); } finally { invalid = false; }
      await assertCached(scanId, value);
    });

    await t.test('GET final actual HTTP publication rechecks policy, report and session', async () => {
      assert.equal((await post()).status, 200);
      const llm = app!.get(LlmService), read = llm.readSummary.bind(llm);
      const scans = app!.get(ScansService), status = scans.status.bind(scans);
      for (const reason of ['policy', 'report', 'session']) {
        llm.readSummary = (...args) => {
          const result = read(...args);
          if (reason === 'policy') currentPolicy = { ...policy, version: 'e'.repeat(64) };
          if (reason === 'report') scans.status = (...input) => ({ ...status(...input), summaryTestRevision: 2 });
          if (reason === 'session') app!.get(AuthStore).revoke(cookie.slice('demo_session='.length));
          return result;
        };
        try {
          const response = await get(); assert.equal(response.status, reason === 'session' ? 503 : 409);
          assert.equal(response.headers.get('cache-control'), 'no-store'); assert.doesNotMatch(await response.text(), /hypotheses|scannerFacts|Сканер/);
        } finally { llm.readSummary = read; currentPolicy = policy; scans.status = status; if (reason === 'session') renew(); }
      }
    });

    await t.test('POST final write rechecks policy/report/session/abort before retention; dispatched usage remains charged', async () => {
      const llm = app!.get(LlmService), generate = llm.summaryForBrowser.bind(llm);
      const scans = app!.get(ScansService), status = scans.status.bind(scans);
      for (const reason of ['policy', 'report', 'session', 'abort']) {
        const scanId = seed(`post-${reason}`), used = quota.snapshot(owner.id, scanId).scan.used.input;
        llm.summaryForBrowser = async (...args) => {
          const controller = new AbortController();
          const result = await generate(args[0], args[1], args[2], reason === 'abort' ? controller.signal : args[3]);
          if (reason === 'policy') currentPolicy = { ...policy, version: 'e'.repeat(64) };
          if (reason === 'report') scans.status = (...input) => ({ ...status(...input), summaryTestRevision: 3 });
          if (reason === 'session') app!.get(AuthStore).revoke(cookie.slice('demo_session='.length));
          if (reason === 'abort') controller.abort();
          return result;
        };
        try {
          const response = await post(scanId); assert.equal(response.status, reason === 'session' ? 503 : 409);
          assert.equal(response.headers.get('cache-control'), 'no-store'); assert.doesNotMatch(await response.text(), /hypotheses|scannerFacts|Сканер/);
        } finally { llm.summaryForBrowser = generate; currentPolicy = policy; scans.status = status; if (reason === 'session') renew(); }
        assert.equal(quota.snapshot(owner.id, scanId).scan.used.input, used + 500); await assertMissing(scanId);
      }
    });

    await t.test('HTTP capacity eviction is bounded to64 retained results; fresh service instance/restart is explicitly missing', async () => {
      const scans = [];
      for (let n = 0; n < SUMMARY_CACHE.entries; n++) {
        const scanId = seed(`eviction-${n}`); scans.push(scanId);
        const response = await post(scanId); assert.equal(response.status, 200, await response.clone().text());
      }
      assert.equal((await get(scans[0])).status, 200);
      const last = seed('eviction-last'); assert.equal((await post(last)).status, 200);
      await assertMissing(scans[1]); assert.equal((await get(scans[0])).status, 200); assert.equal((await get(last)).status, 200);
      const beforeSends = sends, beforeFactories = factories;
      await app!.close(); app = undefined; await start();
      await assertMissing(last); assert.equal(sends, beforeSends); assert.equal(factories, beforeFactories);
    });

    await t.test('provider429 is not retained or retried; passive miss leaves dispatched unknown liability untouched', async () => {
      const scanId = seed('provider429'), before = sends;
      rateLimited = true;
      try {
        const response = await post(scanId); assert.equal(response.status, 429);
        assert.equal(response.headers.get('cache-control'), 'no-store'); assert.equal(response.headers.get('retry-after'), null);
        assert.deepEqual(await response.json(), { errorCode: 'LLM_PROVIDER_RATE_LIMITED', providerFailure: { kind: 'rate_limited', status: 429 } });
      } finally { rateLimited = false; }
      assert.equal(sends, before + 1);
      const liability = quota.snapshot(owner.id, scanId); assert.ok(liability.scan.held.input > 0);
      await assertMissing(scanId);
      assert.equal(sends, before + 1); assert.deepEqual(quota.snapshot(owner.id, scanId), liability);
    });
  } finally {
    await app?.close(); quota.close();
    Object.keys(env).forEach((key, index) => { if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index]; });
    rmSync(directory, { recursive: true, force: true });
  }
});
