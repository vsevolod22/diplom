import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, mkdirSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { AppModule } from '../../app.module.js';
import { PublicImageModule, configurePublicImageIngress } from '../../oci/public-image.module.js';
import { LedgerStore } from '../../ledger/ledger-store.js';
import { AuthStore } from '../../auth/auth.store.js';
import { ScansService } from '../../scans/scans.service.js';
import { publicVulnerabilityFixture } from '../../scans/public-vulnerability.fixture.js';
import { CURRENT_DB_POLICY } from '../../worker/cve-db-policy.mjs';
import { normalizeAdvisory, omittedAdvisory } from '../../worker/vuln-advisory.js';
import { LlmRuntime, LlmService } from '../llm.service.js';
import { LlmQuotaRuntime } from '../quota-runtime.js';
import { OpenRouterProvider } from '../openrouter-provider.js';
import type { BodySendGuard, GuardedTransport } from '../openrouter-transport.js';
import { ReportReader } from '../report-context.js';
import { policyFromEnvironment, type LlmPolicy } from '../policy.js';
import { translationPolicy, type TranslationBinding, type TranslationSource } from '../translation-contract.js';
import { FixtureQuotaLedger, quotaPolicy } from './quota-fixtures.js';
import { fixtureEnv, fakeKey } from './fixtures.js';

type Context = TranslationBinding & { source: TranslationSource; targetLanguage: 'ru'; enabled: boolean; policyVersion: string; disclosure: unknown };
const policy = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'xingchen-agi/xing4.0-29b-a4b:free',
  LLM_PROVIDER_ALLOWLIST: 'phala', LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0',
  LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' })!;
function deferred() { let resolve!: () => void; const promise = new Promise<void>(r => { resolve = r; }); return { promise, resolve }; }

test('public translation cookie HTTP + saved report + real adapter with SYNTHETIC guarded transport only (no live provider)', { timeout: 30000 }, async t => {
  const directory = mkdtempSync(join(tmpdir(), 'translation-http-')), origin = 'http://127.0.0.1:8081';
  const env = { AUTH_DB_PATH: join(directory, 'auth.sqlite'), SCAN_LEDGER_PATH: join(directory, 'ledger.sqlite'), AUTH_ORIGIN: origin,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true', SCAN_BROWSER_ALLOWED_USER_IDS: '' };
  const previous = Object.keys(env).map(key => process.env[key]); Object.assign(process.env, env);
  const quota = new FixtureQuotaLedger(join(directory, 'llm-usage.sqlite'), { ...quotaPolicy,
    user: { input: 1000000, output: 100000, costMicros: 0 }, scan: { input: 1000000, output: 100000, costMicros: 0 } });
  let app: NestExpressApplication | undefined;
  try {
    app = await NestFactory.create<NestExpressApplication>(PublicImageModule, { logger: false, bodyParser: false }); configurePublicImageIngress(app);
    const runtime = app.get(LlmRuntime), quotas = app.get(LlmQuotaRuntime), reader = app.get(ReportReader);
    let currentPolicy: LlmPolicy | null = policy;
    runtime.policy = () => currentPolicy; quotas.ledger = () => quota;
    let guardFailure: unknown;
    let sends = 0, factories = 0, lastWire = '', bad = '', beforeSend: ((init: RequestInit) => Promise<void>) | undefined,
      afterSend: (() => Promise<void>) | undefined, insideSend: (() => void) | undefined;
    const synthetic = Object.assign((async () => assert.fail('translation must never use unguarded transport')) as typeof fetch, {
      sendGuarded: async (_url: string, init: RequestInit, guard: BodySendGuard) => {
        await beforeSend?.(init);
        try { guard(() => { insideSend?.(); sends++; lastWire = String(init.body); }); }
        catch (error) { guardFailure = error; throw error; }
        await afterSend?.();
        const wire = JSON.parse(String(init.body)), text = JSON.parse(wire.messages[1].content);
        const ids = String(text.description ?? '').match(/\b(?:CVE|TEMP)-[A-Za-z0-9-]+/g) ?? [];
        const translation: Record<string, unknown> = { title: text.title === null ? null : 'Ошибка обработки памяти',
          description: text.description === null ? null : `Злоумышленник может повредить память${ids.length ? ' в ' + ids.join(', ') : ''}.` };
        if (bad === 'english') translation.title = 'Memory handling flaw';
        if (bad === 'url') translation.title = 'Ошибка https://evil.test/path';
        if (bad === 'identifier') translation.description = 'Ошибка CVE-2026-99999';
        if (bad === 'extra') translation.raw = 'unexpected';
        if (bad === 'null') translation.description = null;
        return new Response(JSON.stringify({ model: bad === 'model' ? 'other/model' : policy.model,
          usage: bad === 'receipt' ? { prompt_tokens: 500, completion_tokens: 32, cost: 1 } : { prompt_tokens: 500, completion_tokens: 32, cost: 0 },
          choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: JSON.stringify(translation) } }] }),
        { headers: { 'content-type': 'application/json' } });
      },
    }) as GuardedTransport;
    runtime.provider = () => { factories++; return new OpenRouterProvider(fakeKey, synthetic); };
    await app.listen(0, '127.0.0.1');
    const base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    const register = async (name: string) => {
      const response = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ email: `${name}@example.invalid`, password: 'disposable-translation-1234' }) });
      assert.equal(response.status, 201);
      return { id: (await response.json() as { id: string }).id, cookie: response.headers.get('set-cookie')!.split(';')[0] };
    };
    const owner = await register('owner'), other = await register('other'), auth = app.get(AuthStore), ledger = app.get(LedgerStore).ledger!;
    let cookie = owner.cookie;
    const renew = () => { cookie = `demo_session=${auth.createSession(owner.id)}`; };
    const seed = (key: string, mode = 'normal') => {
      const report = publicVulnerabilityFixture();
      if (report.vuln?.outcome !== 'checked') throw new Error('fixture');
      report.vuln.findings = [report.vuln.findings[0], report.vuln.findings.at(-1)!];
      for (const finding of report.vuln.findings) {
        finding.advisory = mode === 'omitted' ? omittedAdvisory('report_budget') : normalizeAdvisory({ DataSource: { ID: 'nvd' }, Language: 'en',
          Title: mode === 'missing' ? undefined : mode === 'redacted' ? 'password="private-value" remaining' : 'Memory handling flaw',
          Description: mode === 'missing' || mode === 'redacted' ? undefined : mode === 'partial' ? 'password="private-value" remaining' :
            `An attacker can corrupt memory in ${finding.cveId}.` }, finding.provenanceRef, finding.cveId);
      }
      const id = ledger.enqueue({ ...report.receipt, subject: owner.id, idempotencyKey: key, scope: 'image', checks: '["sbom","vuln"]', cvePolicy: CURRENT_DB_POLICY }).scanId;
      const job = ledger.claim()!; assert.equal(ledger.finishArchive(id, job.attempts, report, undefined, job.leaseToken), true);
      const finding = report.vuln.findings[0], temp = report.vuln.findings[1];
      const index = Math.max(0, finding.advisory!.assessments.findIndex(a => a.title.value !== null || a.description.value !== null || a.source === 'nvd'));
      return { id, finding, temp, index };
    };
    const scan = seed('normal');
    const path = (scanId = scan.id) => `${base}/browser/scans/${scanId}/llm/translation`;
    const contextUrl = (findingId = scan.finding.findingId, index = scan.index, scanId = scan.id) =>
      `${path(scanId)}/context?findingId=${findingId}&assessmentIndex=${index}`;
    const get = (url = contextUrl(), c = cookie) => fetch(url, { headers: { cookie: c } });
    const context = async (url = contextUrl()) => {
      const response = await get(url); assert.equal(response.status, 200, await response.clone().text());
      assert.equal(response.headers.get('cache-control'), 'no-store'); return response.json() as Promise<Context>;
    };
    const request = (c: Context) => ({ reportVersion: c.reportVersion, findingId: c.findingId, assessmentIndex: c.assessmentIndex,
      sourceVersion: c.sourceVersion, targetLanguage: 'ru', consent: { accepted: true, policyVersion: c.policyVersion } });
    const post = (body: unknown, c = cookie, url = path(), headers = {}, signal?: AbortSignal) => fetch(url, { method: 'POST',
      headers: { cookie: c, origin, 'content-type': 'application/json', ...headers }, body: JSON.stringify(body), signal });
    const initial = await context();
    assert.deepEqual(Object.keys(initial).sort(), ['scanId', 'digest', 'platform', 'reportVersion', 'findingId', 'assessmentIndex', 'sourceVersion',
      'source', 'targetLanguage', 'enabled', 'policyVersion', 'disclosure'].sort());
    assert.equal(initial.enabled, true); assert.equal(initial.policyVersion, translationPolicy(policy)); assert.notEqual(initial.policyVersion, policy.version);
    assert.deepEqual(initial.source, { source: 'nvd', provenanceRef: scan.finding.provenanceRef, language: 'en' });
    assert.doesNotMatch(JSON.stringify(initial), /Memory handling|An attacker|packageName|installedVersion/);
    assert.equal(sends, 0); assert.equal(factories, 0);

    await t.test('ownership, exact DTO/query, consent and stale bindings refuse with zero factory/dispatch', async () => {
      assert.equal((await fetch(contextUrl())).status, 401);
      assert.equal((await get(contextUrl(), other.cookie)).status, 404);
      assert.equal((await post(request(initial), other.cookie)).status, 404);
      for (const suffix of ['&extra=x', '&assessmentIndex=0']) assert.equal((await get(contextUrl() + suffix)).status, 400);
      for (const index of ['01', '-1', '16', '0.0']) assert.equal((await get(contextUrl().replace(/assessmentIndex=\d+/, `assessmentIndex=${index}`))).status, 400);
      for (const [patch, status, code] of [
        [{ text: 'client text' }, 400, 'LLM_INVALID_REQUEST'], [{ targetLanguage: 'en' }, 400, 'LLM_INVALID_REQUEST'],
        [{ consent: { accepted: false, policyVersion: initial.policyVersion } }, 403, 'LLM_CONSENT_REQUIRED'],
        [{ reportVersion: 'f'.repeat(64) }, 409, 'LLM_STALE_REPORT'], [{ sourceVersion: 'f'.repeat(64) }, 409, 'LLM_STALE_SOURCE'],
        [{ consent: { accepted: true, policyVersion: policy.version } }, 409, 'LLM_STALE_POLICY'],
      ] as const) {
        const response = await post({ ...request(initial), ...patch }); assert.equal(response.status, status);
        assert.equal((await response.json() as { errorCode: string }).errorCode, code);
      }
      const malformed = await fetch(path(), { method: 'POST', headers: { cookie, origin, 'content-type': 'application/json' }, body: '{"private":"CANARY"' });
      assert.equal(malformed.status, 400); assert.doesNotMatch(await malformed.text(), /CANARY|private/);
      assert.equal((await post({ text: 'я'.repeat(1024) })).status, 413);
      assert.equal((await post(request(initial), cookie, path(), { origin: 'https://evil.invalid' })).status, 403);
      for (const alias of [path() + '/', path() + '?x=1', path() + '/extra']) assert.equal((await post(request(initial), cookie, alias)).status, 400);
      assert.equal((await post(request(initial), cookie, path(), { 'content-encoding': 'gzip' })).status, 400);
      currentPolicy = null; assert.equal((await context()).enabled, false); assert.equal((await post(request(initial))).status, 503); currentPolicy = policy;
      assert.equal(sends, 0); assert.equal(factories, 0);
    });

    await t.test('missing/omitted/redacted text and ineligible fields never egress', async () => {
      for (const mode of ['missing', 'redacted', 'omitted']) {
        const candidate = seed(mode, mode);
        const response = await get(contextUrl(candidate.finding.findingId, candidate.index, candidate.id));
        assert.equal(response.status, 409); assert.equal((await response.json() as { errorCode: string }).errorCode, 'LLM_TRANSLATION_UNAVAILABLE');
      }
      assert.equal(sends, 0);
      const partial = seed('partial', 'partial'), c = await context(contextUrl(partial.finding.findingId, partial.index, partial.id));
      const response = await post(request(c), cookie, path(partial.id)); assert.equal(response.status, 200, await response.clone().text());
      assert.equal((await response.json() as { translation: { description: null } }).translation.description, null);
      assert.deepEqual(JSON.parse(JSON.parse(lastWire).messages[1].content), { title: 'Memory handling flaw', description: null });
      assert.doesNotMatch(lastWire, /private-value|provenanceRef|reportVersion|findingId|packageName/);
    });

    await t.test('real adapter synthetic success, exact egress, shared quota/capacity, read fence, original and TEMP retained', async () => {
      const original = ledger.archiveResult(scan.id, owner.id), before = quota.snapshot(owner.id, scan.id);
      let lockFailure: unknown;
      insideSend = () => {
        const raw = new Database(env.SCAN_LEDGER_PATH, { timeout: 0 });
        try { assert.throws(() => raw.prepare('UPDATE scans SET state=state WHERE id=?').run(scan.id), /locked/); }
        catch (error) { lockFailure = error; }
        finally { raw.close(); }
      };
      const response = await post(request(initial)); insideSend = undefined;
      assert.equal(response.status, 200, (await response.clone().text()) + ' synthetic guard: ' + String(guardFailure)); assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.equal(lockFailure, undefined);
      const result = await response.json() as Record<string, unknown>;
      assert.deepEqual(Object.keys(result).sort(), ['scanId', 'digest', 'platform', 'reportVersion', 'findingId', 'assessmentIndex', 'sourceVersion',
        'source', 'translation', 'machineTranslated', 'targetLanguage', 'model', 'provider', 'generatedAt'].sort());
      assert.equal(result.machineTranslated, true); assert.equal(result.targetLanguage, 'ru'); assert.equal(result.model, policy.model);
      assert.equal(result.provider, 'OpenRouter'); assert.match(String(result.generatedAt), /^\d{4}-\d\d-\d\dT/);
      const wire = JSON.parse(lastWire); assert.deepEqual(JSON.parse(wire.messages[1].content), {
        title: 'Memory handling flaw', description: `An attacker can corrupt memory in ${scan.finding.cveId}.` });
      assert.equal(wire.model, policy.model); assert.deepEqual(wire.provider.only, ['phala']); assert.equal(wire.provider.allow_fallbacks, false);
      assert.deepEqual(wire.provider.max_price, { prompt: 0, completion: 0, request: 0 }); assert.equal(wire.provider.zdr, true);
      assert.equal(quota.snapshot(owner.id, scan.id).scan.used.input, before.scan.used.input + 500);
      assert.deepEqual(ledger.archiveResult(scan.id, owner.id), original);
      assert.doesNotMatch(JSON.stringify(reader.read({ subject: owner.id, scope: ['scan:read'] }, scan.id)), /Memory handling|An attacker|description/);
      const tempContext = await context(contextUrl(scan.temp.findingId, scan.index));
      const temporary = await post(request(tempContext)); assert.equal(temporary.status, 200, await temporary.clone().text());
      const text = JSON.stringify(await temporary.json()); assert.match(text, /TEMP-1000240-A1B2C3/); assert.doesNotMatch(text, /CVE-|nvd\.nist/);
      assert.deepEqual(ledger.archiveResult(scan.id, owner.id), original);
    });

    await t.test('invalid responses and receipts fail without retries or refunds after dispatch', async () => {
      for (const invalid of ['english', 'url', 'identifier', 'extra', 'null', 'model', 'receipt']) {
        bad = invalid; const before = sends;
        // Unknown/fault receipts retain liability and can lock this user's future admission.
        // Isolate those disposable quota fixtures; never erase/refund them to continue.
        if (['model', 'receipt'].includes(invalid)) mkdirSync(join(directory, invalid), { mode: 0o700 });
        const isolated = ['model', 'receipt'].includes(invalid) ? new FixtureQuotaLedger(join(directory, invalid, 'llm-usage.sqlite'), quotaPolicy) : undefined;
        if (isolated) quotas.ledger = () => isolated;
        try {
          const response = await post(request(initial)); assert.equal(response.status, 502, invalid + ': ' + await response.clone().text());
          assert.equal(sends, before + 1); assert.doesNotMatch(await response.text(), /evil|Memory|private/);
          if (isolated) assert.ok(isolated.snapshot(owner.id, scan.id).scan.held.input > 0);
          else assert.equal(quota.snapshot(owner.id, scan.id).scan.held.input, 0);
        } finally { quotas.ledger = () => quota; isolated?.close(); }
      }
      bad = '';
    });

    await t.test('quota refusal and context bounds precede provider construction', async () => {
      const beforeFactories = factories, beforeSends = sends;
      mkdirSync(join(directory, 'limited'), { mode: 0o700 });
      const limited = new FixtureQuotaLedger(join(directory, 'limited', 'llm-usage.sqlite'), { ...quotaPolicy,
        user: { input: 1, output: 1, costMicros: 0 }, scan: { input: 1, output: 1, costMicros: 0 } });
      quotas.ledger = () => limited;
      try { assert.equal((await post(request(initial))).status, 429); } finally { quotas.ledger = () => quota; limited.close(); }
      currentPolicy = { ...policy, version: 'e'.repeat(64), requestBytes: 1 };
      const bounded = await context(); assert.equal((await post(request(bounded))).status, 503); currentPolicy = policy;
      assert.equal(factories, beforeFactories); assert.equal(sends, beforeSends);
    });

    await t.test('stale auth/policy/report at actual body boundary sends zero and releases reserved quota', async () => {
      for (const reason of ['auth', 'policy', 'report', 'source']) {
        const reached = deferred(), resume = deferred(); beforeSend = async () => { reached.resolve(); await resume.promise; };
        const before = sends, pending = post(request(initial)); await reached.promise;
        if (reason === 'auth') auth.revoke(cookie.slice('demo_session='.length));
        if (reason === 'policy') currentPolicy = { ...policy, version: 'd'.repeat(64) };
        const scans = app!.get(ScansService), originalStatus = scans.status.bind(scans), originalVuln = scans.vuln.bind(scans);
        if (reason === 'source') scans.vuln = (...args) => {
          const page = originalVuln(...args);
          if (page.outcome !== 'checked') return page;
          return { ...page, findings: page.findings.map(f => ({ ...f,
            advisory: normalizeAdvisory({ Title: 'Changed saved source text', Language: 'en' }, f.provenanceRef, f.cveId) })) };
        };
        if (reason === 'report') scans.status = (...args) => ({ ...originalStatus(...args), state: 'failed' });
        resume.resolve(); const response = await pending;
        assert.equal(response.status, 502); assert.equal(sends, before);
        assert.equal(quota.snapshot(owner.id, scan.id).scan.held.input, 0);
        scans.status = originalStatus; scans.vuln = originalVuln; currentPolicy = policy; beforeSend = undefined;
        if (reason === 'auth') renew();
      }
    });

    await t.test('shared capacity blocks concurrent request; cancellation before send never dispatches', async () => {
      const reached = deferred(), resume = deferred(), aborted = deferred();
      beforeSend = async init => { init.signal!.addEventListener('abort', aborted.resolve, { once: true }); reached.resolve(); await resume.promise; };
      const controller = new AbortController(), before = sends;
      const pending = post(request(initial), cookie, path(), {}, controller.signal).catch(error => error);
      await reached.promise; assert.equal((await post(request(initial))).status, 429);
      controller.abort(); await aborted.promise; resume.resolve(); await pending;
      beforeSend = undefined;
      // Wait for the adapter rejection and HTTP finally to release shared capacity.
      for (let n = 0; n < 100 && quota.snapshot(owner.id, scan.id).scan.held.input !== 0; n++) await new Promise(resolve => setTimeout(resolve, 5));
      assert.equal(sends, before); assert.equal(quota.snapshot(owner.id, scan.id).scan.held.input, 0);
    });

    await t.test('revocation after receipt/body admission accounts but suppresses publication', async () => {
      const reached = deferred(), resume = deferred(), before = sends, used = quota.snapshot(owner.id, scan.id).scan.used.input;
      afterSend = async () => { reached.resolve(); await resume.promise; };
      const pending = post(request(initial)); await reached.promise; auth.revoke(cookie.slice('demo_session='.length)); resume.resolve();
      const response = await pending; assert.equal(response.status, 503); assert.equal(sends, before + 1);
      assert.equal(quota.snapshot(owner.id, scan.id).scan.used.input, used + 500);
      assert.doesNotMatch(await response.text(), /Ошибка|Злоумышленник/); afterSend = undefined; renew();
    });

    await t.test('final actual HTTP write rechecks authority after generation and releases shared capacity on refusal', async () => {
      const operation = app!.get(LlmService).translation(), generate = operation.generate.bind(operation);
      const before = sends, used = quota.snapshot(owner.id, scan.id).scan.used.input;
      operation.generate = async (...args) => {
        const result = await generate(...args);
        currentPolicy = { ...policy, version: 'e'.repeat(64) };
        return result;
      };
      try {
        const response = await post(request(initial)); assert.equal(response.status, 409);
        assert.deepEqual(await response.json(), { errorCode: 'LLM_STALE_POLICY' });
        assert.equal(sends, before + 1); assert.equal(quota.snapshot(owner.id, scan.id).scan.used.input, used + 500);
      } finally { operation.generate = generate; currentPolicy = policy; }
      assert.equal((await post(request(initial))).status, 200, 'capacity released even when final write is refused');
    });

    await t.test('public-only registration and exact nginx routes; no legacy translation path', async () => {
      const legacy = await NestFactory.create(AppModule, { logger: false });
      try {
        await legacy.listen(0, '127.0.0.1');
        const url = `http://127.0.0.1:${(legacy.getHttpServer().address() as { port: number }).port}/api/v1/browser/scans/${scan.id}/llm/translation`;
        assert.equal((await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status, 404);
        assert.throws(() => legacy.get(LlmService).translation());
      } finally { await legacy.close(); }
      const nginx = readFileSync(new URL('../../../../deploy/public-stand.nginx.conf', import.meta.url), 'utf8');
      assert.match(nginx, /llm\/translation\$"/); assert.match(nginx, /llm\/translation\/context\$"/);
      const legacyNginx = readFileSync(new URL('../../../../deploy/stand.nginx.conf', import.meta.url), 'utf8');
      assert.doesNotMatch(legacyNginx, /llm\/translation/);
    });
  } finally {
    await app?.close(); quota.close();
    Object.keys(env).forEach((key, index) => { if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index]; });
    rmSync(directory, { recursive: true, force: true });
  }
});
