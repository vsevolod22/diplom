import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { PublicImageModule, configurePublicImageIngress } from '../../oci/public-image.module.js';
import { PublicImageScansService } from '../../scans/public-image-scans.service.js';
import { ScansService } from '../../scans/scans.service.js';
import { publicVulnerabilityFixture } from '../../scans/public-vulnerability.fixture.js';
import { LedgerStore } from '../../ledger/ledger-store.js';
import { CURRENT_DB_POLICY } from '../../worker/cve-db-policy.mjs';
import { LlmRuntime, LlmService } from '../llm.service.js';
import { LlmQuotaRuntime } from '../quota-runtime.js';
import { ReportReader, type ReportContext } from '../report-context.js';
import { OpenRouterProvider } from '../openrouter-provider.js';
import type { BodySendGuard, GuardedTransport } from '../openrouter-transport.js';
import { HistoryStore } from '../history-store.js';
import { policyFromEnvironment } from '../policy.js';
import { fixtureEnv, fixtureReport, fakeKey } from './fixtures.js';
import { FixtureQuotaLedger, quotaPolicy } from './quota-fixtures.js';
import { safeHistoryFinding } from '../history-sources.js';
import { cleanText, reportBinding, validateChatReply } from '../history-contract.js';


const policy = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'xingchen-agi/xing4.0-29b-a4b:free',
  LLM_PROVIDER_ALLOWLIST: 'phala', LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0',
  LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' })!;

const credentialTexts = [
  ...['password', 'api_key', 'authorization', 'credentials', 'passwd', 'access-key', 'private_key', 'token', 'secret',
    'DB_PASSWORD', 'AWS_SECRET_ACCESS_KEY'].map(key => JSON.stringify({ [key]: 'synthetic-review-value' })),
  "{'password': 'synthetic-review-value'}",
  '"Api_Key" = "synthetic-review-value"',
  '"authorization" is synthetic-review-value',
  '{\\"password\\":\\"synthetic-review-value\\"}',
];

test('credential-labelled JSON and quoted KV refuse without rejecting safe localized evidence', () => {
  for (const text of credentialTexts) {
    assert.throws(() => cleanText(text), error => error instanceof Error && 'getStatus' in error &&
      typeof error.getStatus === 'function' && error.getStatus() === 400);
    assert.throws(() => validateChatReply({ ...reportBinding(fixtureReport), text,
      citations: [fixtureReport.findings[0].findingId] }, fixtureReport));
  }
  for (const text of ['Объясни находку и неизвестное покрытие 🙂.', 'Explain password rotation without sharing values.',
    'The "password" field was omitted.', 'Compare CVE-2026-1234 and TEMP-1234567-ABCDEF without inventing mappings.',
    '{"severity":"HIGH","findingCount":2}']) {
    assert.equal(cleanText(text) === text, true);
    assert.equal(validateChatReply({ ...reportBinding(fixtureReport), text,
      citations: [fixtureReport.findings[0].findingId] }, fixtureReport).text === text, true);
  }
});

test('public 8081 reuses owner/report/summary and durable chat with whole counts and no raw evidence egress', { timeout: 30000 }, async t => {
  const directory = mkdtempSync(join(tmpdir(), 'public-llm-')), origin = 'http://127.0.0.1:8081';
  const env = { AUTH_DB_PATH: join(directory, 'auth.sqlite'), SCAN_LEDGER_PATH: join(directory, 'ledger.sqlite'), AUTH_ORIGIN: origin,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true', SCAN_BROWSER_ALLOWED_USER_IDS: '' };
  const previous = Object.keys(env).map(key => process.env[key]); Object.assign(process.env, env);
  let app: NestExpressApplication | undefined, history: HistoryStore | undefined;
  const quota = new FixtureQuotaLedger(join(directory, 'llm-usage.sqlite'), { ...quotaPolicy,
    user: { input: 1000000, output: 100000, costMicros: 0 }, scan: { input: 1000000, output: 100000, costMicros: 0 } });
  try {
    app = await NestFactory.create<NestExpressApplication>(PublicImageModule, { logger: false, bodyParser: false });
    configurePublicImageIngress(app);
    assert.ok(app.get(ScansService) instanceof PublicImageScansService);
    history = new HistoryStore(join(directory, 'llm-history.sqlite'), true);
    const llm = app.get(LlmService), runtime = app.get(LlmRuntime), reader = app.get(ReportReader);
    llm.history().runtime.store = () => history!; app.get(LlmQuotaRuntime).ledger = () => quota;
    runtime.policy = () => policy;
    let sends = 0, factories = 0, invalid = false;
    let replyText = 'Находка сохранена сканером; отсутствующие сведения остаются неизвестными.';
    const wires: Array<{ report: ReportContext; history?: unknown }> = [];
    const response = async (_url: unknown, init?: RequestInit) => {
      sends++;
      const wire = JSON.parse(String(init!.body)), context = JSON.parse(wire.messages[1].content), report: ReportContext = context.report ?? context;
      wires.push(context.report ? context : { report });
      assert.equal(wire.model, policy.model); assert.deepEqual(wire.provider.only, ['phala']);
      assert.deepEqual(wire.provider.max_price, { prompt: 0, completion: 0, request: 0 });
      assert.doesNotMatch(String(init!.body), /Synthetic advisory|package-\d|installedVersion|description|CANARY|rawOutput|password|sk-or-/);
      assert.match(wire.messages[0].content, /untrusted/); assert.match(wire.messages[0].content, /NOT CVEs/);
      const binding = { scanId: report.scanId, digest: report.digest, platform: report.platform, reportVersion: report.reportVersion };
      const ids = [invalid ? 'foreign-finding' : (report.findings.find(f => f.identifierKind === 'debian-temp') ?? report.findings.at(-1)!).findingId];
      const content = context.report ? { ...binding, text: replyText, citations: ids } :
        { ...binding, hypotheses: [{ text: 'Выбрана часть находок; это не полная оценка безопасности.', citations: ids }] };
      return new Response(JSON.stringify({ model: policy.model, usage: { prompt_tokens: 500, completion_tokens: 32, cost: 0 },
        choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: JSON.stringify(content) } }] }),
      { headers: { 'content-type': 'application/json' } });
    };
    const transport = Object.assign(response as typeof fetch, { sendGuarded: async (url: string, init: RequestInit, guard: BodySendGuard) => {
      let result!: Promise<Response>; guard(() => { result = response(url, init); }); return result;
    } }) as GuardedTransport;
    runtime.provider = () => { factories++; return new OpenRouterProvider(fakeKey, transport); };
    await app.listen(0, '127.0.0.1');
    const base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    const register = async (name: string) => {
      const res = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify({ email: `${name}@example.invalid`, password: 'disposable-public-llm-1234' }) });
      assert.equal(res.status, 201); return { id: (await res.json() as { id: string }).id, cookie: res.headers.get('set-cookie')!.split(';')[0] };
    };
    const owner = await register('owner'), other = await register('other');
    const ledger = app.get(LedgerStore).ledger!;
    const seed = (key: string, subject = owner.id, mode = 'findings') => {
      const report = publicVulnerabilityFixture();
      if (report.vuln?.outcome === 'checked') {
              report.vuln.findings.at(-1)!.severity = 'CRITICAL';
              if (mode === 'zero') report.vuln.findings = [];
              if (mode === 'unknown') report.vuln = { outcome: 'unsupported', reason: 'OS_UNKNOWN', db: report.vuln.db,
                dbPolicy: report.vuln.dbPolicy, os: { outcome: 'unsupported', reason: 'OS_UNKNOWN' },
                node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_UNKNOWN' } };
            }
      const id = ledger.enqueue({ ...report.receipt, subject, idempotencyKey: key, scope: 'image', checks: '["sbom","vuln"]', cvePolicy: CURRENT_DB_POLICY }).scanId;
      const job = ledger.claim()!; assert.equal(ledger.finishArchive(id, job.attempts, report, undefined, job.leaseToken), true); return id;
    };
    const id = seed('one'), second = seed('two'), foreign = seed('foreign', other.id);
        const zero = seed('zero', owner.id, 'zero'), unknown = seed('unknown', owner.id, 'unknown');
    const path = (endpoint: string, scanId = id) => `${base}/browser/scans/${scanId}/llm/${endpoint}`;
    const get = (endpoint: string, cookie = owner.cookie, scanId = id) => fetch(path(endpoint, scanId), { headers: { cookie } });
    const post = (endpoint: string, body: unknown, cookie = owner.cookie, requestOrigin = origin) => fetch(path(endpoint), {
      method: 'POST', headers: { cookie, origin: requestOrigin, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const context = async (endpoint = 'context') => {
      const res = await get(endpoint); assert.equal(res.status, 200, await res.clone().text()); assert.equal(res.headers.get('cache-control'), 'no-store'); return res.json();
    };
    const summary = await context(), chat = await context('chat/context');
    runtime.credentialStatus = () => 'missing';
    const missingKey = await context('readiness');
    assert.equal(missingKey.status, 'setup-required'); assert.equal(missingKey.acceptsCredentials, false);
    assert.deepEqual(missingKey.blockers, ['public-key-required']);
    assert.equal(missingKey.provider.status, 'catalog-listed-unprobed'); assert.equal(missingKey.generationVerified, false);
    runtime.credentialStatus = () => 'metadata-valid';
    const local = await context('readiness'); assert.equal(local.localReady, true); assert.equal(local.reportVersion, summary.reportVersion);
    const historyStore = llm.history().runtime.store, quotaLedger = app.get(LlmQuotaRuntime).ledger;
    llm.history().runtime.store = () => { throw new Error('CANARY-private-database-diagnostic'); };
    app.get(LlmQuotaRuntime).ledger = () => { throw new Error('CANARY-private-quota-diagnostic'); };
    runtime.policy = () => null;
    const setup = await context('readiness');
    assert.equal(setup.status, 'setup-required'); assert.ok(setup.blockers.includes('history-store-unavailable'));
    assert.ok(setup.blockers.includes('quota-store-unavailable')); assert.ok(setup.blockers.includes('configuration-required'));
    assert.doesNotMatch(JSON.stringify(setup), /CANARY|sqlite|\/auth|sk-or-/);
    llm.history().runtime.store = historyStore; app.get(LlmQuotaRuntime).ledger = quotaLedger; runtime.policy = () => policy;
    assert.equal(factories, 0); assert.equal(sends, 0);
    assert.equal((await fetch(path('readiness'))).status, 401);
    for (const endpoint of ['context', 'history', 'chat/context', 'usage', 'chat/usage', 'readiness']) {
      assert.equal((await get(endpoint, other.cookie)).status, 404);
      assert.equal((await get(endpoint, owner.cookie, foreign)).status, 404);
    }
    const full = reader.read({ subject: owner.id, scope: ['scan:read'] }, id);
    assert.equal(full.findingCount, 241); assert.deepEqual(full.identifierCounts, { cve: 236, debianTemp: 5 });
    assert.equal(full.findingCounts!.bySeverity.CRITICAL, 1);
    assert.equal((full.coverage.vuln as { node: { reason: string } }).node.reason, 'NODE_INVENTORY_UNKNOWN');
    assert.equal((full.coverage.vuln as { dbPolicy: { status: string } }).dbPolicy.status, 'usable');
    assert.ok(full.findings.every(safeHistoryFinding));
    assert.equal(full.findings.filter(f => f.identifierKind === 'debian-temp').length, 5);
    assert.notEqual(reader.read({ subject: owner.id, scope: ['scan:read'] }, second).reportVersion, full.reportVersion);
        const service = app.get(ScansService), originalStatus = service.status.bind(service), originalVuln = service.vuln.bind(service);
        assert.throws(() => new ReportReader(service).read({ subject: owner.id, scope: ['scan:read'] }, id), 'public grammar is composition-only');
        service.status = (...args) => Object.assign(originalStatus(...args), { identifierCounts: { cve: 241, debianTemp: 0 } });
        assert.throws(() => reader.read({ subject: owner.id, scope: ['scan:read'] }, id)); service.status = originalStatus;
        service.vuln = (...args) => ({ ...originalVuln(...args), platform: 'linux/arm64' }) as ReturnType<typeof service.vuln>;
        assert.throws(() => reader.read({ subject: owner.id, scope: ['scan:read'] }, id)); service.vuln = originalVuln;
        for (const scanId of [zero, unknown]) {
          const emptyContext = await (await get('context', owner.cookie, scanId)).json();
          const empty = reader.read({ subject: owner.id, scope: ['scan:read'] }, scanId);
          if (scanId === zero) assert.deepEqual(empty.identifierCounts, { cve: 0, debianTemp: 0 });
          else { assert.equal(empty.identifierCounts, undefined); assert.equal((empty.coverage.vuln as { outcome: string }).outcome, 'unsupported'); }
          const refused = await fetch(path('summary', scanId), { method: 'POST', headers: { cookie: owner.cookie, origin, 'content-type': 'application/json' },
            body: JSON.stringify({ reportVersion: emptyContext.reportVersion, consent: { accepted: true, policyVersion: emptyContext.policyVersion } }) });
          assert.equal(refused.status, 409); assert.deepEqual(await refused.json(), { errorCode: 'LLM_NO_EVIDENCE' });
        }
        assert.equal(factories, 0); assert.equal(sends, 0);
    await t.test('quoted credential questions and decisions refuse before history writes, quota and provider construction', async regression => {
      const begin = regression.mock.method(history!, 'begin');
      const decision = regression.mock.method(history!, 'decision');
      const reserve = regression.mock.method(quota, 'reserve');
      const before = history!.snapshot(owner.id, id), beforeFactories = factories, beforeSends = sends;
      for (const text of credentialTexts) {
        const expected = { epoch: chat.epoch, revision: chat.revision, mutationId: randomUUID(), reportVersion: chat.reportVersion };
        for (const [endpoint, input] of [
          ['chat', { ...expected, question: text, consent: { accepted: true, policyVersion: chat.policyVersion } }],
          ['history/decision', { ...expected, text, findingIds: [] }],
        ] as const) {
          const denied = await post(endpoint, input);
          assert.equal(denied.status, 400); assert.equal(denied.headers.get('cache-control'), 'no-store');
          assert.deepEqual(await denied.json(), { errorCode: 'LLM_INVALID_REQUEST' });
        }
      }
      assert.equal(begin.mock.calls.length, 0); assert.equal(decision.mock.calls.length, 0);
      assert.equal(reserve.mock.calls.length, 0); assert.equal(factories, beforeFactories); assert.equal(sends, beforeSends);
      assert.deepEqual(history!.snapshot(owner.id, id), before);
      assert.equal(reader.read({ subject: owner.id, scope: ['scan:read'] }, id).reportVersion, full.reportVersion);
    });
    assert.throws(() => reader.read({ subject: owner.id, scope: [] }, id));
    const body = { reportVersion: summary.reportVersion, consent: { accepted: true, policyVersion: summary.policyVersion } };
    assert.equal((await post('summary', { ...body, consent: { ...body.consent, accepted: false } })).status, 403);
    assert.equal((await post('summary', body, owner.cookie, 'http://127.0.0.1:8080')).status, 403);
    const res = await post('summary', body); assert.equal(res.status, 200, await res.clone().text());
    const result = await res.json(); assert.equal(result.findingCount, 241); assert.deepEqual(result.identifierCounts, full.identifierCounts);
    assert.ok(result.contextSelection.omittedFindings > 0);
    assert.equal(wires[0].report.findingCount, 241); assert.ok(wires[0].report.findings.some(f => f.severity === 'CRITICAL'));
    assert.equal(wires[0].report.findings.length + result.contextSelection.omittedFindings, 241);
    const makeChat = async () => { const c = await context('chat/context'); return { epoch: c.epoch, revision: c.revision, reportVersion: c.reportVersion,
      mutationId: randomUUID(), question: 'Explain the Debian TEMP evidence without inventing a CVE mapping.', consent: { accepted: true, policyVersion: c.policyVersion } }; };
    const input = await makeChat();
    const generated = await post('chat', input); assert.equal(generated.status, 200, await generated.clone().text());
    const complete = await generated.json(); assert.equal(complete.reply.kind, 'hypothesis'); assert.equal(complete.findingCount, 241);
    const stored = history.snapshot(owner.id, id); assert.equal(stored.turns[0].state, 'completed');
    assert.ok(stored.turns[0].reply!.sources.every(s => safeHistoryFinding(s.finding)));
        assert.equal(stored.turns[0].reply!.sources[0].finding.identifierKind, 'debian-temp');
    const count = sends; assert.equal((await post('chat', input)).status, 200); assert.equal(sends, count);
    history.close(); history = new HistoryStore(join(directory, 'llm-history.sqlite'));
    const reopened = await (await get('history')).json(); assert.equal(reopened.turns[0].id, complete.turnId);
    assert.equal(reopened.turns[0].reply.sources[0].finding.cveId, stored.turns[0].reply!.sources[0].finding.cveId);
    assert.equal((await (await get('history', owner.cookie, second)).json()).turns.length, 0);
    invalid = true;
    assert.equal((await post('chat', await makeChat())).status, 502);
    assert.equal(history.snapshot(owner.id, id).turns.at(-1)!.state, 'failed');
    assert.equal(quota.snapshot(owner.id, id).scan.used.input, sends * 500, 'invalid citation does not refund usage');
    invalid = false;
    await t.test('quoted credential provider replies are refused before completion without losing accepted history or evidence', async regression => {
      const finish = regression.mock.method(history!, 'finish');
      const before = history!.snapshot(owner.id, id), beforeSends = sends, beforeUsage = quota.snapshot(owner.id, id).scan.used.input;
      try {
        for (const text of credentialTexts) {
          replyText = text;
          const denied = await post('chat', await makeChat());
          assert.equal(denied.status, 502); assert.equal(denied.headers.get('cache-control'), 'no-store');
          assert.deepEqual(await denied.json(), { errorCode: 'LLM_INVALID_RESPONSE' });
        }
      } finally { replyText = 'Находка сохранена сканером; отсутствующие сведения остаются неизвестными.'; }
      assert.equal(finish.mock.calls.length, 0);
      const after = history!.snapshot(owner.id, id);
      assert.deepEqual(after.turns.slice(0, before.turns.length), before.turns);
      assert.deepEqual(after.decisions, before.decisions); assert.equal(after.pending, null);
      assert.equal(after.turns.length, before.turns.length + credentialTexts.length);
      assert.ok(after.turns.slice(before.turns.length).every(turn => turn.state === 'failed' && turn.reply === undefined));
      assert.equal(sends - beforeSends, credentialTexts.length);
      assert.equal(quota.snapshot(owner.id, id).scan.used.input - beforeUsage, credentialTexts.length * 500);
      assert.equal(JSON.stringify(after).includes('synthetic-review-value'), false);
      assert.equal(reader.read({ subject: owner.id, scope: ['scan:read'] }, id).reportVersion, full.reportVersion);
    });
    const before = sends;
    const unsafe = await post('chat', { ...await makeChat(), question: 'password=CANARY-do-not-send' });
    assert.equal(unsafe.status, 400); assert.equal(sends, before); assert.doesNotMatch(await unsafe.text(), /CANARY/);
    const badJson = await fetch(path('chat'), { method: 'POST', headers: { cookie: owner.cookie, origin, 'content-type': 'application/json' }, body: '{"CANARY":' });
    assert.equal(badJson.status, 400); assert.equal(badJson.headers.get('cache-control'), 'no-store'); assert.doesNotMatch(await badJson.text(), /CANARY/);
    invalid = false;
        const streamed = await fetch(path('chat'), { method: 'POST', headers: { cookie: owner.cookie, origin,
          'content-type': 'application/json', accept: 'application/x-ndjson' }, body: JSON.stringify(await makeChat()) });
        assert.equal(streamed.status, 200); assert.match(streamed.headers.get('content-type')!, /application\/x-ndjson/);
        const frames = (await streamed.text()).trim().split('\n').map(line => JSON.parse(line));
        assert.equal(frames[0].type, 'usage'); assert.equal(frames.at(-1).type, 'done');
        assert.ok(frames.every(frame => frame.scanId === id && frame.nativeProviderStream === false));
        assert.ok(JSON.stringify(frames).includes('debian-temp')); assert.equal(history.snapshot(owner.id, id).turns.at(-1)!.state, 'completed');
        assert.equal((await get('chat/context')).status, 200); assert.ok(chat.epoch);
  } finally {
    await app?.close(); history?.close(); quota.close();
    Object.keys(env).forEach((key, index) => { if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index]; });
    rmSync(directory, { recursive: true, force: true });
  }
});
