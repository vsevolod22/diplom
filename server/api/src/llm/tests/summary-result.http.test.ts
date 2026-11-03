import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { request, type ClientRequest } from 'node:http';
import { existsSync, mkdtempSync, renameSync, rmSync } from 'node:fs';
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
import { normalizeAdvisory } from '../../worker/vuln-advisory.js';
import { ReportReader, type SafeFinding } from '../report-context.js';
import { LlmRuntime, LlmService } from '../llm.service.js';

import { OpenRouterProvider } from '../openrouter-provider.js';
import type { BodySendGuard, GuardedTransport } from '../openrouter-transport.js';
import { policyFromEnvironment, type LlmPolicy } from '../policy.js';
import { LlmQuotaRuntime } from '../quota-runtime.js';
import { HistoryStore } from '../history-store.js';
import { HISTORY, hashValue } from '../history-contract.js';
import { HistoryRuntime, HISTORY_AUTHORITY } from '../history-runtime.js';
import { overrideProvider } from './summary-runtime.fixture.js';
import { fillPhysicalHistory, summaryStorageRows } from './summary-storage.fixture.js';
import { fakeKey, fixtureEnv, archiveFixture } from './fixtures.js';
import { completedLegacyFourCheckFixture } from './legacy-summary.fixture.js';
import { prepareSummary } from '../prepared-request.js';
import { validateReply } from '../response.js';
import { summaryRecordHash, type SummaryRow } from '../summary-record.js';
import { FixtureQuotaLedger, quotaPolicy } from './quota-fixtures.js';

const policy = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'dots-studio/dots-3-note-preview:free',
  LLM_PROVIDER_ALLOWLIST: 'atlas-cloud/fp8', LLM_RETENTION: 'no-training', LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0',
  LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' })!;

test('public summary POST retains only guarded validated results; passive owner GET survives reload/login, including runtime recreation', { timeout: 60000 }, async t => {
  const directory = mkdtempSync(join(tmpdir(), 'summary-result-')), origin = 'http://127.0.0.1:8081';
  const env = { AUTH_DB_PATH: join(directory, 'auth.sqlite'), SCAN_LEDGER_PATH: join(directory, 'ledger.sqlite'), AUTH_ORIGIN: origin,
    LLM_HISTORY_ENABLED: 'true', LLM_HISTORY_REVISION: HISTORY.version, LLM_HISTORY_AUTHORITY: HISTORY_AUTHORITY,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true', SCAN_BROWSER_ALLOWED_USER_IDS: '' };
  const previous = Object.keys(env).map(key => process.env[key]); Object.assign(process.env, env);
  const historyPath = join(directory, 'llm-history.sqlite');
  new HistoryStore(historyPath, true).close();
  const quota = new FixtureQuotaLedger(join(directory, 'llm-usage.sqlite'), { ...quotaPolicy,
    user: { input: 1000000, output: 100000, costMicros: 0 }, scan: { input: 1000000, output: 100000, costMicros: 0 } });
  let app: NestExpressApplication | undefined, base = '', sends = 0, factories = 0, invalid = false, rateLimited = false;
  let currentPolicy: LlmPolicy | null = policy;
  let summaryText: ((finding: SafeFinding) => string) | undefined;
  const dispatched: string[] = [];
  let summaryAllCitations = false, legacyScan = '';
  let beforeProviderReply: (() => void) | undefined;
  const start = async () => {
    app = await NestFactory.create<NestExpressApplication>(overrideProvider(PublicImageModule, HistoryRuntime, new HistoryRuntime(historyPath)), { logger: false, bodyParser: false });
    configurePublicImageIngress(app);
    const runtime = app.get(LlmRuntime);
    runtime.policy = () => currentPolicy;
    runtime.provider = () => { factories++;
      const response = async (_url: unknown, init?: RequestInit) => {
      sends++; dispatched.push(String(init!.body));
      if (rateLimited) return new Response('private-provider-body', { status: 429 });
      const report = JSON.parse(JSON.parse(String(init!.body)).messages[1].content);
      const value = { scanId: report.scanId, digest: report.digest, platform: report.platform, reportVersion: report.reportVersion,
        hypotheses: [{ text: invalid ? 'CANARY-private' : summaryText?.(report.findings[0]) ?? 'Сканер сообщил о находке; эксплуатация не установлена.', citations: summaryAllCitations ? report.findings.map((f: SafeFinding) => f.findingId) : [report.findings[0].findingId] }] };
      beforeProviderReply?.();
      return new Response(JSON.stringify({ model: policy.model, usage: { prompt_tokens: 500, completion_tokens: 32, cost: 0 },
        choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: JSON.stringify(value) } }] }),
      { headers: { 'content-type': 'application/json' } });
      };
      const transport = Object.assign(response as typeof fetch, {
        sendGuarded: async (url: string, init: RequestInit, guard: BodySendGuard) => {
          let result!: Promise<Response>;
          guard(() => { result = response(url, init); });
          return result;
        },
      }) as GuardedTransport;
      return new OpenRouterProvider(fakeKey, transport);
    };
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
    let owner = await register('owner');
    const other = await register('other');
    let cookie = owner.cookie;
    // Independent scenarios retain their own rows and liabilities; they must not
    // exhaust one shared owner's finite summary allowance as incidental setup.
    const scopedTest = (name: string, action: () => Promise<void>) => t.test(name, async () => {
      const previousOwner = owner, previousCookie = cookie;
      const auth = app!.get(AuthStore);
      const user = await auth.register(`summary-${hashValue(name).slice(0, 16)}@example.invalid`, 'summary-fixture-only-1234');
      assert.ok(user);
      owner = { id: user.id, cookie: `demo_session=${auth.createSession(user.id)}` }; cookie = owner.cookie;
      try { await action(); } finally { owner = previousOwner; cookie = previousCookie; }
    });
    const renew = () => { cookie = `demo_session=${app!.get(AuthStore).createSession(owner.id)}`; };
    const seed = (key: string, subject = owner.id, score?: number) => {
      const report = publicVulnerabilityFixture();
      if (report.vuln?.outcome === 'checked') {
        report.vuln.findings = report.vuln.findings.slice(0, 1);
        if (score !== undefined) {
          const finding = report.vuln.findings[0];
          finding.advisory = normalizeAdvisory({ CVSS: { nvd: { V3Score: score } } }, finding.provenanceRef, finding.cveId);
        }
      }
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
      assert.equal(response.headers.get('x-llm-summary-retention'), 'durable-owner-scan');
      assert.deepEqual(await response.json(), value);
    };

    await t.test('genuine four-check and archive legacy reports generate plain durable summaries, preserve all-evidence egress and recover under fresh auth/runtime', async regression => {
      const ledger = app!.get(LedgerStore).ledger!, fixture = completedLegacyFourCheckFixture(), immutable = structuredClone(fixture);
      legacyScan = ledger.enqueue({ ...fixture.target, subject: owner.id, idempotencyKey: 'legacy-four-check-durable' }).scanId;
      const job = ledger.claim()!;
      assert.equal(ledger.finishCombined(legacyScan, job.attempts, fixture.outcomes, fixture.config, job.leaseToken), true);
      const archived = { ...archiveFixture(), secret: { outcome: 'checked' as const, findings: [
        { findingId: 'secret-0-1', ruleId: 'rule-0123456789abcdef', line: 1, evidenceRef: 'result-0-secret-1' },
      ] } };
      const archiveId = ledger.enqueue({ ...archived.receipt, subject: owner.id, idempotencyKey: 'legacy-archive-durable', scope: 'image', checks: '["secret"]' }).scanId;
      const archiveJob = ledger.claim()!;
      assert.equal(ledger.finishArchive(archiveId, archiveJob.attempts, archived, undefined, archiveJob.leaseToken), true);
      const reader = app!.get(ReportReader), source = reader.read({ subject: owner.id, scope: ['scan:read'] }, legacyScan);
      assert.equal(source.profile, undefined); assert.equal(source.findingCount, 6);
      assert.deepEqual(source.requestedChecks, ['secret', 'sbom', 'vuln', 'config']);
      const scanDb = new Database(env.SCAN_LEDGER_PATH, { readonly: true });
      try {
        assert.equal(scanDb.prepare('SELECT scan_id FROM scan_archive_results WHERE scan_id=?').get(legacyScan), undefined);
        assert.equal(scanDb.prepare('SELECT scan_id FROM scan_execution_profiles WHERE scan_id=?').get(legacyScan), undefined);
      } finally { scanDb.close(); }
      const retained = new Map<string, ReturnType<typeof validateReply>>();
      summaryAllCitations = true;
      const reserve = regression.mock.method(quota, 'reserve');
      try {
        for (const scanId of [legacyScan, archiveId]) {
          const fresh = reader.read({ subject: owner.id, scope: ['scan:read'] }, scanId);
          assert.equal(fresh.profile, undefined);
          const context = await fetch(`${path(scanId)}/context`, { headers: { cookie } });
          assert.equal(context.status, 200); const capability = await context.json();
          assert.equal(capability.enabled, true); assert.equal(capability.summaryResultRead, true);
          assert.equal(capability.policyVersion, policy.version); assert.equal(Object.hasOwn(capability, 'unavailableReason'), false);
          await assertMissing(scanId);
          const before = { sends, factories, reserves: reserve.mock.callCount(), usage: quota.snapshot(owner.id, scanId).scan.used.input };
          const response = await post(scanId); assert.equal(response.status, 200, await response.clone().text());
          const value = await response.json();
          const expected = validateReply({ scanId, digest: fresh.digest, platform: fresh.platform, reportVersion: fresh.reportVersion,
            hypotheses: [{ text: 'Сканер сообщил о находке; эксплуатация не установлена.', citations: fresh.findings.map(f => f.findingId) }] }, fresh, true);
          assert.deepEqual(value, expected); retained.set(scanId, expected);
          assert.deepEqual(Object.keys(value).sort(), ['scanId', 'digest', 'platform', 'reportVersion', 'hypotheses', 'scannerFacts'].sort());
          assert.deepEqual(value.scannerFacts, fresh.findings);
          assert.equal(dispatched.at(-1), prepareSummary(fresh, policy).body, 'identical legacy ALL-findings producer, not public selection or expanded egress');
          const wire = JSON.parse(dispatched.at(-1)!);
          assert.equal(wire.model, policy.model); assert.deepEqual(wire.provider.only, policy.providers);
          assert.deepEqual(JSON.parse(wire.messages[1].content), fresh);
          for (const key of ['profile', 'contextSelection', 'identifierCounts', 'findingCounts']) assert.equal(Object.hasOwn(JSON.parse(wire.messages[1].content), key), false);
          assert.equal(sends, before.sends + 1); assert.equal(factories, before.factories + 1); assert.equal(reserve.mock.callCount(), before.reserves + 1);
          assert.equal(quota.snapshot(owner.id, scanId).scan.used.input, before.usage + 500);
          await assertCached(scanId, expected);
        }
      } finally { summaryAllCitations = false; reserve.mock.restore(); }
      assert.deepEqual(fixture, immutable);
      const publicContext = await (await fetch(`${path(id)}/context`, { headers: { cookie } })).json();
      assert.equal(publicContext.summaryResultRead, true);
      currentPolicy = null;
      try {
        for (const scanId of [legacyScan, id]) {
          const context = await (await fetch(`${path(scanId)}/context`, { headers: { cookie } })).json();
          assert.equal(context.enabled, false); assert.equal(context.policyVersion, null); assert.equal(context.disclosure, null);
          assert.equal(context.summaryResultRead, true); assert.equal(Object.hasOwn(context, 'unavailableReason'), false);
        }
      } finally { currentPolicy = policy; }
      const standalone = await NestFactory.create<NestExpressApplication>(AppModule, { logger: false });
      try {
        standalone.get(LlmRuntime).policy = () => policy;
        const context = standalone.get(LlmService).context({ subject: owner.id, scope: ['scan:read'] }, legacyScan);
        assert.equal(context.enabled, true); assert.equal(Object.hasOwn(context, 'summaryResultRead'), false);
      } finally { await standalone.close(); }
      const previousService = app!.get(LlmService), previousRuntime = app!.get(HistoryRuntime);
      const beforeSends = sends, beforeFactories = factories, accounted = quota.snapshot(owner.id, legacyScan);
      await app!.close(); app = undefined; await start(); renew();
      assert.notEqual(app!.get(LlmService), previousService); assert.notEqual(app!.get(HistoryRuntime), previousRuntime);
      const dependencies = [
        regression.mock.method(app!.get(LlmRuntime), 'provider', () => assert.fail('legacy recovery cannot generate')),
        regression.mock.method(app!.get(LlmRuntime), 'credentialStatus', () => assert.fail('legacy recovery cannot inspect credentials')),
        regression.mock.method(app!.get(LlmQuotaRuntime), 'ledger', () => assert.fail('legacy recovery cannot access quota')),
        regression.mock.method(HistoryStore.prototype, 'migrateSummarySchema', () => assert.fail('GET cannot migrate')),
        regression.mock.method(HistoryStore.prototype, 'recoverExpired', () => assert.fail('GET cannot recover chat')),
        regression.mock.method(HistoryStore.prototype, 'assertSummaryWritable', () => assert.fail('GET cannot probe write capacity')),
        regression.mock.method(HistoryStore.prototype, 'writeSummary', () => assert.fail('GET cannot write summaries')),
      ];
      const db = new Database(historyPath);
      const assertError = async (response: Response, status: number, code?: string) => {
        assert.equal(response.status, status, await response.clone().text()); assert.equal(response.headers.get('cache-control'), 'no-store');
        const value = await response.json();
        if (code) assert.deepEqual(value, { errorCode: code }); else assert.deepEqual(Object.keys(value), ['errorCode']);
        assert.doesNotMatch(JSON.stringify(value), /summaryResultRead|profile|scannerFacts|hypotheses|disclosure|reportVersion/);
      };
      try {
        const before = summaryStorageRows(db); assert.equal(db.pragma('user_version', { simple: true }), 5);
        for (const [scanId, value] of retained) await assertCached(scanId, value);
        assert.deepEqual(summaryStorageRows(db), before);
        assert.deepEqual(db.prepare('SELECT * FROM history_head').all(), []);
        const input = { reportVersion: source.reportVersion, consent: { accepted: true, policyVersion: policy.version } };
        const send = (body: unknown, token = cookie, scanId = legacyScan) => fetch(`${path(scanId)}/summary`, { method: 'POST',
          headers: { cookie: token, origin, 'content-type': 'application/json' }, body: JSON.stringify(body) });
        for (const [scanId, token] of [[legacyScan, other.cookie], ['00000000-0000-4000-8000-999999999999', cookie]]) {
          for (const endpoint of ['context', 'summary']) await assertError(await fetch(`${path(scanId)}/${endpoint}`, { headers: { cookie: token } }), 404);
          await assertError(await send(input, token, scanId), 404);
        }
        for (const body of [null, {}, [], { ...input, extra: true }, { ...input, profile: 'public-hub-amd64-v1' }])
          await assertError(await send(body), 400, 'LLM_INVALID_REQUEST');
        for (const consent of [null, {}, { accepted: false, policyVersion: policy.version }, { accepted: true }, { ...input.consent, extra: true }])
          await assertError(await send({ ...input, consent }), 403, 'LLM_CONSENT_REQUIRED');
        await assertError(await send({ ...input, reportVersion: 'f'.repeat(64) }), 409, 'LLM_STALE_REPORT');
        const findingId = source.findings.find(f => f.check === 'vuln')!.findingId;
        await assertError(await fetch(`${path(legacyScan)}/translation/context?findingId=${findingId}&assessmentIndex=0`, { headers: { cookie } }), 404, 'SCAN_NOT_FOUND');
        await assertError(await fetch(`${path(legacyScan)}/translation`, { method: 'POST', headers: { cookie, origin, 'content-type': 'application/json' },
          body: JSON.stringify({ ...input, findingId, assessmentIndex: 0, sourceVersion: 'a'.repeat(64), targetLanguage: 'ru' }) }), 404, 'SCAN_NOT_FOUND');
        // Checksums are not authority. Recompute one after each semantic/type corruption.
        const original = db.prepare("SELECT * FROM llm_summary WHERE json_extract(content,'$.value.scanId')=?").get(legacyScan) as SummaryRow;
        const expected = retained.get(legacyScan)!;
        const variants: unknown[] = [
          { ...expected, scannerFacts: expected.scannerFacts.map((f, n) => n === 0 ? { ...f, severity: 'CRITICAL' } : f) },
          { ...expected, scannerFacts: [] },
          { ...expected, hypotheses: [{ ...expected.hypotheses[0], citations: ['foreign-finding'] }] },
          { ...expected, hypotheses: [{ ...expected.hypotheses[0], citations: [source.findings[0].findingId] }] },
          { ...expected, hypotheses: [{ ...expected.hypotheses[0], kind: 'scanner-fact' }] },
          { ...expected, hypotheses: [{ ...expected.hypotheses[0], text: 'This finding is harmless.' }] },
          { ...expected, hypotheses: [{ ...expected.hypotheses[0], text: 'Проверить CVE-2099-9999.' }] },
          { ...expected, profile: 'public-hub-amd64-v1' },
          { ...expected, findingCount: 6, findingCounts: {}, coverage: source.coverage, contextSelection: {} },
          { ...expected, scannerFacts: 'legacy' }, { ...expected, hypotheses: {} }, { ...expected, scanId: 1 },
        ];
        try {
          for (const value of variants) {
            const envelope = JSON.parse(original.content); envelope.value = value; const content = JSON.stringify(envelope);
            db.prepare('UPDATE llm_summary SET content=?,content_hash=? WHERE scope=?').run(content, summaryRecordHash(original.scope, content), original.scope);
            await assertError(await get(legacyScan), 503, 'LLM_HISTORY_UNAVAILABLE');
          }
        } finally { db.prepare('UPDATE llm_summary SET content=?,content_hash=? WHERE scope=?').run(original.content, original.content_hash, original.scope); }
        await assertCached(legacyScan, expected);
        db.exec('BEGIN IMMEDIATE');
        try { await assertError(await send(input), 503, 'LLM_HISTORY_UNAVAILABLE'); } finally { db.exec('ROLLBACK'); }
        assert.deepEqual(summaryStorageRows(db), before);
        for (const dependency of dependencies) assert.equal(dependency.mock.callCount(), 0);
      } finally { db.close(); for (const dependency of dependencies) dependency.mock.restore(); }
      app!.get(HistoryRuntime).close(); renameSync(historyPath, historyPath + '.held');
      try {
        const response = await get(legacyScan); assert.equal(response.status, 503); assert.deepEqual(await response.json(), { errorCode: 'LLM_HISTORY_UNAVAILABLE' });
        assert.equal(existsSync(historyPath), false, 'legacy GET cannot initialize a missing store');
      } finally { renameSync(historyPath + '.held', historyPath); }
      await assertCached(legacyScan, retained.get(legacyScan)!);
      assert.equal(sends, beforeSends); assert.equal(factories, beforeFactories); assert.deepEqual(quota.snapshot(owner.id, legacyScan), accounted);
    });

    await t.test('legacy recovery validates the fresh report/policy and final HTTP publication fence without dispatch or rewriting retained evidence', async regression => {
      const initial = await get(legacyScan); assert.equal(initial.status, 200);
      const expected = await initial.json();
      const scans = app!.get(ScansService), status = scans.status.bind(scans);
      const llm = app!.get(LlmService), read = llm.readSummary.bind(llm);
      const beforeSends = sends, beforeFactories = factories, accounted = quota.snapshot(owner.id, legacyScan);
      const dependencies = [
        regression.mock.method(app!.get(LlmRuntime), 'provider', () => assert.fail('fresh legacy GET cannot generate')),
        regression.mock.method(app!.get(LlmRuntime), 'credentialStatus', () => assert.fail('fresh legacy GET cannot inspect credentials')),
        regression.mock.method(app!.get(LlmQuotaRuntime), 'ledger', () => assert.fail('fresh legacy GET cannot access quota')),
      ];
      const db = new Database(historyPath), before = summaryStorageRows(db);
      const original = db.prepare("SELECT * FROM llm_summary WHERE json_extract(content,'$.value.scanId')=?").get(legacyScan) as SummaryRow;
      const restoreRow = () => db.prepare('UPDATE llm_summary SET content=?,content_hash=? WHERE scope=?')
        .run(original.content, original.content_hash, original.scope);
      const assertFailure = async (status: number, errorCode: string) => {
        const response = await get(legacyScan);
        assert.equal(response.status, status, await response.clone().text()); assert.equal(response.headers.get('cache-control'), 'no-store');
        assert.deepEqual(await response.json(), { errorCode });
      };
      try {
        scans.status = (...args) => ({ ...status(...args), legacyFreshRevision: 1 });
        await assertFailure(404, 'LLM_SUMMARY_MISSING'); scans.status = status;
        await assertCached(legacyScan, expected);
        currentPolicy = { ...policy, version: 'e'.repeat(64) };
        await assertFailure(404, 'LLM_SUMMARY_MISSING'); currentPolicy = policy;
        await assertCached(legacyScan, expected);
        for (const reason of ['report', 'policy', 'session', 'stored-record'] as const) {
          llm.readSummary = (...args) => {
            const result = read(...args);
            if (reason === 'report') scans.status = (...input) => ({ ...status(...input), legacyFreshRevision: 2 });
            if (reason === 'policy') currentPolicy = { ...policy, version: 'e'.repeat(64) };
            if (reason === 'session') app!.get(AuthStore).revoke(cookie.slice('demo_session='.length));
            if (reason === 'stored-record') {
              const envelope = JSON.parse(original.content); envelope.value.hypotheses[0].kind = 'scanner-fact';
              const content = JSON.stringify(envelope);
              db.prepare('UPDATE llm_summary SET content=?,content_hash=? WHERE scope=?')
                .run(content, summaryRecordHash(original.scope, content), original.scope);
            }
            return result;
          };
          try {
            await assertFailure(reason === 'report' || reason === 'policy' ? 409 : 503,
              reason === 'report' ? 'LLM_STALE_REPORT' : reason === 'policy' ? 'LLM_STALE_POLICY' :
                reason === 'session' ? 'AUTH_UNAVAILABLE' : 'LLM_HISTORY_UNAVAILABLE');
          } finally {
            llm.readSummary = read; scans.status = status; currentPolicy = policy; restoreRow();
            if (reason === 'session') renew();
          }
          await assertCached(legacyScan, expected);
        }
        assert.deepEqual(summaryStorageRows(db), before);
        assert.equal(sends, beforeSends); assert.equal(factories, beforeFactories);
        assert.deepEqual(quota.snapshot(owner.id, legacyScan), accounted);
        for (const dependency of dependencies) assert.equal(dependency.mock.callCount(), 0);
      } finally {
        llm.readSummary = read; scans.status = status; currentPolicy = policy; restoreRow(); db.close();
        for (const dependency of dependencies) dependency.mock.restore();
      }
    });

    await t.test('unknown status.profile is rejected after ownership but before projection/policy/storage, never erased into legacy', async regression => {
      const legacy = legacyScan, reader = app!.get(ReportReader);
      const source = reader.read({ subject: owner.id, scope: ['scan:read'] }, legacy);
      const input = { reportVersion: source.reportVersion, consent: { accepted: true, policyVersion: policy.version } };
      const send = (scanId = legacy, token = cookie, body: unknown = input, overrides: Record<string, string> = {}) =>
        fetch(`${path(scanId)}/summary`, { method: 'POST', headers: { cookie: token, origin, 'content-type': 'application/json', ...overrides },
          body: JSON.stringify(body) });
      const dependencies = [
        regression.mock.method(app!.get(LlmRuntime), 'provider', () => assert.fail('unsupported never constructs provider')),
        regression.mock.method(app!.get(LlmRuntime), 'credentialStatus', () => assert.fail('unsupported never reads credentials')),
        regression.mock.method(app!.get(LlmRuntime), 'policy', () => assert.fail('unsupported never discloses current policy')),
        regression.mock.method(app!.get(LlmQuotaRuntime), 'ledger', () => assert.fail('unsupported never opens quota')),
        regression.mock.method(app!.get(HistoryRuntime), 'summaryStore', () => assert.fail('unsupported never opens summary store')),
        regression.mock.method(app!.get(HistoryRuntime), 'store', () => assert.fail('unsupported never opens chat store')),
        regression.mock.method(app!.get(LlmService), 'history', () => assert.fail('unsupported readiness never opens chat service')),
        regression.mock.method(quota, 'reserve', () => assert.fail('unsupported never reserves quota')),
        regression.mock.method(HistoryStore.prototype, 'assertSummaryWritable', () => assert.fail('unsupported never probes storage')),
        regression.mock.method(HistoryStore.prototype, 'readSummary', () => assert.fail('unsupported never reads retained summary')),
        regression.mock.method(HistoryStore.prototype, 'writeSummary', () => assert.fail('unsupported never commits summary')),
      ];
      const scans = app!.get(ScansService), status = scans.status.bind(scans);
      const pages = [regression.mock.method(scans, 'results', () => assert.fail('unknown profile must not paginate findings')),
        regression.mock.method(scans, 'vuln', () => assert.fail('unknown profile must not paginate vulnerabilities')),
        regression.mock.method(scans, 'sbom', () => assert.fail('unknown profile must not paginate inventory'))];
      const beforeSends = sends, beforeFactories = factories;
      const assertError = async (response: Response, status: number, errorCode?: string) => {
        assert.equal(response.status, status, await response.clone().text()); assert.equal(response.headers.get('cache-control'), 'no-store');
        const value = await response.json();
        if (errorCode) assert.deepEqual(value, { errorCode });
        else { assert.deepEqual(Object.keys(value), ['errorCode']); assert.notEqual(value.errorCode, 'LLM_SUMMARY_UNSUPPORTED_REPORT'); }
        assert.doesNotMatch(JSON.stringify(value), /reportVersion|summaryResultRead|unavailableReason|disclosure|profile|findings/);
      };
      try {
        for (const profile of ['unknown-source-v1', null, '', false, {}, 0]) {
          scans.status = (...args) => Object.assign({}, status(...args), { profile });
          for (const endpoint of ['context', 'readiness', 'summary']) await assertError(
            await fetch(`${path(legacy)}/${endpoint}`, { headers: { cookie } }), 409, 'LLM_SUMMARY_UNSUPPORTED_REPORT');
          await assertError(await send(), 409, 'LLM_SUMMARY_UNSUPPORTED_REPORT');
        }
        for (const [scanId, token] of [[legacy, other.cookie], [id, other.cookie], [foreign, cookie], ['00000000-0000-4000-8000-999999999999', cookie]]) {
          for (const endpoint of ['context', 'readiness', 'summary']) await assertError(
            await fetch(`${path(scanId)}/${endpoint}`, { headers: { cookie: token } }), 404);
          await assertError(await send(scanId, token), 404);
          await assertError(await send(scanId, token, {}), 404); // owner lookup precedes body/capability.
        }
        for (const endpoint of ['context', 'readiness', 'summary']) await assertError(
          await fetch(`${path(legacy)}/${endpoint}`), 401, 'UNAUTHORIZED');
        await assertError(await send(legacy, ''), 401, 'UNAUTHORIZED');
        await assertError(await send(legacy, cookie, input, { origin: 'http://127.0.0.1:8080' }), 403, 'INVALID_ORIGIN');
        await assertError(await send(legacy, cookie, input, { 'content-type': 'text/plain' }), 415, 'INVALID_CONTENT_TYPE');
        const previousGate = process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS, previousAllowed = process.env.SCAN_BROWSER_ALLOWED_USER_IDS;
        process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS = 'false'; process.env.SCAN_BROWSER_ALLOWED_USER_IDS = other.id;
        try {
          for (const endpoint of ['context', 'readiness', 'summary']) await assertError(
            await fetch(`${path(legacy)}/${endpoint}`, { headers: { cookie } }), 403, 'SCAN_ACCESS_DENIED');
          await assertError(await send(), 403, 'SCAN_ACCESS_DENIED');
        } finally {
          if (previousGate === undefined) delete process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS; else process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS = previousGate;
          if (previousAllowed === undefined) delete process.env.SCAN_BROWSER_ALLOWED_USER_IDS; else process.env.SCAN_BROWSER_ALLOWED_USER_IDS = previousAllowed;
        }

        assert.equal(sends, beforeSends); assert.equal(factories, beforeFactories);
        for (const dependency of [...dependencies, ...pages]) assert.equal(dependency.mock.callCount(), 0);
      } finally { scans.status = status; for (const dependency of [...dependencies, ...pages]) dependency.mock.restore(); }
    });

    await t.test('explicit missing, validated enriched POST contract, browser reload and fresh-login retrieval', async () => {
      await assertMissing(missing);
      assert.equal((await fetch(`${path(id)}/summary`)).status, 401);
      const response = await post(); assert.equal(response.status, 200, await response.clone().text());
      const value = await response.json();
      assert.equal(response.headers.get('x-llm-summary-retention'), 'durable-owner-scan');
      assert.ok(value.scannerFacts.length); assert.ok(value.contextSelection); assert.equal(value.findingCount, 1);
      assert.equal(value.hypotheses[0].kind, 'hypothesis');
      const before = sends;
      await assertCached(id, value); await assertCached(id, value);
      const login = await fetch(`${base}/auth/login`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
        body: JSON.stringify(credentials('owner')) });
      assert.equal(login.status, 200); cookie = login.headers.get('set-cookie')!.split(';')[0];
      assert.notEqual(cookie, owner.cookie); await assertCached(id, value); assert.equal(sends, before);
    });

    await scopedTest('cited CVSS scores and colon labels publish unchanged and restore without another generation', async () => {
      for (const [index, scoreText] of ['CVSS 7.5', 'оценку CVSS:7,5'].entries()) {
        const scanId = seed(`cited-score-${index}`, owner.id, 7.5), beforeSends = sends;
        const used = quota.snapshot(owner.id, scanId).scan.used.input;
        summaryText = finding => `Пакет:${finding.packageName}; версия:${finding.installedVersion}. Сканер сообщил ${scoreText}.`;
        try {
          const response = await post(scanId); assert.equal(response.status, 200, await response.clone().text());
          const value = await response.json();
          assert.equal(value.hypotheses[0].text, summaryText(value.scannerFacts[0]));
          assert.equal(sends, beforeSends + 1);
          assert.equal(quota.snapshot(owner.id, scanId).scan.used.input, used + 500);
          const accounted = quota.snapshot(owner.id, scanId);
          await assertCached(scanId, value); await assertCached(scanId, value);
          assert.equal(sends, beforeSends + 1); assert.deepEqual(quota.snapshot(owner.id, scanId), accounted);
          summaryText = () => 'Сканер сообщил оценку 99 баллов.';
          const rejected = await post(scanId); assert.equal(rejected.status, 502);
          assert.deepEqual(await rejected.json(), { errorCode: 'LLM_INVALID_RESPONSE' });
          await assertCached(scanId, value);
          assert.equal(sends, beforeSends + 2);
          assert.equal(quota.snapshot(owner.id, scanId).scan.used.input, used + 1000);
        } finally { summaryText = undefined; }
      }
    });

    await scopedTest('invented comma/integer or missing scores are charged once, not retried and never cached', async () => {
      for (const [key, text, score] of [
        ['comma-score', 'Сканер сообщил оценку CVSS 9,9.', 7.5],
        ['integer-score', 'Сканер сообщил оценку 99 баллов.', 7.5],
        ['missing-score', 'Сканер сообщил CVSS 7.5.', undefined],
      ] as const) {
        const scanId = seed(key, owner.id, score), beforeSends = sends;
        const used = quota.snapshot(owner.id, scanId).scan.used.input;
        summaryText = () => text;
        try {
          const response = await post(scanId); assert.equal(response.status, 502);
          assert.equal(response.headers.get('cache-control'), 'no-store');
          assert.equal(response.headers.get('x-llm-failure-phase'), 'grounding');
          assert.equal(response.headers.get('x-llm-failure-reason'), 'unknown_identifier');
          assert.deepEqual(await response.json(), { errorCode: 'LLM_INVALID_RESPONSE' });
        } finally { summaryText = undefined; }
        assert.equal(sends, beforeSends + 1);
        assert.equal(quota.snapshot(owner.id, scanId).scan.used.input, used + 500);
        const accounted = quota.snapshot(owner.id, scanId);
        await assertMissing(scanId);
        assert.equal(sends, beforeSends + 1); assert.deepEqual(quota.snapshot(owner.id, scanId), accounted);
      }
    });

    await t.test('GET never touches provider/key metadata/quota/history; foreign404 precedes cache and policy', async () => {
      const runtime = app!.get(LlmRuntime), quotas = app!.get(LlmQuotaRuntime), llm = app!.get(LlmService);
      const provider = runtime.provider, credential = runtime.credentialStatus, ledger = quotas.ledger, history = llm.history;
      const before = quota.snapshot(owner.id, id), beforeSends = sends, beforeFactories = factories;
      let forbidden = 0;
      const denied = (): never => { forbidden++; throw new Error('private-unreachable'); };
      runtime.provider = denied; runtime.credentialStatus = denied; quotas.ledger = denied; llm.history = denied;
      const lookup = t.mock.method(HistoryStore.prototype, 'readSummary');
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
      currentPolicy = policy; assert.equal((await get()).status, 200);
      assert.equal((await post()).status, 200);
      const scans = app!.get(ScansService), status = scans.status.bind(scans);
      scans.status = (...args) => ({ ...status(...args), summaryTestRevision: 1 });
      try { await assertMissing(); } finally { scans.status = status; }
      assert.equal((await get()).status, 200); assert.equal((await post()).status, 200);
      currentPolicy = null; assert.equal((await get()).status, 503); currentPolicy = policy; assert.equal((await get()).status, 200);
    });

    await scopedTest('unsafe failed POST is charged but never retained; successful result is not replaced by a failure', async () => {
      const scanId = seed('unsafe'), used = quota.snapshot(owner.id, scanId).scan.used.input;
      invalid = true;
      try { const response = await post(scanId); assert.equal(response.status, 502); assert.doesNotMatch(await response.text(), /CANARY/); }
      finally { invalid = false; }
      assert.equal(quota.snapshot(owner.id, scanId).scan.used.input, used + 500); await assertMissing(scanId);
      const db = new Database(historyPath, { readonly: true });
      let deadline: number;
      try {
        const row = db.prepare('SELECT content FROM llm_summary WHERE scope=?').get(hashValue([owner.id, scanId])) as { content: string };
        const hold = JSON.parse(row.content) as { version: string; deadline: number };
        assert.equal(hold.version, 'durable-summary-reservation-v1'); deadline = hold.deadline;
      } finally { db.close(); }
      // A dispatched failure retains its slot. Advance only the synthetic clock
      // so this explicit POST can reacquire it; no deletion or quota refund.
      const clock = t.mock.method(Date, 'now', () => deadline + 1);
      let response: Response;
      try { response = await post(scanId); } finally { clock.mock.restore(); }
      assert.equal(response.status, 200); const value = await response.json();
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

    await scopedTest('policy/report/revoked-session changes before commit cannot retain a generated result', async () => {
      const scans = app!.get(ScansService), status = scans.status.bind(scans);
      for (const reason of ['policy', 'report', 'session']) {
        const scanId = seed(`before-commit-${reason}`), beforeSends = sends;
        beforeProviderReply = () => {
          if (reason === 'policy') currentPolicy = { ...policy, version: 'e'.repeat(64) };
          if (reason === 'report') scans.status = (...args) => ({ ...status(...args), summaryTestRevision: 4 });
          if (reason === 'session') app!.get(AuthStore).revoke(cookie.slice('demo_session='.length));
        };
        try {
          const response = await post(scanId);
          assert.equal(response.status, reason === 'session' ? 503 : 409);
          assert.doesNotMatch(await response.text(), /hypotheses|scannerFacts/);
        } finally {
          beforeProviderReply = undefined; currentPolicy = policy; scans.status = status;
          if (reason === 'session') renew();
        }
        await assertMissing(scanId); assert.equal(sends, beforeSends + 1);
      }
    });

    await scopedTest('POST delivery fence rechecks policy/report/session/abort after durable commit; dispatched usage remains charged', async () => {
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
        assert.equal(quota.snapshot(owner.id, scanId).scan.used.input, used + 500);
        assert.equal((await get(scanId)).status, 200, 'delivery rejection cannot undo an already committed result');
      }
    });

    await scopedTest('FULL commit precedes lost HTTP delivery; recreated runtime restores exact DTO without provider/quota', async () => {
      const scanId = seed('disconnect'), llm = app!.get(LlmService), generate = llm.summaryForBrowser.bind(llm);
      let committed: unknown, outgoing: ClientRequest;
      llm.summaryForBrowser = async (...args) => {
        const result = await generate(...args);
        committed = result.value;
        // The durable commit has returned, but the controller has not published headers.
        outgoing.destroy(new Error('synthetic client disconnect after commit'));
        return result;
      };
      try {
        const context = await (await fetch(`${path(scanId)}/context`, { headers: { cookie } })).json();
        await new Promise<void>((resolve, reject) => {
          outgoing = request(`${path(scanId)}/summary`, { method: 'POST', headers: { cookie, origin, 'content-type': 'application/json' } }, response => {
            response.resume(); reject(new Error('disconnected POST must not receive a response'));
          });
          outgoing.once('error', () => resolve());
          outgoing.end(JSON.stringify({ reportVersion: context.reportVersion, consent: { accepted: true, policyVersion: context.policyVersion } }));
        });
      } finally { llm.summaryForBrowser = generate; }
      assert.ok(committed);
      const accounted = quota.snapshot(owner.id, scanId), beforeSends = sends, beforeFactories = factories;
      await app!.close(); app = undefined; await start();
      const runtime = app!.get(LlmRuntime), quotas = app!.get(LlmQuotaRuntime);
      const provider = runtime.provider, ledger = quotas.ledger;
      runtime.provider = () => assert.fail('recovery must not construct provider');
      quotas.ledger = () => assert.fail('recovery must not access quota');
      try { await assertCached(scanId, committed); } finally { runtime.provider = provider; quotas.ledger = ledger; }
      assert.equal(sends, beforeSends); assert.equal(factories, beforeFactories);
      assert.deepEqual(quota.snapshot(owner.id, scanId), accounted);
    });

    await t.test('healthy absence alone is404; schema3 and storage faults are503 without GET migration or chat mutation', async () => {
      const historyRuntime = app!.get(HistoryRuntime), db = new Database(historyPath);
      const rows = () => ['history_meta', 'history_head', 'history_completion_space'].map(table => db.prepare(`SELECT * FROM ${table}`).all());
      const before = rows(), beforeSends = sends;
      const saved = db.prepare('SELECT * FROM llm_summary').all() as Array<{ scope: string; content: string; content_hash: string }>;
      const unavailable = async () => {
        const response = await get(); assert.equal(response.status, 503);
        assert.equal(response.headers.get('cache-control'), 'no-store');
        assert.deepEqual(await response.json(), { errorCode: 'LLM_HISTORY_UNAVAILABLE' });
      };
      try {
        historyRuntime.close(); db.exec('DROP TABLE llm_summary; PRAGMA user_version=3');
        await unavailable();
        assert.equal(db.pragma('user_version', { simple: true }), 3);
        assert.equal(db.prepare("SELECT name FROM sqlite_master WHERE name='llm_summary'").get(), undefined);
        assert.deepEqual(rows(), before);
        assert.equal((await post()).status, 503); assert.equal(sends, beforeSends);

        const operator = new HistoryStore(historyPath);
        try { operator.migrateSummarySchema(); } finally { operator.close(); }
        assert.equal(db.pragma('user_version', { simple: true }), 4, 'historical migration remains exactly3→4');
        const ordinary = saved.filter(row => JSON.parse(row.content).version === 'durable-summary-v1');
        for (const row of ordinary) db.prepare('INSERT INTO llm_summary VALUES(?,?,?)').run(row.scope, row.content, row.content_hash);
        assert.equal((await get()).status, 200, 'ordinary4 summaries remain readable');
        assert.equal((await post()).status, 503, 'schema4 cannot generate held summaries');
        assert.equal(sends, beforeSends);
        historyRuntime.close();
        HistoryStore.migrateSummaryReservations({ path: historyPath });
        assert.equal(db.pragma('user_version', { simple: true }), 5);
        for (const row of saved.filter(row => JSON.parse(row.content).version !== 'durable-summary-v1'))
          db.prepare('INSERT INTO llm_summary VALUES(?,?,?)').run(row.scope, row.content, row.content_hash);

        const scope = db.prepare('SELECT scope FROM llm_summary WHERE json_extract(content,\'$.value.scanId\')=?').get(id) as { scope: string };
        const original = db.prepare('SELECT content_hash FROM llm_summary WHERE scope=?').get(scope.scope) as { content_hash: string };
        db.prepare('UPDATE llm_summary SET content_hash=? WHERE scope=?').run('f'.repeat(64), scope.scope);
        await unavailable();
        db.prepare('UPDATE llm_summary SET content_hash=? WHERE scope=?').run(original.content_hash, scope.scope);

        db.exec('BEGIN IMMEDIATE');
        try { await unavailable(); } finally { db.exec('ROLLBACK'); }
        assert.deepEqual(rows(), before); assert.equal(sends, beforeSends);
      } finally { db.close(); }
    });

    await scopedTest('provider429 is not retained or retried; passive miss leaves dispatched unknown liability untouched', async () => {
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
    await t.test('physical-full with logical summary space refuses before provider construction or quota reservation and preserves chat padding', async () => {
      const scanId = seed('physical-full'), history = app!.get(HistoryRuntime).summaryStore(), db = new Database(historyPath);
      try {
        fillPhysicalHistory(history, db, 'f'.repeat(32));
        const before = summaryStorageRows(db), used = quota.snapshot(owner.id, scanId), legacyUsed = quota.snapshot(owner.id, legacyScan),
          beforeSends = sends, beforeFactories = factories;
        const totals = db.prepare('SELECT count(*) entries,coalesce(sum(length(CAST(content AS BLOB))),0) bytes FROM llm_summary').get() as { entries: number; bytes: number };
        assert.ok(totals.entries < 64 && totals.bytes + 69632 < 2 * 1024 * 1024, 'logical summary capacity remains available');
        const reserve = t.mock.method(quota, 'reserve', () => assert.fail('physical preflight must precede quota reservation'));
        try {
          for (const target of [scanId, legacyScan]) {
            const response = await post(target);
            assert.equal(response.status, 409, await response.clone().text());
            assert.deepEqual(await response.json(), { errorCode: 'LLM_HISTORY_CAPACITY' });
          }
          assert.equal(reserve.mock.callCount(), 0);
        } finally { reserve.mock.restore(); }
        assert.equal(sends, beforeSends); assert.equal(factories, beforeFactories);
        assert.deepEqual(quota.snapshot(owner.id, scanId), used); assert.deepEqual(quota.snapshot(owner.id, legacyScan), legacyUsed);
        assert.deepEqual(summaryStorageRows(db), before);
      } finally { db.close(); }
    });

  } finally {
    await app?.close(); quota.close();
    Object.keys(env).forEach((key, index) => { if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index]; });
    rmSync(directory, { recursive: true, force: true });
  }
});
