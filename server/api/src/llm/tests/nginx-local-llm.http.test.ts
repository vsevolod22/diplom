import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ModulesContainer, NestFactory } from '@nestjs/core';
import { NginxLocalModule } from '../../oci/nginx-local.module.js';
import { NginxLocalScansService } from '../../oci/nginx-local-profile.js';
import { NGINX_LOCAL_BINDING, NGINX_LOCAL_POLICY as local } from '../../oci/nginx-local-policy.js';
import { ScansService } from '../../scans/scans.service.js';
import { ScansController } from '../../scans/scans.controller.js';
import { BrowserScansController } from '../../scans/browser-scans.controller.js';
import { LedgerStore } from '../../ledger/ledger-store.js';
import { LlmController } from '../llm.controller.js';
import { LlmRuntime } from '../llm.service.js';
import { archiveFixture } from './fixtures.js';
import { LlmQuotaRuntime } from '../quota-runtime.js';
import { FixtureQuotaLedger as QuotaLedger } from './quota-fixtures.js';
import { quotaPolicy } from './quota-fixtures.js';

const origin = 'http://127.0.0.1:8080';

// Actual LOCAL Nest composition, disposable auth/ledger and synthetic terminal report.
// No worker/registry/model request, private env file or LIVE deployment in this test.
test('LOCAL composition registers default-off LLM routes without importing default scan composition', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'local-llm-http-'));
  const values = { AUTH_DB_PATH: join(directory, 'auth.sqlite'), SCAN_LEDGER_PATH: join(directory, 'ledger.sqlite'),
    AUTH_ORIGIN: origin, AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'false',
    SCAN_BROWSER_ALLOWED_USER_IDS: '', LLM_ENABLED: 'false' };
  const names = Object.keys(values);
  const previous = names.map(name => process.env[name]);
  Object.assign(process.env, values);
  const app = await NestFactory.create(NginxLocalModule, { logger: false });
  try {
    const service = app.get(ScansService);
    const ledger = app.get(LedgerStore).ledger!;
    const runtime = app.get(LlmRuntime);
    let providerLookups = 0;
    runtime.provider = () => { providerLookups++; throw new Error('Unexpected provider lookup in default-off fixture'); };
    assert.equal(runtime.policy(), null);
    let statusReads = 0;
    const status = service.status.bind(service);
    service.status = (...args) => { statusReads++; return status(...args); };

    await t.test('one LOCAL ScansService and one of each controller; no ScansModule or LlmModule', () => {
      assert.ok(service instanceof NginxLocalScansService);
      const modules = [...app.get(ModulesContainer).values()];
      assert.equal(modules.filter(module => module.providers.has(ScansService)).length, 1);
      assert.equal(modules.some(module => ['ScansModule', 'LlmModule'].includes(module.metatype.name)), false);
      for (const controller of [ScansController, BrowserScansController, LlmController])
        assert.equal(modules.filter(module => module.controllers.has(controller)).length, 1, controller.name);
    });

    await app.listen(0, '127.0.0.1');
    const base = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1`;
    const registered = await fetch(`${base}/auth/register`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'local-llm@example.test', password: 'synthetic-long-password-123' }) });
    assert.equal(registered.status, 201);
    const cookie = registered.headers.get('set-cookie')!.split(';')[0];
    const owner = (await registered.json() as { id: string }).id;
    process.env.SCAN_BROWSER_ALLOWED_USER_IDS = owner;

    const fixture = archiveFixture();
    const report = { ...fixture, receipt: { ...fixture.receipt, registry: local.registry, repository: local.repository,
      digest: local.digest, configDigest: local.configDigest, platform: local.platform, profileVersion: local.profileVersion },
      secret: { outcome: 'checked' as const, findings: [{ findingId: 'secret-0-0', ruleId: 'rule-0123456789abcdef',
        evidenceRef: 'result-0-secret-0', line: 1 }] } };
    const scanId = ledger.enqueue({ ...report.receipt, executionProfile: NGINX_LOCAL_BINDING, subject: owner,
      idempotencyKey: 'synthetic-local-llm-report', scope: 'image', checks: JSON.stringify(['secret']) }).scanId;
    const attempt = ledger.claim()!;
    assert.equal(ledger.finishArchive(scanId, attempt.attempts, report), true);
    const path = `${base}/browser/scans/${scanId}/llm`;
    const post = (body: unknown, session = cookie) => fetch(`${path}/summary`, { method: 'POST',
      headers: { cookie: session, origin, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const refusal = async (response: Response, expectedStatus: number, code: string) => {
      assert.equal(response.status, expectedStatus);
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.deepEqual(await response.json(), { errorCode: code });
      assert.equal(providerLookups, 0);
    };

    await t.test('context and summary are mounted: anonymous 401/no-store, not 404', async () => {
      await refusal(await fetch(`${path}/context`), 401, 'UNAUTHORIZED');
      await refusal(await post({}, ''), 401, 'UNAUTHORIZED');
    });

    await t.test('owner reads current LOCAL report with enabled=false; consent and off-config refusals precede provider', async () => {
      const before = statusReads;
      const context = await fetch(`${path}/context`, { headers: { cookie } });
      assert.equal(context.status, 200); assert.equal(context.headers.get('cache-control'), 'no-store');
      const body = await context.json() as { scanId: string; digest: string; reportVersion: string;
        enabled: boolean; policyVersion: null; disclosure: null };
      assert.equal(body.scanId, scanId); assert.equal(body.digest, local.digest);
      assert.equal(body.enabled, false); assert.equal(body.policyVersion, null); assert.equal(body.disclosure, null);
      assert.match(body.reportVersion, /^[a-f0-9]{64}$/);
      assert.ok(statusReads > before, 'ReportReader projects through the same LOCAL service instance');
      await refusal(await post({ reportVersion: body.reportVersion }), 400, 'LLM_INVALID_REQUEST');
      await refusal(await post({ reportVersion: body.reportVersion, consent: { accepted: false, policyVersion: null } }),
        403, 'LLM_CONSENT_REQUIRED');
      await refusal(await post({ reportVersion: body.reportVersion, consent: { accepted: true, policyVersion: null } }),
        503, 'LLM_CONFIGURATION_UNAVAILABLE');
      await refusal(await fetch(`${path}/summary`, { method: 'POST', headers: { cookie, origin, 'content-type': 'application/json' },
        body: '{"CANARY-private": BROKEN}' }), 400, 'LLM_INVALID_REQUEST');
      assert.equal(providerLookups, 0);
    });

    await t.test('LOCAL usage is independent owner-only GET with quotas and one existing service graph', async () => {
      const quota = new QuotaLedger(join(directory, 'llm-usage.sqlite'), quotaPolicy);
      const quotas = app.get(LlmQuotaRuntime);
      const original = quotas.ledger.bind(quotas);
      quotas.ledger = () => quota;
      try {
        await refusal(await fetch(`${path}/usage`), 401, 'UNAUTHORIZED');
        const before = await (await fetch(`${path}/context`, { headers: { cookie } })).json();
        for (const endpoint of ['usage', 'USAGE/']) {
          const response = await fetch(`${path}/${endpoint}`, { headers: { cookie } });
          assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
          const snapshot = await response.json() as { available: boolean; integrationEnabled: boolean; scanId: string };
          assert.equal(snapshot.available, true); assert.equal(snapshot.integrationEnabled, false); assert.equal(snapshot.scanId, scanId);
        }
        assert.deepEqual(await (await fetch(`${path}/context`, { headers: { cookie } })).json(), before);
        assert.equal(providerLookups, 0);
      } finally { quotas.ledger = original; quota.close(); }
    });

    await t.test('LOCAL unsupported targets/check sets reject before readiness/resolution and enqueue, even known replay key', async () => {
      let readinessCalls = 0, resolverCalls = 0;
      Object.defineProperties(service, {
        readiness: { value: async () => { readinessCalls++; return false; } },
        resolveTarget: { value: async () => { resolverCalls++; throw new Error('Unexpected target resolution'); } },
      });
      const imageReference = `${local.registry}/${local.repository}@${local.digest}`;
      for (const patch of [{ imageReference: 'registry-1.docker.io/library/node:latest' },
        { imageReference: `${local.registry}/${local.repository}@sha256:${'a'.repeat(64)}` },
        { checks: ['config'] }, { checks: ['secret', 'sbom'] }]) {
        const response = await fetch(`${base}/browser/scans`, { method: 'POST', headers: { cookie, origin, 'content-type': 'application/json' },
          body: JSON.stringify({ imageReference, checks: ['secret'], scope: 'image', idempotencyKey: 'synthetic-local-llm-report', ...patch }) });
        assert.equal(response.status, 400); assert.equal((await response.json() as { errorCode: string }).errorCode, 'UNSUPPORTED_SCAN');
      }
      assert.equal(readinessCalls, 0); assert.equal(resolverCalls, 0); assert.equal(providerLookups, 0);
      assert.equal(ledger.pending().length, 0);
      assert.equal(service.status({ subject: owner, scope: ['scan:read'] }, scanId).state, 'completed');
    });
  } finally {
    await app.close();
    names.forEach((name, index) => { if (previous[index] === undefined) delete process.env[name]; else process.env[name] = previous[index]; });
    rmSync(directory, { recursive: true, force: true });
  }
});
