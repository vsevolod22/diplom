import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test, type TestContext } from 'node:test';
import { mkdtempSync, realpathSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { Module, type DynamicModule } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { configureParentIngress } from './parent-ingress.js';
import { AuthStore } from './auth/auth.store.js';
import { RuntimeApiModule } from './runtime/runtime-api.module.js';
import { RuntimeApiService } from './runtime/runtime-api.service.js';
import { initializeRuntimeStore } from './runtime/runtime-store.js';
import type { QualifiedCapturePort } from '../../runtime/src/live-port.js';

const origin = 'http://127.0.0.1:8080';
const prefix = '/api/v1/browser/runtime';
const target = {
  targetId: 'a'.repeat(32),
  containerId: 'b'.repeat(64),
  context: 'isolated-linux',
  contextVersion: 1,
  version: 1,
  importAllowed: true,
  liveAllowed: true,
};

function deniedPort() {
  let dispatches = 0;
  const port: QualifiedCapturePort = Object.freeze({
    available: () => false,
    revoke: async () => {
      throw new Error('NOT_AUTHORIZED');
    },
    capture: async () => {
      dispatches++;
      throw new Error('NOT_AUTHORIZED');
    },
  });
  return { port, dispatches: () => dispatches };
}

async function application(
  t: TestContext,
  imports: (typeof RuntimeApiModule | DynamicModule)[],
  withStore = true,
) {
  const dir = mkdtempSync(join(realpathSync(tmpdir()), 'runtime-parent-composition-'));
  chmodSync(dir, 0o700);
  // Never inherit a real database path; this test process uses only new disposable stores.
  const env = {
    AUTH_DB_PATH: join(dir, 'auth.sqlite'),
    RUNTIME_DB_PATH: withStore ? join(dir, 'runtime.sqlite') : '',
    SCAN_LEDGER_PATH: '',
    AUTH_ORIGIN: origin,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true',
    SCAN_BROWSER_ALLOWED_USER_IDS: '',
    SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'false',
  };
  Object.assign(process.env, env);
  const resources: { app?: NestExpressApplication } = {};
  t.after(async () => {
    try {
      await resources.app?.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
      for (const key of Object.keys(env)) delete process.env[key];
    }
  });
  if (withStore) initializeRuntimeStore(env.RUNTIME_DB_PATH, [env.AUTH_DB_PATH]);
  @Module({ imports })
  class Root {}
  const app = await NestFactory.create<NestExpressApplication>(Root, {
    logger: false,
    bodyParser: false,
    abortOnError: false,
  });
  resources.app = app;
  return app;
}

for (const kind of ['default', 'dynamic'] as const) {
  test(
    `parent ingress ${kind}: real Nest selection preserves authenticated pre-JSON guard and live denial`,
    { timeout: 15000 },
    async (t) => {
      const denied = deniedPort();
      const selected =
        kind === 'default' ? RuntimeApiModule : RuntimeApiModule.withQualifiedCapture(denied.port);
      const app = await application(t, [selected]);
      // Exercise the unchanged no-argument production call as well as the exact dynamic descriptor.
      if (kind === 'default') configureParentIngress(app);
      else configureParentIngress(app, selected);
      const service = app.select(selected).get(RuntimeApiService, { strict: true });
      assert.equal(service.live, kind === 'default' ? undefined : denied.port);
      assert.equal(service.capabilities().rawIntake, 'authenticated-pre-json');
      assert.equal(service.capabilities().liveCapture, false);
      const auth = app.get(AuthStore);
      const owner = (await auth.register(`parent-${kind}@example.test`, 'synthetic-composition-password'))!;
      assert.ok(owner);
      const cookie = `demo_session=${auth.createSession(owner.id)}`;
      const { publicKey } = generateKeyPairSync('ed25519');
      const der = publicKey.export({ type: 'spki', format: 'der' });
      service
        .database()
        .enroll({
          subject: owner.id,
          target,
          signerId: 'c'.repeat(32),
          publicKey: der.toString('base64'),
          fingerprint: createHash('sha256').update(der).digest('hex'),
          sourceVersion: 'operator-runtime-v1',
        });
      await app.listen(0, '127.0.0.1');
      const base = (await app.getUrl()) + prefix;
      const post = (route: string, body: string, headers: Record<string, string> = {}) =>
        fetch(base + route, {
          method: 'POST',
          headers: { Cookie: cookie, Origin: origin, 'Content-Type': 'application/json', ...headers },
          body,
          signal: AbortSignal.timeout(3000),
        });
      const response = async (r: Response, expected: number) => {
        assert.equal(r.status, expected);
        assert.equal(r.headers.get('cache-control'), 'no-store');
        return r.json();
      };
      // If the ordinary JSON parser ran first these would be parser400, not auth401/Origin403.
      await response(await post('/consents', '{', { Cookie: '' }), 401);
      await response(await post('/consents', '{', { Origin: 'https://foreign.example' }), 403);
      const consentBody = JSON.stringify({
        targetId: target.targetId,
        mode: 'broker-capture',
        confirmed: true,
      });
      await response(
        await post(
          '/consents',
          consentBody.replace('"confirmed":true', '"confirmed":false,"confirmed":true'),
        ),
        400,
      );
      const consent = await response(await post('/consents', consentBody.padEnd(1024, ' ')), 201);
      await response(await post('/consents', consentBody.padEnd(1025, ' ')), 413);
      // The raw import limit remains distinct from controls; an in-limit invalid DTO reaches its service.
      assert.deepEqual(await response(await post('/imports', '{}'.padEnd(65536, ' ')), 400), {
        errorCode: 'INVALID_RUNTIME_INPUT',
      });
      await response(await post('/imports', '{}'.padEnd(65537, ' ')), 413);
      assert.deepEqual(
        await response(
          await post(
            '/captures',
            JSON.stringify({
              targetId: target.targetId,
              consentId: consent.consentId,
              idempotencyKey: 'd'.repeat(32),
            }),
          ),
          403,
        ),
        { errorCode: 'QUALIFICATION_MISSING' },
      );
      const caps = await response(
        await fetch(base + '/capabilities', {
          headers: { Cookie: cookie },
          signal: AbortSignal.timeout(3000),
        }),
        200,
      );
      assert.equal(caps.liveCapture, false);
      assert.equal(caps.rawIntake, 'authenticated-pre-json');
      assert.equal(denied.dispatches(), 0);
      assert.deepEqual(service.database().history(owner.id), { captures: [], nextCursor: null });
    },
  );
}

test(
  'explicit unregistered dynamic module never falls back to the imported static module',
  { timeout: 10000 },
  async (t) => {
    const app = await application(t, [RuntimeApiModule]);
    const absent = RuntimeApiModule.withQualifiedCapture(deniedPort().port);
    const service = app.select(RuntimeApiModule).get(RuntimeApiService, { strict: true });
    assert.throws(() => configureParentIngress(app, absent));
    assert.equal(service.capabilities().rawIntake, 'parent-bootstrap-required');
    configureParentIngress(app);
    assert.equal(service.capabilities().rawIntake, 'authenticated-pre-json');
  },
);

test(
  'dynamic-only composition requires its registered descriptor; omitted or rebuilt selections fail closed',
  { timeout: 10000 },
  async (t) => {
    const selected = RuntimeApiModule.withQualifiedCapture(deniedPort().port);
    const app = await application(t, [selected]);
    const service = app.select(selected).get(RuntimeApiService, { strict: true });
    assert.throws(() => configureParentIngress(app));
    assert.throws(() =>
      configureParentIngress(app, RuntimeApiModule.withQualifiedCapture(deniedPort().port)),
    );
    assert.equal(service.capabilities().rawIntake, 'parent-bootstrap-required');
    configureParentIngress(app, selected);
    assert.equal(service.capabilities().rawIntake, 'authenticated-pre-json');
  },
);

test(
  'when both runtime variants exist, configuration marks only the explicitly selected module',
  { timeout: 10000 },
  async (t) => {
    const selected = RuntimeApiModule.withQualifiedCapture(deniedPort().port);
    // No runtime DB: this tests module identity, not concurrent writers or a recommended deployment.
    const app = await application(t, [RuntimeApiModule, selected], false);
    const normal = app.select(RuntimeApiModule).get(RuntimeApiService, { strict: true });
    const dynamic = app.select(selected).get(RuntimeApiService, { strict: true });
    assert.notEqual(normal, dynamic);
    configureParentIngress(app, selected);
    assert.equal(dynamic.capabilities().rawIntake, 'authenticated-pre-json');
    assert.equal(normal.capabilities().rawIntake, 'parent-bootstrap-required');
    assert.equal(dynamic.capabilities().liveCapture, false);
    assert.equal(normal.capabilities().liveCapture, false);
  },
);
