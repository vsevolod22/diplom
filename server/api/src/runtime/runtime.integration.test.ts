import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, chmodSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { AuthStore } from '../auth/auth.store.js';
import { RuntimeIdentity } from './browser-runtime-identity.js';
import { BrowserRuntimeController } from './browser-runtime.controller.js';
import { RuntimeApiService } from './runtime-api.service.js';
import { RuntimeApiModule } from './runtime-api.module.js';
import { createHistoricalPackage } from '../../../runtime/src/operator-package.js';
import { runtimeSign } from './runtime-sign.js';
import { RuntimeImageLinkAdapter } from './runtime-image-link.adapter.js';
import { RuntimeStore, initializeRuntimeStore } from './runtime-store.js';
import { createRuntimeIntake } from './runtime-intake.js';
import { canonical, type Target } from '../../../runtime/src/contract.js';
import { digest } from './runtime-evidence.js';
import { parseRuntimeReport } from '../../../../src/shared/api/scans/runtimeTransport.js';
import { project } from '../../../broker/src/projection.js';
import type { Pin } from '../../../broker/src/policy.js';
import { SerializedCaptureCoordinator, acceptOperatorQualification } from '../../../runtime/src/live-port.js';

const target: Target = {
  targetId: 'a'.repeat(32),
  containerId: 'b'.repeat(64),
  context: 'isolated-linux',
  contextVersion: 1,
  version: 1,
  importAllowed: true,
  liveAllowed: true,
};
const subject = 'owner-a';
const raw = () => ({
  Id: target.containerId,
  Config: { User: '1000', Env: ['CANARY_PRIVATE_VALUE'] },
  HostConfig: {
    Privileged: false,
    ReadonlyRootfs: true,
    SecurityOpt: [],
    Memory: 1024,
    NanoCpus: 0,
    PidsLimit: 5,
    CpuQuota: 0,
    CpuPeriod: 0,
    NetworkMode: 'none',
    PidMode: '',
    IpcMode: 'private',
    UsernsMode: '',
    CapAdd: [],
    CapDrop: [],
    PortBindings: {},
  },
  Mounts: [],
  State: { Running: true },
  Image: `sha256:${'c'.repeat(64)}`,
});
const pin: Pin = {
  epoch: 1,
  subject,
  id: target.containerId,
  context: { id: target.context, version: 1, transport: 'unix', endpoint: '/never-used', apiVersion: '1.47' },
  grantVersion: 1,
};
function fixture(now = Date.now()) {
  const dir = mkdtempSync(join(tmpdir(), 'runtime-own-'));
  chmodSync(dir, 0o700);
  const path = join(dir, 'runtime.sqlite');
  initializeRuntimeStore(path);
  const store = new RuntimeStore(path, () => now);
  const keys = generateKeyPairSync('ed25519');
  const der = keys.publicKey.export({ type: 'spki', format: 'der' });
  const enrollment = {
    subject,
    target,
    signerId: 'd'.repeat(32),
    publicKey: der.toString('base64'),
    fingerprint: createHash('sha256').update(der).digest('hex'),
    sourceVersion: 'operator-runtime-v1' as const,
  };
  store.enroll(enrollment);
  return {
    dir,
    path,
    store,
    keys,
    enrollment,
    setNow: (value: number) => {
      now = value;
    },
  };
}
function packageFor(
  f: ReturnType<typeof fixture>,
  a: ReturnType<RuntimeStore['consent']>,
  endedAt = f.store.clock(),
) {
  const snapshot = project(raw(), pin, endedAt);
  return createHistoricalPackage(
    {
      snapshot,
      startedAt: snapshot.observedAt,
      running: true,
      imageConfigDigest: null,
      imageSemantics: 'unknown',
      subject,
      targetId: target.targetId,
      targetVersion: 1,
      consentId: a.consentId,
      nonce: a.nonce,
      authorityEpoch: a.epoch,
      signerId: f.enrollment.signerId,
    },
    f.keys.privateKey,
  );
}
const unusedImages = () =>
  ({
    resolve: async () => {
      throw new Error('unexpected image call');
    },
  }) as unknown as RuntimeImageLinkAdapter;

test('owner runtime history is chronological, byte bounded and cursor isolated across pages', async () => {
  const f = fixture();
  try {
    const api = new RuntimeApiService(f.store, undefined, unusedImages());
    const ids: string[] = [];
    for (let i = 0; i < 23; i++) {
      f.setNow(f.store.clock() + 60001);
      const a = f.store.consent(subject, target.targetId, 'imported-historical');
      const r = api.import(subject, {
        idempotencyKey: i.toString(16).padStart(32, '0'),
        package: packageFor(f, a),
      });
      await api.settled();
      ids.push(r.captureId);
    }
    const first = f.store.history(subject);
    assert.equal(first.captures.length, 20);
    assert.ok(Buffer.byteLength(canonical(first)) <= 65536);
    assert.deepEqual(
      first.captures.map((r) => r.captureId),
      [...ids].reverse().slice(0, 20),
    );
    assert.equal(first.nextCursor, first.captures.at(-1)!.captureId);
    const second = f.store.history(subject, first.nextCursor!);
    assert.deepEqual(
      second.captures.map((r) => r.captureId),
      [...ids].reverse().slice(20),
    );
    assert.equal(second.nextCursor, null);
    assert.throws(() => f.store.history('stranger', first.nextCursor!), /NOT_FOUND/);
  } finally {
    f.store.close();
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('signed historical intake is immutable through restart/replay/parser; nonce and ownership remain separate', async () => {
  const f = fixture();
  try {
    const a = f.store.consent(subject, target.targetId, 'imported-historical');
    const p = packageFor(f, a);
    const api = new RuntimeApiService(f.store, undefined, unusedImages());
    const receipt = api.import(subject, { idempotencyKey: 'e'.repeat(32), package: p });
    await api.settled();
    const first = f.store.read(subject, receipt.captureId);
    assert.equal(first.state, 'completed');
    assert.equal(first.mode, 'imported-historical');
    assert.ok(first.receivedAt);
    assert.equal(first.evidence?.running, true);
    assert.equal(first.evidence?.snapshot.facts.configuredUser, 'non-root');
    assert.equal(canonical(first).includes('CANARY'), false);
    assert.deepEqual(parseRuntimeReport(JSON.parse(canonical(first)), subject), first);
    assert.throws(() => f.store.read('owner-b', receipt.captureId), /NOT_FOUND/);
    assert.throws(
      () => api.import(subject, { idempotencyKey: 'f'.repeat(32), package: p }),
      /NOT_AUTHORIZED/,
    );
    assert.equal(api.import(subject, { idempotencyKey: 'e'.repeat(32), package: p }).created, false);
    const modified = structuredClone(p);
    modified.payload.capture.running = false;
    assert.throws(
      () => api.import(subject, { idempotencyKey: 'e'.repeat(32), package: modified }),
      /INVALID_RUNTIME_INPUT/,
    );
    f.store.close();
    const reopened = new RuntimeStore(f.path);
    try {
      assert.deepEqual(reopened.read(subject, receipt.captureId), first);
    } finally {
      reopened.close();
    }
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('signature/trust/freshness/nonce negatives never persist invalid evidence', async () => {
  const f = fixture();
  try {
    const a = f.store.consent(subject, target.targetId, 'imported-historical');
    const good = packageFor(f, a);
    const api = new RuntimeApiService(f.store, undefined, unusedImages());
    const variants = [
      { ...good, signature: 'A'.repeat(86) },
      packageFor(f, a, f.store.clock() - 300001),
      packageFor(f, a, f.store.clock() + 30001),
      { ...good, payload: { ...good.payload, subject: 'owner-b' } },
      { ...good, payload: { ...good.payload, trustKey: 'CANARY' } },
    ];
    for (const p of variants)
      assert.throws(() => api.import(subject, { idempotencyKey: 'e'.repeat(32), package: p }));
    assert.equal(f.store.history(subject).captures.length, 0);
    f.store.revoke(subject, a.consentId);
    assert.throws(
      () => api.import(subject, { idempotencyKey: 'e'.repeat(32), package: good }),
      /NOT_AUTHORIZED/,
    );
    assert.equal(f.store.history(subject).captures.length, 0);
  } finally {
    f.store.close();
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('late commit cannot overwrite cancel or revoked authority; running restart is indeterminate', async () => {
  const f = fixture();
  try {
    const a = f.store.consent(subject, target.targetId, 'imported-historical');
    const p = packageFor(f, a);
    const started = f.store.begin(
      subject,
      'e'.repeat(32),
      digest(p.payload, 'runtime-import-intent-v1'),
      a.consentId,
      'imported-historical',
    );
    f.store.cancel(subject, started.captureId);
    assert.equal(
      f.store.commit(
        subject,
        started.captureId,
        1,
        p.payload.capture,
        { signerId: f.enrollment.signerId, sourceVersion: 'operator-runtime-v1' },
        a.nonce,
      ),
      false,
    );
    assert.equal(f.store.read(subject, started.captureId).state, 'cancelled');
    const b = f.store.consent(subject, target.targetId, 'imported-historical');
    const pending = f.store.begin(
      subject,
      'f'.repeat(32),
      digest(b, 'test'),
      b.consentId,
      'imported-historical',
    );
    f.store.close();
    const recovered = new RuntimeStore(f.path);
    try {
      assert.equal(recovered.read(subject, pending.captureId).reason, 'INDETERMINATE');
      assert.equal(recovered.read(subject, pending.captureId).evidence, null);
    } finally {
      recovered.close();
    }
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('uninitialized/nonalias/single-writer store and qualification deny are fail closed', () => {
  const f = fixture();
  try {
    assert.throws(() => new RuntimeStore(f.path), /RUNTIME_UNAVAILABLE/);
    assert.throws(() => new RuntimeStore(f.path, Date.now, [f.path]), /RUNTIME_UNAVAILABLE/);
    assert.throws(
      () =>
        new SerializedCaptureCoordinator(
          {},
          {
            inspect: async () => {
              throw new Error();
            },
            invalidate: async () => {},
          },
        ),
      /QUALIFICATION_MISSING/,
    );
    assert.throws(
      () =>
        acceptOperatorQualification(
          {
            schema: 'runtime-qualification-v1',
            fixtureAccepted: true,
            applicationAccepted: true,
            protocolAccepted: true,
            platform: 'linux',
            context: target.context,
            contextVersion: 1,
            sourceHash: 'a'.repeat(64),
            topologyHash: 'b'.repeat(64),
            epoch: 1,
            expiresAt: Date.now() + 10000,
          },
          () => false,
        ),
      /QUALIFICATION_MISSING/,
    );
    const a = f.store.consent(subject, target.targetId, 'broker-capture');
    const api = new RuntimeApiService(f.store, undefined, unusedImages());
    assert.throws(
      () =>
        api.capture(subject, {
          idempotencyKey: 'e'.repeat(32),
          consentId: a.consentId,
          targetId: target.targetId,
        }),
      /QUALIFICATION_MISSING/,
    );
    assert.equal(f.store.history(subject).captures.length, 0);
  } finally {
    f.store.close();
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('operator signing accepts only sanitized owned input and a synthetic local Ed25519 key; no Engine', async () => {
  const f = fixture();
  try {
    const a = f.store.consent(subject, target.targetId, 'imported-historical');
    const p = packageFor(f, a);
    const c = p.payload.capture;
    const input = {
      snapshot: c.snapshot,
      startedAt: c.startedAt,
      running: c.running,
      imageConfigDigest: c.imageConfigDigest,
      imageSemantics: c.imageSemantics,
      subject,
      targetId: target.targetId,
      targetVersion: target.version,
      consentId: a.consentId,
      nonce: a.nonce,
      authorityEpoch: a.epoch,
      signerId: f.enrollment.signerId,
    };
    const inputPath = join(f.dir, 'sanitized.json'),
      keyPath = join(f.dir, 'synthetic-only.pem');
    writeFileSync(inputPath, canonical(input), { mode: 0o600 });
    writeFileSync(keyPath, f.keys.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
    const packet = JSON.parse(runtimeSign(['--authorize-runtime-sign', inputPath, keyPath]));
    assert.deepEqual(packet, p);
    const api = new RuntimeApiService(f.store, undefined, unusedImages());
    const receipt = api.import(subject, { idempotencyKey: 'e'.repeat(32), package: packet });
    await api.settled();
    assert.equal(f.store.read(subject, receipt.captureId).state, 'completed');
    assert.throws(
      () => runtimeSign(['--no-opt-in', inputPath, keyPath]),
      /EXPLICIT_RUNTIME_AUTHORIZATION_REQUIRED/,
    );
    writeFileSync(inputPath, canonical({ ...input, snapshot: { ...c.snapshot, Env: ['CANARY_PRIVATE'] } }));
    assert.throws(
      () => runtimeSign(['--authorize-runtime-sign', inputPath, keyPath]),
      /INVALID_RUNTIME_INPUT/,
    );
    chmodSync(keyPath, 0o644);
    assert.throws(
      () => runtimeSign(['--authorize-runtime-sign', inputPath, keyPath]),
      /INVALID_RUNTIME_INPUT/,
    );
  } finally {
    f.store.close();
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('actual runtime module bootstraps default-deny and explicit initialized store without auto-init or Engine', async () => {
  const f = fixture();
  f.store.close();
  const previous = {
    AUTH_DB_PATH: process.env.AUTH_DB_PATH,
    RUNTIME_DB_PATH: process.env.RUNTIME_DB_PATH,
    SCAN_LEDGER_PATH: process.env.SCAN_LEDGER_PATH,
  };
  process.env.AUTH_DB_PATH = join(f.dir, 'auth.sqlite');
  delete process.env.RUNTIME_DB_PATH;
  delete process.env.SCAN_LEDGER_PATH;
  try {
    const absent = await NestFactory.createApplicationContext(RuntimeApiModule, {
      logger: false,
      abortOnError: false,
    });
    try {
      const api = absent.get(RuntimeApiService);
      assert.equal(api.capabilities().historicalImport, false);
      assert.equal(api.capabilities().liveCapture, false);
      assert.throws(() => api.database(), /RUNTIME_UNAVAILABLE/);
    } finally {
      await absent.close();
    }
    process.env.RUNTIME_DB_PATH = join(f.dir, 'missing.sqlite');
    const missing = await NestFactory.createApplicationContext(RuntimeApiModule, {
      logger: false,
      abortOnError: false,
    });
    try {
      assert.equal(missing.get(RuntimeApiService).capabilities().historicalImport, false);
      assert.equal(existsSync(process.env.RUNTIME_DB_PATH!), false);
    } finally {
      await missing.close();
    }
    process.env.RUNTIME_DB_PATH = f.path;
    const ready = await NestFactory.createApplicationContext(RuntimeApiModule, {
      logger: false,
      abortOnError: false,
    });
    try {
      const api = ready.get(RuntimeApiService);
      assert.equal(api.capabilities().historicalImport, true);
      assert.equal(api.capabilities().liveCapture, false);
      assert.equal(api.database().targets(subject).length, 1);
    } finally {
      await ready.close();
    }
    const deniedPort = {
      available: () => false,
      revoke: async () => {},
      capture: async () => {
        throw new Error('QUALIFICATION_MISSING');
      },
    };
    const configured = await NestFactory.createApplicationContext(
      RuntimeApiModule.withQualifiedCapture(deniedPort),
      { logger: false, abortOnError: false },
    );
    try {
      assert.equal(configured.get(RuntimeApiService).live, deniedPort);
      assert.equal(configured.get(RuntimeApiService).capabilities().liveCapture, false);
    } finally {
      await configured.close();
    }
  } finally {
    rmSync(f.dir, { recursive: true, force: true });
    for (const [k, v] of Object.entries(previous)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});

test('freshness inclusive bounds, idempotency conflicts, revoke at commit and rejected authority roll back', async () => {
  const f = fixture();
  try {
    const a = f.store.consent(subject, target.targetId, 'imported-historical');
    const api = new RuntimeApiService(f.store, undefined, unusedImages());
    const packet = packageFor(f, a, f.store.clock() - 300000);
    const result = api.import(subject, { idempotencyKey: 'e'.repeat(32), package: packet });
    await api.settled();
    assert.equal(f.store.read(subject, result.captureId).state, 'completed');
    const b = f.store.consent(subject, target.targetId, 'imported-historical');
    assert.throws(
      () => api.import(subject, { idempotencyKey: 'e'.repeat(32), package: packageFor(f, b) }),
      /RUNTIME_CONFLICT/,
    );
    const next = api.import(subject, {
      idempotencyKey: 'f'.repeat(32),
      package: packageFor(f, b, f.store.clock() + 30000),
    });
    await api.settled();
    assert.equal(f.store.read(subject, next.captureId).state, 'completed');
    const c = f.store.consent(subject, target.targetId, 'imported-historical');
    const pending = api.import(subject, { idempotencyKey: '0'.repeat(32), package: packageFor(f, c) });
    f.store.revoke(subject, c.consentId);
    await api.settled();
    assert.equal(f.store.read(subject, pending.captureId).state, 'failed');
    assert.equal(f.store.read(subject, pending.captureId).evidence, null);
    const d = f.store.consent(subject, target.targetId, 'imported-historical');
    const p = packageFor(f, d);
    const begun = f.store.begin(
      subject,
      '1'.repeat(32),
      digest(p.payload, 'runtime-import-intent-v1'),
      d.consentId,
      'imported-historical',
    );
    assert.throws(
      () =>
        f.store.commit(
          subject,
          begun.captureId,
          1,
          p.payload.capture,
          { signerId: '0'.repeat(32), sourceVersion: 'operator-runtime-v1' },
          d.nonce,
        ),
      /NOT_AUTHORIZED/,
    );
    assert.equal(f.store.events(subject, begun.captureId, 0).length, 1);
    assert.equal(f.store.authority(subject, d.consentId, 'imported-historical').nonce, d.nonce);
    assert.equal(
      f.store.commit(
        subject,
        begun.captureId,
        1,
        p.payload.capture,
        { signerId: f.enrollment.signerId, sourceVersion: 'operator-runtime-v1' },
        d.nonce,
      ),
      true,
    );
    assert.equal(f.store.events(subject, begun.captureId, 0).length, 2);
  } finally {
    f.store.close();
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('actual Nest cookie+Origin import above 1KiB -> durable owner report -> strict browser parser and SSE replay', async () => {
  const f = fixture();
  const previous = {
    AUTH_DB_PATH: process.env.AUTH_DB_PATH,
    AUTH_ORIGIN: process.env.AUTH_ORIGIN,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP: process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP,
  };
  process.env.AUTH_DB_PATH = join(f.dir, 'auth.sqlite');
  process.env.AUTH_ORIGIN = 'http://127.0.0.1:8080';
  process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true';
  const auth = new AuthStore();
  const user = await auth.register('runtime-own@example.test', 'own-fixture-password');
  assert.ok(user);
  const cookie = `demo_session=${auth.createSession(user.id)}`;
  f.store.enroll({ ...f.enrollment, subject: user.id });
  const api = new RuntimeApiService(f.store, undefined, unusedImages());
  @Module({
    controllers: [BrowserRuntimeController],
    providers: [
      RuntimeIdentity,
      { provide: AuthStore, useValue: auth },
      { provide: RuntimeApiService, useValue: api },
    ],
  })
  class TestModule {}
  const app = await NestFactory.create<NestExpressApplication>(TestModule, {
    logger: false,
    bodyParser: false,
  });
  app.use(createRuntimeIntake((req) => app.get(RuntimeIdentity).resolve(req, true)));
  app.useBodyParser('json', { limit: '1kb' });
  await app.listen(0, '127.0.0.1');
  const base = await app.getUrl();
  const path = '/api/v1/browser/runtime';
  const post = async (route: string, body: unknown, withCookie = cookie, origin = 'http://127.0.0.1:8080') =>
    fetch(base + path + route, {
      method: 'POST',
      headers: { Cookie: withCookie, Origin: origin, 'Content-Type': 'application/json' },
      body: typeof body === 'string' ? body : JSON.stringify(body),
    });
  try {
    const cResponse = await post('/consents', {
      targetId: target.targetId,
      mode: 'imported-historical',
      confirmed: true,
    });
    assert.equal(cResponse.status, 201);
    const c = (await cResponse.json()) as ReturnType<RuntimeStore['consent']>;
    const authority = f.store.authority(user.id, c.consentId, 'imported-historical');
    const packet = packageFor(f, authority);
    packet.payload.subject = user.id;
    packet.hash = digest(packet.payload, 'runtime-import-v1');
    packet.signature = sign(
      null,
      Buffer.from(`runtime-import-v1\n${canonical(packet.payload)}`),
      f.keys.privateKey,
    ).toString('base64url');
    const request = { idempotencyKey: 'e'.repeat(32), package: packet };
    assert.ok(Buffer.byteLength(JSON.stringify(request)) > 1024);
    assert.equal((await post('/imports', request, cookie, 'https://wrong.example')).status, 403);
    assert.equal((await post('/imports', request, '')).status, 401);
    assert.equal(
      (await post('/imports', JSON.stringify(request).replace('"targetVersion":1', '"targetVersion":1.0')))
        .status,
      400,
    );
    assert.equal((await post('/imports', '{"a":1,"a":2}')).status, 400);
    assert.equal((await post('/imports', ' '.repeat(65537))).status, 413);
    const controlBody = JSON.stringify({
      targetId: target.targetId,
      mode: 'imported-historical',
      confirmed: true,
    });
    assert.equal((await post('/consents', controlBody.padEnd(1024, ' '))).status, 201);
    assert.equal((await post('/consents', controlBody.padEnd(1025, ' '))).status, 413);
    const accepted = await post('/imports', request);
    assert.equal(accepted.status, 202);
    const receipt = (await accepted.json()) as { captureId: string };
    await api.settled();
    const response = await fetch(`${base}${path}/captures/${receipt.captureId}`, {
      headers: { Cookie: cookie },
    });
    assert.equal(response.status, 200);
    const result = parseRuntimeReport(await response.json(), user.id);
    const boundary = await post('/imports', JSON.stringify(request).padEnd(65536, ' '));
    assert.equal(boundary.status, 202);
    assert.equal(((await boundary.json()) as { created: boolean }).created, false);
    assert.equal(result.mode, 'imported-historical');
    assert.equal(result.state, 'completed');
    assert.equal(canonical(result).includes('CANARY'), false);
    f.setNow(f.store.clock() + 300001);
    f.store.revoke(user.id, c.consentId);
    f.store.enroll({ ...f.enrollment, subject: user.id, target: { ...target, version: 2 } });
    const expiredReplay = await post('/imports', request);
    assert.equal(expiredReplay.status, 202);
    assert.deepEqual(await expiredReplay.json(), { captureId: receipt.captureId, created: false });
    assert.deepEqual(f.store.read(user.id, receipt.captureId), result);
    const events = await fetch(`${base}${path}/captures/${receipt.captureId}/events`, {
      headers: { Cookie: cookie },
    });
    const text = await events.text();
    assert.match(text, /event: runtime-state/);
    const ids = [...text.matchAll(/id: (\d+)/g)].map((m) => Number(m[1]));
    assert.equal(ids.length, 2);
    const resumed = await fetch(`${base}${path}/captures/${receipt.captureId}/events`, {
      headers: { Cookie: cookie, 'Last-Event-ID': String(ids[0]) },
    });
    const replay = await resumed.text();
    assert.equal([...replay.matchAll(/id: (\d+)/g)].length, 1);
    assert.match(replay, /completed/);
    const stranger = await auth.register('other-own@example.test', 'another-own-password');
    assert.ok(stranger);
    const otherCookie = `demo_session=${auth.createSession(stranger.id)}`;
    assert.equal(
      (await fetch(`${base}${path}/captures/${receipt.captureId}`, { headers: { Cookie: otherCookie } }))
        .status,
      404,
    );
    assert.equal(
      (
        await fetch(`${base}${path}/captures/${receipt.captureId}/events`, {
          headers: { Cookie: otherCookie },
        })
      ).status,
      404,
    );
    const noHook = await NestFactory.create<NestExpressApplication>(TestModule, {
      logger: false,
      bodyParser: false,
    });
    noHook.useBodyParser('json', { limit: '1kb' });
    await noHook.listen(0, '127.0.0.1');
    try {
      const unhooked = await fetch((await noHook.getUrl()) + path + '/consents', {
        method: 'POST',
        headers: { Cookie: cookie, Origin: 'http://127.0.0.1:8080', 'Content-Type': 'application/json' },
        body: controlBody,
      });
      assert.equal(unhooked.status, 503);
      assert.equal(
        ((await unhooked.json()) as { errorCode: string }).errorCode,
        'RUNTIME_RAW_INTAKE_REQUIRED',
      );
    } finally {
      await noHook.close();
    }
  } finally {
    await app.close();
    auth.onModuleDestroy();
    f.store.close();
    rmSync(f.dir, { recursive: true, force: true });
    for (const [k, v] of Object.entries(previous)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});
