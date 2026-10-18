import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, realpathSync, chmodSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { configureParentIngress } from '../parent-ingress.js';
import { AuthStore } from '../auth/auth.store.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { RuntimeApiModule } from './runtime-api.module.js';
import { RuntimeApiService } from './runtime-api.service.js';
import { RuntimeIdentity } from './browser-runtime-identity.js';
import { BrowserRuntimeController } from './browser-runtime.controller.js';
import { RuntimeStore, initializeRuntimeStore, type Authority } from './runtime-store.js';
import { RuntimeImageLinkAdapter, ownerImageJob } from './runtime-image-link.adapter.js';
import { createRuntimeIntake } from './runtime-intake.js';
import { digest } from './runtime-evidence.js';
import { createHistoricalPackage } from '../../../runtime/src/operator-package.js';
import { EXCLUSIONS, type Target } from '../../../runtime/src/contract.js';
import { parseRuntimeReport } from '../../../../src/shared/api/scans/runtimeTransport.js';
import { project } from '../../../broker/src/projection.js';

const prefix = '/api/v1/browser/runtime';
const origin = 'http://127.0.0.1:8080';
const hash = (bytes: Buffer): `sha256:${string}` =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const target: Target = {
  targetId: 'a'.repeat(32),
  containerId: 'b'.repeat(64),
  context: 'isolated-linux',
  contextVersion: 1,
  version: 1,
  importAllowed: true,
  liveAllowed: true,
};

function fixture() {
  const dir = mkdtempSync(join(realpathSync(tmpdir()), 'runtime-http-continuation-'));
  chmodSync(dir, 0o700);
  const path = join(dir, 'runtime.sqlite');
  // Only new disposable paths are installed. No ambient/private config or credentials are loaded.
  Object.assign(process.env, {
    AUTH_DB_PATH: join(dir, 'auth.sqlite'),
    SCAN_LEDGER_PATH: join(dir, 'images.sqlite'),
    RUNTIME_DB_PATH: path,
    AUTH_ORIGIN: origin,
    AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true',
    SCAN_BROWSER_ALLOWED_USER_IDS: '',
    SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'false',
  });
  initializeRuntimeStore(path, [process.env.AUTH_DB_PATH!, process.env.SCAN_LEDGER_PATH!]);
  const keys = generateKeyPairSync('ed25519');
  const der = keys.publicKey.export({ format: 'der', type: 'spki' });
  const enrollment = (subject: string) => ({
    subject,
    target,
    signerId: 'c'.repeat(32),
    publicKey: der.toString('base64'),
    fingerprint: createHash('sha256').update(der).digest('hex'),
    sourceVersion: 'operator-runtime-v1' as const,
  });
  const packet = (a: Authority, imageDigest: string | null = null) => {
    // Deliberately synthetic raw input, projected locally. This is NOT Engine evidence.
    const snapshot = project(
      {
        Id: a.target.containerId,
        Config: {
          User: '1000',
          Env: ['CONTINUATION_ENV_CANARY'],
          Labels: { private: 'CONTINUATION_LABEL_CANARY' },
        },
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
        NetworkSettings: { IPAddress: 'CONTINUATION_NETWORK_CANARY' },
      },
      {
        epoch: a.epoch,
        subject: a.subject,
        id: a.target.containerId,
        grantVersion: 1,
        context: {
          id: a.target.context,
          version: a.target.contextVersion,
          transport: 'unix',
          endpoint: '/never-contacted',
          apiVersion: '1.47',
        },
      },
      Date.now(),
    );
    return createHistoricalPackage(
      {
        snapshot,
        startedAt: snapshot.observedAt,
        running: true,
        imageConfigDigest: imageDigest,
        imageSemantics: imageDigest ? 'docker-config-sha256-v1' : 'unknown',
        subject: a.subject,
        targetId: a.target.targetId,
        targetVersion: a.target.version,
        consentId: a.consentId,
        nonce: a.nonce,
        authorityEpoch: a.epoch,
        signerId: enrollment(a.subject).signerId,
      },
      keys.privateKey,
    );
  };
  return {
    dir,
    path,
    enrollment,
    packet,
    cleanup: () => {
      rmSync(dir, { recursive: true, force: true });
      for (const key of [
        'AUTH_DB_PATH',
        'SCAN_LEDGER_PATH',
        'RUNTIME_DB_PATH',
        'AUTH_ORIGIN',
        'AUTH_ALLOW_INSECURE_LOCAL_HTTP',
        'SCAN_BROWSER_ALLOWED_USER_IDS',
        'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS',
      ])
        delete process.env[key];
    },
  };
}

function client(base: string, cookie: string) {
  return async (route: string, body?: unknown) =>
    fetch(base + prefix + route, {
      method: body === undefined ? 'GET' : 'POST',
      headers: {
        Cookie: cookie,
        ...(body === undefined ? {} : { Origin: origin, 'Content-Type': 'application/json' }),
      },
      body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
      signal: AbortSignal.timeout(5000),
    });
}

async function json(response: Response, status = 200) {
  assert.equal(response.status, status);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const text = await response.text();
  assert.ok(Buffer.byteLength(text) <= 65536);
  assert.doesNotMatch(
    text,
    /CONTINUATION_.*_CANARY|brokerSubject|privateKey|publicKey|SQLITE|\/never-contacted/,
  );
  return JSON.parse(text);
}

@Module({ imports: [RuntimeApiModule] })
class ActualRuntimeModule {}

async function bootActual() {
  const app = await NestFactory.create<NestExpressApplication>(ActualRuntimeModule, {
    logger: false,
    bodyParser: false,
    abortOnError: false,
  });
  try {
    configureParentIngress(app);
    await app.listen(0, '127.0.0.1');
    return app;
  } catch (error) {
    await app.close();
    throw error;
  }
}

test(
  'qualified-module handoff requires exact dynamic Nest selection; a denied port never advertises live',
  { timeout: 10000 },
  async () => {
    const f = fixture();
    const selected = RuntimeApiModule.withQualifiedCapture({
      available: () => false,
      revoke: async () => {
        throw new Error('NOT_AUTHORIZED');
      },
      capture: async () => {
        throw new Error('NOT_AUTHORIZED');
      },
    });
    const app = await NestFactory.createApplicationContext(selected, { logger: false, abortOnError: false });
    try {
      assert.equal(
        app.select(selected).get(RuntimeApiService, { strict: true }).capabilities().liveCapture,
        false,
      );
      // Static selection cannot substitute for this descriptor. Parent ingress now accepts the exact
      // selected dynamic module explicitly; the composition regression is in parent-ingress.runtime.test.ts.
      assert.throws(() => app.select(RuntimeApiModule));
    } finally {
      await app.close();
      f.cleanup();
    }
  },
);

test(
  'actual module + parent ingress: owner HTTP history survives restart/target replacement; live stays denied',
  { timeout: 20000 },
  async () => {
    const f = fixture();
    let app: NestExpressApplication | undefined;
    try {
      app = await bootActual();
      const auth = app.get(AuthStore);
      const owner = (await auth.register('continuation-owner@example.test', 'synthetic-only-password'))!;
      const stranger = (await auth.register('continuation-other@example.test', 'synthetic-other-password'))!;
      assert.ok(owner && stranger);
      const cookie = `demo_session=${auth.createSession(owner.id)}`;
      const otherCookie = `demo_session=${auth.createSession(stranger.id)}`;
      let api = app.get(RuntimeApiService);
      api.database().enroll(f.enrollment(owner.id));
      let http = client(await app.getUrl(), cookie);
      let other = client(await app.getUrl(), otherCookie);
      assert.deepEqual(await json(await http('/capabilities')), {
        schemaVersion: 'runtime-capabilities-v1',
        historicalImport: true,
        liveCapture: false,
        liveReason: 'QUALIFICATION_MISSING',
        host: 'not_authorized',
        rawIntake: 'authenticated-pre-json',
      });
      assert.deepEqual(await json(await other('/targets')), { targets: [] });
      await json(
        await other('/consents', { targetId: target.targetId, mode: 'imported-historical', confirmed: true }),
        403,
      );
      await json(
        await http('/consents', { targetId: target.targetId, mode: 'imported-historical', confirmed: false }),
        403,
      );
      await json(
        await http('/captures', {
          targetId: target.targetId,
          consentId: '0'.repeat(32),
          idempotencyKey: '0'.repeat(32),
        }),
        403,
      );
      await json(await client(await app.getUrl(), '')('/targets'), 401);
      await json(
        await fetch((await app.getUrl()) + prefix + '/imports', {
          method: 'POST',
          headers: { Cookie: cookie, Origin: 'https://foreign.example', 'Content-Type': 'application/json' },
          body: '{}',
          signal: AbortSignal.timeout(5000),
        }),
        403,
      );
      const consent = await json(
        await http('/consents', { targetId: target.targetId, mode: 'imported-historical', confirmed: true }),
        201,
      );
      const packet = f.packet(api.database().authority(owner.id, consent.consentId, 'imported-historical'));
      const request = { idempotencyKey: 'd'.repeat(32), package: packet };
      assert.ok(Buffer.byteLength(JSON.stringify(request)) > 1024);
      await json(await http('/imports', '{"package":{"Env":"CONTINUATION_ENV_CANARY"},"package":{}}'), 400);
      const receipt = await json(await http('/imports', request), 202);
      await api.settled();
      const report = await parseRuntimeReport(
        await json(await http(`/captures/${receipt.captureId}`)),
        owner.id,
      );
      assert.equal(report.state, 'completed');
      assert.equal(report.mode, 'imported-historical');
      assert.equal(report.evidence!.snapshot.containerId, target.containerId);
      assert.deepEqual(report.evidence!.snapshot.context, { id: target.context, version: 1 });
      assert.equal(report.evidence!.endedAt, packet.payload.capture.endedAt);
      assert.equal(report.evidence!.hash, packet.payload.capture.hash);
      assert.deepEqual(report.exclusions, EXCLUSIONS);
      const beforeEvents = await (await http(`/captures/${receipt.captureId}/events`)).text();
      assert.equal((beforeEvents.match(/event: runtime-state/g) ?? []).length, 2);
      const live = await json(
        await http('/consents', { targetId: target.targetId, mode: 'broker-capture', confirmed: true }),
        201,
      );
      assert.deepEqual(
        await json(
          await http('/captures', {
            targetId: target.targetId,
            consentId: live.consentId,
            idempotencyKey: 'e'.repeat(32),
          }),
          403,
        ),
        { errorCode: 'QUALIFICATION_MISSING' },
      );
      assert.equal((await json(await http('/captures'))).captures.length, 1);

      // Seed an interrupted admitted attempt without dispatch. Restart must not auto-recapture it.
      const interruptedConsent = api.database().consent(owner.id, target.targetId, 'broker-capture');
      const interrupted = api
        .database()
        .begin(
          owner.id,
          'f'.repeat(32),
          digest({ synthetic: true }, 'test-intent'),
          interruptedConsent.consentId,
          'broker-capture',
        );
      await app.close();
      app = undefined;
      assert.equal(existsSync(`${f.path}.writer`), false);
      const operator = new RuntimeStore(f.path);
      try {
        operator.enroll({
          ...f.enrollment(owner.id),
          target: {
            ...target,
            containerId: '1'.repeat(64),
            context: 'replacement-context',
            contextVersion: 2,
            version: 2,
          },
        });
      } finally {
        operator.close();
      }
      app = await bootActual();
      api = app.get(RuntimeApiService);
      http = client(await app.getUrl(), cookie);
      other = client(await app.getUrl(), otherCookie);
      assert.deepEqual(await json(await http(`/captures/${receipt.captureId}/results`)), report);
      assert.equal(await (await http(`/captures/${receipt.captureId}/events`)).text(), beforeEvents);
      const restarted = await json(await http(`/captures/${interrupted.captureId}`));
      assert.equal(restarted.state, 'failed');
      assert.equal(restarted.reason, 'INDETERMINATE');
      assert.equal(restarted.evidence, null);
      assert.deepEqual(await json(await http('/imports', request), 202), {
        captureId: receipt.captureId,
        created: false,
      });
      const terminalCancel = await json(await http(`/captures/${receipt.captureId}/cancel`, {}));
      assert.deepEqual(terminalCancel, { changed: false, cancelled: false, state: 'completed' });
      assert.deepEqual((await json(await http('/targets'))).targets[0].containerId, '1'.repeat(64));
      for (const route of [
        `/captures/${receipt.captureId}`,
        `/captures/${receipt.captureId}/results`,
        `/captures/${receipt.captureId}/events`,
        `/captures?cursor=${receipt.captureId}`,
      ])
        assert.deepEqual(await json(await other(route), 404), { errorCode: 'NOT_FOUND' });
      for (const route of [`/captures/${receipt.captureId}/cancel`, `/consents/${consent.consentId}/revoke`])
        assert.deepEqual(await json(await other(route, {}), 404), { errorCode: 'NOT_FOUND' });
      await json(
        await other(`/captures/${receipt.captureId}/image-links`, {
          imageScanId: '00000000-0000-0000-0000-000000000001',
        }),
        404,
      );
      assert.deepEqual(await json(await http(`/captures/${receipt.captureId}`)), report);
      // Persisted runtime bytes never contain source Env/labels/network or the import signature.
      await app.close();
      app = undefined;
      const stored = readFileSync(f.path);
      for (const canary of [
        'CONTINUATION_ENV_CANARY',
        'CONTINUATION_LABEL_CANARY',
        'CONTINUATION_NETWORK_CANARY',
        packet.signature,
      ])
        assert.equal(stored.includes(Buffer.from(canary)), false);
    } finally {
      await app?.close();
      f.cleanup();
    }
  },
);

test(
  'actual HTTP cancel/revoke fence controlled admitted rows and reject late publication after reopen',
  { timeout: 15000 },
  async () => {
    const f = fixture();
    let app: NestExpressApplication | undefined;
    try {
      app = await bootActual();
      const auth = app.get(AuthStore);
      const owner = (await auth.register('fence-owner@example.test', 'synthetic-only-password'))!;
      const cookie = `demo_session=${auth.createSession(owner.id)}`;
      let store = app.get(RuntimeApiService).database();
      store.enroll(f.enrollment(owner.id));
      const http = client(await app.getUrl(), cookie);
      const pending = [];
      for (const [index, action] of ['cancel', 'revoke'].entries()) {
        const consent = await json(
          await http('/consents', {
            targetId: target.targetId,
            mode: 'imported-historical',
            confirmed: true,
          }),
          201,
        );
        const a = store.authority(owner.id, consent.consentId, 'imported-historical');
        const packet = f.packet(a);
        // Deliberately pause at the real durable admission API; no fake live port or Engine qualification.
        const row = store.begin(
          owner.id,
          String(index + 5).repeat(32),
          digest(packet.payload, 'runtime-import-intent-v1'),
          a.consentId,
          'imported-historical',
        );
        const route =
          action === 'cancel' ? `/captures/${row.captureId}/cancel` : `/consents/${a.consentId}/revoke`;
        const response = await json(await http(route, {}));
        assert.equal(response.changed, true);
        const repeated = await json(await http(route, {}));
        assert.equal(repeated.changed, false);
        assert.equal(
          store.commit(
            owner.id,
            row.captureId,
            row.attempt,
            packet.payload.capture,
            { signerId: packet.payload.signerId, sourceVersion: packet.payload.sourceVersion },
            a.nonce,
          ),
          false,
        );
        const terminal = await json(await http(`/captures/${row.captureId}`));
        assert.equal(terminal.state, action === 'cancel' ? 'cancelled' : 'failed');
        assert.equal(terminal.evidence, null);
        pending.push({ row, packet, a, terminal });
      }
      await app.close();
      app = undefined;
      app = await bootActual();
      store = app.get(RuntimeApiService).database();
      const reopened = client(await app.getUrl(), cookie);
      for (const { row, packet, a, terminal } of pending) {
        assert.deepEqual(await json(await reopened(`/captures/${row.captureId}`)), terminal);
        assert.equal(
          store.commit(
            owner.id,
            row.captureId,
            row.attempt,
            packet.payload.capture,
            { signerId: packet.payload.signerId, sourceVersion: packet.payload.sourceVersion },
            a.nonce,
          ),
          false,
        );
        const events = await (await reopened(`/captures/${row.captureId}/events`)).text();
        assert.equal((events.match(/event: runtime-state/g) ?? []).length, 2);
      }
    } finally {
      await app?.close();
      f.cleanup();
    }
  },
);

test(
  'HTTP image association uses real owner ledger/verifier/store, preserves independent outcomes across restart',
  { timeout: 20000 },
  async () => {
    const f = fixture();
    const auth = new AuthStore();
    const images = new LedgerStore();
    let store = new RuntimeStore(f.path);
    let app: NestExpressApplication | undefined;
    let loads = 0;
    let loaderMode: 'valid' | 'wrong-platform' | 'error' = 'valid';
    const configBytes = Buffer.from(
      JSON.stringify({ os: 'linux', architecture: 'amd64', config: { User: '1000' } }),
    );
    const manifestBytes = Buffer.from(
      JSON.stringify({
        schemaVersion: 2,
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        config: {
          digest: hash(configBytes),
          size: configBytes.length,
          mediaType: 'application/vnd.oci.image.config.v1+json',
        },
        layers: [],
      }),
    );
    const adapter = RuntimeImageLinkAdapter.controlled(
      images,
      ownerImageJob(process.env.SCAN_LEDGER_PATH),
      async (job) => {
        loads++;
        if (loaderMode === 'error') throw new Error('CONTINUATION_LOADER_CANARY');
        return {
          identity: {
            registry: job.registry,
            repository: job.repository,
            manifestDigest: job.digest,
            platform: { os: 'linux', architecture: loaderMode === 'wrong-platform' ? 'arm64' : 'amd64' },
          },
          configBytes,
          manifestBytes,
        };
      },
    );
    const boot = async () => {
      const api = new RuntimeApiService(store, undefined, adapter);
      @Module({
        controllers: [BrowserRuntimeController],
        providers: [
          RuntimeIdentity,
          { provide: AuthStore, useValue: auth },
          { provide: RuntimeApiService, useValue: api },
        ],
      })
      class ControlledImageHttpModule {}
      const instance = await NestFactory.create<NestExpressApplication>(ControlledImageHttpModule, {
        logger: false,
        bodyParser: false,
      });
      instance.use(createRuntimeIntake((req) => instance.get(RuntimeIdentity).resolve(req, true)));
      instance.useBodyParser('json', { limit: '1kb' });
      api.configureRawIntake();
      await instance.listen(0, '127.0.0.1');
      return { instance, api };
    };
    try {
      const owner = (await auth.register('image-owner@example.test', 'synthetic-only-password'))!;
      const stranger = (await auth.register('image-other@example.test', 'synthetic-other-password'))!;
      const cookie = `demo_session=${auth.createSession(owner.id)}`;
      const otherCookie = `demo_session=${auth.createSession(stranger.id)}`;
      store.enroll(f.enrollment(owner.id));
      const ledger = images.ledger!;
      const imageTarget = {
        subject: owner.id,
        idempotencyKey: 'synthetic-image',
        registry: 'registry-1.docker.io',
        repository: 'library/alpine',
        digest: hash(manifestBytes),
        platform: 'linux/amd64',
        checks: '["sbom","vuln"]',
        scope: 'image',
      };
      const scanId = ledger.enqueue(imageTarget).scanId;
      const job = ledger.claim()!;
      assert.equal(job.scanId, scanId);
      assert.equal(
        ledger.finishCombined(scanId, job.attempts, [
          {
            check: 'sbom',
            outcome: 'checked',
            scannerVersion: '0.69.3',
            sbom: {
              image: `${imageTarget.registry}/${imageTarget.repository}@${imageTarget.digest}`,
              platform: 'linux/amd64',
              os: { name: 'alpine', version: '3.21.3' },
              components: [{ ecosystem: 'apk', name: 'synthetic-package', version: '1.0' }],
            },
          },
          { check: 'vuln', outcome: 'failed', errorCode: 'SCAN_FAILED' },
        ], undefined, job.leaseToken),
        true,
      );
      const foreignScanId = ledger.enqueue({
        ...imageTarget,
        subject: stranger.id,
        idempotencyKey: 'foreign-image',
      }).scanId;
      const initial = await boot();
      app = initial.instance;
      let http = client(await app.getUrl(), cookie);
      const other = client(await app.getUrl(), otherCookie);
      const consent = await json(
        await http('/consents', { targetId: target.targetId, mode: 'imported-historical', confirmed: true }),
        201,
      );
      const packet = f.packet(
        store.authority(owner.id, consent.consentId, 'imported-historical'),
        hash(configBytes),
      );
      const receipt = await json(
        await http('/imports', { idempotencyKey: '3'.repeat(32), package: packet }),
        202,
      );
      await initial.api.settled();
      const route = `/captures/${receipt.captureId}/image-links`;
      await json(await other(route, { imageScanId: scanId }), 404);
      await json(await http(route, { imageScanId: foreignScanId }), 409);
      assert.equal(loads, 0);
      loaderMode = 'error';
      assert.deepEqual(await json(await http(route, { imageScanId: scanId }), 409), {
        errorCode: 'IMAGE_LINK_UNAVAILABLE',
      });
      loaderMode = 'wrong-platform';
      await json(await http(route, { imageScanId: scanId }), 409);
      assert.deepEqual(store.read(owner.id, receipt.captureId).links, []);
      loaderMode = 'valid';
      const linked = await json(await http(route, { imageScanId: scanId }));
      assert.equal(loads, 3);
      assert.equal(linked.configDigest, hash(configBytes));
      assert.equal(linked.manifestDigest, hash(manifestBytes));
      assert.notEqual(linked.configDigest, linked.manifestDigest);
      assert.equal(linked.platform, 'linux/amd64');
      assert.equal(linked.captureHash, packet.payload.capture.hash);
      assert.equal(linked.sbom.outcome, 'checked');
      assert.equal(linked.sbom.scannerVersion, '0.69.3');
      const sbom = ledger.sbom(scanId, owner.id)!;
      assert.equal(sbom.outcome, 'checked');
      if (sbom.outcome !== 'checked') throw new Error('Expected synthetic checked SBOM');
      assert.equal(linked.sbom.checkedAt, `${sbom.checkedAt.replace(' ', 'T')}.000Z`);
      assert.equal(linked.vuln.outcome, 'failed');
      assert.equal(linked.vuln.scannerVersion, null);
      const report = await parseRuntimeReport(
        await json(await http(`/captures/${receipt.captureId}`)),
        owner.id,
      );
      assert.deepEqual(report.links, [linked]);
      const mismatchConsent = await json(
        await http('/consents', { targetId: target.targetId, mode: 'imported-historical', confirmed: true }),
        201,
      );
      const mismatchPacket = f.packet(
        store.authority(owner.id, mismatchConsent.consentId, 'imported-historical'),
        `sha256:${'9'.repeat(64)}`,
      );
      const mismatch = await json(
        await http('/imports', { idempotencyKey: '4'.repeat(32), package: mismatchPacket }),
        202,
      );
      await initial.api.settled();
      assert.deepEqual(
        await json(await http(`/captures/${mismatch.captureId}/image-links`, { imageScanId: scanId }), 409),
        { errorCode: 'IMAGE_IDENTITY_MISMATCH' },
      );
      assert.deepEqual(store.read(owner.id, mismatch.captureId).links, []);
      assert.equal(loads, 4);
      await app.close();
      app = undefined;
      store.close();
      store = new RuntimeStore(f.path);
      // Auth provider closed with Nest; reopen actual auth storage, not a fabricated identity callback.
      // A separate restart module below uses a newly opened AuthStore and the same durable cookie.
      const reopenedAuth = new AuthStore();
      const api = new RuntimeApiService(store, undefined, adapter);
      @Module({
        controllers: [BrowserRuntimeController],
        providers: [
          RuntimeIdentity,
          { provide: AuthStore, useValue: reopenedAuth },
          { provide: RuntimeApiService, useValue: api },
        ],
      })
      class RestartModule {}
      app = await NestFactory.create<NestExpressApplication>(RestartModule, {
        logger: false,
        bodyParser: false,
      });
      app.use(createRuntimeIntake((req) => app!.get(RuntimeIdentity).resolve(req, true)));
      app.useBodyParser('json', { limit: '1kb' });
      await app.listen(0, '127.0.0.1');
      http = client(await app.getUrl(), cookie);
      loaderMode = 'error';
      assert.deepEqual(await json(await http(route, { imageScanId: scanId })), linked);
      assert.equal(loads, 4, 'durable association replay must not reload or reinterpret image results');
      assert.deepEqual(await json(await http(`/captures/${receipt.captureId}`)), report);
    } finally {
      await app?.close();
      // The module owns AuthStore; the test owns only these two storage handles.
      images.onModuleDestroy();
      store.close();
      f.cleanup();
    }
  },
);
