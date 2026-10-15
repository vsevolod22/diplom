import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { RuntimeStore, initializeRuntimeStore } from './runtime-store.js';
import { RuntimeApiService } from './runtime-api.service.js';
import type { RuntimeImageLinkAdapter } from './runtime-image-link.adapter.js';
import { createHistoricalPackage } from '../../../runtime/src/operator-package.js';
import { project } from '../../../broker/src/projection.js';
import { digest } from './runtime-evidence.js';
import type { Target } from '../../../runtime/src/contract.js';
import type { QualifiedCapturePort } from '../../../runtime/src/live-port.js';

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
  const dir = mkdtempSync(join(tmpdir(), 'runtime-rework-'));
  chmodSync(dir, 0o700);
  const path = join(dir, 'runtime.sqlite');
  initializeRuntimeStore(path);
  let now = Date.now();
  const store = new RuntimeStore(path, () => now);
  const keys = generateKeyPairSync('ed25519');
  const der = keys.publicKey.export({ format: 'der', type: 'spki' });
  const enrollment = {
    subject: 'alice',
    target,
    signerId: 'd'.repeat(32),
    publicKey: der.toString('base64'),
    fingerprint: createHash('sha256').update(der).digest('hex'),
    sourceVersion: 'operator-runtime-v1' as const,
  };
  store.enroll(enrollment);
  store.enroll({ ...enrollment, subject: 'bob' });
  const packet = (a: ReturnType<RuntimeStore['consent']>, running = true, image = false) => {
    const raw = {
      Id: target.containerId,
      Config: { User: '1000' },
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
    };
    const snapshot = project(
      raw,
      {
        epoch: 1,
        subject: a.subject,
        id: target.containerId,
        context: {
          id: target.context,
          version: 1,
          transport: 'unix',
          endpoint: '/never-used',
          apiVersion: '1.47',
        },
        grantVersion: 1,
      },
      now,
    );
    return createHistoricalPackage(
      {
        snapshot,
        startedAt: snapshot.observedAt,
        running,
        imageConfigDigest: image ? `sha256:${'c'.repeat(64)}` : null,
        imageSemantics: image ? 'docker-config-sha256-v1' : 'unknown',
        subject: a.subject,
        targetId: target.targetId,
        targetVersion: a.target.version,
        consentId: a.consentId,
        nonce: a.nonce,
        authorityEpoch: a.epoch,
        signerId: enrollment.signerId,
      },
      keys.privateKey,
    );
  };
  return {
    dir,
    path,
    store,
    enrollment,
    packet,
    advance: (ms: number) => {
      now += ms;
    },
    close: () => {
      store.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
const unusedImages = {} as RuntimeImageLinkAdapter;

test('R1 genuine and repeated authority mutations are owner/consent isolated with accurate terminal transitions', async () => {
  const f = fixture();
  try {
    const alice = f.store.consent('alice', target.targetId, 'imported-historical');
    const aliceOther = f.store.consent('alice', target.targetId, 'imported-historical');
    const bob = f.store.consent('bob', target.targetId, 'imported-historical');
    let invalidations = 0;
    const live = {
      available: () => false,
      revoke: async () => {
        invalidations++;
      },
      capture: async () => {},
    } as QualifiedCapturePort;
    const api = new RuntimeApiService(f.store, live, unusedImages);
    assert.equal((await api.revoke('alice', alice.consentId)).changed, true);
    assert.equal((await api.revoke('alice', alice.consentId)).changed, false);
    assert.equal(invalidations, 1);
    assert.equal(f.store.authority('bob', bob.consentId, 'imported-historical').nonce, bob.nonce);
    assert.equal(
      f.store.authority('alice', aliceOther.consentId, 'imported-historical').nonce,
      aliceOther.nonce,
    );
    const started = f.store.begin(
      'alice',
      '1'.repeat(32),
      digest('test', 'test'),
      aliceOther.consentId,
      'imported-historical',
    );
    assert.equal((await api.cancel('alice', started.captureId)).changed, true);
    assert.equal((await api.cancel('alice', started.captureId)).changed, false);
    assert.equal(invalidations, 2);
    assert.equal(f.store.authority('bob', bob.consentId, 'imported-historical').nonce, bob.nonce);
    const a = f.store.consent('alice', target.targetId, 'imported-historical');
    const p = f.packet(a);
    const r = api.import('alice', { idempotencyKey: '2'.repeat(32), package: p });
    await api.settled();
    const noOp = await api.cancel('alice', r.captureId);
    assert.equal(noOp.cancelled, false);
    assert.equal(noOp.state, 'completed');
    assert.equal(invalidations, 2);
    f.advance(60001);
    const failedConsent = f.store.consent('alice', target.targetId, 'imported-historical');
    const failing = f.store.begin(
      'alice',
      '3'.repeat(32),
      digest('failed', 'test'),
      failedConsent.consentId,
      'imported-historical',
    );
    f.store.fail('alice', failing.captureId, 'INDETERMINATE', 1);
    assert.deepEqual(await api.cancel('alice', failing.captureId), {
      changed: false,
      cancelled: false,
      state: 'failed',
    });
    assert.equal(invalidations, 2);
    const pendingConsent = f.store.consent('alice', target.targetId, 'imported-historical');
    const pending = f.store.begin(
      'alice',
      '4'.repeat(32),
      digest('pending', 'test'),
      pendingConsent.consentId,
      'imported-historical',
    );
    const unacked = new RuntimeApiService(
      f.store,
      {
        ...live,
        revoke: async () => {
          throw new Error('lost');
        },
      },
      unusedImages,
    );
    await assert.rejects(unacked.cancel('alice', pending.captureId), /INDETERMINATE/);
    assert.equal(f.store.read('alice', pending.captureId).state, 'cancelled');
    assert.deepEqual(await unacked.cancel('alice', pending.captureId), {
      changed: false,
      cancelled: true,
      state: 'cancelled',
    });
  } finally {
    f.close();
  }
});

test('R2 owner replay survives expiry/revoke/re-enrollment/restart with no new work or signature authority', async () => {
  const f = fixture();
  let closed = false;
  try {
    const a = f.store.consent('alice', target.targetId, 'imported-historical');
    const p = f.packet(a);
    const req = { idempotencyKey: '1'.repeat(32), package: p };
    let api = new RuntimeApiService(f.store, undefined, unusedImages);
    const receipt = api.import('alice', req);
    await api.settled();
    const original = f.store.read('alice', receipt.captureId);
    f.advance(300001);
    f.store.revoke('alice', a.consentId);
    f.store.enroll({ ...f.enrollment, target: { ...target, version: 2 } });
    assert.deepEqual(api.import('alice', req), { captureId: receipt.captureId, created: false });
    const changed = structuredClone(p);
    changed.payload.targetVersion = 2;
    changed.hash = digest(changed.payload, 'runtime-import-v1');
    assert.throws(
      () => api.import('alice', { idempotencyKey: req.idempotencyKey, package: changed }),
      /RUNTIME_CONFLICT/,
    );
    assert.throws(() => api.import('bob', req), /NOT_AUTHORIZED/);
    f.store.close();
    closed = true;
    const reopened = new RuntimeStore(f.path);
    api = new RuntimeApiService(reopened, undefined, unusedImages);
    try {
      assert.deepEqual(api.import('alice', req), { captureId: receipt.captureId, created: false });
      assert.deepEqual(reopened.read('alice', receipt.captureId), original);
    } finally {
      reopened.close();
    }
  } finally {
    if (!closed) f.store.close();
    rmSync(f.dir, { recursive: true, force: true });
  }
});

test('R3 controlled live stopped/invalid/denied outcomes survive service persistence, not uncertain success', async () => {
  const f = fixture();
  try {
    for (const reason of ['TARGET_NOT_RUNNING', 'INVALID_RUNTIME_INPUT', 'NOT_AUTHORIZED', 'INDETERMINATE']) {
      const a = f.store.consent('alice', target.targetId, 'broker-capture');
      const live = {
        available: () => true,
        revoke: async () => {},
        capture: async () => {
          throw new Error(reason);
        },
      } as QualifiedCapturePort;
      const api = new RuntimeApiService(f.store, live, unusedImages);
      const r = api.capture('alice', {
        idempotencyKey: (
          ['TARGET_NOT_RUNNING', 'INVALID_RUNTIME_INPUT', 'NOT_AUTHORIZED', 'INDETERMINATE'].indexOf(reason) +
          1
        )
          .toString()
          .repeat(32),
        targetId: target.targetId,
        consentId: a.consentId,
      });
      await api.settled();
      const result = f.store.read('alice', r.captureId);
      assert.equal(result.reason, reason);
      assert.equal(result.state, 'failed');
      assert.equal(result.evidence, null);
      f.store.revoke('alice', a.consentId);
      const deniedApi = new RuntimeApiService(f.store, undefined, unusedImages);
      const replay = deniedApi.capture('alice', {
        idempotencyKey: (
          ['TARGET_NOT_RUNNING', 'INVALID_RUNTIME_INPUT', 'NOT_AUTHORIZED', 'INDETERMINATE'].indexOf(reason) +
          1
        )
          .toString()
          .repeat(32),
        targetId: target.targetId,
        consentId: a.consentId,
      });
      assert.deepEqual(replay, { captureId: r.captureId, created: false });
      f.advance(60001);
    }
  } finally {
    f.close();
  }
});
