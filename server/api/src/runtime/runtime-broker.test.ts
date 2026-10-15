import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, chmodSync, rmSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { Broker } from '../../../broker/src/broker.js';
import { AuditBuffer } from '../../../broker/src/audit.js';
import { PolicyStore, credentialDigest } from '../../../broker/src/policy.js';
import { UnixEngine } from '../../../broker/src/engine.js';
import { verifyPrivateBoundary } from '../../../broker/src/boundary.js';
import { validateCaptureHash } from './runtime-evidence.js';

test('same actual Unix HTTP fake-Engine response yields new state/image receipt without changing v1; no real fixture claim', async () => {
  const dir = mkdtempSync(join(realpathSync(join(process.cwd(), '../broker')), '.rt-'));
  chmodSync(dir, 0o700);
  const socket = join(dir, 's');
  const id = 'a'.repeat(64);
  let count = 0;
  let running: unknown = true;
  const raw = {
    Id: id,
    Config: { User: '1000', Env: ['RAW_CANARY'] },
    HostConfig: {
      Privileged: false,
      ReadonlyRootfs: true,
      CapAdd: [],
      CapDrop: [],
      SecurityOpt: [],
      NetworkMode: 'none',
      PidMode: '',
      IpcMode: 'private',
      UsernsMode: '',
      Memory: 0,
      NanoCpus: 0,
      PidsLimit: 5,
      CpuQuota: 0,
      CpuPeriod: 0,
      PortBindings: {},
    },
    Mounts: [],
    State: { Running: true },
    Image: `sha256:${'b'.repeat(64)}`,
  };
  const server = createServer((req, res) => {
    count++;
    assert.equal(req.method, 'GET');
    assert.equal(req.url, `/v1.47/containers/${id}/json`);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ...raw, State: { Running: running } }));
  });
  await new Promise<void>((resolve) => server.listen(socket, resolve));
  chmodSync(socket, 0o600);
  try {
    const policy = new PolicyStore();
    const credential = 'c'.repeat(64);
    const now = Date.now();
    policy.replace({
      version: 1,
      callers: [{ id: 'caller-a', subject: 'subject-a', digest: credentialDigest(credential) }],
      contexts: [{ id: 'context-a', version: 1, transport: 'unix', endpoint: socket, apiVersion: '1.47' }],
      consents: [
        {
          id: 'consent-a',
          caller: 'caller-a',
          subject: 'subject-a',
          version: 1,
          approved: true,
          revoked: false,
        },
      ],
      grants: [
        {
          id: 'grant-a',
          caller: 'caller-a',
          subject: 'subject-a',
          consent: 'consent-a',
          consentVersion: 1,
          context: 'context-a',
          contextVersion: 1,
          policyVersion: 1,
          version: 1,
          containerId: id,
          audience: 'inspect-broker',
          scope: 'container:inspect',
          notBefore: now,
          expiresAt: now + 60000,
          revoked: false,
        },
      ],
    });
    const engine = new UnixEngine();
    const boundary = verifyPrivateBoundary(dir, socket);
    const audit = new AuditBuffer(512);
    const make = () => new Broker({ policy, engine, boundary, audit, enabled: true });
    const target = { id, context: 'context-a', grant: 'grant-a', credential };
    const v1 = await make().handle(target, new AbortController().signal);
    assert.equal(v1.status, 'checked');
    assert.ok(v1.snapshot);
    assert.equal(Object.hasOwn(v1, 'capture'), false);
    assert.equal(Object.hasOwn(v1.snapshot, 'running'), false);
    assert.equal(count, 1);
    const extended = await make().handle(target, new AbortController().signal, () => {}, {
      binding: { nonce: 'd'.repeat(64), consentId: 'e'.repeat(32), authorityEpoch: 1 },
      imageConfigSemantics: true,
    });
    assert.equal(count, 2);
    assert.equal(engine.dispatches, 2);
    assert.ok(extended.capture);
    assert.equal(extended.capture.running, true);
    assert.equal(extended.capture.imageConfigDigest, raw.Image);
    validateCaptureHash(extended.capture);
    assert.equal(JSON.stringify(extended).includes('RAW_CANARY'), false);
    running = false;
    const stopped = await make().handle(target, new AbortController().signal, () => {}, {
      binding: { nonce: 'd'.repeat(64), consentId: 'e'.repeat(32), authorityEpoch: 1 },
      imageConfigSemantics: true,
    });
    assert.equal(stopped.capture?.running, false);
    assert.equal(count, 3);
    running = 'true';
    const invalid = await make().handle(target, new AbortController().signal, () => {}, {
      binding: { nonce: 'd'.repeat(64), consentId: 'e'.repeat(32), authorityEpoch: 1 },
      imageConfigSemantics: true,
    });
    assert.equal(invalid.status, 'failed');
    assert.equal(invalid.runtimeReason, 'INVALID_RUNTIME_INPUT');
    assert.equal(invalid.capture, undefined);
    assert.equal(count, 4);
    chmodSync(dir, 0o755);
    const denied = await make().handle(target, new AbortController().signal);
    assert.equal(denied.status, 'not_authorized');
    assert.equal(count, 4);
    assert.equal(engine.dispatches, 4);
    chmodSync(dir, 0o700);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  }
});
