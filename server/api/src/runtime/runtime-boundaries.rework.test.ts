import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, chmodSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, request } from 'node:http';
import { AuthorityQueue, type LiveIntent } from '../../../runtime/src/live-port.js';
import { dispatchPermit } from '../../../runtime/src/dispatch-permit.js';
import { CallerJournal, initializeCallerJournal } from './runtime-caller-journal.js';
import { EnrolledRuntimeCaller } from '../../../broker/src/enrolled-runtime.js';
import { verifyPrivateBoundary } from '../../../broker/src/boundary.js';
import { RuntimeApiService } from './runtime-api.service.js';
import type { RuntimeImageLinkAdapter } from './runtime-image-link.adapter.js';
import type { RuntimeStore } from './runtime-store.js';
import { createRuntimeIntake, runtimeIntake } from './runtime-intake.js';
import { verifyRuntimeReport } from '../../../../src/shared/api/scans/runtimeTransport.js';
import { parseRuntimeJson } from '../../../runtime/src/runtime-json.js';
import { project } from '../../../broker/src/projection.js';
import { createHistoricalPackage } from '../../../runtime/src/operator-package.js';
import { generateKeyPairSync } from 'node:crypto';
import {
  EXCLUSIONS,
  canonical,
  type ImageLink,
  type Report,
  type Target,
} from '../../../runtime/src/contract.js';
const target: Target = {
  targetId: 'a'.repeat(32),
  containerId: 'b'.repeat(64),
  context: 'isolated-linux',
  contextVersion: 1,
  version: 1,
  importAllowed: true,
  liveAllowed: true,
};
const intent = (): LiveIntent => ({
  subject: 'alice',
  target,
  consentId: 'c'.repeat(32),
  nonce: 'd'.repeat(64),
  expiresAt: Date.now() + 60000,
  epoch: 7,
  brokerSubject: 'broker-alice',
  captureId: 'e'.repeat(32),
  attempt: 1,
});
const raw = () => ({
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
  State: { Running: true },
});
function completed(): Report {
  const i = intent(),
    now = Date.now();
  const snapshot = project(
    raw(),
    {
      epoch: 1,
      subject: 'alice',
      id: target.containerId,
      context: { id: target.context, version: 1, transport: 'unix', endpoint: '/unused', apiVersion: '1.47' },
      grantVersion: 1,
    },
    now,
  );
  const p = createHistoricalPackage(
    {
      snapshot,
      startedAt: snapshot.observedAt,
      running: true,
      imageConfigDigest: null,
      imageSemantics: 'unknown',
      subject: 'alice',
      targetId: target.targetId,
      targetVersion: 1,
      consentId: i.consentId,
      nonce: i.nonce,
      authorityEpoch: i.epoch,
      signerId: 'f'.repeat(32),
    },
    generateKeyPairSync('ed25519').privateKey,
  );
  return {
    captureId: i.captureId,
    subject: 'alice',
    target,
    mode: 'imported-historical',
    state: 'completed',
    reason: 'READY',
    createdAt: snapshot.observedAt,
    receivedAt: snapshot.observedAt,
    consentId: i.consentId,
    checksVersion: 'runtime-config-v1',
    resourcePolicyVersion: 'runtime-host-policy-v1',
    evidence: p.payload.capture,
    provenance: { signerId: 'f'.repeat(32), sourceVersion: 'operator-runtime-v1' },
    links: [],
    exclusions: EXCLUSIONS,
  };
}
const deferred = <T>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
};

test('R4 finite16 queue rejects17th and expired queued work has zero effects', async () => {
  const queue = new AuthorityQueue(16, 25),
    hold = deferred<void>();
  let effects = 0;
  const first = queue.run(() => hold.promise);
  const waiting = Array.from({ length: 15 }, () =>
    queue.run(async () => {
      effects++;
    }),
  );
  const settled = Promise.allSettled(waiting);
  assert.equal(queue.pending, 16);
  await assert.rejects(
    queue.run(async () => {
      effects++;
    }),
    /RUNTIME_CAPACITY/,
  );
  const results = await settled;
  assert.ok(results.every((r) => r.status === 'rejected'));
  assert.equal(effects, 0);
  assert.equal(queue.pending, 1);
  hold.resolve();
  await first;
  await new Promise((r) => setTimeout(r, 0));
  await queue.run(async () => {
    effects++;
  });
  assert.equal(effects, 1);
});

test('R7 one-use exact permit/nonce/attempt guard persists across restart, scoped revoke and indeterminate decisions', () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'runtime-journal-')));
  chmodSync(dir, 0o700);
  const path = join(dir, 'caller.sqlite'),
    key = '1'.repeat(64);
  initializeCallerJournal(path);
  let journal = new CallerJournal(path, key);
  try {
    const i = intent(),
      permit = dispatchPermit(i, key);
    assert.throws(
      () => journal.consume({ ...i, target: { ...target, containerId: '0'.repeat(64) } }, permit),
      /NOT_AUTHORIZED/,
    );
    assert.throws(() => journal.consume(i, '0'.repeat(64)), /NOT_AUTHORIZED/);
    journal.consume(i, permit);
    journal.dispatched(i);
    assert.throws(() => journal.consume(i, permit), /NOT_AUTHORIZED/);
    journal.close();
    journal = new CallerJournal(path, key);
    assert.equal(journal.state(i), 'indeterminate');
    assert.throws(() => journal.consume(i, permit), /NOT_AUTHORIZED/);
    const next = { ...i, captureId: '2'.repeat(32), attempt: 2 };
    assert.throws(() => journal.consume(next, dispatchPermit(next, key)), /NOT_AUTHORIZED/);
    const bob = {
      ...intent(),
      subject: 'bob',
      consentId: '3'.repeat(32),
      nonce: '4'.repeat(64),
      captureId: '5'.repeat(32),
    };
    journal.invalidate({ subject: i.subject, consentId: i.consentId, epoch: i.epoch });
    journal.consume(bob, dispatchPermit(bob, key));
    journal.settle(bob, false);
    assert.equal(journal.state(bob), 'settled');
    const revoked = {
      ...intent(),
      consentId: '6'.repeat(32),
      nonce: '7'.repeat(64),
      captureId: '8'.repeat(32),
    };
    journal.invalidate({ subject: revoked.subject, consentId: revoked.consentId, epoch: revoked.epoch });
    assert.throws(() => journal.consume(revoked, dispatchPermit(revoked, key)), /NOT_AUTHORIZED/);
  } finally {
    journal.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('R3/R7 actual confined caller with fake transport refuses replay with zero additional sends; stopped remains explicit', async () => {
  const dir = mkdtempSync(join(realpathSync(join(process.cwd(), '../broker')), '.rt-'));
  chmodSync(dir, 0o700);
  const socket = join(dir, 'tap'),
    path = join(dir, 'caller.sqlite'),
    key = '1'.repeat(64);
  const server = createServer();
  await new Promise<void>((r) => server.listen(socket, r));
  chmodSync(socket, 0o600);
  initializeCallerJournal(path);
  const journal = new CallerJournal(path, key);
  let sends = 0;
  const acknowledgements: string[] = [];
  try {
    const caller = new EnrolledRuntimeCaller(
      { context: target.context, contextVersion: 1, tapEndpoint: socket, imageConfigSemantics: false },
      verifyPrivateBoundary(dir, socket),
      1,
      () => true,
      journal,
      {
        inspect: async (_pin, _signal, _bound, dispatch) => {
          dispatch();
          sends++;
          return Buffer.from(JSON.stringify({ ...raw(), State: { Running: false } }));
        },
      },
    );
    const i = intent();
    await assert.rejects(
      caller.inspect(
        i,
        new AbortController().signal,
        (v) => acknowledgements.push(v),
        dispatchPermit(i, key),
      ),
      /TARGET_NOT_RUNNING/,
    );
    assert.equal(sends, 1);
    assert.deepEqual(acknowledgements, ['dispatched']);
    await assert.rejects(
      caller.inspect(
        i,
        new AbortController().signal,
        (v) => acknowledgements.push(v),
        dispatchPermit(i, key),
      ),
      /NOT_AUTHORIZED/,
    );
    assert.equal(sends, 1);
    assert.deepEqual(acknowledgements, ['dispatched', 'aborted']);
  } finally {
    journal.close();
    await new Promise<void>((r) => server.close(() => r()));
    rmSync(dir, { recursive: true, force: true });
  }
});

test('R4 queued ack/revoke/publication retain FIFO order without granting a qualification permit', async () => {
  const q = new AuthorityQueue(),
    ack = deferred<void>(),
    order: string[] = [];
  const capture = q.run(async () => {
    order.push('admission');
    await ack.promise;
    order.push('ack');
  });
  const revoke = q.run(async () => {
    order.push('revoke');
  });
  const publication = q.run(async () => {
    order.push('publication');
  });
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(order, ['admission']);
  ack.resolve();
  await Promise.all([capture, revoke, publication]);
  assert.deepEqual(order, ['admission', 'ack', 'revoke', 'publication']);
});

test('R5 absolute image deadline does not release an uncooperative underlying loader slot before settlement', async () => {
  const r = completed();
  r.evidence!.imageConfigDigest = `sha256:${'2'.repeat(64)}`;
  const store = {
    read: () => r,
    admit: () => {},
    associate: () => {
      throw new Error('late publication');
    },
  } as unknown as RuntimeStore;
  const hold = deferred<ImageLink>();
  let calls = 0;
  const api = new RuntimeApiService(store, undefined, {
    resolve: async () => {
      calls++;
      return hold.promise;
    },
  } as unknown as RuntimeImageLinkAdapter);
  const imageScanId = '00000000-0000-0000-0000-000000000001';
  try {
    await assert.rejects(api.imageLink('alice', r.captureId, { imageScanId }), /IMAGE_LINK_UNAVAILABLE/);
    await assert.rejects(
      api.imageLink('alice', r.captureId, { imageScanId: '00000000-0000-0000-0000-000000000002' }),
      /RUNTIME_CAPACITY/,
    );
    assert.equal(calls, 1);
  } finally {
    hold.resolve(imageLink(imageScanId, r.evidence!.hash));
    await new Promise((q) => setTimeout(q, 0));
    api.onModuleDestroy();
  }
});

const imageLink = (id: string, captureHash: string): ImageLink => ({
  imageScanId: id,
  manifestDigest: `sha256:${'1'.repeat(64)}`,
  configDigest: `sha256:${'2'.repeat(64)}`,
  platform: 'linux/amd64',
  verificationVersion: 'image-config-chain-v1',
  captureHash,
  linkedAt: new Date().toISOString(),
  sbom: {
    outcome: 'unsupported',
    reason: 'IMAGE_RESULT_UNAVAILABLE',
    scannerVersion: null,
    checkedAt: null,
    dbEvidenceHash: null,
  },
  vuln: {
    outcome: 'failed',
    reason: 'IMAGE_RESULT_UNAVAILABLE',
    scannerVersion: null,
    checkedAt: null,
    dbEvidenceHash: null,
  },
});
test('R5 pre-I/O owner/global2/noqueue admission, coalescing, replay/full8/foreign zero-send and release on error', async () => {
  const r = completed();
  r.evidence!.imageConfigDigest = `sha256:${'2'.repeat(64)}`;
  const rows = new Map<string, Report>([
    ['alice', r],
    ['bob', { ...r, subject: 'bob' }],
    ['charlie', { ...r, subject: 'charlie' }],
  ]);
  let admitted = 0,
    calls = 0,
    active = 0,
    max = 0;
  const pending: ReturnType<typeof deferred<ImageLink>>[] = [];
  const store = {
    read: (s: string) => {
      const row = rows.get(s);
      if (!row) throw new Error('NOT_FOUND');
      return row;
    },
    admit: () => {
      admitted++;
    },
    associate: (s: string, _id: string, l: ImageLink) => {
      rows.get(s)!.links.push(l);
      return l;
    },
  } as unknown as RuntimeStore;
  const adapter = {
    resolve: async () => {
      calls++;
      active++;
      max = Math.max(max, active);
      const d = deferred<ImageLink>();
      pending.push(d);
      try {
        return await d.promise;
      } finally {
        active--;
      }
    },
  } as unknown as RuntimeImageLinkAdapter;
  const api = new RuntimeApiService(store, undefined, adapter),
    id = '00000000-0000-0000-0000-000000000001',
    other = '00000000-0000-0000-0000-000000000002';
  const a = api.imageLink('alice', r.captureId, { imageScanId: id }),
    duplicate = api.imageLink('alice', r.captureId, { imageScanId: id });
  await new Promise((q) => setTimeout(q, 0));
  assert.equal(calls, 1);
  await assert.rejects(api.imageLink('alice', r.captureId, { imageScanId: other }), /RUNTIME_CAPACITY/);
  const b = api.imageLink('bob', r.captureId, { imageScanId: id });
  await new Promise((q) => setTimeout(q, 0));
  assert.equal(calls, 2);
  await assert.rejects(api.imageLink('charlie', r.captureId, { imageScanId: id }), /RUNTIME_CAPACITY/);
  await assert.rejects(api.imageLink('foreign', r.captureId, { imageScanId: id }), /NOT_FOUND/);
  pending[0].resolve(imageLink(id, r.evidence!.hash));
  pending[1].resolve(imageLink(id, r.evidence!.hash));
  await Promise.all([a, b, duplicate]);
  assert.equal(max, 2);
  assert.equal(admitted, 2);
  await api.imageLink('alice', r.captureId, { imageScanId: id });
  assert.equal(calls, 2);
  rows.get('alice')!.links = Array.from({ length: 8 }, (_, n) =>
    imageLink(`00000000-0000-0000-0000-${String(n + 10).padStart(12, '0')}`, r.evidence!.hash),
  );
  await assert.rejects(api.imageLink('alice', r.captureId, { imageScanId: other }), /RUNTIME_CAPACITY/);
  assert.equal(calls, 2);
  const failApi = new RuntimeApiService(store, undefined, {
    resolve: async () => {
      throw new Error('IMAGE_LINK_UNAVAILABLE');
    },
  } as unknown as RuntimeImageLinkAdapter);
  await assert.rejects(
    failApi.imageLink('bob', r.captureId, { imageScanId: other }),
    /IMAGE_LINK_UNAVAILABLE/,
  );
  await assert.rejects(
    failApi.imageLink('bob', r.captureId, { imageScanId: other }),
    /IMAGE_LINK_UNAVAILABLE/,
  );
});

test('R6 no-cookie and invalid-cookie partial bodies use zero scarce slots; authenticated body succeeds; legacy hook503', async () => {
  const old = process.env.AUTH_ORIGIN,
    insecure = process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP;
  process.env.AUTH_ORIGIN = 'http://127.0.0.1:8080';
  process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true';
  let next = 0;
  const hook = createRuntimeIntake((req) => {
    if (req.headers.cookie !== 'test=valid') throw new Error('UNAUTHORIZED');
    return 'raw-owner';
  });
  const server = createServer((req, res) =>
    hook(req, res, () => {
      next++;
      res.end('{}');
    }),
  );
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const post = (cookie: string | undefined, partial: boolean) =>
    new Promise<number>((resolve, reject) => {
      const req = request(
        {
          hostname: '127.0.0.1',
          port: address.port,
          path: '/api/v1/browser/runtime/imports',
          method: 'POST',
          headers: {
            Origin: 'http://127.0.0.1:8080',
            'Content-Type': 'application/json',
            'Content-Length': 2,
            ...(cookie ? { Cookie: cookie } : {}),
          },
        },
        (res) => {
          res.resume();
          res.on('end', () => resolve(res.statusCode!));
        },
      );
      req.on('error', reject);
      if (partial) req.write('{');
      else req.end('{}');
    });
  try {
    assert.deepEqual(await Promise.all([post(undefined, true), post('test=invalid', true)]), [401, 401]);
    assert.equal(await post('test=valid', false), 200);
    assert.equal(next, 1);
    await new Promise<void>((resolve) => {
      const req = {
        url: '/api/v1/browser/runtime/imports',
        method: 'POST',
        headers: {
          origin: 'http://127.0.0.1:8080',
          'content-length': '2',
          'content-type': 'application/json',
        },
        rawHeaders: [],
        socket: {},
      };
      const res = {
        headersSent: false,
        setHeader: () => {},
        statusCode: 0,
        end: () => {
          assert.equal(res.statusCode, 503);
          resolve();
        },
      };
      runtimeIntake(req as never, res as never, () => {
        throw new Error('fallback');
      });
    });
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    if (old === undefined) delete process.env.AUTH_ORIGIN;
    else process.env.AUTH_ORIGIN = old;
    if (insecure === undefined) delete process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP;
    else process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = insecure;
  }
});

test('R8 browser canonical hash, consent/state/source/link/owner and lexical one-fault mutations fail closed', async () => {
  const r = completed();
  assert.deepEqual(await verifyRuntimeReport(r, 'alice'), r);
  for (const mutate of [
    (v: Report) => {
      v.consentId = '0'.repeat(32);
    },
    (v: Report) => {
      v.evidence!.snapshot.facts.privileged = true;
    },
    (v: Report) => {
      v.evidence!.hash = '0'.repeat(64);
    },
    (v: Report) => {
      v.state = 'cancelled';
    },
    (v: Report) => {
      v.provenance!.sourceVersion = 'wrong' as never;
    },
    (v: Report) => {
      v.target.contextVersion = 2;
    },
  ]) {
    const bad = structuredClone(r);
    mutate(bad);
    await assert.rejects(verifyRuntimeReport(bad, 'alice'), /INVALID_RUNTIME_INPUT/);
  }
  await assert.rejects(verifyRuntimeReport(r, 'bob'), /RUNTIME_ACCESS_CHANGED/);
  for (const text of ['{"epoch":1.0}', '{"epoch":1e0}', '{"a":1,"a":2}', '{"__proto__":1}'])
    assert.throws(() => parseRuntimeJson(new TextEncoder().encode(text)), /INVALID_RUNTIME_INPUT/);
  const transportText = canonical(r);
  assert.ok(transportText.length > 1024);
});
