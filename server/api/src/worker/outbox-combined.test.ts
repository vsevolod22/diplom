import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { ScanLedger } from '../ledger/ledger.js';
import { consumeOne } from './outbox-consumer.js';
import type { ImageSbom } from './cyclonedx-components.js';
import type { VulnScanOptions } from './vuln-worker.js';

const digest = `sha256:${'a'.repeat(64)}` as const;
const image = `registry-1.docker.io/library/alpine@${digest}`;
const sbom: ImageSbom = { image, platform: 'linux/amd64', os: { name: 'alpine', version: '3.21.3' },
  components: [{ ecosystem: 'apk' as const, name: 'busybox', version: '1.0' }] };
const vuln: Omit<VulnScanOptions, 'timeoutMs' | 'signal'> = { cacheDir: '/tmp/cache', releaseDir: '/release',
  trust: { trustedPublicKeyPem: 'public', expectedSigner: 'operator', expectedSource: 'source',
    expectedSchemaVersion: 2, expectedManifestDigest: `sha256:${'b'.repeat(64)}`,
    expectedArtifactSha256: 'c'.repeat(64) } };
const options = { timeoutMs: 1000, dbDir: '/tmp/cache', vuln };
async function fixture(checks: string, run: (db: ScanLedger, id: string) => Promise<void>) {
  const dir = mkdtempSync(join(tmpdir(), 'outbox-combined-'));
  const db = new ScanLedger(join(dir, 'ledger.sqlite'));
  try {
    const id = db.enqueue({ subject: 'alice', idempotencyKey: 'combined', registry: 'registry-1.docker.io',
      repository: 'library/alpine', digest, platform: 'linux/amd64', checks, scope: 'image' }).scanId;
    await run(db, id);
  } finally { db.close(); rmSync(dir, { recursive: true, force: true }); }
}

test('all three checks run sequentially with single-check views of same pinned job; mixed failure is partial', async () =>
  fixture('["secret","sbom","vuln"]', async (db, id) => {
    const seen: string[] = [];
    await consumeOne(db, options, async (job) => {
      seen.push(job.checks);
      assert.equal(job.scanId, id);
      assert.equal(job.digest, digest);
      return { ok: true, findings: [], scannerVersion: '0.69.3' };
    }, 1000, async (job) => {
      seen.push(job.checks);
      assert.equal(job.scanId, id);
      return { ok: false, errorCode: 'SCAN_TIMEOUT' };
    }, async (job) => {
      seen.push(job.checks);
      assert.equal(job.scanId, id);
      return { ok: true, findings: [], scannerVersion: '0.69.3' };
    });
    assert.deepEqual(seen, ['["secret"]', '["sbom"]', '["vuln"]']);
    assert.equal(db.state(id, 'alice'), 'partial');
    assert.equal(db.result(id, 'alice')?.outcome, 'checked');
    assert.equal(db.sbom(id, 'alice')?.outcome, 'failed');
    assert.equal(db.vuln(id, 'alice')?.outcome, 'checked');
    assert.deepEqual(db.events(id, 'alice', null)?.map(e => e.state), ['queued', 'running', 'partial']);
  }));

test('two-check failure is independent and only one combined terminal transition occurs', async () =>
  fixture('["secret","sbom"]', async (db, id) => {
    await consumeOne(db, options, async () => { throw Error('raw secret log'); }, 1000,
      async () => ({ ok: true, sbom, scannerVersion: '0.69.3' }));
    assert.equal(db.state(id, 'alice'), 'partial');
    assert.equal(db.result(id, 'alice')?.outcome, 'failed');
    assert.equal(db.sbom(id, 'alice')?.outcome, 'checked');
    assert.deepEqual(db.events(id, 'alice', null)?.map(e => e.state), ['queued', 'running', 'partial']);
  }));

test('missing vuln configuration fails that check, not preceding successful check', async () =>
  fixture('["sbom","vuln"]', async (db, id) => {
    await consumeOne(db, { timeoutMs: 1000, dbDir: '/tmp/cache' }, async () => { throw Error('secret'); },
      1000, async () => ({ ok: true, sbom, scannerVersion: '0.69.3' }),
      async () => { throw Error('must not run'); });
    assert.equal(db.state(id, 'alice'), 'partial');
    assert.equal(db.sbom(id, 'alice')?.outcome, 'checked');
    assert.equal(db.vuln(id, 'alice')?.outcome, 'failed');
  }));

test('abort mid-combination skips subsequent checks and commits nothing', async () =>
  fixture('["secret","sbom","vuln"]', async (db, id) => {
    let started!: () => void;
    const ready = new Promise<void>(resolve => { started = resolve; });
    let called = false;
    const work = consumeOne(db, options, async () => ({ ok: true, findings: [], scannerVersion: '0.69.3' }),
      1000, async (_job, config) => {
        started();
        await new Promise<void>(resolve => config.signal?.addEventListener('abort', () => resolve(), { once: true }));
        return { ok: true, sbom, scannerVersion: '0.69.3' };
      }, async () => { called = true; return { ok: true, findings: [], scannerVersion: '0.69.3' }; });
    await ready;
    db.cancel(id, 'alice');
    assert.equal(await work, true);
    assert.equal(called, false);
    assert.equal(db.result(id, 'alice'), undefined);
    assert.equal(db.sbom(id, 'alice'), undefined);
    assert.equal(db.state(id, 'alice'), 'cancelled');
  }));

test('caller abort during a combined scan skips remaining checks and leaves attempt uncommitted', async () =>
  fixture('["secret","sbom"]', async (db, id) => {
    const controller = new AbortController();
    let sbomCalled = false;
    const work = consumeOne(db, { ...options, signal: controller.signal }, async (_job, config) => {
      controller.abort();
      assert.equal(config.signal?.aborted, true);
      return { ok: true, findings: [], scannerVersion: '0.69.3' };
    }, 1000, async () => { sbomCalled = true; return { ok: true, sbom, scannerVersion: '0.69.3' }; });
    assert.equal(await work, true);
    assert.equal(sbomCalled, false);
    assert.equal(db.state(id, 'alice'), 'running');
    assert.equal(db.result(id, 'alice'), undefined);
  }));

test('replacement claim fences old combined attempt before final write', async () =>
  fixture('["secret","sbom"]', async (db, id) => {
    let started!: () => void;
    const ready = new Promise<void>(resolve => { started = resolve; });
    const first = consumeOne(db, options, async () => ({ ok: true, findings: [], scannerVersion: '0.69.3' }),
      1000, async (_job, config) => {
        started();
        await new Promise<void>(resolve => config.signal?.addEventListener('abort', () => resolve(), { once: true }));
        return { ok: true, sbom, scannerVersion: '0.69.3' };
      });
    await ready;
    const second = db.claim(34_001, 1000)!;
    assert.equal(second.attempts, 2);
    assert.equal(await first, true);
    assert.equal(db.result(id, 'alice'), undefined);
    assert.equal(db.sbom(id, 'alice'), undefined);
    assert.equal(db.attemptActive(id, second.attempts), true);
  }));
