import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { ScanLedger } from '../ledger/ledger.js';
import type { ImageSbom } from './cyclonedx-components.js';
import { consumeOne } from './outbox-consumer.js';

const options = { timeoutMs: 1000, dbDir: '/tmp/cache' };
const digest = `sha256:${'a'.repeat(64)}` as const;
const image = `registry-1.docker.io/library/alpine@${digest}`;
const sbom: ImageSbom = { image, platform: 'linux/amd64', os: { name: 'alpine', version: '3.21.3' },
  components: [{ ecosystem: 'apk', name: 'alpine-baselayout', version: '3.6.8-r1' }] };

async function fixture(run: (db: ScanLedger, scanId: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), 'outbox-sbom-'));
  const db = new ScanLedger(join(dir, 'ledger.sqlite'));
  try {
    const { scanId } = db.enqueue({ subject: 'alice', idempotencyKey: 'sbom', registry: 'registry-1.docker.io',
      repository: 'library/alpine', digest, platform: 'linux/amd64', checks: '["sbom"]', scope: 'image' });
    await run(db, scanId);
  } finally { db.close(); rmSync(dir, { recursive: true, force: true }); }
}

const secretMustNotRun = async (): Promise<never> => { throw new Error('secret runner called for SBOM'); };

test('SBOM success routes to bounded runner and persists only allowlisted components', async () => fixture(async (db, scanId) => {
  assert.equal(await consumeOne(db, options, secretMustNotRun, 1000, async (job, runOptions) => {
    assert.equal(job.scanId, scanId);
    assert.equal(job.checks, '["sbom"]');
    assert.deepEqual({ timeoutMs: runOptions.timeoutMs, cacheDir: runOptions.cacheDir },
      { timeoutMs: 1000, cacheDir: '/tmp/cache' });
    assert.equal(runOptions.signal?.aborted, false);
    return { ok: true, sbom, scannerVersion: '0.69.3' };
  }), true);
  assert.equal(db.state(scanId, 'alice'), 'completed');
  assert.deepEqual(db.sbom(scanId, 'alice')?.components, sbom.components);
  assert.equal(db.result(scanId, 'alice'), undefined);
  assert.deepEqual(db.events(scanId, 'alice', null)?.map(event => event.state), ['queued', 'running', 'completed']);
}));

test('SBOM scanner failure and exception fail closed without a false secret failure', async () => {
  const failures = [async () => ({ ok: false as const, errorCode: 'SCAN_TIMEOUT' as const }),
    async (): Promise<never> => { throw new Error('raw scanner diagnostics'); }];
  for (const failure of failures) {
    await fixture(async (db, scanId) => {
      assert.equal(await consumeOne(db, options, secretMustNotRun, 1000, failure), true);
      assert.equal(db.state(scanId, 'alice'), 'failed');
      assert.equal(db.result(scanId, 'alice'), undefined);
      const coverage = db.sbom(scanId, 'alice');
      assert.equal(coverage?.outcome, 'failed');
      if (coverage?.outcome !== 'failed') throw new Error('Expected failed SBOM coverage');
      assert.equal(coverage.errorCode, failure === failures[0] ? 'SCAN_TIMEOUT' : 'SCAN_FAILED');
      assert.equal(db.pending().length, 0);
      assert.deepEqual(db.events(scanId, 'alice', null)?.map(event => event.state), ['queued', 'running', 'failed']);
    });
  }
});

test('stale SBOM attempt cannot publish after a replacement claim', async () => fixture(async (db, scanId) => {
  let started!: () => void;
  const ready = new Promise<void>(resolve => { started = resolve; });
  const first = consumeOne(db, options, secretMustNotRun, 1000, async (_job, runOptions) => {
    started();
    await new Promise<void>(resolve => runOptions.signal?.addEventListener('abort', () => resolve(), { once: true }));
    return { ok: true, sbom, scannerVersion: '0.69.3' };
  });
  await ready;
  const second = db.claim(32_000, 1000)!;
  assert.equal(second.attempts, 2);
  assert.equal(await first, true);
  assert.equal(db.sbom(scanId, 'alice'), undefined);
  assert.equal(db.attemptActive(scanId, second.attempts), true);
  assert.equal(db.finishWithSbom(scanId, second.attempts, sbom, '0.69.3'), true);
  assert.equal(db.state(scanId, 'alice'), 'completed');
}));

test('cancel aborts SBOM runner and cannot publish a late success', async () => fixture(async (db, scanId) => {
  let started!: () => void;
  const ready = new Promise<void>(resolve => { started = resolve; });
  let signal: AbortSignal | undefined;
  const work = consumeOne(db, options, secretMustNotRun, 1000, async (_job, runOptions) => {
    signal = runOptions.signal;
    started();
    return new Promise(() => {}); // An uncooperative runner must not hold the consumer.
  });
  await ready;
  assert.equal(db.cancel(scanId, 'alice'), 'cancelled');
  assert.equal(await work, true);
  assert.equal(signal?.aborted, true);
  assert.equal(db.state(scanId, 'alice'), 'cancelled');
  assert.equal(db.sbom(scanId, 'alice'), undefined);
  assert.equal(db.result(scanId, 'alice'), undefined);
}));
