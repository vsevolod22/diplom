import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { ScanLedger } from '../ledger/ledger.js';
import { consumeOne } from './outbox-consumer.js';
import type { VulnScanOptions } from './vuln-worker.js';

const digest = `sha256:${'a'.repeat(64)}` as const;
const image = `registry-1.docker.io/library/alpine@${digest}`;
const vuln: Omit<VulnScanOptions, 'timeoutMs' | 'signal'> = {
  cacheDir: '/tmp/cache', releaseDir: '/releases/pinned', trust: {
    trustedPublicKeyPem: 'public-only', expectedSigner: 'local-db-operator-v1',
    expectedSource: `ghcr.io/aquasecurity/trivy-db@sha256:${'b'.repeat(64)}`,
    expectedSchemaVersion: 2, expectedManifestDigest: `sha256:${'b'.repeat(64)}`,
    expectedArtifactSha256: 'c'.repeat(64),
  },
};
const options = { timeoutMs: 1000, dbDir: '/tmp/cache', vuln };
const noSecret = async (): Promise<never> => { throw Error('secret called'); };
const noSbom = async (): Promise<never> => { throw Error('sbom called'); };
async function fixture(run: (db: ScanLedger, id: string) => Promise<void>) {
  const dir = mkdtempSync(join(tmpdir(), 'outbox-vuln-'));
  const db = new ScanLedger(join(dir, 'ledger.sqlite'), () => 1000);
  try {
    const id = db.enqueue({ subject: 'alice', idempotencyKey: 'vuln', registry: 'registry-1.docker.io',
      repository: 'library/alpine', digest, platform: 'linux/amd64', checks: '["vuln"]', scope: 'image' }).scanId;
    await run(db, id);
  } finally { db.close(); rmSync(dir, { recursive: true, force: true }); }
}

test('standalone vuln uses pinned single-check job and stores checked result', async () => fixture(async (db, id) => {
  await consumeOne(db, options, noSecret, 1000, noSbom, async (job, config) => {
    assert.equal(job.scanId, id);
    assert.equal(job.checks, '["vuln"]');
    assert.equal(`${job.registry}/${job.repository}@${job.digest}`, image);
    assert.equal(config.releaseDir, vuln.releaseDir);
    assert.deepEqual(config.trust, vuln.trust);
    assert.equal(config.signal?.aborted, false);
    return { ok: true, findings: [], scannerVersion: '0.69.3' };
  });
  assert.equal(db.state(id, 'alice'), 'completed');
  assert.equal(db.vuln(id, 'alice')?.outcome, 'checked');
}));

test('missing config and runner exception fail closed without exposing diagnostics', async () => {
  for (const configured of [false, true]) await fixture(async (db, id) => {
    let invoked = false;
    await consumeOne(db, configured ? options : { timeoutMs: 1000, dbDir: '/tmp/cache' },
      noSecret, 1000, noSbom, async () => { invoked = true; throw Error('raw private log'); });
    assert.equal(invoked, configured);
    assert.equal(db.state(id, 'alice'), 'failed');
    assert.equal(db.vuln(id, 'alice')?.outcome, 'failed');
    const coverage = db.vuln(id, 'alice');
        assert.equal(coverage?.outcome, 'failed');
        assert.equal(coverage?.outcome === 'failed' ? coverage.errorCode : undefined,
      configured ? 'SCAN_FAILED' : 'SCAN_UNAVAILABLE');
  });
});

test('cancelled vuln attempt aborts and never publishes late success', async () => fixture(async (db, id) => {
  let started!: () => void;
  const ready = new Promise<void>(resolve => { started = resolve; });
  let signal: AbortSignal | undefined;
  const work = consumeOne(db, options, noSecret, 1000, noSbom, async (_job, config) => {
    signal = config.signal;
    started();
    return new Promise(() => {});
  });
  await ready;
  db.cancel(id, 'alice');
  assert.equal(await work, true);
  assert.equal(signal?.aborted, true);
  assert.equal(db.vuln(id, 'alice'), undefined);
}));
