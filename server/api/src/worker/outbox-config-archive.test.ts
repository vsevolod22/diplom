import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { ScanLedger } from '../ledger/ledger.js';
import { NGINX_ARCHIVE_CANDIDATES, archiveProfileVersion } from '../oci/bounded-image-archive.js';
import { consumeOne } from './outbox-consumer.js';
import type { ArchiveScanReport } from './archive-scan-worker.js';

for (const target of NGINX_ARCHIVE_CANDIDATES) for (const selected of [false, true]) for (const crossing of [false, true]) {
  test(`exact archive ${target.digest.slice(-6)} config=${selected}, DB crossing=${crossing} retains independent report in one transaction`, async () => {
    const directory = mkdtempSync(join(tmpdir(), 'config-archive-')); const ledger = new ScanLedger(join(directory, 'db.sqlite'));
    const clock = Date.now; const now = clock();
    try {
      const checks = ['secret', 'sbom', 'vuln', ...(selected ? ['config'] : [])];
      const id = ledger.enqueue({ ...target, digest: target.digest as `sha256:${string}`, subject: 'alice', idempotencyKey: 'config-archive', checks: JSON.stringify(checks) }).scanId;
      const nextUpdate = now + 3_600_000;
      const report: ArchiveScanReport = { receipt: { ...target, layerDigests: [`sha256:${'a'.repeat(64)}`], diffIds: [`sha256:${'b'.repeat(64)}`],
        archiveSha256: `sha256:${'c'.repeat(64)}`, profileVersion: archiveProfileVersion(target), resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' },
        scannerVersion: '0.69.3', checkedAt: now, metrics: { wireBytes: 100, requests: 5, compressedBytes: 50, expandedBytes: 2048,
          entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 }, secret: { outcome: 'checked', findings: [] },
        sbom: { outcome: 'failed', reason: 'SCAN_FAILED' }, vuln: { outcome: 'unsupported', reason: 'OS_EOL',
          os: { outcome: 'unsupported', reason: 'OS_EOL' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' },
          db: { envelopeVersion: 1, signer: 'local-db-operator-v1', source: `ghcr.io/aquasecurity/trivy-db@sha256:${'d'.repeat(64)}`,
            schemaVersion: 2, manifestDigest: `sha256:${'d'.repeat(64)}`, artifactSha256: 'a'.repeat(64), metadataSha256: 'b'.repeat(64), dbSha256: 'c'.repeat(64),
            updatedAt: new Date(now - 60_000).toISOString(), downloadedAt: new Date(now - 30_000).toISOString(), nextUpdate: new Date(nextUpdate).toISOString() } } };
      const finish = ledger.finishArchive.bind(ledger); let commits = 0;
      if (crossing) ledger.finishArchive = (...args) => { commits++; Date.now = () => nextUpdate + 1; return finish(...args); };
      let loaded = false;
      // No synthetic bytes can pretend to hash to an externally pinned nginx digest.
      // Actual config module returns redacted loader failure; positive live nginx remains pending.
      await consumeOne(ledger, { timeoutMs: 1000, dbDir: '/unused', configLoader: async () => { loaded = true; throw Error('CANARY_OCI_ERROR'); } },
        async () => { throw Error('normal runner must not receive archive'); }, now, undefined, undefined,
        async requested => { assert.deepEqual(requested, ['secret','sbom','vuln']); return report; });
      assert.equal(loaded, selected);
      assert.equal(ledger.configResult(id, 'alice')?.config.outcome, selected ? 'failed' : 'skipped');
      assert.equal(ledger.archiveResult(id, 'alice')?.secret?.outcome, 'checked');
      assert.equal(ledger.archiveResult(id, 'alice')?.sbom?.outcome, 'failed');
      assert.deepEqual(ledger.archiveResult(id, 'alice')?.vuln, crossing ? { outcome: 'failed', reason: 'DB_UNAVAILABLE' } : report.vuln);
      assert.equal(ledger.state(id, 'alice'), 'partial'); assert.equal(JSON.stringify(ledger.configResult(id, 'alice')).includes('CANARY'), false);
      assert.deepEqual(ledger.events(id, 'alice', null)?.map(event => event.state), ['queued','running','partial']);
      if (crossing) assert.equal(commits, 2);
      const raw = new Database(join(directory, 'db.sqlite'));
      try { assert.equal((raw.prepare('SELECT count(*) AS n FROM scan_check_results').get() as { n: number }).n, 1); }
      finally { raw.close(); }
    } finally { Date.now = clock; ledger.close(); rmSync(directory, { recursive: true, force: true }); }
  });
}
