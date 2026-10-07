import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { ScanLedger } from '../ledger/ledger.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { OciResolver } from '../oci/oci-resolver.js';
import { ScansService } from './scans.service.js';
import { normalizeAdvisory } from '../worker/vuln-advisory.js';
import { NGINX_ARCHIVE_TARGET } from '../oci/bounded-image-archive.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';
const identity = { subject: 'owner', scope: ['scan:create'] };
const target = { subject: 'owner', idempotencyKey: 'advisory', registry: 'registry-1.docker.io', repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}` as const, platform: 'linux/amd64', scope: 'image', checks: '["vuln"]' };
function service(ledger: ScanLedger): ScansService {
  const store = Object.create(LedgerStore.prototype);
  Object.defineProperty(store, 'ledger', { value: ledger });
  return new ScansService(store, Object.create(OciResolver.prototype));
}
test('serialized ordinary service projection is accepted by actual browser parser (no HTTP claim)', async () => {
  const { parseCurrentVuln } = await import(new URL('../../../../src/shared/api/scans/scanTransport.ts', import.meta.url).href);
  const ledger = new ScanLedger(':memory:');
  try {
    const image = `${target.registry}/${target.repository}@${target.digest}`, provenanceRef = `target-${'b'.repeat(64)}`, cveId = 'CVE-2025-12345';
    const findingId = `vuln-${createHash('sha256').update(JSON.stringify(['apk', provenanceRef, cveId, 'busybox', '1.2'])).digest('hex')}`;
    const finding = { findingId, cveId, ecosystem: 'apk' as const, packageName: 'busybox', installedVersion: '1.2', severity: 'HIGH' as const, severitySources: ['alpine'], provenanceRef, fixedVersion: null,
      advisory: normalizeAdvisory({ Title: 'Safe text', Description: 'CANARY-secret remainder', DataSource: { ID: 'alpine' }, CVSS: { nvd: { V3Score: 0, V3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } } }, provenanceRef, cveId) };
    const id = ledger.enqueue(target).scanId, job = ledger.claim()!;
    ledger.finishWithVuln(id, job.attempts, image, [finding], '0.69.3');
    const api = service(ledger), wire: unknown = JSON.parse(JSON.stringify(api.vuln(identity, id, undefined, '1')));
    const parsed = parseCurrentVuln(wire);
    assert.equal(parsed.outcome, 'checked'); assert.deepEqual(parsed.findings, [finding]);
    assert.ok(!JSON.stringify(parsed).includes('CANARY'));
    assert.throws(() => api.vuln({ ...identity, subject: 'other' }, id, undefined, '1'));
  } finally { ledger.close(); }
});
test('archive service preserves checked Secrets zero and nonchecked unknown; actual parser consumes both', async () => {
  const { parseCurrentResults, parseCurrentVuln } = await import(new URL('../../../../src/shared/api/scans/scanTransport.ts', import.meta.url).href);
  const ledger = new ScanLedger(':memory:');
  try {
    for (const checked of [true, false]) {
      const candidate = { ...target, ...NGINX_ARCHIVE_TARGET, digest: NGINX_ARCHIVE_TARGET.digest as `sha256:${string}`, idempotencyKey: `archive-${checked}`, checks: '["secret","vuln"]' };
      const value: ArchiveScanReport = { receipt: { ...NGINX_ARCHIVE_TARGET, layerDigests: [`sha256:${'a'.repeat(64)}`], diffIds: [`sha256:${'b'.repeat(64)}`], archiveSha256: `sha256:${'c'.repeat(64)}`, profileVersion: 'nginx-alpine-amd64-v1', resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' }, scannerVersion: '0.69.3', checkedAt: Date.now(), metrics: { wireBytes: 100, requests: 5, compressedBytes: 50, expandedBytes: 2048, entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 }, secret: checked ? { outcome: 'checked', findings: [] } : { outcome: 'failed', reason: 'SCAN_FAILED' }, vuln: { outcome: 'failed', reason: 'DB_UNAVAILABLE' } };
      const id = ledger.enqueue(candidate).scanId, job = ledger.claim()!;
      ledger.finishArchive(id, job.attempts, value);
      const api = service(ledger);
      const wire = api.results(identity, id, undefined, '50');
      assert.equal(wire.coverage?.findingCount, checked ? 0 : null);
      const parsed = parseCurrentResults(JSON.parse(JSON.stringify(wire)));
      assert.equal(parsed.coverage[0].findingCount, checked ? 0 : undefined);
      assert.equal(parseCurrentVuln(JSON.parse(JSON.stringify(api.vuln(identity, id, undefined, '50')))).outcome, 'failed');
    }
  } finally { ledger.close(); }
});
