import { NGINX_ARCHIVE_TARGET } from '../oci/bounded-image-archive.js';
import { validArchiveBinding } from '../oci/archive-identity.js';
import { ARCHIVE_LIMITS as L } from '../oci/layer-tar-validator.js';
import { assertDbFreshness } from './vuln-db-bundle.js';
import type { ArchiveScanReport } from './archive-scan-worker.js';
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const exact = (value: unknown, keys: string[]): value is Record<string, unknown> => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const invalid = (): never => { throw new TypeError('Invalid archive result'); };
export function assertArchiveDbFreshness(report: ArchiveScanReport, now = Date.now()): void {
  if (report.vuln && report.vuln.outcome !== 'failed' && report.vuln.db) {
    assertDbFreshness(report.vuln.db, report.checkedAt);
    assertDbFreshness(report.vuln.db, now);
  }
}
export function validateArchiveReport(report: ArchiveScanReport, requested: string[]): void {
  if (!exact(report, ['receipt', 'scannerVersion', 'checkedAt', 'metrics', ...requested]) ||
      report.scannerVersion !== '0.69.3' || !Number.isSafeInteger(report.checkedAt) || report.checkedAt < 1 ||
      !exact(report.receipt, [...Object.keys(NGINX_ARCHIVE_TARGET), 'layerDigests', 'diffIds', 'archiveSha256',
        'profileVersion', 'resourcePolicyVersion', 'checksVersion']) ||
      !validArchiveBinding({ receipt: report.receipt, archivePath: '/tmp/trivy/jobs/00000000-0000-0000-0000-000000000000/image.tar' })) invalid();
  const bounds = { wireBytes: L.wireBytes, requests: L.requests, compressedBytes: L.compressedTotal,
    expandedBytes: L.expandedTotal, entries: L.entries, archiveBytes: L.archiveBytes, reservationPeak: L.scratchBytes, scratchPeak: L.scratchBytes };
  if (!exact(report.metrics, Object.keys(bounds)) || Object.entries(bounds).some(([key, max]) => {
    const value = report.metrics[key as keyof typeof bounds]; return !Number.isSafeInteger(value) || value < 0 || value > max;
  })) invalid();
  for (const check of requested) {
    const candidate: unknown = report[check as 'secret' | 'sbom' | 'vuln'];
    if (!object(candidate)) return invalid();
    const item = candidate;
    if (item.outcome === 'failed') {
      if (!exact(item, ['outcome', 'reason']) || !['SCAN_FAILED', 'SCAN_TIMEOUT', 'DB_UNAVAILABLE'].includes(item.reason as string)) invalid();
    } else if (check === 'vuln' && item.outcome === 'unsupported') {
      if (!exact(item, ['outcome', 'reason', 'db', 'os', 'node']) || !['OS_EOL', 'OS_UNKNOWN'].includes(item.reason as string) ||
          !exact(item.os, ['outcome', 'reason']) || item.os.outcome !== 'unsupported' || item.os.reason !== item.reason ||
          !exact(item.node, ['outcome', 'reason']) || item.node.outcome !== 'unsupported' || item.node.reason !== 'NODE_INVENTORY_ABSENT') invalid();
    } else if (item.outcome !== 'checked') invalid();
    if (check === 'vuln' && item.outcome !== 'failed') {
      const db = item.db;
      if (!exact(db, ['envelopeVersion', 'signer', 'source', 'schemaVersion', 'artifactSha256', 'metadataSha256', 'dbSha256',
          'manifestDigest', 'updatedAt', 'downloadedAt', 'nextUpdate']) || db.envelopeVersion !== 1 || db.schemaVersion !== 2 ||
          db.signer !== 'local-db-operator-v1' || typeof db.manifestDigest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(db.manifestDigest) ||
          db.source !== `ghcr.io/aquasecurity/trivy-db@${db.manifestDigest}` ||
          ['artifactSha256', 'metadataSha256', 'dbSha256'].some(key => typeof db[key] !== 'string' || !/^[a-f0-9]{64}$/.test(db[key] as string)) ||
          ['updatedAt', 'downloadedAt', 'nextUpdate'].some(key => typeof db[key] !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,9}Z$/.test(db[key] as string))) invalid();
    }
  }
}
