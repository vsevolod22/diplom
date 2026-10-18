import { plainObject, validateAdvisoryBudget } from './vuln-advisory.js';
import { PUBLIC_IMAGE_LIMITS, isPublicReceipt } from '../oci/public-image-policy.js';
import { PUBLIC_ECOSYSTEMS, publicOs, publicPackageName, publicPackageVersion, publicVulnerabilityId, type PackageEcosystem } from './public-image-evidence.js';
import { PUBLIC_VULN_SOURCES } from './vuln-findings.js';
import { NGINX_ARCHIVE_TARGET } from '../oci/bounded-image-archive.js';
import { validArchiveBinding } from '../oci/archive-identity.js';
import { ARCHIVE_LIMITS as L } from '../oci/layer-tar-validator.js';
import { assertDbFreshness } from './vuln-db-bundle.js';
import { CURRENT_DB_POLICY, LEGACY_DB_POLICY, validateDbPolicyReceipt, type CveDbPolicy } from './cve-db-policy.mjs';
import type { ArchiveScanReport } from './archive-scan-worker.js';
const object = (value: unknown): value is Record<string, unknown> => plainObject(value);
const exact = (value: unknown, keys: string[]): value is Record<string, unknown> => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const invalid = (): never => { throw new TypeError('Invalid archive result'); };
function boundedArray(value: unknown, maximum = 1000): value is unknown[] {
  return Array.isArray(value) && Object.getPrototypeOf(value) === Array.prototype && value.length <= maximum &&
      Reflect.ownKeys(value).length === value.length + 1 && Object.keys(value).length === value.length &&
      Object.keys(value).every((key, index) => key === String(index) && 'value' in Object.getOwnPropertyDescriptor(value, key)!);
}
function validatePublicPayload(check: string, item: Record<string, unknown>, report: ArchiveScanReport): void {
  if (check === 'sbom') {
    const sbom = item.sbom;
    if (!exact(sbom, ['image', 'platform', 'os', 'components']) ||
        sbom.image !== `${report.receipt.registry}/${report.receipt.repository}@${report.receipt.digest}` ||
        sbom.platform !== 'linux/amd64' || !exact(sbom.os, ['name', 'version']) ||
        !publicOs({ Family: sbom.os.name, Name: sbom.os.version }) || !boundedArray(sbom.components) || !sbom.components.length) invalid();
    const seen = new Set<string>();
    for (const component of (sbom as Record<string, unknown>).components as unknown[]) {
      if (!exact(component, ['ecosystem', 'name', 'version']) || !(PUBLIC_ECOSYSTEMS as readonly unknown[]).includes(component.ecosystem) ||
          !publicPackageName(component.name, component.ecosystem as PackageEcosystem) || !publicPackageVersion(component.version)) invalid();
      const key = JSON.stringify(component); if (seen.has(key)) invalid(); seen.add(key);
    }
    return;
  }
  if (!boundedArray(item.findings)) invalid();
  const seen = new Set<string>();
  for (const finding of item.findings as unknown[]) {
    if (check === 'secret') {
      if (!exact(finding, ['findingId', 'ruleId', 'line', 'evidenceRef']) ||
          typeof finding.findingId !== 'string' || !/^secret-[0-9]{1,4}-[0-9]{1,4}$/.test(finding.findingId) ||
          typeof finding.ruleId !== 'string' || !/^rule-[a-f0-9]{16}$/.test(finding.ruleId) ||
          typeof finding.evidenceRef !== 'string' || !/^result-[0-9]{1,4}-secret-[0-9]{1,4}$/.test(finding.evidenceRef) ||
          finding.line !== null && (!Number.isSafeInteger(finding.line) || (finding.line as number) < 0 || (finding.line as number) > 10_000_000)) invalid();
    } else {
      if (!object(finding) || !exact(finding, ['findingId', 'cveId', 'ecosystem', 'packageName', 'installedVersion', 'severity',
          'severitySources', 'provenanceRef', 'fixedVersion', ...(Object.hasOwn(finding, 'advisory') ? ['advisory'] : [])]) ||
          typeof finding.findingId !== 'string' || !/^vuln-[a-f0-9]{64}$/.test(finding.findingId) ||
          !publicVulnerabilityId(finding.cveId, finding.ecosystem as PackageEcosystem) ||
          !(PUBLIC_ECOSYSTEMS as readonly unknown[]).includes(finding.ecosystem) ||
          !publicPackageName(finding.packageName, finding.ecosystem as PackageEcosystem) || !publicPackageVersion(finding.installedVersion) ||
          !['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(finding.severity as string) ||
          !boundedArray(finding.severitySources, PUBLIC_VULN_SOURCES.length) || !finding.severitySources.length ||
          finding.severitySources.some((source, index, all) => typeof source !== 'string' || !PUBLIC_VULN_SOURCES.includes(source) ||
            index > 0 && String(all[index - 1]) >= source) ||
          typeof finding.provenanceRef !== 'string' || !/^target-[a-f0-9]{64}$/.test(finding.provenanceRef) ||
          finding.fixedVersion !== null && !publicPackageVersion(finding.fixedVersion)) invalid();
    }
    const id = (finding as Record<string, unknown>).findingId as string;
    if (seen.has(id)) invalid(); seen.add(id);
  }
  if (check === 'vuln') validateAdvisoryBudget(item.findings as import('./vuln-findings.js').VulnFinding[]);
}

export function assertArchiveDbFreshness(report: ArchiveScanReport, now = Date.now(), policy: CveDbPolicy = LEGACY_DB_POLICY): void {
  if (report.vuln && report.vuln.outcome !== 'failed' && report.vuln.db) {
    if (policy === CURRENT_DB_POLICY) validateDbPolicyReceipt(report.vuln.db, report.vuln.dbPolicy, report.checkedAt, policy);
    assertDbFreshness(report.vuln.db, report.checkedAt, policy);
    assertDbFreshness(report.vuln.db, now, policy);
  }
}
export function validateArchiveReport(report: ArchiveScanReport, requested: string[], policy: CveDbPolicy = LEGACY_DB_POLICY): void {
  if (!Array.isArray(requested) || requested.length < 1 || requested.length > 3 ||
      requested.some((check, index) => !['secret', 'sbom', 'vuln'].includes(check) ||
        index > 0 && ['secret', 'sbom', 'vuln'].indexOf(requested[index - 1]) >= ['secret', 'sbom', 'vuln'].indexOf(check)) ||
      !exact(report, ['receipt', 'scannerVersion', 'checkedAt', 'metrics', ...requested]) ||
      report.scannerVersion !== '0.69.3' || !Number.isSafeInteger(report.checkedAt) || report.checkedAt < 1 ||
      !exact(report.receipt, [...Object.keys(NGINX_ARCHIVE_TARGET), 'layerDigests', 'diffIds', 'archiveSha256',
        'profileVersion', 'resourcePolicyVersion', 'checksVersion']) ||
      !validArchiveBinding({ receipt: report.receipt, archivePath: '/tmp/trivy/jobs/00000000-0000-0000-0000-000000000000/image.tar' })) invalid();
  const publicImage = isPublicReceipt(report.receipt);
  const limits = publicImage ? PUBLIC_IMAGE_LIMITS : L;
  const bounds = { wireBytes: limits.wireBytes, requests: limits.requests, compressedBytes: limits.compressedTotal,
    expandedBytes: limits.expandedTotal, entries: limits.entries, archiveBytes: limits.archiveBytes, reservationPeak: limits.scratchBytes, scratchPeak: limits.scratchBytes };
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
      if (!exact(item, ['outcome', 'reason', 'db', 'os', 'node', ...(policy === CURRENT_DB_POLICY ? ['dbPolicy'] : [])]) || !['OS_EOL', 'OS_UNKNOWN'].includes(item.reason as string) ||
          !exact(item.os, ['outcome', 'reason']) || item.os.outcome !== 'unsupported' || item.os.reason !== item.reason ||
          !exact(item.node, ['outcome', 'reason']) || item.node.outcome !== 'unsupported' || item.node.reason !== (publicImage ? 'NODE_INVENTORY_UNKNOWN' : 'NODE_INVENTORY_ABSENT')) invalid();
    } else if (item.outcome !== 'checked') invalid();
    // Validate the ORIGINAL envelope before any discriminator/version is added.
    // Never let a derived object's overwritten fields hide data that gets stored.
    if (item.outcome === 'checked') {
      if (publicImage) validatePublicPayload(check, item, report);
      if (check === 'secret' && !exact(item, ['outcome', 'findings'])) invalid();
      if (check === 'sbom' && !exact(item, ['outcome', 'sbom'])) invalid();
      if (check === 'vuln' && (!exact(item.os, ['outcome']) || item.os.outcome !== 'checked' ||
          !(exact(item.node, ['outcome']) && item.node.outcome === 'checked' ||
            exact(item.node, ['outcome', 'reason']) && item.node.outcome === 'unsupported' && item.node.reason === (publicImage ? 'NODE_INVENTORY_UNKNOWN' : 'NODE_INVENTORY_ABSENT')))) invalid();
    }
    if (check === 'vuln' && item.outcome !== 'failed') {
      if (item.outcome === 'checked' && !exact(item, ['outcome', 'findings', 'db', 'os', 'node', ...(policy === CURRENT_DB_POLICY ? ['dbPolicy'] : [])])) invalid();
      const db = item.db;
      if (!exact(db, ['envelopeVersion', 'signer', 'source', 'schemaVersion', 'artifactSha256', 'metadataSha256', 'dbSha256',
          'manifestDigest', 'updatedAt', 'downloadedAt', 'nextUpdate']) || db.envelopeVersion !== 1 || db.schemaVersion !== 2 ||
          db.signer !== 'local-db-operator-v1' || typeof db.manifestDigest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(db.manifestDigest) ||
          db.source !== `ghcr.io/aquasecurity/trivy-db@${db.manifestDigest}` ||
          ['artifactSha256', 'metadataSha256', 'dbSha256'].some(key => typeof db[key] !== 'string' || !/^[a-f0-9]{64}$/.test(db[key] as string)) ||
          ['updatedAt', 'downloadedAt', 'nextUpdate'].some(key => typeof db[key] !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,9}Z$/.test(db[key] as string))) invalid();
      if (policy === CURRENT_DB_POLICY) validateDbPolicyReceipt(db as unknown as import('./vuln-db-bundle.js').VerifiedDbIdentity, item.dbPolicy, report.checkedAt, policy);
    }
  }
}
