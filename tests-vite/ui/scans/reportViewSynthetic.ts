import type { Severity, ReportPages } from '@/shared/api/scans/reportView';
import type { ScanStatus, VulnFinding } from '@/shared/api/scans/scanTransport';

// Synthetic public-shaped data only: no runtime fixtures, scanner output, or environment imports.
export const scanId = '10000000-0000-4000-8000-000000000001';
export const image = `registry-1.docker.io/library/alpine@sha256:${'a'.repeat(64)}`;
export const checkedAt = '2026-01-02T00:00:00.000Z';
export const finding = (index: number, severity: Severity = 'HIGH'): VulnFinding => ({ findingId: `finding-${index}`, cveId: `CVE-2026-${String(1000 + index)}`, ecosystem: 'apk', packageName: `package-${index}`, installedVersion: '1.0', fixedVersion: '2.0', severity });
export const vulnRows = Array.from({ length: 30 }, (_, index) => finding(index, index < 8 ? 'CRITICAL' : index < 20 ? 'HIGH' : 'LOW'));
export const sbomRows = Array.from({ length: 30 }, (_, index) => ({ ecosystem: index < 15 ? 'apk' as const : 'npm' as const, name: `package-${String(index).padStart(2, '0')}`, version: '1.0' }));
export const secretRows = Array.from({ length: 30 }, (_, index) => ({ findingId: `secret-${index}`, ruleId: index < 15 ? 'RULE_A' : 'RULE_B', line: index % 2 ? index + 1 : null, evidenceRef: `redacted:${index}` }));
export const status: ScanStatus = {
  scanId, state: 'completed', digest: `sha256:${'a'.repeat(64)}`, imageReference: image, platform: 'linux/amd64', checks: ['secret', 'sbom', 'vuln'],
  perCheck: {
    vuln: { check: 'vuln', coverage: 'image', outcome: 'checked', findingCount: 30, scannerVersion: 'synthetic', checkedAt },
    sbom: { check: 'sbom', coverage: 'image', outcome: 'checked', componentCount: 30, scannerVersion: 'synthetic', checkedAt },
    secret: { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 30, errorCode: null, scannerVersion: 'synthetic' },
  },
};
export const meta = (overrides: Partial<ReportPages['vuln']> = {}): ReportPages['vuln'] => ({ version: 1, limit: 5, offset: 0, returnedCount: 5, totalCount: 30, matchedCount: 30, sort: 'severity:desc', filters: { severity: null }, ...overrides });
export function vulnWire(overrides: Record<string, unknown> = {}) {
  return { outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64', findingCount: 30, checkedAt, scannerVersion: 'synthetic', findings: vulnRows.slice(0, 5), nextCursor: 'opaque:5/+==', page: meta(), ...overrides };
}
export function sbomWire(overrides: Record<string, unknown> = {}) {
  return { outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64', componentCount: 30, checkedAt, scannerVersion: 'synthetic', os: { name: 'alpine', version: '3.0' }, components: sbomRows.slice(0, 5), nextCursor: 'opaque:5/+==', page: { ...meta(), sort: 'name:asc', filters: { ecosystem: null, name: null } }, ...overrides };
}
export function secretWire(overrides: Record<string, unknown> = {}) {
  return { findings: secretRows.slice(0, 5), nextCursor: 'opaque:5/+==', coverage: { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 30, errorCode: null, scannerVersion: 'synthetic' }, page: { ...meta(), sort: 'ruleId:asc', filters: { ruleId: null, linePresence: null } }, ...overrides };
}
export function v2Evidence() {
  const db = { envelopeVersion: 1, signer: 'local-db-operator-v1', source: `ghcr.io/aquasecurity/trivy-db@sha256:${'b'.repeat(64)}`, schemaVersion: 2, manifestDigest: `sha256:${'b'.repeat(64)}`, artifactSha256: 'b'.repeat(64), metadataSha256: 'b'.repeat(64), dbSha256: 'b'.repeat(64), updatedAt: '2026-01-01T00:00:00.000000000Z', downloadedAt: '2026-01-01T01:00:00.000000000Z', nextUpdate: '2026-01-03T00:00:00.000000000Z' };
  return { db, resultContractVersion: 2, dbPolicy: { version: 2, policy: 'cve-db-updated-at-14d-v2', evaluatedAt: Date.parse(checkedAt), status: 'usable', warnings: [] }, usableUntil: '2026-01-15T00:00:00.000000000Z', workerCheckedAt: Date.parse(checkedAt) };
}
