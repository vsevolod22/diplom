import { z } from 'zod';
import { scanChecks, type ScanCheck, type ScanProgress } from './types';
export { scanChecks } from './types';
export type { ScanCheck, ScanOutcome, ScanProgress } from './types';
import { parseReportView } from './reportView';
import type { ReportPages, SecretReportQuery, SbomReportQuery, VulnReportQuery } from './reportView';
import { CveReportContractError, cveMetadataFields, hasCveMetadata, validateCveMetadata } from './cveDbMetadata';
import { advisoryV1, advisorySource, advisorySeverity, provenanceRef, assertPlainWire, serializedBytes, validAdvisoryReferences } from './vulnAdvisory';
import { imageConfigReport, wireConfigCoverage } from './imageConfigReport';
import { pinnedPublicImage, publicProfile, validReportImage, reportEcosystem, reportOs, reportSeveritySource } from './publicImageProfile';

import { identifierCounts, isCveId, isDebianTempId, validVulnerabilityId, validateIdentifierCounts } from './publicVulnerabilityIdentifiers';

const state = z.enum(['queued', 'running', 'cancelling', 'completed', 'partial', 'failed', 'cancelled']);
const coverageState = z.enum(['checked', 'unsupported', 'not_authorized', 'failed', 'skipped']);
const coverage = z.object({ check: z.string(), status: coverageState, reason: z.string().optional(), scannerVersion: z.string().optional(), dbVersion: z.string().optional(), findingCount: z.number().int().nonnegative().nullable().optional(), checksVersion: z.string().optional(), resourcePolicyVersion: z.string().optional() });
const finding = z.object({ findingId: z.string(), category: z.string(), ruleId: z.string(), severity: z.string(), location: z.string().optional(), evidenceRef: z.string().optional() });
const checkName = z.enum(scanChecks);
const wireOutcome = z.enum(['checked', 'failed', 'unsupported', 'skipped', 'not_authorized']);
const wireChecks = z.array(checkName).min(1).max(4).refine(checks => checks.every((check, index) => index === 0 || scanChecks.indexOf(checks[index - 1]) < scanChecks.indexOf(check)), 'Проверки должны быть отсортированы без повторов');
const progressSchema = z.strictObject({
  basis: z.literal('durable-outcomes-v1'), requestedChecks: wireChecks,
  outcomes: z.partialRecord(checkName, wireOutcome.nullable()),
  resolvedChecks: z.number().int().min(0).max(4), checkedChecks: z.number().int().min(0).max(4),
}).refine(progress => Object.keys(progress.outcomes).every(check => progress.requestedChecks.includes(check as ScanCheck)) &&
  progress.resolvedChecks === Object.values(progress.outcomes).filter(outcome => outcome != null).length &&
  progress.checkedChecks === Object.values(progress.outcomes).filter(outcome => outcome === 'checked').length,
'Несогласованный durable progress');

function validateStatusProgress(progress: ScanProgress | undefined, checks: ScanCheck[] | undefined,
  perCheck: Partial<Record<ScanCheck, { outcome: string } | null>> | undefined, state: string): void {
  if (!progress) return;
  if (JSON.stringify(progress.requestedChecks) !== JSON.stringify(checks)) throw new Error('Несогласованный набор progress');
  const active = ['queued', 'running', 'cancelling'].includes(state);
  if (state === 'queued' && progress.resolvedChecks !== 0 || active && Object.values(perCheck ?? {}).some(item => item != null))
    throw new Error('Промежуточный progress не является отчётом');
  if (!active && checks?.some(check => (progress.outcomes[check] ?? null) !== (perCheck?.[check]?.outcome ?? null)))
    throw new Error('Progress не совпадает с опубликованным отчётом');
}
const failureCode = z.enum(['SCAN_FAILED', 'SCAN_TIMEOUT', 'SCAN_UNAVAILABLE']);
const archiveFailureReason = z.enum(['SCAN_FAILED', 'SCAN_TIMEOUT', 'DB_UNAVAILABLE']);
const archiveReason = z.enum(['SCAN_FAILED', 'SCAN_TIMEOUT', 'DB_UNAVAILABLE', 'OS_EOL', 'OS_UNKNOWN', 'NODE_INVENTORY_ABSENT', 'NODE_INVENTORY_UNKNOWN']);
const subCoverage = z.discriminatedUnion('outcome', [z.strictObject({ outcome: z.literal('checked') }),
  z.strictObject({ outcome: z.literal('unsupported'), reason: archiveReason })]);
const dbTime = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,9}Z$/);
const dbIdentity = z.strictObject({ envelopeVersion: z.literal(1), signer: z.literal('local-db-operator-v1'),
  source: z.string().regex(/^ghcr\.io\/aquasecurity\/trivy-db@sha256:[a-f0-9]{64}$/), schemaVersion: z.literal(2),
  manifestDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/), artifactSha256: z.string().regex(/^[a-f0-9]{64}$/),
  metadataSha256: z.string().regex(/^[a-f0-9]{64}$/), dbSha256: z.string().regex(/^[a-f0-9]{64}$/),
  updatedAt: dbTime, downloadedAt: dbTime, nextUpdate: dbTime }).refine(db => db.source === `ghcr.io/aquasecurity/trivy-db@${db.manifestDigest}`);
const archiveEvidence = { os: subCoverage.optional(), node: subCoverage.optional(), db: dbIdentity.optional() };
const reportImage = pinnedPublicImage;
const status = z.object({ progress: progressSchema.optional(), identifierCounts: identifierCounts.optional(), profile: publicProfile.optional(), config: imageConfigReport.optional(), scanId: z.string(), state, stage: z.string().optional(), percent: z.number().min(0).max(100).nullable().optional(), imageReference: z.string().optional(), digest: z.string().optional(), platform: z.string().optional(), updatedAt: z.string().optional(), check: checkName.optional(), checks: z.array(checkName).optional(), perCheck: z.partialRecord(checkName, z.object({ check: checkName, coverage: z.literal('image'), outcome: z.enum(['checked', 'failed', 'unsupported', 'skipped', 'not_authorized']), errorCode: z.string().nullable().optional(), scannerVersion: z.string().nullable().optional(), findingCount: z.number().int().nonnegative().nullable().optional(), componentCount: z.number().int().nonnegative().optional(), reason: z.enum(['SCAN_FAILED', 'SCAN_TIMEOUT', 'DB_UNAVAILABLE', 'OS_EOL', 'OS_UNKNOWN', 'NODE_INVENTORY_ABSENT', 'NODE_INVENTORY_UNKNOWN', 'CHECK_DISABLED', 'USER_NOT_RESOLVABLE', 'OCI_IDENTITY_REJECTED', 'CONFIG_LIMIT_EXCEEDED', 'INVALID_CONFIG']).optional(), ...archiveEvidence, resultContractVersion: cveMetadataFields.resultContractVersion.optional(), dbPolicy: cveMetadataFields.dbPolicy.optional(), usableUntil: cveMetadataFields.usableUntil.optional(), workerCheckedAt: cveMetadataFields.workerCheckedAt.optional(), checksVersion: z.string().max(80).optional(), resourcePolicyVersion: z.string().max(80).optional(), supportedRuleIds: z.array(z.string()).optional(), completedRuleIds: z.array(z.string()).optional(), checkedAt: z.string().max(40).optional() }).nullable()).optional() });
const results = z.object({ findings: z.array(finding), nextCursor: z.string().nullable(), coverage: z.array(coverage) });
// Receipt URLs may refer to the internal API. Only the ID crosses into browser navigation.
const receipt = z.object({ scanId: z.string().uuid() });
export type ScanStatus = z.infer<typeof status>;
export type ScanResults = Omit<z.infer<typeof results>, 'findings' | 'coverage'> & { findings: ScanFinding[]; coverage: ScanCoverage[]; page?: ReportPages['secret'] };
export type ScanFinding = z.infer<typeof finding> & { line?: number | null };
export type ScanCoverage = z.infer<typeof coverage> & { checkedAt?: string };
export type ScanReceipt = z.infer<typeof receipt>;
export type ScanSummary = ScanStatus & { targetLabel: string };
export type ScanIntent = { imageReference: string; scope: 'image'; checks: ScanCheck[]; idempotencyKey: string };
type BrowserCursor<T> = T extends unknown ? Omit<T, 'nextCursor'> & { nextCursor: string | null } : never;
export type ScanVuln = BrowserCursor<z.infer<typeof wireVuln>> & { page?: ReportPages['vuln'] };
export type VulnFinding = z.infer<typeof wireVulnFinding>;
export type ScanSbom = BrowserCursor<z.infer<typeof wireSbom>> & { page?: ReportPages['sbom'] };
export type ScanCapabilities = { list: boolean; create: boolean; cancel: boolean; events: boolean };
export type ScanTransport = {
  kind: 'fixture' | 'live';
  capabilities: ScanCapabilities;
  list(signal?: AbortSignal): Promise<ScanSummary[]>;
  get(scanId: string, signal?: AbortSignal): Promise<ScanStatus>;
  results(scanId: string, cursor?: string, signal?: AbortSignal, query?: SecretReportQuery): Promise<ScanResults>;
  sbom(scanId: string, cursor?: string, signal?: AbortSignal, query?: SbomReportQuery): Promise<ScanSbom>;
  vuln(scanId: string, cursor?: string, signal?: AbortSignal, query?: VulnReportQuery): Promise<ScanVuln>;
  create(intent: ScanIntent): Promise<ScanReceipt>;
  cancel(scanId: string): Promise<void>;
  subscribeEvents?(scanId: string, onHint: () => void, onError: () => void, onOpen: () => void): () => void;
};
export const parseScanStatus = (value: unknown): ScanStatus => {
  assertPlainWire(value);
  const parsed = status.parse(value);
  for (const [key, item] of Object.entries((value as ScanStatus).perCheck ?? {})) {
    if (hasCveMetadata(item)) {
      if (key !== 'vuln') throw new Error('Invalid CVE metadata category');
      wireV2Check.parse(item);
    }
  }
  for (const [key, item] of Object.entries(parsed.perCheck ?? {})) {
    if (!item) continue;
    if (key === 'config') wireConfigCoverage.parse(item);
    else if (item.reason !== undefined) archiveReason.parse(item.reason);
  }
  validateStatusProgress(parsed.progress, parsed.checks, parsed.perCheck, parsed.state);
  if (parsed.progress && (parsed.percent != null || ['queued', 'running', 'cancelling'].includes(parsed.state) && parsed.config !== undefined))
    throw new Error('Durable progress не является процентом или промежуточным config');
  validateIdentifierCounts(parsed.profile, parsed.identifierCounts, parsed.perCheck?.vuln?.findingCount, parsed.perCheck?.vuln?.outcome === 'checked');
  return parsed;
};
export const parseScanResults = (value: unknown): ScanResults => results.parse(value);
export const parseScanReceipt = (value: unknown): ScanReceipt => receipt.parse(value);

// Browser scan endpoints currently expose this limited wire shape; new fields require review before display.
// Legacy nonchecked zero is tolerated, but never becomes a confirmed count.
const wireCoverage = z.strictObject({ findingCount: z.number().int().nonnegative().nullable().optional(), check: z.literal('secret'), coverage: z.literal('image'), outcome: wireOutcome, errorCode: z.string().nullable(), scannerVersion: z.string().nullable(), reason: archiveReason.optional(), checkedAt: z.string().datetime().optional() }).refine(item => item.outcome === 'checked' ? item.findingCount != null : item.findingCount == null || item.findingCount === 0);
const wireSbomResult = z.discriminatedUnion('outcome', [
  z.strictObject({ check: z.literal('sbom'), coverage: z.literal('image'), outcome: z.literal('checked'), componentCount: z.number().int().positive(), scannerVersion: z.string(), checkedAt: z.string() }),
  z.strictObject({ check: z.literal('sbom'), coverage: z.literal('image'), outcome: z.literal('failed'), errorCode: z.enum(['SCAN_FAILED', 'SCAN_TIMEOUT', 'SCAN_UNAVAILABLE']) }),
]);
const wireVulnResult = z.discriminatedUnion('outcome', [
  z.strictObject({ check: z.literal('vuln'), coverage: z.literal('image'), outcome: z.literal('checked'), findingCount: z.number().int().nonnegative(), scannerVersion: z.string().min(1), checkedAt: z.string().min(1) }),
  z.strictObject({ check: z.literal('vuln'), coverage: z.literal('image'), outcome: z.literal('failed'), errorCode: failureCode }),
]);
const wireArchiveCheck = z.strictObject({ check: checkName, coverage: z.literal('image'), outcome: wireOutcome,
  reason: archiveReason.optional(), errorCode: failureCode.nullable(), scannerVersion: z.literal('0.69.3'),
  checksVersion: z.string().min(1).max(80), checkedAt: z.string().datetime(),
  findingCount: z.number().int().nonnegative().nullable().optional(), componentCount: z.number().int().nonnegative().optional(), ...archiveEvidence }).refine(item => item.check !== 'secret' || (item.outcome === 'checked' ? item.findingCount != null : item.findingCount == null));
const wireV2Check = z.union([
  z.strictObject({ check: z.literal('vuln'), coverage: z.literal('image'), outcome: z.literal('checked'), findingCount: z.number().int().nonnegative(), scannerVersion: z.string().min(1), checkedAt: z.string(), db: dbIdentity, os: subCoverage.optional(), node: subCoverage.optional(), ...cveMetadataFields }),
  z.strictObject({ check: z.literal('vuln'), coverage: z.literal('image'), outcome: z.enum(['checked', 'unsupported']), reason: archiveReason.optional(), errorCode: z.null(), scannerVersion: z.literal('0.69.3'), checksVersion: z.string().min(1).max(80), checkedAt: z.string(), findingCount: z.number().int().nonnegative().optional(), db: dbIdentity, os: subCoverage.optional(), node: subCoverage.optional(), ...cveMetadataFields })
    .refine(item => item.outcome === 'checked' ? item.findingCount != null && item.reason === undefined : item.findingCount === undefined && item.reason !== undefined),
]).refine(validateCveMetadata, 'Invalid saved CVE metadata');
const wirePerCheck = z.unknown().transform((value, context) => {
  const schema = hasCveMetadata(value) ? wireV2Check : value && typeof value === 'object' && 'check' in value && value.check === 'config'
    ? wireConfigCoverage : value && typeof value === 'object' && 'checksVersion' in value
      ? wireArchiveCheck : z.union([wireCoverage, wireSbomResult, wireVulnResult]);
  const parsed = schema.safeParse(value);
  if (!parsed.success) { context.addIssue({ code: 'custom', message: 'Invalid check coverage' }); return z.NEVER; }
  return parsed.data;
});
const wireStatus = z.object({ progress: progressSchema.optional(), identifierCounts: identifierCounts.optional(), profile: publicProfile.optional(), config: imageConfigReport.optional(), imageReference: reportImage.optional(), scanId: z.string(), state: z.enum(['queued', 'running', 'completed', 'partial', 'failed', 'cancelled']), digest: z.string().regex(/^sha256:[a-f0-9]{64}$/).optional(), platform: z.literal('linux/amd64').optional(), check: checkName.nullable().optional(), checks: wireChecks.optional(), perCheck: z.partialRecord(checkName, wirePerCheck.nullable()).optional(), result: wirePerCheck.nullable() });
const sbomComponent = z.strictObject({ ecosystem: reportEcosystem, name: z.string().min(1).max(128), version: z.string().min(1).max(80) });
const wireSbom = z.discriminatedUnion('outcome', [
  z.strictObject({ profile: publicProfile.optional(), outcome: z.literal('checked'), coverage: z.literal('image'), image: reportImage, platform: z.literal('linux/amd64'), os: z.union([reportOs, z.strictObject({ name: z.literal('alpine'), version: z.string().min(1).max(80) })]), componentCount: z.number().int().positive(), scannerVersion: z.string().min(1), checkedAt: z.string().min(1), components: z.array(sbomComponent).max(100), nextCursor: z.number().int().nonnegative().nullable() }),
  z.strictObject({ outcome: z.literal('failed'), coverage: z.literal('image'), errorCode: failureCode,
    reason: archiveFailureReason.optional(), components: z.tuple([]), nextCursor: z.null() })
    .refine(page => page.reason === undefined || page.errorCode === (page.reason === 'SCAN_TIMEOUT' ? 'SCAN_TIMEOUT' : 'SCAN_FAILED'), 'Несогласованная причина отказа SBOM'),
]);
export function parseCurrentSbom(value: unknown, query?: SbomReportQuery, cursor?: string): ScanSbom {
  if (query) return parseReportView(value, 'sbom', query, cursor, parseCurrentSbom);
  assertPlainWire(value);
  const page = wireSbom.parse(value);
  if (page.outcome === 'failed') return page;
  if (!validReportImage(page.image, page.profile) || page.profile && !reportOs.safeParse(page.os).success || !page.profile && (page.os.name !== 'alpine' || page.components.some(row => row.ecosystem !== 'apk' && row.ecosystem !== 'npm'))) throw new Error('Недопустимый профиль SBOM');
  if (page.components.length > page.componentCount || (page.nextCursor !== null && (page.components.length === 0 || page.nextCursor > page.componentCount))) throw new Error('Недопустимая страница SBOM');
  return { ...page, nextCursor: page.nextCursor === null ? null : String(page.nextCursor) };
}
const wireList = z.object({ scans: z.array(z.object({ scanId: z.string().uuid(), state: wireStatus.shape.state, digest: wireStatus.shape.digest.unwrap(), platform: wireStatus.shape.platform.unwrap(), targetLabel: z.string() })), nextCursor: z.string().regex(/^[1-9]\d{0,14}:[1-9]\d{0,14}$/).nullable() });
const wireResults = z.object({ findings: z.array(z.object({ findingId: z.string(), ruleId: z.string(), line: z.number().nullable(), evidenceRef: z.string() })), nextCursor: z.number().int().nonnegative().nullable(), coverage: wireCoverage.nullable() });
export function parseCurrentStatus(value: unknown): ScanStatus {
  assertPlainWire(value);
  const current = wireStatus.parse(value);
  if (current.profile && (!current.imageReference || !current.digest || current.platform !== 'linux/amd64')) throw new Error('Нет закреплённой public-цели');
  if (current.imageReference && (!validReportImage(current.imageReference, current.profile) || current.digest && !current.imageReference.endsWith(`@${current.digest}`) || current.profile && (!current.digest || current.platform !== 'linux/amd64'))) throw new Error('Несогласованная закреплённая цель');
  const checks = current.checks ?? (current.check || current.result ? [current.check ?? current.result!.check] : undefined);
  const perCheck = current.perCheck ?? (checks?.length === 1 ? { [checks[0]]: current.result ?? null } : undefined);
  validateStatusProgress(current.progress, current.checks, perCheck, current.state);
  if (current.progress && ['queued', 'running'].includes(current.state) && current.result !== null)
    throw new Error('Промежуточный progress не является результатом');
  if (checks && perCheck && (Object.keys(perCheck).some(key => !checks.includes(key as ScanCheck) || (perCheck[key as ScanCheck] != null && perCheck[key as ScanCheck]?.check !== key)) || checks.some(key => !(key in perCheck)))) throw new Error('Недопустимый статус проверок');
  if (current.result && (hasCveMetadata(current.result) || hasCveMetadata(perCheck?.vuln))) {
    const actual = wireV2Check.parse(current.result);
    const expected = wireV2Check.parse(perCheck?.vuln);
    if (JSON.stringify(actual) !== JSON.stringify(expected))
      throw new Error('Inconsistent CVE result and perCheck');
  }
  const vulnCheck = perCheck?.vuln;
  validateIdentifierCounts(current.profile, current.identifierCounts, vulnCheck && 'findingCount' in vulnCheck ? vulnCheck.findingCount : undefined, vulnCheck?.outcome === 'checked');
  if (current.config) {
    if ((current.config.config.outcome === 'skipped') === (checks?.includes('config') === true) ||
        current.config.findings.some(finding => finding.manifestDigest !== current.digest || current.platform !== 'linux/amd64')) throw new Error('Недопустимая цель config');
    if (checks?.includes('config')) {
      const expected = { check: 'config', coverage: 'image', ...current.config.config, checksVersion: current.config.checksVersion,
        resourcePolicyVersion: current.config.resourcePolicyVersion, supportedRuleIds: current.config.supportedRuleIds,
        completedRuleIds: current.config.completedRuleIds, findingCount: current.config.findings.length };
      const actual = perCheck?.config;
      if (!actual || Object.keys(expected).some(key => JSON.stringify(actual[key as keyof typeof actual]) !== JSON.stringify(expected[key as keyof typeof expected]))) throw new Error('Несогласованный config outcome');
    }
  } else if (perCheck?.config != null) throw new Error('Нет config evidence');
  return { scanId: current.scanId, state: current.state, percent: null,
    ...(current.progress ? { progress: current.progress } : {}),
    ...(current.profile ? { profile: current.profile } : {}),
    ...(current.identifierCounts ? { identifierCounts: current.identifierCounts } : {}),
    ...(current.config ? { config: current.config } : {}),
    ...(checks ? { checks, perCheck, ...(checks.length === 1 ? { check: checks[0] } : {}) } : {}),
    ...(current.digest && current.platform ? { digest: current.digest, platform: current.platform } : {}),
    ...(current.imageReference ? { imageReference: current.imageReference } : {}) };
}
export function parseCurrentList(value: unknown): { scans: ScanSummary[]; nextCursor: string | null } {
  const page = wireList.parse(value);
  return { scans: page.scans.map(({ scanId, state, digest, platform, targetLabel }) => ({
    scanId, state, digest, platform, targetLabel, percent: null,
  })), nextCursor: page.nextCursor };
}
export function parseCurrentResults(value: unknown, query?: SecretReportQuery, cursor?: string): ScanResults {
  if (query) {
    const page = parseReportView(value, 'secret', query, cursor, parseCurrentResults);
    // Preserve only the meaningful nullable line, never the redacted evidence payload.
    const rows = (value as { findings: { line: number | null }[] }).findings;
    // The bridge already validated wireCoverage; only opt-in preserves a supplied stamp.
    const checkedAt = (value as { coverage: { checkedAt?: string } | null }).coverage?.checkedAt;
    return {
      ...page,
      coverage: page.coverage.map(item => item.check === 'Secrets' && checkedAt !== undefined ? { ...item, checkedAt } : item),
      findings: page.findings.map((item, index) => ({ ...item, line: rows[index].line })),
    };
  }
  assertPlainWire(value);
  const current = wireResults.parse(value);
  const secret = current.coverage;
  // An empty legacy page without coverage is absence, not a completed zero or a skipped check.
  if (secret === null) {
    if (current.findings.length || current.nextCursor !== null) throw new Error('Находки без подтверждённого покрытия');
    return { findings: [], nextCursor: null, coverage: [] };
  }
  return {
    findings: current.findings.map(({ findingId, ruleId }) => ({ findingId, ruleId, category: 'secret', severity: 'unknown' })),
    nextCursor: current.nextCursor === null ? null : String(current.nextCursor),
    coverage: [
      { check: 'Secrets', status: secret?.outcome ?? 'skipped', reason: secret?.reason ?? secret?.errorCode ?? (secret ? undefined : 'Результат ещё не получен'), scannerVersion: secret?.scannerVersion ?? undefined, ...(secret?.outcome === 'checked' && secret.findingCount != null ? { findingCount: secret.findingCount } : {}) },
      { check: 'CVE', status: 'unsupported', reason: 'В текущем API проверка недоступна' },
      { check: 'SBOM', status: 'unsupported', reason: 'В текущем API проверка недоступна' },
    ],
  };
}
const wireVulnFinding = z.strictObject({ findingId: z.string().min(1).max(69), cveId: z.string().min(1).max(21), ecosystem: reportEcosystem, packageName: z.string().min(1).max(128), installedVersion: z.string().min(1).max(80), severity: advisorySeverity, fixedVersion: z.string().max(80).nullable(),
  severitySources: z.array(reportSeveritySource).min(1).max(32).refine(items => items.every((source, index) => index === 0 || items[index - 1] < source)).optional(), provenanceRef: provenanceRef.optional(), advisory: advisoryV1.nullable().optional(),
}).refine(item => item.advisory == null || (serializedBytes(item) <= 16384 && (isCveId(item.cveId) || isDebianTempId(item.cveId)) && validAdvisoryReferences(item.advisory, item.cveId)));
const wireLegacyVuln = z.discriminatedUnion('outcome', [
  z.strictObject({ identifierCounts: identifierCounts.optional(), profile: publicProfile.optional(), outcome: z.literal('checked'), coverage: z.literal('image'), image: reportImage, ...archiveEvidence, platform: z.literal('linux/amd64'), findingCount: z.number().int().nonnegative(), scannerVersion: z.string().min(1), checkedAt: z.string().min(1), findings: z.array(wireVulnFinding).max(100), nextCursor: z.number().int().nonnegative().nullable() }),
  z.strictObject({ outcome: z.literal('failed'), coverage: z.literal('image'), errorCode: failureCode,
      reason: archiveFailureReason.optional(), findings: z.tuple([]), nextCursor: z.null() })
      .refine(page => page.reason === undefined || page.errorCode === (page.reason === 'SCAN_TIMEOUT' ? 'SCAN_TIMEOUT' : 'SCAN_FAILED'), 'Несогласованная причина отказа CVE'),
  z.strictObject({ profile: publicProfile.optional(), outcome: z.literal('unsupported'), coverage: z.literal('image'), reason: archiveReason, ...archiveEvidence, findings: z.tuple([]), nextCursor: z.null() }),
]);
const wireV2Vuln = z.union([
  z.strictObject({ identifierCounts: identifierCounts.optional(), profile: publicProfile.optional(), outcome: z.literal('checked'), coverage: z.literal('image'), image: reportImage, platform: z.literal('linux/amd64'), findingCount: z.number().int().nonnegative(), scannerVersion: z.string().min(1), checkedAt: z.string(), findings: z.array(wireVulnFinding).max(100), nextCursor: z.number().int().nonnegative().nullable(), db: dbIdentity, os: subCoverage.optional(), node: subCoverage.optional(), ...cveMetadataFields }),
  z.strictObject({ profile: publicProfile.optional(), outcome: z.literal('unsupported'), coverage: z.literal('image'), reason: archiveReason, checkedAt: z.string(), findings: z.tuple([]), nextCursor: z.null(), db: dbIdentity, os: subCoverage.optional(), node: subCoverage.optional(), ...cveMetadataFields }),
]).refine(validateCveMetadata, 'Invalid saved CVE metadata');
const wireVuln = z.unknown().transform<z.infer<typeof wireLegacyVuln> | z.infer<typeof wireV2Vuln>>((value, context) => {
  const parsed = (hasCveMetadata(value) ? wireV2Vuln : wireLegacyVuln).safeParse(value);
  if (!parsed.success) { context.addIssue({ code: 'custom', message: 'Invalid CVE report' }); return z.NEVER; }
  return parsed.data;
});
export function parseCurrentVuln(value: unknown, query?: VulnReportQuery, cursor?: string): ScanVuln {
  if (query) return parseReportView(value, 'vuln', query, cursor, parseCurrentVuln);
  try {
    assertPlainWire(value);
    const page = wireVuln.parse(value);
    if (page.outcome !== 'checked') return page;
    validateIdentifierCounts(page.profile, page.identifierCounts, page.findingCount, true);
    // Preserve historical unmarked rows; only the public contract gains TEMP.
    if (page.findings.some(row => page.profile ? !validVulnerabilityId(row.cveId, row.ecosystem, page.profile) : row.cveId.startsWith('TEMP-'))) throw new CveReportContractError();
    if (page.identifierCounts) {
      const debianTemp = page.findings.filter(row => isDebianTempId(row.cveId)).length;
      const cve = page.findings.length - debianTemp;
      if (debianTemp > page.identifierCounts.debianTemp || cve > page.identifierCounts.cve ||
          page.findings.length === page.findingCount && (cve !== page.identifierCounts.cve || debianTemp !== page.identifierCounts.debianTemp)) throw new CveReportContractError();
    }
    if (!validReportImage(page.image, page.profile) || !page.profile && page.findings.some(row => row.ecosystem !== 'apk' && row.ecosystem !== 'npm' || row.severitySources?.some(source => !advisorySource.safeParse(source).success))) throw new CveReportContractError();
    if (page.findings.length > page.findingCount || (page.nextCursor !== null && (page.findings.length === 0 || page.nextCursor > page.findingCount))) throw new CveReportContractError();
    if (page.findings.reduce((bytes, item) => bytes + (item.advisory == null ? 0 : serializedBytes(item.advisory)), 2 + Math.max(0, page.findings.length - 1)) > 1048576) throw new CveReportContractError();
    return { ...page, nextCursor: page.nextCursor === null ? null : String(page.nextCursor) };
  } catch {
    // Only the synchronous decoder is classified here, never the preceding HTTP request.
    throw new CveReportContractError();
  }
}
export const BROWSER_SCANS_PATH = '/api/v1/browser/scans';

const eventHint = z.object({ scanId: z.string().uuid(), state: state, percent: z.null() });
export function parseScanEventHint(value: unknown, scanId: string): boolean {
  const parsed = eventHint.safeParse(value);
  return parsed.success && parsed.data.scanId === scanId;
}

export function sameOriginScanUrl(raw: string, scanId: string, suffix: '' | '/results' | '/sbom' | '/vuln' | '/events' = ''): string {
  const expected = `${BROWSER_SCANS_PATH}/${encodeURIComponent(scanId)}${suffix}`;
  const url = new URL(raw, window.location.origin);
  if (raw !== expected || url.origin !== window.location.origin || url.pathname !== expected || url.search || url.hash) {
    throw new Error('Недопустимый адрес скана');
  }
  return expected;
}
export function reconcileSnapshot(current: ScanStatus, incoming: ScanStatus): ScanStatus {
  if (incoming.scanId !== current.scanId) return current;
  const terminal = ['completed', 'partial', 'failed', 'cancelled'];
  if (terminal.includes(current.state) && !terminal.includes(incoming.state)) return current;
  // No comparable server revision: only the subsequent GET snapshot can be authoritative.
  return incoming;
}
