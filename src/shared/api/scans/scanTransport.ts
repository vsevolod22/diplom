import { z } from 'zod';
import { imageConfigReport, wireConfigCoverage } from './imageConfigReport';

const state = z.enum(['queued', 'running', 'cancelling', 'completed', 'partial', 'failed', 'cancelled']);
const coverageState = z.enum(['checked', 'unsupported', 'not_authorized', 'failed', 'skipped']);
const coverage = z.object({ check: z.string(), status: coverageState, reason: z.string().optional(), scannerVersion: z.string().optional(), dbVersion: z.string().optional(), checksVersion: z.string().optional(), resourcePolicyVersion: z.string().optional() });
const finding = z.object({ findingId: z.string(), category: z.string(), ruleId: z.string(), severity: z.string(), location: z.string().optional(), evidenceRef: z.string().optional() });
export const scanChecks = ['secret', 'sbom', 'vuln', 'config'] as const;
export type ScanCheck = typeof scanChecks[number];
const checkName = z.enum(scanChecks);
const failureCode = z.enum(['SCAN_FAILED', 'SCAN_TIMEOUT', 'SCAN_UNAVAILABLE']);
const archiveFailureReason = z.enum(['SCAN_FAILED', 'SCAN_TIMEOUT', 'DB_UNAVAILABLE']);
const archiveReason = z.enum(['SCAN_FAILED', 'SCAN_TIMEOUT', 'DB_UNAVAILABLE', 'OS_EOL', 'OS_UNKNOWN', 'NODE_INVENTORY_ABSENT']);
const subCoverage = z.discriminatedUnion('outcome', [z.object({ outcome: z.literal('checked') }),
  z.object({ outcome: z.literal('unsupported'), reason: archiveReason })]);
const dbTime = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,9}Z$/);
const dbIdentity = z.object({ envelopeVersion: z.literal(1), signer: z.literal('local-db-operator-v1'),
  source: z.string().regex(/^ghcr\.io\/aquasecurity\/trivy-db@sha256:[a-f0-9]{64}$/), schemaVersion: z.literal(2),
  manifestDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/), artifactSha256: z.string().regex(/^[a-f0-9]{64}$/),
  metadataSha256: z.string().regex(/^[a-f0-9]{64}$/), dbSha256: z.string().regex(/^[a-f0-9]{64}$/),
  updatedAt: dbTime, downloadedAt: dbTime, nextUpdate: dbTime }).refine(db => db.source === `ghcr.io/aquasecurity/trivy-db@${db.manifestDigest}`);
const archiveEvidence = { os: subCoverage.optional(), node: subCoverage.optional(), db: dbIdentity.optional() };
const reportImage = z.union([z.string().regex(/^registry-1\.docker\.io\/library\/alpine@sha256:[a-f0-9]{64}$/),
  z.literal('registry-1.docker.io/library/nginx@sha256:0dcc88822d45581e65ae329f8be769762bf628d3b2bb7d2a077d4aa5c98b30e3'),
    z.literal('registry-1.docker.io/library/nginx@sha256:b17b00f7ef0038aeb11362157f49006a130628ee711cefcced871405d046f114')]);
const status = z.object({ config: imageConfigReport.optional(), scanId: z.string(), state, stage: z.string().optional(), percent: z.number().min(0).max(100).nullable().optional(), imageReference: z.string().optional(), digest: z.string().optional(), platform: z.string().optional(), updatedAt: z.string().optional(), check: checkName.optional(), checks: z.array(checkName).optional(), perCheck: z.partialRecord(checkName, z.object({ check: checkName, coverage: z.literal('image'), outcome: z.enum(['checked', 'failed', 'unsupported', 'skipped', 'not_authorized']), errorCode: z.string().nullable().optional(), scannerVersion: z.string().nullable().optional(), findingCount: z.number().int().nonnegative().optional(), componentCount: z.number().int().nonnegative().optional(), reason: z.enum(['SCAN_FAILED', 'SCAN_TIMEOUT', 'DB_UNAVAILABLE', 'OS_EOL', 'OS_UNKNOWN', 'NODE_INVENTORY_ABSENT', 'CHECK_DISABLED', 'USER_NOT_RESOLVABLE', 'OCI_IDENTITY_REJECTED', 'CONFIG_LIMIT_EXCEEDED', 'INVALID_CONFIG']).optional(), ...archiveEvidence, checksVersion: z.string().max(80).optional(), resourcePolicyVersion: z.string().max(80).optional(), supportedRuleIds: z.array(z.string()).optional(), completedRuleIds: z.array(z.string()).optional(), checkedAt: z.string().max(40).optional() }).nullable()).optional() });
const results = z.object({ findings: z.array(finding), nextCursor: z.string().nullable(), coverage: z.array(coverage) });
// Receipt URLs may refer to the internal API. Only the ID crosses into browser navigation.
const receipt = z.object({ scanId: z.string().uuid() });
export type ScanStatus = z.infer<typeof status>;
export type ScanResults = z.infer<typeof results>;
export type ScanFinding = z.infer<typeof finding>;
export type ScanCoverage = z.infer<typeof coverage>;
export type ScanReceipt = z.infer<typeof receipt>;
export type ScanSummary = ScanStatus & { targetLabel: string };
export type ScanIntent = { imageReference: string; scope: 'image'; checks: ScanCheck[]; idempotencyKey: string };
type ArchiveEvidence = { os?: z.infer<typeof subCoverage>; node?: z.infer<typeof subCoverage>; db?: z.infer<typeof dbIdentity> };
export type ScanVuln =
  | ArchiveEvidence & { outcome: 'checked'; coverage: 'image'; image: string; platform: 'linux/amd64'; findingCount: number; scannerVersion: string; checkedAt: string; findings: { findingId: string; cveId: string; ecosystem: 'apk' | 'npm'; packageName: string; installedVersion: string; severity: 'UNKNOWN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'; fixedVersion: string | null }[]; nextCursor: string | null }
  | { outcome: 'failed'; coverage: 'image'; errorCode: 'SCAN_FAILED' | 'SCAN_TIMEOUT' | 'SCAN_UNAVAILABLE'; reason?: z.infer<typeof archiveFailureReason>; findings: []; nextCursor: null }
  | ArchiveEvidence & { outcome: 'unsupported'; coverage: 'image'; reason: z.infer<typeof archiveReason>; findings: []; nextCursor: null };
export type ScanSbom =
  | { outcome: 'checked'; coverage: 'image'; image: string; platform: 'linux/amd64'; os: { name: 'alpine'; version: string }; componentCount: number; scannerVersion: string; checkedAt: string; components: { ecosystem: 'apk' | 'npm'; name: string; version: string }[]; nextCursor: string | null }
  | { outcome: 'failed'; coverage: 'image'; errorCode: 'SCAN_FAILED' | 'SCAN_TIMEOUT' | 'SCAN_UNAVAILABLE'; reason?: z.infer<typeof archiveFailureReason>; components: []; nextCursor: null };
export type ScanCapabilities = { list: boolean; create: boolean; cancel: boolean; events: boolean };
export type ScanTransport = {
  kind: 'fixture' | 'live';
  capabilities: ScanCapabilities;
  list(signal?: AbortSignal): Promise<ScanSummary[]>;
  get(scanId: string, signal?: AbortSignal): Promise<ScanStatus>;
  results(scanId: string, cursor?: string, signal?: AbortSignal): Promise<ScanResults>;
  sbom(scanId: string, cursor?: string, signal?: AbortSignal): Promise<ScanSbom>;
  vuln(scanId: string, cursor?: string, signal?: AbortSignal): Promise<ScanVuln>;
  create(intent: ScanIntent): Promise<ScanReceipt>;
  cancel(scanId: string): Promise<void>;
  subscribeEvents?(scanId: string, onHint: () => void, onError: () => void, onOpen: () => void): () => void;
};
export const parseScanStatus = (value: unknown): ScanStatus => {
  const parsed = status.parse(value);
  for (const [key, item] of Object.entries(parsed.perCheck ?? {})) {
    if (!item) continue;
    if (key === 'config') wireConfigCoverage.parse(item);
    else if (item.reason !== undefined) archiveReason.parse(item.reason);
  }
  return parsed;
};
export const parseScanResults = (value: unknown): ScanResults => results.parse(value);
export const parseScanReceipt = (value: unknown): ScanReceipt => receipt.parse(value);

// Browser scan endpoints currently expose this limited wire shape; new fields require review before display.
const wireOutcome = z.enum(['checked', 'failed', 'unsupported', 'skipped', 'not_authorized']);
const wireCoverage = z.object({ findingCount: z.number().int().nonnegative(), check: z.literal('secret'), coverage: z.literal('image'), outcome: wireOutcome, errorCode: z.string().nullable(), scannerVersion: z.string().nullable() });
const wireSbomResult = z.discriminatedUnion('outcome', [
  z.object({ check: z.literal('sbom'), coverage: z.literal('image'), outcome: z.literal('checked'), componentCount: z.number().int().positive(), scannerVersion: z.string(), checkedAt: z.string() }),
  z.object({ check: z.literal('sbom'), coverage: z.literal('image'), outcome: z.literal('failed'), errorCode: z.enum(['SCAN_FAILED', 'SCAN_TIMEOUT', 'SCAN_UNAVAILABLE']) }),
]);
const wireVulnResult = z.discriminatedUnion('outcome', [
  z.object({ check: z.literal('vuln'), coverage: z.literal('image'), outcome: z.literal('checked'), findingCount: z.number().int().nonnegative(), scannerVersion: z.string().min(1), checkedAt: z.string().min(1) }),
  z.object({ check: z.literal('vuln'), coverage: z.literal('image'), outcome: z.literal('failed'), errorCode: failureCode }),
]);
const wireArchiveCheck = z.object({ check: checkName, coverage: z.literal('image'), outcome: wireOutcome,
  reason: archiveReason.optional(), errorCode: failureCode.nullable(), scannerVersion: z.literal('0.69.3'),
  checksVersion: z.string().min(1).max(80), checkedAt: z.string().datetime(),
  findingCount: z.number().int().nonnegative().optional(), componentCount: z.number().int().nonnegative().optional(), ...archiveEvidence });
const wirePerCheck = z.unknown().transform((value, context) => {
  const schema = value && typeof value === 'object' && 'check' in value && value.check === 'config'
    ? wireConfigCoverage : value && typeof value === 'object' && 'checksVersion' in value
      ? wireArchiveCheck : z.union([wireCoverage, wireSbomResult, wireVulnResult]);
  const parsed = schema.safeParse(value);
  if (!parsed.success) { context.addIssue({ code: 'custom', message: 'Invalid check coverage' }); return z.NEVER; }
  return parsed.data;
});
const wireChecks = z.array(checkName).min(1).max(4).refine(checks => checks.every((check, index) => index === 0 || scanChecks.indexOf(checks[index - 1]) < scanChecks.indexOf(check)), 'Проверки должны быть отсортированы без повторов');
const wireStatus = z.object({ config: imageConfigReport.optional(), imageReference: reportImage.optional(), scanId: z.string(), state: z.enum(['queued', 'running', 'completed', 'partial', 'failed', 'cancelled']), digest: z.string().regex(/^sha256:[a-f0-9]{64}$/).optional(), platform: z.string().regex(/^linux\/[a-z0-9]+(?:\/[a-z0-9]+)?$/).optional(), check: checkName.nullable().optional(), checks: wireChecks.optional(), perCheck: z.partialRecord(checkName, wirePerCheck.nullable()).optional(), result: wirePerCheck.nullable() });
const sbomComponent = z.strictObject({ ecosystem: z.enum(['apk', 'npm']), name: z.string().min(1).max(128), version: z.string().min(1).max(80) });
const wireSbom = z.discriminatedUnion('outcome', [
  z.strictObject({ outcome: z.literal('checked'), coverage: z.literal('image'), image: reportImage, platform: z.literal('linux/amd64'), os: z.strictObject({ name: z.literal('alpine'), version: z.string().min(1).max(80) }), componentCount: z.number().int().positive(), scannerVersion: z.string().min(1), checkedAt: z.string().min(1), components: z.array(sbomComponent).max(100), nextCursor: z.number().int().nonnegative().nullable() }),
  z.strictObject({ outcome: z.literal('failed'), coverage: z.literal('image'), errorCode: failureCode,
    reason: archiveFailureReason.optional(), components: z.tuple([]), nextCursor: z.null() })
    .refine(page => page.reason === undefined || page.errorCode === (page.reason === 'SCAN_TIMEOUT' ? 'SCAN_TIMEOUT' : 'SCAN_FAILED'), 'Несогласованная причина отказа SBOM'),
]);
export function parseCurrentSbom(value: unknown): ScanSbom {
  const page = wireSbom.parse(value);
  if (page.outcome === 'failed') return page;
  if (page.components.length > page.componentCount || (page.nextCursor !== null && (page.components.length === 0 || page.nextCursor > page.componentCount))) throw new Error('Недопустимая страница SBOM');
  return { ...page, nextCursor: page.nextCursor === null ? null : String(page.nextCursor) };
}
const wireList = z.object({ scans: z.array(z.object({ scanId: z.string().uuid(), state: wireStatus.shape.state, digest: wireStatus.shape.digest.unwrap(), platform: wireStatus.shape.platform.unwrap(), targetLabel: z.string() })), nextCursor: z.string().regex(/^[1-9]\d{0,14}:[1-9]\d{0,14}$/).nullable() });
const wireResults = z.object({ findings: z.array(z.object({ findingId: z.string(), ruleId: z.string(), line: z.number().nullable(), evidenceRef: z.string() })), nextCursor: z.number().int().nonnegative().nullable(), coverage: wireCoverage.nullable() });
export function parseCurrentStatus(value: unknown): ScanStatus {
  const current = wireStatus.parse(value);
  const checks = current.checks ?? (current.check || current.result ? [current.check ?? current.result!.check] : undefined);
  const perCheck = current.perCheck ?? (checks?.length === 1 ? { [checks[0]]: current.result ?? null } : undefined);
  if (checks && perCheck && (Object.keys(perCheck).some(key => !checks.includes(key as ScanCheck) || (perCheck[key as ScanCheck] != null && perCheck[key as ScanCheck]?.check !== key)) || checks.some(key => !(key in perCheck)))) throw new Error('Недопустимый статус проверок');
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
export function parseCurrentResults(value: unknown): ScanResults {
  const current = wireResults.parse(value);
  const secret = current.coverage;
  return {
    findings: current.findings.map(({ findingId, ruleId }) => ({ findingId, ruleId, category: 'secret', severity: 'unknown' })),
    nextCursor: current.nextCursor === null ? null : String(current.nextCursor),
    coverage: [
      { check: 'Secrets', status: secret?.outcome ?? 'skipped', reason: secret?.errorCode ?? (secret ? undefined : 'Результат ещё не получен'), scannerVersion: secret?.scannerVersion ?? undefined },
      { check: 'CVE', status: 'unsupported', reason: 'В текущем API проверка недоступна' },
      { check: 'SBOM', status: 'unsupported', reason: 'В текущем API проверка недоступна' },
    ],
  };
}
const wireVulnFinding = z.object({ findingId: z.string(), cveId: z.string(), ecosystem: z.enum(['apk', 'npm']), packageName: z.string(), installedVersion: z.string(), severity: z.enum(['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']), fixedVersion: z.string().nullable() });
const wireVuln = z.discriminatedUnion('outcome', [
  z.object({ outcome: z.literal('checked'), coverage: z.literal('image'), image: reportImage, ...archiveEvidence, platform: z.literal('linux/amd64'), findingCount: z.number().int().nonnegative(), scannerVersion: z.string().min(1), checkedAt: z.string().min(1), findings: z.array(wireVulnFinding).max(100), nextCursor: z.number().int().nonnegative().nullable() }),
  z.strictObject({ outcome: z.literal('failed'), coverage: z.literal('image'), errorCode: failureCode,
      reason: archiveFailureReason.optional(), findings: z.tuple([]), nextCursor: z.null() })
      .refine(page => page.reason === undefined || page.errorCode === (page.reason === 'SCAN_TIMEOUT' ? 'SCAN_TIMEOUT' : 'SCAN_FAILED'), 'Несогласованная причина отказа CVE'),
  z.object({ outcome: z.literal('unsupported'), coverage: z.literal('image'), reason: archiveReason, ...archiveEvidence, findings: z.tuple([]), nextCursor: z.null() }),
]);
export function parseCurrentVuln(value: unknown): ScanVuln {
  const page = wireVuln.parse(value);
  if (page.outcome !== 'checked') return page;
  if (page.findings.length > page.findingCount || (page.nextCursor !== null && (page.findings.length === 0 || page.nextCursor > page.findingCount))) throw new Error('Недопустимая страница CVE');
  return { ...page, findings: page.findings.map(({ findingId, cveId, ecosystem, packageName, installedVersion, severity, fixedVersion }) => ({ findingId, cveId, ecosystem, packageName, installedVersion, severity, fixedVersion })), nextCursor: page.nextCursor === null ? null : String(page.nextCursor) };
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
