import { z } from 'zod';
import { reportEcosystem, reportSeveritySource, type ReportEcosystem } from './publicImageProfile';
import { vulnerabilityIdentifierKind } from './publicVulnerabilityIdentifiers';
import { advisorySeverity, advisorySource } from './vulnAdvisory';

const count = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);

// Keep aligned with server llm/remediation-identifiers.ts and worker/public-image-evidence.ts.
const dataToken = (value: string) =>
  !/CANARY|(?:^|[-_.])(?:sk-|AKIA)|(?:ignore|disregard)[-_.]*(?:all[-_.]*)?(?:previous[-_.]*)?instructions|(?:system|developer)[-_.]*prompt|(?:api[-_]?key|password|secret|token)[:=]|[A-Za-z0-9_+/=-]{40,}/i.test(
    value,
  );
function packageName(value: string, ecosystem: ReportEcosystem): boolean {
  if (!value.length || value.length > 128) return false;
  if (ecosystem === 'npm') return /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(value);
  if (ecosystem === 'gomod')
    return (
      ['stdlib', 'toolchain'].includes(value) ||
      /^[A-Za-z0-9][A-Za-z0-9._+-]*(?:\/[A-Za-z0-9][A-Za-z0-9._+-]*)+$/.test(value)
    );
  if (ecosystem === 'composer') return /^[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*$/.test(value);
  if (ecosystem === 'maven') return /^[A-Za-z0-9][A-Za-z0-9._-]*:[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value);
  return /^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(value);
}
const packageVersion = (value: unknown): value is string =>
  typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._+~:!,-]{0,79}$/.test(value) && dataToken(value);
function validRemediationFinding(value: {
  check: string;
  packageName?: string;
  installedVersion?: string;
  fixedVersion?: string | null;
  ecosystem?: ReportEcosystem;
  identifierKind?: string;
  cveId?: string;
  fixedVersionReported?: boolean;
}): boolean {
  const hasFields = ['packageName', 'installedVersion', 'fixedVersion'].some((key) =>
    Object.hasOwn(value, key),
  );
  const kind = typeof value.cveId === 'string' ? vulnerabilityIdentifierKind(value.cveId) : undefined;
  if (value.check === 'vuln' && (!kind || (kind === 'cve'
    ? value.identifierKind !== undefined && value.identifierKind !== kind
    : value.identifierKind !== kind || value.ecosystem !== 'deb'))) return false;
  if (!hasFields) return true;
  return (
    value.check === 'vuln' &&
    typeof value.cveId === 'string' &&
    kind !== undefined && value.identifierKind === kind &&
    !!value.ecosystem &&
    typeof value.packageName === 'string' &&
    packageName(value.packageName, value.ecosystem) &&
    dataToken(value.packageName) &&
    packageVersion(value.installedVersion) &&
    (value.fixedVersion === null || packageVersion(value.fixedVersion)) &&
    value.fixedVersionReported === (value.fixedVersion !== null)
  );
}
const fieldState = z.enum([
  'available',
  'missing',
  'invalid',
  'redacted',
  'truncated',
  'unsupported',
  'omitted',
]);
const cvss = z
  .strictObject({
    family: z.enum(['v2', 'v3']),
    version: z.enum(['2.0', '3.0', '3.1']).nullable(),
    versionState: fieldState,
    reportedScore: z.number().finite().min(0).max(10).nullable(),
    scoreState: z.enum(['available', 'missing', 'invalid']),
    vectorState: fieldState,
  })
  .refine((v) => (v.scoreState === 'available' ? v.reportedScore !== null : v.reportedScore === null));
const vulnBase = {
  check: z.literal('vuln'),
  findingId: z.string().regex(/^vuln-[a-f0-9]{64}$/),
  severity: advisorySeverity,
  cveId: z.string().refine((id) => vulnerabilityIdentifierKind(id) !== undefined),
  identifierKind: z.enum(['cve', 'debian-temp', 'debian-dla']).optional(),
  ecosystem: reportEcosystem,
  severitySources: z
    .array(reportSeveritySource)
    .min(1)
    .max(32)
    .refine((v) => new Set(v).size === v.length),
  provenanceRef: z.string().regex(/^target-[a-f0-9]{64}$/),
  fixedVersionReported: z.boolean(),
  packageName: z.string().optional(),
  installedVersion: z.string().optional(),
  fixedVersion: z.string().nullable().optional(),
};
export const publicSafeFinding = z
  .union([
    z.strictObject({
      check: z.literal('secret'),
      findingId: z.string().regex(/^secret-\d{1,6}-\d{1,6}$/),
      severity: z.literal('UNKNOWN'),
      ruleId: z.string().regex(/^rule-[a-f0-9]{16}$/),
      line: count.max(10000000).nullable(),
      evidenceRef: z.string().regex(/^result-\d{1,6}-secret-\d{1,6}$/),
    }),
    z.strictObject({
      check: z.literal('config'),
      findingId: z.string().regex(/^sha256:[a-f0-9]{64}$/),
      severity: z.literal('MEDIUM'),
      ruleId: z.literal('IMGCFG_USER_ROOT'),
      classification: z.enum(['DEFAULT_ROOT', 'NUMERIC_ROOT']),
      configDigest: digest,
      manifestDigest: digest,
      location: z.literal('/config/User'),
    }),
    z.strictObject({ ...vulnBase, advisoryState: z.literal('unknown') }),
    z.strictObject({
      ...vulnBase,
      advisoryState: z.enum(['available', 'omitted']),
      conflictState: z.enum(['none', 'present', 'unknown']),
      conflicts: z.array(z.enum(['title', 'description', 'severity', 'fixedVersion', 'cvss'])).max(5),
      limitations: z
        .array(
          z.enum([
            'invalid_metadata',
            'redaction',
            'field_limit',
            'assessment_limit',
            'reference_limit',
            'finding_budget',
            'scan_budget',
            'report_budget',
          ]),
        )
        .max(8),
      assessments: z
        .array(
          z.strictObject({
            source: advisorySource,
            severity: advisorySeverity.nullable(),
            fixedVersionReported: z.boolean(),
            cvss: cvss.nullable(),
          }),
        )
        .max(16),
    }),
  ])
  .refine(validRemediationFinding);

export type LlmFinding = z.infer<typeof publicSafeFinding>;
