import { z } from 'zod';

export const advisorySources = [
  'unknown',
  'alpine',
  'nvd',
  'ghsa',
  'npm',
  'nodejs-security-wg',
  'osv',
  'cve',
  'redhat',
  'ubuntu',
  'photon',
  'amazon',
  'oracle-oval',
  'julia',
  'alma',
  'azure',
  'rocky',
  'cbl-mariner',
  'bitnami',
  'ruby-advisory-db',
  'bottlerocket',
] as const;
export const advisorySource = z.enum(advisorySources);
export const advisorySeverity = z.enum(['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export const provenanceRef = z.string().regex(/^target-[a-f0-9]{64}$/);
export const utf8Bytes = (value: string) => new TextEncoder().encode(value).length;
export const serializedBytes = (value: unknown) => utf8Bytes(JSON.stringify(value));

// Run before Zod can copy objects: inherited properties, accessors and magic keys
// must never become trusted wire evidence. JSON responses only contain data objects.
export function assertPlainWire(value: unknown, ancestors = new Set<object>()): void {
  if (value === null || typeof value !== 'object') return;
  if (
    ancestors.has(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== Array.prototype &&
      Object.getPrototypeOf(value) !== null)
  )
    throw new Error('Invalid wire object');
  ancestors.add(value);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || ['__proto__', 'prototype', 'constructor'].includes(key))
      throw new Error('Invalid wire key');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !('value' in descriptor)) throw new Error('Invalid wire property');
    assertPlainWire(descriptor.value, ancestors);
  }
  ancestors.delete(value);
}

const boundedText = (bytes: number) =>
  z
    .string()
    .min(1)
    .refine((value) => utf8Bytes(value) <= bytes, 'Text byte limit');
// Reject controls at the wire boundary; this regex deliberately names control bytes.
const safePlainText = (value: string) =>
  value === value.trim() &&
  // eslint-disable-next-line no-control-regex
  !/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\ufeff\ud800-\udfff]/u.test(value) &&
  !/<[^>]*>|!?\[[^\]]*\]\([^)]*\)|(?:https?:\/\/|www\.)|-----BEGIN [^-]*PRIVATE KEY-----/i.test(value) &&
  !/\b(?:(?:basic|bearer)\s+\S+|(?:password|passwd|secret|credentials?|api[_-]?key|access[_-]?key|token|signature|x-amz-[\w-]+)["']?\s*[:=]\s*[^\s]+|[\w-]*CANARY[\w-]*|AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{12,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/i.test(
    value,
  );
const fieldState = z.enum([
  'available',
  'missing',
  'invalid',
  'redacted',
  'truncated',
  'unsupported',
  'omitted',
]);
const plainField = (bytes: number) =>
  z
    .strictObject({
      value: boundedText(bytes).refine(safePlainText).nullable(),
      state: fieldState,
      redacted: z.boolean(),
    })
    .refine(
      (field) => (field.state === 'available' || field.state === 'truncated') === (field.value !== null),
    )
    .refine((field) => field.state !== 'redacted' || field.redacted);
const metrics: Record<string, string[]> = {
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'R'],
  S: ['U', 'C'],
  C: ['H', 'L', 'N'],
  I: ['H', 'L', 'N'],
  A: ['H', 'L', 'N'],
};
export function validCvssVector(vector: string, version: '3.0' | '3.1'): boolean {
  if (utf8Bytes(vector) > 256 || !vector.startsWith(`CVSS:${version}/`)) return false;
  const seen = new Set<string>();
  for (const part of vector.split('/').slice(1)) {
    const [key, value, extra] = part.split(':');
    if (extra !== undefined || !Object.hasOwn(metrics, key) || !metrics[key].includes(value) || seen.has(key))
      return false;
    seen.add(key);
  }
  return ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'].every((key) => seen.has(key));
}
const cvss = z
  .strictObject({
    family: z.enum(['v2', 'v3']),
    version: z.enum(['2.0', '3.0', '3.1']).nullable(),
    versionState: fieldState,
    reportedScore: z.number().finite().min(0).max(10).nullable(),
    scoreState: z.enum(['available', 'missing', 'invalid']),
    vector: boundedText(256).nullable(),
    vectorState: fieldState,
  })
  .refine(
    (value) =>
      (value.versionState === 'available') === (value.version !== null) &&
      (value.scoreState === 'available') === (value.reportedScore !== null) &&
      (value.vectorState === 'available') === (value.vector !== null),
  )
  .refine((value) =>
    value.family === 'v2'
      ? value.version === '2.0' &&
        value.versionState === 'available' &&
        value.vector === null &&
        value.vectorState === 'unsupported'
      : value.vector === null
        ? value.version === null &&
          ['missing', 'invalid', 'unsupported', 'omitted'].includes(value.vectorState) &&
          ['missing', 'invalid', 'unsupported', 'omitted'].includes(value.versionState)
        : (value.version === '3.0' || value.version === '3.1') &&
          validCvssVector(value.vector, value.version),
  );
const assessment = z.strictObject({
  source: advisorySource,
  provenanceRef,
  title: plainField(512),
  description: plainField(4096),
  language: boundedText(35)
    .regex(/^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/)
    .nullable(),
  severity: advisorySeverity.nullable(),
  fixedVersion: boundedText(80)
    .regex(/^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,79}$/)
    .nullable(),
  cvss: cvss.nullable(),
});
export const FIRST_CALCULATOR = 'https://www.first.org/cvss/calculator/3.1';
export function canonicalReferences(cveId: string) {
  if (!/^CVE-[0-9]{4}-[0-9]{4,12}$/.test(cveId)) return [];
  return [
    {
      kind: 'canonical' as const,
      authority: 'cve' as const,
      url: `https://www.cve.org/CVERecord?id=${cveId}`,
    },
    {
      kind: 'canonical' as const,
      authority: 'nvd' as const,
      url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
    },
  ];
}
const reference = z.strictObject({
  kind: z.enum(['canonical', 'calculator']),
  authority: z.enum(['cve', 'nvd', 'first']),
  url: boundedText(2048),
});
const ordered = (items: string[], values: readonly string[]) =>
  items.every((item, index) => index === 0 || values.indexOf(items[index - 1]) < values.indexOf(item));
const conflictKeys = ['title', 'description', 'severity', 'fixedVersion', 'cvss'] as const;
const limitationKeys = [
  'invalid_metadata',
  'redaction',
  'field_limit',
  'assessment_limit',
  'reference_limit',
  'finding_budget',
  'scan_budget',
  'report_budget',
] as const;
const unique = (items: unknown[]) => new Set(items.map((item) => JSON.stringify(item))).size === items.length;
export const advisoryV1 = z
  .strictObject({
    schemaVersion: z.literal(1),
    state: z.enum(['available', 'omitted']),
    assessments: z.array(assessment).max(16).refine(unique),
    references: z.array(reference).max(8).refine(unique),
    conflicts: z
      .array(z.enum(conflictKeys))
      .max(5)
      .refine((items) => ordered(items, conflictKeys)),
    conflictState: z.enum(['none', 'present', 'unknown']),
    limitations: z
      .array(z.enum(limitationKeys))
      .max(8)
      .refine((items) => ordered(items, limitationKeys)),
  })
  .refine((value) => serializedBytes(value) <= 16384)
  .refine(
    (value) =>
      value.conflictState === 'unknown' || (value.conflictState === 'present') === value.conflicts.length > 0,
  )
  .refine(
    (value) =>
      value.state !== 'omitted' ||
      (value.assessments.length === 0 &&
        value.references.length === 0 &&
        value.conflicts.length === 0 &&
        value.conflictState === 'unknown' &&
        value.limitations.some((limit) =>
          ['finding_budget', 'scan_budget', 'report_budget'].includes(limit),
        )),
  );
export type AdvisoryV1 = z.infer<typeof advisoryV1>;
export function validAdvisoryReferences(advisory: AdvisoryV1, cveId: string): boolean {
  const allowed = canonicalReferences(cveId);
  const canCalculate =
    allowed.length > 0 &&
    advisory.assessments.some(
      (item) =>
        item.cvss?.version === '3.1' && item.cvss.vector !== null && validCvssVector(item.cvss.vector, '3.1'),
    );
  if (
    !ordered(
      advisory.references.map((ref) => ref.authority),
      ['cve', 'nvd', 'first'],
    )
  )
    return false;
  return advisory.references.every((ref) =>
    ref.kind === 'calculator'
      ? canCalculate && ref.authority === 'first' && ref.url === FIRST_CALCULATOR
      : allowed.some((item) => item.authority === ref.authority && item.url === ref.url),
  );
}
