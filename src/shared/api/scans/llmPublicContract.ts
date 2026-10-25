import { z } from 'zod';
import { cveMetadataFields } from './cveDbMetadata';
import { imageConfigReport } from './imageConfigReport';
import { identifierCounts } from './publicVulnerabilityIdentifiers';

const count = z.number().int().min(0).max(1000);
const hash = z.string().regex(/^[a-f0-9]{64}$/);
const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const stamp = z.string().regex(/^\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+Z)?$/);
const dbStamp = z.string().regex(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z$/);
const reason = z.enum([
  'SCAN_FAILED',
  'SCAN_TIMEOUT',
  'SCAN_UNAVAILABLE',
  'DB_UNAVAILABLE',
  'OS_EOL',
  'OS_UNKNOWN',
  'NODE_INVENTORY_ABSENT',
  'NODE_INVENTORY_UNKNOWN',
  'OS_UNSUPPORTED',
  'CHECK_DISABLED',
  'INVALID_CHECK_FLAG',
  'INVALID_RESOURCE_POLICY',
  'OCI_IDENTITY_REJECTED',
  'CONFIG_LIMIT_EXCEEDED',
  'INVALID_CONFIG',
  'USER_NOT_RESOLVABLE',
  'RULE_NOT_IMPLEMENTED',
  'SOURCE_NOT_PROVIDED',
  'SOURCE_ANALYZER_UNSUPPORTED',
]);
const unknown = z.strictObject({
  outcome: z.literal('unknown'),
  reason: z.enum(['NOT_REPORTED', 'CHECK_NOT_REQUESTED', 'NO_RESULT']),
});
const basic = z.strictObject({
  outcome: z.enum(['checked', 'failed', 'unsupported', 'skipped']),
  scope: z.literal('image'),
  reason: reason.nullable(),
  errorCode: reason.nullable(),
  findingCount: count.nullable().optional(),
  componentCount: count.optional(),
  scannerVersion: z
    .string()
    .regex(/^\d+\.\d+\.\d+$/)
    .nullable()
    .optional(),
  checkedAt: stamp.optional(),
});
const db = z.strictObject({
  envelopeVersion: z.literal(1),
  schemaVersion: z.literal(2),
  signer: z.literal('local-db-operator-v1'),
  manifestDigest: digest,
  artifactSha256: hash,
  metadataSha256: hash,
  dbSha256: hash,
  updatedAt: dbStamp,
  downloadedAt: dbStamp,
  nextUpdate: dbStamp,
});
const coverage = basic.extend({
  os: z.union([basic, unknown]),
  node: z.union([basic, unknown]),
  db: z.union([db, unknown]),
  dbPolicy: cveMetadataFields.dbPolicy.optional(),
});
const config = coverage.extend({
  history: imageConfigReport.shape.history,
  dockerfile: imageConfigReport.shape.dockerfile,
  iac: imageConfigReport.shape.iac,
  rules: imageConfigReport.shape.rules,
  checksVersion: imageConfigReport.shape.checksVersion,
  resourcePolicyVersion: imageConfigReport.shape.resourcePolicyVersion,
  supportedRuleIds: imageConfigReport.shape.supportedRuleIds,
  completedRuleIds: imageConfigReport.shape.completedRuleIds,
});
const publicCoverage = z.strictObject({
  secret: z.union([coverage, unknown]),
  sbom: z.union([coverage, unknown]),
  vuln: z.union([coverage, unknown]),
  config: z.union([config, unknown]),
});
const findingCounts = z.strictObject({
  byCheck: z.strictObject({
    secret: count.nullable(),
    sbom: count.nullable(),
    vuln: count.nullable(),
    config: count.nullable(),
  }),
  bySeverity: z.strictObject({ UNKNOWN: count, LOW: count, MEDIUM: count, HIGH: count, CRITICAL: count }),
});
export const publicChatMetadataShape = {
  findingCount: count.optional(),
  findingCounts: findingCounts.optional(),
  identifierCounts: identifierCounts.optional(),
  coverage: publicCoverage.optional(),
};
type PublicMetadata = z.infer<z.ZodObject<typeof publicChatMetadataShape>>;
// Legacy responses have none of these fields. A public group must be complete and internally consistent.
export function validPublicChatMetadata(value: PublicMetadata): boolean {
  if (value.findingCount === undefined)
    return (
      value.findingCounts === undefined &&
      value.identifierCounts === undefined &&
      value.coverage === undefined
    );
  if (!value.findingCounts || !value.coverage) return false;
  if (
    Object.values(value.findingCounts.bySeverity).reduce((n, v) => n + v, 0) !== value.findingCount ||
    Object.values(value.findingCounts.byCheck).reduce<number>((n, v) => n + (v ?? 0), 0) !==
      value.findingCount
  )
    return false;
  for (const check of ['secret', 'sbom', 'vuln', 'config'] as const) {
    const item = value.coverage[check];
    if (
      value.findingCounts.byCheck[check] !==
      (item.outcome === 'checked' ? (check === 'sbom' ? 0 : item.findingCount) : null)
    )
      return false;
  }
  return value.coverage.vuln.outcome === 'checked'
    ? !!value.identifierCounts &&
        value.identifierCounts.cve + value.identifierCounts.debianTemp === value.findingCounts.byCheck.vuln
    : value.identifierCounts === undefined;
}
export const chatContextSelectionSchema = z.strictObject({
  findings: count,
  explanations: z.number().int().min(0).max(256),
  selectedFindingIds: z
    .array(z.string().regex(/^(?:secret-\d{1,6}-\d{1,6}|vuln-[a-f0-9]{64}|sha256:[a-f0-9]{64})$/))
    .max(1000)
    .refine((ids) => new Set(ids).size === ids.length),
});

export const freeProfileSchema = z.union([
  z.strictObject({
    model: z.literal('apodex/apodex-1.1-mini:free'),
    providers: z.tuple([z.literal('novita/bf16')]),
  }),
  z.strictObject({
    model: z.literal('xingchen-agi/xing4.0-29b-a4b:free'),
    providers: z.tuple([z.literal('phala')]),
  }),
]);
const catalogBase = { checkedOn: z.literal('2026-10-21'), liveVerified: z.literal(false) };
const catalog = z.union([
  z.strictObject({
    ...catalogBase,
    status: z.literal('catalog-listed-unprobed'),
    model: z.literal('xingchen-agi/xing4.0-29b-a4b:free'),
    endpoint: z.literal('phala'),
    zdrListed: z.literal(true),
  }),
  z.strictObject({
    ...catalogBase,
    status: z.literal('no-catalog-endpoints'),
    model: z.literal('apodex/apodex-1.1-mini:free'),
    endpoint: z.literal('novita/bf16'),
    zdrListed: z.literal(false),
  }),
  z.strictObject({ ...catalogBase, status: z.literal('unverified-profile'), zdrListed: z.literal(false) }),
]);
export const readinessBlockerSchema = z.enum([
  'configuration-required',
  'public-key-required',
  'public-key-unsafe',
  'quota-store-unavailable',
  'history-store-unavailable',
  'provider-profile-unavailable',
]);
export const publicReadinessShape = {
  status: z.enum(['setup-required', 'locally-configured']),
  localReady: z.boolean(),
  blockers: z
    .array(readinessBlockerSchema)
    .max(5)
    .refine((v) => new Set(v).size === v.length),
  credential: z.enum(['unconfigured', 'missing', 'unsafe', 'metadata-valid']),
  quota: z.enum(['available', 'unavailable']),
  history: z.enum(['available', 'unavailable']),
  provider: catalog,
  generationVerified: z.literal(false),
  requiresConsent: z.literal(true),
  acceptsCredentials: z.literal(false),
  setupAction: z.literal('operator-public-file-configuration'),
};
export function validPublicReadiness(value: z.infer<z.ZodObject<typeof publicReadinessShape>>) {
  const expected: z.infer<typeof readinessBlockerSchema>[] = [];
  if (value.provider.status === 'unverified-profile') expected.push('configuration-required');
  if (value.credential !== 'metadata-valid')
    expected.push(value.credential === 'unsafe' ? 'public-key-unsafe' : 'public-key-required');
  if (value.quota !== 'available') expected.push('quota-store-unavailable');
  if (value.history !== 'available') expected.push('history-store-unavailable');
  if (value.provider.status !== 'catalog-listed-unprobed') expected.push('provider-profile-unavailable');
  return (
    JSON.stringify(expected) === JSON.stringify(value.blockers) &&
    value.localReady === !expected.length &&
    value.status === (expected.length ? 'setup-required' : 'locally-configured')
  );
}
export type ReadinessBlocker = z.infer<typeof readinessBlockerSchema>;

export const providerFailureSchema = z
  .strictObject({
    kind: z.enum(['rate_limited', 'auth_failed', 'unavailable']),
    status: z.number().int().min(300).max(599),
    retryAfterSeconds: z.number().int().min(0).max(86400).optional(),
  })
  .refine((value) => {
    const kind =
      value.status === 429 || value.status === 503
        ? 'rate_limited'
        : value.status === 401
          ? 'auth_failed'
          : 'unavailable';
    return value.kind === kind && (value.retryAfterSeconds === undefined || kind === 'rate_limited');
  })
  .readonly();
export type ProviderFailure = z.infer<typeof providerFailureSchema>;
export const providerErrorCodeSchema = z.enum([
  'LLM_PROVIDER_RATE_LIMITED',
  'LLM_PROVIDER_AUTH_FAILED',
  'LLM_PROVIDER_UNAVAILABLE',
]);
export type ProviderErrorCode = z.infer<typeof providerErrorCodeSchema>;
export function validProviderError(value: { errorCode: string; providerFailure?: ProviderFailure }) {
  if (!value.providerFailure) return true;
  const code =
    value.providerFailure.kind === 'rate_limited'
      ? 'LLM_PROVIDER_RATE_LIMITED'
      : value.providerFailure.kind === 'auth_failed'
        ? 'LLM_PROVIDER_AUTH_FAILED'
        : 'LLM_PROVIDER_UNAVAILABLE';
  return value.errorCode === code;
}
export const providerErrorSchema = z
  .strictObject({
    errorCode: providerErrorCodeSchema,
    providerFailure: providerFailureSchema.optional(),
  })
  .refine(validProviderError);
export const llmJsonErrorSchema = z.union([
  providerErrorSchema,
  // Legacy JSON diagnostics were ignored, never displayed. They cannot smuggle new provider metadata.
  z.object({
    errorCode: z
      .string()
      .regex(/^[A-Z_]{1,64}$/)
      .refine((code) => code !== 'LLM_PROVIDER_RATE_LIMITED' && code !== 'LLM_PROVIDER_AUTH_FAILED'),
    providerFailure: z.never().optional(),
  }),
]);
export function validLlmErrorStatus(
  value: { errorCode: string; providerFailure?: ProviderFailure },
  status: number,
) {
  if (value.errorCode === 'LLM_PROVIDER_RATE_LIMITED')
    return (
      (status === 429 || status === 503) &&
      (!value.providerFailure || value.providerFailure.status === status)
    );
  if (value.errorCode === 'LLM_PROVIDER_AUTH_FAILED') return status === 503;
  return value.providerFailure === undefined || status === 502;
}
export function providerFailureDetails(failure: ProviderFailure | undefined): string {
  if (!failure) return '';
  return (
    ` Статус провайдера: HTTP ${failure.status}.` +
    (failure.retryAfterSeconds === undefined
      ? ''
      : ` Подсказка ожидания провайдера: ${failure.retryAfterSeconds} с; не гарантия доступности и не разрешение на повтор.`)
  );
}
