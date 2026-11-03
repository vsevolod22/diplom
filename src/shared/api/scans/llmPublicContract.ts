import { z } from 'zod';
import { cveMetadataFields } from './cveDbMetadata';
import { imageConfigReport } from './imageConfigReport';
import { identifierCounts, identifierCountsTotal } from './publicVulnerabilityIdentifiers';

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
        identifierCountsTotal(value.identifierCounts) === value.findingCounts.byCheck.vuln
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
    retention: z.literal('no-storage'),
  }),
  z.strictObject({
    model: z.literal('dots-studio/dots-3-note-preview:free'),
    providers: z.tuple([z.literal('atlas-cloud/fp8')]),
    retention: z.literal('no-training'),
  }),
]);
export const LEGACY_SCANNER_DISCLOSURE =
  'Sanitized scanner findings and coverage; no raw evidence or credentials.';
export const REMEDIATION_SCANNER_DISCLOSURE =
  'Sanitized scanner findings, package names, installed and reported fixed versions, and coverage; no raw evidence or credentials.';
export const scannerDisclosureData = z.enum([LEGACY_SCANNER_DISCLOSURE, REMEDIATION_SCANNER_DISCLOSURE]);
/** New egress is supported only by the exact public remediation profile; legacy DTOs stay readable. */
export function validScannerDisclosure(value: {
  data: string;
  model: string;
  providers: string[];
  retention: string;
  freeOnly?: boolean;
  requestBudgetUsd: number;
  maxPrice?: { prompt: number; completion: number; request: number | null };
}): boolean {
  return (
    value.data === LEGACY_SCANNER_DISCLOSURE ||
    (value.data === REMEDIATION_SCANNER_DISCLOSURE &&
      value.model === 'dots-studio/dots-3-note-preview:free' &&
      freeProfileSchema.safeParse({
        model: value.model,
        providers: value.providers,
        retention: value.retention,
      }).success &&
      value.freeOnly === true &&
      value.requestBudgetUsd === 0 &&
      value.maxPrice?.prompt === 0 &&
      value.maxPrice.completion === 0 &&
      value.maxPrice.request === 0)
  );
}
export const OPENAI_MODEL = 'gpt-5.4-mini-2026-03-17';
export const OPENAI_COST_BASIS = 'server-estimated-configured-rates-not-invoice';
const positiveInteger = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const positiveBudget = z.number().finite().positive();
const openAiDisclosureShape = {
  provider: z.literal('OpenAI'),
  model: z.literal(OPENAI_MODEL),
  retention: z.literal('no-training'),
  operatorApprovedRouting: z.literal(true),
  providerComplianceNotProvenByDeclaration: z.literal(true),
  zeroDataRetentionVerified: z.literal(false),
  costBasis: z.literal(OPENAI_COST_BASIS),
  estimatedPrice: z.strictObject({
    unit: z.literal('microUSD-per-million-tokens'),
    input: positiveInteger,
    output: positiveInteger,
  }),
  data: scannerDisclosureData,
};
export const openAiDisclosureSchema = z.discriminatedUnion('monetaryLimit', [
  z.strictObject({
    ...openAiDisclosureShape,
    monetaryLimit: z.literal('capped'),
    requestBudgetMicros: positiveBudget,
    userBudgetMicros: positiveBudget,
    scanBudgetMicros: positiveBudget,
  }),
  z.strictObject({
    ...openAiDisclosureShape,
    monetaryLimit: z.literal('uncapped'),
    requestBudgetMicros: z.null(),
    userBudgetMicros: z.null(),
    scanBudgetMicros: z.null(),
  }),
]);
export type OpenAiDisclosure = z.infer<typeof openAiDisclosureSchema>;

const catalogBase = { checkedOn: z.literal('2026-10-21'), liveVerified: z.literal(false) };
const catalog = z.union([
  z.strictObject({
    checkedOn: z.literal('2026-10-29'),
    liveVerified: z.literal(false),
    status: z.literal('catalog-listed-unprobed'),
    model: z.literal('dots-studio/dots-3-note-preview:free'),
    endpoint: z.literal('atlas-cloud/fp8'),
    zdrListed: z.literal(false),
    retention: z.literal('no-training'),
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
  if (value.provider.status !== 'catalog-listed-unprobed') expected.push('configuration-required');
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

export const openAiReadinessShape = {
  status: z.enum(['setup-required', 'locally-configured']),
  localReady: z.boolean(),
  blockers: z
    .array(
      z.enum([
        'configuration-required',
        'environment-key-required',
        'accounting-configuration-required',
        'quota-store-unavailable',
        'history-store-unavailable',
      ]),
    )
    .max(5)
    .refine((v) => new Set(v).size === v.length),
  credential: z.enum(['unavailable', 'environment-valid']),
  quota: z.enum(['available', 'unavailable']),
  history: z.enum(['available', 'unavailable']),
  accounting: z.enum(['unavailable', 'configured']),
  provider: z.strictObject({
    name: z.literal('OpenAI'),
    model: z.literal(OPENAI_MODEL).nullable(),
    status: z.enum(['configured-unprobed', 'configuration-unavailable']),
    liveVerified: z.literal(false),
  }),
  generationVerified: z.literal(false),
  requiresConsent: z.literal(true),
  acceptsCredentials: z.literal(false),
  setupAction: z.literal('operator-server-environment-configuration'),
};
export function validOpenAiReadiness(value: z.infer<z.ZodObject<typeof openAiReadinessShape>>) {
  const configured = value.provider.status === 'configured-unprobed';
  if (configured !== (value.provider.model === OPENAI_MODEL)) return false;
  const expected: typeof value.blockers = [];
  if (!configured) expected.push('configuration-required');
  if (value.credential !== 'environment-valid') expected.push('environment-key-required');
  if (value.accounting !== 'configured') expected.push('accounting-configuration-required');
  if (value.quota !== 'available') expected.push('quota-store-unavailable');
  if (value.history !== 'available') expected.push('history-store-unavailable');
  return (
    JSON.stringify(expected) === JSON.stringify(value.blockers) &&
    value.localReady === !expected.length &&
    value.status === (expected.length ? 'setup-required' : 'locally-configured')
  );
}

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
