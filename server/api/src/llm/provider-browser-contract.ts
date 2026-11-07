import type { OpenAiPolicy } from './openai-policy.js';
import type { QuotaPolicy } from './quota-policy.js';
import { exact } from './response.js';
import type { ReportBinding } from './history-contract.js';

export const OPENAI_ESTIMATE_SOURCE = 'server-estimated-configured-rates-not-invoice';
export const OPENROUTER_RECEIPT_SOURCE = 'server-validated-provider-reported-not-invoice';
export const LEGACY_SCANNER_DATA = 'Sanitized scanner findings and coverage; no raw evidence or credentials.';
export const PUBLIC_SCANNER_DATA = 'Sanitized scanner findings, package names, installed and reported fixed versions, and coverage; no raw evidence or credentials.';
export const CHAT_SENT_DATA = 'Cleaned question, all user history/accepted decisions and selected findings with complete coverage.';
export const CHAT_LOCAL_RETENTION = 'Durable owner+scan history until separately authorized operator lifecycle; capacity can refuse; context cache only, not output cache.';

export type OpenAiDisclosure = {
  provider: 'OpenAI'; model: 'gpt-5.4-mini-2026-03-17'; retention: 'no-training';
  operatorApprovedRouting: true; providerComplianceNotProvenByDeclaration: true; zeroDataRetentionVerified: false;
  costBasis: typeof OPENAI_ESTIMATE_SOURCE;
  estimatedPrice: { unit: 'microUSD-per-million-tokens'; input: number; output: number };
  data: typeof LEGACY_SCANNER_DATA | typeof PUBLIC_SCANNER_DATA;
  lifetimeUserCostMicros?: number;
} & ({ monetaryLimit: 'uncapped'; requestBudgetMicros: null; userBudgetMicros: null; scanBudgetMicros: null } |
  { monetaryLimit: 'capped'; requestBudgetMicros: number; userBudgetMicros: number; scanBudgetMicros: number });
export type ChatDisclosureFields = { sentData: typeof CHAT_SENT_DATA; localRetention: typeof CHAT_LOCAL_RETENTION };
export type ChatReceipt = Readonly<{ input: number; output: number } & (
  { costMicros: 0; source: typeof OPENROUTER_RECEIPT_SOURCE } |
  { costMicros: number; source: typeof OPENAI_ESTIMATE_SOURCE })>;

export function openAiDisclosure(policy: OpenAiPolicy, quota: QuotaPolicy, publicReport: boolean): OpenAiDisclosure {
  const base: Omit<OpenAiDisclosure, 'monetaryLimit' | 'requestBudgetMicros' | 'userBudgetMicros' | 'scanBudgetMicros'> = { provider: 'OpenAI' as const, model: policy.model, retention: policy.retention,
    operatorApprovedRouting: true as const, providerComplianceNotProvenByDeclaration: true as const, zeroDataRetentionVerified: false as const,
    costBasis: OPENAI_ESTIMATE_SOURCE, estimatedPrice: { unit: 'microUSD-per-million-tokens' as const,
      input: policy.inputPriceMicrosPerMillion, output: policy.outputPriceMicrosPerMillion },
    data: publicReport ? PUBLIC_SCANNER_DATA : LEGACY_SCANNER_DATA,
    ...(quota.lifetimeUserCostMicros !== undefined ? { lifetimeUserCostMicros: quota.lifetimeUserCostMicros } : {}) };
  if (policy.monetaryLimit === 'uncapped' && quota.monetaryLimit === 'uncapped')
    return { ...base, monetaryLimit: 'uncapped', requestBudgetMicros: null, userBudgetMicros: null, scanBudgetMicros: null };
  if (policy.monetaryLimit !== 'uncapped' && quota.monetaryLimit !== 'uncapped')
    return { ...base, monetaryLimit: 'capped', requestBudgetMicros: policy.requestBudgetMicros,
      userBudgetMicros: quota.user.costMicros, scanBudgetMicros: quota.scan.costMicros };
  throw new Error('Incompatible accounting configuration');
}

export function validChatReceipt(value: unknown, outputTokens = 4096): value is ChatReceipt {
  if (!exact(value, ['input', 'output', 'costMicros', 'source'])) return false;
  const count = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
  if (!count(value.input) || !count(value.output) || !count(value.costMicros) || value.output > outputTokens) return false;
  return value.source === OPENROUTER_RECEIPT_SOURCE ? value.costMicros === 0 :
    value.source === OPENAI_ESTIMATE_SOURCE && value.input > 0 && value.costMicros > 0;
}

export type TranslationReadinessBlocker = 'configuration-required' | 'public-key-required' | 'public-key-unsafe' |
  'quota-store-unavailable' | 'provider-profile-unavailable' | 'quota-policy-incompatible';
export type TranslationReadiness = ReportBinding & {
  operation: 'translation'; status: 'setup-required' | 'locally-configured'; localReady: boolean;
  blockers: TranslationReadinessBlocker[];
  credential: 'unconfigured' | 'missing' | 'unsafe' | 'metadata-valid';
  quota: 'available' | 'unavailable';
  // Legacy informational field only; translation does not probe or depend on history.
  history: 'available' | 'unavailable';
  provider: { name: 'OpenRouter'; checkedOn: string; liveVerified: false;
    status: 'catalog-listed-unprobed' | 'no-catalog-endpoints' | 'unverified-profile';
    model?: string; endpoint?: string; zdrListed: false; retention?: 'no-training' };
  generationVerified: false; requiresConsent: true; acceptsCredentials: false;
  setupAction: 'operator-public-file-configuration';
};

export type OpenAiReadinessBlocker = 'configuration-required' | 'environment-key-required' | 'accounting-configuration-required' |
  'quota-store-unavailable' | 'history-store-unavailable';
export type OpenAiReadiness = {
  status: 'setup-required' | 'locally-configured'; localReady: boolean; blockers: OpenAiReadinessBlocker[];
  credential: 'unavailable' | 'environment-valid'; quota: 'available' | 'unavailable'; history: 'available' | 'unavailable';
  accounting: 'unavailable' | 'configured';
  provider: { name: 'OpenAI'; model: 'gpt-5.4-mini-2026-03-17' | null;
    status: 'configured-unprobed' | 'configuration-unavailable'; liveVerified: false };
  generationVerified: false; requiresConsent: true; acceptsCredentials: false; setupAction: 'operator-server-environment-configuration';
};
