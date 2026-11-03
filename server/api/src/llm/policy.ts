import { createHash } from 'node:crypto';
import { CHAT_SOURCE_BUDGET } from './chat-source-budget.js';

export const CEILINGS = Object.freeze({ timeoutMs: 30_000, requestBytes: 262_144, responseBytes: 65_536,
  findings: 1000, outputTokens: 2048, budgetUsd: 1, pricePerMillion: 1000 });
// Fixed profile from the parent-reported 2026-10-08 synthetic compatibility probe.
export const FREE_MODEL = 'apodex/apodex-1.1-mini:free';
export const FREE_PROVIDER = 'novita/bf16';
// Explicit operator-authorized free-only switch, never an automatic fallback.
// Dots3/Atlas permits retention, not training; this is not ZDR/no-storage.
// Catalog metadata and a synthetic transport receipt are not product qualification.
export const PUBLIC_FREE_MODEL = 'dots-studio/dots-3-note-preview:free';
export const PUBLIC_FREE_PROVIDER = 'atlas-cloud/fp8';
export const PUBLIC_FREE_TIMEOUT_MS = 90_000;
export const PUBLIC_FREE_OUTPUT_TOKENS = 4096;
// Internal policy identity, never a request-supplied timeout/profile selector.
export function publicFreePolicy(policy: LlmPolicy | null | undefined): boolean {
  return !!policy && policy.freeOnly && policy.model === PUBLIC_FREE_MODEL && policy.providers.length === 1 &&
    policy.providers[0] === PUBLIC_FREE_PROVIDER && policy.region === 'global' && policy.retention === 'no-training' &&
    policy.budgetUsd === 0 && policy.inputPricePerMillion === 0 && policy.outputPricePerMillion === 0 && policy.requestPriceUsd === 0;
}
export function supportedFreeProfile(model: string, providers: readonly string[], retention: string | undefined): boolean {
  return providers.length === 1 && (model === FREE_MODEL && providers[0] === FREE_PROVIDER && retention === 'no-storage' ||
    model === PUBLIC_FREE_MODEL && providers[0] === PUBLIC_FREE_PROVIDER && retention === 'no-training');
}
export type LlmPolicy = Readonly<{
  version: string; model: string; providers: readonly string[]; region: 'global'; retention: 'no-training' | 'no-storage';
  timeoutMs: number; requestBytes: number; responseBytes: number; findings: number; outputTokens: number;
  budgetUsd: number; inputPricePerMillion: number; outputPricePerMillion: number;
  freeOnly: boolean; requestPriceUsd: number | null;
}>;
const positive = (value: string | undefined, max: number, integer = false): number => {
  if (!value || !/^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value)) throw new Error();
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0 || n > max || integer && !Number.isSafeInteger(n)) throw new Error();
  return n;
};

// Read named non-secret settings only. Never serialize process.env or load an env file.
export function policyFromEnvironment(env: NodeJS.ProcessEnv = process.env): LlmPolicy | null {
  if (env.LLM_ENABLED !== 'true') return null;
  try {
    const freeOnly = env.LLM_FREE_ONLY === 'true';
    if (env.LLM_FREE_ONLY !== undefined && !['true', 'false'].includes(env.LLM_FREE_ONLY)) return null;
    const price = (name: string, max: number) => {
      if (!freeOnly) return positive(env[name], max);
      if (env[name] !== '0') throw new Error();
      return 0;
    };
    const model = env.LLM_MODEL;
    const providers = env.LLM_PROVIDER_ALLOWLIST?.split(',');
    const revision = env.LLM_POLICY_REVISION;
    if (!model || (freeOnly ? !supportedFreeProfile(model, providers ?? [], env.LLM_RETENTION) :
        !/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(model) || ['openrouter/auto', 'openrouter/free'].includes(model)) || model.length > 160 ||
        !providers?.length || providers.length > 8 || new Set(providers).size !== providers.length ||
        !freeOnly && providers.some(p => !/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$/.test(p)) ||
        !revision || !/^[A-Za-z0-9._-]{1,80}$/.test(revision) || env.LLM_ROUTING_APPROVED !== 'true' ||
        env.LLM_REGION !== 'global' || !['no-training', 'no-storage'].includes(env.LLM_RETENTION ?? '')) return null;
    // The fixed API has no enforceable regional routing selector; EU/US fail closed.
    const publicProfile = freeOnly && model === PUBLIC_FREE_MODEL && providers.length === 1 && providers[0] === PUBLIC_FREE_PROVIDER;
    const settings = {
      model, providers: Object.freeze(providers), region: 'global' as const,
      retention: env.LLM_RETENTION as LlmPolicy['retention'],
      timeoutMs: positive(env.LLM_TIMEOUT_MS, publicProfile ? PUBLIC_FREE_TIMEOUT_MS : CEILINGS.timeoutMs, true),
      requestBytes: positive(env.LLM_REQUEST_BYTES, CEILINGS.requestBytes, true),
      responseBytes: positive(env.LLM_RESPONSE_BYTES, CEILINGS.responseBytes, true),
      findings: positive(env.LLM_MAX_FINDINGS, CEILINGS.findings, true),
      outputTokens: positive(env.LLM_OUTPUT_TOKENS, publicProfile ? PUBLIC_FREE_OUTPUT_TOKENS : CEILINGS.outputTokens, true),
      freeOnly, requestPriceUsd: freeOnly ? price('LLM_REQUEST_PRICE_USD', 0) : null,
      budgetUsd: price('LLM_REQUEST_BUDGET_USD', CEILINGS.budgetUsd),
      inputPricePerMillion: price('LLM_INPUT_PRICE_PER_MILLION_USD', CEILINGS.pricePerMillion),
      outputPricePerMillion: price('LLM_OUTPUT_PRICE_PER_MILLION_USD', CEILINGS.pricePerMillion),
    };
    const version = createHash('sha256').update(JSON.stringify({ revision, chatSources: CHAT_SOURCE_BUDGET, responseLanguageRevision: freeOnly && model === PUBLIC_FREE_MODEL ? 'russian-remediation-v10-bounded' : 'russian-prose-v6-cyrillic', ...settings })).digest('hex');
    return Object.freeze({ version, ...settings });
  } catch { return null; }
}

export function disclosure(policy: LlmPolicy) {
  return { provider: 'OpenRouter', model: policy.model, providers: [...policy.providers], region: policy.region,
    retention: policy.retention, operatorApprovedRouting: true, providerComplianceNotProvenByDeclaration: true,
    requestBudgetUsd: policy.budgetUsd, freeOnly: policy.freeOnly,
    maxPrice: { prompt: policy.inputPricePerMillion, completion: policy.outputPricePerMillion, request: policy.requestPriceUsd },
    data: publicFreePolicy(policy) ? 'Sanitized scanner findings, package names, installed and reported fixed versions, and coverage; no raw evidence or credentials.' :
          'Sanitized scanner findings and coverage; no raw evidence or credentials.' };
}
