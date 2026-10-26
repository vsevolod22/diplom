import { createHash } from 'node:crypto';

export const CEILINGS = Object.freeze({ timeoutMs: 30_000, requestBytes: 262_144, responseBytes: 65_536,
  findings: 1000, outputTokens: 2048, budgetUsd: 1, pricePerMillion: 1000 });
// Fixed profile from the parent-reported 2026-10-08 synthetic compatibility probe.
export const FREE_MODEL = 'apodex/apodex-1.1-mini:free';
export const FREE_PROVIDER = 'novita/bf16';
// Explicit operator selection, never an automatic fallback. Official model/endpoints
// and endpoints/zdr catalog intersection checked 2026-10-21; generation unprobed.
export const PUBLIC_FREE_MODEL = 'xingchen-agi/xing4.0-29b-a4b:free';
export const PUBLIC_FREE_PROVIDER = 'phala';
export function supportedFreeProfile(model: string, providers: readonly string[]): boolean {
  return providers.length === 1 && (model === FREE_MODEL && providers[0] === FREE_PROVIDER ||
    model === PUBLIC_FREE_MODEL && providers[0] === PUBLIC_FREE_PROVIDER);
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
    if (!model || (freeOnly ? !supportedFreeProfile(model, providers ?? []) || env.LLM_RETENTION !== 'no-storage' :
        !/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(model) || ['openrouter/auto', 'openrouter/free'].includes(model)) || model.length > 160 ||
        !providers?.length || providers.length > 8 || new Set(providers).size !== providers.length ||
        !freeOnly && providers.some(p => !/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$/.test(p)) ||
        !revision || !/^[A-Za-z0-9._-]{1,80}$/.test(revision) || env.LLM_ROUTING_APPROVED !== 'true' ||
        env.LLM_REGION !== 'global' || !['no-training', 'no-storage'].includes(env.LLM_RETENTION ?? '')) return null;
    // The fixed API has no enforceable regional routing selector; EU/US fail closed.
    const settings = {
      model, providers: Object.freeze(providers), region: 'global' as const,
      retention: env.LLM_RETENTION as LlmPolicy['retention'],
      timeoutMs: positive(env.LLM_TIMEOUT_MS, CEILINGS.timeoutMs, true),
      requestBytes: positive(env.LLM_REQUEST_BYTES, CEILINGS.requestBytes, true),
      responseBytes: positive(env.LLM_RESPONSE_BYTES, CEILINGS.responseBytes, true),
      findings: positive(env.LLM_MAX_FINDINGS, CEILINGS.findings, true),
      outputTokens: positive(env.LLM_OUTPUT_TOKENS, CEILINGS.outputTokens, true),
      freeOnly, requestPriceUsd: freeOnly ? price('LLM_REQUEST_PRICE_USD', 0) : null,
      budgetUsd: price('LLM_REQUEST_BUDGET_USD', CEILINGS.budgetUsd),
      inputPricePerMillion: price('LLM_INPUT_PRICE_PER_MILLION_USD', CEILINGS.pricePerMillion),
      outputPricePerMillion: price('LLM_OUTPUT_PRICE_PER_MILLION_USD', CEILINGS.pricePerMillion),
    };
    const version = createHash('sha256').update(JSON.stringify({ revision, responseLanguageRevision: 'russian-prose-v3-grounded', ...settings })).digest('hex');
    return Object.freeze({ version, ...settings });
  } catch { return null; }
}

export function disclosure(policy: LlmPolicy) {
  return { provider: 'OpenRouter', model: policy.model, providers: [...policy.providers], region: policy.region,
    retention: policy.retention, operatorApprovedRouting: true, providerComplianceNotProvenByDeclaration: true,
    requestBudgetUsd: policy.budgetUsd, freeOnly: policy.freeOnly,
    maxPrice: { prompt: policy.inputPricePerMillion, completion: policy.outputPricePerMillion, request: policy.requestPriceUsd },
    data: 'Sanitized scanner findings and coverage; no raw evidence or credentials.' };
}
