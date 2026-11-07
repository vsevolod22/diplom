import { createHash } from 'node:crypto';
import { checkedOpenAiPolicy, type OpenAiPolicy } from './openai-policy.js';
import { checkedOpenAiPrepared, type OpenAiPrepared } from './openai-prepared-request.js';
import { checkedOpenAiUsage, estimateOpenAiCost, openAiReserve, type OpenAiUsage } from './openai-usage.js';
import { checkedQuotaMonetaryPolicy, integer, MAX_OBSERVATION_COST_MICROS, quotaUnavailable, type MonetaryLimit, type QuotaPolicy, type Vector } from './quota-policy.js';
import { exact } from './response.js';
import type { QuotaBindings, QuotaLedger } from './quota-ledger.js';
import type { OpenAiAccounting, OpenAiAccountingBinding } from './openai-provider.js';

export const OPENAI_ACCOUNTING_CONTRACT = 'openai-quota-estimate-v1';
export const OPENAI_COST_BASIS = 'server-estimated-configured-rates-not-invoice';
export type OpenAiAccountingPolicy = Readonly<{
  enabled: true; revision: string; providerPolicyVersion: string; quotaPolicyVersion: string; monetaryLimit?: MonetaryLimit;
  billing: 'text-tokens-only-no-additional-fees'; costBasis: typeof OPENAI_COST_BASIS; version: string;
}>;
const approvals = new WeakMap<OpenAiAccountingPolicy, { provider: OpenAiPolicy; quota: QuotaPolicy }>();
const hash = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const sameVector = (a: Vector, b: Vector) => a.input === b.input && a.output === b.output && a.costMicros === b.costMicros;

// A server composition approval, NOT an env default, user consent or permission to
// dispatch. No budget/rate is selected here. Fees/tools/audio/prediction are excluded;
// cached input is charged at the full rate and reasoning is included in output.
export function createOpenAiAccountingPolicy(config: unknown, provider: OpenAiPolicy, quota: QuotaPolicy): OpenAiAccountingPolicy | null {
  try {
    checkedOpenAiPolicy(provider);
    checkedQuotaMonetaryPolicy(quota);
    const explicitMode = provider.monetaryLimit !== undefined || quota.monetaryLimit !== undefined;
    const keys = ['enabled', 'revision', 'providerPolicyVersion', 'quotaPolicyVersion', 'billing', 'costBasis'];
    if (explicitMode) keys.push('monetaryLimit');
    if (!exact(config, keys) ||
        explicitMode && (config.monetaryLimit !== provider.monetaryLimit || config.monetaryLimit !== quota.monetaryLimit ||
          config.monetaryLimit !== 'capped' && config.monetaryLimit !== 'uncapped') ||
        config.enabled !== true || typeof config.revision !== 'string' || config.revision === 'undecided' ||
        !/^[A-Za-z0-9._-]{1,80}$/.test(config.revision) || config.providerPolicyVersion !== provider.version ||
        config.quotaPolicyVersion !== quota.version || config.billing !== 'text-tokens-only-no-additional-fees' ||
        config.costBasis !== OPENAI_COST_BASIS || !/^[a-f0-9]{64}$/.test(quota.version)) return null;
    const { version, ...quotaSettings } = quota;
    if (hash(quotaSettings) !== version) return null;
    for (const scope of [quota.user, quota.scan]) {
      if (integer(scope.input) === 0 || integer(scope.output) === 0 ||
          quota.monetaryLimit !== 'uncapped' && integer(scope.costMicros, 1_000_000) === 0) return null;
    }
    if (integer(quota.requestInput, 65_536) < provider.inputTokens ||
        integer(quota.observationTokens, 1_048_576) < Math.max(provider.inputTokens, provider.outputTokens) ||
        integer(quota.observationCostMicros, MAX_OBSERVATION_COST_MICROS) < (provider.monetaryLimit === 'uncapped'
          ? estimateOpenAiCost(provider.inputTokens, provider.outputTokens, provider) : provider.requestBudgetMicros) ||
        integer(quota.receiptMs, 300_000) <= provider.timeoutMs) return null;
    const settings: Omit<OpenAiAccountingPolicy, 'version'> = { enabled: true, revision: config.revision, providerPolicyVersion: provider.version,
      quotaPolicyVersion: quota.version, billing: 'text-tokens-only-no-additional-fees' as const, costBasis: OPENAI_COST_BASIS,
      ...(explicitMode ? { monetaryLimit: provider.monetaryLimit } : {}) };
    const approval = Object.freeze({ ...settings, version: hash({ contract: OPENAI_ACCOUNTING_CONTRACT, ...settings }) });
    // Freeze our own copy: later caller mutations must never change an approval.
    const frozenQuota = quota.monetaryLimit === 'uncapped'
      ? Object.freeze({ ...quota, user: Object.freeze({ ...quota.user }), scan: Object.freeze({ ...quota.scan }) })
      : Object.freeze({ ...quota, user: Object.freeze({ ...quota.user }), scan: Object.freeze({ ...quota.scan }) });
    approvals.set(approval, Object.freeze({ provider, quota: frozenQuota }));
    return approval;
  } catch { return null; }
}

export type OpenAiQuotaContext = Readonly<{
  binding: Readonly<QuotaBindings>; reserve: Vector;
  accounting: Readonly<{
    contract: typeof OPENAI_ACCOUNTING_CONTRACT; provider: 'OpenAI'; model: OpenAiPolicy['model'];
    operation: OpenAiPrepared['operation']; providerPolicyVersion: string; accountingPolicyVersion: string;
    quotaPolicyVersion: string; inputPriceMicrosPerMillion: number; outputPriceMicrosPerMillion: number;
    requestBudgetMicros: number | null; monetaryLimit?: MonetaryLimit;
    billing: OpenAiAccountingPolicy['billing']; costBasis: typeof OPENAI_COST_BASIS;
  }>;
}>;
const contexts = new WeakMap<OpenAiQuotaContext, { provider: OpenAiPolicy; quota: QuotaPolicy }>();

// Only authorized server owner/report bindings and a factory-prepared request may
// enter. The caller still owns authorization, consent and fresh report checks.
export function createOpenAiQuotaContext(binding: QuotaBindings, request: OpenAiPrepared,
  provider: OpenAiPolicy, approval: OpenAiAccountingPolicy): OpenAiQuotaContext {
  checkedOpenAiPrepared(request, provider);
  const accepted = approvals.get(approval);
  if (!accepted || accepted.provider !== provider || binding.policyVersion !== provider.version ||
      binding.requestHash !== request.hash || !binding.subject || binding.subject.length > 200 ||
      !binding.scanId || binding.scanId.length > 200 ||
      ![binding.reportVersion, binding.policyVersion, binding.requestHash].every(value => /^[a-f0-9]{64}$/.test(value))) throw quotaUnavailable();
  const reserve = openAiReserve(request.reserve.input, provider);
  if (!sameVector(reserve, request.reserve)) throw quotaUnavailable();
  const context: OpenAiQuotaContext = Object.freeze({ binding: Object.freeze({ ...binding }), reserve,
    accounting: Object.freeze({ contract: OPENAI_ACCOUNTING_CONTRACT, provider: 'OpenAI', model: provider.model,
      operation: request.operation, providerPolicyVersion: provider.version, accountingPolicyVersion: approval.version,
      quotaPolicyVersion: accepted.quota.version, inputPriceMicrosPerMillion: provider.inputPriceMicrosPerMillion,
      outputPriceMicrosPerMillion: provider.outputPriceMicrosPerMillion, requestBudgetMicros: provider.requestBudgetMicros,
      billing: approval.billing, costBasis: OPENAI_COST_BASIS,
      ...(approval.monetaryLimit !== undefined ? { monetaryLimit: approval.monetaryLimit } : {}) }) });
  contexts.set(context, accepted);
  return context;
}

export function checkedOpenAiQuotaContext(context: OpenAiQuotaContext) {
  const accepted = contexts.get(context);
  if (!accepted) throw quotaUnavailable();
  return accepted;
}
export function checkedOpenAiQuotaUsage(context: OpenAiQuotaContext, usage: OpenAiUsage): void {
  const { provider } = checkedOpenAiQuotaContext(context);
  checkedOpenAiUsage(usage, context.reserve, provider);
}

// Adapter bridge only: authority and transport callbacks belong to orchestration.
// Dispatch commits before the final synchronous check and send. Only a rejected
// pre-send check can compensate that fresh dispatch; an entered send is not a refund.
export function bindOpenAiAccounting(ledger: QuotaLedger, id: string, context: OpenAiQuotaContext): Readonly<{
  accounting: OpenAiAccounting; dispatch: (binding: OpenAiAccountingBinding) => boolean;
  dispatchGuarded: (binding: OpenAiAccountingBinding, beforeSend: () => void, send: () => void) => boolean;
  release: () => boolean;
}> {
  checkedOpenAiQuotaContext(context);
  const matches = (binding: OpenAiAccountingBinding) => binding.operation === context.accounting.operation &&
    binding.policyVersion === context.binding.policyVersion && binding.requestHash === context.binding.requestHash &&
    sameVector(binding.reserve, context.reserve);
  const accounting: OpenAiAccounting = Object.freeze({
    assertReserved: (binding: OpenAiAccountingBinding) => matches(binding) && ledger.assertOpenAiReserved(id, context),
    observe: (binding: OpenAiAccountingBinding, usage: OpenAiUsage) => matches(binding) && ledger.observeOpenAi(id, context, usage),
  });
  return Object.freeze({ accounting, dispatch: (binding: OpenAiAccountingBinding) => matches(binding) && ledger.dispatchOpenAi(id, context),
    dispatchGuarded: (binding: OpenAiAccountingBinding, beforeSend: () => void, send: () => void) =>
      matches(binding) && ledger.dispatchOpenAiGuarded(id, context, beforeSend, send),
    release: () => ledger.releaseOpenAi(id, context) });
}
