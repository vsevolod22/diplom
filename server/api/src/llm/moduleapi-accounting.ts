import { createHash } from 'node:crypto';
import { checkedModuleApiPolicy, type ModuleApiPolicy } from './moduleapi-policy.js';
import { checkedModuleApiPrepared, type ModuleApiPrepared } from './moduleapi-prepared-request.js';
import { checkedModuleApiUsage, estimateModuleApiCost, moduleApiReserve, type ModuleApiUsage } from './moduleapi-usage.js';
import { checkedQuotaMonetaryPolicy, integer, MAX_OBSERVATION_COST_MICROS, quotaUnavailable, type MonetaryLimit, type QuotaPolicy, type Vector } from './quota-policy.js';
import { exact } from './response.js';
import type { QuotaBindings, QuotaLedger } from './quota-ledger.js';
import type { ModuleApiAccounting, ModuleApiAccountingBinding } from './moduleapi-provider.js';

export const MODULEAPI_ACCOUNTING_CONTRACT = 'moduleapi-quota-estimate-v1';
export const MODULEAPI_BILLING = 'estimate-only-effective-tariff-not-verified';
export const MODULEAPI_COST_BASIS = 'moduleapi-server-estimated-configured-rates-not-invoice';
export type ModuleApiAccountingPolicy = Readonly<{
  enabled: true; revision: string; providerPolicyVersion: string; quotaPolicyVersion: string; monetaryLimit: MonetaryLimit;
  billing: typeof MODULEAPI_BILLING; costBasis: typeof MODULEAPI_COST_BASIS; version: string;
}>;
const approvals = new WeakMap<ModuleApiAccountingPolicy, { provider: ModuleApiPolicy; quota: QuotaPolicy }>();
const hash = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const sameVector = (a: Vector, b: Vector) => a.input === b.input && a.output === b.output && a.costMicros === b.costMicros;

// A server composition approval, NOT an env default, user consent or permission to
// dispatch. No budget/rate is selected here. Effective tariff, fees and token
// conversion are unverified: this is a configured-rate estimate, never an invoice
// cap. Unsupported tools/audio/prediction cannot settle as ordinary text usage;
// cached input uses the full configured rate and reasoning is included in output.
export function createModuleApiAccountingPolicy(config: unknown, provider: ModuleApiPolicy, quota: QuotaPolicy): ModuleApiAccountingPolicy | null {
  try {
    checkedModuleApiPolicy(provider);
    checkedQuotaMonetaryPolicy(quota);
    const keys = ['enabled', 'revision', 'providerPolicyVersion', 'quotaPolicyVersion', 'billing', 'costBasis', 'monetaryLimit'];
    if (!exact(config, keys) ||
        config.monetaryLimit !== provider.monetaryLimit || config.monetaryLimit !== quota.monetaryLimit ||
        config.monetaryLimit !== 'capped' && config.monetaryLimit !== 'uncapped' ||
        config.enabled !== true || typeof config.revision !== 'string' || config.revision === 'undecided' ||
        !/^[A-Za-z0-9._-]{1,80}$/.test(config.revision) || config.providerPolicyVersion !== provider.version ||
        config.quotaPolicyVersion !== quota.version || config.billing !== MODULEAPI_BILLING ||
        config.costBasis !== MODULEAPI_COST_BASIS || !/^[a-f0-9]{64}$/.test(quota.version)) return null;
    const { version, ...quotaSettings } = quota;
    if (hash(quotaSettings) !== version) return null;
    for (const scope of [quota.user, quota.scan]) {
      if (integer(scope.input) === 0 || integer(scope.output) === 0 ||
          quota.monetaryLimit !== 'uncapped' && integer(scope.costMicros, 1_000_000) === 0) return null;
    }
    if (integer(quota.requestInput, 65_536) < provider.inputTokens ||
        integer(quota.observationTokens, 1_048_576) < Math.max(provider.inputTokens, provider.outputTokens) ||
        integer(quota.observationCostMicros, MAX_OBSERVATION_COST_MICROS) < (provider.monetaryLimit === 'uncapped'
          ? estimateModuleApiCost(provider.inputTokens, provider.outputTokens, provider) : provider.requestBudgetMicros) ||
        integer(quota.receiptMs, 300_000) <= provider.timeoutMs) return null;
    const settings: Omit<ModuleApiAccountingPolicy, 'version'> = { enabled: true, revision: config.revision, providerPolicyVersion: provider.version,
      quotaPolicyVersion: quota.version, billing: MODULEAPI_BILLING, costBasis: MODULEAPI_COST_BASIS,
      monetaryLimit: provider.monetaryLimit };
    const approval = Object.freeze({ ...settings, version: hash({ contract: MODULEAPI_ACCOUNTING_CONTRACT, ...settings }) });
    // Freeze our own copy: later caller mutations must never change an approval.
    const frozenQuota = quota.monetaryLimit === 'uncapped'
      ? Object.freeze({ ...quota, user: Object.freeze({ ...quota.user }), scan: Object.freeze({ ...quota.scan }) })
      : Object.freeze({ ...quota, user: Object.freeze({ ...quota.user }), scan: Object.freeze({ ...quota.scan }) });
    approvals.set(approval, Object.freeze({ provider, quota: frozenQuota }));
    return approval;
  } catch { return null; }
}

export type ModuleApiQuotaContext = Readonly<{
  binding: Readonly<QuotaBindings>; reserve: Vector;
  accounting: Readonly<{
    contract: typeof MODULEAPI_ACCOUNTING_CONTRACT; provider: 'ModuleAPI'; model: ModuleApiPolicy['model'];
    operation: ModuleApiPrepared['operation']; providerPolicyVersion: string; accountingPolicyVersion: string;
    quotaPolicyVersion: string; inputPriceMicrosPerMillion: number; outputPriceMicrosPerMillion: number;
    requestBudgetMicros: number | null; monetaryLimit: MonetaryLimit;
    billing: ModuleApiAccountingPolicy['billing']; costBasis: typeof MODULEAPI_COST_BASIS;
  }>;
}>;
const contexts = new WeakMap<ModuleApiQuotaContext, { provider: ModuleApiPolicy; quota: QuotaPolicy }>();

// Only authorized server owner/report bindings and a factory-prepared request may
// enter. The caller still owns authorization, consent and fresh report checks.
export function createModuleApiQuotaContext(binding: QuotaBindings, request: ModuleApiPrepared,
  provider: ModuleApiPolicy, approval: ModuleApiAccountingPolicy): ModuleApiQuotaContext {
  checkedModuleApiPrepared(request, provider);
  const accepted = approvals.get(approval);
  if (!accepted || accepted.provider !== provider || binding.policyVersion !== provider.version ||
      binding.requestHash !== request.hash || !binding.subject || binding.subject.length > 200 ||
      !binding.scanId || binding.scanId.length > 200 ||
      ![binding.reportVersion, binding.policyVersion, binding.requestHash].every(value => /^[a-f0-9]{64}$/.test(value))) throw quotaUnavailable();
  const reserve = moduleApiReserve(request.reserve.input, provider);
  if (!sameVector(reserve, request.reserve)) throw quotaUnavailable();
  const context: ModuleApiQuotaContext = Object.freeze({ binding: Object.freeze({ ...binding }), reserve,
    accounting: Object.freeze({ contract: MODULEAPI_ACCOUNTING_CONTRACT, provider: 'ModuleAPI', model: provider.model,
      operation: request.operation, providerPolicyVersion: provider.version, accountingPolicyVersion: approval.version,
      quotaPolicyVersion: accepted.quota.version, inputPriceMicrosPerMillion: provider.inputPriceMicrosPerMillion,
      outputPriceMicrosPerMillion: provider.outputPriceMicrosPerMillion, requestBudgetMicros: provider.requestBudgetMicros,
      billing: approval.billing, costBasis: MODULEAPI_COST_BASIS,
      monetaryLimit: approval.monetaryLimit }) });
  contexts.set(context, accepted);
  return context;
}

export function checkedModuleApiQuotaContext(context: ModuleApiQuotaContext) {
  const accepted = contexts.get(context);
  if (!accepted) throw quotaUnavailable();
  return accepted;
}
export function checkedModuleApiQuotaUsage(context: ModuleApiQuotaContext, usage: ModuleApiUsage): void {
  const { provider } = checkedModuleApiQuotaContext(context);
  checkedModuleApiUsage(usage, context.reserve, provider);
}

// Adapter bridge only: authority and transport callbacks belong to orchestration.
// Dispatch commits before the final synchronous check and send. Only a rejected
// pre-send check can compensate that fresh dispatch; an entered send is not a refund.
export function bindModuleApiAccounting(ledger: QuotaLedger, id: string, context: ModuleApiQuotaContext): Readonly<{
  accounting: ModuleApiAccounting; dispatch: (binding: ModuleApiAccountingBinding) => boolean;
  dispatchGuarded: (binding: ModuleApiAccountingBinding, beforeSend: () => void, send: () => void) => boolean;
  release: () => boolean;
}> {
  checkedModuleApiQuotaContext(context);
  const matches = (binding: ModuleApiAccountingBinding) => binding.operation === context.accounting.operation &&
    binding.policyVersion === context.binding.policyVersion && binding.requestHash === context.binding.requestHash &&
    sameVector(binding.reserve, context.reserve);
  const accounting: ModuleApiAccounting = Object.freeze({
    assertReserved: (binding: ModuleApiAccountingBinding) => matches(binding) && ledger.assertModuleApiReserved(id, context),
    observe: (binding: ModuleApiAccountingBinding, usage: ModuleApiUsage) => matches(binding) && ledger.observeModuleApi(id, context, usage),
  });
  return Object.freeze({ accounting, dispatch: (binding: ModuleApiAccountingBinding) => matches(binding) && ledger.dispatchModuleApi(id, context),
    dispatchGuarded: (binding: ModuleApiAccountingBinding, beforeSend: () => void, send: () => void) =>
      matches(binding) && ledger.dispatchModuleApiGuarded(id, context, beforeSend, send),
    release: () => ledger.releaseModuleApi(id, context) });
}
