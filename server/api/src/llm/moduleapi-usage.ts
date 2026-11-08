import { checkedModuleApiPolicy, moduleApiConfigurationError, type ModuleApiPolicy } from './moduleapi-policy.js';
import { object } from './response.js';

export type ModuleApiReserve = Readonly<{ input: number; output: number; costMicros: number }>;
export type ModuleApiUsage = Readonly<{
  normal: boolean; input?: number; output?: number; costMicros?: number;
  source: 'moduleapi-server-estimated-configured-rates-not-invoice';
}>;
const TOKEN_CEILING = 1_048_576;
const token = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= TOKEN_CEILING;
const source = 'moduleapi-server-estimated-configured-rates-not-invoice' as const;
const observations = new WeakMap<ModuleApiUsage, { policyVersion: string; reserve: ModuleApiReserve }>();

// Production accounting accepts only normalized observations, never a structural
// cast from client/provider JSON. Re-normalization after restart is supported.
export function checkedModuleApiUsage(usage: ModuleApiUsage, reserve: ModuleApiReserve, policy: ModuleApiPolicy): void {
  checkedModuleApiPolicy(policy);
  const origin = observations.get(usage);
  if (!origin || origin.policyVersion !== policy.version || origin.reserve.input !== reserve.input ||
      origin.reserve.output !== reserve.output || origin.reserve.costMicros !== reserve.costMicros) throw moduleApiConfigurationError();
}

// Prices are integer microUSD per million tokens. Round the total up, never down.
// Cached tokens receive no discount; completion_tokens already includes reasoning.
export function estimateModuleApiCost(input: number, output: number, policy: ModuleApiPolicy): number {
  checkedModuleApiPolicy(policy);
  if (!token(input) || !token(output)) throw moduleApiConfigurationError();
  const numerator = BigInt(input) * BigInt(policy.inputPriceMicrosPerMillion) +
    BigInt(output) * BigInt(policy.outputPriceMicrosPerMillion);
  const cost = (numerator + 999_999n) / 1_000_000n;
  if (cost > BigInt(Number.MAX_SAFE_INTEGER)) throw moduleApiConfigurationError();
  return Number(cost);
}

export function moduleApiReserve(input: number, policy: ModuleApiPolicy): ModuleApiReserve {
  checkedModuleApiPolicy(policy);
  if (!token(input) || input < 1 || input > policy.inputTokens) throw moduleApiConfigurationError();
  const costMicros = estimateModuleApiCost(input, policy.outputTokens, policy);
  if (policy.monetaryLimit !== 'uncapped' && costMicros > policy.requestBudgetMicros) throw moduleApiConfigurationError();
  return Object.freeze({ input, output: policy.outputTokens, costMicros });
}

function validDetails(value: unknown, total: number, keys: readonly string[], zeroKeys: readonly string[]): boolean {
  if (value === undefined || value === null) return true;
  return object(value) && Object.keys(value).every(key => keys.includes(key) && token(value[key]) &&
    (value[key] as number) <= total && (!zeroKeys.includes(key) || value[key] === 0));
}

// This is an estimate from provider-reported token counts, NOT a provider cost
// receipt or invoice. Unknown/invalid usage never becomes zero-cost success.
export function observeModuleApiUsage(usage: unknown, reserve: ModuleApiReserve, policy: ModuleApiPolicy): ModuleApiUsage {
  checkedModuleApiPolicy(policy);
  const observed = (value: ModuleApiUsage): ModuleApiUsage => {
    const result = Object.freeze(value);
    observations.set(result, { policyVersion: policy.version, reserve: Object.freeze({ ...reserve }) });
    return result;
  };
  if (!object(usage)) return observed({ normal: false, source });
  const input = token(usage.prompt_tokens) ? usage.prompt_tokens : undefined;
  const output = token(usage.completion_tokens) ? usage.completion_tokens : undefined;
  // Both dimensions are bounded safe integers; their sum is safe and may reach
  // 2 * TOKEN_CEILING. A per-dimension cap on total would discard known overages.
  const consistent = input !== undefined && output !== undefined && usage.total_tokens === input + output;
  // Every prepared request is nonempty. Zero prompt tokens cannot establish
  // known usage/cost; preserve unknown liability rather than settling at zero.
  if (!consistent || input === 0) return observed({ normal: false, source });
  const costMicros = estimateModuleApiCost(input, output, policy);
  const shape = Object.keys(usage).every(key => ['prompt_tokens', 'completion_tokens', 'total_tokens',
    'prompt_tokens_details', 'completion_tokens_details'].includes(key)) &&
    validDetails(usage.prompt_tokens_details, input, ['cached_tokens', 'audio_tokens'], ['audio_tokens']) &&
    validDetails(usage.completion_tokens_details, output,
      ['reasoning_tokens', 'audio_tokens', 'accepted_prediction_tokens', 'rejected_prediction_tokens'],
      ['audio_tokens', 'accepted_prediction_tokens', 'rejected_prediction_tokens']);
  return observed({ normal: shape && input <= reserve.input && output <= reserve.output &&
    costMicros <= reserve.costMicros && (policy.monetaryLimit === 'uncapped' || costMicros <= policy.requestBudgetMicros),
    input, output, costMicros, source });
}
