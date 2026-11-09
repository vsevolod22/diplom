import { createHash } from 'node:crypto';
import { ServiceUnavailableException } from '@nestjs/common';
import { exact } from './response.js';
import { moduleApiResponseFormat } from './moduleapi-chat-format.js';
export { MODULEAPI_PROMPTS } from './moduleapi-prompts.js';
import { CHAT_SOURCE_BUDGET } from './chat-source-budget.js';

// Explicit alias contract only: these returned identifiers do not prove model equivalence.
// Routing approval is neither live qualification nor a privacy/tariff guarantee.
export const MODULEAPI_MODEL = 'gpt-5.4-mini';
export const MODULEAPI_RETURNED_MODELS = Object.freeze([MODULEAPI_MODEL, 'gpt-5.4-mini-2026-03-17'] as const);
export const MODULEAPI_ENDPOINT = 'https://moduleapi.pro/v1/chat/completions';
export type ModuleApiPrompts = Readonly<{ summary: string; chat: string }>;
export type ModuleApiSettings = Readonly<{
  enabled: true; model: typeof MODULEAPI_MODEL; revision: string;
  routingApproved: true; retention: 'unknown';
  inputPriceMicrosPerMillion: number; outputPriceMicrosPerMillion: number;
  timeoutMs: number; requestBytes: number; responseBytes: number;
  inputTokens: number; outputTokens: number; findings: number;
} & (
  { monetaryLimit: 'capped'; requestBudgetMicros: number } |
  { monetaryLimit: 'uncapped'; requestBudgetMicros: null }
)>;
export type CappedModuleApiPolicy = ModuleApiPolicy & { monetaryLimit: 'capped'; requestBudgetMicros: number };
export type ModuleApiPolicy = ModuleApiSettings & Readonly<{ provider: 'ModuleAPI'; version: string }>;
const policies = new WeakMap<ModuleApiPolicy, ModuleApiPrompts>();
export const moduleApiConfigurationError = () => new ServiceUnavailableException({ errorCode: 'LLM_CONFIGURATION_UNAVAILABLE' });
const positive = (value: unknown, max: number) => typeof value === 'number' && Number.isSafeInteger(value) && value > 0 && value <= max;
const hash = (value: string) => createHash('sha256').update(value).digest('hex');

// Trusted composition only, never bind these arguments to an HTTP request. No env,
// model, price, prompt or credential defaults. Unknown retention must be disclosed.
export function createModuleApiPolicy<T extends { requestBudgetMicros: number; monetaryLimit: 'capped' }>(config: T, prompts: ModuleApiPrompts): CappedModuleApiPolicy | null;
export function createModuleApiPolicy(config: unknown, prompts: ModuleApiPrompts): ModuleApiPolicy | null;
export function createModuleApiPolicy(config: unknown, prompts: ModuleApiPrompts): ModuleApiPolicy | null {
  try {
    const keys = ['enabled', 'model', 'revision', 'routingApproved', 'retention',
      'inputPriceMicrosPerMillion', 'outputPriceMicrosPerMillion', 'requestBudgetMicros', 'monetaryLimit',
      'timeoutMs', 'requestBytes', 'responseBytes', 'inputTokens', 'outputTokens', 'findings'];
    if (!exact(config, keys) ||
        config.monetaryLimit !== 'capped' && config.monetaryLimit !== 'uncapped' ||
        config.enabled !== true || config.model !== MODULEAPI_MODEL || config.routingApproved !== true || config.retention !== 'unknown' ||
        typeof config.revision !== 'string' || config.revision === 'undecided' || !/^[A-Za-z0-9._-]{1,80}$/.test(config.revision) ||
        !positive(config.inputPriceMicrosPerMillion, 1_000_000_000) || !positive(config.outputPriceMicrosPerMillion, 1_000_000_000) ||
        (config.monetaryLimit === 'uncapped' ? config.requestBudgetMicros !== null : !positive(config.requestBudgetMicros, 1_000_000)) ||
        !positive(config.timeoutMs, 90_000) ||
        !positive(config.requestBytes, 262_144) || !positive(config.responseBytes, 65_536) ||
        !positive(config.inputTokens, 65_536) || !positive(config.outputTokens, 4096) || !positive(config.findings, 1000) ||
        !exact(prompts, ['summary', 'chat']) || [prompts.summary, prompts.chat].some(text =>
          typeof text !== 'string' || !text.trim() || Buffer.byteLength(text) > 16_384 ||
          // Prompts are server-authored text, not a runtime prompt/template channel.
          // eslint-disable-next-line no-control-regex -- Reject NUL in server-authored prompts intentionally.
          /[\u0000\u202a-\u202e\u2066-\u2069\ud800-\udfff]/u.test(text))) return null;
    // Explicit null is legal ONLY with uncapped; no absent mode, missing budget
    // or zero grants permission. ModuleAPI has no inherited legacy defaults.
    const money = config.monetaryLimit === 'uncapped'
      ? { monetaryLimit: 'uncapped' as const, requestBudgetMicros: null }
      : { monetaryLimit: 'capped' as const, requestBudgetMicros: config.requestBudgetMicros as number };
    const settings: ModuleApiSettings = {
      enabled: true, model: MODULEAPI_MODEL, revision: config.revision, routingApproved: true, retention: 'unknown',
      inputPriceMicrosPerMillion: config.inputPriceMicrosPerMillion as number,
      outputPriceMicrosPerMillion: config.outputPriceMicrosPerMillion as number, ...money,
      timeoutMs: config.timeoutMs as number, requestBytes: config.requestBytes as number, responseBytes: config.responseBytes as number,
      inputTokens: config.inputTokens as number, outputTokens: config.outputTokens as number, findings: config.findings as number,
    };
    const frozenPrompts = Object.freeze({ summary: prompts.summary, chat: prompts.chat });
    const version = hash(JSON.stringify({ contract: 'moduleapi-offline-core-v2', accounting: 'configured-rates-ceil-micros-v1',
      provider: 'ModuleAPI', endpoint: MODULEAPI_ENDPOINT, returnedModels: MODULEAPI_RETURNED_MODELS,
      privacy: 'retention-and-training-unknown', tariff: 'effective-tariff-not-verified', ...settings, chatSources: CHAT_SOURCE_BUDGET,
            historyWire: 'exact-source-catalog-v1',
      prompts: { summary: hash(frozenPrompts.summary), chat: hash(frozenPrompts.chat) },
      responseFormats: { summary: moduleApiResponseFormat('summary'), chat: moduleApiResponseFormat('chat') } }));
    const policy = Object.freeze({ ...settings, provider: 'ModuleAPI' as const, version });
    policies.set(policy, frozenPrompts);
    return policy;
  } catch { return null; }
}

export function checkedModuleApiPolicy(policy: ModuleApiPolicy): ModuleApiPrompts {
  const prompts = policies.get(policy);
  if (!prompts) throw moduleApiConfigurationError();
  return prompts;
}
