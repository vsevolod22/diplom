import { createHash } from 'node:crypto';
import { ServiceUnavailableException } from '@nestjs/common';
import { exact } from './response.js';
import { openAiResponseFormat } from './openai-response-contract.js';
import { CHAT_SOURCE_BUDGET } from './chat-source-budget.js';

// Candidate snapshot from the coordinator-supplied model docs; not activation approval.
export const OPENAI_MODEL = 'gpt-5.4-mini-2026-03-17';
export const OPENAI_ENDPOINT = 'https://api.openai.com/v1/chat/completions';
export type OpenAiPrompts = Readonly<{ summary: string; chat: string }>;
export type OpenAiSettings = Readonly<{
  enabled: true; model: typeof OPENAI_MODEL; revision: string;
  routingApproved: true; retention: 'no-training';
  inputPriceMicrosPerMillion: number; outputPriceMicrosPerMillion: number;
  timeoutMs: number; requestBytes: number; responseBytes: number;
  inputTokens: number; outputTokens: number; findings: number;
} & (
  { monetaryLimit?: 'capped'; requestBudgetMicros: number } |
  { monetaryLimit: 'uncapped'; requestBudgetMicros: null }
)>;
export type CappedOpenAiPolicy = OpenAiPolicy & { monetaryLimit?: 'capped'; requestBudgetMicros: number };
export type OpenAiPolicy = OpenAiSettings & Readonly<{ provider: 'OpenAI'; version: string }>;
const policies = new WeakMap<OpenAiPolicy, OpenAiPrompts>();
export const openAiConfigurationError = () => new ServiceUnavailableException({ errorCode: 'LLM_CONFIGURATION_UNAVAILABLE' });
const positive = (value: unknown, max: number) => typeof value === 'number' && Number.isSafeInteger(value) && value > 0 && value <= max;
const hash = (value: string) => createHash('sha256').update(value).digest('hex');

// Trusted composition only, never bind these arguments to an HTTP request. No env,
// model, price, prompt or credential defaults. Retention approval is not ZDR proof.
export function createOpenAiPolicy<T extends { requestBudgetMicros: number; monetaryLimit?: 'capped' }>(config: T, prompts: OpenAiPrompts): CappedOpenAiPolicy | null;
export function createOpenAiPolicy(config: unknown, prompts: OpenAiPrompts): OpenAiPolicy | null;
export function createOpenAiPolicy(config: unknown, prompts: OpenAiPrompts): OpenAiPolicy | null {
  try {
    const keys = ['enabled', 'model', 'revision', 'routingApproved', 'retention',
      'inputPriceMicrosPerMillion', 'outputPriceMicrosPerMillion', 'requestBudgetMicros',
      'timeoutMs', 'requestBytes', 'responseBytes', 'inputTokens', 'outputTokens', 'findings'];
    if (config && typeof config === 'object' && Object.hasOwn(config, 'monetaryLimit')) keys.push('monetaryLimit');
    if (!exact(config, keys) ||
        config.monetaryLimit !== undefined && config.monetaryLimit !== 'capped' && config.monetaryLimit !== 'uncapped' ||
        Object.hasOwn(config, 'monetaryLimit') && config.monetaryLimit === undefined ||
        config.enabled !== true || config.model !== OPENAI_MODEL || config.routingApproved !== true || config.retention !== 'no-training' ||
        typeof config.revision !== 'string' || !/^[A-Za-z0-9._-]{1,80}$/.test(config.revision) ||
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
    // Explicit null is legal ONLY with uncapped; neither a missing budget nor 0
    // grants permission. Preserve legacy capped serialization/version verbatim.
    const money = config.monetaryLimit === 'uncapped'
      ? { monetaryLimit: 'uncapped' as const, requestBudgetMicros: null }
      : { ...(config.monetaryLimit === 'capped' ? { monetaryLimit: 'capped' as const } : {}), requestBudgetMicros: config.requestBudgetMicros as number };
    const settings: OpenAiSettings = {
      enabled: true, model: OPENAI_MODEL, revision: config.revision, routingApproved: true, retention: 'no-training',
      inputPriceMicrosPerMillion: config.inputPriceMicrosPerMillion as number,
      outputPriceMicrosPerMillion: config.outputPriceMicrosPerMillion as number, ...money,
      timeoutMs: config.timeoutMs as number, requestBytes: config.requestBytes as number, responseBytes: config.responseBytes as number,
      inputTokens: config.inputTokens as number, outputTokens: config.outputTokens as number, findings: config.findings as number,
    };
    const frozenPrompts = Object.freeze({ summary: prompts.summary, chat: prompts.chat });
    const version = hash(JSON.stringify({ contract: 'openai-offline-core-v2', accounting: 'configured-rates-ceil-micros-v1',
      provider: 'OpenAI', endpoint: OPENAI_ENDPOINT, ...settings, chatSources: CHAT_SOURCE_BUDGET,
      prompts: { summary: hash(frozenPrompts.summary), chat: hash(frozenPrompts.chat) },
      responseFormats: { summary: openAiResponseFormat('summary'), chat: openAiResponseFormat('chat') } }));
    const policy = Object.freeze({ ...settings, provider: 'OpenAI' as const, version });
    policies.set(policy, frozenPrompts);
    return policy;
  } catch { return null; }
}

export function checkedOpenAiPolicy(policy: OpenAiPolicy): OpenAiPrompts {
  const prompts = policies.get(policy);
  if (!prompts) throw openAiConfigurationError();
  return prompts;
}
