import { createOpenAiPolicy, OPENAI_MODEL, type OpenAiSettings } from '../openai-policy.js';
import { HISTORY, reportBinding } from '../history-contract.js';
import type { ReportContext } from '../report-context.js';
import type { HistoryContext } from '../history-context.js';
import { fixtureReport } from './fixtures.js';

// Explicit synthetic prices/prompts/key; no deployment settings or credential reads.
export const openAiSettings: OpenAiSettings = {
  enabled: true, model: OPENAI_MODEL, revision: 'offline-test-v1', routingApproved: true, retention: 'no-training',
  inputPriceMicrosPerMillion: 1_000_000, outputPriceMicrosPerMillion: 2_000_000, requestBudgetMicros: 100_000,
  timeoutMs: 1000, requestBytes: 65_536, responseBytes: 8192, inputTokens: 65_536, outputTokens: 256, findings: 1000,
};
export const openAiPrompts = { summary: 'Write summary prose directly in Russian. Preserve source bindings and citations exactly.',
  chat: 'Write response prose directly in Russian. Preserve source bindings and citations exactly.' };
export const makeOpenAiPolicy = (overrides: Partial<OpenAiSettings> = {}) => {
  const policy = createOpenAiPolicy({ ...openAiSettings, ...overrides }, openAiPrompts);
  if (!policy) throw new Error('Invalid synthetic policy fixture');
  return policy;
};
export const syntheticOpenAiKey = 'synthetic_openai_not_a_real_key_12345';
export const openAiReport: ReportContext = { ...fixtureReport, requestedChecks: ['secret'],
  coverage: { secret: { outcome: 'checked', findingCount: 1 }, sbom: { outcome: 'unknown', reason: 'CHECK_NOT_REQUESTED' },
    config: { outcome: 'unknown', reason: 'CHECK_NOT_REQUESTED' }, vuln: { outcome: 'unknown', reason: 'CHECK_NOT_REQUESTED' } },
  findings: [{ check: 'secret', findingId: 'secret-0-1', severity: 'UNKNOWN', ruleId: 'rule-0123456789abcdef', line: 1, evidenceRef: 'result-0-secret-1' }] };
export const openAiHistory: HistoryContext = { version: HISTORY.version, report: openAiReport,
  history: { epoch: '00000000-0000-4000-8000-000000000001', revision: 0, userTurns: [], decisions: [], optionalExplanations: [] },
  question: 'Что проверить?', omission: { findings: 0, explanations: 0, selectedFindingIds: ['secret-0-1'] } };
export const openAiText = 'Сканер сообщил о находке;  требуется проверка.';
export const openAiReply = (operation: 'summary' | 'chat' = 'summary', text = openAiText) => ({ ...reportBinding(openAiReport),
  ...(operation === 'summary' ? { hypotheses: [{ text, citations: ['secret-0-1'] }] } : { text, citations: ['secret-0-1'] }) });
export const openAiEnvelope = (content: unknown = openAiReply(), usage: unknown = { prompt_tokens: 20, completion_tokens: 10, total_tokens: 30 }) => ({
  model: OPENAI_MODEL, service_tier: 'default', usage,
  choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: JSON.stringify(content) } }],
});
export const openAiResponse = (value: unknown = openAiEnvelope()) => new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } });
