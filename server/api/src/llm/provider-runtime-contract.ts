import type { HistoryContext } from './history-context.js';
import type { ChatReply } from './history-contract.js';
import type { OpenAiPolicy } from './openai-policy.js';
import type { LlmPolicy, disclosure } from './policy.js';
import type { ChatReceipt, OpenAiDisclosure } from './provider-browser-contract.js';
import type { QuotaBindings, QuotaLedger, QuotaSnapshot } from './quota-ledger.js';
import type { Vector } from './quota-policy.js';
import type { ReportContext } from './report-context.js';
import type { SummaryResponse } from './summary-result-cache.js';

export type OpenAiSummaryPolicy = Readonly<{ provider: 'OpenAI'; version: string; policy: OpenAiPolicy;
  findings: number; requestBytes: number; responseBytes: number }>;
export type SummaryValidationPolicy = LlmPolicy | OpenAiSummaryPolicy;
// Authority surrounds a synchronous dispatch+send action, never a cached permission.
export type RuntimeSendFence = (dispatchAndSend: () => void) => void;
export type RuntimeAttempt<T> = Readonly<{
  id: string;
  // Notification after accounting dispatch, inside the actual send fence (not
  // the lazy credential fence). It may still refuse send; liability stays held.
  generate(signal: AbortSignal, fence: RuntimeSendFence, observed: (receipt: ChatReceipt) => void, dispatched?: () => void): Promise<T>;
  release(): void;
}>;
export type PreparedOperation<T> = Readonly<{
  hash: string; reserve: Vector;
  checkAdapter?: () => void;
  snapshot(ledger: QuotaLedger, binding: QuotaBindings): QuotaSnapshot;
  reserveAttempt(ledger: QuotaLedger, binding: QuotaBindings): RuntimeAttempt<T>;
}>;
export type ProviderRuntimeSnapshot = Readonly<{
  provider: 'OpenAI' | 'OpenRouter'; version: string; chatVersion: string; providerPolicyVersion: string;
  timeoutMs: number; requestBytes: number; responseBytes: number; findings: number; outputTokens: number;
  chatEnabled: boolean; durableSummary: boolean; summaryPolicy: SummaryValidationPolicy;
  disclosure(report: ReportContext): OpenAiDisclosure | ReturnType<typeof disclosure>;
  prepareSummary(report: ReportContext): PreparedOperation<SummaryResponse>;
  prepareChat(context: HistoryContext): PreparedOperation<ChatReply>;
}>;
