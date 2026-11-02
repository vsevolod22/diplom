import { HttpException } from '@nestjs/common';
import { hashValue, HISTORY, validateChatReply } from './history-contract.js';
import { prepareSummary, prepareHistory, type PreparedRequest } from './prepared-request.js';
import { OpenRouterProvider, configError, type LlmProvider } from './openrouter-provider.js';
import { disclosure, publicFreePolicy, type LlmPolicy } from './policy.js';
import { validateReply } from './response.js';
import { quotaPolicyFromEnvironment, quotaUnavailable, type QuotaPolicy } from './quota-policy.js';
import type { QuotaBindings, QuotaLedger } from './quota-ledger.js';
import { createOpenAiAccountingPolicy, createOpenAiQuotaContext, bindOpenAiAccounting, OPENAI_COST_BASIS } from './openai-accounting.js';
import { prepareOpenAiSummary, prepareOpenAiChat, type OpenAiPrepared } from './openai-prepared-request.js';
import { OpenAiProvider, type OpenAiGuardedTransport } from './openai-provider.js';
import { readOpenAiEnvironment, type OpenAiServerConfiguration } from './openai-environment.js';
import { readOpenAiKeyEnvironment, openAiKeyEnvironmentReady, type OpenAiEnvironment } from './openai-key-environment.js';
import type { OpenAiPolicy } from './openai-policy.js';
import { makeOpenAiTransport } from './openai-transport.js';
import { OPENAI_PROMPTS } from './openai-prompts.js';
import { openAiDisclosure, OPENAI_ESTIMATE_SOURCE, OPENROUTER_RECEIPT_SOURCE, type ChatReceipt } from './provider-browser-contract.js';
import type { PreparedOperation, ProviderRuntimeSnapshot, RuntimeAttempt } from './provider-runtime-contract.js';

export const PROVIDER_RUNTIME_OPTIONS = Symbol('PROVIDER_RUNTIME_OPTIONS');
// Trusted DI seams only. Neither transport nor credential/config callbacks come from HTTP.
export type ProviderRuntimeOptions = Readonly<{
  environment?: () => OpenAiEnvironment;
  configuration?: () => OpenAiServerConfiguration | null;
  quotaPolicy?: () => QuotaPolicy | null;
  credential?: () => string;
  credentialReady?: () => boolean;
  transport?: (policy: OpenAiPolicy, maxConcurrent: number) => OpenAiGuardedTransport;
}>;
export type LegacyProviderRuntime = { policy(): LlmPolicy | null; provider(): LlmProvider;
  resolve?: () => ProviderRuntimeSnapshot | null };
export function resolveProviderRuntime(runtime: LegacyProviderRuntime): ProviderRuntimeSnapshot | null {
  if (runtime.resolve) return runtime.resolve();
  const policy = runtime.policy();
  return policy ? openRouterRuntime(policy, () => runtime.provider()) : null;
}
export function openRouterRuntime(policy: LlmPolicy, provider: () => LlmProvider): ProviderRuntimeSnapshot {
  function operation<T>(prepared: PreparedRequest, validate: (value: unknown) => T, chat: boolean): PreparedOperation<T> {
    let admittedAdapter: LlmProvider | undefined;
    return Object.freeze({ hash: prepared.hash, reserve: prepared.reserve,
      ...(chat ? { checkAdapter: () => {
        admittedAdapter = provider();
        if (!(admittedAdapter instanceof OpenRouterProvider)) throw configError();
      } } : {}),
      snapshot: (ledger: QuotaLedger, binding: QuotaBindings) => ledger.snapshot(binding.subject, binding.scanId, prepared.reserve),
      reserveAttempt: (ledger: QuotaLedger, binding: QuotaBindings): RuntimeAttempt<T> => {
        const id = ledger.reserve(binding, prepared.reserve);
        return Object.freeze({ id, release: () => { ledger.release(id); },
          async generate(signal, fence, observed) {
            const adapter = admittedAdapter ?? provider();
            let receipt: ChatReceipt | undefined;
            const accounting = { policy: ledger.policy, observe: (usage: Parameters<QuotaLedger['observe']>[1]) => {
              if (!ledger.observe(id, usage) || usage.input === undefined || usage.output === undefined || usage.costMicros !== 0) throw quotaUnavailable();
              receipt = Object.freeze({ input: usage.input, output: usage.output, costMicros: 0, source: OPENROUTER_RECEIPT_SOURCE });
              observed(receipt);
            } };
            let raw: unknown;
            if (chat) {
              if (!(adapter instanceof OpenRouterProvider)) throw configError();
              raw = await adapter.generateGuarded(prepared, policy, signal, accounting, send => fence(() => {
                if (!ledger.dispatch(id)) throw quotaUnavailable();
                send();
              }));
            } else {
              // Preserve the established OpenRouter summary seam, including injected
              // three/four-argument fixtures. OpenAI never enters this branch.
              if (!adapter.summarizePrepared) throw configError();
              let pending: Promise<unknown> | undefined;
              fence(() => {
                if (!ledger.dispatch(id)) throw quotaUnavailable();
                pending = adapter.summarizePrepared!(prepared, policy, signal, accounting);
              });
              if (!pending) throw quotaUnavailable();
              raw = await pending;
            }
            if (!receipt) throw quotaUnavailable();
            return validate(raw);
          } });
      } });
  }
  return Object.freeze({ provider: 'OpenRouter', version: policy.version,
    chatVersion: hashValue([policy.version, HISTORY.version, 'question-history-decisions-retained-no-output-cache']),
    providerPolicyVersion: policy.version, timeoutMs: policy.timeoutMs, requestBytes: policy.requestBytes,
    responseBytes: policy.responseBytes, findings: policy.findings, outputTokens: policy.outputTokens,
    chatEnabled: policy.freeOnly, durableSummary: publicFreePolicy(policy), summaryPolicy: policy,
    disclosure: () => disclosure(policy),
    prepareSummary: report => operation(prepareSummary(report, policy), raw => validateReply(raw, report, policy.freeOnly), false),
    prepareChat: context => operation(prepareHistory(context, policy), raw => validateChatReply(raw, context.report, true), true) });
}

class OpenAiAdmission {
  private readonly active = new Set<{ limit: number }>();
  acquire(limit: number, currentLimit = limit): () => void {
    if (![limit, currentLimit].every(value => Number.isSafeInteger(value) && value >= 1 && value <= 8)) throw configError();
    const effectiveLimit = Math.min(limit, currentLimit, ...[...this.active].map(attempt => attempt.limit));
    if (this.active.size >= effectiveLimit) throw new HttpException({ errorCode: 'LLM_CAPACITY' }, 429);
    const attempt = { limit: effectiveLimit };
    this.active.add(attempt);
    return () => { this.active.delete(attempt); };
  }
}

// Approval and prepared requests keep this SAME branded policy object. Versions
// compare current authority; they never replace the factory's object provenance.
export function createOpenAiRuntime(config: OpenAiServerConfiguration, quota: QuotaPolicy,
  provider: () => OpenAiProvider,
  admit?: () => () => void): ProviderRuntimeSnapshot | null {
  const admission = new OpenAiAdmission();
  const acquire = admit ?? (() => admission.acquire(config.maxConcurrent));
  const policy = config.policy;
  if (!config.accountingRevision || config.spending.userBudgetMicros !== quota.user.costMicros ||
      config.spending.scanBudgetMicros !== quota.scan.costMicros) return null;
  const approval = createOpenAiAccountingPolicy({ enabled: true, revision: config.accountingRevision, providerPolicyVersion: policy.version,
    quotaPolicyVersion: quota.version, billing: 'text-tokens-only-no-additional-fees', costBasis: OPENAI_COST_BASIS,
    ...(policy.monetaryLimit === undefined ? {} : { monetaryLimit: policy.monetaryLimit }) }, policy, quota);
  if (!approval) return null;
  const version = hashValue(['openai-runtime-v1', policy.version, quota.version, approval.version]);
  function operation<T>(prepared: OpenAiPrepared, select: (result: Awaited<ReturnType<OpenAiProvider['generate']>>) => T): PreparedOperation<T> {
    const contextFor = (binding: QuotaBindings) => createOpenAiQuotaContext(binding, prepared, policy, approval!);
    return Object.freeze({ hash: prepared.hash, reserve: prepared.reserve,
      snapshot: (ledger: QuotaLedger, binding: QuotaBindings) => ledger.snapshotOpenAi(contextFor(binding)),
      reserveAttempt: (ledger: QuotaLedger, binding: QuotaBindings): RuntimeAttempt<T> => {
        const context = contextFor(binding), id = ledger.reserveOpenAi(context), bound = bindOpenAiAccounting(ledger, id, context);
        return Object.freeze({ id, release: () => { bound.release(); },
          async generate(signal, fence, observed) {
            let release: (() => void) | undefined;
            try {
              let adapter: OpenAiProvider | undefined;
              // Recheck authority and shared capacity before opening the lazy credential.
              // The transport still repeats the full dispatch fence immediately before send.
              fence(() => {
                if (signal.aborted) throw configError();
                release = acquire();
                adapter = provider();
              });
              if (!adapter) throw configError();
              let receipt: ChatReceipt | undefined;
              const result = await adapter.generate(prepared, signal, {
                assertReserved: bound.accounting.assertReserved,
                observe(binding, usage) {
                  const accepted = bound.accounting.observe(binding, usage);
                  if (accepted && usage.normal && usage.input !== undefined && usage.output !== undefined && usage.costMicros !== undefined) {
                    receipt = Object.freeze({ input: usage.input, output: usage.output, costMicros: usage.costMicros, source: OPENAI_ESTIMATE_SOURCE });
                    observed(receipt);
                  }
                  return accepted;
                },
              }, (binding, send) => fence(() => {
                if (!bound.dispatch(binding)) throw quotaUnavailable();
                send();
              }));
              if (!receipt) throw quotaUnavailable();
              return select(result);
            } finally { release?.(); }
          } });
      } });
  }
  return Object.freeze({ provider: 'OpenAI', version,
    chatVersion: hashValue([version, HISTORY.version, 'question-history-decisions-retained-no-output-cache']),
    providerPolicyVersion: policy.version, timeoutMs: policy.timeoutMs, requestBytes: policy.requestBytes,
    responseBytes: policy.responseBytes, findings: policy.findings, outputTokens: policy.outputTokens,
    chatEnabled: true, durableSummary: true,
    summaryPolicy: Object.freeze({ provider: 'OpenAI', version, policy, findings: policy.findings,
      requestBytes: policy.requestBytes, responseBytes: policy.responseBytes }),
    disclosure: report => openAiDisclosure(policy, quota, !!report.profile),
    prepareSummary: report => operation(prepareOpenAiSummary(report, policy), result => {
      if (result.operation !== 'summary') throw configError(); return result.value;
    }),
    prepareChat: context => operation(prepareOpenAiChat(context, policy), result => {
      if (result.operation !== 'chat') throw configError(); return result.value;
    }) });
}

export class OpenAiRuntimeResolver {
  private readonly admission = new OpenAiAdmission();
  private readonly snapshots = new Map<string, { configuration: OpenAiServerConfiguration; runtime: ProviderRuntimeSnapshot | null }>();
  constructor(private readonly options: ProviderRuntimeOptions = {}) {}
  environment(): OpenAiEnvironment { return this.options.environment?.() ?? process.env; }
  selected(): 'openrouter' | 'openai' | null {
    const value = this.environment().LLM_PROVIDER;
    return value === undefined || value === 'openrouter' ? 'openrouter' : value === 'openai' ? 'openai' : null;
  }
  inspect(): { configuration: OpenAiServerConfiguration | null; runtime: ProviderRuntimeSnapshot | null } {
    const configuration = this.options.configuration ? this.options.configuration() : readOpenAiEnvironment(OPENAI_PROMPTS, this.environment());
    if (!configuration) return { configuration: null, runtime: null };
    const quota = this.options.quotaPolicy ? this.options.quotaPolicy() : quotaPolicyFromEnvironment(this.environment());
    if (!quota) return { configuration, runtime: null };
    const key = hashValue([configuration, quota]);
    const existing = this.snapshots.get(key);
    if (existing) return existing;
    // Keep old snapshots alive for attempts/receipts; bounded rotations fail closed.
    if (this.snapshots.size >= 4) return { configuration, runtime: null };
    let transport: OpenAiGuardedTransport | undefined;
    const runtime = createOpenAiRuntime(configuration, quota, () => {
      transport ??= (this.options.transport ?? makeOpenAiTransport)(configuration.policy, configuration.maxConcurrent);
      return new OpenAiProvider(configuration.policy,
        this.options.credential ? this.options.credential() : readOpenAiKeyEnvironment(this.environment()), transport);
    }, () => {
      // A rotation must not create a new concurrency pool or widen old active limits.
      if (this.selected() !== 'openai') throw configError();
      const current = this.inspect();
      if (!current.runtime || !current.configuration) throw configError();
      return this.admission.acquire(configuration.maxConcurrent, current.configuration.maxConcurrent);
    });
    const snapshot = Object.freeze({ configuration, runtime });
    this.snapshots.set(key, snapshot);
    return snapshot;
  }
  translationCompatible(): boolean {
    const mode = this.options.quotaPolicy ? this.options.quotaPolicy()?.monetaryLimit : this.environment().LLM_QUOTA_MONETARY_LIMIT;
    return (mode === undefined || mode === 'capped') && this.environment().OPENAI_MONETARY_LIMIT !== 'uncapped';
  }
  credentialReady(): boolean { return this.options.credentialReady?.() ?? openAiKeyEnvironmentReady(this.environment()); }
}
