import { lazy, Suspense, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';
import { scanSession, subscribeScanSession } from '@/shared/api/auth/scanSession';
import { subscribeReportPreferences, useReportPreferences } from '@/shared/api/preferences/reportPreferences';
import { reportPreferencesCurrent } from '@/shared/api/scans/reportAutomation';
import { ChatError, createChatClient, type ChatClient } from '@/shared/api/scans/llmChatClient';
import {
  chatContextFence,
  chatReceiptMatchesProvider,
  sameChatBinding,
  validChatText,
  verifiedChatSources,
  type ChatContext,
  type ChatHistory,
  type ChatReadiness,
  type ChatResult,
  type ChatSource,
} from '@/shared/api/scans/llmChatContract';
import { collectSummarySources, type SummarySource } from '@/shared/api/scans/llmSummaryClient';
import type { ScanStatus, ScanTransport } from '@/shared/api/scans/scanTransport';
import { usageMatchesDisclosure, type LlmUsage } from '@/shared/api/scans/llmUsageClient';
import { OpenAiDisclosure } from './OpenAiDisclosure';
import { isPaidDisclosure } from '@/shared/api/scans/llmPublicContract';
import { ReportRemediation } from './ReportRemediation';
import type { ReportSourceNavigate } from './reportSourceNavigation';
import { utf8Bytes } from '@/shared/api/scans/vulnAdvisory';
import { PUBLIC_IMAGE_PROFILE } from '@/shared/api/scans/publicImageProfile';
import { identifierLabel, identifierCountsTotal } from '@/shared/api/scans/publicVulnerabilityIdentifiers';
import { Alert, Button } from '@/shared/ui/scan-primitives';
import { SafeMarkdown } from './safeMarkdown';
import { ChatBubble, ChatThinking } from './ChatConversation';
import { SCAN_CHAT_INPUT_BYTE_LIMIT, scanChatInputFeedback } from './scanChatInputFeedback';

const ChatMarkdownComposer = lazy(() => import('./ChatMarkdownComposer').then(module => ({ default: module.ChatMarkdownComposer })));

type Props = { status: ScanStatus; transport: ScanTransport; client?: ChatClient; onNavigateSource?: ReportSourceNavigate };
type Operation = 'read' | 'chat' | 'decision';
type Snapshot = {
  context: ChatContext;
  history: ChatHistory;
  usage: LlmUsage | null;
  sources: SummarySource[];
};
const readinessMessages = {
  'configuration-required': 'Чат не настроен. Обратитесь к оператору.',
  'environment-key-required': 'Требуется серверная настройка провайдера. Не вводите ключ в интерфейс.',
  'accounting-configuration-required': 'Учёт стоимости провайдера не настроен. Обратитесь к оператору.',
  'public-key-required': 'Чат не настроен. Обратитесь к оператору; не вводите ключи в чат.',
  'public-key-unsafe': 'Настройки чата не прошли проверку безопасности. Обратитесь к оператору.',
  'quota-store-unavailable': 'Не удалось проверить лимиты. Попробуйте обновить историю позже.',
  'history-store-unavailable': 'История временно недоступна. Попробуйте позже.',
  'provider-profile-unavailable': 'Сервис ответов недоступен. Обратитесь к оператору.',
};
function chatErrorMessage(error: unknown, operation: Operation = 'chat') {
  const code = error instanceof ChatError ? error.code : '';
  if (code === 'SESSION') return 'Сессия изменилась или истекла. Войдите заново.';
  if (code === 'ACCESS') return 'Доступ к чату этого отчёта не подтверждён. Проверьте аккаунт.';
  if (['STALE', 'LLM_STALE_REPORT', 'LLM_STALE_POLICY', 'LLM_HISTORY_CONFLICT'].includes(code))
    return 'Данные отчёта или условия чата изменились. Обновите историю перед отправкой.';
  if (operation === 'read') {
    if (['TIMEOUT', 'ABORTED', 'LLM_REQUEST_ABORTED'].includes(code))
      return 'Обновление истории остановлено. Это было только чтение: новый вопрос не отправлялся. Данные скрыты до успешной проверки; обновите историю вручную.';
    return 'Не удалось проверить сохранённую историю. Данные скрыты до успешной проверки; обновите историю вручную. Новый вопрос не отправлялся.';
  }
  if (['TIMEOUT', 'ABORTED', 'LLM_REQUEST_ABORTED', 'LLM_PROVIDER_TIMEOUT'].includes(code))
    return 'Ожидание остановлено. Ответ ещё может сохраниться — обновите историю перед повтором.';
  if (['LLM_QUOTA_EXCEEDED', 'LLM_BUDGET_EXCEEDED', 'LLM_CAPACITY'].includes(code))
    return 'Достигнут лимит запросов. Попробуйте позже.';
  if (code === 'LLM_HISTORY_CAPACITY')
    return 'Недостаточно доступной ёмкости хранилища истории. Это может быть общий лимит сервиса, а не размер этого чата. Обратитесь к оператору; автоматического повтора нет.';
  if (code === 'LLM_CONTEXT_LIMIT')
    return 'Обязательный контекст не помещается в новый запрос. История не удаляется; автоматического повтора нет.';
  if (code === 'LLM_CONFIGURATION_UNAVAILABLE') return 'Чат не настроен. Обратитесь к оператору.';
  if (code === 'LLM_PROVIDER_RATE_LIMITED') return 'Сервис ответов занят. Обновите историю перед повтором.';
  if (code === 'LLM_PROVIDER_AUTH_FAILED') return 'Чат временно недоступен. Обратитесь к оператору.';
  if (['LLM_PROVIDER_UNAVAILABLE', 'LLM_UNAVAILABLE'].includes(code))
    return 'Сервис ответов недоступен. Обновите историю перед повтором.';
  if (code === 'LLM_HISTORY_UNAVAILABLE') return 'История временно недоступна. Попробуйте позже.';
  if (['LLM_REPORT_UNAVAILABLE', 'REPORT_UNAVAILABLE'].includes(code))
    return 'Отчёт недоступен для чата. Проверьте доступ к отчёту.';
  if (code === 'LLM_NO_EVIDENCE') return 'Нет подтверждённых источников для ответа.';
  if (code === 'DUPLICATE') return 'Запрос уже зарегистрирован. Обновите историю, чтобы увидеть ответ.';
  if (code === 'INPUT') return 'Введите короткий вопрос без ссылок и секретов.';
  return 'Не удалось проверить ответ. Обновите историю перед повтором.';
}
function readinessMatchesContext(ready: ChatReadiness, context: ChatContext) {
  if (!sameChatBinding(ready, context)) return false;
  if (ready.setupAction === 'operator-server-environment-configuration') {
    if (!context.enabled) return true; // Disabled contexts deliberately disclose no provider policy.
    return isPaidDisclosure(context.disclosure) &&
      ready.provider.name === context.disclosure.provider && ready.provider.model === context.disclosure.model;
  }
  if (!context.enabled) return ready.provider.status === 'unverified-profile';
  return (
    context.disclosure?.provider === 'OpenRouter' &&
    'model' in ready.provider &&
    ready.provider.model === context.disclosure.model &&
    ready.provider.endpoint === context.disclosure.providers[0]
  );
}
const checkLabels = { secret: 'Секреты', vuln: 'Уязвимости', config: 'Конфигурация' };
const severityLabels: Record<string, string> = {
  CRITICAL: 'Критическая',
  HIGH: 'Высокая',
  MEDIUM: 'Средняя',
  LOW: 'Низкая',
  INFO: 'Информационная',
  UNKNOWN: 'Неизвестна',
};
function coverageLabel(outcome?: string) {
  const labels: Record<string, string> = {
    checked: 'проверено',
    unsupported: 'не поддерживается',
    failed: 'ошибка проверки',
    skipped: 'пропущено',
    cancelled: 'отменено',
    not_checked: 'не проверено',
    unknown: 'неизвестно',
    not_authorized: 'не разрешено',
  };
  return outcome ? (labels[outcome] ?? 'неизвестно') : 'неизвестно';
}
function coverageReason(reason: string) {
  const labels: Record<string, string> = {
    SCAN_FAILED: 'ошибка сканирования',
    SCAN_TIMEOUT: 'истекло время сканирования',
    DB_UNAVAILABLE: 'база уязвимостей недоступна',
    OS_EOL: 'поддержка ОС завершена',
    OS_UNKNOWN: 'ОС не определена',
    NODE_INVENTORY_ABSENT: 'состав пакетов Node.js отсутствует',
    NODE_INVENTORY_UNKNOWN: 'состав пакетов Node.js не установлен',
  };
  return labels[reason] ?? 'причина не установлена';
}
function sourceLabel(label: string) {
  return label
    .split(' · ')
    .map(
      (part) =>
        severityLabels[part] ??
        (part === 'Secrets'
          ? 'Секреты'
          : part === 'Debian advisory (не CVE)'
            ? 'Уведомление Debian (не CVE)'
            : part === 'Debian DLA advisory (не CVE)'
              ? 'Бюллетень Debian DLA (не CVE)'
              : part),
    )
    .join(' · ');
}
const sessionKey = () => JSON.stringify(scanSession());
const policyFence = (v: ChatContext) =>
  JSON.stringify({
    scanId: v.scanId,
    digest: v.digest,
    platform: v.platform,
    reportVersion: v.reportVersion,
    policyVersion: v.policyVersion,
    disclosure: v.disclosure,
    enabled: v.enabled,
    findingCount: v.findingCount,
    findingCounts: v.findingCounts,
    identifierCounts: v.identifierCounts,
    coverage: v.coverage,
  });
export function ScanChatPanel(props: Props) {
  const session = useSyncExternalStore(subscribeScanSession, sessionKey, sessionKey);
  const preferences = useReportPreferences();
  // Session, report and preference changes fence drafts and pending explicit submissions.
  return (
    <ChatScope
      key={JSON.stringify([session, props.status, preferences])}
      {...props}
      preferences={preferences}
    />
  );
}
function SourceList({
  sources,
  current,
  prefix,
  onNavigate,
  disabled,
}: {
  sources: ChatSource[];
  current: ChatContext;
  prefix: string;
  onNavigate?: ReportSourceNavigate;
  disabled: boolean;
}) {
  return (
    <div aria-label="Источники ответа">
      <p>Источники ({sources.length})</p>
      <ul>
        {sources.map((source) => (
          <li key={source.finding.findingId} id={`${prefix}-${source.finding.findingId}`} tabIndex={-1}>
            <strong>
              {checkLabels[source.finding.check]} · {severityLabels[source.finding.severity] ?? 'Неизвестна'}
            </strong>
            {source.finding.check === 'vuln' ? (
              <p style={{ overflowWrap: 'anywhere' }}>
                {source.finding.cveId} · {sourceLabel(identifierLabel(source.finding.cveId))}
              </p>
            ) : null}
            <p>
              {sameChatBinding(source, current)
                ? 'Источник текущего отчёта, проверен по результатам сканирования.'
                : 'Исторический источник — не разрешён как находка текущего отчёта. Данные ниже относятся только к сохранённому источнику, не к текущему образу.'}
            </p>
            <ReportRemediation source={{ findingId: source.finding.findingId, check: source.finding.check,
              label: source.finding.check === 'vuln' ? source.finding.cveId : checkLabels[source.finding.check], finding: source.finding }}
              onNavigate={onNavigate} disabled={disabled || !sameChatBinding(source, current)} />
          </li>
        ))}
      </ul>
    </div>
  );
}
function ChatScope({
  status,
  transport,
  client: providedClient,
  onNavigateSource,
  preferences,
}: Props & { preferences: ReturnType<typeof useReportPreferences> }) {
  const client = useMemo(() => providedClient ?? createChatClient(scanSession()), [providedClient]);
  const current = () => client.current() && reportPreferencesCurrent(preferences);

  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [readiness, setReadiness] = useState<ChatReadiness | null>(null);
  const publicReport = status.profile === PUBLIC_IMAGE_PROFILE;
  const [question, setQuestion] = useState('');
  const [decision, setDecision] = useState('');
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState('');
  const [receipt, setReceipt] = useState<Extract<ChatResult, { reply: unknown }>['usage'] | null>(null);
  const request = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const questionInput = useRef<HTMLElement | null>(null);
  const chatContent = useRef<HTMLDivElement | null>(null);
  const followLatest = useRef(true);
  const verifiedSources = useRef<{ fence: string; sources: SummarySource[] } | null>(null);
  const [operation, setOperation] = useState<Operation>('read');
  useEffect(() => {
    const content = chatContent.current;
    if (content && followLatest.current) content.scrollTop = content.scrollHeight;
  }, [snapshot?.history.revision, pending]);

  function invalidate() {
    generation.current++;
    verifiedSources.current = null;
    request.current?.abort();
    request.current = null;
  }
  function cancel() {
    invalidate();
    setPending(false);
    setSnapshot(null);
    setReceipt(null);
    setSelectedIds([]);
    setReadiness(null);
    setMessage(chatErrorMessage(new ChatError('ABORTED'), operation));
  }
  function checkStatus(context: ChatContext) {
    if (
      context.scanId !== status.scanId ||
      context.digest !== status.digest ||
      context.platform !== status.platform
    )
      throw new ChatError('STALE');
    if (
      publicReport &&
      (context.findingCount === undefined ||
        context.identifierCounts?.cve !== status.identifierCounts?.cve ||
        context.identifierCounts?.debianTemp !== status.identifierCounts?.debianTemp ||
        (context.identifierCounts?.debianDla ?? 0) !== (status.identifierCounts?.debianDla ?? 0))
    )
      throw new ChatError('STALE');
  }
  async function readReadiness(signal: AbortSignal) {
    try {
      const value = await client.readiness(status.scanId, signal);
      if (
        value.scanId !== status.scanId ||
        value.digest !== status.digest ||
        value.platform !== status.platform
      )
        throw new ChatError('STALE');
      return value;
    } catch (error) {
      if (
        error instanceof ChatError &&
        ['SESSION', 'ACCESS', 'REPORT_UNAVAILABLE', 'STALE', 'ABORTED'].includes(error.code)
      )
        throw error;
      if (signal.aborted) throw error;
      // A malformed/offline/timed-out readiness is unknown, never a generation permission; history may still work.
      return null;
    }
  }
  async function readSnapshot(
    signal: AbortSignal,
    observeContext?: (context: ChatContext) => void,
  ): Promise<Snapshot> {
    const context = await client.context(status.scanId, signal);
    checkStatus(context);
    observeContext?.(context);
    const [history, usage, sources] = await Promise.all([
      client.history(context, signal),
      client.usage(context, signal).catch((error) => {
        if (
          error instanceof ChatError &&
          ['SESSION', 'ACCESS', 'REPORT_UNAVAILABLE', 'ABORTED', 'TIMEOUT'].includes(error.code)
        )
          throw error;
        return null;
      }),
      verifiedSources.current?.fence === policyFence(context)
        ? Promise.resolve(verifiedSources.current.sources)
        : collectSummarySources(transport, status, signal),
    ]);
    if (publicReport && sources.length !== context.findingCount) throw new ChatError('STALE');
    if (
      history.epoch !== context.epoch ||
      history.revision !== context.revision ||
      !!history.pending !== context.pending
    )
      throw new ChatError('STALE');
    for (const turn of history.turns) {
      if (
        turn.state === 'completed' &&
        sameChatBinding(turn.report, context) &&
        !verifiedChatSources(turn.reply, sources)
      )
        throw new ChatError('INVALID');
    }
    for (const entry of history.decisions) {
      if (
        sameChatBinding(entry.report, context) &&
        entry.sources.some(
          (source) =>
            !sources.some(
              (s) => s.findingId === source.finding.findingId && s.check === source.finding.check,
            ),
        )
      )
        throw new ChatError('INVALID');
    }
    const after = await client.context(status.scanId, signal);
    observeContext?.(after);
    if (chatContextFence(after) !== chatContextFence(context)) throw new ChatError('STALE');
    // The immutable report binding covers these fully verified scanner pages.
    // Cache only inside this owner/session/preferences mount, after the final fence.
    if (!signal.aborted && current()) verifiedSources.current = { fence: policyFence(context), sources };
    return { context, history, usage, sources };
  }
  async function operate(
    kind: Operation,
    timeoutMs: number,
    action: (signal: AbortSignal, publish: (action: () => void) => void) => Promise<void>,
  ) {
    if (request.current || !current()) return;
    const controller = new AbortController();
    request.current = controller;
    const version = ++generation.current;
    setOperation(kind);
    setPending(true);
    setReceipt(null);
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    const live = () => generation.current === version && !controller.signal.aborted && current();
    const stopped = new Promise<never>((_, reject) =>
      controller.signal.addEventListener(
        'abort',
        () => reject(new ChatError(timedOut ? 'TIMEOUT' : 'ABORTED')),
        { once: true },
      ),
    );
    // The guarded publish callback also fences injected clients that ignore AbortSignal.
    const publish = (value: () => void) => {
      if (live()) value();
    };
    try {
      await Promise.race([action(controller.signal, publish), stopped]);
    } catch (error) {
      if (generation.current === version && current()) {
        setSnapshot(null);
        // A known history outage may retain setup blockers, never a generation permission.
        setReadiness((value) =>
          kind === 'read' && error instanceof ChatError && error.code === 'LLM_HISTORY_UNAVAILABLE' && !value?.localReady
            ? value
            : null,
        );
        setSelectedIds([]);
        if (
          error instanceof ChatError &&
          ['SESSION', 'ACCESS', 'REPORT_UNAVAILABLE', 'LLM_REPORT_UNAVAILABLE'].includes(error.code)
        ) {
          setQuestion('');
          setDecision('');
        }
        setMessage(chatErrorMessage(error, kind));
      }
    } finally {
      clearTimeout(timer);
      controller.abort();
      if (generation.current === version) {
        request.current = null;
        setPending(false);
      }
    }
  }

  function retainedDecisionSources(previous: Snapshot | null, next: Snapshot, ids: string[]) {
    if (
      !previous ||
      policyFence(previous.context) !== policyFence(next.context) ||
      previous.context.epoch !== next.context.epoch ||
      next.context.revision < previous.context.revision
    ) return [];
    return ids.filter(id => {
      const before = previous.sources.find(source => source.findingId === id);
      const after = next.sources.find(source => source.findingId === id);
      return before && after && JSON.stringify(before) === JSON.stringify(after);
    });
  }

  function refresh() {
    if (request.current || !current()) return;
    // Explicit refresh rechecks scanner pages too, including same-ID content drift.
    verifiedSources.current = null;
    setReadiness(null);
    setMessage('');
    // Keep only this mounted session/report's last confirmed view while reading.
    // Any contradictory context or failed read clears it; it never authorizes a mutation.
    const previous = snapshot;
    void operate('read', 45_000, async (signal, publish) => {
      const discardPrevious = () => publish(() => {
        setSnapshot(null);
        setSelectedIds([]);
      });
      const observeContext = (value: ChatContext) => {
        if (
          previous &&
          (policyFence(value) !== policyFence(previous.context) ||
            value.epoch !== previous.context.epoch ||
            value.revision < previous.context.revision)
        )
          discardPrevious();
      };
      // Keep setup diagnostics available even if the history-backed context cannot be read.
      let ready = publicReport ? await readReadiness(signal) : null;
      publish(() => setReadiness(ready));
      if (publicReport && !ready) publish(() => setSnapshot(null));
      else if (publicReport && ready && previous && !readinessMatchesContext(ready, previous.context))
        discardPrevious();
      const next = await readSnapshot(signal, observeContext);
      if (!publicReport && isPaidDisclosure(next.context.disclosure)) {
        ready = await readReadiness(signal);
        publish(() => setReadiness(ready));
      }
      if (ready && !readinessMatchesContext(ready, next.context)) {
        publish(() => setReadiness(null));
        throw new ChatError('STALE');
      }
      publish(() => {
        setSnapshot(next);
        setSelectedIds(ids => retainedDecisionSources(previous, next, ids));
      });
    });
  }
  useEffect(() => {
    const preferencesChanged = () => {
      if (reportPreferencesCurrent(preferences)) return;
      invalidate();
      setSnapshot(null);
      setReadiness(null);
      setReceipt(null);
      setSelectedIds([]);
      setQuestion('');
      setDecision('');
      setPending(false);
    };
    const unsubscribePreferences = subscribeReportPreferences(preferencesChanged);
    const unsubscribe = subscribeScanSession(() => {
      invalidate();
      setSnapshot(null);
      setReadiness(null);
      setReceipt(null);
      setSelectedIds([]);
      setQuestion('');
      setDecision('');
      setPending(false);
    });
    refresh();
    return () => {
      invalidate();
      unsubscribe();
      unsubscribePreferences();
    };
    // Automatic connection reads only GETs; questions and decisions remain explicit actions.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, preferences]);

  function mutate(kind: 'chat' | 'decision') {
    const accepted = snapshot;
    if (
      !accepted ||
      pending ||
      accepted.context.pending ||
      !current() ||
      (kind === 'chat' &&
        (!accepted.context.enabled ||
          ((publicReport || isPaidDisclosure(accepted.context.disclosure)) && !readiness?.localReady)))
    )
      return;
    const value = kind === 'chat' ? question : decision;
    if (!validChatText(value)) {
      setMessage(scanChatInputFeedback(value) ?? chatErrorMessage(new ChatError('INPUT')));
      return;
    }
    if (request.current) return;
    setMessage('');
    followLatest.current = true;
    const mutationId = crypto.randomUUID();
    const ids = [...selectedIds];
    void operate(kind, kind === 'chat' ? 120_000 : 45_000, async (signal, publish) => {
      if (kind === 'chat' && (publicReport || isPaidDisclosure(accepted.context.disclosure))) {
        const ready = await readReadiness(signal);
        publish(() => setReadiness(ready));
        if (!ready?.localReady) throw new ChatError('LLM_CONFIGURATION_UNAVAILABLE');
        if (!readinessMatchesContext(ready, accepted.context)) throw new ChatError('STALE');
      }
      const before = await client.context(status.scanId, signal);
      checkStatus(before);
      if (chatContextFence(before) !== chatContextFence(accepted.context) || signal.aborted || !current())
        throw new ChatError('STALE');
      const send = async () => {
        try {
          return kind === 'chat'
            ? await client.chat(before, value, mutationId, signal)
            : await client.decision(before, value, ids, mutationId, signal);
        } catch (error) {
          // Recovery reads never repeat a paid POST or turn a typed provider
          // failure into success. Only this exact completed/failed turn may appear.
          if (kind !== 'chat' || signal.aborted || !current() || !(error instanceof ChatError)) throw error;
          const deliveryFailure = ['DELIVERY', 'TIMEOUT'].includes(error.code);
          const terminalFailure = ['LLM_UNAVAILABLE', 'LLM_PROVIDER_UNAVAILABLE', 'LLM_INVALID_RESPONSE',
            'LLM_PROVIDER_TIMEOUT', 'LLM_PROVIDER_RATE_LIMITED', 'LLM_PROVIDER_AUTH_FAILED'].includes(error.code);
          if (!deliveryFailure && !terminalFailure) throw error;
          const recovered = await readSnapshot(signal).catch(() => { throw error; });
          const saved = recovered.history.turns.find(turn => turn.mutationId === mutationId);
          if (policyFence(recovered.context) !== policyFence(before) ||
            recovered.context.epoch !== before.epoch || recovered.context.pending ||
            recovered.history.epoch !== before.epoch || recovered.history.revision !== before.revision + 2 ||
            !saved || saved.question !== value || !sameChatBinding(saved.report, before)) throw error;
          if (terminalFailure) {
            if (saved.state !== 'failed') throw error;
            publish(() => {
              setSnapshot(recovered);
              setSelectedIds(previous => retainedDecisionSources(accepted, recovered, previous));
              setMessage(chatErrorMessage(error, kind));
            });
            return null;
          }
          if (saved.state !== 'completed' || !verifiedChatSources(saved.reply, recovered.sources)) throw error;
          publish(() => {
            setSnapshot(recovered);
            setQuestion('');
            setSelectedIds(previous => retainedDecisionSources(accepted, recovered, previous));
            setMessage('Ответ сохранён. Соединение прервалось, поэтому ответ прочитан из подтверждённой истории без повторной отправки.');
          });
          return null;
        }
      };
      const result = await send();
      if (!result) return;
      if (signal.aborted || !current()) throw new ChatError('STALE');
      if (
        'reply' in result &&
        (!verifiedChatSources(result.reply, accepted.sources) ||
          !chatReceiptMatchesProvider(result.usage, before))
      )
        throw new ChatError('INVALID');
      // No optimistic assistant or decision. Status-only duplicate, ambiguous cancellation and disconnect recover through GET.
      const next = await readSnapshot(signal);
      if (
        policyFence(next.context) !== policyFence(accepted.context) ||
        next.history.epoch !== accepted.context.epoch ||
        next.history.revision < result.revision
      )
        throw new ChatError('STALE');
      if ('reply' in result) {
        const saved = next.history.turns.find((t) => t.id === result.turnId && t.mutationId === mutationId);
        if (
          !saved ||
          saved.state !== 'completed' ||
          saved.question !== value ||
          !sameChatBinding(saved.report, accepted.context) ||
          next.history.revision !== result.revision ||
          JSON.stringify(saved.reply) !== JSON.stringify(result.reply)
        )
          throw new ChatError('INVALID');
      } else if (
        kind === 'decision' &&
        !('duplicate' in result) &&
        !next.history.decisions.some((d) => d.mutationId === mutationId && d.text === value)
      )
        throw new ChatError('INVALID');
      publish(() => {
        setSnapshot(next);
        setSelectedIds(ids => kind === 'decision' ? [] : retainedDecisionSources(accepted, next, ids));
        if (kind === 'chat') setQuestion('');
        else setDecision('');
        if ('reply' in result) setReceipt(result.usage);
        if ('duplicate' in result) setMessage('Запрос уже зарегистрирован. История обновлена.');
      });
    });
  }
  const context = snapshot?.context;
  const questionFeedback = scanChatInputFeedback(question);
  const decisionFeedback = scanChatInputFeedback(decision);
  const questionInvalid = question.length > 0 && !validChatText(question);
  const decisionInvalid = decision.length > 0 && !validChatText(decision);
  const available = !!snapshot && !pending && !context?.pending && current();
  const needsReadiness = publicReport || isPaidDisclosure(context?.disclosure);
  const generationAllowed = !!context?.enabled && (!needsReadiness || readiness?.localReady === true);
  const connection = pending
    ? operation === 'read'
      ? 'Читаем сохранённую историю… Новый вопрос не отправляется.'
      : operation === 'chat'
        ? 'Ожидаем ответ…'
        : 'Сохраняем решение…'
    : snapshot
      ? context?.pending
        ? 'Запрос ещё выполняется. Обновите историю позже.'
        : needsReadiness && !readiness?.localReady
          ? readiness?.blockers.length
            ? readinessMessages[readiness.blockers[0]]
            : 'Не удалось проверить готовность чата. Обновите историю позже.'
          : context?.enabled
            ? ''
            : 'Новые ответы отключены. История доступна.'
      : 'Не удалось подключить чат. Обновите историю.';
  return (
    <section
      id="scan-report-chat"
      className="scan-a1__chat"
      tabIndex={-1}
      aria-label="Чат по отчёту"
      aria-busy={pending}
      style={{ minWidth: 0, maxWidth: '100%', overflowWrap: 'anywhere' }}
    >
      <div className="scan-chat-content" ref={chatContent} onScroll={event => {
        const element = event.currentTarget;
        followLatest.current = element.scrollHeight - element.scrollTop - element.clientHeight < 64;
      }}>
      <h3>Задать вопрос по отчёту</h3>
            <p>Уточните непонятную находку или порядок исправлений. Ответ ИИ — подсказка, не замена проверки источников.</p>
      {['partial', 'failed', 'cancelled'].includes(status.state) ? (
        <p>
          Проверка {status.state === 'partial' ? 'завершилась частично' : status.state === 'failed' ? 'завершилась с ошибкой' : 'отменена'}.
          {' '}Авторазбор и отдельный перевод описаний доступны только для полностью завершённой проверки.
          Чат, если разрешён сервером, использует сохранённые результаты; непроверенное не означает отсутствие проблем.
        </p>
      ) : null}
      <p id="scan-chat-connection" role="status" aria-label="Состояние подключения чата" aria-live="polite">
        {connection}
      </p>

      <Button type="button" variant="secondary" disabled={pending || !current()} onClick={refresh}>
        Обновить историю
      </Button>
      {pending ? (
        <>
          <p>
            {operation === 'read'
              ? 'Можно остановить чтение и обновить историю позже. Это не отменяет ранее отправленные запросы.'
              : 'Отмена остановит ожидание, но запрос ещё может завершиться.'}
          </p>
          <Button type="button" variant="secondary" onClick={cancel}>
            {operation === 'read' ? 'Отменить обновление истории' : 'Отменить ожидание чата'}
          </Button>
        </>
      ) : null}
      {snapshot && pending && operation === 'read' ? (
        <Alert tone="warning">
          Показана предыдущая подтверждённая история. Данные могут быть устаревшими: обновление ещё не
          завершено. Отправка вопроса, подготовка повтора и сохранение решения недоступны до проверки.
        </Alert>
      ) : null}
      {message ? (
        <Alert role="alert" tone="warning">
          {message}
        </Alert>
      ) : null}
      {snapshot && context ? (
        <>
          {!snapshot.history.turns.length && !snapshot.history.decisions.length ? (
            <p>Например: «С каких находок начать?» Не добавляйте пароли, ключи или другие чувствительные данные.</p>
          ) : null}
          <div className="scan-chat-conversation" aria-label="Сохранённая переписка">
          {snapshot.history.turns.map((turn) => (
            <article key={turn.id}>
              <ChatBubble direction="outgoing">
              <h5>
                Вопрос ·{' '}
                {
                  {
                    pending: 'ожидает ответа',
                    completed: 'ответ сохранён',
                    failed: 'ошибка',
                    cancelled: 'отменён',
                    interrupted: 'прерван',
                  }[turn.state]
                }
              </h5>
              <SafeMarkdown text={turn.question} />
              </ChatBubble>
              {turn.state === 'completed' ? (
                <ChatBubble direction="incoming">
                  <h5>Ответ · проверьте по источникам</h5>
                  <SafeMarkdown text={turn.reply.text} />
                  <SourceList sources={turn.reply.sources} current={context} prefix={`chat-${turn.id}`}
                                      onNavigate={onNavigateSource ? category => current() && !pending && onNavigateSource(category) : undefined}
                                      disabled={pending} />
                </ChatBubble>
              ) : (
                <>
                  <p>
                    {
                      {
                        pending:
                          'По сохранённому статусу запрос ожидает ответа. Обновите историю позже; повторно он не отправляется.',
                        failed:
                          'Попытка завершилась с ошибкой. Подтверждённого ответа нет; причина в сохранённой истории не указана.',
                        cancelled: 'Попытка отменена. Подтверждённого ответа в истории нет.',
                        interrupted:
                          'Попытка прервана. Подтверждённого ответа нет; причина прерывания в сохранённой истории не указана.',
                      }[turn.state]
                    }
                  </p>
                  {turn.state !== 'pending' ? (
                    <p>
                      Автоматического повтора нет. Подготовка повтора только скопирует вопрос в черновик;
                      новая отправка требует отдельного нажатия и может быть платной. Статус не определяет
                      фактическую стоимость попытки.
                    </p>
                  ) : null}
                  {turn.state !== 'pending' ? (
                    <Button
                      type="button"
                      variant="secondary"
                      disabled={!available || !generationAllowed}
                      onClick={() => {
                        setQuestion(turn.question);
                        questionInput.current?.focus();
                      }}
                    >
                      Подготовить повтор вопроса
                    </Button>
                  ) : null}
                </>
              )}
            </article>
          ))}
          </div>
        </>
      ) : null}
      {pending && operation === 'chat' ? <ChatThinking /> : null}
      </div>
      <form
        className="scan-a1__compose"
        aria-label="Отправка вопроса по отчёту"
        onSubmit={(event) => {
          event.preventDefault();
          mutate('chat');
        }}
      >
        <Suspense fallback={<p role="status">Загрузка редактора…</p>}>
          <ChatMarkdownComposer textareaRef={questionInput} value={question} onChange={setQuestion}
            disabled={pending && operation !== 'read'} invalid={questionInvalid}
            describedBy={`scan-chat-input-help scan-chat-input-count${questionInvalid ? ' scan-chat-input-error' : ''}`} />
        </Suspense>
        <p id="scan-chat-input-count" hidden={utf8Bytes(question) < SCAN_CHAT_INPUT_BYTE_LIMIT * 0.9}>
          {utf8Bytes(question)} / {SCAN_CHAT_INPUT_BYTE_LIMIT} байт UTF-8
        </p>
        <p id="scan-chat-input-error" role="status" aria-live="polite" aria-atomic="true">
          {questionInvalid ? questionFeedback : null}
        </p>
        <details className="scan-chat-conditions">
          <summary>Об использовании ИИ</summary>
          <small id="scan-chat-input-help">
            Markdown: заголовки, списки, выделение и код. Без ссылок, HTML и секретов. До 2048 байт UTF-8.
          </small>
          {isPaidDisclosure(context?.disclosure) ? (
          <>
            <p>{context.disclosure.provider} · {context.disclosure.model}. Платный запрос:{' '}
              {'lifetimeUserCostMicros' in context.disclosure && typeof context.disclosure.lifetimeUserCostMicros === 'number' && context.disclosure.lifetimeUserCostMicros > 0
                ? `бюджет аккаунта $${context.disclosure.lifetimeUserCostMicros / 1_000_000} за всё время. `
                : context.disclosure.monetaryLimit === 'uncapped'
                  ? 'без локального денежного лимита — это не бесплатный режим. '
                  : 'с серверными денежными лимитами. '}
              {context.disclosure.provider === 'ModuleAPI' ? 'Хранение и обучение у провайдера не подтверждены.' : 'ZDR не подтверждён.'}</p>
            <OpenAiDisclosure disclosure={context.disclosure} chat />
          </>
        ) : null}
        <p>
          Нажимая «Отправить вопрос», вы разрешаете{' '}
          {isPaidDisclosure(context?.disclosure)
            ? `платный запрос ${context.disclosure.provider} и передачу вопроса, находок и истории на условиях выше. Это отдельное согласие, не прежний бесплатный opt-in.`
            : 'передать внешнему ИИ вопрос и контекст отчёта, включая историю чата. Запрет обучения не гарантирует отсутствие хранения.'}
        </p>
        </details>
        <p id="scan-chat-send-help" className="scan-chat-paid-notice">
          {isPaidDisclosure(context?.disclosure)
            ? `Отправка — платный запрос ${context.disclosure.provider}. Вы передаёте вопрос и контекст отчёта.`
            : 'Отправляя вопрос, вы передаёте его и контекст отчёта внешнему ИИ.'}
        </p>
        <Button
          type="submit"
          aria-describedby={`scan-chat-send-help scan-chat-input-help scan-chat-input-count scan-chat-connection${questionInvalid ? ' scan-chat-input-error' : ''}`}
          disabled={!available || !generationAllowed || !validChatText(question)}
        >
          Отправить вопрос
        </Button>
      </form>
      <details className="scan-chat-technical">
        <summary>Подробности · история решений, условия и использование</summary>
        {needsReadiness ? (
          <section aria-label="Готовность генерации">
            <h4>Готовность генерации</h4>
            {readiness ? (
              <>
                <p>
                  {readiness.localReady
                    ? 'Локальная настройка подтверждена, не доступность провайдера.'
                    : 'Для генерации требуется настройка оператора.'}
                </p>
                <ul>
                  {readiness.blockers.map((blocker) => (
                    <li key={blocker}>{readinessMessages[blocker]}</li>
                  ))}
                </ul>
                <p>
                  Генерация не проверена. Локальная настройка не подтверждает успешный вызов. Новый запрос
                  отправляется только кнопкой «Отправить вопрос»; ключи в интерфейсе не принимаются.
                </p>
              </>
            ) : (
              <p>
                Готовность генерации неизвестна. Историю можно читать независимо; новая отправка запрещена до
                подтверждения настроек.
              </p>
            )}
          </section>
        ) : null}
        {snapshot && context ? (
          <>
            {status.profile === PUBLIC_IMAGE_PROFILE ? (
              <div aria-label="Границы отчёта публичного образа в чате">
                <p>
                  Весь сохранённый отчёт:{' '}
                  {status.identifierCounts
                    ? `находок всего: ${identifierCountsTotal(status.identifierCounts)}; CVE: ${status.identifierCounts.cve}; Debian TEMP: ${status.identifierCounts.debianTemp}; Debian DLA: ${status.identifierCounts.debianDla ?? 0}`
                    : 'число находок и их распределение по типам идентификаторов неизвестно'}
                  . Debian TEMP и бюллетени Debian DLA — не CVE.
                </p>
                <p>
                  Покрытие уязвимостей: {coverageLabel(status.perCheck?.vuln?.outcome)}; ОС:{' '}
                  {coverageLabel(status.perCheck?.vuln?.os?.outcome)}; Node.js:{' '}
                  {coverageLabel(status.perCheck?.vuln?.node?.outcome)}
                  {status.perCheck?.vuln?.node?.outcome === 'unsupported'
                    ? ` · ${coverageReason(status.perCheck.vuln.node.reason)}`
                    : ''}
                  . Непроверенное не означает ноль; выполненная проверка не гарантирует безопасность.
                </p>
              </div>
            ) : null}
            <dl className="scan-a1__facts">
              <div>
                <dt>Привязка</dt>
                <dd>
                  {context.scanId} · {context.digest} · {context.platform} · отчёт {context.reportVersion}
                </dd>
              </div>
              <div>
                <dt>История</dt>
                <dd>
                  Владелец + скан · поколение {context.epoch} · ревизия {context.revision}
                </dd>
              </div>
            </dl>
            <p>
              История хранится на сервере до отдельно разрешённой операции оператора, без автоматического
              срока удаления. Кэш содержит контекст, не ответы; экономия вызовов провайдера не заявлена.
            </p>
            {context.disclosure ? (
              <>
                {context.disclosure.provider === 'OpenRouter' ? (
                  <>
                    <p>
                      OpenRouter · {context.disclosure.model} · {context.disclosure.providers.join(', ')} ·
                      регион не ограничен.
                    </p>
                    <p>
                      Только бесплатный профиль, все ценовые пределы равны нулю, без платной замены и
                      автоматических повторов. Текущий предел ответа — 2048 токенов; это не фактический счёт.
                    </p>
                  </>
                ) : (
                  <p>{context.disclosure.provider} · {context.disclosure.model}. Платный ответ, оценка сервера — не счёт.</p>
                )}
                <p>
                  {context.disclosure.retention === 'unknown'
                    ? 'Условия хранения и обучения у стороннего ModuleAPI неизвестны; отсутствие обучения и хранения не подтверждено, это не проверенный ZDR'
                    : context.disclosure.retention === 'no-storage'
                      ? 'Провайдер декларирует отсутствие хранения и обучения'
                      : 'Провайдер декларирует отсутствие обучения (no-training); отсутствие хранения не заявлено, это не ZDR; запросы могут сохраняться'}
                  ; декларация и одобрение оператора не доказывают соблюдение. Передаются очищенный вопрос,
                  все пользовательские сообщения и решения, выбранные находки и полное покрытие, без исходных
                  свидетельств.
                </p>
                <small>Политика чата {context.policyVersion}</small>
              </>
            ) : (
              <p>
                Генерация чата выключена; подтверждённая история и ручные решения не требуют вызова модели.
              </p>
            )}

            <section aria-label="Квоты чата">
              <h4>Использование</h4>
              {snapshot.usage?.available && usageMatchesDisclosure(snapshot.usage, context.disclosure) ? (
                <>
                  <p>
                    Окно {new Date(snapshot.usage.window.start).toISOString()} —{' '}
                    {new Date(snapshot.usage.window.end).toISOString()}
                  </p>
                  {(['user', 'scan'] as const).map((scope) =>
                    snapshot.usage?.available ? (
                      <p key={scope}>
                        {scope === 'user' ? 'Владелец' : 'Скан'}: остаток входных токенов{' '}
                        {snapshot.usage[scope].remaining.input}, выходных токенов{' '}
                        {snapshot.usage[scope].remaining.output}; использовано{' '}
                        {snapshot.usage[scope].used.input}/{snapshot.usage[scope].used.output}, удержано{' '}
                        {snapshot.usage[scope].held.input}/{snapshot.usage[scope].held.output}, перенесено{' '}
                        {snapshot.usage[scope].carried.input}/{snapshot.usage[scope].carried.output}; учтённая
                        стоимость в миллионных долях доллара: {snapshot.usage[scope].used.costMicros}.{' '}
                        Денежный остаток:{' '}
                        {snapshot.usage[scope].remaining.costMicros === null
                          ? 'без локального денежного лимита; платно, оценка не счёт'
                          : `${snapshot.usage[scope].remaining.costMicros} микро-USD`}
                        . Резерв стоимости: {snapshot.usage[scope].held.costMicros}; перенос:{' '}
                        {snapshot.usage[scope].carried.costMicros}.
                        {snapshot.usage[scope].exhausted
                          ? ' Квота исчерпана.'
                          : snapshot.usage[scope].warning
                            ? ' Приближается лимит.'
                            : ''}
                      </p>
                    ) : null,
                  )}
                  <p>
                    Допуск запроса неизвестен до точного вопроса и полного запроса. Остаток не гарантирует
                    допуск.
                  </p>
                </>
              ) : (
                <p>
                  Учёт недоступен, не ноль и не разрешение на генерацию. Сервер проверит квоты при отправке.
                </p>
              )}
              {receipt ? (
                <p>
                  Последний ответ: входных токенов {receipt.input}, выходных токенов {receipt.output},
                  учтённая стоимость в миллионных долях доллара: {receipt.costMicros}.{' '}
                  {receipt.source === 'server-estimated-configured-rates-not-invoice' ||
                                    receipt.source === 'moduleapi-server-estimated-configured-rates-not-invoice'
                    ? 'Оценка сервера по настроенным ставкам, не счёт провайдера.'
                    : 'Проверенное сервером сообщение провайдера, не счёт.'}
                </p>
              ) : null}
            </section>

            {snapshot.history.decisions.map((entry) => (
              <article key={entry.id}>
                <h5>Решение пользователя · не вывод сканера</h5>
                <p style={{ whiteSpace: 'pre-wrap' }}>{entry.text}</p>
                <SourceList sources={entry.sources} current={context} prefix={`decision-${entry.id}`}
                                  onNavigate={onNavigateSource ? category => current() && !pending && onNavigateSource(category) : undefined}
                                  disabled={pending} />
              </article>
            ))}
            <fieldset
              className="scan-a1__compose"
              disabled={!available}
              style={{ minWidth: 0, maxWidth: '100%' }}
            >
              <legend>Сохранить решение без вызова модели</legend>
              <label>
                Текст решения
                <textarea
                  value={decision}
                  aria-describedby={`scan-chat-decision-help scan-chat-decision-count${decisionInvalid ? ' scan-chat-decision-error' : ''}`}
                  aria-invalid={decisionInvalid}
                  rows={3}
                  onChange={(e) => setDecision(e.target.value)}
                  style={{ width: '100%' }}
                />
              </label>
              <small id="scan-chat-decision-help">
                Обычный текст без ссылок, разметки, секретов и служебных символов; до 2048 байт UTF-8.
                Выберите до 32 источников текущего отчёта (можно без источников).
              </small>
              <p id="scan-chat-decision-count">
                {utf8Bytes(decision)} / {SCAN_CHAT_INPUT_BYTE_LIMIT} байт UTF-8
              </p>
              <p id="scan-chat-decision-error" role="status" aria-live="polite" aria-atomic="true">
                {decisionInvalid ? decisionFeedback : null}
              </p>
              <details>
                <summary>Основания решения</summary>
                {snapshot.sources.map((source) => (
                  <label key={source.findingId} style={{ display: 'block', overflowWrap: 'anywhere', minWidth: 0 }}>
                    <input
                      type="checkbox"
                      checked={selectedIds.includes(source.findingId)}
                      disabled={!selectedIds.includes(source.findingId) && selectedIds.length >= 32}
                      onChange={(e) => {
                        setSelectedIds((ids) =>
                          e.target.checked
                            ? [...ids, source.findingId]
                            : ids.filter((id) => id !== source.findingId),
                        );
                      }}
                    />
                    {sourceLabel(source.label)} · {source.findingId}
                  </label>
                ))}
              </details>
              <Button
                type="button"
                disabled={!available || !validChatText(decision)}
                aria-describedby={`scan-chat-decision-help scan-chat-decision-count${decisionInvalid ? ' scan-chat-decision-error' : ''}`}
                onClick={() => mutate('decision')}
              >
                Сохранить решение
              </Button>
            </fieldset>
          </>
        ) : null}
      </details>
    </section>
  );
}
