import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';
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
import { LlmFindingDetails } from './LlmFindingDetails';
import { utf8Bytes } from '@/shared/api/scans/vulnAdvisory';
import { PUBLIC_IMAGE_PROFILE } from '@/shared/api/scans/publicImageProfile';
import { identifierLabel, identifierCountsTotal } from '@/shared/api/scans/publicVulnerabilityIdentifiers';
import { Alert, Button } from '@/shared/ui/scan-primitives';
import { SafeMarkdown } from './safeMarkdown';
import { SCAN_CHAT_INPUT_BYTE_LIMIT, scanChatInputFeedback } from './scanChatInputFeedback';

type Props = { status: ScanStatus; transport: ScanTransport; client?: ChatClient };
type Snapshot = {
  context: ChatContext;
  history: ChatHistory;
  usage: LlmUsage | null;
  sources: SummarySource[];
};
const readinessMessages = {
  'configuration-required': 'Чат не настроен. Обратитесь к оператору.',
  'environment-key-required': 'Требуется серверная настройка OpenAI. Не вводите ключ в интерфейс.',
  'accounting-configuration-required': 'Учёт стоимости OpenAI не настроен. Обратитесь к оператору.',
  'public-key-required': 'Чат не настроен. Обратитесь к оператору; не вводите ключи в чат.',
  'public-key-unsafe': 'Настройки чата не прошли проверку безопасности. Обратитесь к оператору.',
  'quota-store-unavailable': 'Не удалось проверить лимиты. Попробуйте обновить историю позже.',
  'history-store-unavailable': 'История временно недоступна. Попробуйте позже.',
  'provider-profile-unavailable': 'Сервис ответов недоступен. Обратитесь к оператору.',
};
function chatErrorMessage(error: unknown) {
  const code = error instanceof ChatError ? error.code : '';
  if (code === 'SESSION') return 'Сессия изменилась или истекла. Войдите заново.';
  if (code === 'ACCESS') return 'Доступ к чату этого отчёта не подтверждён. Проверьте аккаунт.';
  if (['STALE', 'LLM_STALE_REPORT', 'LLM_STALE_POLICY', 'LLM_HISTORY_CONFLICT'].includes(code))
    return 'Данные отчёта или условия чата изменились. Обновите историю перед отправкой.';
  if (['TIMEOUT', 'ABORTED', 'LLM_REQUEST_ABORTED', 'LLM_PROVIDER_TIMEOUT'].includes(code))
    return 'Ожидание остановлено. Ответ ещё может сохраниться — обновите историю перед повтором.';
  if (['LLM_QUOTA_EXCEEDED', 'LLM_BUDGET_EXCEEDED', 'LLM_CAPACITY'].includes(code))
    return 'Достигнут лимит запросов. Попробуйте позже.';
  if (['LLM_CONTEXT_LIMIT', 'LLM_HISTORY_CAPACITY'].includes(code))
    return 'В чате слишком много данных для нового ответа. История сохранена.';
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
    return context.disclosure?.provider === 'OpenAI' && ready.provider.model === context.disclosure.model;
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
}: {
  sources: ChatSource[];
  current: ChatContext;
  prefix: string;
}) {
  return (
    <details>
      <summary>Источники ({sources.length})</summary>
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
            <LlmFindingDetails finding={source.finding} />
            <p>
              {sameChatBinding(source, current)
                ? 'Источник текущего отчёта, проверен по результатам сканирования.'
                : 'Исторический источник — не разрешён как находка текущего отчёта.'}
            </p>
          </li>
        ))}
      </ul>
    </details>
  );
}
function ChatScope({
  status,
  transport,
  client: providedClient,
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
  const questionInput = useRef<HTMLTextAreaElement | null>(null);
  const [operation, setOperation] = useState<'read' | 'chat' | 'decision'>('read');

  function invalidate() {
    generation.current++;
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
    setMessage(chatErrorMessage(new ChatError('ABORTED')));
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
        ['SESSION', 'ACCESS', 'REPORT_UNAVAILABLE', 'STALE', 'ABORTED', 'TIMEOUT'].includes(error.code)
      )
        throw error;
      // A malformed/offline readiness is unknown, never a generation permission; history may still work.
      return null;
    }
  }
  async function readSnapshot(signal: AbortSignal): Promise<Snapshot> {
    const context = await client.context(status.scanId, signal);
    checkStatus(context);
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
      collectSummarySources(transport, status, signal),
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
    if (chatContextFence(after) !== chatContextFence(context)) throw new ChatError('STALE');
    return { context, history, usage, sources };
  }
  async function operate(
    timeoutMs: number,
    action: (signal: AbortSignal, publish: (action: () => void) => void) => Promise<void>,
  ) {
    if (request.current || !current()) return;
    const controller = new AbortController();
    request.current = controller;
    const version = ++generation.current;
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
        setSelectedIds([]);
        setMessage(chatErrorMessage(error));
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

  function refresh() {
    if (request.current || !current()) return;
    setOperation('read');
    setReadiness(null);

    setSnapshot(null);
    setSelectedIds([]);
    void operate(45_000, async (signal, publish) => {
      // Keep setup diagnostics available even if the history-backed context cannot be read.
      let ready = publicReport ? await readReadiness(signal) : null;
      publish(() => setReadiness(ready));
      const next = await readSnapshot(signal);
      if (!publicReport && next.context.disclosure?.provider === 'OpenAI') {
        ready = await readReadiness(signal);
        publish(() => setReadiness(ready));
      }
      if (ready && !readinessMatchesContext(ready, next.context)) {
        publish(() => setReadiness(null));
        throw new ChatError('STALE');
      }
      publish(() => setSnapshot(next));
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
          ((publicReport || accepted.context.disclosure?.provider === 'OpenAI') && !readiness?.localReady)))
    )
      return;
    const value = kind === 'chat' ? question : decision;
    if (!validChatText(value)) {
      setMessage(scanChatInputFeedback(value) ?? chatErrorMessage(new ChatError('INPUT')));
      return;
    }
    if (request.current) return;
    setOperation(kind);
    setMessage('');
    const mutationId = crypto.randomUUID();
    const ids = [...selectedIds];
    void operate(kind === 'chat' ? 120_000 : 45_000, async (signal, publish) => {
      if (kind === 'chat' && (publicReport || accepted.context.disclosure?.provider === 'OpenAI')) {
        const ready = await readReadiness(signal);
        publish(() => setReadiness(ready));
        if (!ready?.localReady) throw new ChatError('LLM_CONFIGURATION_UNAVAILABLE');
        if (!readinessMatchesContext(ready, accepted.context)) throw new ChatError('STALE');
      }
      const before = await client.context(status.scanId, signal);
      checkStatus(before);
      if (chatContextFence(before) !== chatContextFence(accepted.context) || signal.aborted || !current())
        throw new ChatError('STALE');
      const result =
        kind === 'chat'
          ? await client.chat(before, value, mutationId, signal)
          : await client.decision(before, value, ids, mutationId, signal);
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
        setSelectedIds([]);
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
  const needsReadiness = publicReport || context?.disclosure?.provider === 'OpenAI';
  const generationAllowed = !!context?.enabled && (!needsReadiness || readiness?.localReady === true);
  const connection = pending
    ? operation === 'read'
      ? 'Загружаем историю…'
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
          <p>Отмена остановит ожидание, но запрос ещё может завершиться.</p>
          <Button type="button" variant="secondary" onClick={cancel}>
            Отменить ожидание чата
          </Button>
        </>
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
          {snapshot.history.turns.map((turn) => (
            <article key={turn.id}>
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
              <p style={{ whiteSpace: 'pre-wrap' }}>{turn.question}</p>
              {turn.state === 'completed' ? (
                <>
                  <h5>Ответ · проверьте по источникам</h5>
                  <SafeMarkdown text={turn.reply.text} />
                  <SourceList sources={turn.reply.sources} current={context} prefix={`chat-${turn.id}`} />
                </>
              ) : (
                <>
                  <p>Ответ пока не получен.</p>
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
        </>
      ) : null}
      <form
        className="scan-a1__compose"
        aria-label="Отправка вопроса по отчёту"
        onSubmit={(event) => {
          event.preventDefault();
          mutate('chat');
        }}
      >
        <label>
          Вопрос чату
          <textarea
            ref={questionInput}
            aria-describedby={`scan-chat-input-help scan-chat-input-count${questionInvalid ? ' scan-chat-input-error' : ''}`}
            aria-invalid={questionInvalid}
            value={question}
            disabled={pending && operation !== 'read'}
            rows={3}
            onChange={(event) => setQuestion(event.target.value)}
            style={{ width: '100%' }}
          />
        </label>
        <small id="scan-chat-input-help">
          Короткий вопрос без ссылок, разметки, секретов и служебных символов. Лимит — 2048 байт UTF-8, не символов:
          русская буква обычно занимает 2 байта. Например: «С каких находок начать?»
        </small>
        <p id="scan-chat-input-count">
          {utf8Bytes(question)} / {SCAN_CHAT_INPUT_BYTE_LIMIT} байт UTF-8
        </p>
        <p id="scan-chat-input-error" role="status" aria-live="polite" aria-atomic="true">
          {questionInvalid ? questionFeedback : null}
        </p>
        {context?.disclosure?.provider === 'OpenAI' ? (
          <OpenAiDisclosure disclosure={context.disclosure} chat />
        ) : null}
        <p id="scan-chat-send-help">
          Нажимая «Отправить вопрос», вы разрешаете{' '}
          {context?.disclosure?.provider === 'OpenAI'
            ? 'платный запрос OpenAI на показанных условиях текущей политики и передачу вопроса, находок и истории. Это отдельное согласие, не прежний бесплатный opt-in.'
            : 'передать внешнему ИИ вопрос и контекст отчёта, включая историю чата. Запрет обучения не гарантирует отсутствие хранения.'}
        </p>
        <Button
          type="submit"
          aria-describedby={`scan-chat-send-help scan-chat-input-help scan-chat-input-count scan-chat-connection${questionInvalid ? ' scan-chat-input-error' : ''}`}
          disabled={!available || !generationAllowed || !validChatText(question)}
        >
          Отправить вопрос
        </Button>
      </form>
      <details>
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
                  <p>OpenAI · {context.disclosure.model}. Платный ответ, оценка сервера — не счёт.</p>
                )}
                <p>
                  {context.disclosure.retention === 'no-storage'
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
                  {receipt.source === 'server-estimated-configured-rates-not-invoice'
                    ? 'Оценка сервера по настроенным ставкам, не счёт провайдера.'
                    : 'Проверенное сервером сообщение провайдера, не счёт.'}
                </p>
              ) : null}
            </section>

            {snapshot.history.decisions.map((entry) => (
              <article key={entry.id}>
                <h5>Решение пользователя · не вывод сканера</h5>
                <p style={{ whiteSpace: 'pre-wrap' }}>{entry.text}</p>
                <SourceList sources={entry.sources} current={context} prefix={`decision-${entry.id}`} />
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
