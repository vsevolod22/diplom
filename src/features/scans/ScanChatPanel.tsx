import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';
import { scanSession, subscribeScanSession } from '@/shared/api/auth/scanSession';
import {
  ChatError,
  chatErrorMessage,
  createChatClient,
  type ChatClient,
} from '@/shared/api/scans/llmChatClient';
import {
  chatContextFence,
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
import type { LlmUsage } from '@/shared/api/scans/llmUsageClient';
import { utf8Bytes } from '@/shared/api/scans/vulnAdvisory';
import { PUBLIC_IMAGE_PROFILE } from '@/shared/api/scans/publicImageProfile';
import { isDebianTempId } from '@/shared/api/scans/publicVulnerabilityIdentifiers';
import { Alert, Button } from '@/shared/ui/scan-primitives';
import { SafeMarkdown } from './safeMarkdown';

type Props = { status: ScanStatus; transport: ScanTransport; client?: ChatClient };
type Snapshot = {
  context: ChatContext;
  history: ChatHistory;
  usage: LlmUsage | null;
  sources: SummarySource[];
};
const readinessMessages = {
  'configuration-required': 'Требуется настройка политики генерации оператором.',
  'public-key-required':
    'Серверный ключ не настроен или отсутствует. Настройка — только оператором; не вводите ключ в чат.',
  'public-key-unsafe': 'Метаданные серверного ключа не прошли проверку безопасности. Обратитесь к оператору.',
  'quota-store-unavailable': 'Хранилище квоты недоступно. Это не нулевой расход и не разрешение на отправку.',
  'history-store-unavailable': 'Хранилище истории недоступно; генерация заблокирована.',
  'provider-profile-unavailable':
    'Профиль провайдера недоступен в проверенном каталоге. Автоматической замены модели нет.',
};
function readinessMatchesContext(ready: ChatReadiness, context: ChatContext) {
  if (!sameChatBinding(ready, context)) return false;
  if (!context.enabled) return ready.provider.status === 'unverified-profile';
  return (
    'model' in ready.provider &&
    ready.provider.model === context.disclosure?.model &&
    ready.provider.endpoint === context.disclosure?.providers[0]
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
  // A→B→A and same-owner reauthentication create new local state, not reusable old requests/consent.
  return <ChatScope key={`${session}:${JSON.stringify(props.status)}`} {...props} />;
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
    <>
      <p>
        Основания ответа/решения:{' '}
        {sources.map((source) => (
          <a key={source.finding.findingId} href={`#${prefix}-${source.finding.findingId}`}>
            Находка {source.finding.findingId}{' '}
          </a>
        ))}
      </p>
      <ul>
        {sources.map((source) => (
          <li key={source.finding.findingId} id={`${prefix}-${source.finding.findingId}`} tabIndex={-1}>
            <strong>
              {checkLabels[source.finding.check]} · {severityLabels[source.finding.severity] ?? 'Неизвестна'}
            </strong>{' '}
            · {source.finding.findingId}
            {source.finding.check === 'vuln' ? (
              <p>
                {source.finding.cveId} ·{' '}
                {isDebianTempId(source.finding.cveId) ? 'Уведомление Debian (не CVE)' : 'CVE'}
              </p>
            ) : null}
            <p>
              {sameChatBinding(source, current)
                ? 'Источник текущего отчёта, проверен по результатам сканирования.'
                : 'Исторический источник — не разрешён как находка текущего отчёта.'}
            </p>
            <small>
              Отчёт {source.reportVersion} · {source.digest} · {source.platform}
            </small>
          </li>
        ))}
      </ul>
    </>
  );
}
function ChatScope({ status, transport, client: providedClient }: Props) {
  const client = useMemo(() => providedClient ?? createChatClient(scanSession()), [providedClient]);
  const [opened, setOpened] = useState(false);
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
        context.identifierCounts?.debianTemp !== status.identifierCounts?.debianTemp)
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
    action: (signal: AbortSignal, publish: (action: () => void) => void) => Promise<void>,
  ) {
    if (request.current || !client.current()) return;
    const controller = new AbortController();
    request.current = controller;
    const version = ++generation.current;
    setPending(true);
    setReceipt(null);
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, 45_000);
    const live = () => generation.current === version && !controller.signal.aborted && client.current();
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
      if (generation.current === version && client.current()) {
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
    if (request.current || !client.current()) return;
    setOperation('read');
    setReadiness(null);
    setOpened(true);
    setSnapshot(null);
    setSelectedIds([]);
    void operate(async (signal, publish) => {
      const ready = publicReport ? await readReadiness(signal) : null;
      publish(() => setReadiness(ready));
      const next = await readSnapshot(signal);
      if (ready && !readinessMatchesContext(ready, next.context)) {
        publish(() => setReadiness(null));
        throw new ChatError('STALE');
      }
      publish(() => setSnapshot(next));
    });
  }
  useEffect(() => {
    const unsubscribe = subscribeScanSession(() => {
      invalidate();
      setSnapshot(null);
      setReadiness(null);
      setReceipt(null);
      setSelectedIds([]);
      setPending(false);
    });
    return () => {
      invalidate();
      unsubscribe();
    };
    // Scope is keyed by the complete status and session; no generation POST is ever an effect.
  }, [client]);

  function mutate(kind: 'chat' | 'decision') {
    const accepted = snapshot;
    if (
      !accepted ||
      pending ||
      accepted.context.pending ||
      !client.current() ||
      (kind === 'chat' && (!accepted.context.enabled || (publicReport && !readiness?.localReady)))
    )
      return;
    const value = kind === 'chat' ? question : decision;
    if (!validChatText(value)) {
      setMessage(chatErrorMessage(new ChatError('INPUT')));
      return;
    }
    if (request.current) return;
    setOperation(kind);
    setMessage('');
    const mutationId = crypto.randomUUID();
    const ids = [...selectedIds];
    void operate(async (signal, publish) => {
      if (kind === 'chat' && publicReport) {
        const ready = await readReadiness(signal);
        publish(() => setReadiness(ready));
        if (!ready?.localReady) throw new ChatError('LLM_CONFIGURATION_UNAVAILABLE');
        if (!readinessMatchesContext(ready, accepted.context)) throw new ChatError('STALE');
      }
      const before = await client.context(status.scanId, signal);
      checkStatus(before);
      if (
        chatContextFence(before) !== chatContextFence(accepted.context) ||
        signal.aborted ||
        !client.current()
      )
        throw new ChatError('STALE');
      const result =
        kind === 'chat'
          ? await client.chat(before, value, mutationId, signal)
          : await client.decision(before, value, ids, mutationId, signal);
      if (signal.aborted || !client.current()) throw new ChatError('STALE');
      if ('reply' in result && !verifiedChatSources(result.reply, accepted.sources))
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
        if ('duplicate' in result)
          setMessage(
            'Повтор уже зарегистрирован. Прочитана долговечная история; новая генерация не запущена.',
          );
      });
    });
  }
  const context = snapshot?.context;
  const available = !!snapshot && !pending && !context?.pending && client.current();
  const generationAllowed = !!context?.enabled && (!publicReport || readiness?.localReady === true);
  const connection = pending
    ? operation === 'read'
      ? 'Подключение: читаем условия, источники и историю отчёта…'
      : operation === 'chat'
        ? 'Ожидаем проверенный полный ответ. Частичный текст не показывается.'
        : 'Сохраняем решение без вызова провайдера…'
    : snapshot
      ? context?.pending
        ? 'На сервере уже выполняется запрос. Новая отправка заблокирована; обновите историю вручную позже.'
        : publicReport && !readiness?.localReady
          ? 'История подключена. Готовность генерации не подтверждена; проверьте настройку ниже.'
          : context?.enabled
            ? 'История подключена. Чат разрешён сервером; доступность провайдера проверяется только при отправке.'
            : 'История подключена. Генерация выключена сервером; историю и решения можно читать без модели.'
      : opened
        ? 'Подключение не подтверждено. Повторите чтение истории перед новым запросом.'
        : 'Чат не подключён. Открытие читает условия и историю, но не вызывает провайдера.';
  return (
    <section
      id="scan-report-chat"
      className="scan-a1__chat"
      tabIndex={-1}
      aria-label="Чат по отчёту"
      aria-busy={pending}
      style={{ minWidth: 0, maxWidth: '100%', overflowWrap: 'anywhere' }}
    >
      <h3>Чат по отчёту · только вручную</h3>
      <p role="status" aria-label="Состояние подключения чата" aria-live="polite">
        {connection}
      </p>
      <p>
        Находки и покрытие — результаты сканирования в основном отчёте. Ответ ИИ — отдельная интерпретация:
        предположения и рекомендации требуют проверки по источникам. Ошибка ИИ не меняет отчёт.
      </p>
      <p>
        Провайдер возвращает полный ответ, а не поток токенов. Показываем его только после завершения
        передачи, проверки учёта расхода, ссылок на находки и совпадения с сохранённой историей. Промежуточный
        текст не показываем.
      </p>
      <Button type="button" variant="secondary" disabled={pending || !client.current()} onClick={refresh}>
        {opened ? 'Обновить историю и условия чата' : 'Открыть чат'}
      </Button>
      {pending ? (
        <>
          <p>
            Отмена останавливает только ожидание в браузере, не гарантирует отмену на сервере или возврат
            квоты.
          </p>
          <Button type="button" variant="secondary" onClick={cancel}>
            Отменить ожидание чата
          </Button>
        </>
      ) : null}
      {publicReport && opened ? (
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
                Генерация не проверена. Каталог не подтверждает успешный вызов. Новый запрос отправляется
                только кнопкой «Отправить вопрос»; ключи в интерфейсе не принимаются.
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
      {message ? (
        <Alert role="alert" tone="warning">
          {message}
        </Alert>
      ) : null}
      {snapshot && context ? (
        <>
          {status.profile === PUBLIC_IMAGE_PROFILE ? (
            <div aria-label="Границы отчёта публичного образа в чате">
              <p>
                Весь сохранённый отчёт:{' '}
                {status.identifierCounts
                  ? `CVE: ${status.identifierCounts.cve}; уведомления Debian: ${status.identifierCounts.debianTemp}`
                  : 'число CVE и уведомлений Debian неизвестно'}
                . Debian TEMP — не CVE.
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
            История хранится на сервере до отдельно разрешённой операции оператора, без автоматического срока
            удаления. Кэш содержит контекст, не ответы; экономия вызовов провайдера не заявлена.
          </p>
          {context.disclosure ? (
            <>
              <p>
                OpenRouter · {context.disclosure.model} · {context.disclosure.providers.join(', ')} · регион
                не ограничен.
              </p>
              <p>
                Только бесплатный профиль, все ценовые пределы равны нулю, без платной замены и автоматических
                повторов. Текущий предел ответа — 2048 токенов; это не фактический счёт.
              </p>
              <p>
                Провайдер декларирует отсутствие хранения и обучения; декларация и одобрение оператора не
                доказывают соблюдение. Передаются очищенный вопрос, все пользовательские сообщения и решения,
                выбранные находки и полное покрытие, без исходных свидетельств.
              </p>
              <small>Политика чата {context.policyVersion}</small>
            </>
          ) : (
            <p>Генерация чата выключена; подтверждённая история и ручные решения не требуют вызова модели.</p>
          )}
          {context.pending ? (
            <p role="status">
              Сервер уже обрабатывает запрос этого владельца и scan. Обновите историю вручную позже; отмена
              ожидания не удаляет серверную историю.
            </p>
          ) : null}
          <section aria-label="Квоты чата">
            <h4>Использование</h4>
            {snapshot.usage?.available ? (
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
                      стоимость в миллионных долях доллара: {snapshot.usage[scope].used.costMicros}.
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
                Последний ответ: входных токенов {receipt.input}, выходных токенов {receipt.output}, учтённая
                стоимость в миллионных долях доллара: {receipt.costMicros}. Проверенное сервером сообщение
                провайдера, не счёт.
              </p>
            ) : null}
          </section>
          {snapshot.history.turns.length ? (
            <p>
              Продолжите чат новым вопросом. История входит в следующий запрос только при новом нажатии
              «Отправить вопрос».
            </p>
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
                aria-describedby="scan-chat-input-help"
                aria-invalid={question.length > 0 && !validChatText(question)}
                value={question}
                disabled={pending}
                rows={3}
                onChange={(e) => setQuestion(e.target.value)}
                style={{ width: '100%' }}
              />
            </label>
            <small id="scan-chat-input-help">
              {utf8Bytes(question)} / 2048 UTF-8 байт. Без ссылок, секретов и исходных свидетельств.
            </small>
            <p id="scan-chat-send-help">
              Нажимая «Отправить вопрос», вы разрешаете один запрос: очищенный вопрос, историю, решения,
              выбранные находки и покрытие — указанным выше модели и провайдеру OpenRouter. Только бесплатный
              профиль, без платной замены и автоповтора. Условия проверяются заново перед отправкой.
            </p>
            <Button
              type="submit"
              aria-describedby="scan-chat-send-help"
              disabled={!available || !generationAllowed || !validChatText(question)}
            >
              Отправить вопрос
            </Button>
          </form>
          <h4>Подтверждённая история</h4>
          {!snapshot.history.turns.length && !snapshot.history.decisions.length ? (
            <p>История пока пуста. Это не означает, что отчёт безопасен.</p>
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
                  <h5>Ответ ИИ · требует проверки</h5>
                  <SafeMarkdown text={turn.reply.text} />
                  <SourceList sources={turn.reply.sources} current={context} prefix={`chat-${turn.id}`} />
                </>
              ) : (
                <>
                  <p>Полного подтверждённого ответа нет. Автоматический повтор не выполняется.</p>
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
                rows={3}
                onChange={(e) => setDecision(e.target.value)}
                style={{ width: '100%' }}
              />
            </label>
            <small>
              {utf8Bytes(decision)} / 2048 UTF-8 байт. Выберите до 32 источников текущего отчёта (можно без
              источников).
            </small>
            <details>
              <summary>Основания решения</summary>
              {snapshot.sources.map((source) => (
                <label key={source.findingId} style={{ display: 'block' }}>
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
              onClick={() => mutate('decision')}
            >
              Сохранить решение
            </Button>
          </fieldset>
        </>
      ) : null}
    </section>
  );
}
