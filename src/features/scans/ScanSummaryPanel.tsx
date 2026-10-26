import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';
import {
  REPORT_AUTOMATION_REVISION,
  subscribeReportPreferences,
  useReportPreferences,
} from '@/shared/api/preferences/reportPreferences';
import { createUsageClient } from '@/shared/api/scans/llmUsageClient';
import {
  allowAutomationDisclosure,
  reportPreferencesCurrent,
  ReportAutomationError,
  reportAutomationKey,
  reportAutomationMessage,
  runReportAutomation,
  runReportMetadata,
} from '@/shared/api/scans/reportAutomation';
import { Sparkles } from 'lucide-react';
import { scanSession, subscribeScanSession } from '@/shared/api/auth/scanSession';
import {
  collectSummarySources,
  contextFence,
  createSummaryClient,
  matchesSummaryTuple,
  SummaryError,
  summaryErrorMessage,
  verifiedSummarySources,
  type SummaryClient,
  type SummaryContext,
  type SummaryReply,
  type SummarySource,
} from '@/shared/api/scans/llmSummaryClient';
import type { ScanStatus, ScanTransport } from '@/shared/api/scans/scanTransport';
import { PUBLIC_IMAGE_PROFILE } from '@/shared/api/scans/publicImageProfile';
import { Alert, Button } from '@/shared/ui/scan-primitives';
import { LlmUsagePanel } from './LlmUsagePanel';
import { ScanChatPanel } from './ScanChatPanel';

const sourceLabels: Record<string, string> = {
  Secrets: 'Секреты',
  CRITICAL: 'Критическая',
  HIGH: 'Высокая',
  MEDIUM: 'Средняя',
  LOW: 'Низкая',
  INFO: 'Информационная',
  UNKNOWN: 'Неизвестна',
  'Debian advisory (не CVE)': 'Уведомление Debian (не CVE)',
};
type Props = { status: ScanStatus; transport: ScanTransport; client?: SummaryClient };
const sessionKey = () => JSON.stringify(scanSession());
export function ScanSummaryPanel(props: Props) {
  const session = useSyncExternalStore(subscribeScanSession, sessionKey, sessionKey);
  const preferences = useReportPreferences();
  return (
    <SummaryScope
      key={JSON.stringify([session, props.status, preferences])}
      {...props}
      preferences={preferences}
    />
  );
}
function SummaryScope({
  status,
  transport,
  client: providedClient,
  preferences,
}: Props & { preferences: ReturnType<typeof useReportPreferences> }) {
  const client = useMemo<SummaryClient>(
    () => providedClient ?? createSummaryClient(scanSession()),
    [providedClient],
  );
  const current = () => client.current() && reportPreferencesCurrent(preferences);
  const automationCurrent = () => client.current() && reportPreferencesCurrent(preferences, 'summary');
  const [context, setContext] = useState<SummaryContext | null>(null);

  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState('');
  const [usageRefreshVersion, setUsageRefreshVersion] = useState(0);
  const [result, setResult] = useState<{
    reply: SummaryReply;
    sources: SummarySource[];
    recovered?: true;
  } | null>(null);
  const request = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const contextRef = useRef<SummaryContext | null>(null);

  const authorized = preferences.authorized && preferences.autoSummary;

  function invalidateRequest() {
    generation.current++;
    request.current?.abort();
    request.current = null;
  }
  function stop() {
    invalidateRequest();
    setPending(false);
    setResult(null);
  }
  function checkContext(next: SummaryContext) {
    if (next.scanId !== status.scanId || next.digest !== status.digest || next.platform !== status.platform)
      throw new SummaryError('STALE');
  }
  async function refresh(automate = false, retry = false) {
    if (request.current || !current()) return;
    const controller = new AbortController();
    request.current = controller;
    const version = ++generation.current;
    setPending(true);
    let timedOut = false;
    const deadline = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, 45_000);
    const stopped = new Promise<never>((_, reject) =>
      controller.signal.addEventListener(
        'abort',
        () => reject(new SummaryError(timedOut ? 'TIMEOUT' : 'ABORTED')),
        { once: true },
      ),
    );
    let accepted: SummaryContext | null = null;
    let recovered = false;
    const live = () => generation.current === version && !controller.signal.aborted && current();
    try {
      const next = await Promise.race([
        runReportMetadata(JSON.stringify(['summary-context', status]), controller.signal, (signal) =>
          client.context(status.scanId, signal),
        ),
        stopped,
      ]);
      checkContext(next);
      if (generation.current !== version || controller.signal.aborted || !current()) return;
      if (contextRef.current && contextFence(next) !== contextFence(contextRef.current)) setResult(null);
      contextRef.current = next;
      setContext(next);
      accepted = next;
      const existing = client.existing;
      if (existing && status.state === 'completed' && status.profile === PUBLIC_IMAGE_PROFILE) {
        // Recovery is a public-profile endpoint; the legacy proxy supports POST only.
        // Reading an owner's previous result needs no autoSummary opt-in or attempt marker.
        const value = await Promise.race([
          runReportMetadata(
            JSON.stringify(['summary-recovery', status, contextFence(next)]),
            controller.signal,
            async (signal) => {
              const reply = await existing(next, signal);
              if (signal.aborted || !client.current()) throw new SummaryError('STALE');
              if (reply === null) return null;
              if (!reply || !matchesSummaryTuple(reply, next)) throw new SummaryError('STALE');
              const sources = await collectSummarySources(transport, status, signal);
              const verified = verifiedSummarySources(reply, sources);
              if (signal.aborted || !client.current()) throw new SummaryError('STALE');
              const after = await client.context(status.scanId, signal);
              checkContext(after);
              if (contextFence(after) !== contextFence(next) || signal.aborted || !client.current())
                throw new SummaryError('STALE');
              return { reply, sources: verified };
            },
          ),
          stopped,
        ]);
        if (!live()) return;
        if (value) {
          setResult({ ...value, recovered: true });
          setMessage('');
          recovered = true;
        }
      }
    } catch (error) {
      accepted = null;
      if (generation.current !== version) return;
      contextRef.current = null;
      setContext(null);
      setResult(null);
      setMessage(summaryErrorMessage(error));
    } finally {
      clearTimeout(deadline);
      controller.abort();
      if (generation.current === version) {
        request.current = null;
        setPending(false);
      }
    }
    if (
      automate &&
      !recovered &&
      accepted &&
      generation.current === version &&
      authorized &&
      status.state === 'completed'
    )
      void generate(accepted, retry);
  }
  useEffect(() => {
    const unsubscribePreferences = subscribeReportPreferences(() => {
      if (reportPreferencesCurrent(preferences)) return;
      stop();
      contextRef.current = null;
      setContext(null);
      setMessage('Настройки изменились. Ожидание сводки остановлено; прежнее разрешение не используется.');
    });
    const unsubscribe = subscribeScanSession(() => {
      stop();
      contextRef.current = null;
      setContext(null);
      setMessage('Сессия изменилась. Сводка скрыта; войдите и откройте отчёт заново.');
    });
    void refresh(true);
    // Focus and reconnect never create generation intent or discard a verified cached reply.
    return () => {
      invalidateRequest();
      unsubscribe();
      unsubscribePreferences();
    };
    // The parent keys this panel by session, scan and complete status snapshot.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, status.scanId, preferences]);

  async function generate(accepted = contextRef.current, retry = false) {
    if (
      !authorized ||
      status.state !== 'completed' ||
      !accepted?.enabled ||
      !accepted.policyVersion ||
      !accepted.disclosure ||
      request.current ||
      !automationCurrent()
    )
      return;
    if (!allowAutomationDisclosure(accepted.disclosure, 'summary')) {
      setMessage(reportAutomationMessage(new ReportAutomationError('DISCLOSURE'))!);
      return;
    }
    const controller = new AbortController();
    const version = ++generation.current;
    request.current = controller;

    setPending(true);
    setResult(null);
    setMessage('');
    let timedOut = false;
    const deadline = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, 45_000);
    const stopped = new Promise<never>((_, reject) =>
      controller.signal.addEventListener(
        'abort',
        () => reject(new SummaryError(timedOut ? 'TIMEOUT' : 'ABORTED')),
        { once: true },
      ),
    );
    const operation = async () => {
      const before = await client.context(status.scanId, controller.signal);
      checkContext(before);
      if (contextFence(before) !== contextFence(accepted)) {
        if (generation.current === version && !controller.signal.aborted) {
          contextRef.current = before;
          setContext(before);
        }
        throw new SummaryError('STALE');
      }
      if (controller.signal.aborted || !current() || generation.current !== version)
        throw new SummaryError('STALE');
      const usage = await createUsageClient().get(before, controller.signal);
      if (controller.signal.aborted || !current() || generation.current !== version)
        throw new SummaryError('STALE');
      if (
        !usage.available ||
        !usage.integrationEnabled ||
        !usage.quotaEnabled ||
        usage.user.exhausted ||
        usage.scan.exhausted ||
        usage.reason === 'policy_fault' ||
        usage.admission.status === 'insufficient' ||
        usage.admission.status === 'policy_fault'
      )
        throw new SummaryError('LLM_QUOTA_EXCEEDED');
      if (!allowAutomationDisclosure(before.disclosure, 'summary'))
        throw new ReportAutomationError('DISCLOSURE');
      if (controller.signal.aborted || !automationCurrent() || generation.current !== version)
        throw new SummaryError('STALE');
      const reply = await client.summary(before, controller.signal);
      if (controller.signal.aborted || !current() || generation.current !== version)
        throw new SummaryError('STALE');
      const sources = await collectSummarySources(transport, status, controller.signal);
      const verified = verifiedSummarySources(reply, sources);
      if (controller.signal.aborted || !current() || generation.current !== version)
        throw new SummaryError('STALE');
      const after = await client.context(status.scanId, controller.signal);
      checkContext(after);
      if (contextFence(after) !== contextFence(accepted)) {
        if (generation.current === version && !controller.signal.aborted) {
          contextRef.current = after;
          setContext(after);
        }
        throw new SummaryError('STALE');
      }
      if (controller.signal.aborted || !current() || generation.current !== version)
        throw new SummaryError('STALE');
      return { reply, sources: verified, fence: contextFence(before) };
    };
    try {
      const key = reportAutomationKey(
        'summary',
        REPORT_AUTOMATION_REVISION,
        JSON.stringify([
          accepted.scanId,
          accepted.digest,
          accepted.platform,
          accepted.reportVersion,
          accepted.policyVersion,
        ]),
      );
      const value = await Promise.race([
        runReportAutomation(key, controller.signal, operation, retry),
        stopped,
      ]);
      // A cached reply still needs the exact disclosure and current authorization before publication.
      if (generation.current !== version || controller.signal.aborted || !current()) return;
      if (value.fence !== contextFence(accepted)) throw new SummaryError('STALE');
      const after = await Promise.race([
        runReportMetadata(JSON.stringify(['summary-context', status]), controller.signal, (signal) =>
          client.context(status.scanId, signal),
        ),
        stopped,
      ]);
      checkContext(after);
      if (contextFence(after) !== contextFence(accepted)) throw new SummaryError('STALE');
      if (!allowAutomationDisclosure(after.disclosure, 'summary'))
        throw new ReportAutomationError('DISCLOSURE');
      if (generation.current === version && !controller.signal.aborted && automationCurrent())
        setResult(value);
    } catch (error) {
      if (generation.current === version)
        setMessage(reportAutomationMessage(error) ?? summaryErrorMessage(error));
    } finally {
      clearTimeout(deadline);
      controller.abort();
      if (generation.current === version) {
        request.current = null;
        setPending(false);
        setUsageRefreshVersion((value) => value + 1);
      }
    }
  }
  const policy = context?.disclosure;
  return (
    <section className="scan-a1__ai" aria-labelledby="scan-a1-ai" aria-busy={pending}>
      <div>
        <p className="scan-a1__eyebrow">04 / ИИ-СВОДКА · НАСТРОЙКИ АККАУНТА</p>
        <h3 id="scan-a1-ai">
          <Sparkles size={24} aria-hidden="true" /> Сводка отчёта
        </h3>
        <p>
          Находки и покрытие — результаты сканирования в основном отчёте. Сводка ИИ — отдельная интерпретация:
          предположения и рекомендации требуют проверки по исходным находкам.
        </p>
        {policy ? (
          <dl className="scan-a1__facts">
            <div>
              <dt>Модель</dt>
              <dd>
                {policy.provider} · {policy.model}
              </dd>
            </div>
            <div>
              <dt>Маршрутизация</dt>
              <dd>{policy.providers.join(', ')} · регион не ограничен</dd>
            </div>
            <div>
              <dt>Стоимость</dt>
              <dd>
                {policy.freeOnly === true
                  ? 'Серверная политика: только бесплатный режим'
                  : policy.freeOnly === false
                    ? 'Бесплатный режим выключен'
                    : 'Бесплатный режим не подтверждён сервером'}{' '}
                · бюджет допуска {policy.requestBudgetUsd} USD/запрос; не фактический счёт и не
                пользовательская квота
              </dd>
            </div>
            <div>
              <dt>Данные</dt>
              <dd>Очищенные находки и покрытие проверок; без исходных свидетельств и учётных данных.</dd>
            </div>
            <div>
              <dt>Обработка</dt>
              <dd>
                {policy.retention === 'no-storage'
                  ? 'Без хранения и обучения (декларация провайдера)'
                  : 'Без обучения (декларация провайдера); отсутствие хранения не заявлено'}
                . Одобрение оператора и декларация не доказывают соблюдение провайдером.
              </dd>
            </div>
            <div>
              <dt>Привязка запроса</dt>
              <dd>
                Отчёт {context?.reportVersion} · политика {context?.policyVersion}
              </dd>
            </div>
          </dl>
        ) : (
          <p>
            {context && !context.enabled
              ? 'ИИ выключен или политика не настроена.'
              : 'Условия передачи пока не подтверждены.'}
          </p>
        )}
      </div>
      <div className="scan-a1__compose">
        <p id="scan-summary-send-help">
          При сохранённом разрешении аккаунта сводка запрашивается автоматически один раз для отчёта и
          политики: очищенные находки и покрытие — указанным выше модели и провайдеру OpenRouter.{' '}
          {policy?.freeOnly === true
            ? 'Только бесплатный профиль.'
            : policy?.freeOnly === false
              ? 'Бесплатность выключена.'
              : 'Бесплатность не подтверждена.'}{' '}
          Бюджет указан выше. Без автоматического повтора или замены модели; условия проверяются заново перед
          отправкой.
        </p>
        {!authorized ? (
          <p>
            Автоматическая сводка выключена. Сохраните разрешение в <a href="/account">настройках аккаунта</a>
            . История и чат доступны независимо.
          </p>
        ) : null}
        {authorized && message && !result ? (
          <Button
            type="button"
            aria-describedby="scan-summary-send-help"
            disabled={pending || !context?.enabled || !policy || !current()}
            onClick={() => void refresh(true, true)}
          >
            Повторить сводку
          </Button>
        ) : null}
        {pending ? (
          <>
            <p role="status">Проверяем условия или получаем сводку…</p>
            <Button
              type="button"
              variant="secondary"
              onClick={() => {
                stop();
                setMessage(
                  'Запрос отменён; результат не будет показан. Передача провайдеру уже могла начаться.',
                );
              }}
            >
              Отменить запрос сводки
            </Button>
          </>
        ) : (
          <Button type="button" variant="secondary" onClick={() => void refresh()}>
            Обновить условия
          </Button>
        )}
        <small>
          После ошибки или отмены автоматического повтора нет. «Повторить сводку» разрешает один новый запрос
          с повторной проверкой условий и квот. Сводка может восстанавливаться из ограниченного кэша процесса
          сервера. Это не долговечное хранение: после перезапуска процесса или вытеснения запись может
          исчезнуть. Ответы не сохраняются в браузерном хранилище.
        </small>
        {message ? (
          <Alert role="alert" tone="warning">
            {message}
          </Alert>
        ) : null}
      </div>
      <LlmUsagePanel
        binding={
          context && current()
            ? {
                scanId: context.scanId,
                digest: context.digest,
                platform: context.platform,
                reportVersion: context.reportVersion,
              }
            : null
        }
        refreshVersion={usageRefreshVersion}
      />
      {result ? (
        <div aria-label="Сводка ИИ · требует проверки">
          {result.recovered ? (
            <p>Сводка восстановлена из кэша процесса сервера; это не долговечная история.</p>
          ) : null}
          {result.reply.hypotheses.map((hypothesis, index) => (
            <article key={index}>
              <h4>Пункт {index + 1} · интерпретация ИИ</h4>
              <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{hypothesis.text}</p>
              <ul>
                {hypothesis.citations.map((id) => (
                  <li key={id}>
                    <a href={`#ai-source-${encodeURIComponent(id)}`}>Находка {id}</a>
                  </li>
                ))}
              </ul>
            </article>
          ))}
          <h4>Основания ответа</h4>
          <p>
            Источники найдены в авторизованных результатах сканирования, включая другие категории и страницы.
            Наличие источника не доказывает вывод ИИ; выполненная проверка не гарантирует безопасность.
          </p>
          <ul>
            {result.sources.map((source) => (
              <li id={`ai-source-${source.findingId}`} tabIndex={-1} key={source.findingId}>
                <strong>
                  {source.label
                    .split(' · ')
                    .map((part) => sourceLabels[part] ?? part)
                    .join(' · ')}
                </strong>
                <p>
                  {{ secret: 'Секреты', vuln: 'Уязвимости', config: 'Конфигурация' }[source.check]} · ID:{' '}
                  {source.findingId}
                </p>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <ScanChatPanel status={status} transport={transport} />
    </section>
  );
}
