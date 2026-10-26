import { useEffect, useMemo, useRef, useState } from 'react';
import { Sparkles } from 'lucide-react';
import { scanSession, subscribeScanSession } from '@/shared/api/auth/scanSession';
import {
  collectSummarySources,
  contextFence,
  createSummaryClient,
  SummaryError,
  summaryErrorMessage,
  verifiedSummarySources,
  type SummaryClient,
  type SummaryContext,
  type SummaryReply,
  type SummarySource,
} from '@/shared/api/scans/llmSummaryClient';
import type { ScanStatus, ScanTransport } from '@/shared/api/scans/scanTransport';
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
export function ScanSummaryPanel({ status, transport, client: providedClient }: Props) {
  const client = useMemo(() => providedClient ?? createSummaryClient(scanSession()), [providedClient]);
  const [context, setContext] = useState<SummaryContext | null>(null);

  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState('');
  const [usageRefreshVersion, setUsageRefreshVersion] = useState(0);
  const [result, setResult] = useState<{ reply: SummaryReply; sources: SummarySource[] } | null>(null);
  const request = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const contextRef = useRef<SummaryContext | null>(null);

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
  async function refresh() {
    if (request.current || !client.current()) return;
    const controller = new AbortController();
    request.current = controller;
    const version = ++generation.current;
    setPending(true);
    setResult(null);
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
    try {
      const next = await Promise.race([client.context(status.scanId, controller.signal), stopped]);
      checkContext(next);
      if (generation.current !== version || controller.signal.aborted || !client.current()) return;
      contextRef.current = next;
      setContext(next);
    } catch (error) {
      if (generation.current !== version) return;
      contextRef.current = null;
      setContext(null);
      setMessage(summaryErrorMessage(error));
    } finally {
      clearTimeout(deadline);
      controller.abort();
      if (generation.current === version) {
        request.current = null;
        setPending(false);
      }
    }
  }
  useEffect(() => {
    void refresh();
    const unsubscribe = subscribeScanSession(() => {
      stop();
      contextRef.current = null;
      setContext(null);
      setMessage('Сессия изменилась. Сводка скрыта; войдите и откройте отчёт заново.');
    });
    // Revalidate only GET on focus; never regenerate implicitly.
    const focus = () => {
      if (!request.current) void refresh();
    };
    window.addEventListener('focus', focus);
    return () => {
      invalidateRequest();
      unsubscribe();
      window.removeEventListener('focus', focus);
    };
    // The parent keys this panel by session, scan and complete status snapshot.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, status.scanId]);

  async function generate() {
    const accepted = contextRef.current;
    if (
      !accepted?.enabled ||
      !accepted.policyVersion ||
      !accepted.disclosure ||
      request.current ||
      !client.current()
    )
      return;
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
      if (controller.signal.aborted || !client.current() || generation.current !== version)
        throw new SummaryError('STALE');
      const reply = await client.summary(before, controller.signal);
      if (controller.signal.aborted || !client.current() || generation.current !== version)
        throw new SummaryError('STALE');
      const sources = await collectSummarySources(transport, status, controller.signal);
      const verified = verifiedSummarySources(reply, sources);
      if (controller.signal.aborted || !client.current() || generation.current !== version)
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
      if (controller.signal.aborted || !client.current() || generation.current !== version)
        throw new SummaryError('STALE');
      return { reply, sources: verified };
    };
    try {
      const value = await Promise.race([operation(), stopped]);
      if (generation.current === version && !controller.signal.aborted && client.current()) setResult(value);
    } catch (error) {
      if (generation.current === version) setMessage(summaryErrorMessage(error));
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
        <p className="scan-a1__eyebrow">04 / ИИ-СВОДКА · ПО ЯВНОМУ ЗАПРОСУ</p>
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
          Нажимая «Получить сводку», вы разрешаете один запрос: очищенные находки и покрытие этого отчёта —
          указанным выше модели и провайдеру OpenRouter.{' '}
          {policy?.freeOnly === true
            ? 'Только бесплатный профиль.'
            : policy?.freeOnly === false
              ? 'Бесплатность выключена.'
              : 'Бесплатность не подтверждена.'}{' '}
          Бюджет указан выше. Без автоматического повтора или замены модели; условия проверяются заново перед
          отправкой.
        </p>
        <Button
          type="button"
          aria-describedby="scan-summary-send-help"
          disabled={pending || !context?.enabled || !policy || !client.current()}
          onClick={() => void generate()}
        >
          Получить сводку
        </Button>
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
          Каждое нажатие разрешает только один запрос. После ошибки, отмены или изменения условий нужна новая
          отправка вручную. Чтение условий и остатка квот не запускает генерацию.
        </small>
        {message ? (
          <Alert role="alert" tone="warning">
            {message}
          </Alert>
        ) : null}
      </div>
      <LlmUsagePanel
        binding={
          context && client.current()
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
