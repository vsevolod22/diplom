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

type Props = { status: ScanStatus; transport: ScanTransport; client?: SummaryClient };
export function ScanSummaryPanel({ status, transport, client: providedClient }: Props) {
  const client = useMemo(() => providedClient ?? createSummaryClient(scanSession()), [providedClient]);
  const [context, setContext] = useState<SummaryContext | null>(null);
  const [consent, setConsent] = useState(false);
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState('');
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
    setConsent(false);
    setResult(null);
  }
  function checkContext(next: SummaryContext) {
    if (next.scanId !== status.scanId || next.digest !== status.digest || next.platform !== status.platform)
      throw new SummaryError('STALE');
  }
  async function refresh() {
    if (request.current) return;
    const controller = new AbortController();
    request.current = controller;
    const version = ++generation.current;
    setPending(true);
    setMessage('');
    setConsent(false);
    setResult(null);
    try {
      const next = await client.context(status.scanId, controller.signal);
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
      setMessage('Сессия изменилась. Сводка и согласие сброшены.');
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
    if (!consent || !accepted?.enabled || request.current || !client.current()) return;
    const controller = new AbortController();
    const version = ++generation.current;
    request.current = controller;
    setPending(true);
    setConsent(false);
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
      const reply = await client.summary(accepted, controller.signal);
      const sources = await collectSummarySources(transport, status, controller.signal);
      const verified = verifiedSummarySources(reply, sources);
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
          ИИ предлагает гипотезы, а не результаты сканирования. Покрытие и исходные находки выше остаются
          основным отчётом.
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
              <dd>{policy.providers.join(', ')} · global: регион не ограничен</dd>
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
              <dd>{policy.data}</dd>
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
              <dt>Привязка согласия</dt>
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
        <label>
          <input
            type="checkbox"
            checked={consent}
            disabled={pending || !context?.enabled || !policy || !client.current()}
            onChange={(event) => {
              setConsent(event.target.checked);
              setResult(null);
            }}
          />{' '}
          Разрешаю отправить очищенные findings и coverage этого отчёта указанной модели OpenRouter по
          раскрытой политике только для одного запроса сводки.
        </label>
        <Button
          type="button"
          disabled={pending || !consent || !context?.enabled || !client.current()}
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
          Согласие сбрасывается после каждого запроса, отмены или изменения условий. Чат, история, кэш и учёт
          продуктовых квот здесь не реализованы.
        </small>
        {message ? (
          <Alert role="alert" tone="warning">
            {message}
          </Alert>
        ) : null}
      </div>
      {result ? (
        <div aria-label="ИИ-гипотезы">
          {result.reply.hypotheses.map((hypothesis, index) => (
            <article key={index}>
              <h4>Гипотеза {index + 1} · не доказанный факт</h4>
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
          <h4>Проверенные ссылки на исходные находки</h4>
          <p>
            Источники найдены в авторизованных scanner results, включая другие категории и страницы. Наличие
            источника не доказывает вывод ИИ; checked не означает безопасность.
          </p>
          <ul>
            {result.sources.map((source) => (
              <li id={`ai-source-${source.findingId}`} tabIndex={-1} key={source.findingId}>
                <strong>{source.label}</strong>
                <p>
                  {source.check} · ID: {source.findingId}
                </p>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}
