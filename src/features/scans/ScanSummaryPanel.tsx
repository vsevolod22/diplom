import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';
import {
  REPORT_AUTOMATION_REVISION,
  readReportPreferences,
  saveReportPreferences,
  openAiSummaryConsentSchema,
  subscribeReportPreferences,
  useReportPreferences,
} from '@/shared/api/preferences/reportPreferences';
import { OpenAiDisclosure } from './OpenAiDisclosure';
import { LifetimeBudgetDetails } from './LlmUsagePanel';
import { ReportRemediation } from './ReportRemediation';
import { ReportSourceLink, type ReportSourceNavigate } from './reportSourceNavigation';
import {
  createUsageClient,
  UsageError,
  usageMatchesDisclosure,
  type LifetimeBudget,
  type LlmUsage,
} from '@/shared/api/scans/llmUsageClient';
import {
  allowAutomationDisclosure,
  allowSummaryAutomation,
  reportPreferencesCurrent,
  ReportAutomationError,
  reportAutomationKey,
  runReportAutomation,
  runReportMetadata,
} from '@/shared/api/scans/reportAutomation';
import { CheckCircle2, LoaderCircle, Sparkles } from 'lucide-react';
import { scanSession, subscribeScanSession } from '@/shared/api/auth/scanSession';
import {
  collectSummarySources,
  contextFence,
  createSummaryClient,
  isUnsupportedSummaryReport,
  matchesSummaryTuple,
  SummaryError,
  summaryErrorMessage,
  verifiedSummarySources,
  type SummaryClient,
  type SummaryContext,
  type SummaryFailureDiagnostic,
  type SummaryReply,
  type SummarySource,
} from '@/shared/api/scans/llmSummaryClient';
import type { ScanStatus, ScanTransport } from '@/shared/api/scans/scanTransport';
import { PUBLIC_IMAGE_PROFILE } from '@/shared/api/scans/publicImageProfile';
import { Alert, Button } from '@/shared/ui/scan-primitives';


const summaryPhases = {
  context: 'Проверяем доступность разбора',
  recovery: 'Ищем сохранённый разбор',
  waiting: 'Ожидаем начала разбора',
  generation: 'Модель готовит рекомендации',
  verification: 'Проверяем источники и готовим результат',
} as const;
type SummaryPhase = keyof typeof summaryPhases;

function SummaryProgress({ phase }: { phase: SummaryPhase }) {
  const [startedAt] = useState(() => Date.now());
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    const timer = window.setInterval(
      () => setSeconds(Math.max(0, Math.floor((Date.now() - startedAt) / 1000))),
      1000,
    );
    return () => window.clearInterval(timer);
  }, [startedAt]);
  return (
    <div className="scan-summary-progress" data-phase={phase}>
      <p role="status" aria-atomic="true">
        <LoaderCircle className="scan-summary-progress__spinner" size={20} aria-hidden="true" />
        <span>
          <span className="sr-only">Готовим разбор… </span>
          {summaryPhases[phase]}
        </span>
      </p>
      <progress aria-label="Подготовка ИИ-отчёта" />
      <small>Точный процент пока неизвестен. Исходные находки доступны в разделе «Находки и исправления».</small>
      {seconds >= 10 ? <small className="scan-summary-progress__elapsed">Ожидание: {seconds} с</small> : null}
    </div>
  );
}

type Props = { status: ScanStatus; transport: ScanTransport; client?: SummaryClient; onNavigateSource?: ReportSourceNavigate };
const sessionKey = () => JSON.stringify(scanSession());
export function ScanSummaryPanel(props: Props) {
  const session = useSyncExternalStore(subscribeScanSession, sessionKey, sessionKey);
  const preferences = useReportPreferences();
  const owner = scanSession();
  const scope = JSON.stringify([session, props.status]);
  // A failed persistent save revokes consent and remounts SummaryScope; keep its feedback owner-scoped.
  const [saveFailure, setSaveFailure] = useState<{
    scope: string;
    preferences: ReturnType<typeof useReportPreferences>;
  } | null>(null);
  function enableAutomation(context: SummaryContext) {
    if (!reportPreferencesCurrent(preferences) || !context.enabled || !context.policyVersion) return;
    const paid =
      context.disclosure?.provider === 'OpenAI'
        ? openAiSummaryConsentSchema.safeParse({
            version: 1,
            policyVersion: context.policyVersion,
            disclosure: context.disclosure,
          })
        : null;
    if (paid ? !paid.success : !allowAutomationDisclosure(context.disclosure, 'summary')) return;
    const saved = saveReportPreferences(
      {
        language: preferences.language,
        autoSummary: true,
        ...(paid?.success ? { openAiSummaryConsent: paid.data } : {}),
      },
      owner,
    );
    setSaveFailure(saved ? null : { scope, preferences: readReportPreferences() });
  }
  return (
    <SummaryScope
      key={JSON.stringify([session, props.status, preferences])}
      {...props}
      preferences={preferences}
      onEnableAutomation={enableAutomation}
      optInFailed={saveFailure?.scope === scope && saveFailure.preferences === preferences}
    />
  );
}
function SummaryScope({
  status,
  transport,
  client: providedClient,
  onNavigateSource,
  preferences,
  onEnableAutomation,
  optInFailed,
}: Props & {
  preferences: ReturnType<typeof useReportPreferences>;
  onEnableAutomation: (context: SummaryContext) => void;
  optInFailed: boolean;
}) {
  const client = useMemo<SummaryClient>(
    () => providedClient ?? createSummaryClient(scanSession()),
    [providedClient],
  );
  const current = () => client.current() && reportPreferencesCurrent(preferences);
  const automationCurrent = (accepted = contextRef.current) =>
    client.current() &&
    reportPreferencesCurrent(preferences, 'summary') &&
    !!accepted &&
    allowSummaryAutomation(preferences, accepted);
  const [context, setContext] = useState<SummaryContext | null>(null);

  const [pending, setPending] = useState(false);
  const [phase, setPhase] = useState<SummaryPhase>('context');
  const [message, setMessage] = useState('');
  const [postFailure, setPostFailure] = useState<SummaryFailureDiagnostic | null>(null);
  const [quotaBlock, setQuotaBlock] = useState<Extract<LlmUsage, { available: true }> | null>(null);
  const [lifetimeBudget, setLifetimeBudget] = useState<LifetimeBudget | null>(null);
  const [unsupportedReport, setUnsupportedReport] = useState(false);
    const [missingResult, setMissingResult] = useState(false);
  const [result, setResult] = useState<{
    reply: SummaryReply;
    sources: SummarySource[];
  } | null>(null);
  const request = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const contextRef = useRef<SummaryContext | null>(null);

  const authorized = !!context && allowSummaryAutomation(preferences, context);

  function invalidateRequest() {
    generation.current++;
    request.current?.abort();
    request.current = null;
  }
  function stop() {
    invalidateRequest();
    setPending(false);
    setResult(null);
    setPostFailure(null);
    setQuotaBlock(null);
    setLifetimeBudget(null);
  }
  function checkContext(next: SummaryContext) {
    if (next.scanId !== status.scanId || next.digest !== status.digest || next.platform !== status.platform)
      throw new SummaryError('STALE');
    if (next.unavailableReason === 'LLM_SUMMARY_UNSUPPORTED_REPORT')
      throw new SummaryError(next.unavailableReason);
  }
  async function checkUsage(usage: LlmUsage, accepted: SummaryContext, signal: AbortSignal, recheck = false) {
    setQuotaBlock(null);
    if (!usage.available || !usage.integrationEnabled || !usage.quotaEnabled ||
      usage.admission.status === 'unavailable' || !usageMatchesDisclosure(usage, accepted.disclosure))
      throw new SummaryError('LLM_QUOTA_UNAVAILABLE');
    // Lifetime snapshots retain daily counters, but only their server-level reason governs exhaustion.
    const blocked =
      usage.reason === 'exhausted' || usage.reason === 'policy_fault' ||
      (!usage.lifetimeBudget && (usage.user.exhausted || usage.scan.exhausted)) ||
      usage.admission.status === 'insufficient' || usage.admission.status === 'policy_fault';
    if (blocked || recheck) {
      const after = await client.context(status.scanId, signal);
      checkContext(after);
      if (signal.aborted || !current() || contextFence(after) !== contextFence(accepted))
        throw new SummaryError('STALE');
    }
    setLifetimeBudget(usage.lifetimeBudget ?? null);
    if (blocked) {
      setQuotaBlock(usage);
      throw new SummaryError('LLM_QUOTA_EXCEEDED');
    }
  }
  async function refresh(automate = false, retry = false) {
    if (request.current || !current()) return;
    const controller = new AbortController();
    request.current = controller;
    const version = ++generation.current;
    setPending(true);
    setPhase('context');
    setMissingResult(false);
    setMessage('');
    setQuotaBlock(null);
    setLifetimeBudget(null);
    setUnsupportedReport(false);
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
      if (contextRef.current && contextFence(next) !== contextFence(contextRef.current)) {
        setResult(null);
        setPostFailure(null);
        setQuotaBlock(null);
      }
      contextRef.current = next;
      setContext(next);
      accepted = next;
      const existing = client.existing;
      const canReadSummary = next.summaryResultRead ?? status.profile === PUBLIC_IMAGE_PROFILE;
      if (existing && status.state === 'completed' && canReadSummary) {
        // Explicit route capability includes compatible legacy reports; older contexts use the profile fallback.
        // Reading an owner's previous result needs no autoSummary opt-in or attempt marker.
        setPhase('recovery');
        const value = await Promise.race([
          runReportMetadata(
            JSON.stringify(['summary-recovery', status, contextFence(next)]),
            controller.signal,
            async (signal) => {
              const reply = await existing(next, signal);
              if (signal.aborted || !client.current()) throw new SummaryError('STALE');
              if (reply === null) return null;
              if (!reply || !matchesSummaryTuple(reply, next)) throw new SummaryError('STALE');
              if (live()) setPhase('verification');
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
        setMissingResult(value === null);
        if (value) {
          setResult(value);
          setQuotaBlock(null);
          setMessage('');
          recovered = true;
        }
      }
      if (!automate && !recovered && quotaBlock) {
        const usage = await Promise.race([
          runReportMetadata(JSON.stringify(['summary-usage', status, contextFence(next)]), controller.signal,
            signal => createUsageClient().get(next, signal)),
          stopped,
        ]);
        if (!live()) return;
        await Promise.race([checkUsage(usage, next, controller.signal, true), stopped]);
      }
    } catch (error) {
      accepted = null;
      if (generation.current !== version || !current()) return;
      setUnsupportedReport(isUnsupportedSummaryReport(error));
      contextRef.current = null;
      setContext(null);
      setResult(null);
      setPostFailure(null);
      setMessage(
        summaryErrorMessage(error instanceof UsageError ? new SummaryError('LLM_QUOTA_UNAVAILABLE') : error),
      );
    } finally {
      clearTimeout(deadline);
      controller.abort();
      if (generation.current === version) {
        request.current = null;
        setPending(false);
      }
    }
    if (
      accepted?.enabled &&
      !recovered &&
      generation.current === version &&
      preferences.authorized &&
      preferences.autoSummary &&
      !allowSummaryAutomation(preferences, accepted)
    ) {
      setMessage(
        accepted.disclosure?.provider === 'OpenAI'
          ? 'Для платного OpenAI требуется новое согласие на показанные условия. Прежний opt-in не применяется.'
          : 'Условия ИИ-разбора изменились. Проверьте настройки аккаунта.',
      );
    }
    if (
      automate &&
      !recovered &&
      accepted &&
      generation.current === version &&
      allowSummaryAutomation(preferences, accepted) &&
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
      setUnsupportedReport(false);
      setMessage('Настройки изменились. Разбор остановлен.');
    });
    const unsubscribe = subscribeScanSession(() => {
      stop();
      contextRef.current = null;
      setContext(null);
      setUnsupportedReport(false);
      setMessage('Сессия изменилась. Откройте отчёт заново.');
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
      unsupportedReport ||
      status.state !== 'completed' ||
      !accepted?.enabled ||
      !accepted.policyVersion ||
      !accepted.disclosure ||
      request.current ||
      !automationCurrent(accepted)
    )
      return;
    if (!allowSummaryAutomation(preferences, accepted)) {
      setMessage('Условия ИИ-разбора изменились. Проверьте настройки аккаунта.');
      return;
    }
    const controller = new AbortController();
    const version = ++generation.current;
    request.current = controller;

    setPending(true);
    setMissingResult(false);
    setPhase('waiting');
    setResult(null);
    setPostFailure(null);
    setQuotaBlock(null);
    setLifetimeBudget(null);
    setMessage('');
    let timedOut = false;
    const deadline = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, 120_000);
    const stopped = new Promise<never>((_, reject) =>
      controller.signal.addEventListener(
        'abort',
        () => reject(new SummaryError(timedOut ? 'TIMEOUT' : 'ABORTED')),
        { once: true },
      ),
    );
    const updatePhase = (next: SummaryPhase) => {
      if (generation.current === version && !controller.signal.aborted && current()) setPhase(next);
    };
    const operation = async () => {
      updatePhase('context');
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
      await checkUsage(usage, before, controller.signal);
      if (!allowSummaryAutomation(preferences, before)) throw new ReportAutomationError('DISCLOSURE');
      if (controller.signal.aborted || !automationCurrent() || generation.current !== version)
        throw new SummaryError('STALE');
      updatePhase('generation');
      const reply = await client.summary(before, controller.signal);
      if (controller.signal.aborted || !current() || generation.current !== version)
        throw new SummaryError('STALE');
      updatePhase('verification');
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
      updatePhase('verification');
      const after = await Promise.race([
        runReportMetadata(JSON.stringify(['summary-context', status]), controller.signal, (signal) =>
          client.context(status.scanId, signal),
        ),
        stopped,
      ]);
      checkContext(after);
      if (contextFence(after) !== contextFence(accepted)) throw new SummaryError('STALE');
      if (!allowSummaryAutomation(preferences, after)) throw new ReportAutomationError('DISCLOSURE');
      if (generation.current === version && !controller.signal.aborted && automationCurrent())
        setResult(value);
    } catch (error) {
      if (generation.current === version && current()) {
        setUnsupportedReport(isUnsupportedSummaryReport(error));
        setPostFailure(error instanceof SummaryError ? error.diagnostic ?? null : null);
        setMessage(
          error instanceof ReportAutomationError
            ? error.code === 'DISCLOSURE'
              ? 'Условия ИИ-разбора изменились. Проверьте настройки аккаунта.'
              : 'Не удалось подготовить разбор. Отчёт сканеров доступен; можно повторить вручную.'
            : summaryErrorMessage(error instanceof UsageError ? new SummaryError('LLM_QUOTA_UNAVAILABLE') : error),
        );
      }
    } finally {
      clearTimeout(deadline);
      controller.abort();
      if (generation.current === version) {
        request.current = null;
        setPending(false);
      }
    }
  }
  function enableAutomation() {
    const accepted = contextRef.current;
    if (
      pending ||
      unsupportedReport ||
      !current() ||
      !accepted?.enabled ||
      !(
        accepted.disclosure?.provider === 'OpenAI' ||
        allowAutomationDisclosure(accepted.disclosure, 'summary')
      )
    )
      return;
    checkContext(accepted);
    onEnableAutomation(accepted);
  }

  const failure = unsupportedReport
    ? 'ИИ-разбор недоступен для этого формата отчёта. Исходные результаты доступны в разделе «Находки и исправления».'
    : optInFailed
      ? 'Не удалось сохранить настройку. Авторазбор не включён.'
      : message ||
        (status.state !== 'completed'
          ? 'ИИ-разбор доступен только для полностью завершённой проверки. Сохранённые находки доступны в отчёте.'
          : context && !context.enabled
            ? 'ИИ-разбор сейчас недоступен. Отчёт сканеров доступен.'
            : '');

  return (
    <section className="scan-a1__ai" aria-labelledby="scan-a1-ai" aria-busy={pending}>
      <h3 id="scan-a1-ai">
        <Sparkles size={24} aria-hidden="true" /> Объяснение ИИ
      </h3>
      <p>Дополнительное объяснение, не заключение о безопасности. Проверяйте рекомендации по находкам сканера и источникам под каждым абзацем.</p>
      {context?.disclosure?.provider === 'OpenAI' ? (
        <OpenAiDisclosure disclosure={context.disclosure} />
      ) : null}
      {lifetimeBudget && current() ? (
        <>
          <LifetimeBudgetDetails budget={lifetimeBudget} />
          <p>
            Денежный режим «без лимита» относится только к запросу и суткам. Отдельный бюджет аккаунта за всё
            время ограничивает расход; показан снимок перед отправкой.
          </p>
        </>
      ) : null}
      {missingResult && !pending && !result && !failure ? (
              <div>
                <p role="status">Сохранённого ИИ-разбора пока нет. Результаты сканеров доступны ниже; отсутствие разбора не означает, что образ безопасен.</p>
                <Button type="button" variant="secondary" disabled={!current()} onClick={() => void refresh()}>
                  Проверить сохранённый разбор
                </Button>
                {authorized ? (
                  <Button type="button" disabled={!current() || !context?.enabled} onClick={() => void refresh(true, true)}>
                    {context?.disclosure?.provider === 'OpenAI' ? 'Создать платный ИИ-разбор' : 'Создать ИИ-разбор'}
                  </Button>
                ) : null}
              </div>
            ) : null}
            {!authorized && !result && !unsupportedReport ? (
        <div>
          <p id="scan-summary-send-help">
            {context?.disclosure?.provider === 'OpenAI'
              ? 'Включение разрешает платный авторазбор только для показанных OpenAI, политики и денежного режима. Старое бесплатное согласие не применяется.'
              : 'Находки отчёта, имена пакетов и версии передаются внешней модели, которая может сохранять данные.'}{' '}
            Авторазбор следующих сканирований можно выключить в <a href="/account">настройках аккаунта</a>.
          </p>
          <Button
            type="button"
            aria-describedby="scan-summary-send-help"
            disabled={
              pending ||
              !current() ||
              status.state !== 'completed' ||
              !context?.enabled ||
              !(
                context.disclosure?.provider === 'OpenAI' ||
                allowAutomationDisclosure(context.disclosure, 'summary')
              )
            }
            onClick={enableAutomation}
          >
            {context?.disclosure?.provider === 'OpenAI'
              ? 'Включить платный авторазбор OpenAI'
              : 'Включить авторазбор'}
          </Button>
        </div>
      ) : null}
      {pending ? (
        <div>
          <SummaryProgress phase={phase} />
          <Button
            type="button"
            variant="secondary"
            onClick={() => {
              stop();
              setMessage('Разбор отменён. Передача данных уже могла начаться.');
            }}
          >
            Отменить разбор
          </Button>
        </div>
      ) : null}
      {postFailure && !pending && !result && current() ? (
        <details>
          <summary>Технические сведения запроса summary</summary>
          <p>Ответ на POST /llm/summary: HTTP {postFailure.httpStatus}</p>
          {postFailure.providerStatus !== undefined ? <p>HTTP провайдера: {postFailure.providerStatus}</p> : null}
          {postFailure.providerErrorCode ? <p>Код провайдера: {postFailure.providerErrorCode}</p> : null}
          {postFailure.providerErrorParam ? <p>Параметр запроса: {postFailure.providerErrorParam}</p> : null}
          {postFailure.phase && postFailure.reason ? (
            <p>Этап и причина: {postFailure.phase} / {postFailure.reason}</p>
          ) : null}
          <p>Проверенный результат не получен. Запрос уже мог быть обработан или учтён. Автоматического повтора нет. Проверка сохранённого разбора через GET не восстанавливает причину этой ошибки.</p>
        </details>
      ) : null}
      {failure && !pending && !result ? (
        <div>
          <Alert role="alert" tone="warning">
            {failure}
          </Alert>
          {quotaBlock && current() ? (
            <div>
              <p>
                Локальная квота ИИ: новая отправка остановлена до обращения к модели. Предыдущие запросы уже
                могли быть обработаны или учтены; это не означает отсутствия расхода.
              </p>
              {quotaBlock.monetaryLimit === 'uncapped' ? (
                <p>
                  Денежный режим — без лимита запроса и суток; отдельный бюджет аккаунта может ограничивать
                  расход. {quotaBlock.lifetimeBudget
                    ? 'Оконные счётчики токенов — статистика, не блокирующие бюджеты.'
                    : 'Технические лимиты токенов остаются отдельными.'}
                </p>
              ) : null}
              {(['user', 'scan'] as const).map(scope => (
                <div key={scope}>
                  <h4>
                    {scope === 'user' ? 'Пользователь' : 'Этот скан'}
                    {quotaBlock.lifetimeBudget ? ' · оконные счётчики' : ''}
                  </h4>
                  {(['input', 'output', 'costMicros'] as const).map(dimension => (
                    <div key={dimension}>
                      <p>{dimension === 'input' ? 'Входные токены' : dimension === 'output' ? 'Выходные токены' : 'Стоимость, микро-USD'}</p>
                      <p>
                        {quotaBlock[scope].limits[dimension] === null
                          ? 'Без денежного лимита запроса и суток; бюджет аккаунта учитывается отдельно'
                          : quotaBlock.lifetimeBudget
                            ? `Оконный счётчик: ${quotaBlock[scope].limits[dimension]}; расчётный остаток счётчика ${quotaBlock[scope].remaining[dimension]} (не бюджет допуска)`
                            : `Осталось ${quotaBlock[scope].remaining[dimension]} из ${quotaBlock[scope].limits[dimension]}`}
                        ; учтено {quotaBlock[scope].used[dimension]}; резерв {quotaBlock[scope].held[dimension]}; перенос неопределённого расхода {quotaBlock[scope].carried[dimension]}
                      </p>
                    </div>
                  ))}
                </div>
              ))}
              {quotaBlock.admission.status !== 'unavailable' ? (
                <ul>
                  {quotaBlock.admission.signals.map((signal, index) => (
                    <li key={index}>
                      {signal.scope === 'user' ? 'Пользователь' : 'Этот скан'} ·{' '}
                      {signal.dimension === 'input' ? 'входные токены' : signal.dimension === 'output' ? 'выходные токены' : signal.dimension === 'costMicros' ? 'стоимость' : 'весь бюджет'}:{' '}
                      {signal.reason === 'insufficient'
                        ? `требуется ${signal.required}, осталось ${signal.remaining}`
                        : 'учёт заблокирован из-за расхождения с политикой'}
                    </li>
                  ))}
                </ul>
              ) : null}
              <p>Резерв и перенос не означают подтверждённый расход. Неопределённые обязательства не сбрасываются со сменой суток. Оператору нужно сверить учёт или согласованно изменить лимиты; повторное нажатие этого не исправляет.</p>
              <Button type="button" disabled={!current()} onClick={() => void refresh()}>
                Проверить квоту и сохранённый разбор
              </Button>
            </div>
          ) : !unsupportedReport ? (
            <Button type="button" disabled={!current()} onClick={() => void refresh(true, true)}>
              Повторить разбор
            </Button>
          ) : null}
        </div>
      ) : null}

      {result ? (
        <div aria-label="ИИ-разбор отчёта">
          <div className="scan-summary-ready" role="status">
            <CheckCircle2 size={18} aria-hidden="true" /> ИИ-разбор готов
          </div>
          <div aria-label="Объём контекста модели">
            {result.reply.contextSelection ? (
              <>
                <p>
                  Модель получила {result.reply.contextSelection.selectedFindings} из{' '}
                  {result.reply.contextSelection.totalFindings} находок;{' '}
                  {result.reply.contextSelection.omittedFindings} не включены в контекст.
                </p>
                <p>
                  Включаются все критические находки (в том числе с критической оценкой отдельного источника)
                  и находки с неизвестной опасностью; остальные отбираются по уровню опасности в пределах
                  объёма контекста. Это отбор для объяснения, а не удаление находок из отчёта.
                </p>
                <p>
                  {result.reply.contextSelection.omittedFindings > 0
                    ? 'Объяснение охватывает только отобранные находки. Не включённые находки тоже требуют проверки.'
                    : 'В контекст включены все находки сохранённого отчёта. Это не означает, что все проверки поддерживаются или образ безопасен.'}
                </p>
              </>
            ) : (
              <p>
                Объём контекста модели неизвестен: в этом сохранённом разборе нет данных об отборе находок.
                Полнота охвата не подтверждена; число цитат не равно числу переданных модели находок.
              </p>
            )}
            <p>
              <ReportSourceLink category="all" onNavigate={onNavigateSource ? category => current() && !pending && onNavigateSource(category) : undefined} disabled={pending}>
                              Полный отчёт сканеров · находки и исправления
                            </ReportSourceLink>
              {' '}— проверьте все категории и страницы. Объём контекста не зависит от текущего фильтра или страницы.
            </p>
          </div>
          <details className="scan-summary-explanation">
            <summary>Прочитать объяснение и проверить его источники</summary>
          {result.reply.hypotheses.map((paragraph, index) => (
            <div key={index}>
              <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{paragraph.text}</p>
              <div aria-label={`Источники абзаца ${index + 1}`}>
                <p>На чём основан абзац {index + 1} · находок: {paragraph.citations.length}</p>
                <ul>
                  {result.sources.filter((source) => paragraph.citations.includes(source.findingId)).map((source) => (
                    <li key={source.findingId}>
                      <ReportRemediation source={source}
                        onNavigate={onNavigateSource ? category => current() && !pending && onNavigateSource(category) : undefined}
                        disabled={pending} />
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          ))}
          </details>
        </div>
      ) : null}
    </section>
  );
}
