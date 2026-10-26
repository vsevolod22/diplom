import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from 'react';
import { scanSession, subscribeScanSession } from '@/shared/api/auth/scanSession';
import {
  REPORT_AUTOMATION_REVISION,
  subscribeReportPreferences,
  useReportPreferences,
} from '@/shared/api/preferences/reportPreferences';
import {
  allowAutomationDisclosure,
  reportPreferencesCurrent,
  ReportAutomationError,
  runReportMetadata,
  reportAutomationKey,
  reportAutomationMessage,
  runReportAutomation,
} from '@/shared/api/scans/reportAutomation';
import {
  createAdvisoryTranslationClient,
  TranslationError,
  translationErrorMessage,
  type AdvisoryTranslationClient,
} from '@/shared/api/scans/advisoryTranslationClient';
import {
  hasTranslationText,
  matchesTranslationFields,
  matchesTranslationSource,
  translationContextFence,
  translationSourceVersion,
  type AdvisoryAssessment,
  type TranslationContext,
  type TranslationReply,
} from '@/shared/api/scans/advisoryTranslationContract';
import { sameChatBinding, type ChatReadiness } from '@/shared/api/scans/llmChatContract';
import type { ScanStatus } from '@/shared/api/scans/scanTransport';

const ReportScope = createContext<ScanStatus | null>(null);
export function AdvisoryTranslationScope({
  status,
  children,
}: {
  status: ScanStatus | null;
  children: ReactNode;
}) {
  return <ReportScope.Provider value={status}>{children}</ReportScope.Provider>;
}
type Props = {
  findingId: string;
  vulnerabilityId: string;
  assessmentIndex: number;
  assessment: AdvisoryAssessment;
  client?: AdvisoryTranslationClient;
};
type Snapshot = { context: TranslationContext; readiness: ChatReadiness };
const sessionKey = () => JSON.stringify(scanSession());
const blockerMessages = {
  'configuration-required': 'Оператор должен настроить политику ИИ.',
  'public-key-required': 'Серверный ключ не настроен или отсутствует. Не вводите ключи в интерфейс.',
  'public-key-unsafe': 'Метаданные серверного ключа не прошли проверку безопасности.',
  'quota-store-unavailable': 'Хранилище квоты недоступно.',
  'history-store-unavailable': 'Хранилище истории недоступно.',
  'provider-profile-unavailable': 'Проверенный профиль провайдера недоступен.',
};
export function AdvisoryTranslationPanel(props: Props) {
  const status = useContext(ReportScope);
  const session = useSyncExternalStore(subscribeScanSession, sessionKey, sessionKey);
  const preferences = useReportPreferences();
  // Reset before rendering another owner, preference, report, source slot or original text.
  const scope = JSON.stringify([
    session,
    preferences,
    status,
    props.findingId,
    props.vulnerabilityId,
    props.assessmentIndex,
    props.assessment,
  ]);
  return <TranslationScope key={scope} {...props} status={status} preferences={preferences} />;
}
function TranslationScope({
  status,
  findingId,
  vulnerabilityId,
  assessmentIndex,
  assessment,
  client: providedClient,
  preferences,
}: Props & { status: ScanStatus | null; preferences: ReturnType<typeof useReportPreferences> }) {
  const client = useMemo(() => providedClient ?? createAdvisoryTranslationClient(), [providedClient]);
  const current = () => client.current() && reportPreferencesCurrent(preferences, 'translation');
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const disclosureId = `translation-send-${findingId}-${assessmentIndex}`;
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState('');
  const [result, setResult] = useState<TranslationReply | null>(null);
  const [showTranslation, setShowTranslation] = useState(true);
  const request = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const allowed = hasTranslationText(assessment);
  const authorized = preferences.authorized && preferences.language === 'ru';
  const available = !!status && status.state === 'completed' && allowed && current() && authorized;
  const selection = { findingId, assessmentIndex };

  function invalidate() {
    generation.current++;
    request.current?.abort();
    request.current = null;
  }
  function clear() {
    invalidate();
    setSnapshot(null);
    setResult(null);
    setPending(false);
  }
  async function readSnapshot(signal: AbortSignal, passive = false): Promise<Snapshot> {
    if (!status || !allowed || signal.aborted) throw new TranslationError('STALE');
    if (passive) {
      const key = JSON.stringify(['translation-metadata', status, selection, vulnerabilityId, assessment]);
      return runReportMetadata(key, signal, (sharedSignal) => readSnapshot(sharedSignal));
    }
    const [context, readiness, sourceVersion] = await Promise.all([
      client.context(status.scanId, selection, signal),
      client.readiness(status.scanId, signal),
      translationSourceVersion(vulnerabilityId, assessment),
    ]);
    if (
      context.scanId !== status.scanId ||
      context.findingId !== findingId ||
      context.assessmentIndex !== assessmentIndex ||
      (status.digest !== undefined && context.digest !== status.digest) ||
      (status.platform !== undefined && context.platform !== status.platform) ||
      context.sourceVersion !== sourceVersion ||
      !matchesTranslationSource(context, assessment) ||
      !sameChatBinding(readiness, context)
    )
      throw new TranslationError('STALE');
    if (
      context.enabled &&
      (readiness.provider.status === 'unverified-profile' ||
        readiness.provider.model !== context.disclosure?.model ||
        readiness.provider.endpoint !== context.disclosure?.providers[0])
    )
      throw new TranslationError('STALE');
    return { context, readiness };
  }
  async function operate(action: 'read' | 'translate', accepted = snapshot, automate = false, retry = false) {
    if (
      !available ||
      request.current ||
      (action === 'translate' &&
        (!accepted?.context.enabled || !accepted.context.policyVersion || !accepted.readiness.localReady))
    )
      return;

    if (
      action === 'translate' &&
      accepted &&
      !allowAutomationDisclosure(accepted.context.disclosure, 'translation')
    ) {
      setMessage(reportAutomationMessage(new ReportAutomationError('DISCLOSURE'))!);
      return;
    }
    const controller = new AbortController();
    const version = ++generation.current;
    request.current = controller;
    const live = () => generation.current === version && !controller.signal.aborted && current();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, 45_000);
    const stopped = new Promise<never>((_, reject) =>
      controller.signal.addEventListener(
        'abort',
        () => reject(new TranslationError(timedOut ? 'TIMEOUT' : 'ABORTED')),
        { once: true },
      ),
    );
    setPending(true);
    if (action === 'translate') {
      setResult(null);
      setMessage('');
    }
    let latest: Snapshot | null = null;
    let validated: TranslationReply | null = null;
    const run = async () => {
      // Mutation tasks already own a queue slot; passive snapshots must acquire one first.
      const before = await readSnapshot(controller.signal, action === 'read');
      if (!live()) return;
      latest = before;
      setSnapshot(before);
      if (action === 'read') {
        if (accepted && translationContextFence(before.context) !== translationContextFence(accepted.context))
          setResult(null);
        return;
      }
      if (!accepted || translationContextFence(before.context) !== translationContextFence(accepted.context))
        throw new TranslationError('STALE');
      if (!before.readiness.localReady || !before.context.enabled || !before.context.policyVersion)
        throw new TranslationError('LLM_CONFIGURATION_UNAVAILABLE');
      if (!allowAutomationDisclosure(before.context.disclosure, 'translation'))
        throw new ReportAutomationError('DISCLOSURE');
      if (!live()) throw new TranslationError('STALE');
      const reply = await client.translate(
        before.context,
        { accepted: true, policyVersion: before.context.policyVersion },
        controller.signal,
      );
      if (!live()) return;
      if (!matchesTranslationFields(reply, assessment)) throw new TranslationError('INVALID');
      const after = await readSnapshot(controller.signal);
      if (!live()) return;
      latest = after;
      setSnapshot(after);
      if (
        !after.readiness.localReady ||
        translationContextFence(after.context) !== translationContextFence(before.context)
      )
        throw new TranslationError('STALE');
      validated = reply;
    };
    try {
      if (action === 'read') {
        await Promise.race([run(), stopped]);
      } else if (accepted) {
        const key = reportAutomationKey(
          'translation',
          REPORT_AUTOMATION_REVISION,
          JSON.stringify([
            accepted.context.scanId,
            accepted.context.digest,
            accepted.context.platform,
            accepted.context.reportVersion,
            accepted.context.policyVersion,
            accepted.context.findingId,
            accepted.context.assessmentIndex,
            accepted.context.sourceVersion,
            'ru',
          ]),
        );
        // Cache only validated replies; source and policy are checked again even on a cache hit.
        const value = await Promise.race([
          runReportAutomation(
            key,
            controller.signal,
            async () => {
              await run();
              if (!live() || !validated) throw new TranslationError('STALE');
              return { reply: validated, fence: translationContextFence(accepted.context) };
            },
            retry,
          ),
          stopped,
        ]);
        if (!live()) return;
        if (value.fence !== translationContextFence(accepted.context)) throw new TranslationError('STALE');
        const after = await Promise.race([readSnapshot(controller.signal, true), stopped]);
        if (!live()) return;
        if (
          !after.readiness.localReady ||
          translationContextFence(after.context) !== translationContextFence(accepted.context)
        )
          throw new TranslationError('STALE');
        if (!allowAutomationDisclosure(after.context.disclosure, 'translation'))
          throw new ReportAutomationError('DISCLOSURE');
        if (!live()) return;
        setSnapshot(after);
        setResult(value.reply);
        setShowTranslation(true);
      }
    } catch (error) {
      if (generation.current === version && current()) {
        setSnapshot(latest ?? accepted);
        setResult(null);
        setMessage(reportAutomationMessage(error) ?? translationErrorMessage(error));
      }
    } finally {
      clearTimeout(timer);
      if (generation.current === version) {
        request.current = null;
        setPending(false);
      }
      controller.abort();
    }
    if (automate && latest && generation.current === version && authorized && current())
      void operate('translate', latest);
  }
  useEffect(() => {
    // Only opened cards mount this scope. Saved Russian-language authorization permits one attempt.
    const unsubscribePreferences = subscribeReportPreferences(() => {
      if (!reportPreferencesCurrent(preferences, 'translation')) clear();
    });
    const unsubscribe = subscribeScanSession(clear);
    void operate('read', null, true);

    return () => {
      invalidate();
      unsubscribe();
      unsubscribePreferences();
    };
    // The outer key includes the complete source, report and session snapshot.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, preferences]);
  const context = snapshot?.context;
  const ready = available && !pending && !!context?.enabled && snapshot?.readiness.localReady === true;
  return (
    <section
      aria-label={`Перевод ${vulnerabilityId}, источник ${assessment.source}, оценка ${assessmentIndex + 1}`}
      aria-busy={pending}
    >
      <p>Оригинал выше сохранён без изменений. Язык перевода: русский (ru).</p>
      {!authorized ? (
        <p>
          Показан оригинал. Автоматический перевод на русский требует сохранённого разрешения в{' '}
          <a href="/account">настройках аккаунта</a>.
        </p>
      ) : null}
      {!allowed ? (
        <p>
          Перевод недоступен: нет разрешённого текста источника (данные отсутствуют, скрыты или не включены).
        </p>
      ) : !status ? (
        <p>Перевод доступен только для авторизованного завершённого отчёта.</p>
      ) : null}
      <button
        type="button"
        className="scan-a1__link"
        disabled={!available || pending}
        onClick={() => void operate('read')}
      >
        Обновить условия перевода
      </button>
      {context?.disclosure ? (
        <div id={`${disclosureId}-policy`}>
          <p>
            {context.disclosure.provider} · {context.disclosure.model} ·{' '}
            {context.disclosure.providers.join(', ')} · регион не ограничен.
          </p>
          <p>
            Внешнему провайдеру передаётся разрешённый текст заголовка и описания только выбранной оценки
            уведомления об уязвимости. Не весь отчёт и не история чата.
          </p>
          <p>
            {context.disclosure.retention === 'no-storage'
              ? 'Без хранения и обучения'
              : 'Без обучения; отсутствие хранения не заявлено'}{' '}
            — декларация провайдера, не доказательство соблюдения.
          </p>
          <p>
            {context.disclosure.freeOnly ? 'Только бесплатный профиль' : 'Бесплатный режим выключен'} · бюджет
            допуска {context.disclosure.requestBudgetUsd} USD/запрос, не фактический счёт. Политика{' '}
            {context.policyVersion}.
          </p>
        </div>
      ) : null}
      {snapshot && !snapshot.readiness.localReady ? (
        <ul>
          {snapshot.readiness.blockers.map((blocker) => (
            <li key={blocker}>{blockerMessages[blocker]}</li>
          ))}
        </ul>
      ) : null}
      {context && !context.enabled ? <p>Перевод выключен сервером. Оригинал остаётся доступен.</p> : null}
      <p id={disclosureId}>
        Сохранённое разрешение аккаунта запускает один перевод при открытии: заголовок и описание только
        выбранной оценки — указанным выше модели и провайдеру. Не весь отчёт и не история чата. Бесплатность и
        бюджет указаны выше; платной замены и автоматического повтора после ошибки нет. «Повторить перевод»
        разрешает один новый запрос с повторной проверкой источника и условий.
      </p>
      {authorized && message && !result ? (
        <button
          type="button"
          className="scan-a1__link"
          aria-describedby={`${disclosureId} ${disclosureId}-policy`}
          disabled={!ready}
          onClick={() => void operate('translate', snapshot, false, true)}
        >
          Повторить перевод
        </button>
      ) : null}
      {pending ? (
        <>
          <p role="status">Проверяем условия или ожидаем полный проверенный перевод…</p>
          <button
            type="button"
            className="scan-a1__link"
            onClick={() => {
              clear();
              setMessage(translationErrorMessage(new TranslationError('ABORTED')));
            }}
          >
            Отменить ожидание перевода
          </button>
        </>
      ) : null}
      {message ? <p role="alert">{message}</p> : null}
      {result ? (
        <div>
          <p>Машинный перевод на русский · не официальный текст NVD или БДУ. Сверяйте с оригиналом.</p>
          <div role="group" aria-label="Отображение перевода">
            <button
              type="button"
              className="scan-a1__link"
              aria-pressed={!showTranslation}
              onClick={() => setShowTranslation(false)}
            >
              Оригинал
            </button>
            <button
              type="button"
              className="scan-a1__link"
              aria-pressed={showTranslation}
              onClick={() => setShowTranslation(true)}
            >
              Перевод
            </button>
          </div>
          {showTranslation ? (
            <div style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
              {result.translation.title !== null ? (
                <p>
                  <strong>Перевод заголовка: </strong>
                  {result.translation.title}
                </p>
              ) : null}
              {result.translation.description !== null ? (
                <p>
                  <strong>Перевод описания: </strong>
                  {result.translation.description}
                </p>
              ) : null}
              <p>
                {result.provider} · {result.model} · {result.generatedAt}
              </p>
            </div>
          ) : (
            <p>Показан оригинальный текст источника выше.</p>
          )}
          {assessment.title.state === 'truncated' || assessment.description.state === 'truncated' ? (
            <p>Исходный текст сокращён; перевод не восстанавливает пропущенное.</p>
          ) : null}
          {assessment.title.redacted || assessment.description.redacted ? (
            <p>Скрытые поля не переводились и не восстанавливались.</p>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
