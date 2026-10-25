import { scanSession, subscribeScanSession } from '@/shared/api/auth/scanSession';
import { BROWSER_SCANS_PATH } from './scanTransport';
import { ChatError, createChatClient } from './llmChatClient';
import { chatBindingSchema } from './llmChatContract';
import { assertPlainWire } from './vulnAdvisory';
import {
  llmJsonErrorSchema,
  providerFailureDetails,
  providerFailureSchema,
  validLlmErrorStatus,
  type ProviderFailure,
} from './llmPublicContract';
import {
  sameTranslationBinding,
  translationContextSchema,
  translationReplySchema,
  translationRequestSchema,
  translationSelectionSchema,
  type TranslationContext,
  type TranslationSelection,
} from './advisoryTranslationContract';

export class TranslationError extends Error {
  readonly providerFailure?: ProviderFailure;
  constructor(
    readonly code: string,
    providerFailure?: ProviderFailure,
  ) {
    super('Перевод недоступен');
    this.providerFailure =
      providerFailure === undefined ? undefined : providerFailureSchema.parse(providerFailure);
  }
}
export function translationErrorMessage(error: unknown) {
  const code = error instanceof TranslationError ? error.code : '';
  if (code === 'SESSION') return 'Сессия изменилась. Перевод и согласие сброшены; откройте условия заново.';
  if (code === 'ACCESS') return 'Доступ к переводу этого отчёта не подтверждён. Оригинал не изменён.';
  if (['STALE', 'LLM_STALE_REPORT', 'LLM_STALE_POLICY', 'LLM_STALE_SOURCE'].includes(code))
    return 'Отчёт, источник или политика изменились. Обновите условия и подтвердите согласие заново.';
  if (code === 'LLM_CONFIGURATION_UNAVAILABLE')
    return 'Перевод недоступен: ИИ выключен или серверная настройка не подтверждена. Не вводите ключи в интерфейс.';
  const providerDetails =
    error instanceof TranslationError ? providerFailureDetails(error.providerFailure) : '';
  if (code === 'LLM_PROVIDER_RATE_LIMITED')
    return (
      'Провайдер занят или ограничил частоту запросов.' +
      providerDetails +
      ' Оригинал не изменён; автоматического повтора нет, возврат квоты не гарантирован. Повтор — только вручную после чтения условий и нового согласия.'
    );
  if (code === 'LLM_PROVIDER_AUTH_FAILED')
    return (
      'Провайдер отклонил серверный ключ. Обратитесь к оператору; не вводите ключ в интерфейс.' +
      providerDetails +
      ' Оригинал не изменён; автоматического повтора нет, возврат квоты не гарантирован. Новый запрос требует чтения условий и нового согласия.'
    );
  if (code === 'LLM_PROVIDER_UNAVAILABLE')
    return (
      'Провайдер недоступен или не вернул проверенный полный перевод.' +
      providerDetails +
      ' Оригинал не изменён; автоматического повтора нет. Обновите условия перед новым запросом.'
    );
  if (['LLM_QUOTA_EXCEEDED', 'LLM_BUDGET_EXCEEDED', 'LLM_CAPACITY'].includes(code))
    return 'Достигнут лимит запросов или квоты. Оригинал доступен; автоматического повтора нет.';
  if (['TIMEOUT', 'ABORTED', 'LLM_REQUEST_ABORTED', 'LLM_PROVIDER_TIMEOUT'].includes(code))
    return 'Ожидание перевода остановлено. Передача уже могла начаться; возврат квоты не гарантирован. Повтор — только вручную после нового согласия.';
  return 'Не удалось безопасно получить перевод. Оригинал не изменён; автоматического повтора нет. Обновите условия перед новым запросом.';
}

export function createAdvisoryTranslationClient(session = scanSession(), fetcher: typeof fetch = fetch) {
  const chat = createChatClient(session, fetcher);
  const current = chat.current;
  async function request(
    scanId: string,
    endpoint: string,
    signal: AbortSignal,
    body?: object,
  ): Promise<unknown> {
    if (!chatBindingSchema.shape.scanId.safeParse(scanId).success) throw new TranslationError('INVALID');
    if (!current()) throw new TranslationError('SESSION');
    const controller = new AbortController();
    let timedOut = false;
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    const abort = () => controller.abort();
    const unsubscribe = subscribeScanSession(abort);
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    const timer = setTimeout(() => {
      timedOut = true;
      abort();
    }, 40_000);
    const stopped = new Promise<never>((_, reject) => {
      const stop = () => {
        void reader?.cancel().catch(() => {});
        reject(new TranslationError(!current() ? 'SESSION' : timedOut ? 'TIMEOUT' : 'ABORTED'));
      };
      controller.signal.addEventListener('abort', stop, { once: true });
      if (controller.signal.aborted) stop();
    });
    const operation = async () => {
      if (controller.signal.aborted) throw new TranslationError('ABORTED');
      const response = await fetcher(`${BROWSER_SCANS_PATH}/${scanId}/llm/${endpoint}`, {
        method: body ? 'POST' : 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      if (!current() || controller.signal.aborted || [401, 403, 404].includes(response.status)) {
        void response.body?.cancel().catch(() => {});
        throw new TranslationError(
          !current() || response.status === 401 ? 'SESSION' : response.status === 403 ? 'ACCESS' : 'STALE',
        );
      }
      const limit = response.ok ? 65536 : 8192;
      const length = response.headers.get('content-length');
      if (
        response.redirected ||
        !/^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? '') ||
        (length !== null && (!/^\d+$/.test(length) || Number(length) > limit))
      ) {
        void response.body?.cancel().catch(() => {});
        throw new TranslationError('INVALID');
      }
      reader = response.body?.getReader();
      if (!reader) throw new TranslationError('INVALID');
      const chunks: Uint8Array[] = [];
      let size = 0;
      for (;;) {
        const part = await reader.read();
        if (!current() || controller.signal.aborted) throw new TranslationError('SESSION');
        if (part.done) break;
        size += part.value.byteLength;
        if (size > limit) throw new TranslationError('INVALID');
        chunks.push(part.value);
      }
      if (length !== null && Number(length) !== size) throw new TranslationError('INVALID');
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
      }
      const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      assertPlainWire(value);
      if (!current() || controller.signal.aborted) throw new TranslationError('SESSION');
      if (!response.ok) {
        const error = llmJsonErrorSchema.safeParse(value);
        if (!error.success || !validLlmErrorStatus(error.data, response.status))
          throw new TranslationError('INVALID');
        throw new TranslationError(error.data.errorCode, error.data.providerFailure);
      }
      return value;
    };
    try {
      return await Promise.race([operation(), stopped]);
    } catch (error) {
      throw error instanceof TranslationError ? error : new TranslationError('INVALID');
    } finally {
      clearTimeout(timer);
      unsubscribe();
      signal.removeEventListener('abort', abort);
      controller.abort();
      void reader?.cancel().catch(() => {});
    }
  }
  return {
    current,
    async readiness(scanId: string, signal: AbortSignal) {
      try {
        return await chat.readiness(scanId, signal);
      } catch (error) {
        throw error instanceof ChatError
          ? new TranslationError(error.code, error.providerFailure)
          : new TranslationError('INVALID');
      }
    },
    async context(scanId: string, selection: TranslationSelection, signal: AbortSignal) {
      const selected = translationSelectionSchema.parse(selection);
      const query = new URLSearchParams({
        findingId: selected.findingId,
        assessmentIndex: String(selected.assessmentIndex),
      });
      const value = translationContextSchema.parse(
        await request(scanId, `translation/context?${query}`, signal),
      );
      if (
        value.scanId !== scanId ||
        value.findingId !== selected.findingId ||
        value.assessmentIndex !== selected.assessmentIndex
      )
        throw new TranslationError('STALE');
      return value;
    },
    async translate(
      context: TranslationContext,
      consent: { accepted: true; policyVersion: string },
      signal: AbortSignal,
    ) {
      const accepted = translationContextSchema.parse(context);
      if (!accepted.enabled || !accepted.policyVersion || consent.policyVersion !== accepted.policyVersion)
        throw new TranslationError('LLM_CONFIGURATION_UNAVAILABLE');
      const body = translationRequestSchema.parse({
        reportVersion: accepted.reportVersion,
        findingId: accepted.findingId,
        assessmentIndex: accepted.assessmentIndex,
        sourceVersion: accepted.sourceVersion,
        targetLanguage: 'ru',
        consent,
      });
      const result = translationReplySchema.parse(
        await request(accepted.scanId, 'translation', signal, body),
      );
      if (
        !sameTranslationBinding(result, accepted) ||
        result.model !== accepted.disclosure?.model ||
        result.provider !== accepted.disclosure.provider
      )
        throw new TranslationError('STALE');
      return result;
    },
  };
}
export type AdvisoryTranslationClient = ReturnType<typeof createAdvisoryTranslationClient>;
