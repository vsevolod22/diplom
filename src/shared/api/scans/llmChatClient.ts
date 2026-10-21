import { z } from 'zod';
import { scanSession, subscribeScanSession } from '@/shared/api/auth/scanSession';
import { BROWSER_SCANS_PATH } from './scanTransport';
import { usageSchema } from './llmUsageClient';
import {
  CHAT_DELIVERY,
  createChatFrameParser,
  chatBindingSchema,
  chatContextSchema,
  chatHistorySchema,
  chatReadinessSchema,
  chatResultSchema,
  duplicateSchema,
  sameChatBinding,
  validChatText,
  type ChatBinding,
  type ChatContext,
} from './llmChatContract';
import { assertPlainWire, serializedBytes } from './vulnAdvisory';

export class ChatError extends Error {
  constructor(readonly code: string) {
    super('Чат недоступен');
  }
}
export function chatErrorMessage(error: unknown) {
  const code = error instanceof ChatError ? error.code : '';
  if (code === 'SESSION')
    return 'Сессия изменилась или истекла. История и согласие скрыты; войдите и откройте чат заново.';
  if (code === 'ACCESS')
    return 'Доступ к чату этого отчёта не подтверждён. История скрыта; проверьте аккаунт и разрешение на отчёт.';
  if (['STALE', 'LLM_STALE_REPORT', 'LLM_STALE_POLICY', 'LLM_HISTORY_CONFLICT'].includes(code))
    return 'Отчёт, политика или ревизия истории изменились. Обновите историю и подтвердите согласие заново.';
  if (['TIMEOUT', 'ABORTED', 'LLM_REQUEST_ABORTED', 'LLM_PROVIDER_TIMEOUT'].includes(code))
    return 'Ожидание остановлено. Передача уже могла начаться, а ответ — сохраниться. Сначала обновите историю; автоматического повтора и возврата квоты нет.';
  if (['LLM_QUOTA_EXCEEDED', 'LLM_BUDGET_EXCEEDED', 'LLM_CAPACITY'].includes(code))
    return 'Достигнут лимит запросов или квоты. Исходные findings и coverage остаются в отчёте.';
  if (['LLM_CONTEXT_LIMIT', 'LLM_HISTORY_CAPACITY'].includes(code))
    return 'Обязательный контекст или история не помещаются. Подтверждённые решения не удалены; запрос не повторяется автоматически.';
  if (code === 'LLM_CONFIGURATION_UNAVAILABLE')
    return 'Серверный ключ или политика провайдера не настроены либо чат выключен. Точная причина не раскрывается; не вводите API-ключ в вопрос. Исходный отчёт сохранён.';
  if (['LLM_PROVIDER_UNAVAILABLE', 'LLM_UNAVAILABLE'].includes(code))
    return 'Провайдер недоступен или не вернул проверенный полный ответ. Сначала обновите историю: запрос уже мог быть учтён. Автоматического повтора нет; исходный отчёт сохранён.';
  if (code === 'LLM_HISTORY_UNAVAILABLE')
    return 'Хранилище истории недоступно. Доступность провайдера не подтверждена; исходный отчёт сохранён.';
  if (['LLM_REPORT_UNAVAILABLE', 'REPORT_UNAVAILABLE'].includes(code))
    return 'Контекст этого отчёта недоступен или не поддерживается чатом. Это не означает отсутствие находок; исходный отчёт остаётся отдельно.';
  if (code === 'LLM_NO_EVIDENCE')
    return 'Нет подтверждённых источников для ответа. Непроверенное покрытие не означает ноль проблем; запрос не повторяется автоматически.';
  if (code === 'DUPLICATE')
    return 'Запрос уже зарегистрирован. Ответ не переотправлен; обновите историю вручную. Новая генерация и возврат квоты не заявлены.';
  if (code === 'INPUT')
    return 'Текст должен быть непустым, до 2048 UTF-8 байт, без URL, секретов и управляющих символов.';
  return 'Не удалось безопасно прочитать ответ. Обновите историю перед новым запросом; исходный отчёт сохранён.';
}

export function createChatClient(session = scanSession(), fetcher: typeof fetch = fetch) {
  const current = () => {
    const now = scanSession();
    return !!session.subject && now.subject === session.subject && now.generation === session.generation;
  };
  async function request(
    scanId: string,
    endpoint: string,
    limit: number,
    signal: AbortSignal,
    body?: object,
    framing?: { context: ChatContext; mutationId: string },
  ): Promise<unknown> {
    if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(scanId))
      throw new ChatError('INVALID');
    if (!current()) throw new ChatError('SESSION');
    if (body && serializedBytes(body) > 8192) throw new ChatError('INPUT');
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
        reject(new ChatError(!current() ? 'SESSION' : timedOut ? 'TIMEOUT' : 'ABORTED'));
      };
      controller.signal.addEventListener('abort', stop, { once: true });
      if (controller.signal.aborted) stop();
    });
    const operation = async () => {
      if (controller.signal.aborted) throw new ChatError('ABORTED');
      const response = await fetcher(`${BROWSER_SCANS_PATH}/${scanId}/llm/${endpoint}`, {
        method: body ? 'POST' : 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        headers: body
          ? { 'Content-Type': 'application/json', ...(framing ? { Accept: 'application/x-ndjson' } : {}) }
          : undefined,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      if (
        !current() ||
        controller.signal.aborted ||
        response.status === 401 ||
        response.status === 403 ||
        response.status === 404
      ) {
        void response.body?.cancel().catch(() => {});
        throw new ChatError(
          !current() || response.status === 401
            ? 'SESSION'
            : controller.signal.aborted
              ? 'ABORTED'
              : response.status === 403
                ? 'ACCESS'
                : 'REPORT_UNAVAILABLE',
        );
      }
      const length = response.headers.get('content-length');
      const framed = !!framing && response.ok;
      const cap = response.ok ? limit : 8192;
      if (
        !current() ||
        controller.signal.aborted ||
        response.redirected ||
        !(framed ? /^application\/x-ndjson(?:;|$)/i : /^application\/json(?:;|$)/i).test(
          response.headers.get('content-type') ?? '',
        ) ||
        (length !== null && (!/^\d+$/.test(length) || Number(length) > cap))
      ) {
        void response.body?.cancel().catch(() => {});
        throw new ChatError('INVALID');
      }
      reader = response.body?.getReader();
      if (!reader) throw new ChatError('INVALID');
      const chunks: Uint8Array[] = [];
      const frames = framed ? createChatFrameParser(framing!.context, framing!.mutationId) : null;
      const line = new Uint8Array(CHAT_DELIVERY.lineBytes);
      let lineSize = 0,
        size = 0;
      for (;;) {
        const part = await reader.read();
        if (!current() || controller.signal.aborted) throw new ChatError('STALE');
        if (part.done) break;
        size += part.value.byteLength;
        if (size > cap) throw new ChatError('INVALID');
        if (!frames) chunks.push(part.value);
        else
          for (const byte of part.value) {
            if (byte === 10) {
              if (!lineSize) throw new ChatError('INVALID');
              const value: unknown = JSON.parse(
                new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(line.subarray(0, lineSize)),
              );
              assertPlainWire(value);
              frames.accept(value);
              lineSize = 0;
            } else {
              if (lineSize >= CHAT_DELIVERY.lineBytes - 1) throw new ChatError('INVALID');
              line[lineSize++] = byte;
            }
          }
      }
      if (length !== null && Number(length) !== size) throw new ChatError('INVALID');
      if (frames) {
        if (lineSize) throw new ChatError('INVALID');
        const value = frames.finish();
        if ('errorCode' in value) throw new ChatError(value.errorCode);
        return value;
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
      }
      const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      assertPlainWire(value);
      if (!current() || controller.signal.aborted) throw new ChatError('SESSION');
      if (!response.ok) {
        const error = z.object({ errorCode: z.string().regex(/^[A-Z_]{1,64}$/) }).safeParse(value);
        throw new ChatError(error.success ? error.data.errorCode : 'UNAVAILABLE');
      }
      return value;
    };
    try {
      return await Promise.race([operation(), stopped]);
    } catch (error) {
      throw error instanceof ChatError ? error : new ChatError('INVALID');
    } finally {
      clearTimeout(timer);
      unsubscribe();
      signal.removeEventListener('abort', abort);
      controller.abort();
      void reader?.cancel().catch(() => {});
    }
  }
  const bound = <T extends ChatBinding>(value: T, binding: ChatBinding) => {
    if (!sameChatBinding(value, binding) || !current()) throw new ChatError('STALE');
    return value;
  };
  return {
    current,
    async readiness(scanId: string, signal: AbortSignal) {
      const value = chatReadinessSchema.parse(await request(scanId, 'readiness', 8192, signal));
      if (value.scanId !== scanId) throw new ChatError('STALE');
      return value;
    },
    async context(scanId: string, signal: AbortSignal) {
      const value = chatContextSchema.parse(await request(scanId, 'chat/context', 8192, signal));
      if (value.scanId !== scanId) throw new ChatError('STALE');
      return value;
    },
    async history(binding: ChatBinding, signal: AbortSignal) {
      return bound(
        chatHistorySchema.parse(await request(binding.scanId, 'history', 524288, signal)),
        binding,
      );
    },
    async usage(binding: ChatBinding, signal: AbortSignal) {
      const raw = await request(binding.scanId, 'chat/usage', 16384, signal);
      // Reuse TASK15's exact counters/arithmetic validator, not its endpoint or admission promises.
      const wire = z.object({ available: z.boolean() }).parse(raw);
      const unavailable = !wire.available
        ? z
            .strictObject({
              ...chatBindingSchema.shape,
              available: z.literal(false),
              admission: z.strictObject({ status: z.literal('unavailable') }),
            })
            .parse(raw)
        : null;
      const value = usageSchema.parse(
        unavailable
          ? {
              scanId: unavailable.scanId,
              digest: unavailable.digest,
              platform: unavailable.platform,
              reportVersion: unavailable.reportVersion,
              available: false,
              reason: 'unavailable',
              integrationEnabled: true,
              quotaEnabled: true,
            }
          : { ...(raw as object), integrationEnabled: true, quotaEnabled: true },
      );
      if (value.available && value.admission.status !== 'unavailable') throw new ChatError('INVALID');
      return bound(value, binding);
    },
    async chat(context: ChatContext, question: string, mutationId: string, signal: AbortSignal) {
      if (!context.enabled || !context.policyVersion || context.pending) throw new ChatError('STALE');
      if (!validChatText(question)) throw new ChatError('INPUT');
      const value = chatResultSchema.parse(
        await request(
          context.scanId,
          'chat',
          CHAT_DELIVERY.totalBytes,
          signal,
          {
            epoch: context.epoch,
            revision: context.revision,
            mutationId,
            reportVersion: context.reportVersion,
            question,
            consent: { accepted: true, policyVersion: context.policyVersion },
          },
          { context, mutationId },
        ),
      );
      if ('duplicate' in value) throw new ChatError('DUPLICATE');
      if (value.epoch !== context.epoch || value.revision !== context.revision + 2)
        throw new ChatError('STALE');
      return bound(value, context);
    },
    async decision(
      context: ChatContext,
      text: string,
      findingIds: string[],
      mutationId: string,
      signal: AbortSignal,
    ) {
      if (!validChatText(text) || findingIds.length > 32 || new Set(findingIds).size !== findingIds.length)
        throw new ChatError('INPUT');
      const value = z.union([chatHistorySchema, duplicateSchema]).parse(
        await request(context.scanId, 'history/decision', 524288, signal, {
          epoch: context.epoch,
          revision: context.revision,
          mutationId,
          reportVersion: context.reportVersion,
          text,
          findingIds,
        }),
      );
      if (
        value.epoch !== context.epoch ||
        value.revision < context.revision ||
        (!('duplicate' in value) && value.revision !== context.revision + 1)
      )
        throw new ChatError('STALE');
      return 'duplicate' in value ? value : bound(value, context);
    },
  };
}
export type ChatClient = ReturnType<typeof createChatClient>;
