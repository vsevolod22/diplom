import { z } from 'zod';
import { assertPlainWire } from './vulnAdvisory';

const stage = z.enum(['inspection', 'download', 'decode', 'archive', 'scan']);
const resource = z.enum([
  'layers',
  'layer_bytes',
  'download_bytes',
  'expanded_bytes',
  'file_bytes',
  'entries',
  'scratch_bytes',
  'requests',
  'output_bytes',
]);

export const imageFailureDetailSchema = z
  .discriminatedUnion('reason', [
    z.strictObject({
      reason: z.enum([
        'IMAGE_NOT_ACCESSIBLE',
        'PLATFORM_UNSUPPORTED',
        'FORMAT_UNSUPPORTED',
        'IMAGE_INVALID',
        'INTEGRITY_FAILED',
        'ARCHIVE_UNSAFE',
        'REGISTRY_RATE_LIMITED',
        'REGISTRY_UNAVAILABLE',
        'DEADLINE_EXCEEDED',
        'SCANNER_FAILED',
      ]),
      stage,
    }),
    z
      .strictObject({ reason: z.literal('RESOURCE_LIMIT'), stage, resource: resource.optional() })
      .refine(
        (detail) => !Object.hasOwn(detail, 'resource') || detail.resource !== undefined,
        'Invalid image failure resource',
      ),
  ])
  .readonly();

export type ImageFailureDetail = z.infer<typeof imageFailureDetailSchema>;
export type ImageFailurePresentation = Readonly<{
  title: string;
  description: string;
  nextStep: string;
  stageLabel: string;
}>;

/** Decode a present failureDetail. Callers handle absence; malformed evidence must not be silently accepted. */
export function parseImageFailureDetail(value: unknown): ImageFailureDetail {
  assertPlainWire(value);

  return imageFailureDetailSchema.parse(value);
}

const stages: Record<ImageFailureDetail['stage'], string> = {
  inspection: 'Проверка образа',
  download: 'Загрузка образа',
  decode: 'Чтение формата',
  archive: 'Распаковка файлов',
  scan: 'Анализ файлов',
};
const messages: Record<ImageFailureDetail['reason'], Omit<ImageFailurePresentation, 'stageLabel'>> = {
  IMAGE_NOT_ACCESSIBLE: {
    title: 'Образ недоступен',
    description: 'Не удалось получить выбранный образ из Docker Hub.',
    nextStep:
      'Проверьте название и тег, а также публичность репозитория. Пароль или токен вводить не нужно: приватные образы не поддерживаются.',
  },
  PLATFORM_UNSUPPORTED: {
    title: 'Платформа не поддерживается',
    description: 'Выбранная сборка не подходит для проверки Linux (amd64).',
    nextStep: 'Выберите тег, у которого есть сборка для Linux (amd64).',
  },
  FORMAT_UNSUPPORTED: {
    title: 'Формат образа не поддерживается',
    description: 'Сервис не может прочитать формат этой сборки.',
    nextStep: 'Выберите другую сборку образа. Повтор той же версии не меняет её формат.',
  },
  IMAGE_INVALID: {
    title: 'Образ не удалось прочитать',
    description: 'Структура или метаданные образа не прошли проверку.',
    nextStep: 'Проверьте другую версию или пересоберите свой образ перед новой попыткой.',
  },
  INTEGRITY_FAILED: {
    title: 'Целостность образа не подтверждена',
    description: 'Полученные данные не совпали с заявленным содержимым образа.',
    nextStep: 'Не считайте эту сборку проверенной. Уточните её происхождение и выберите проверенную версию.',
  },
  ARCHIVE_UNSAFE: {
    title: 'Распаковка остановлена',
    description: 'Структура архива не прошла безопасную проверку. Это не результат поиска уязвимостей.',
    nextStep: 'Выберите другую сборку или проверьте способ упаковки своего образа.',
  },
  RESOURCE_LIMIT: {
    title: 'Образ превысил ограничения проверки',
    description: 'Для обработки образа потребовалось больше ресурсов, чем разрешено сервисом.',
    nextStep:
      'Выберите меньшую сборку или сократите её содержимое. Повтор без изменения образа может закончиться так же.',
  },
  REGISTRY_RATE_LIMITED: {
    title: 'Docker Hub временно ограничил запросы',
    description: 'Сервис не смог продолжить получение образа из-за ограничения частоты запросов.',
    nextStep:
      'Дождитесь окончания указанного ожидания, если оно показано, и повторите вручную позже. Не запускайте несколько повторов подряд.',
  },
  REGISTRY_UNAVAILABLE: {
    title: 'Docker Hub сейчас недоступен',
    description: 'Не удалось завершить обмен с хранилищем образов.',
    nextStep: 'Проверьте результат в списке проверок и повторите вручную позже, если это необходимо.',
  },
  DEADLINE_EXCEEDED: {
    title: 'Время проверки истекло',
    description: 'Обработку не удалось завершить за отведённое время.',
    nextStep:
      'Проверьте доступные результаты. Для новой попытки можно выбрать меньший образ; повтор не гарантирует завершение.',
  },
  SCANNER_FAILED: {
    title: 'Анализ не завершён',
    description: 'Сканер не смог закончить обработку образа.',
    nextStep:
      'Проверьте, какие результаты успели появиться в отчёте. При повторной ошибке сохраните адрес проверки для разбора.',
  },
};
const resourceMessages: Record<z.infer<typeof resource>, string> = {
  layers: 'В образе слишком много слоёв.',
  layer_bytes: 'Один из сжатых слоёв слишком большой.',
  download_bytes: 'Превышен общий объём загрузки образа.',
  expanded_bytes: 'Содержимое образа после распаковки слишком велико.',
  file_bytes: 'Один из файлов превышает допустимый размер.',
  entries: 'В образе слишком много записей файловой системы.',
  scratch_bytes: 'Превышен лимит временного дискового пространства для проверки.',
  requests: 'Для получения образа потребовалось слишком много запросов.',
  output_bytes: 'Объём результатов анализа превысил допустимый предел.',
};

/** Only fixed copy derived from validated server codes; never display upstream text or infer success. */
export function presentImageFailure(value: ImageFailureDetail): ImageFailurePresentation {
  const detail = parseImageFailureDetail(value);
  return Object.freeze({
    ...messages[detail.reason],
    ...(detail.reason === 'RESOURCE_LIMIT' && detail.resource
      ? { description: resourceMessages[detail.resource] }
      : {}),
    stageLabel: stages[detail.stage],
  });
}
