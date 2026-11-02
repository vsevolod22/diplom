import type { ScanCheck, ScanStatus } from '@/shared/api/scans/scanTransport';

export const scanCheckLabels: Record<ScanCheck, string> = {
  secret: 'Поиск секретов',
  sbom: 'Состав пакетов (SBOM)',
  vuln: 'Уязвимости',
  config: 'Конфигурация образа',
};

/** Only the current snapshot supplies visible counts; remembered estimates are not evidence. */
export function scanCheckSnapshot(scan: ScanStatus) {
  const requested = [
    ...new Set(scan.progress?.requestedChecks ?? scan.checks ?? (scan.check ? [scan.check] : [])),
  ];
  const entries = requested.map((check) => {
    const published = scan.perCheck?.[check];
    const result = published?.check === check ? published : undefined;
    const outcome = scan.progress ? (scan.progress.outcomes[check] ?? null) : (result?.outcome ?? null);
    return { check, outcome, result: result?.outcome === outcome ? result : undefined };
  });
  const known = requested.length > 0 && (scan.progress !== undefined || scan.perCheck !== undefined);
  return {
    requested,
    entries,
    known,
    resolved: known ? entries.filter((item) => item.outcome !== null).length : null,
    checked: known ? entries.filter((item) => item.outcome === 'checked').length : null,
  };
}

type ProgressDisplay = {
  source: 'completed' | 'server' | 'unknown';
  percent: number | null;
  awaitingCompletion: boolean;
};

export function scanProgressPresentation(
  scan: ScanStatus,
  estimate: number | null = null,
  compact = false,
): ProgressDisplay {
  // Retain the call signature, but neither elapsed estimates nor layout can prove work.
  void estimate;
  void compact;
  if (scan.state === 'completed') return { source: 'completed', percent: 100, awaitingCompletion: false };
  if (
    (scan.state === 'running' || scan.state === 'cancelling') &&
    !scan.progress &&
    typeof scan.percent === 'number' &&
    Number.isFinite(scan.percent) &&
    scan.percent >= 0 &&
    scan.percent <= 100
  ) {
    // A number cannot override the lifecycle. Do not invent 99% to reconcile conflicting data.
    return scan.percent === 100
      ? { source: 'unknown', percent: null, awaitingCompletion: true }
      : { source: 'server', percent: scan.percent, awaitingCompletion: false };
  }
  const snapshot = scanCheckSnapshot(scan);
  return {
    source: 'unknown',
    percent: null,
    awaitingCompletion: scan.state === 'running' && snapshot.known && snapshot.resolved === snapshot.requested.length,
  };
}

export function scanExecutionLabel(scan: ScanStatus): string {
  if (scan.state === 'queued') return 'В очереди';
  if (scan.state === 'cancelling') return 'Отменяем проверку';
  if (scan.state === 'completed') return 'Сканирование завершено';
  if (scan.state === 'partial') return 'Завершено с неполными результатами';
  if (scan.state === 'failed') return 'Сканирование завершилось с ошибкой';
  if (scan.state === 'cancelled') return 'Сканирование отменено';
  const snapshot = scanCheckSnapshot(scan);
  if (snapshot.known && snapshot.resolved === snapshot.requested.length)
    return 'Результаты получены · ожидаем завершения';
  // Missing outcomes do not establish which check or acquisition step is running.
  return scan.stage ? scanStageLabel(scan.stage) : 'Проверка продолжается';
}

export function scanStageLabel(stage?: string) {
  const name = stage?.trim();
  if (!name) return 'Проверка продолжается';
  return Object.hasOwn(scanCheckLabels, name)
    ? scanCheckLabels[name as ScanCheck]
    : 'Проверка продолжается';
}

const reasonLabels: Record<string, string> = {
  SCAN_FAILED: 'Не удалось выполнить проверку',
  SCAN_TIMEOUT: 'Превышено время выполнения проверки',
  SCAN_UNAVAILABLE: 'Сканер недоступен',
  DB_UNAVAILABLE: 'База уязвимостей недоступна',
  OS_EOL: 'Версия операционной системы больше не поддерживается',
  OS_UNKNOWN: 'Операционная система не определена',
  NODE_INVENTORY_ABSENT: 'Сведения о пакетах Node.js отсутствуют',
  NODE_INVENTORY_UNKNOWN: 'Состав пакетов Node.js не определён',
  CHECK_DISABLED: 'Проверка не была включена',
  USER_NOT_RESOLVABLE: 'Не удалось определить пользователя образа',
  OCI_IDENTITY_REJECTED: 'Не удалось подтвердить идентичность образа',
  CONFIG_LIMIT_EXCEEDED: 'Превышен лимит анализа конфигурации',
  INVALID_CONFIG: 'Некорректная конфигурация образа',
};
export function scanReasonLabel(reason: string) {
  return Object.hasOwn(reasonLabels, reason) ? reasonLabels[reason] : reason;
}
