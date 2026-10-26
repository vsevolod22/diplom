import { useId } from 'react';
import type { ScanStatus } from '@/shared/api/scans/scanTransport';
import { stateLabels } from './scanStateLabels';
import './ScanProgressPanel.css';

type Props = { scan: ScanStatus; compact?: boolean };

export function ScanProgressPanel({ scan, compact = false }: Props) {
  const descriptionId = useId();
  const active = ['queued', 'running', 'cancelling'].includes(scan.state);
  const progress = scan.progress;
  const requested = [
    ...new Set(progress?.requestedChecks ?? scan.checks ?? (scan.check ? [scan.check] : [])),
  ];
  const hasCheckSnapshot = !!progress || (requested.length > 0 && scan.perCheck !== undefined);
  const resolved = requested.filter((check) => scan.perCheck?.[check]?.check === check);
  const resolvedCount = progress?.resolvedChecks ?? resolved.length;
  const checkedCount =
    progress?.checkedChecks ??
    resolved.filter((check) => scan.perCheck?.[check]?.outcome === 'checked').length;
  const remaining = requested.length - resolvedCount;
  const percent =
    !progress &&
    active &&
    typeof scan.percent === 'number' &&
    Number.isFinite(scan.percent) &&
    scan.percent >= 0 &&
    scan.percent <= 100
      ? scan.percent
      : undefined;
  const counts = hasCheckSnapshot
    ? `Получены итоги: ${resolvedCount} из ${requested.length}. Успешно выполнено: ${checkedCount}.`
    : 'Счётчики проверок не предоставлены сервером.';
  const stage = scan.stage?.trim() || 'не предоставлен сервером';

  return (
    <div
      className={`scan-progress-panel${compact ? ' scan-progress-panel--compact' : ''}`}
      role="group"
      aria-label={`Ход сканирования ${scan.scanId}`}
      data-state={scan.state}
    >
      <p className="scan-progress-panel__stage">Этап сканирования: {stage}</p>
      {active ? (
        <progress
          className="scan-progress-panel__bar"
          max={100}
          value={percent}
          aria-label={`Прогресс сканирования ${scan.scanId}`}
          aria-describedby={descriptionId}
          aria-valuetext={
            percent === undefined
              ? `Процент выполнения неизвестен. ${counts} Точное оставшееся время неизвестно.`
              : `${percent}% по данным сервера. ${counts} Точное оставшееся время неизвестно.`
          }
        />
      ) : (
        <p className="scan-progress-panel__outcome">Итог скана: {stateLabels[scan.state]}</p>
      )}
      <span className="scan-progress-panel__percent">
        Прогресс: {percent === undefined ? 'неизвестен' : `${percent}%`}
      </span>
      <div id={descriptionId} className="scan-progress-panel__description">
        <p>{counts}</p>
        {hasCheckSnapshot ? (
          <p>
            {active ? 'Без подтверждённого итога' : 'Без сохранённого итога'}: {remaining}.
            {active && remaining === 0 ? ' Ожидаем итоговый статус скана.' : ''}
          </p>
        ) : null}
        <p>
          {active
            ? 'Точное оставшееся время неизвестно. Полученные итоги не показывают длительность этапов.'
            : 'Скан больше не выполняется. Отсутствующие итоги не считаются успешными проверками.'}
        </p>
      </div>
    </div>
  );
}
