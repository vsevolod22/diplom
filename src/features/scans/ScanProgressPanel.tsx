import { useId } from 'react';
import type { ScanOutcome, ScanStatus } from '@/shared/api/scans/scanTransport';
import { scanCheckLabels, scanCheckSnapshot, scanExecutionLabel, scanProgressPresentation } from './scanProgressPresentation';
import { stateLabels } from './scanStateLabels';
import { ScanCheckFailure } from './ScanCheckFailure';
import './ScanProgressPanel.css';

type Props = { scan: ScanStatus; compact?: boolean; list?: boolean };

const outcomeLabels: Record<ScanOutcome, string> = {
  checked: 'Выполнено',
  failed: 'Ошибка проверки',
  unsupported: 'Не поддерживается',
  skipped: 'Пропущено',
  not_authorized: 'Нет разрешения',
};

export function ScanProgressPanel({ scan, compact = false, list = false }: Props) {
  const descriptionId = useId();
  const active = ['queued', 'running', 'cancelling'].includes(scan.state);
  const snapshot = scanCheckSnapshot(scan);
  const { percent, source, awaitingCompletion } = scanProgressPresentation(scan);
  const percentText = source === 'completed'
    ? '100% — проверка завершена.'
    : awaitingCompletion
      ? 'Ожидаем завершения проверки.'
      : source === 'server'
        ? `Выполнено: ${percent}%.`
        : active
          ? 'Процент выполнения пока неизвестен.'
          : '';
  const terminalList = list && !active;
  const counts = terminalList ? 'Подробности в отчёте.' : snapshot.known
    ? `Получены результаты: ${snapshot.resolved} из ${snapshot.requested.length}. Выполнено проверок: ${snapshot.checked}.`
    : 'Результаты проверок пока недоступны.';

  return (
    <div
      className={`scan-progress-panel${compact ? ' scan-progress-panel--compact' : ''}`}
      role="group"
      aria-label={`Ход сканирования ${scan.scanId}`}
      data-state={scan.state}
      data-progress-source={source}
    >
      <p className="scan-progress-panel__stage">{scanExecutionLabel(scan)}</p>
      {active ? (
        <progress
          className="scan-progress-panel__bar"
          max={100}
          value={percent ?? undefined}
          aria-label={`Прогресс сканирования ${scan.scanId}`}
          aria-describedby={descriptionId}
          aria-valuetext={`${percentText} ${counts}`}
        />
      ) : (
        <p className="scan-progress-panel__outcome">Итог скана: {stateLabels[scan.state]}</p>
      )}
      {percentText ? <span className="scan-progress-panel__percent">{percentText}</span> : null}
      <div id={descriptionId} className="scan-progress-panel__description">
        <p role="status" aria-live="polite">{counts}</p>
        {!terminalList && snapshot.entries.length > 0 ? (
          <ul className="scan-progress-panel__checks" aria-label="Результаты проверок">
            {snapshot.entries.map(({ check, outcome, result }) => (
              <li key={check} className="scan-progress-panel__check" data-outcome={outcome ?? 'unknown'}>
                <span>{scanCheckLabels[check]}</span>
                <strong>{outcome !== null ? outcomeLabels[outcome]
                  : !snapshot.known ? 'Нет данных'
                    : active ? 'Ожидаем результат' : 'Нет результата'}</strong>
                {outcome === 'failed' ? (
                  <ScanCheckFailure detail={result?.failureDetail} reason={result?.reason ?? result?.errorCode} />
                ) : null}
              </li>
            ))}
          </ul>
        ) : null}
        {!terminalList ? <p>{active ? 'Оставшееся время пока неизвестно.' : 'Смотрите результаты отдельных проверок.'}</p> : null}
      </div>
    </div>
  );
}
