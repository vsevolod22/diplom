import { useEffect, useId, useState } from 'react';
import type { ScanStatus } from '@/shared/api/scans/scanTransport';
import { useLiveScanSession } from './liveScanContext';
import { estimateScanProgress } from './scanProgressEstimate';
import { stateLabels } from './scanStateLabels';
import './ScanProgressPanel.css';

type Props = { scan: ScanStatus; compact?: boolean };

export function ScanProgressPanel(props: Props) {
  const session = useLiveScanSession();
  // No cross-scan, owner or login-session memory, even when a parent reuses us.
  return <ObservedScanProgress key={JSON.stringify([session?.scope, props.scan.scanId])} {...props} />;
}

function ObservedScanProgress({ scan, compact = false }: Props) {
  const descriptionId = useId();
  const [sample, setSample] = useState(() => ({
    scan,
    estimate: estimateScanProgress(scan, performance.now()),
  }));
  let current = sample;
  if (sample.scan !== scan) {
    current = { scan, estimate: estimateScanProgress(scan, performance.now(), sample.estimate) };
    setSample(current);
  }
  const running = scan.state === 'running';
  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => {
      setSample((previous) => ({
        scan: previous.scan,
        estimate: estimateScanProgress(previous.scan, performance.now(), previous.estimate),
      }));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [running]);

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
  const serverPercent =
    running &&
    !progress &&
    typeof scan.percent === 'number' &&
    current.estimate.percent === scan.percent &&
    scan.percent < 100;
  const percent =
    current.estimate.percent === null
      ? null
      : serverPercent
        ? current.estimate.percent
        : Math.floor(current.estimate.percent);
  const percentText =
    scan.state === 'completed'
      ? 'Прогресс: 100% — завершение подтверждено сервером.'
      : percent === null
        ? 'Выполнение не подтверждено; оценка до остановки отсутствует.'
        : serverPercent
          ? `Прогресс: ${percent}% по данным сервера.`
          : `Оценка прогресса: ≈${percent}%${active ? '' : ' на момент остановки'}.`;
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
          value={percent ?? 0}
          aria-label={`Прогресс сканирования ${scan.scanId}`}
          aria-describedby={descriptionId}
          aria-valuetext={`${percentText} ${counts} Точное оставшееся время неизвестно.`}
        />
      ) : (
        <p className="scan-progress-panel__outcome">Итог скана: {stateLabels[scan.state]}</p>
      )}
      <span className="scan-progress-panel__percent">{percentText}</span>
      <div id={descriptionId} className="scan-progress-panel__description">
        <p>{counts}</p>
        {hasCheckSnapshot ? (
          <p>
            {active ? 'Без подтверждённого итога' : 'Без сохранённого итога'}: {remaining}.
            {active && remaining === 0 ? ' Ожидаем итоговый статус скана.' : ''}
          </p>
        ) : null}
        {active ? (
          <>
            <p>
              Эвристика наблюдаемого скана, не измерение текущей попытки. Точное оставшееся время неизвестно.
              {scan.state === 'queued' ? ' Время очереди не считается выполнением.' : ''}
              {scan.state === 'cancelling' ? ' Оценка приостановлена: ожидаем подтверждение отмены.' : ''}
            </p>
            {compact ? (
              <p>
                Внутренний повтор без изменения итогов не распознаётся. Без новых данных оценка тоже может
                расти.
                {requested.length === 0 ? ' Набор проверок неизвестен; используется общая модель.' : ''}
              </p>
            ) : (
              <details>
                <summary>Как считается оценка</summary>
                <p>
                  Время наблюдения и сохранённые итоги учитываются с разными весами: загрузка образа и анализ
                  уязвимостей весят больше проверки конфигурации. Это не доля успешных проверок и не гарантия
                  безопасности.
                </p>
                <p>
                  Внутренний повтор без изменения итогов не распознаётся: сервер не сообщает номер попытки.
                  Без новых данных оценка тоже может расти; это не подтверждение выполнения. При потере
                  сохранённых итогов или снижении числа выполненных проверок наблюдение сбрасывается.
                </p>
                <p>
                  Наблюдение только в этой панели и сессии; после ухода или перезагрузки начинается заново.
                  {requested.length === 0 ? ' Набор проверок неизвестен; используется общая модель.' : ''}
                </p>
              </details>
            )}
          </>
        ) : (
          <p>Скан больше не выполняется. Отсутствующие итоги не считаются успешными проверками.</p>
        )}
      </div>
    </div>
  );
}
