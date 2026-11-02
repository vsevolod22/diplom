import { useEffect, useState } from 'react';
import * as AlertDialog from '@radix-ui/react-alert-dialog';

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, CheckCircle2, CircleDashed, CircleOff, LockKeyhole, XCircle } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';


import { ScanChatPanel } from '@/features/scans/ScanChatPanel';
import { ScanSummaryPanel } from '@/features/scans/ScanSummaryPanel';
import { AdvisoryTranslationScope } from '@/features/scans/AdvisoryTranslationPanel';
import { ScanShell, controlClass } from '@/features/scans/ScanShell';
import { useLiveScanSession } from '@/features/scans/liveScanContext';

import { ScanStatusAnnouncement } from '@/features/scans/ScanStatusAnnouncement';
import { ScanProgressPanel } from '@/features/scans/ScanProgressPanel';
import { scanCheckLabels, scanCheckSnapshot, scanReasonLabel } from '@/features/scans/scanProgressPresentation';
import { stateLabels } from '@/features/scans/scanStateLabels';
import { fixtureScanTransport, unavailableScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import { ScanAccessError, ScanHttpError } from '@/shared/api/scans/httpScanTransport';
import type { ScanCoverage, ScanStatus } from '@/shared/api/scans/scanTransport';
import { Alert, Badge, Button } from '@/shared/ui/scan-primitives';
import { ScanReportSections } from './ScanReportSections';
import { ScanReportOverview } from './ScanReportOverview';
import './scan-detail-a1.css';

import { identifierCountLabel } from '@/shared/api/scans/publicVulnerabilityIdentifiers';

const unavailableScope = ['live-scans', 'unavailable'] as const;
const terminalStates = new Set<ScanStatus['state']>(['completed', 'partial', 'failed', 'cancelled']);

class StatusSnapshotGuard {
  accessFailure: ScanAccessError | null = null;
  constructor(public retainable: boolean) {}
}

function recoverableStatusError(error: unknown): boolean {
  if (error instanceof ScanAccessError) return false;
  if (error instanceof ScanHttpError) {
    // An auth-store outage does not confirm access, even when it uses HTTP 503.
    if (error.code && (/(?:^|_)(?:AUTH|AUTHENTICATION|AUTHORIZATION|SESSION|ACCESS|UNAUTHORIZED|FORBIDDEN|CREDENTIALS)(?:_|$)/i.test(error.code) || error.code === 'INVALID_ORIGIN')) return false;
    // GET status reports scanner availability as 503; unknown application codes stay fail-closed.
    if (error.code !== null) return error.status === 503 && error.code === 'SCANNER_UNAVAILABLE';
    // A proxy may return no application code; retain only for these transient server statuses.
    return [500, 502, 503, 504].includes(error.status);
  }
  // The existing transport does not type every HTTP failure. Unknown errors stay fail-closed;
  // only known browser fetch failures may preserve a previously validated snapshot.
  return error instanceof TypeError && [
    'Failed to fetch', 'Load failed', 'NetworkError when attempting to fetch resource.',
    'Network request failed', 'fetch failed',
  ].includes(error.message);
}

const coverageLabels: Record<ScanCoverage['status'], string> = {
  checked: 'Выполнено',
  failed: 'Сбой · не проверено',
  unsupported: 'Не поддерживается',
  not_authorized: 'Нет разрешения',
  skipped: 'Пропущено',
};
const coverageIcons = {
  checked: CheckCircle2,
  failed: XCircle,
  unsupported: CircleOff,
  not_authorized: LockKeyhole,
  skipped: CircleDashed,
} satisfies Record<ScanCoverage['status'], typeof CheckCircle2>;
const stateTone: Record<ScanStatus['state'], 'neutral' | 'info' | 'warning' | 'danger'> = {
  queued: 'neutral',
  running: 'info',
  cancelling: 'warning',
  completed: 'neutral',
  partial: 'warning',
  failed: 'danger',
  cancelled: 'neutral',
};

export function ScanDetailPage({ demo = false }: { demo?: boolean }) {
  const { scanId = '' } = useParams();
  const live = useLiveScanSession();
  // Remount all page state before requesting a different route, subject or session.
  return <ScanDetailContent key={JSON.stringify([demo, live?.scope, scanId])} demo={demo} />;
}

function ScanDetailContent({ demo }: { demo: boolean }) {
  const { scanId = '' } = useParams();
  const [filter, setFilter] = useState('all');
  const [coverageOpen, setCoverageOpen] = useState(false);

  const live = useLiveScanSession();
  const transport = demo ? fixtureScanTransport : live?.transport ?? unavailableScanTransport;
  const enabled = !!scanId && (demo || transport.capabilities.list);
  const queryClient = useQueryClient();
  const scope = live?.scope ?? unavailableScope;
  const streamKey = `${scope.join(':')}:${scanId}`;

  const [realtime, setRealtime] = useState<'connecting' | 'connected' | 'reconnecting' | 'polling'>('polling');
  const scanQueryKey = demo ? ['scan', 'fixture', scanId] : [...scope, 'scan', scanId];
  const [snapshotGuard] = useState(() => {
    const cached = queryClient.getQueryCache().find({ queryKey: scanQueryKey, exact: true });
    const guard = cached?.meta?.statusSnapshotGuard;
    if (guard instanceof StatusSnapshotGuard) return guard;
    const state = queryClient.getQueryState<ScanStatus>(scanQueryKey);
    return new StatusSnapshotGuard(state?.status === 'success' && state.data?.scanId === scanId && state.dataUpdatedAt > 0);
  });
  const cancellation = useMutation({
    mutationFn: (id: string) => {
      const current = queryClient.getQueryState<ScanStatus>(scanQueryKey);
      if (!enabled || snapshotGuard.accessFailure || current?.status !== 'success' ||
        current.data?.scanId !== id || !['queued', 'running'].includes(current.data.state)) {
        throw new Error('Для отмены требуется свежий подтверждённый статус');
      }
      return transport.cancel(id);
    },
    onSuccess: async (_, id) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: [...scope, 'scan', id] }),
        queryClient.invalidateQueries({ queryKey: [...scope, 'results', id] }),
        queryClient.invalidateQueries({ queryKey: [...scope, 'sbom', id] }),
        queryClient.invalidateQueries({ queryKey: [...scope, 'vuln', id] }),
      ]);
    },
  });
  const scan = useQuery({
    queryKey: scanQueryKey,
    // The guard shares this exact session/owner/scan query's lifetime, including remounts and eviction.
    meta: { statusSnapshotGuard: snapshotGuard },
    queryFn: async ({ signal }) => {
      try {
        if (snapshotGuard.accessFailure) throw snapshotGuard.accessFailure;
        const next = await transport.get(scanId, signal);
        if (signal.aborted || next.scanId !== scanId) throw new Error('Снимок скана устарел');
        const current = queryClient.getQueryState<ScanStatus>(scanQueryKey);
        if (snapshotGuard.accessFailure) throw snapshotGuard.accessFailure;
        if (current?.error instanceof ScanAccessError) throw current.error;
        const previous = current?.data;
        if (previous && (previous.scanId !== next.scanId ||
          (previous.digest && previous.digest !== next.digest) ||
          (previous.platform && previous.platform !== next.platform) ||
          (previous.imageReference && previous.imageReference !== next.imageReference))) {
          throw new Error('Снимок скана устарел');
        }
        snapshotGuard.retainable = true;
        // An older in-flight poll must not reopen a scan after another GET confirmed its terminal state.
        if (previous && terminalStates.has(previous.state) && next.state !== previous.state) return previous;
        return next;
      } catch (error) {
        if (!signal.aborted) {
          if (error instanceof ScanAccessError) snapshotGuard.accessFailure = error;
          if (!recoverableStatusError(error)) snapshotGuard.retainable = false;
        }
        throw error;
      }
    },
    enabled,
    retry: false,
    refetchOnWindowFocus: false,
    refetchInterval: demo ? false : (query) => {
      if (snapshotGuard.accessFailure || (query.state.error && !recoverableStatusError(query.state.error))) return false;
      const snapshot = query.state.data as ScanStatus | undefined;
      // Durable checkpoints do not emit SSE events; poll while active even when the stream is connected.
      return snapshot && ['queued', 'running', 'cancelling'].includes(snapshot.state) ? 2000 : false;
    },
  });
  const staleSnapshot = scan.isRefetchError && snapshotGuard.retainable && !snapshotGuard.accessFailure &&
    recoverableStatusError(scan.error);
  const showSnapshot = enabled && !snapshotGuard.accessFailure && scan.data?.scanId === scanId &&
    (scan.isSuccess || staleSnapshot);
  const checkSnapshot = showSnapshot && scan.data ? scanCheckSnapshot(scan.data) : undefined;
  const vulnEntry = checkSnapshot?.entries.find(entry => entry.check === 'vuln');
  const vulnSubcoverage = vulnEntry?.result;
  const report = useQuery({
    queryKey: ['scan-results', 'fixture', scanId],
    queryFn: ({ signal }) => fixtureScanTransport.results(scanId, undefined, signal),
    enabled: demo && enabled && scan.isSuccess && scan.data.scanId === scanId,
    retry: false,
  });
  const active = showSnapshot && !!scan.data && ['queued', 'running', 'cancelling'].includes(scan.data.state);
  useEffect(() => {
    if (demo || !active || !transport.capabilities.events || !transport.subscribeEvents) return;
    let mounted = true;
    let refreshing = false;
    let pending = false;
    let lastRefresh = Date.now();
    let refreshTimer: ReturnType<typeof setTimeout> | undefined;
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
    setRealtime('connecting');
    const refresh = () => {
      pending = true;
      if (refreshing || refreshTimer || !mounted) return;
      refreshTimer = setTimeout(async () => {
        refreshTimer = undefined;
        if (!mounted) return;
        pending = false; refreshing = true; lastRefresh = Date.now();
        try {
          // Hints never replace status. Do not cancel/restart an overlapping GET.
          await queryClient.invalidateQueries({ queryKey: [...scope, 'scan', scanId] }, { cancelRefetch: false });
          if (mounted && queryClient.getQueryState([...scope, 'scan', scanId])?.status === 'success') await Promise.all([
            queryClient.invalidateQueries({ queryKey: [...scope, 'results', scanId] }, { cancelRefetch: false }),
            queryClient.invalidateQueries({ queryKey: [...scope, 'sbom', scanId] }, { cancelRefetch: false }),
            queryClient.invalidateQueries({ queryKey: [...scope, 'vuln', scanId] }, { cancelRefetch: false }),
          ]);
        } finally { refreshing = false; if (pending && mounted) refresh(); }
      }, Math.max(0, 1000 - (Date.now() - lastRefresh)));
    };
    let close: () => void;
    try {
      close = transport.subscribeEvents(scanId, refresh,
        () => {
          if (!mounted) return;
          setRealtime('reconnecting');
          reconnectTimer ??= setTimeout(() => { if (mounted) setRealtime('polling'); }, 15_000);
        },
        () => {
          if (!mounted) return;
          clearTimeout(reconnectTimer); reconnectTimer = undefined;
          setRealtime('connected'); refresh();
        });
    } catch {
      // Invalid ID or unavailable EventSource: keep polling the GET snapshot.
      setRealtime('polling');
      return;
    }
    return () => { mounted = false; clearTimeout(refreshTimer); clearTimeout(reconnectTimer); close(); };
  }, [demo, active, transport, queryClient, scanId, streamKey, scope]);

  const reportData = demo && scan.isSuccess && report.isSuccess ? report.data : undefined;
  const pendingChecks = demo ? [] : checkSnapshot?.entries.filter(item => item.outcome === null).map(item => item.check) ?? [];
  const liveCoverage: Array<ScanCoverage & { pendingPublication?: boolean }> | undefined = demo ? undefined : checkSnapshot?.entries.flatMap(({ check, outcome, result }) => outcome === null ? [] : [{
    check: scanCheckLabels[check],
    status: outcome,
    reason: result?.reason ?? result?.errorCode ?? undefined,
    scannerVersion: result?.scannerVersion ?? undefined,
    checksVersion: result?.checksVersion,
    resourcePolicyVersion: result?.resourcePolicyVersion,
    pendingPublication: active && !!scan.data?.progress,
  }]);
  const coverage: Array<ScanCoverage & { pendingPublication?: boolean }> = liveCoverage ?? reportData?.coverage ?? [];
  const changeFilter = (value: string) => {
      if (!staleSnapshot) setFilter(value);
    };

  const statusDetails = showSnapshot && scan.data ? (
            <div className="scan-a1__state">
              <div className="scan-a1__state-main">
                {!active ? <details className="scan-a1__technical scan-a1__terminal-progress">
                  <summary>Подробности · ход завершённой проверки</summary>
                  <ScanProgressPanel scan={scan.data} />
                </details> : null}
                <details className="scan-a1__technical">
                  <summary>Подробности · точный образ и данные сканирования</summary>
                  <dl className="scan-a1__facts">
                  <div>
                    <dt>Указанная цель</dt>
                    <dd>Указанная цель: {scan.data.imageReference || 'не предоставлена сервером'}</dd>
                  </div>
                  <div>
                    <dt>Подтверждение цели</dt>
                    <dd>
                      Закреплённая цель:{' '}
                      {scan.data.digest && scan.data.platform
                        ? `${scan.data.digest} · ${scan.data.platform}`
                        : 'ожидаем подтверждения digest/platform от авторизованного GET status'}
                    </dd>
                  </div>
                  <div>
                    <dt>Статус</dt>
                    <dd>{stateLabels[scan.data.state]}</dd>
                  </div>
                  <div>
                    <dt>Этап</dt>
                    <dd>Этап: {scan.data.stage || 'не предоставлен'}</dd>
                  </div>
                  <div><dt>ID сканирования</dt><dd>ID / {scanId}</dd></div>
                  </dl>
                </details>
                {!staleSnapshot ? <ScanStatusAnnouncement scan={scan.data} /> : null}
                {!demo && scan.data.state === 'cancelled' ? (
                  <Alert tone="neutral">
                    {liveCoverage?.length
                      ? 'Сканирование отменено. Сохранены результаты завершённых проверок. Это не означает, что все запрошенные проверки выполнены.'
                      : 'Сканирование отменено. Сохранённых результатов завершённых проверок нет.'}
                    {' '}Проверки без сохранённого результата не подтверждены как завершённые; число находок в них неизвестно.
                  </Alert>
                ) : null}
              </div>
              <div className="scan-a1__state-aside">

                {!demo && transport.capabilities.cancel && ['queued', 'running'].includes(scan.data.state) ? (
                  <AlertDialog.Root>
                    <AlertDialog.Trigger asChild>
                      <Button variant="secondary" type="button" disabled={staleSnapshot || cancellation.isPending}>
                        {cancellation.isPending ? 'Отменяем…' : 'Отменить скан'}
                      </Button>
                    </AlertDialog.Trigger>
                    <AlertDialog.Portal>
                      <AlertDialog.Overlay className="fixed inset-0 z-40 bg-slate-950/65" />
                      <AlertDialog.Content className="fixed left-1/2 top-1/2 z-50 w-[min(calc(100vw-2rem),28rem)] -translate-x-1/2 -translate-y-1/2 space-y-5 rounded-lg border border-slate-300 bg-white p-6 text-slate-900 shadow-2xl">
                        <AlertDialog.Title className="text-xl font-semibold">Отменить скан?</AlertDialog.Title>
                        <AlertDialog.Description className="text-sm leading-relaxed text-slate-600">
                          Сохранённые результаты завершённых проверок останутся доступны. Остальные проверки не будут завершены. Статус подтвердит сервер.
                        </AlertDialog.Description>
                        <div className="flex flex-wrap justify-end gap-3">
                          <AlertDialog.Cancel asChild>
                            <Button variant="secondary" type="button">Продолжить сканирование</Button>
                          </AlertDialog.Cancel>
                          <AlertDialog.Action asChild>
                            <Button type="button" disabled={staleSnapshot || cancellation.isPending} onClick={() => {
                              if (!staleSnapshot && !cancellation.isPending) cancellation.mutate(scanId);
                            }}>Подтвердить отмену</Button>
                          </AlertDialog.Action>
                        </div>
                      </AlertDialog.Content>
                    </AlertDialog.Portal>
                  </AlertDialog.Root>
                ) : null}
                {cancellation.isError && !['cancelling', 'cancelled'].includes(scan.data.state) ? (
                  <Alert role="alert" tone="warning">
                    <p>
                      {terminalStates.has(scan.data.state)
                        ? `Сервер подтвердил итог: ${stateLabels[scan.data.state]}. Отмена не подтверждена.`
                        : cancellation.error instanceof ScanAccessError
                          ? cancellation.error.status === 401
                            ? 'Сессия недействительна. Для проверки результата отмены войдите заново.'
                            : 'Нет разрешения проверить отмену этого скана.'
                          : cancellation.error instanceof ScanHttpError && [400, 409].includes(cancellation.error.status)
                            ? 'Сервер отклонил запрос отмены. Обновите статус скана.'
                            : 'Не удалось подтвердить отмену: результат запроса неизвестен. Проверьте статус перед повторной отменой.'}
                    </p>
                    {!terminalStates.has(scan.data.state) && !(cancellation.error instanceof ScanAccessError) ? (
                      <Button type="button" variant="secondary" disabled={scan.isFetching}
                        onClick={() => void scan.refetch({ cancelRefetch: false })}>
                        {scan.isFetching ? 'Получаем статус…' : 'Проверить статус отмены'}
                      </Button>
                    ) : null}
                  </Alert>
                ) : null}
              </div>
            </div>
  ) : null;

  return (
    <ScanShell demo={demo} compact>
      <section className="scan-a1-detail" aria-labelledby="scan-detail">
        <div className="scan-a1__chapter">
          <span>Отчёт</span>
          <Link to={demo ? '/demo/scans' : '/scans'}>
            <ArrowLeft size={17} aria-hidden="true" /> К списку
          </Link>
        </div>
        <div className="scan-a1__lead">
          <div className="scan-a1__lead-copy">
            <p className="scan-a1__eyebrow">
              {demo ? 'Демонстрационный отчёт · вымышленные данные' : 'Отчёт по образу'}
            </p>
            <h2 id="scan-detail">
              Результат проверки образа
            </h2>
            <p className="scan-a1__reference">{showSnapshot && scan.data ? scan.data.imageReference?.split('@')[0] ?? 'Образ не указан сервером' : scan.isError ? 'Образ не подтверждён' : 'Загружаем образ…'}</p>
          </div>

          {showSnapshot && scan.data ? (
            <div className="scan-a1__summary" data-terminal={!active}>
              <Badge tone={stateTone[scan.data.state]}>{stateLabels[scan.data.state]}</Badge>
              {active ? <ScanProgressPanel scan={scan.data} /> : null}
              {!demo ? <span className="sr-only" role="status" aria-label="Состояние realtime">{active ? {
                connecting: 'SSE: подключаемся; статус обновляется через GET',
                connected: 'SSE: подключён; этап подтверждается GET',
                reconnecting: 'SSE: переподключение; статус обновляется через GET',
                polling: 'SSE: недоступен; статус обновляется через GET',
              }[realtime] : scan.data.state === 'cancelled' ? 'Скан отменён; realtime остановлен' : 'Скан завершён; realtime остановлен'}</span> : null}
            </div>
          ) : null}
        </div>
        {!enabled ? (
          <Alert tone="neutral">
            Деталь недоступна без защищённой авторизованной сессии; scanId в адресе не подтверждает доступ.
          </Alert>
        ) : null}
        {scan.isPending && enabled ? <p role="status">Загружаем снимок…</p> : null}
        {scan.isError ? (
          <Alert role="alert" tone="danger">
            <p>{staleSnapshot && showSnapshot
              ? 'Не удалось обновить статус. Показан последний подтверждённый снимок, а не текущее состояние проверки. Отмена и действия с отчётом недоступны до успешного обновления.'
              : 'Не удалось получить данные скана. Его существование и доступность не подтверждены.'}</p>
            {enabled && !(scan.error instanceof ScanAccessError) ? (
              <Button type="button" variant="secondary" disabled={scan.isFetching}
                onClick={() => void scan.refetch({ cancelRefetch: false })}>
                {scan.isFetching ? 'Получаем статус…' : 'Повторить получение статуса'}
              </Button>
            ) : null}
          </Alert>
        ) : null}
        {showSnapshot && scan.data ? (
          <>

            <ScanReportOverview status={scan.data}
                          onShowFindings={check => changeFilter(check === 'secret' ? 'secret' : demo ? 'vulnerability' : 'cve')}
                          onShowCoverage={() => setCoverageOpen(true)} />
            <nav className="scan-a1__report-nav" aria-label="Разделы отчёта">
              <a href="#scan-a1-findings" onClick={() => changeFilter('all')}>Находки и исправления</a>
              <a href="#scan-a1-coverage" onClick={() => setCoverageOpen(true)}>Что проверено</a>
              {!demo && live && !staleSnapshot && scan.data.state === 'completed' ? <a href="#scan-a1-ai">Объяснение ИИ</a> : null}
              {!demo && live && !staleSnapshot && !active ? <a href="#scan-report-chat">Задать вопрос</a> : null}
            </nav>

            {active ? statusDetails : null}

            <div className="scan-a1__grid">
              <details className="scan-a1__panel scan-a1__coverage-panel" open={coverageOpen}
                              onToggle={event => setCoverageOpen(event.currentTarget.open)}>
                <summary id="scan-a1-coverage">Подробности · что удалось проверить</summary>
                <p className="scan-a1__coverage-note">«Выполнено» означает завершение проверки, а не гарантию безопасности. Пропущенные проверки не означают отсутствие проблем.</p>
                {scan.data.identifierCounts ? <p>Уязвимости · весь сохранённый отчёт: {identifierCountLabel(scan.data.identifierCounts)}.</p> : null}
                {pendingChecks.length ? <ul aria-label="Проверки без подтверждённого результата">{pendingChecks.map(check => <li key={check}>
                  {scanCheckLabels[check]}: {active ? 'ожидаем подтверждённый результат' : scan.data.state === 'cancelled' ? 'завершение не подтверждено; сохранённого результата нет' : 'результат не предоставлен сервером'}
                </li>)}</ul> : null}
                {vulnEntry ? (
                  <section aria-label="Покрытие системных пакетов и пакетов приложения">
                    <h4>Какие пакеты удалось проверить на уязвимости</h4>
                    <ul>
                      {([
                        ['Системные пакеты', vulnSubcoverage?.os],
                        ['Пакеты приложения (Node/npm)', vulnSubcoverage?.node],
                      ] as const).map(([label, result]) => (
                        <li key={label}>
                          <strong>{label}: </strong>
                          {!result ? 'Нет данных о покрытии; отсутствие уязвимостей не подтверждено.'
                            : result.outcome === 'checked' ? 'Проверка выполнена; это не гарантия безопасности.'
                              : `Не поддерживается — ${scanReasonLabel(result.reason)}.`}
                          {result?.outcome === 'unsupported' && result.reason === 'NODE_INVENTORY_UNKNOWN'
                            ? ' Отсутствие пакетов Node.js не доказано.' : null}
                        </li>
                      ))}
                    </ul>
                  </section>
                ) : null}
                {coverage.length > 0 ? (
                  <ul className="scan-a1__coverage" aria-label="Исходы проверок">
                    {coverage.map((item) => {
                      const StatusIcon = coverageIcons[item.status];
                      return (
                        <li key={item.check} data-outcome={item.status}>
                          <div className="scan-a1__coverage-heading">
                            <strong>{item.check}</strong>
                            <span className="scan-a1__coverage-status">
                              <StatusIcon size={16} aria-hidden="true" />
                              {coverageLabels[item.status]}
                            </span>
                          </div>
                          {item.pendingPublication ? <p>Исход проверки подтверждён; отчёт ещё не опубликован.</p> : null}
                          {item.reason ? <p className="scan-a1__coverage-reason">{scanReasonLabel(item.reason) === item.reason ? 'Причина не описана сервером; код доступен в подробностях.' : scanReasonLabel(item.reason)}</p> : null}
                          {item.reason || item.checksVersion || item.resourcePolicyVersion || item.scannerVersion || item.dbVersion ? (
                            <details className="scan-a1__coverage-technical">
                              <summary>Технические данные · {item.check}</summary>
                              {item.reason ? <p>Причина: {item.reason}</p> : null}
                              {item.checksVersion || item.resourcePolicyVersion ? (
                                <p>checks {item.checksVersion ?? 'не предоставлена'} · policy {item.resourcePolicyVersion ?? 'не предоставлена'}</p>
                              ) : null}
                              {item.scannerVersion || item.dbVersion ? (
                                <p>
                                  {item.scannerVersion ? `scanner ${item.scannerVersion}` : ''}
                                  {item.scannerVersion && item.dbVersion ? ' · ' : ''}
                                  {item.dbVersion ? `DB ${item.dbVersion}` : ''}
                                </p>
                              ) : null}
                            </details>
                          ) : null}
                        </li>
                      );
                    })}
                  </ul>
                ) : (
                  <p>Итоги проверок ещё не подтверждены. Отсутствие результатов не означает отсутствие проблем.</p>
                )}
              </details>
              <section className="scan-a1__panel scan-a1__findings-panel" aria-labelledby="scan-a1-findings">
                <h3 id="scan-a1-findings">Находки и исправления</h3>
                <p>Выберите категорию, проверьте находку и выполните следующий шаг. Точные данные источников — в подробностях карточки.</p>
                {!demo ? scan.data.config ? (
                  <section id="scan-report-config" tabIndex={-1} aria-label="Настройки образа" className="scan-report-section">
                    <h4>Пользователь запуска контейнера</h4>
                    <p>{coverageLabels[scan.data.config.config.outcome]}{scan.data.config.config.outcome !== 'checked' ? ` · ${scanReasonLabel(scan.data.config.config.reason)}` : ''}</p>
                    <details className="scan-a1__coverage-technical">
                      <summary>Подробности проверки настроек</summary>
                      <p>checks {scan.data.config.checksVersion} · policy {scan.data.config.resourcePolicyVersion}</p>
                      <p>Правила: выполнено {scan.data.config.completedRuleIds.length} / поддерживается {scan.data.config.supportedRuleIds.length}</p>
                      <p>Поддерживаемые правила: {scan.data.config.supportedRuleIds.join(', ')}</p>
                      <p>History: {scan.data.config.history.reason}. Dockerfile: {scan.data.config.dockerfile.reason}. IaC: {scan.data.config.iac.reason}.</p>
                    </details>
                    <p>Проверены только настройки пользователя в образе, не права запущенного контейнера. История сборки не анализируется; Dockerfile и файлы инфраструктуры не предоставлены.</p>
                    {scan.data.config.findings.length ? <ul>{scan.data.config.findings.map(finding => <li key={finding.findingId}>
                      <strong>{finding.classification === 'DEFAULT_ROOT' ? 'Не задан пользователь без прав администратора' : 'В образе явно указан пользователь root'}</strong>
                      <p>Почему важно: запуск с правами администратора может увеличить последствия ошибки приложения.</p>
                      <p>Что сделать: задайте явный ненулевой числовой идентификатор пользователя и отдельно проверьте права при запуске контейнера.</p>
                      <details><summary>Подробности · данные сканера</summary>
                        <p>{finding.ruleId} · {finding.classification} · {finding.severity}</p>
                        <p>{finding.message}</p><p>{finding.recommendation}</p>
                        <p>Место: {finding.location} · ID: {finding.findingId}</p>
                      </details>
                    </li>)}</ul> : scan.data.config.config.outcome === 'checked' ? <p>В метаданных не найдено указания на запуск от root. Это не гарантия безопасного запуска.</p> : <p>Результаты проверки конфигурации не подтверждены.</p>}
                  </section>
                ) : null : null}

                <fieldset disabled={staleSnapshot} className="scan-report-interactions">
                <div className="scan-report-category">
                  <label htmlFor="finding-filter">Показать находки</label>
                  <select id="finding-filter" className={controlClass} value={filter} onChange={event => changeFilter(event.target.value)}>
                    <option value="all">Все категории</option><option value={demo ? "vulnerability" : "cve"}>Уязвимости пакетов</option><option value="secret">Возможные секреты</option>
                  </select>
                </div>
                <AdvisoryTranslationScope status={!demo && live && !staleSnapshot && !active ? scan.data : null}>
                  <ScanReportSections status={scan.data} transport={transport} scope={scope} demo={demo} filter={filter} onResetFilter={() => changeFilter("all")} />
                </AdvisoryTranslationScope>
                </fieldset>
              </section>
            </div>
            {!active ? statusDetails : null}
            {!demo && live && !staleSnapshot && scan.data.state === 'completed' ? <ScanSummaryPanel
              key={JSON.stringify(['summary', scope, scan.data])}
              status={scan.data}
              transport={transport}
            /> : null}
            {!demo && live && !staleSnapshot && !active ? <ScanChatPanel
              key={JSON.stringify(['chat', scope, scan.data])}
              status={scan.data}
              transport={transport}
            /> : null}
          </>
        ) : null}
      </section>
    </ScanShell>
  );
}
