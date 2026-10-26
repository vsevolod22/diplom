import { useEffect, useState } from 'react';

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, CheckCircle2, CircleDashed, CircleOff, LockKeyhole, XCircle } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { MagicCard } from '@/features/scans/MagicCard';
import {
  ReportAccordion,
  ReportAccordionContent,
  ReportAccordionItem,
  ReportAccordionTrigger,
} from '@/features/scans/ReportAccordion';
import { ScanFilterSheet } from '@/features/scans/ScanFilterSheet';
import { ScanSummaryPanel } from '@/features/scans/ScanSummaryPanel';
import { AdvisoryTranslationScope } from '@/features/scans/AdvisoryTranslationPanel';
import { ScanShell, controlClass } from '@/features/scans/ScanShell';
import { useLiveScanSession } from '@/features/scans/liveScanContext';
import { ScanScene } from '@/features/scans/ScanScene';
import { ScanStatusAnnouncement } from '@/features/scans/ScanStatusAnnouncement';
import { ScanProgressPanel } from '@/features/scans/ScanProgressPanel';
import { stateLabels } from '@/features/scans/scanStateLabels';
import { fixtureScanTransport, unavailableScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import { ScanAccessError } from '@/shared/api/scans/httpScanTransport';
import type { ScanCheck, ScanCoverage, ScanStatus } from '@/shared/api/scans/scanTransport';
import { Alert, Badge, Button } from '@/shared/ui/scan-primitives';
import { ScanReportSections } from './ScanReportSections';
import './scan-detail-a1.css';
import { PUBLIC_IMAGE_PROFILE } from '@/shared/api/scans/publicImageProfile';
import { identifierCountLabel } from '@/shared/api/scans/publicVulnerabilityIdentifiers';

const unavailableScope = ['live-scans', 'unavailable'] as const;
const terminalStates = new Set<ScanStatus['state']>(['completed', 'partial', 'failed', 'cancelled']);

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

  const live = useLiveScanSession();
  const transport = demo ? fixtureScanTransport : live?.transport ?? unavailableScanTransport;
  const enabled = !!scanId && (demo || transport.capabilities.list);
  const queryClient = useQueryClient();
  const scope = live?.scope ?? unavailableScope;
  const streamKey = `${scope.join(':')}:${scanId}`;

  const [realtime, setRealtime] = useState<'connecting' | 'connected' | 'reconnecting' | 'polling'>('polling');
  const cancellation = useMutation({
    mutationFn: (id: string) => transport.cancel(id),
    onSuccess: async (_, id) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: [...scope, 'scan', id] }),
        queryClient.invalidateQueries({ queryKey: [...scope, 'results', id] }),
        queryClient.invalidateQueries({ queryKey: [...scope, 'sbom', id] }),
        queryClient.invalidateQueries({ queryKey: [...scope, 'vuln', id] }),
      ]);
    },
  });
  const scanQueryKey = demo ? ['scan', 'fixture', scanId] : [...scope, 'scan', scanId];
  const scan = useQuery({
    queryKey: scanQueryKey,
    queryFn: async ({ signal }) => {
      const next = await transport.get(scanId, signal);
      if (signal.aborted || next.scanId !== scanId) throw new Error('Снимок скана устарел');
      const current = queryClient.getQueryState<ScanStatus>(scanQueryKey);
      if (current?.error instanceof ScanAccessError) throw current.error;
      // An older in-flight poll must not reopen a scan after another GET confirmed its terminal state.
      if (current?.data?.scanId === scanId && terminalStates.has(current.data.state) && next.state !== current.data.state)
        return current.data;
      return next;
    },
    enabled,
    retry: false,
    refetchOnWindowFocus: false,
    refetchInterval: demo ? false : (query) => {
      if (query.state.error instanceof ScanAccessError) return false;
      const snapshot = query.state.data as ScanStatus | undefined;
      // Durable checkpoints do not emit SSE events; poll while active even when the stream is connected.
      return snapshot && ['queued', 'running', 'cancelling'].includes(snapshot.state) ? 2000 : false;
    },
  });
  const requested = scan.data?.checks ?? (scan.data?.check ? [scan.data.check] : []);
  const report = useQuery({
    queryKey: ['scan-results', 'fixture', scanId],
    queryFn: ({ signal }) => fixtureScanTransport.results(scanId, undefined, signal),
    enabled: demo && enabled && scan.isSuccess && scan.data.scanId === scanId,
    retry: false,
  });
  const active = scan.isSuccess && scan.data?.scanId === scanId && ['queued', 'running', 'cancelling'].includes(scan.data.state);
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
          if (mounted) await Promise.all([
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
  const publicReport = scan.data?.profile === PUBLIC_IMAGE_PROFILE;
  const reportData = demo && scan.isSuccess && report.isSuccess ? report.data : undefined;
  const pendingChecks = demo ? [] : requested.filter(check => !scan.data?.perCheck?.[check]);
  const liveCoverage = demo ? undefined : scan.data?.checks?.filter(check => !!scan.data?.perCheck?.[check]).map((check: ScanCheck): ScanCoverage => {
    const outcome = scan.data?.perCheck?.[check];
    return { check: { secret: 'Secrets', sbom: 'SBOM', vuln: publicReport ? 'Уязвимости' : 'CVE', config: 'Image config' }[check], status: outcome?.outcome ?? 'skipped', reason: outcome?.reason ?? outcome?.errorCode ?? (outcome ? undefined : 'Результат ещё не получен'), scannerVersion: outcome?.scannerVersion ?? undefined, checksVersion: outcome?.checksVersion, resourcePolicyVersion: outcome?.resourcePolicyVersion };
  });
  const changeFilter = setFilter;

  return (
    <ScanShell demo={demo}>
      <section className="scan-a1-detail" aria-labelledby="scan-detail">
        <div className="scan-a1__chapter">
          <span>ГЛАВА 03 / ОТЧЁТ</span>
          <Link to={demo ? '/demo/scans' : '/scans'}>
            <ArrowLeft size={17} aria-hidden="true" /> К списку
          </Link>
        </div>
        <div className="scan-a1__lead">
          <div className="scan-a1__lead-copy">
            <p className="scan-a1__eyebrow">
              {demo ? 'ДЕМО / ВЫМЫШЛЕННЫЕ ДАННЫЕ' : 'РЕАЛЬНЫЙ РЕЖИМ / СНИМОК API'}
            </p>
            <h2 id="scan-detail">
              Не всё, что видно, <em>проверено.</em>
            </h2>
            <p className="scan-a1__reference">ID / {scanId}</p>
            <p className="scan-a1__muted">
              {demo ? 'Демонстрационная карточка · вымышленные данные' : 'Авторизованный снимок статуса'}
            </p>
          </div>

          {scan.isSuccess && scan.data.scanId === scanId ? (
            <div className="scan-a1__summary">
              <Badge tone={stateTone[scan.data.state]}>{stateLabels[scan.data.state]}</Badge>
              <span>Текущая фаза: {stateLabels[scan.data.state]}</span>
              <ScanProgressPanel scan={scan.data} />
              {!demo ? <span role="status" aria-label="Состояние realtime">{active ? {
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
        {scan.isPending && enabled ? <p>Загружаем снимок…</p> : null}
        {scan.isError ? (
          <Alert role="alert" tone="danger">
            Не удалось получить данные скана. Его существование и доступность не подтверждены.
          </Alert>
        ) : null}
        {scan.isSuccess && scan.data.scanId === scanId ? (
          <>
            <MagicCard className="scan-a1__reading-card">
              <p className="scan-a1__reading-copy">
                Порядок чтения / цель → состояние → покрытие → находки. Подсветка помогает ориентироваться, но
                не показывает ход проверки.
              </p>
            </MagicCard>
            <nav className="scan-a1__report-nav" aria-label="Разделы отчёта">
              <a href="#scan-a1-state">
                01 <span>Состояние и цель</span>
              </a>
              <a href="#scan-a1-coverage">
                02 <span>Покрытие</span>
              </a>
              <a href="#scan-a1-findings">
                03 <span>Находки и пакеты</span>
              </a>
              <a href="#scan-a1-ai">
                04 <span>Помощник</span>
              </a>
              {!demo && live && !active ? <a href="#scan-report-chat">05 <span>Чат по отчёту</span></a> : null}
            </nav>
            <div className="scan-a1__chapter scan-a1__chapter--section" id="scan-a1-state">
              01 / СОСТОЯНИЕ И ЦЕЛЬ
            </div>
            <div className="scan-a1__state">
              <div className="scan-a1__state-main">
                <h3>Цель и состояние</h3>
                <p className="scan-a1__muted">Указанная цель не подтверждает закреплённый образ.</p>
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
                </dl>
                <ScanStatusAnnouncement scan={scan.data} />
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
                <p>
                  {demo
                    ? 'Состояние из локальной фикстуры; это не GET status и не live-поток.'
                    : 'SSE сообщает о переходах; состояние и находки подтверждаются отдельными GET. При потере потока работает polling.'}
                </p>
                {!demo && transport.capabilities.cancel && ['queued', 'running'].includes(scan.data.state) ? (
                  <Button
                    variant="secondary"
                    type="button"
                    disabled={cancellation.isPending}
                    onClick={() => {
                      if (window.confirm('Отменить скан? Сохранённые результаты завершённых проверок останутся доступны. Остальные проверки не будут завершены.')) {
                        cancellation.mutate(scanId);
                      }
                    }}
                  >
                    {cancellation.isPending ? 'Отменяем…' : 'Отменить скан'}
                  </Button>
                ) : (
                  <p>Отмена недоступна в текущем состоянии.</p>
                )}
                <p>{demo ? 'Демо не отправляет серверную отмену.' : 'При отмене сохраняются уже записанные результаты завершённых проверок. Незавершённые проверки не получают результат; статус подтверждается GET snapshot.'}</p>
                {cancellation.isError ? (
                  <Alert role="alert" tone="danger">
                    Не удалось отменить скан: он недоступен или отмена невозможна в текущем состоянии. Обновите статус.
                  </Alert>
                ) : null}
              </div>
            </div>
            <div className="scan-a1__detail-divider" aria-hidden="true">
              <ScanScene variant="detail" />
            </div>
            <div className="scan-a1__grid">
              <section className="scan-a1__panel scan-a1__coverage-panel" aria-labelledby="scan-a1-coverage">
                <p className="scan-a1__eyebrow">02 / ПОКРЫТИЕ</p>
                <h3 id="scan-a1-coverage">Покрытие проверок</h3>
                <p className="scan-a1__muted">Исход каждой проверки отдельно от статуса скана.</p>
                <p className="scan-a1__coverage-note">
                  «Выполнено» означает завершение проверки в указанной области, а не гарантию безопасности.
                  Сбой, пропуск или отсутствие результата оставляют число находок неизвестным.
                </p>
                {scan.data.identifierCounts ? <p>Уязвимости · весь сохранённый отчёт: {identifierCountLabel(scan.data.identifierCounts)}.</p> : null}
                {pendingChecks.length ? <ul aria-label="Проверки без подтверждённого результата">{pendingChecks.map(check => <li key={check}>
                  {check}: {active ? `ожидаем подтверждённый результат; ${scan.data.stage ? 'текущий этап указан сервером выше' : 'внутренний этап не предоставлен сервером'}` : scan.data.state === 'cancelled' ? 'завершение не подтверждено; сохранённого результата нет' : 'результат не предоставлен сервером'}
                </li>)}</ul> : null}
                {(liveCoverage ?? reportData?.coverage) ? (
                  <ul className="scan-a1__coverage" aria-label="Исходы проверок">
                    {(liveCoverage ?? reportData?.coverage ?? []).map((item) => {
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
                          {item.reason ? <p className="scan-a1__coverage-reason">{item.reason}</p> : null}
                          {item.checksVersion || item.resourcePolicyVersion || item.scannerVersion || item.dbVersion ? (
                            <details className="scan-a1__coverage-technical">
                              <summary>Технические данные · {item.check}</summary>
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
                  <p>Нет подтверждённого coverage; тип проверки и результат неизвестны. «0 проблем» недопустимо.</p>
                )}
                {!demo ? scan.data.config ? (
                  <div aria-label="Image config coverage">
                    <h4>Image config · только метаданные образа</h4>
                    <p>{coverageLabels[scan.data.config.config.outcome]}{scan.data.config.config.outcome !== 'checked' ? ` · ${scan.data.config.config.reason}` : ''}</p>
                    <details className="scan-a1__coverage-technical">
                      <summary>Технические данные · Image config</summary>
                      <p>checks {scan.data.config.checksVersion} · policy {scan.data.config.resourcePolicyVersion}</p>
                    </details>
                    <p>Правила: выполнено {scan.data.config.completedRuleIds.length} / поддерживается {scan.data.config.supportedRuleIds.length} · {scan.data.config.supportedRuleIds.join(', ')}</p>
                    <p>History: {scan.data.config.history.reason}. Dockerfile: {scan.data.config.dockerfile.reason}. IaC: {scan.data.config.iac.reason}.</p>
                    <p>OCI history не является исходным Dockerfile/IaC. Numeric UID без находки не доказывает non-root runtime.</p>
                    {scan.data.config.findings.length ? <ul>{scan.data.config.findings.map(finding => <li key={finding.findingId}>
                      <strong>{finding.ruleId} · {finding.classification} · {finding.severity}</strong>
                      <p>{finding.message}</p><p>{finding.recommendation}</p>
                    </li>)}</ul> : scan.data.config.config.outcome === 'checked' ? <p>Root metadata finding отсутствует.</p> : <p>Находки config не подтверждены.</p>}
                  </div>
                ) : <p>Нет подтверждённого image config coverage: проверка ещё не завершена или это legacy scan без versioned evidence.</p> : null}

                <div className="scan-a1__coverage-guide">
                  <span className="scan-a1__eyebrow">КАК ЧИТАТЬ ПОКРЫТИЕ / СПРАВКА</span>
                  <p>Статус, исходы и причины проверок показаны выше без раскрытия подсказок.</p>
                  <ReportAccordion type="single" collapsible>
                    <ReportAccordionItem value="partial">
                      <ReportAccordionTrigger>Что означает неполный отчёт?</ReportAccordionTrigger>
                      <ReportAccordionContent>
                        Нельзя считать непроверенные категории безопасными. Сбой проверки не означает «0
                        находок».
                      </ReportAccordionContent>
                    </ReportAccordionItem>
                    <ReportAccordionItem value="target">
                      <ReportAccordionTrigger>Когда цель считается подтверждённой?</ReportAccordionTrigger>
                      <ReportAccordionContent>
                        Только когда авторизованный GET status предоставляет закреплённые digest и platform;
                        указанный tag не подтверждает содержимое образа.
                      </ReportAccordionContent>
                    </ReportAccordionItem>
                  </ReportAccordion>
                </div>
              </section>
              <section className="scan-a1__panel scan-a1__findings-panel" aria-labelledby="scan-a1-findings">
                <p className="scan-a1__eyebrow">03 / РЕЗУЛЬТАТЫ</p>
                <h3 id="scan-a1-findings">Результаты проверок</h3>
                {!publicReport ? <ScanFilterSheet filter={filter} onFilterChange={changeFilter} cveValue={demo ? "vulnerability" : "cve"} /> : null}
                <div className={publicReport ? undefined : 'scan-a1__desktop-filter'}>
                  <label htmlFor="finding-filter">Категория</label>
                  <select id="finding-filter" className={controlClass} value={filter} onChange={event => changeFilter(event.target.value)}>
                    <option value="all">Все категории</option><option value={demo ? "vulnerability" : "cve"}>{publicReport ? 'Уязвимости' : 'CVE'}</option><option value="secret">Secrets</option>
                  </select>
                </div>
                <AdvisoryTranslationScope status={!demo && live && !active ? scan.data : null}>
                  <ScanReportSections status={scan.data} transport={transport} scope={scope} demo={demo} filter={filter} onResetFilter={() => changeFilter("all")} />
                </AdvisoryTranslationScope>
              </section>
            </div>
            {!demo && live && !active ? <ScanSummaryPanel
              key={JSON.stringify([scope, scan.data])}
              status={scan.data}
              transport={transport}
            /> : <section className="scan-a1__ai" aria-labelledby="scan-a1-ai">
              <h3 id="scan-a1-ai">Сводка отчёта</h3>
              <p>{demo ? 'Демо не отправляет данные модели и не имитирует ИИ-сводку.' : 'ИИ-сводка доступна только для завершённого авторизованного отчёта.'} Чат доступен только для авторизованного отчёта при разрешении сервера.</p>
            </section>}
          </>
        ) : null}
      </section>
    </ScanShell>
  );
}
