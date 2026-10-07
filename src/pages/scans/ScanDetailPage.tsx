import { useEffect, useState } from 'react';

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, Sparkles } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { MagicCard } from '@/features/scans/MagicCard';
import {
  ReportAccordion,
  ReportAccordionContent,
  ReportAccordionItem,
  ReportAccordionTrigger,
} from '@/features/scans/ReportAccordion';
import { ScanFilterSheet } from '@/features/scans/ScanFilterSheet';
import { ScanShell, controlClass } from '@/features/scans/ScanShell';
import { useLiveScanSession } from '@/features/scans/liveScanContext';
import { ScanScene } from '@/features/scans/ScanScene';
import { ScanStatusAnnouncement } from '@/features/scans/ScanStatusAnnouncement';
import { stateLabels } from '@/features/scans/scanStateLabels';
import { fixtureScanTransport, unavailableScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import { ScanAccessError, ScanHttpError } from '@/shared/api/scans/httpScanTransport';
import type { ScanCheck, ScanCoverage, ScanStatus } from '@/shared/api/scans/scanTransport';
import { Alert, Badge, Button } from '@/shared/ui/scan-primitives';
import { VulnAdvisoryCard } from './VulnAdvisoryCard';
import './scan-detail-a1.css';

const unavailableScope = ['live-scans', 'unavailable'] as const;

const coverageLabels: Record<ScanCoverage['status'], string> = {
  checked: 'Выполнено (не гарантия безопасности)',
  failed: 'Сбой · не проверено',
  unsupported: 'Не поддерживается',
  not_authorized: 'Нет разрешения',
  skipped: 'Пропущено',
};
const coverageTone: Record<ScanCoverage['status'], 'neutral' | 'info' | 'warning' | 'danger'> = {
  checked: 'info',
  failed: 'danger',
  unsupported: 'warning',
  not_authorized: 'warning',
  skipped: 'neutral',
};
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
  const [cursor, setCursor] = useState<string | undefined>();
  const [sbomCursor, setSbomCursor] = useState<string | undefined>();
  const [vulnCursor, setVulnCursor] = useState<string | undefined>();
  const live = useLiveScanSession();
  const transport = demo ? fixtureScanTransport : live?.transport ?? unavailableScanTransport;
  const enabled = !!scanId && (demo || transport.capabilities.list);
  const queryClient = useQueryClient();
  const scope = live?.scope ?? unavailableScope;
  const streamKey = `${scope.join(':')}:${scanId}`;
  const [connectedStream, setConnectedStream] = useState<string | null>(null);
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
  const scan = useQuery({
    queryKey: demo ? ['scan', 'fixture', scanId] : [...(live?.scope ?? ['live-scans', 'unavailable']), 'scan', scanId],
    queryFn: ({ signal }) => transport.get(scanId, signal),
    enabled,
    retry: false,
    refetchOnWindowFocus: false,
    refetchInterval: demo ? false : (query) => {
      if (query.state.error instanceof ScanAccessError) return false;
      const snapshot = query.state.data as ScanStatus | undefined;
      return snapshot && ['queued', 'running', 'cancelling'].includes(snapshot.state) && connectedStream !== streamKey ? 2000 : false;
    },
  });
  const requested = scan.data?.checks ?? (scan.data?.check ? [scan.data.check] : []);
  const isSbom = requested.includes('sbom');
  const isSecret = demo || requested.includes('secret');
  const isVuln = requested.includes('vuln');
  const sbomOnly = isSbom && !isSecret && !isVuln && !requested.includes('config');
  const sbom = useQuery({
    queryKey: [...scope, 'sbom', scanId, scan.data?.state, sbomCursor],
    queryFn: ({ signal }) => transport.sbom(scanId, sbomCursor, signal),
    enabled: enabled && scan.isSuccess && scan.data.scanId === scanId && isSbom && scan.data.perCheck?.sbom?.outcome != null && ['completed', 'partial', 'failed'].includes(scan.data.state),
    retry: false,
  });
  const vuln = useQuery({
    queryKey: [...scope, 'vuln', scanId, scan.data?.state, vulnCursor],
    queryFn: ({ signal }) => transport.vuln(scanId, vulnCursor, signal),
    enabled: enabled && scan.isSuccess && scan.data.scanId === scanId && isVuln && scan.data.perCheck?.vuln?.outcome != null && ['completed', 'partial', 'failed'].includes(scan.data.state),
    retry: false,
  });
  const report = useQuery({
    queryKey: demo ? ['scan-results', 'fixture', scanId, cursor] : [...(live?.scope ?? ['live-scans', 'unavailable']), 'results', scanId, scan.data?.state, cursor],
    queryFn: ({ signal }) => transport.results(scanId, cursor, signal),
    enabled: enabled && scan.isSuccess && scan.data.scanId === scanId && isSecret,
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
          setConnectedStream(null); setRealtime('reconnecting');
          reconnectTimer ??= setTimeout(() => { if (mounted) setRealtime('polling'); }, 15_000);
        },
        () => {
          if (!mounted) return;
          clearTimeout(reconnectTimer); reconnectTimer = undefined;
          setConnectedStream(streamKey); setRealtime('connected'); refresh();
        });
    } catch {
      // Invalid ID or unavailable EventSource: keep polling the GET snapshot.
      setRealtime('polling');
      return;
    }
    return () => { mounted = false; clearTimeout(refreshTimer); clearTimeout(reconnectTimer); close(); };
  }, [demo, active, transport, queryClient, scanId, streamKey, scope]);
  const reportData = isSecret && scan.isSuccess && report.isSuccess ? report.data : undefined;
  const pendingChecks = demo ? [] : requested.filter(check => !scan.data?.perCheck?.[check]);
  const liveCoverage = demo ? undefined : scan.data?.checks?.filter(check => !!scan.data?.perCheck?.[check]).map((check: ScanCheck): ScanCoverage => {
    const outcome = scan.data?.perCheck?.[check];
    return { check: { secret: 'Secrets', sbom: 'SBOM', vuln: 'CVE', config: 'Image config' }[check], status: outcome?.outcome ?? 'skipped', reason: outcome?.reason ?? outcome?.errorCode ?? (outcome ? undefined : 'Результат ещё не получен'), scannerVersion: outcome?.scannerVersion ?? undefined, checksVersion: outcome?.checksVersion, resourcePolicyVersion: outcome?.resourcePolicyVersion };
  });
  const findings = reportData?.findings.filter(item => !demo || filter === 'all' || item.category === filter) ?? [];
  const changeFilter = setFilter;
  const [confirmedVulnCount, setConfirmedVulnCount] = useState<number | null>(null);
  const [confirmedSecretCount, setConfirmedSecretCount] = useState<number | null>(null);
  const vulnPage = vuln.isSuccess && vuln.data.outcome === 'checked' ? vuln.data : undefined;
  const identityMatches = !!vulnPage && !!scan.data?.digest && scan.data.platform === vulnPage.platform &&
    vulnPage.image === (scan.data.imageReference ?? `registry-1.docker.io/library/alpine@${scan.data.digest}`);
  const secretCoverage = reportData?.coverage.find(item => item.check === 'Secrets');
  const statusSecret = scan.data?.perCheck?.secret;
  useEffect(() => {
    if (identityMatches && vulnPage) setConfirmedVulnCount(vulnPage.findingCount);
  }, [identityMatches, vulnPage]);
  useEffect(() => {
    if (statusSecret?.outcome === 'checked' && statusSecret.findingCount != null) setConfirmedSecretCount(statusSecret.findingCount);
    else if (secretCoverage?.status === 'checked' && secretCoverage.findingCount != null) setConfirmedSecretCount(secretCoverage.findingCount);
  }, [statusSecret, secretCoverage]);

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
              <span>Прогресс: {scan.data.percent == null ? 'неизвестен' : `${scan.data.percent}%`}</span>
              {!demo ? <span role="status" aria-label="Состояние realtime">{active ? {
                connecting: 'SSE: подключаемся; статус обновляется через GET',
                connected: 'SSE: подключён; этап подтверждается GET',
                reconnecting: 'SSE: переподключение; статус обновляется через GET',
                polling: 'SSE: недоступен; статус обновляется через GET',
              }[realtime] : 'Скан завершён; realtime остановлен'}</span> : null}
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
                03 <span>{sbomOnly ? 'Пакеты SBOM' : 'Находки и пакеты'}</span>
              </a>
              <a href="#scan-a1-ai">
                04 <span>Помощник</span>
              </a>
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
                      if (window.confirm('Отменить скан? Незавершённые результаты не будут опубликованы.')) {
                        cancellation.mutate(scanId);
                      }
                    }}
                  >
                    {cancellation.isPending ? 'Отменяем…' : 'Отменить скан'}
                  </Button>
                ) : (
                  <Button variant="secondary" type="button" disabled>
                    Отмена недоступна
                  </Button>
                )}
                <p>{demo ? 'Демо не отправляет серверную отмену.' : 'Отмена завершает скан без публикации промежуточных результатов. Статус подтверждается GET snapshot.'}</p>
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
              <section className="scan-a1__panel" aria-labelledby="scan-a1-coverage">
                <p className="scan-a1__eyebrow">02 / ПОКРЫТИЕ</p>
                <h3 id="scan-a1-coverage">Покрытие проверок</h3>
                <p className="scan-a1__muted">Исход каждой проверки отдельно от статуса скана.</p>
                {pendingChecks.length ? <ul aria-label="Проверки без подтверждённого результата">{pendingChecks.map(check => <li key={check}>
                  {check}: {active ? `ожидаем подтверждённый результат; ${scan.data.stage ? 'текущий этап указан сервером выше' : 'внутренний этап не предоставлен сервером'}` : 'результат не предоставлен сервером'}
                </li>)}</ul> : null}
                {(liveCoverage ?? reportData?.coverage) ? (
                  <ul className="scan-a1__coverage">
                    {(liveCoverage ?? reportData?.coverage ?? []).map((item) => (
                      <li key={item.check}>
                        <strong>{item.check}</strong>
                        <div>
                          <Badge tone={coverageTone[item.status]}>{coverageLabels[item.status]}</Badge>
                          {item.reason ? <p>{item.reason}</p> : null}
                          {item.checksVersion ? <p>checks {item.checksVersion} · policy {item.resourcePolicyVersion ?? 'не предоставлена'}</p> : null}
                          {item.scannerVersion || item.dbVersion ? (
                            <small>
                              {item.scannerVersion ? `scanner ${item.scannerVersion}` : ''}
                              {item.scannerVersion && item.dbVersion ? ' · ' : ''}
                              {item.dbVersion ? `DB ${item.dbVersion}` : ''}
                            </small>
                          ) : null}
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p>Нет подтверждённого coverage; тип проверки и результат неизвестны. «0 проблем» недопустимо.</p>
                )}
                {!demo ? scan.data.config ? (
                  <div aria-label="Image config coverage">
                    <h4>Image config · только метаданные образа</h4>
                    <p>{coverageLabels[scan.data.config.config.outcome]}{scan.data.config.config.outcome !== 'checked' ? ` · ${scan.data.config.config.reason}` : ''}</p>
                    <p>checks {scan.data.config.checksVersion} · policy {scan.data.config.resourcePolicyVersion}</p>
                    <p>Правила: выполнено {scan.data.config.completedRuleIds.length} / поддерживается {scan.data.config.supportedRuleIds.length} · {scan.data.config.supportedRuleIds.join(', ')}</p>
                    <p>History: {scan.data.config.history.reason}. Dockerfile: {scan.data.config.dockerfile.reason}. IaC: {scan.data.config.iac.reason}.</p>
                    <p>OCI history не является исходным Dockerfile/IaC. Numeric UID без находки не доказывает non-root runtime.</p>
                    {scan.data.config.findings.length ? <ul>{scan.data.config.findings.map(finding => <li key={finding.findingId}>
                      <strong>{finding.ruleId} · {finding.classification} · {finding.severity}</strong>
                      <p>{finding.message}</p><p>{finding.recommendation}</p>
                    </li>)}</ul> : scan.data.config.config.outcome === 'checked' ? <p>Root metadata finding отсутствует; это не гарантия безопасности.</p> : <p>Находки config не подтверждены.</p>}
                  </div>
                ) : <p>Нет подтверждённого image config coverage: проверка ещё не завершена или это legacy scan без versioned evidence.</p> : null}
                {isSbom && sbom.isError ? <Alert role="alert" tone="danger">Не удалось загрузить SBOM: данные не подтверждены.</Alert> : null}
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
              <section className="scan-a1__panel" aria-labelledby="scan-a1-findings">
                <p className="scan-a1__eyebrow">03 / РЕЗУЛЬТАТЫ</p>
                <h3 id="scan-a1-findings">{sbomOnly ? 'Пакеты SBOM' : 'Находки'}</h3>
                {sbomOnly ? (
                  ['queued', 'running'].includes(scan.data.state) ? <p>SBOM ещё выполняется; перечень пакетов не подтверждён.</p> :
                  scan.data.state === 'cancelled' ? <p>Скан отменён; SBOM не подтверждён.</p> :
                  !scan.data.perCheck?.sbom ? <p>Результат SBOM не подтверждён; число пакетов неизвестно.</p> : sbom.isPending ? <p>Загружаем SBOM…</p> : sbom.isError ? (
                    <Alert role="alert" tone="danger">Перечень пакетов недоступен; результат неизвестен.</Alert>
                  ) : sbom.data.outcome === 'failed' ? (
                    <p>SBOM не проверен. Пакеты и уязвимости не подтверждены.</p>
                  ) : (
                    <div>
                      <p>Подтверждённый инвентарь: {sbom.data.componentCount} пакетов · ОС {sbom.data.os.name} {sbom.data.os.version} · {sbom.data.platform}</p>
                      <p className="scan-a1__muted">Образ: {sbom.data.image}. SBOM не содержит оценку CVE и не подтверждает безопасность.</p>
                      <ul className="scan-a1__findings">{sbom.data.components.map((component, index) => (
                        <li key={`${sbomCursor ?? '0'}-${index}`}><strong>{component.name}</strong><p>{component.ecosystem} · версия {component.version}</p></li>
                      ))}</ul>
                      {sbom.data.nextCursor !== null ? <Button variant="secondary" type="button" onClick={() => setSbomCursor(sbom.data.nextCursor ?? undefined)}>Следующая страница SBOM</Button> : null}
                    </div>
                  )
                ) : isSecret || isVuln ? (<>
                <p className="scan-a1__muted">CVE и Secrets — отдельные наборы данных. Общий итог не суммируется из неполных результатов.</p>
                <ScanFilterSheet filter={filter} onFilterChange={changeFilter} cveValue={demo ? 'vulnerability' : 'cve'} />
                <div className="scan-a1__desktop-filter">
                  <label htmlFor="finding-filter">Категория</label>
                  <select id="finding-filter" className={controlClass} value={filter} onChange={event => changeFilter(event.target.value)}>
                    <option value="all">Все категории</option><option value={demo ? 'vulnerability' : 'cve'}>CVE</option><option value="secret">Secrets</option>
                  </select>
                </div>
                <p className="scan-a1__muted">Категория: {filter === 'all' ? 'Все' : filter === 'secret' ? 'Secrets' : 'CVE'}. Показаны загруженные страницы.</p>
            {isVuln && filter !== 'secret' ? <section className="scan-a1__panel" aria-label="Результаты CVE">
              <h4>CVE · registry IMAGE</h4>
              {confirmedVulnCount !== null ? <p>Подтверждённое число CVE: {confirmedVulnCount}</p> : null}
              {vuln.isSuccess ? vuln.data.outcome === 'failed' ? <p>CVE не проверены: {vuln.data.reason ?? vuln.data.errorCode}. Число уязвимостей неизвестно.</p> : vuln.data.outcome === 'unsupported' ? <p>CVE не поддерживаются: {vuln.data.reason}. Это не нулевое число находок.</p> : !identityMatches ? <p>Идентичность образа в CVE-отчёте не совпадает со статусом; результат неизвестен.</p> : <>
                <p>Находок в проверенной области: {vuln.data.findingCount}. Это не гарантия безопасности; другие области не проверялись.</p>
                                {vuln.data.os ? <p>OS CVE: {coverageLabels[vuln.data.os.outcome]}{vuln.data.os.outcome === 'unsupported' ? ` · ${vuln.data.os.reason}` : ''}</p> : null}
                                {vuln.data.node ? <p>Node/npm CVE: {coverageLabels[vuln.data.node.outcome]}{vuln.data.node.outcome === 'unsupported' ? ` · ${vuln.data.node.reason}` : ''}</p> : null}
                                {vuln.data.db ? <p className="scan-a1__muted">DB {vuln.data.db.manifestDigest} · {vuln.data.db.signer} (локальная аттестация, не подпись издателя) · обновлена {vuln.data.db.updatedAt} · срок {vuln.data.db.nextUpdate}</p> : null}
                                <p className="scan-a1__muted">scanner {vuln.data.scannerVersion} · проверено {vuln.data.checkedAt}{scan.data.perCheck?.vuln?.checksVersion ? ` · checks ${scan.data.perCheck.vuln.checksVersion}` : ''}</p>
                <ul className="scan-a1__findings">{vuln.data.findings.map(finding => <VulnAdvisoryCard key={finding.findingId} finding={finding} />)}</ul>
                {vuln.data.nextCursor !== null ? <Button variant="secondary" type="button" onClick={() => setVulnCursor(vuln.data.nextCursor ?? undefined)}>Следующая страница CVE</Button> : null}
              </> : <p>{vuln.isError ? confirmedVulnCount !== null ? 'Страница CVE недоступна; ранее подтверждённое число сохранено.' : vuln.error instanceof ScanHttpError && vuln.error.status === 503 ? 'CVE недоступны: проверьте настройку базы уязвимостей у администратора. Число находок неизвестно.' : 'CVE недоступны; число уязвимостей неизвестно.' : !scan.data.perCheck?.vuln && ['completed', 'partial', 'failed'].includes(scan.data.state) ? 'Нет подтверждённого результата CVE; число находок неизвестно.' : 'Ожидаем результат CVE. Нулевое число не подтверждено.'}</p>}
            </section> : null}
                {isSecret && filter !== 'cve' ? <section aria-label="Результаты Secrets">
                  <h4>Secrets</h4>
                  {!demo ? confirmedSecretCount !== null ? <p>Подтверждённое число Secrets: {confirmedSecretCount}</p> : <p>Число Secrets неизвестно.</p> : null}
                  {report.isPending ? <p>Загружаем результаты Secrets…</p> : null}
                  {report.isError ? <Alert role="alert" tone="danger">{confirmedSecretCount !== null ? 'Страница Secrets недоступна; ранее подтверждённое число сохранено.' : 'Не удалось загрузить результаты; число находок неизвестно.'}</Alert> : null}
                  {secretCoverage && secretCoverage.status !== 'checked' ? <p>Secrets: {coverageLabels[secretCoverage.status]}{secretCoverage.reason ? ` · ${secretCoverage.reason}` : ''}</p> : null}
                  {findings.length > 0 ? <ul className="scan-a1__findings">{findings.map(finding => <li key={finding.findingId}>
                    <span className="scan-a1__eyebrow">НАХОДКА / {finding.severity}</span><strong>{finding.category} · {finding.ruleId}</strong><p>ID: {finding.findingId}</p>
                  </li>)}</ul> : null}
                  {reportData && confirmedSecretCount === 0 ? <p>0 находок в выполненной проверенной области Secrets; другие области не исключены.</p> : null}
                  {demo && reportData && findings.length === 0 ? filter !== 'all' ? <Alert tone="neutral">Нет совпадений фильтра на загруженной странице. <button type="button" className="scan-a1__link" onClick={() => changeFilter('all')}>Сбросить фильтр</button></Alert> : !cursor && !reportData.nextCursor ? <p>{secretCoverage?.status === 'checked' ? '0 находок в выполненной проверенной области; другие области не исключены.' : 'Нет подтверждённых находок: область не проверена полностью.'}</p> : null : null}
                  {!demo && reportData && findings.length === 0 && confirmedSecretCount !== 0 ? <p>На текущей странице находок Secrets нет; это не подтверждает нулевой итог.</p> : null}
                  {reportData?.nextCursor ? <Button variant="secondary" type="button" onClick={() => setCursor(reportData.nextCursor ?? undefined)}>Следующая страница</Button> : null}
                </section> : null}
                {filter === 'cve' && !isVuln ? <p>CVE не запрашивались для этого скана.</p> : null}
                {filter === 'secret' && !isSecret ? <p>Secrets не запрашивались для этого скана.</p> : null}
                </>) : <p>Тип проверки пока не указан в ответе статуса. Результаты не запрашиваются до подтверждения типа сервером.</p>}
              </section>
            </div>
            {isSbom && !sbomOnly ? <section className="scan-a1__panel" aria-label="Пакеты SBOM">
              <h3>Пакеты SBOM</h3>
              {sbom.isSuccess ? sbom.data.outcome === 'failed' ? <p>SBOM не проверен: {sbom.data.errorCode}. Число пакетов неизвестно.</p> : <>
                <p>Инвентарь image: {sbom.data.componentCount} пакетов · ОС {sbom.data.os.name} {sbom.data.os.version}. SBOM не оценивает CVE.</p>
                <ul className="scan-a1__findings">{sbom.data.components.map((component, index) => <li key={`${sbomCursor ?? '0'}-${index}`}><strong>{component.name}</strong><p>{component.ecosystem} · {component.version}</p></li>)}</ul>
                {sbom.data.nextCursor !== null ? <Button variant="secondary" type="button" onClick={() => setSbomCursor(sbom.data.nextCursor ?? undefined)}>Следующая страница SBOM</Button> : null}
              </> : <p>{sbom.isError ? 'SBOM недоступен; число пакетов неизвестно.' : 'Ожидаем результат SBOM.'}</p>}
            </section> : null}
            <section className="scan-a1__ai" aria-labelledby="scan-a1-ai">
              <div>
                <p className="scan-a1__eyebrow">04 / КОНТЕКСТНЫЙ ПОМОЩНИК · КОНЦЕПТ</p>
                <h3 id="scan-a1-ai">
                  <Sparkles size={24} aria-hidden="true" /> Спросить об отчёте
                </h3>
                <p>
                  Будущий чат должен учитывать finding_id и границы coverage. Здесь нет модели, истории или
                  авторизованной отправки.
                </p>
              </div>
              <div className="scan-a1__compose">
                <label htmlFor="scan-a1-prompt">Ваш вопрос</label>
                <textarea id="scan-a1-prompt" disabled placeholder="Почему проверка не выполнена?" />
                <Button type="button" disabled>
                  Чат недоступен
                </Button>
                <small>Сообщения не сохраняются и не отправляются.</small>
              </div>
            </section>
          </>
        ) : null}
      </section>
    </ScanShell>
  );
}
