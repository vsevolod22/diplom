import { useCallback, useState } from 'react';
import { scanReasonLabel } from '@/features/scans/scanProgressPresentation';
import { ScanCheckFailure } from '@/features/scans/ScanCheckFailure';
import { normalizeReportQuery, ReportViewContractError, reportViewIdentity } from '@/shared/api/scans/reportView';
import type { SbomReportQuery, SecretReportQuery, VulnReportQuery } from '@/shared/api/scans/reportView';
import { SbomReportControls, SecretReportControls, UnsupportedReportControls, VulnReportControls } from './ReportViewControls';
import { cveMetadataIdentity, hasCveMetadata, savedDbAge } from '@/shared/api/scans/cveDbMetadata';
import type {
  ScanResults,
  ScanSbom,
  ScanStatus,
  ScanTransport,
  ScanVuln,
} from '@/shared/api/scans/scanTransport';
import { CursorReportPager, ReportIdentityError } from './CursorReportPager';
import { fingerprintReportRows } from './reportRowFingerprint';
import type { PageDescription } from './CursorReportPager';
import { VulnAdvisoryCard } from './VulnAdvisoryCard';
import { ReportCount } from './ScanReportOverview';
import { countVulnerabilityIdentifiers, identifierCountLabel } from '@/shared/api/scans/publicVulnerabilityIdentifiers';

type Props = {
  status: ScanStatus;
  transport: ScanTransport;
  scope: readonly (string | number)[];
  demo: boolean;
  filter: string;
  onResetFilter: () => void;
};
const terminal = ['completed', 'partial', 'failed', 'cancelled'];
const outcomes = {
  checked: 'Выполнено (не гарантия безопасности)',
  failed: 'Сбой · не проверено',
  unsupported: 'Не поддерживается',
  skipped: 'Пропущено',
  not_authorized: 'Нет разрешения',
};

function matchesTarget(status: ScanStatus, page: { image: string; platform: string }) {
  return (
    !!status.digest &&
    page.image.endsWith(`@${status.digest}`) &&
    page.platform === status.platform &&
    page.image === (status.imageReference ?? `registry-1.docker.io/library/alpine@${status.digest}`)
  );
}
function checkVersion(
  status: ScanStatus,
  check: 'vuln' | 'sbom',
  page: { checkedAt: string; scannerVersion: string },
  count: number,
) {
  const result = status.perCheck?.[check];
  if (
    result?.outcome !== 'checked' ||
    (result.checkedAt && result.checkedAt !== page.checkedAt) ||
    (result.scannerVersion && result.scannerVersion !== page.scannerVersion) ||
    (check === 'vuln' && result.findingCount != null && result.findingCount !== count) ||
    (check === 'sbom' && result.componentCount != null && result.componentCount !== count)
  )
    throw new ReportIdentityError();
}

export function ScanReportSections(props: Props) {
  const { status, demo, scope, filter } = props;
  const checks = status.checks ?? (status.check ? [status.check] : []);
  const identity = JSON.stringify([
    demo,
    scope,
    status.scanId,
    status.state,
    status.digest,
    status.platform,
    status.imageReference,
    status.updatedAt,
    status.checks,
    status.perCheck,
  ]);
  const secretsFirst = status.perCheck?.secret?.outcome === 'checked' && (status.perCheck.secret.findingCount ?? 0) > 0;
  const secrets = demo || checks.includes('secret') ? (
    <div key="secrets" hidden={!demo && filter === 'cve'}>
      <SecretReport {...props} reportKey={`${identity}:secret`} />
    </div>
  ) : null;
  return (
    <div key={identity} className="scan-report-sections">
      {secretsFirst ? secrets : null}
      {checks.includes('vuln') ? (
        <div key="vulnerabilities" hidden={filter === 'secret'}>
          <VulnReport {...props} reportKey={`${identity}:vuln`} />
        </div>
      ) : null}
      {!secretsFirst ? secrets : null}
      {checks.includes('sbom') ? <SbomReport {...props} reportKey={`${identity}:sbom`} /> : null}
      {filter === 'cve' && !checks.includes('vuln') ? <p>Проверка уязвимостей не запрашивалась для этого образа.</p> : null}
      {filter === 'secret' && !demo && !checks.includes('secret') ? (
        <p>Поиск возможных секретов не запрашивался для этого образа.</p>
      ) : null}
      {!demo && checks.length === 0 ? (
        <p>
          Тип проверки пока не указан в ответе статуса. Результаты не запрашиваются до подтверждения типа
          сервером.
        </p>
      ) : null}
    </div>
  );
}

type SectionProps = Props & { reportKey: string };
function useReportSelection<Q>(initial: Q) {
  const [selection, setSelection] = useState({ query: initial, revision: 0 });
  const select = (query: Q) => setSelection(previous => ({ query, revision: previous.revision + 1 }));
  return [selection.query, select, selection.revision] as const;
}
function viewRowFingerprint(rows: Parameters<typeof fingerprintReportRows>[0], reportView: boolean): string {
  try { return fingerprintReportRows(rows); }
  catch (error) { if (reportView) throw new ReportViewContractError(); throw error; }
}
function VulnReport({ status, transport, reportKey, demo, scope }: SectionProps) {

  const label = 'Уязвимости';
  const [query, setQuery, revision] = useReportSelection<VulnReportQuery>({ view: 'report-v1', limit: 25, sort: 'severity:desc', severity: null });
  const supported = !demo && transport.kind === 'live';
  const load = useCallback(
    (cursor: string | undefined, signal: AbortSignal) => transport.vuln(status.scanId, cursor, signal, supported ? query : undefined),
    [transport, status.scanId, supported, query],
  );
  const describe = useCallback(
    (page: ScanVuln): PageDescription => {
      if (supported && !page.page) throw new ReportViewContractError();
      const result = status.perCheck?.vuln;
      if (hasCveMetadata(page) || hasCveMetadata(result)) {
        if (!('resultContractVersion' in page) || !result || result.resultContractVersion !== 2 ||
            page.outcome !== result.outcome || cveMetadataIdentity(page) !== cveMetadataIdentity(result) ||
            (page.outcome === 'unsupported' && page.reason !== result.reason)) throw new ReportIdentityError();
      }
      if (page.outcome !== 'checked')
        return {
          checked: false,
          identity: page.outcome,
          rowIds: [],
          rowFingerprint: fingerprintReportRows([]),
          total: null,
          nextCursor: null,
        };
      if (!matchesTarget(status, page)) throw new ReportIdentityError();
      checkVersion(status, 'vuln', page, page.findingCount);
      if (page.profile !== status.profile || JSON.stringify(page.identifierCounts) !== JSON.stringify(status.identifierCounts)) throw new ReportIdentityError();
      return {
        checked: true,
        identity: JSON.stringify([
          page.image,
          page.platform,
          page.checkedAt,
          page.scannerVersion,
          page.identifierCounts,
          page.os,
          page.node,
          page.db,
          'resultContractVersion' in page ? cveMetadataIdentity(page) : null,
          reportViewIdentity(page.page),
        ]),
        rowIds: page.findings.map((item) => item.findingId),
        rowFingerprint: viewRowFingerprint(page.findings, !!page.page),
        total: page.page?.matchedCount ?? page.findingCount,
        ...(page.page ? { wholeTotal: page.page.totalCount, offset: page.page.offset } : {}),
        nextCursor: page.nextCursor,
      };
    },
    [status, supported],
  );
  return (
    <section id="scan-report-vulnerabilities" tabIndex={-1} aria-label={`Результаты ${label}`} className="scan-report-section">
      <h4>{label}</h4>
      <p className="scan-report-section__intro">Сравните установленную и исправленную версии. Оценка опасности относится к находке, а не ко всему образу.</p>
      {/* Controls survive query changes; the keyed pager alone cancels and resets replaced reads. */}
      {supported ? <VulnReportControls query={query} onChange={setQuery} disabled={false} label={label} /> : <UnsupportedReportControls />}
      <CursorReportPager
        reportKey={`${reportKey}:${revision}:${JSON.stringify(query)}`}
        queryKey={[...scope, 'report-page', status.scanId, 'vuln', supported ? { view: query.view, ...normalizeReportQuery('vuln', query) } : null, reportKey]}
        label={label}
        load={load}
        describe={describe}
        enabled={terminal.includes(status.state) && !!status.perCheck?.vuln}
        waiting={status.state === 'cancelled' ? `${label}: завершённый результат не сохранён. Число уязвимостей неизвестно.` : `Ожидаем результат ${label}. Нулевое число не подтверждено.`}
      >
        {(page) =>
          page.outcome === 'failed' ? (
            <div className="scan-report-unavailable">
              <strong>Не удалось проверить уязвимости</strong>
              <p>Число уязвимостей неизвестно, а не равно нулю. Не используйте этот результат как подтверждение безопасности.</p>
              <ScanCheckFailure detail={page.failureDetail} reason={page.reason ?? page.errorCode} />
            </div>
          ) : page.outcome === 'unsupported' ? (
            <div className="scan-report-unavailable">
              <strong>Проверка уязвимостей не поддерживается</strong>
              <p>{scanReasonLabel(page.reason)}. Число уязвимостей неизвестно, а не равно нулю.</p>
              <p>Проверьте эту область другим подходящим инструментом; повторный запуск сам по себе не устраняет ограничение.</p>
              <CveDbFacts page={page} />
            </div>
          ) : (
            <>
              <p className="scan-a1__muted">
                Всего находок в проверенной области: <strong>{page.findingCount}</strong>. Фильтр меняет список, но не этот итог.
              </p>

              <div className="scan-report-section__coverage">
                {page.os ? (
                  <p>
                    Системные пакеты: {page.os.outcome === 'checked' ? 'проверены' : outcomes[page.os.outcome]}
                    {page.os.outcome === 'unsupported' ? ` · ${scanReasonLabel(page.os.reason)}` : ''}
                  </p>
                ) : null}
                {page.node ? (
                  <p>
                    Пакеты приложения (Node/npm): {page.node.outcome === 'checked' ? 'проверены' : outcomes[page.node.outcome]}
                    {page.node.outcome === 'unsupported' ? ` · ${scanReasonLabel(page.node.reason)}` : ''}
                                        {page.node.outcome === 'unsupported' && page.node.reason === 'NODE_INVENTORY_UNKNOWN' ? ' · Инвентарь не установлен; отсутствие Node-пакетов не доказано.' : ''}
                  </p>
                ) : null}
                {!page.os || !page.node ? <p>Неизвестно, насколько полно проверены системные пакеты и пакеты приложения.</p> : null}
              </div>
              <CveDbFacts page={page} />
              <details className="scan-report-section__metadata">
                <summary>Подробности · данные проверки уязвимостей</summary>
                                {page.identifierCounts ? <p>Весь сохранённый отчёт (до фильтров): {identifierCountLabel(page.identifierCounts)}.
                                  {' '}На этой странице: {identifierCountLabel(countVulnerabilityIdentifiers(page.findings))}.
                                </p> : null}
                <p>scanner {page.scannerVersion} · проверено {page.checkedAt}
                  {status.perCheck?.vuln?.checksVersion ? ` · checks ${status.perCheck.vuln.checksVersion}` : ''}
                </p>
              </details>
              {page.findingCount === 0 ? (
                <p>0 находок в выполненной проверенной области; это не гарантия безопасности.</p>
              ) : null}
              {page.page?.matchedCount === 0 && page.findingCount > 0 ? <p>По выбранному фильтру находок нет. Во всём отчёте: {page.findingCount}. Измените фильтр, чтобы увидеть остальные.</p> : null}
              <ul className="scan-vuln-list" aria-label={`Находки ${label}`}>
                {page.findings.map((finding) => (
                  <VulnAdvisoryCard key={finding.findingId} finding={finding} />
                ))}
              </ul>
            </>
          )
        }
      </CursorReportPager>
    </section>
  );
}

function isV2CvePage(page: ScanVuln): page is Extract<ScanVuln, { resultContractVersion: 2 }> {
  return 'resultContractVersion' in page && page.resultContractVersion === 2;
}

function CveDbFacts({ page }: { page: Exclude<ScanVuln, { outcome: 'failed' }> }) {
  const v2 = isV2CvePage(page) ? page : null;
  return <div className="scan-report-db">
    {v2 ? <div className="scan-report-db__policy">
      <p>Возраст базы на момент проверки: {savedDbAge(v2.db, v2.dbPolicy.evaluatedAt)}.</p>
      {v2.dbPolicy.warnings.includes('DB_DATA_OLDER_THAN_24H') ? <p className="scan-vuln-row__warning">Данные базы старше 24 часов на момент проверки.</p> : null}
      {v2.dbPolicy.warnings.includes('DB_PUBLICATION_OVERDUE') ? <p className="scan-vuln-row__warning">Ожидаемое обновление базы не вышло к моменту проверки.</p> : null}
    </div> : <p className="scan-a1__muted">Актуальность базы на момент проверки не подтверждена.</p>}
    <details className="scan-report-section__metadata">
      <summary>Сведения о базе уязвимостей</summary>
      {v2 ? <>
        <p><strong>Политика CVE DB: UpdatedAt + 14 дней включительно</strong> · {v2.dbPolicy.status === 'stale-but-usable' ? 'допустима с предупреждениями' : 'допустима'} на сохранённый момент проверки, не сейчас.</p>
        <p>Оценено {new Date(v2.dbPolicy.evaluatedAt).toISOString()}. Исторический результат не подтверждает текущую готовность базы или безопасность образа.</p>
      </> : null}
      {page.db ? <>
        <p>DB {page.db.manifestDigest} · {page.db.signer} (локальная аттестация, не подпись издателя; браузер не проверяет подпись).</p>
        <p>UpdatedAt · обновлена {page.db.updatedAt}</p>
        <p>DownloadedAt · загружена {page.db.downloadedAt}</p>
        <p>NextUpdate · ожидаемая публикация {page.db.nextUpdate}, не срок допустимости.</p>
      </> : <p>Идентичность DB не предоставлена.</p>}
      {v2 ? <>
        <p>usableUntil · предел политики {v2.usableUntil} (включительно).</p>
        <p>worker checkedAt · {v2.checkedAt} · сохранённый clock {v2.workerCheckedAt}</p>
        <p>result contract 2 · envelope 1 · {v2.dbPolicy.policy}</p>
      </> : null}
    </details>
  </div>;
}

function SbomReport({ status, transport, reportKey, demo, scope }: SectionProps) {
  const [query, setQuery, revision] = useReportSelection<SbomReportQuery>({ view: 'report-v1', limit: 25, sort: 'name:asc', ecosystem: null, name: null });
  const supported = !demo && transport.kind === 'live';
  const load = useCallback(
    (cursor: string | undefined, signal: AbortSignal) => transport.sbom(status.scanId, cursor, signal, supported ? query : undefined),
    [transport, status.scanId, supported, query],
  );
  const describe = useCallback(
    (page: ScanSbom): PageDescription => {
      if (supported && !page.page) throw new ReportViewContractError();
      if (page.outcome !== 'checked')
        return {
          checked: false,
          identity: page.outcome,
          rowIds: [],
          rowFingerprint: fingerprintReportRows([]),
          total: null,
          nextCursor: null,
        };
      if (!matchesTarget(status, page)) throw new ReportIdentityError();
      checkVersion(status, 'sbom', page, page.componentCount);
      return {
        checked: true,
        identity: JSON.stringify([page.image, page.platform, page.checkedAt, page.scannerVersion, page.os, reportViewIdentity(page.page)]),
        rowIds: page.components.map((item) => JSON.stringify([item.ecosystem, item.name, item.version])),
        rowFingerprint: viewRowFingerprint(page.components, !!page.page),
        total: page.page?.matchedCount ?? page.componentCount,
        ...(page.page ? { wholeTotal: page.page.totalCount, offset: page.page.offset } : {}),
        nextCursor: page.nextCursor,
      };
    },
    [status, supported],
  );
  return (
    <details aria-label="Пакеты SBOM" className="scan-report-section">
      <summary>Состав образа · найти пакет и его версию{status.perCheck?.sbom?.outcome === 'checked' && status.perCheck.sbom.componentCount != null ? <> · <ReportCount value={status.perCheck.sbom.componentCount} unit="package" /></> : null}</summary>
      <p>Инвентарь пакетов (SBOM) — для проверки зависимостей. Это не список уязвимостей.</p>
      {supported ? <SbomReportControls query={query} onChange={setQuery} disabled={false} /> : <UnsupportedReportControls />}
      <CursorReportPager
        reportKey={`${reportKey}:${revision}:${JSON.stringify(query)}`}
        queryKey={[...scope, 'report-page', status.scanId, 'sbom', supported ? { view: query.view, ...normalizeReportQuery('sbom', query) } : null, reportKey]}

        label="Пакеты"
        load={load}
        describe={describe}
        enabled={terminal.includes(status.state) && !!status.perCheck?.sbom}
        waiting={status.state === 'cancelled' ? 'Состав пакетов не сохранён до отмены. Число пакетов неизвестно.' : 'Состав образа ещё не подтверждён; число пакетов неизвестно.'}
      >
        {(page) =>
          page.outcome === 'failed' ? (
            <>
              <p>Состав образа не проверен. Число пакетов неизвестно.</p>
              <ScanCheckFailure detail={page.failureDetail} reason={page.reason ?? page.errorCode} />
            </>
          ) : (
            <>
              <p>
                Подтверждённый инвентарь: <ReportCount value={page.componentCount} unit="package" /> · ОС {page.os.name} {page.os.version}{' '}
                · {page.platform}
              </p>
              <p className="scan-a1__muted">Список пакетов сам по себе не подтверждает безопасность образа.</p>
              <details className="scan-report-section__metadata">
                <summary>Сведения о составе пакетов</summary>
                <p>Образ: {page.image}. SBOM не содержит оценку CVE.</p>
                <p>scanner {page.scannerVersion} · проверено {page.checkedAt}</p>
              </details>
              {page.page?.matchedCount === 0 ? <p>Пакетов с такими параметрами нет. Измените фильтр; во всём инвентаре: <ReportCount value={page.componentCount} unit="package" />.</p> : null}
              <ul className="scan-report-inventory">
                {page.components.map((component) => (
                  <li key={JSON.stringify(component)}>
                    <strong>{component.name}</strong>
                    <span>
                      {component.ecosystem} · версия {component.version}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )
        }
      </CursorReportPager>
    </details>
  );
}

function SecretReport({ status, transport, reportKey, demo, scope, filter, onResetFilter }: SectionProps) {
  const [query, setQuery, revision] = useReportSelection<SecretReportQuery>({ view: 'report-v1', limit: 25, sort: 'ruleId:asc', ruleId: null, linePresence: null });
  const supported = !demo && transport.kind === 'live';
  const load = useCallback(
    (cursor: string | undefined, signal: AbortSignal) => transport.results(status.scanId, cursor, signal, supported ? query : undefined),
    [transport, status.scanId, supported, query],
  );
  const describe = useCallback(
    (page: ScanResults): PageDescription => {
      if (supported && !page.page) throw new ReportViewContractError();
      const coverage = page.coverage.find((item) => item.check === 'Secrets');
      const result = status.perCheck?.secret;
      if (
        !demo &&
        (coverage?.status !== result?.outcome ||
          (coverage?.checkedAt !== undefined && result?.checkedAt !== undefined && coverage.checkedAt !== result.checkedAt) ||
          (result?.outcome === 'checked' &&
            ((result.findingCount != null && result.findingCount !== coverage?.findingCount) ||
              (result.scannerVersion != null && result.scannerVersion !== coverage?.scannerVersion))))
      )
        throw new ReportIdentityError();
      if (!demo && coverage?.status === 'checked' && !terminal.includes(status.state))
        throw new ReportIdentityError();
      return {
        checked: coverage?.status === 'checked',
        identity: JSON.stringify([coverage, reportViewIdentity(page.page)]),
        rowIds: coverage?.status === 'checked' ? page.findings.map((item) => item.findingId) : [],
        rowFingerprint: viewRowFingerprint(coverage?.status === 'checked' ? page.findings : [], !!page.page),
        total: coverage?.status === 'checked' ? (page.page?.matchedCount ?? coverage.findingCount ?? null) : null,
        ...(page.page ? { wholeTotal: page.page.totalCount, offset: page.page.offset } : {}),
        nextCursor: coverage?.status === 'checked' ? page.nextCursor : null,
      };
    },
    [status, demo, supported],
  );
  return (
    <section id="scan-report-secrets" tabIndex={-1} aria-label="Возможные секреты" className="scan-report-section">
      <h4>Возможные ключи и пароли</h4>
      <p>Совпадение с правилом ещё не означает утечку. Проверьте, являются ли найденные данные действующими; сами значения здесь не отображаются.</p>
      {supported ? <SecretReportControls query={query} onChange={setQuery} disabled={false} /> : <UnsupportedReportControls />}
      <CursorReportPager
        reportKey={`${reportKey}:${revision}:${JSON.stringify(query)}`}
        queryKey={[...scope, 'report-page', status.scanId, 'secret', supported ? { view: query.view, ...normalizeReportQuery('secret', query) } : null, reportKey]}

        label="Возможные секреты"
        load={load}
        describe={describe}
        enabled={demo || !!status.perCheck?.secret}
        waiting={status.state === 'cancelled' ? 'Результат поиска секретов не сохранён до отмены. Число находок неизвестно.' : 'Результат поиска секретов не подтверждён; число находок неизвестно.'}
      >
        {(page) => {
          const coverage = page.coverage.find((item) => item.check === 'Secrets');
          const findings =
            coverage?.status === 'checked'
              ? page.findings.filter((item) => !demo || filter === 'all' || item.category === filter)
              : [];
          return (
            <>
              {coverage ? (
                <p>
                  Поиск секретов:{' '}
                  {coverage.status === 'checked'
                    ? 'проверка выполнена; не гарантия безопасности'
                    : outcomes[coverage.status]}
                  {coverage.status !== 'failed' && coverage.reason ? ` · ${scanReasonLabel(coverage.reason) === coverage.reason ? 'причина не описана' : scanReasonLabel(coverage.reason)}` : ''}
                </p>
              ) : (
                <p>Неизвестно, выполнен ли поиск секретов.</p>
              )}
              {coverage?.status === 'failed' ? (
                <ScanCheckFailure detail={coverage.failureDetail} reason={coverage.reason} />
              ) : coverage?.reason ? <details><summary>Подробности · причина результата</summary><p>{coverage.reason}</p></details> : null}
              {findings.length ? (
                <ul className="scan-report-inventory">
                  {findings.map((finding, index) => (
                    <li key={finding.findingId}>
                      <strong>{finding.category === 'secret' ? 'Возможный секрет' : 'Демонстрационная находка'} · на странице {index + 1}</strong>
                      <span>{finding.line == null ? 'Номер строки неизвестен' : `Строка ${finding.line}`}</span>
                      {finding.category === 'secret' ? <p>Если это действующий ключ или пароль, замените его, уберите из сборки и пересоберите образ. Удаление из нового образа само по себе не отзывает ключ.</p> : null}
                      <details><summary>Подробности · правило и место находки</summary>
                        <p>Правило: {finding.ruleId} · категория: {finding.category}</p>
                        {finding.location ? <p>Место: {finding.location}</p> : null}
                        {finding.evidenceRef ? <p>Ссылка на свидетельство: {finding.evidenceRef}</p> : null}
                        <p>ID: {finding.findingId}</p>
                      </details>
                    </li>
                  ))}
                </ul>
              ) : page.page?.matchedCount === 0 && coverage?.findingCount !== 0 ? (
                <p>По выбранному фильтру находок нет. Во всём отчёте: {coverage?.findingCount ?? 'количество неизвестно'}.</p>
              ) : demo && filter !== 'all' ? (
                <p>
                  Нет совпадений фильтра на загруженной странице.{' '}
                  <button type="button" className="scan-a1__link" onClick={onResetFilter}>
                    Сбросить фильтр
                  </button>
                </p>
              ) : coverage?.status === 'checked' && coverage.findingCount === 0 ? (
                <p>В выполненной проверке секретов находок нет. Это не исключает их наличие в непроверенных областях.</p>
              ) : coverage?.status === 'checked' ? (
                <p>На текущей странице находок нет; это не значит, что их нет во всём отчёте.</p>
              ) : (
                <p>Нет подтверждённых находок: область не проверена полностью.</p>
              )}
              <details className="scan-report-section__metadata">
                <summary>Как проверить совпадение</summary>
                <p>Значения секретов не отображаются. Правило и номер строки помогают найти совпадение, но не определяют его опасность. Проверяйте действительность ключа в своей системе, не публикуя его значение.</p>
              </details>
            </>
          );
        }}
      </CursorReportPager>
    </section>
  );
}
