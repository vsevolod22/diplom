import { useCallback, useState } from 'react';
import { ReportViewContractError, reportViewIdentity } from '@/shared/api/scans/reportView';
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

type Props = {
  status: ScanStatus;
  transport: ScanTransport;
  scope: readonly (string | number)[];
  demo: boolean;
  filter: string;
  onResetFilter: () => void;
};
const terminal = ['completed', 'partial', 'failed'];
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
  return (
    <div key={identity} className="scan-report-sections">
      <p className="scan-a1__muted">
        CVE, Secrets и SBOM — независимые наборы данных и итоги. Категория только переключает видимость; не
        сортирует и не фильтрует весь отчёт.
      </p>
      {checks.includes('vuln') ? (
        <div hidden={filter === 'secret'}>
          <VulnReport {...props} reportKey={`${identity}:vuln`} />
        </div>
      ) : null}
      {demo || checks.includes('secret') ? (
        <div hidden={!demo && filter === 'cve'}>
          <SecretReport {...props} reportKey={`${identity}:secret`} />
        </div>
      ) : null}
      {checks.includes('sbom') ? <SbomReport {...props} reportKey={`${identity}:sbom`} /> : null}
      {filter === 'cve' && !checks.includes('vuln') ? <p>CVE не запрашивались для этого скана.</p> : null}
      {filter === 'secret' && !demo && !checks.includes('secret') ? (
        <p>Secrets не запрашивались для этого скана.</p>
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
function VulnReport({ status, transport, reportKey, demo }: SectionProps) {
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
      return {
        checked: true,
        identity: JSON.stringify([
          page.image,
          page.platform,
          page.checkedAt,
          page.scannerVersion,
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
    <section aria-label="Результаты CVE" className="scan-report-section">
      <h4>
        CVE <span className="scan-report-section__scope">registry IMAGE</span>
      </h4>
      <CursorReportPager
        reportKey={`${reportKey}:${revision}:${JSON.stringify(query)}`}
        controls={pending => supported ? <VulnReportControls query={query} onChange={setQuery} disabled={pending} /> : <UnsupportedReportControls />}
        label="CVE"
        load={load}
        describe={describe}
        enabled={terminal.includes(status.state) && !!status.perCheck?.vuln}
        waiting="Ожидаем результат CVE. Нулевое число не подтверждено."
      >
        {(page) =>
          page.outcome === 'failed' ? (
            <p>CVE не проверены: {page.reason ?? page.errorCode}. Число уязвимостей неизвестно.</p>
          ) : page.outcome === 'unsupported' ? (
            <>
              <p>CVE не поддерживаются: {page.reason}. Это не нулевое число находок.</p>
              <CveDbFacts page={page} />
            </>
          ) : (
            <>
              <p className="scan-a1__muted">
                Находок в проверенной области: {page.findingCount}. Это не гарантия безопасности; другие
                области не проверялись.
              </p>
              <div className="scan-report-section__coverage">
                {page.os ? (
                  <p>
                    OS CVE: {outcomes[page.os.outcome]}
                    {page.os.outcome === 'unsupported' ? ` · ${page.os.reason}` : ''}
                  </p>
                ) : null}
                {page.node ? (
                  <p>
                    Node/npm CVE: {outcomes[page.node.outcome]}
                    {page.node.outcome === 'unsupported' ? ` · ${page.node.reason}` : ''}
                  </p>
                ) : null}
                {!page.os || !page.node ? <p>Часть сведений о покрытии OS/Node не предоставлена.</p> : null}
              </div>
              <CveDbFacts page={page} />
              <p className="scan-a1__muted">scanner {page.scannerVersion} · проверено {page.checkedAt}
                {status.perCheck?.vuln?.checksVersion ? ` · checks ${status.perCheck.vuln.checksVersion}` : ''}
              </p>
              {page.findingCount === 0 ? (
                <p>0 CVE в выполненной проверенной области; это не гарантия безопасности.</p>
              ) : null}
              {page.page?.matchedCount === 0 && page.findingCount > 0 ? <p>Нет совпадений глобального фильтра CVE. Полный отчёт содержит {page.findingCount} находок.</p> : null}
              <ul className="scan-vuln-list" aria-label="Находки CVE">
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
      <p><strong>Политика CVE DB: UpdatedAt + 14 дней включительно</strong> · {v2.dbPolicy.status === 'stale-but-usable' ? 'допустима с предупреждениями' : 'допустима'} на сохранённый момент проверки, не сейчас.</p>
      <p>Возраст базы на сохранённый момент: {savedDbAge(v2.db, v2.dbPolicy.evaluatedAt)} · оценено {new Date(v2.dbPolicy.evaluatedAt).toISOString()}.</p>
      {v2.dbPolicy.warnings.includes('DB_DATA_OLDER_THAN_24H') ? <p className="scan-vuln-row__warning">DB_DATA_OLDER_THAN_24H: данные базы старше 24 часов на момент оценки.</p> : null}
      {v2.dbPolicy.warnings.includes('DB_PUBLICATION_OVERDUE') ? <p className="scan-vuln-row__warning">DB_PUBLICATION_OVERDUE: ожидаемая публикация NextUpdate просрочена на момент оценки.</p> : null}
      <p>Исторический результат не подтверждает текущую готовность базы или безопасность образа.</p>
    </div> : <p className="scan-a1__muted">Legacy CVE: versioned policy evidence не предоставлено; правило 14 дней и актуальная допустимость не подтверждены.</p>}
    <details className="scan-report-section__metadata">
      <summary>Версии scanner и базы CVE</summary>
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

function SbomReport({ status, transport, reportKey, demo }: SectionProps) {
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
    <section aria-label="Пакеты SBOM" className="scan-report-section">
      <h4>Пакеты SBOM</h4>
      <CursorReportPager
        reportKey={`${reportKey}:${revision}:${JSON.stringify(query)}`}
        controls={pending => supported ? <SbomReportControls query={query} onChange={setQuery} disabled={pending} /> : <UnsupportedReportControls />}
        label="SBOM"
        load={load}
        describe={describe}
        enabled={terminal.includes(status.state) && !!status.perCheck?.sbom}
        waiting="SBOM не подтверждён; число пакетов неизвестно."
      >
        {(page) =>
          page.outcome === 'failed' ? (
            <p>SBOM не проверен: {page.reason ?? page.errorCode}. Число пакетов неизвестно.</p>
          ) : (
            <>
              <p>
                Подтверждённый инвентарь: {page.componentCount} пакетов · ОС {page.os.name} {page.os.version}{' '}
                · {page.platform}
              </p>
              <p className="scan-a1__muted">
                Образ: {page.image}. SBOM не содержит оценку CVE и не подтверждает безопасность.
              </p>
              <p className="scan-a1__muted">
                scanner {page.scannerVersion} · проверено {page.checkedAt}
              </p>
              {page.page?.matchedCount === 0 ? <p>Нет совпадений глобального фильтра SBOM; полный инвентарь: {page.componentCount} пакетов.</p> : null}
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
    </section>
  );
}

function SecretReport({ status, transport, reportKey, demo, filter, onResetFilter }: SectionProps) {
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
    <section aria-label="Результаты Secrets" className="scan-report-section">
      <h4>Secrets</h4>
      <CursorReportPager
        reportKey={`${reportKey}:${revision}:${JSON.stringify(query)}`}
        controls={pending => supported ? <SecretReportControls query={query} onChange={setQuery} disabled={pending} /> : <UnsupportedReportControls />}
        label="Secrets"
        load={load}
        describe={describe}
        enabled={demo || !!status.perCheck?.secret}
        waiting="Результат Secrets не подтверждён; число находок неизвестно."
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
                  Secrets:{' '}
                  {coverage.status === 'checked'
                    ? 'проверка выполнена; не гарантия безопасности'
                    : outcomes[coverage.status]}
                  {coverage.reason ? ` · ${coverage.reason}` : ''}
                </p>
              ) : (
                <p>Coverage Secrets неизвестно.</p>
              )}
              {findings.length ? (
                <ul className="scan-report-inventory">
                  {findings.map((finding) => (
                    <li key={finding.findingId}>
                      <strong>{finding.ruleId}</strong>
                      <span>
                        {finding.category} · {finding.line == null ? 'Номер строки неизвестен' : `Строка ${finding.line}`}
                      </span>
                      <span>ID: {finding.findingId}</span>
                    </li>
                  ))}
                </ul>
              ) : page.page?.matchedCount === 0 && coverage?.findingCount !== 0 ? (
                <p>Нет совпадений глобального фильтра Secrets; полный отчёт: {coverage?.findingCount ?? 'неизвестен'}.</p>
              ) : demo && filter !== 'all' ? (
                <p>
                  Нет совпадений фильтра на загруженной странице.{' '}
                  <button type="button" className="scan-a1__link" onClick={onResetFilter}>
                    Сбросить фильтр
                  </button>
                </p>
              ) : coverage?.status === 'checked' && coverage.findingCount === 0 ? (
                <p>0 находок в выполненной проверенной области Secrets; другие области не исключены.</p>
              ) : coverage?.status === 'checked' ? (
                <p>На текущей странице находок Secrets нет; это не подтверждает нулевой итог.</p>
              ) : (
                <p>Нет подтверждённых находок: область не проверена полностью.</p>
              )}
              <p className="scan-a1__muted">
                Значения секретов не отображаются. Номер строки и правило не являются оценкой severity.
              </p>
            </>
          );
        }}
      </CursorReportPager>
    </section>
  );
}
