import { useCallback } from 'react';
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
function VulnReport({ status, transport, reportKey }: SectionProps) {
  const load = useCallback(
    (cursor: string | undefined, signal: AbortSignal) => transport.vuln(status.scanId, cursor, signal),
    [transport, status.scanId],
  );
  const describe = useCallback(
    (page: ScanVuln): PageDescription => {
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
        ]),
        rowIds: page.findings.map((item) => item.findingId),
        rowFingerprint: fingerprintReportRows(page.findings),
        total: page.findingCount,
        nextCursor: page.nextCursor,
      };
    },
    [status],
  );
  return (
    <section aria-label="Результаты CVE" className="scan-report-section">
      <h4>
        CVE <span className="scan-report-section__scope">registry IMAGE</span>
      </h4>
      <CursorReportPager
        reportKey={reportKey}
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
            <p>CVE не поддерживаются: {page.reason}. Это не нулевое число находок.</p>
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
              <details className="scan-report-section__metadata">
                <summary>Версии scanner и базы CVE</summary>
                {page.db ? (
                  <p>
                    DB {page.db.manifestDigest} · {page.db.signer} (локальная аттестация, не подпись издателя)
                    · обновлена {page.db.updatedAt} · срок {page.db.nextUpdate}
                  </p>
                ) : (
                  <p>Идентичность DB не предоставлена.</p>
                )}
                <p>
                  scanner {page.scannerVersion} · проверено {page.checkedAt}
                  {status.perCheck?.vuln?.checksVersion
                    ? ` · checks ${status.perCheck.vuln.checksVersion}`
                    : ''}
                </p>
              </details>
              {page.findingCount === 0 ? (
                <p>0 CVE в выполненной проверенной области; это не гарантия безопасности.</p>
              ) : null}
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

function SbomReport({ status, transport, reportKey }: SectionProps) {
  const load = useCallback(
    (cursor: string | undefined, signal: AbortSignal) => transport.sbom(status.scanId, cursor, signal),
    [transport, status.scanId],
  );
  const describe = useCallback(
    (page: ScanSbom): PageDescription => {
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
        identity: JSON.stringify([page.image, page.platform, page.checkedAt, page.scannerVersion, page.os]),
        rowIds: page.components.map((item) => JSON.stringify([item.ecosystem, item.name, item.version])),
        rowFingerprint: fingerprintReportRows(page.components),
        total: page.componentCount,
        nextCursor: page.nextCursor,
      };
    },
    [status],
  );
  return (
    <section aria-label="Пакеты SBOM" className="scan-report-section">
      <h4>Пакеты SBOM</h4>
      <CursorReportPager
        reportKey={reportKey}
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
  const load = useCallback(
    (cursor: string | undefined, signal: AbortSignal) => transport.results(status.scanId, cursor, signal),
    [transport, status.scanId],
  );
  const describe = useCallback(
    (page: ScanResults): PageDescription => {
      const coverage = page.coverage.find((item) => item.check === 'Secrets');
      const result = status.perCheck?.secret;
      if (
        !demo &&
        (coverage?.status !== result?.outcome ||
          (result?.outcome === 'checked' &&
            ((result.findingCount != null && result.findingCount !== coverage?.findingCount) ||
              (result.scannerVersion != null && result.scannerVersion !== coverage?.scannerVersion))))
      )
        throw new ReportIdentityError();
      if (!demo && coverage?.status === 'checked' && !terminal.includes(status.state))
        throw new ReportIdentityError();
      return {
        checked: coverage?.status === 'checked',
        identity: JSON.stringify(coverage),
        rowIds: coverage?.status === 'checked' ? page.findings.map((item) => item.findingId) : [],
        rowFingerprint: fingerprintReportRows(coverage?.status === 'checked' ? page.findings : []),
        total: coverage?.status === 'checked' ? (coverage.findingCount ?? null) : null,
        nextCursor: coverage?.status === 'checked' ? page.nextCursor : null,
      };
    },
    [status, demo],
  );
  return (
    <section aria-label="Результаты Secrets" className="scan-report-section">
      <h4>Secrets</h4>
      <CursorReportPager
        reportKey={reportKey}
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
                        {finding.category} · severity: {finding.severity}
                      </span>
                      <span>ID: {finding.findingId}</span>
                    </li>
                  ))}
                </ul>
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
                Значения секретов не отображаются. Severity unknown не превращается в оценку риска.
              </p>
            </>
          );
        }}
      </CursorReportPager>
    </section>
  );
}
