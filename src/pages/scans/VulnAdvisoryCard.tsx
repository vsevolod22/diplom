import { useState } from 'react';
import { AdvisoryTranslationPanel } from '@/features/scans/AdvisoryTranslationPanel';
import type { VulnFinding } from '@/shared/api/scans/scanTransport';
import { canonicalReferences, FIRST_CALCULATOR, validCvssVector } from '@/shared/api/scans/vulnAdvisory';
import { identifierLabel, vulnerabilityIdentifierKind } from '@/shared/api/scans/publicVulnerabilityIdentifiers';
import type { AdvisoryV1 } from '@/shared/api/scans/vulnAdvisory';

const severityLabels = {
  CRITICAL: 'Критическая оценка', HIGH: 'Высокая оценка', MEDIUM: 'Средняя оценка',
  LOW: 'Низкая оценка', UNKNOWN: 'Опасность неизвестна',
};
type PlainField = AdvisoryV1['assessments'][number]['title'];
const fieldLabels = {
  available: '',
  missing: 'Не предоставлено источником',
  invalid: 'Некорректные данные источника',
  redacted: 'Содержимое скрыто',
  truncated: 'Текст сокращён',
  unsupported: 'Формат не поддерживается',
  omitted: 'Не включено в отчёт',
};
function AdvisoryText({ label, field }: { label: string; field: PlainField }) {
  return (
    <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
      <strong>{label}: </strong>
      {field.value ?? fieldLabels[field.state]}
      {field.value && field.state === 'truncated' ? ' · Текст сокращён' : ''}
      {field.redacted ? ' · чувствительные данные скрыты' : ''}
    </p>
  );
}
function CopyVector({ vector }: { vector: string }) {
  const [message, setMessage] = useState('');
  return (
    <>
      <button
        type="button"
        className="scan-a1__link"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(vector);
            setMessage('Вектор скопирован');
          } catch {
            setMessage('Не удалось скопировать; выделите вектор вручную');
          }
        }}
      >
        Копировать вектор CVSS 3.1
      </button>
      <span role="status">{message}</span>
    </>
  );
}
export function VulnAdvisoryCard({ finding }: { finding: VulnFinding }) {
  const [detailsOpen, setDetailsOpen] = useState(false);
  const advisory = finding.advisory;
  const identifierKind = vulnerabilityIdentifierKind(finding.cveId);
  const identifierName = identifierKind === 'debian-dla' ? 'Бюллетень Debian DLA (не CVE)'
    : identifierKind === 'debian-temp' ? 'Уведомление Debian (не CVE)' : identifierLabel(finding.cveId);
  const references = identifierKind === 'cve' ? canonicalReferences(finding.cveId) : [];
  const incompleteAssessments =
    !advisory || advisory.state === 'omitted' || advisory.conflictState === 'unknown';
  const representativeSeverity = incompleteAssessments || advisory.conflicts.includes('severity');
  const representativeFix = incompleteAssessments || advisory.conflicts.includes('fixedVersion');
  const calculator =
    references.length > 0 &&
    advisory?.assessments.some(
      (item) =>
        item.cvss?.version === '3.1' && item.cvss.vector !== null && validCvssVector(item.cvss.vector, '3.1'),
    );
  return (
    <li className="scan-vuln-row" data-severity={finding.severity}>
      <div className="scan-vuln-row__headline">
        <strong className="scan-vuln-row__id">{finding.packageName}</strong>
        <span style={{ overflowWrap: 'anywhere', minWidth: 0 }}>
          {finding.cveId}{identifierKind !== 'cve' ? ` · ${identifierName}` : ''}
        </span>
        <span className="scan-vuln-row__severity">{severityLabels[finding.severity]}</span>
      </div>
      <dl className="scan-vuln-row__facts">

        <div>
          <dt>Установлено</dt>
          <dd>{finding.installedVersion}</dd>
        </div>
        <div>
          <dt>{representativeFix ? 'Версия исправления · требует сверки' : 'Исправленная версия по отчёту'}</dt>
          <dd>{finding.fixedVersion ?? 'источник не указал'}</dd>
        </div>
      </dl>
      <div className="scan-vuln-row__action">
        <p><strong>Следующий шаг.</strong> {representativeFix
          ? 'Сверьте исправление с поставщиком: данные источников неполны или расходятся.'
          : finding.fixedVersion
            ? 'Проверьте совместимость и обновите пакет или базовый образ до подходящей исправленной версии. Затем пересоберите образ и повторите проверку.'
            : 'Уточните исправление у поставщика. Неуказанная версия не доказывает, что исправления нет; при его отсутствии оцените замену или ограничение использования пакета.'}</p>
      </div>
      {advisory?.assessments.some((item) => item.severity === 'CRITICAL') &&
      finding.severity !== 'CRITICAL' ? (
        <p className="scan-vuln-row__warning">
          Один из источников считает уязвимость критической; оценки расходятся.
        </p>
      ) : null}
      {representativeSeverity || representativeFix || (advisory?.conflicts.length ?? 0) > 0 || (advisory?.limitations.length ?? 0) > 0 ? (
        <p className="scan-vuln-row__warning">
          {representativeSeverity ? 'Опасность требует уточнения. ' : ''}
          {representativeFix ? 'Версия исправления не подтверждена всеми источниками. ' : ''}
          {advisory?.conflicts.length ? 'Есть расхождения источников. ' : ''}
          {advisory?.limitations.length ? 'Часть данных ограничена. ' : ''}
          {advisory?.conflictState === 'unknown' ? 'Согласованность источников неизвестна. ' : ''}
          Сверьте сведения в подробностях.
        </p>
      ) : null}

      <details
        className="scan-vuln-row__details"
        onToggle={(event) => setDetailsOpen(event.currentTarget.open)}
      >
        <summary>Подробности · описание уязвимости и источники</summary>
        <p><strong>Почему важно.</strong> Установленный пакет совпал с записью об уязвимости. Это не доказательство эксплуатации: применимость к вашему приложению нужно проверить отдельно.</p>
        <p>Тип пакета: {finding.ecosystem}</p>
        <p>{identifierName}: {finding.cveId}</p>
        <p>Оценка сканера: {finding.severity}. Источники: {finding.severitySources?.join(', ') || 'неизвестны'}.</p>
        {advisory?.conflicts.length ? <p>Поля с расхождениями: {advisory.conflicts.join(', ')}</p> : null}
        {advisory?.limitations.length ? <p>Ограничения источника: {advisory.limitations.join(', ')}</p> : null}
        <p>ID находки: {finding.findingId}</p>
        <p>Provenance: {finding.provenanceRef ?? 'не предоставлен'}</p>
        {!advisory ? (
          <p>Описание уязвимости недоступно: исторический отчёт без advisory.</p>
        ) : advisory.state === 'omitted' ? (
          <p>Описание не включено из-за ограничения объёма отчёта.</p>
        ) : (
          <>
            {advisory.assessments.length === 0 ? <p>Не предоставлено источником</p> : null}
            {advisory.assessments.map((item, index) => (
              <div
                key={`${item.source}-${item.provenanceRef}-${index}`}
                aria-label={`Источник ${item.source}`}
              >
                <p>
                  <strong>Источник: {item.source}</strong> · {item.provenanceRef}
                </p>
                <p>Язык источника: {item.language ?? 'не указан'} · оригинальный текст источника</p>
                <p>Оценка источника №{index + 1}. Отдельный перевод описания — не ИИ-разбор и не ответ чата.</p>
                <AdvisoryText label="Заголовок" field={item.title} />
                <AdvisoryText label="Описание" field={item.description} />
                {detailsOpen ? (
                  <AdvisoryTranslationPanel
                    findingId={finding.findingId}
                    vulnerabilityId={finding.cveId}
                    assessmentIndex={index}
                    assessment={item}
                  />
                ) : null}
                <p>
                  Severity источника: {item.severity ?? 'не предоставлена'} · исправление источника:{' '}
                  {item.fixedVersion ?? 'не предоставлено'}
                </p>
                {item.cvss ? (
                  <>
                    <p>
                      CVSS{' '}
                      {item.cvss.version ??
                        `${item.cvss.family}, версия: ${fieldLabels[item.cvss.versionState]}`}{' '}
                      · оценка источника: {item.cvss.reportedScore ?? fieldLabels[item.cvss.scoreState]} ·
                      оценка не пересчитывалась
                    </p>
                    <p style={{ overflowWrap: 'anywhere' }}>
                      Вектор: {item.cvss.vector ?? fieldLabels[item.cvss.vectorState]}
                    </p>
                    {item.cvss.version === '3.1' &&
                    item.cvss.vector &&
                    validCvssVector(item.cvss.vector, '3.1') ? (
                      <CopyVector vector={item.cvss.vector} />
                    ) : null}
                  </>
                ) : (
                  <p>CVSS не предоставлен источником</p>
                )}
              </div>
            ))}
          </>
        )}

        {references.length > 0 ? (
          <>
            <p>Канонические адреса CVE.org и NVD: наличие записи и её содержимое не проверены.</p>
            <ul>
              {references.map((ref) => (
                <li key={ref.authority}>
                  <a href={ref.url} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">
                    {ref.authority === 'cve' ? 'CVE.org' : 'NVD'} · открыть запись
                  </a>
                </li>
              ))}
            </ul>
          </>
        ) : null}
        {calculator ? (
          <p>
            <a href={FIRST_CALCULATOR} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">
              FIRST · калькулятор CVSS 3.1
            </a>{' '}
            · базовый инструмент без автозаполнения; вставьте проверенный вектор вручную.
          </p>
        ) : null}
        {identifierKind === 'debian-temp' ? <p>Временный Debian advisory ID, не CVE. Сопоставленные внешние ссылки не предоставлены.</p>
          : identifierKind === 'debian-dla' ? <p>Бюллетень Debian DLA — не идентификатор CVE. Сопоставление с CVE/NVD не выполнялось; сведения источника приведены отдельно.</p>
            : identifierKind === 'cve' ? <p>Проверенный русский источник для этой CVE недоступен. Ссылка БДУ не подтверждена.</p>
              : <p>Тип идентификатора не определён; внешние ссылки не сопоставлялись.</p>}
      </details>

    </li>
  );
}
