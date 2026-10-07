import { useState } from 'react';
import type { VulnFinding } from '@/shared/api/scans/scanTransport';
import { canonicalReferences, FIRST_CALCULATOR, validCvssVector } from '@/shared/api/scans/vulnAdvisory';
import type { AdvisoryV1 } from '@/shared/api/scans/vulnAdvisory';

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
  const advisory = finding.advisory;
  const references = canonicalReferences(finding.cveId);
  const incompleteAssessments = !advisory || advisory.state === 'omitted' || advisory.conflictState === 'unknown';
  const representativeSeverity = incompleteAssessments || advisory.conflicts.includes('severity');
  const representativeFix = incompleteAssessments || advisory.conflicts.includes('fixedVersion');
  const calculator =
    references.length > 0 &&
    advisory?.assessments.some(
      (item) =>
        item.cvss?.version === '3.1' && item.cvss.vector !== null && validCvssVector(item.cvss.vector, '3.1'),
    );
  return (
    <li>
      <strong>
        {finding.cveId} · {finding.severity}
      </strong>
      <p>
        {finding.ecosystem} · {finding.packageName} {finding.installedVersion} · исправление:{' '}
        {finding.fixedVersion ?? 'не указано'}
      </p>
      {representativeSeverity ? (
        <p>Совместимое значение severity, не авторитетная оценка источника. Отдельные оценки приведены ниже, если доступны.</p>
      ) : null}
      {representativeFix ? (
        <p>Совместимое значение исправления, не авторитетная оценка источника. Отдельные оценки приведены ниже, если доступны.</p>
      ) : null}
      <p>
        Источники отдельных оценок: {finding.severitySources?.join(', ') || 'неизвестны'} · provenance:{' '}
        {finding.provenanceRef ?? 'не предоставлен'}
      </p>
      {!advisory ? (
        <p>Описание уязвимости недоступно: исторический отчёт без advisory.</p>
      ) : advisory.state === 'omitted' ? (
        <p>Описание не включено из-за ограничения объёма отчёта.</p>
      ) : (
        <>
          {advisory.assessments.length === 0 ? <p>Не предоставлено источником</p> : null}
          {advisory.assessments.map((item, index) => (
            <div key={`${item.source}-${item.provenanceRef}-${index}`} aria-label={`Источник ${item.source}`}>
              <p>
                <strong>Источник: {item.source}</strong> · {item.provenanceRef}
              </p>
              <p>Язык источника: {item.language ?? 'не указан'} · перевод не выполнялся</p>
              <AdvisoryText label="Заголовок" field={item.title} />
              <AdvisoryText label="Описание" field={item.description} />
              <p>
                Severity источника: {item.severity ?? 'не предоставлена'} · исправление источника:{' '}
                {item.fixedVersion ?? 'не предоставлено'}
              </p>
              {item.cvss ? (
                <>
                  <p>
                    CVSS {item.cvss.version ?? `${item.cvss.family}, версия неизвестна`} · оценка источника:{' '}
                    {item.cvss.reportedScore ?? 'не предоставлена'} · оценка не пересчитывалась
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
      {advisory && advisory.conflicts.length > 0 ? (
        <p>Источники расходятся: {advisory.conflicts.join(', ')}. Сохранены отдельные оценки источников.</p>
      ) : null}
      {advisory?.conflictState === 'unknown' ? (
        <p>Согласованность источников неизвестна: часть наблюдений недоступна.</p>
      ) : null}
      {advisory && advisory.limitations.length > 0 ? (
        <p>Ограничения данных: {advisory.limitations.join(', ')}</p>
      ) : null}
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
      <p>Проверенный русский источник для этой CVE недоступен. Ссылка БДУ не подтверждена.</p>
    </li>
  );
}
