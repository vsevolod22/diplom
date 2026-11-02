import type { LlmFinding } from '@/shared/api/scans/llmFindingContract';

/** Additional technical details from validated scanner facts, not the model's narrative. */
export function LlmFindingDetails({ finding }: { finding: LlmFinding }) {
  if (finding.check === 'secret') {
    return (
      <p>
        Правило: <code>{finding.ruleId}</code>. Строка: {finding.line ?? 'не указана'}.
        {' '}Свидетельство: <code>{finding.evidenceRef}</code>.
      </p>
    );
  }
  if (finding.check === 'config') {
    return (
      <p>
        Правило: <code>{finding.ruleId}</code>. Поле: <code>{finding.location}</code>.
        {' '}Классификация: <code>{finding.classification}</code>.
      </p>
    );
  }
  return (
    <div style={{ overflowWrap: 'anywhere' }}>
      <p>
        Экосистема: <code>{finding.ecosystem}</code>.{' '}
        {finding.packageName !== undefined ? (
          <>Пакет: <code>{finding.packageName}</code>. Установленная версия: <code>{finding.installedVersion}</code>.</>
        ) : 'Пакет и установленная версия не включены в источник.'}
      </p>
      <p>
        Сообщённая исправленная версия:{' '}
        {typeof finding.fixedVersion === 'string' ? <code>{finding.fixedVersion}</code> :
          finding.fixedVersionReported ? 'точное значение не включено в источник' : 'не сообщена'}.
        {' '}Это сведения сканера, не проверка совместимости обновления.
      </p>
      {'assessments' in finding ? (
        <>
          <ul aria-label="Оценки CVSS источника">
            {finding.assessments.map((assessment, index) => assessment.cvss ? (
              <li key={`${assessment.source}-${index}`}>
                {assessment.source} · CVSS {assessment.cvss.version ?? assessment.cvss.family}:{' '}
                {assessment.cvss.scoreState === 'available' ? assessment.cvss.reportedScore : 'оценка недоступна'}
              </li>
            ) : null)}
          </ul>
          {finding.conflictState === 'present' ? <p>Источники расходятся; оценки не объединены.</p> : null}
        </>
      ) : null}
    </div>
  );
}
