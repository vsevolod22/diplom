import { publicSafeFinding, type LlmFinding } from '@/shared/api/scans/llmFindingContract';
import type { SummarySource } from '@/shared/api/scans/llmSummaryClient';
import { LlmFindingDetails } from './LlmFindingDetails';
import { ReportSourceLink, type ReportSourceNavigate } from './reportSourceNavigation';
import './ReportRemediation.css';

type RemediationFacts = {
  findingId: string;
  packageName: string | null;
  installedVersion: string | null;
  reportedFixedVersion: string | null;
  fixedVersionState: 'reported' | 'unknown' | 'not-included';
  conflictState: 'none' | 'present' | 'unknown';
  advisoryState: 'available' | 'omitted' | 'unknown';
};

export function reportRemediationFacts(finding?: LlmFinding): RemediationFacts | null {
  const parsed = publicSafeFinding.safeParse(finding);
  if (!parsed.success || parsed.data.check !== 'vuln') return null;
  const value = parsed.data;
  return {
    findingId: value.findingId,
    packageName: value.packageName ?? null,
    installedVersion: value.installedVersion ?? null,
    reportedFixedVersion: value.fixedVersion ?? null,
    fixedVersionState:
      typeof value.fixedVersion === 'string'
        ? 'reported'
        : value.fixedVersion === null || !value.fixedVersionReported
          ? 'unknown'
          : 'not-included',
    conflictState: 'conflictState' in value ? value.conflictState : 'unknown',
    advisoryState: value.advisoryState,
  };
}

const labels: Record<string, string> = {
  Secrets: 'Секреты',
  CRITICAL: 'Критическая',
  HIGH: 'Высокая',
  MEDIUM: 'Средняя',
  LOW: 'Низкая',
  INFO: 'Информационная',
  UNKNOWN: 'Неизвестна',
  'Debian advisory (не CVE)': 'Уведомление Debian (не CVE)',
  'Debian DLA advisory (не CVE)': 'Бюллетень Debian DLA (не CVE)',
};

export function ReportRemediation({
  source,
  onNavigate,
  disabled = false,
}: {
  source: SummarySource;
  onNavigate?: ReportSourceNavigate;
  disabled?: boolean;
}) {
  const parsed = publicSafeFinding.safeParse(source.finding);
  const finding =
    parsed.success && parsed.data.findingId === source.findingId && parsed.data.check === source.check
      ? parsed.data
      : undefined;
  const facts = reportRemediationFacts(finding);
  return (
    <div className="report-remediation" data-finding-id={source.findingId}>
      <strong>
        {source.label
          .split(' · ')
          .map((part) => labels[part] ?? part)
          .join(' · ')}
      </strong>
      {finding && finding.check !== 'vuln' ? <LlmFindingDetails finding={finding} /> : null}
      {facts ? (
        <>
          {finding?.check === 'vuln' ? (
            <p>
              Экосистема: <code>{finding.ecosystem}</code>.
            </p>
          ) : null}
          <dl className="report-remediation__versions">
            <div>
              <dt>Пакет</dt>
              <dd>{facts.packageName ? <code>{facts.packageName}</code> : 'Не включён в источник'}</dd>
            </div>
            <div>
              <dt>Установлено</dt>
              <dd>
                {facts.installedVersion ? (
                  <code>{facts.installedVersion}</code>
                ) : (
                  'Версия не включена в источник'
                )}
              </dd>
            </div>
            <div>
              <dt>Исправление по данным сканера</dt>
              <dd>
                {facts.reportedFixedVersion ? (
                  <code>{facts.reportedFixedVersion}</code>
                ) : facts.fixedVersionState === 'not-included' ? (
                  'Исправление сообщено, точная версия не включена'
                ) : (
                  'Исправленная версия неизвестна'
                )}
              </dd>
            </div>
          </dl>
          <p>
            Это точные поля одной находки, не текст модели. Сообщённое исправление сохранено целиком: это не
            выбранная минимальная или гарантированно безопасная версия.
          </p>
          {facts.conflictState === 'present' ? (
            <p>Источники расходятся. Сверьте отдельные оценки в отчёте перед выбором обновления.</p>
          ) : facts.conflictState === 'unknown' ? (
            <p>Согласованность источников неизвестна; отсутствие расхождений не подтверждено.</p>
          ) : null}
          {facts.advisoryState !== 'available' ? (
            <p>
              Подробности advisory{' '}
              {facts.advisoryState === 'omitted' ? 'не включены полностью' : 'неизвестны'}. Эти данные не
              восстанавливаются из текста ИИ.
            </p>
          ) : null}
          {finding?.check === 'vuln' && 'limitations' in finding && finding.limitations.length > 0 ? (
            <p>Источник содержит ограничения полноты данных. Проверьте их в исходном отчёте.</p>
          ) : null}
          <p>
            {facts.fixedVersionState === 'reported'
              ? 'Что сделать: проверьте применимость сообщённого исправления для этого пакета и совместимость обновления, затем пересоберите образ и повторно проверьте результат.'
              : 'Что сделать: сначала найдите подтверждённое исправление для этого пакета в источниках отчёта — подходящая версия здесь не установлена. После проверки совместимости обновления пересоберите образ и повторно проверьте результат.'}
          </p>
          <p>
            Подтверждённого соответствия «исправленная версия пакета → Docker-тег образа» в этих данных нет.
            Подходящий тег и безопасность образа не установлены.
          </p>
        </>
      ) : (
        <p>
          {source.check === 'vuln'
            ? 'Точные пакет, установленная и исправленная версии не подтверждены этим источником сохранённого ответа. Не выводите их из текста ИИ; проверьте находку в отчёте. Подходящий Docker-тег неизвестен.'
            : source.check === 'secret'
              ? 'Проверьте совпадение в исходном отчёте. Если это действующий ключ или пароль, отзовите его, удалите из сборки и пересоберите образ; само удаление не отзывает ключ.'
              : 'Проверьте настройки пользователя в исходном отчёте и права при запуске контейнера. Результат проверки настроек образа не подтверждает безопасность запущенного контейнера.'}
        </p>
      )}
      <p>
        <ReportSourceLink category={source.check} onNavigate={onNavigate} disabled={disabled} />
      </p>
      <small>Переход к разделу, не к точной находке: проверьте фильтры и страницы списка.</small>
    </div>
  );
}
