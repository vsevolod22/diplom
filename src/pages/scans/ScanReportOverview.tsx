import { scanCheckSnapshot } from '@/features/scans/scanProgressPresentation';
import type { ScanCheck, ScanStatus } from '@/shared/api/scans/scanTransport';

const countForms = {
  finding: ['находка', 'находки', 'находок'],
  remark: ['замечание', 'замечания', 'замечаний'],
  package: ['пакет', 'пакета', 'пакетов'],
} as const;

export function ReportCount({ value, unit, emphasize = false }: {
  value: number; unit: keyof typeof countForms; emphasize?: boolean;
}) {
  const lastHundred = value % 100;
  const lastDigit = value % 10;
  const form = lastHundred >= 11 && lastHundred <= 14 ? 2 : lastDigit === 1 ? 0 : lastDigit >= 2 && lastDigit <= 4 ? 1 : 2;
  return <>{emphasize ? <strong>{value}</strong> : value} {countForms[unit][form]}</>;
}

const categories: ReadonlyArray<{ check: ScanCheck; label: string; unit: keyof typeof countForms }> = [
  { check: 'vuln', label: 'Уязвимости пакетов', unit: 'finding' },
  { check: 'secret', label: 'Возможные секреты', unit: 'finding' },
  { check: 'config', label: 'Настройки образа', unit: 'remark' },
  { check: 'sbom', label: 'Состав образа', unit: 'package' },
];
const outcomes = {
  failed: 'Не удалось проверить',
  unsupported: 'Не поддерживается',
  skipped: 'Пропущено',
  not_authorized: 'Нет разрешения',
};

export function ScanReportOverview({ status, onShowFindings, onShowCoverage }: {
  status: ScanStatus;
  onShowFindings: (check: 'secret' | 'vuln') => void;
  onShowCoverage: () => void;
}) {
  const snapshot = scanCheckSnapshot(status);
  const active = ['queued', 'running', 'cancelling'].includes(status.state);
  const rows = categories.map(category => {
    const entry = snapshot.entries.find(item => item.check === category.check);
    // Only a matching, published checked result is evidence of a count, including zero.
    const count = !active && entry?.outcome === 'checked'
      ? category.check === 'sbom' ? entry.result?.componentCount : entry.result?.findingCount
      : null;
    return { ...category, entry, count: count ?? null };
  });
  const findings = rows.filter(row => row.check !== 'sbom');
  const hasFindings = findings.some(row => row.count !== null && row.count > 0);
  const gaps = snapshot.entries.filter(entry => entry.outcome !== 'checked');
  const vuln = rows.find(row => row.check === 'vuln')?.entry?.result;
  const incompleteVuln = vuln?.outcome === 'checked' &&
    (!vuln.os || !vuln.node || vuln.os.outcome !== 'checked' || vuln.node.outcome !== 'checked');
  const countsUnknown = rows.some(row => row.entry?.outcome === 'checked' && row.count === null);
  const incomplete = !snapshot.known || gaps.length > 0 || incompleteVuln || countsUnknown ||
    ['partial', 'failed', 'cancelled'].includes(status.state);
  const knownZero = findings.some(row => row.count === 0);
  const title = active ? 'Проверка ещё идёт'
    : hasFindings ? 'Есть находки для проверки'
      : incomplete ? 'Данных недостаточно для полного вывода'
        : knownZero ? 'В выполненных проверках находок нет'
          : 'Состав образа получен — оценка рисков неполна';
  const countFor = (check: ScanCheck) => rows.find(row => row.check === check)?.count ?? null;
  const secretCount = countFor('secret');
  const vulnCount = countFor('vuln');
  const configCount = countFor('config');

  return (
    <section className="scan-report-overview" aria-labelledby="scan-report-outcome">

      <h3 id="scan-report-outcome">{title}</h3>
      {active ? <p>Ждём окончания проверки. Итоговые количества пока неизвестны.</p> : null}
      {!active ? <p className={incomplete ? 'scan-report-overview__warning' : 'scan-report-overview__scope'}>
        <strong>{status.state === 'failed' ? 'Проверка завершилась с ошибкой.'
          : status.state === 'cancelled' ? 'Проверка отменена.'
            : incomplete ? 'Результаты неполны.' : 'Запрошенные проверки выполнены.'}</strong>
      </p> : null}
      <dl className="scan-report-overview__counts">
        {rows.map(row => (
          <div key={row.check} data-result={row.count !== null ? row.count > 0 ? 'findings' : 'zero' : 'unknown'}>
            <dt>{row.label}</dt>
            <dd>{row.count !== null ? <ReportCount value={row.count} unit={row.unit} emphasize />
              : !row.entry ? snapshot.requested.length ? 'Не запрашивалось' : 'Неизвестно, запрашивалось ли'
                : row.entry.outcome === 'checked' ? 'Количество пока неизвестно'
                  : row.entry.outcome === null ? active ? 'Ожидаем результат' : 'Результат неизвестен'
                    : outcomes[row.entry.outcome]}</dd>
          </div>
        ))}
      </dl>
      {!active ? <p className="scan-report-overview__caption">Числа по всему отчёту выбранных проверок. Неизвестно — не значит ноль; отсутствие находок не гарантирует безопасность.
        {incomplete ? <> Непроверенные области не считаются безопасными. <a href="#scan-a1-coverage" onClick={onShowCoverage}>Что осталось непроверенным</a></> : null}
      </p> : null}
      {!active && incompleteVuln ? <p className="scan-report-overview__warning">Покрытие системных пакетов и пакетов приложения неполное или неизвестно.</p> : null}
      {!active ? (
        <section aria-labelledby="scan-report-actions">
          <h4 id="scan-report-actions">Что требует внимания</h4>

          <ol className="scan-report-actions">
            {secretCount !== null && secretCount > 0 ? <li>
              <strong>Проверьте ключи и пароли</strong>
              <p>Действующий ключ может дать посторонним доступ. Подтверждённые ключи отзовите и удалите из сборки.</p>
              <a href="#scan-report-secrets" onClick={() => onShowFindings('secret')}>Посмотреть возможные секреты</a>
            </li> : null}
            {vulnCount !== null && vulnCount > 0 ? <li>
              <strong>Обновите уязвимые зависимости</strong>
              <p>Начните с высоких и критических оценок. Проверьте применимость уязвимости и исправленную версию перед обновлением.</p>
              <a href="#scan-report-vulnerabilities" onClick={() => onShowFindings('vuln')}>Открыть пакеты и исправления</a>
            </li> : null}
            {configCount !== null && configCount > 0 ? <li>
              <strong>Проверьте пользователя контейнера</strong>
              <p>Избыточные права усиливают последствия ошибок. Настройте запуск без прав администратора и проверьте его в окружении.</p>
              <a href={status.config ? '#scan-report-config' : '#scan-a1-coverage'} onClick={status.config ? undefined : onShowCoverage}>Открыть замечание к настройкам</a>
            </li> : null}
            {incomplete ? <li>
              <strong>Уточните, что осталось непроверенным</strong>
              <p>Посмотрите доступную причину и следующий шаг. Для неизвестной области нужна отдельная проверка, а не вывод об отсутствии проблем.</p>
              <a href="#scan-a1-coverage" onClick={onShowCoverage}>Посмотреть ограничения</a>
            </li> : null}
            {!hasFindings && !incomplete ? <li>
              <strong>Не ограничивайтесь этим отчётом</strong>
              <p>{knownZero ? 'В выполненных проверках находок нет. ' : 'Список пакетов сам по себе не выявляет уязвимости. '}
                Перед использованием образа проверьте незапрошенные области, права контейнера и настройки развёртывания отдельно.</p>
            </li> : null}
          </ol>
          {hasFindings ? <p className="scan-a1__muted">После изменений пересоберите образ и запустите новую проверку. Этот отчёт относится к прежней сборке.</p> : null}
        </section>
      ) : null}
    </section>
  );
}
