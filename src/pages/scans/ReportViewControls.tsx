import { useState } from 'react';
import { REPORT_ECOSYSTEMS, reportEcosystem } from '@/shared/api/scans/publicImageProfile';
import type { ReactNode } from 'react';
import { REPORT_LIMITS, REPORT_RULE_ID_PATTERN, REPORT_SEVERITIES } from '@/shared/api/scans/reportView';
import type { ReportLimit, SbomReportQuery, SecretReportQuery, VulnReportQuery } from '@/shared/api/scans/reportView';

const SORT_LABELS: Record<string, string> = {
  'severity:desc': 'Сначала критические',
  'severity:asc': 'Сначала низкие',
  'name:asc': 'Имя: А → Я',
  'name:desc': 'Имя: Я → А',
  'ecosystem:asc': 'Экосистема: А → Я',
  'ecosystem:desc': 'Экосистема: Я → А',
  'ruleId:asc': 'Правило: А → Я',
  'ruleId:desc': 'Правило: Я → А',
  'line:asc': 'Строка: по возрастанию',
  'line:desc': 'Строка: по убыванию',
};
const SEVERITY_LABELS = {
  UNKNOWN: 'Не определён (UNKNOWN)',
  LOW: 'Низкий (LOW)',
  MEDIUM: 'Средний (MEDIUM)',
  HIGH: 'Высокий (HIGH)',
  CRITICAL: 'Критический (CRITICAL)',
};

function Controls({ label, limit, sort, sorts, disabled, onLimit, onSort, children }: {
  label: string; limit: ReportLimit; sort: string; sorts: readonly string[]; disabled: boolean;
  onLimit: (limit: ReportLimit) => void; onSort: (sort: string) => void; children: ReactNode;
}) {
  return <fieldset className="scan-report-view-controls" disabled={disabled}>
    <legend>Весь отчёт {label} · фильтры и сортировка</legend>
    <label>Строк на странице · {label}
      <select value={limit} onChange={event => onLimit(Number(event.target.value) as ReportLimit)}>
        {REPORT_LIMITS.map(size => <option key={size} value={size}>{size}</option>)}
      </select>
    </label>
    <label>Сортировка · {label}
      <select value={sort} onChange={event => onSort(event.target.value)}>
        {sorts.map(value => <option key={value} value={value}>{SORT_LABELS[value]}</option>)}
      </select>
    </label>
    {children}
    <p>Сервер фильтрует и сортирует весь сохранённый отчёт до выбора страницы. Изменение настроек начинает с первой страницы.</p>
  </fieldset>;
}
export function UnsupportedReportControls() {
  return <p className="scan-a1__muted">Демо: размер страницы, глобальные фильтры и сортировка report-v1 не поддерживаются. Показаны исходные демонстрационные данные.</p>;
}
export function VulnReportControls({ query, onChange, disabled, label = 'CVE' }: { query: VulnReportQuery; onChange: (query: VulnReportQuery) => void; disabled: boolean; label?: string }) {
  const selected = query.severity?.join(',') ?? '';
  return <Controls label={label} limit={query.limit ?? 25} sort={query.sort ?? 'severity:desc'} sorts={['severity:desc', 'severity:asc']} disabled={disabled}
    onLimit={limit => onChange({ ...query, limit })} onSort={sort => onChange({ ...query, sort: sort as VulnReportQuery['sort'] })}>
    <label>Уровень опасности (severity) · {label}
      <select value={selected} onChange={event => onChange({ ...query, severity: event.target.value ? REPORT_SEVERITIES.filter(item => event.target.value.split(',').includes(item)) : null })}>
        <option value="">Все уровни опасности</option>
        <option value="HIGH,CRITICAL">Высокие и критические (HIGH + CRITICAL)</option>
        {REPORT_SEVERITIES.map(item => <option key={item} value={item}>{SEVERITY_LABELS[item]}</option>)}
      </select>
    </label>
    <button type="button" onClick={() => onChange({ ...query, severity: ['HIGH', 'CRITICAL'] })}>Высокие и критические (HIGH + CRITICAL)</button>
    <p>Используется сохранённый уровень опасности (severity) находки, не максимальная оценка advisory. Неопределённый уровень (UNKNOWN) всегда в конце при любом порядке сортировки.</p>
  </Controls>;
}
export function SbomReportControls({ query, onChange, disabled }: { query: SbomReportQuery; onChange: (query: SbomReportQuery) => void; disabled: boolean }) {
  const [name, setName] = useState(query.name ?? '');
  return <Controls label="SBOM" limit={query.limit ?? 25} sort={query.sort ?? 'name:asc'} sorts={['name:asc', 'name:desc', 'ecosystem:asc', 'ecosystem:desc']} disabled={disabled}
    onLimit={limit => onChange({ ...query, limit })} onSort={sort => onChange({ ...query, sort: sort as SbomReportQuery['sort'] })}>
    <label>Экосистема · SBOM
      <select value={query.ecosystem ?? ''} onChange={event => onChange({ ...query, ecosystem: reportEcosystem.safeParse(event.target.value).data ?? null })}>
        <option value="">Все экосистемы</option>{REPORT_ECOSYSTEMS.map(ecosystem => <option key={ecosystem} value={ecosystem}>{ecosystem}</option>)}
      </select>
    </label>
    <form onSubmit={event => { event.preventDefault(); onChange({ ...query, name: name || null }); }}>
      <label>Имя пакета · SBOM
        <input value={name} maxLength={128} pattern={'[A-Za-z0-9@._+:\\/\\-]{1,128}'} onChange={event => setName(event.target.value)} placeholder="Например, openssl" />
      </label>
      <button type="submit">Применить имя · SBOM</button>
      <button type="button" onClick={() => { setName(''); onChange({ ...query, name: null }); }}>Сбросить имя · SBOM</button>
      <small>Буквальная подстрока без учёта регистра ASCII; не регулярное выражение.</small>
    </form>
  </Controls>;
}
export function SecretReportControls({ query, onChange, disabled }: { query: SecretReportQuery; onChange: (query: SecretReportQuery) => void; disabled: boolean }) {
  const [ruleId, setRuleId] = useState(query.ruleId ?? '');
  const [ruleError, setRuleError] = useState(false);
  return <Controls label="Secrets" limit={query.limit ?? 25} sort={query.sort ?? 'ruleId:asc'} sorts={['ruleId:asc', 'ruleId:desc', 'line:asc', 'line:desc']} disabled={disabled}
    onLimit={limit => onChange({ ...query, limit })} onSort={sort => onChange({ ...query, sort: sort as SecretReportQuery['sort'] })}>
    <label>Номер строки · Secrets
      <select value={query.linePresence ?? ''} onChange={event => onChange({ ...query, linePresence: event.target.value === 'known' || event.target.value === 'unknown' ? event.target.value : null })}>
        <option value="">Все строки</option><option value="known">Известен</option><option value="unknown">Неизвестен</option>
      </select>
    </label>
    <form onSubmit={event => {
      event.preventDefault();
      if (ruleId && !REPORT_RULE_ID_PATTERN.test(ruleId)) { setRuleError(true); return; }
      setRuleError(false);
      onChange({ ...query, ruleId: ruleId || null });
    }}>
      <label>Rule ID · Secrets<input value={ruleId} maxLength={80} pattern={'[A-Za-z0-9._\\-]{1,80}'} aria-invalid={ruleError} onChange={event => { setRuleId(event.target.value); setRuleError(false); }} /></label>
      {ruleError ? <p role="alert">Rule ID: от 1 до 80 символов ASCII — буквы, цифры, точка, подчёркивание или дефис.</p> : null}
      <button type="submit">Применить Rule ID</button>
      <button type="button" onClick={() => { setRuleId(''); setRuleError(false); onChange({ ...query, ruleId: null }); }}>Сбросить Rule ID</button>
      <small>Точное правило; значения секретов и выдуманная severity не используются.</small>
    </form>
  </Controls>;
}
