import { useId, useState } from 'react';
import { REPORT_ECOSYSTEMS, reportEcosystem } from '@/shared/api/scans/publicImageProfile';
import type { ReactNode } from 'react';
import { REPORT_LIMITS, REPORT_RULE_ID_PATTERN, REPORT_SEVERITIES } from '@/shared/api/scans/reportView';
import type { ReportLimit, SbomReportQuery, SecretReportQuery, VulnReportQuery } from '@/shared/api/scans/reportView';

const REPORT_NAME_PATTERN = /^[A-Za-z0-9@._+:/-]{1,128}$/;

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
  UNKNOWN: 'Не определён',
  LOW: 'Низкий',
  MEDIUM: 'Средний',
  HIGH: 'Высокий',
  CRITICAL: 'Критический',
};

function Controls({ label, limit, sort, sorts, disabled, onLimit, onSort, children }: {
  label: string; limit: ReportLimit; sort: string; sorts: readonly string[]; disabled: boolean;
  onLimit: (limit: ReportLimit) => void; onSort: (sort: string) => void; children: ReactNode;
}) {
  return <details className="scan-report-filters">
    <summary>Фильтры и сортировка · {label}</summary>
    <fieldset className="scan-report-view-controls" disabled={disabled}>
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
    <p>Фильтры применяются ко всему отчёту. При изменении открывается первая страница.</p>
    </fieldset>
  </details>;
}
export function UnsupportedReportControls() {
  return <p className="scan-a1__muted">Демонстрационные данные. Фильтры и размер страницы в этом режиме недоступны.</p>;
}
export function VulnReportControls({ query, onChange, disabled, label = 'CVE' }: { query: VulnReportQuery; onChange: (query: VulnReportQuery) => void; disabled: boolean; label?: string }) {
  const selected = query.severity?.join(',') ?? '';
  return <>
    <fieldset className="scan-report-quick-filters" disabled={disabled}>
      <legend>Показать уязвимости</legend>
      <button type="button" aria-pressed={selected === ''} onClick={() => onChange({ ...query, severity: null })}>Все уровни</button>
      <button type="button" aria-pressed={query.severity?.length === 2 && query.severity.includes('HIGH') && query.severity.includes('CRITICAL') || false}
        onClick={() => onChange({ ...query, severity: ['HIGH', 'CRITICAL'] })}>Высокие и критические</button>
      <button type="button" aria-pressed={selected === 'UNKNOWN'} onClick={() => onChange({ ...query, severity: ['UNKNOWN'] })}>Опасность неизвестна</button>
    </fieldset>
    <Controls label={label} limit={query.limit ?? 25} sort={query.sort ?? 'severity:desc'} sorts={['severity:desc', 'severity:asc']} disabled={disabled}
    onLimit={limit => onChange({ ...query, limit })} onSort={sort => onChange({ ...query, sort: sort as VulnReportQuery['sort'] })}>
    <label>Уровень опасности · {label}
      <select value={selected} onChange={event => onChange({ ...query, severity: event.target.value ? REPORT_SEVERITIES.filter(item => event.target.value.split(',').includes(item)) : null })}>
        <option value="">Все уровни опасности</option>
        <option value="HIGH,CRITICAL">Высокие и критические</option>
        {REPORT_SEVERITIES.map(item => <option key={item} value={item}>{SEVERITY_LABELS[item]}</option>)}
      </select>
    </label>
    <p>{query.sort === 'severity:asc' ? 'Сначала низкие оценки.' : 'Сначала критические оценки.'} Находки с неизвестным уровнем опасности — в конце списка.</p>
  </Controls>
  </>;
}
export function SbomReportControls({ query, onChange, disabled }: { query: SbomReportQuery; onChange: (query: SbomReportQuery) => void; disabled: boolean }) {
  const [name, setName] = useState(query.name ?? '');
  const [nameError, setNameError] = useState(false);
  const nameId = useId();
  return <Controls label="Пакеты" limit={query.limit ?? 25} sort={query.sort ?? 'name:asc'} sorts={['name:asc', 'name:desc', 'ecosystem:asc', 'ecosystem:desc']} disabled={disabled}
    onLimit={limit => onChange({ ...query, limit })} onSort={sort => onChange({ ...query, sort: sort as SbomReportQuery['sort'] })}>
    <label>Тип пакетов
      <select value={query.ecosystem ?? ''} onChange={event => onChange({ ...query, ecosystem: reportEcosystem.safeParse(event.target.value).data ?? null })}>
        <option value="">Все типы</option>{REPORT_ECOSYSTEMS.map(ecosystem => <option key={ecosystem} value={ecosystem}>{ecosystem}</option>)}
      </select>
    </label>
    <form noValidate onSubmit={event => {
      event.preventDefault();
      if (disabled) return;
      if (name && !REPORT_NAME_PATTERN.test(name)) { setNameError(true); return; }
      setNameError(false);
      onChange({ ...query, name: name || null });
    }}>
      <label>Название пакета
        <input value={name} maxLength={128} pattern={'[A-Za-z0-9@._+:\\/\\-]{1,128}'} aria-invalid={nameError}
          aria-describedby={`${nameId}-help${nameError ? ` ${nameId}-error` : ''}`}
          onChange={event => { setName(event.target.value); setNameError(false); }} placeholder="Например, openssl" />
      </label>
      {nameError ? <p id={`${nameId}-error`} role="alert">Название пакета: от 1 до 128 символов — латинские буквы, цифры и @ . _ + : / - без пробелов.</p> : null}
      <button type="submit">Найти пакет</button>
      <button type="button" onClick={() => { setName(''); setNameError(false); onChange({ ...query, name: null }); }}>Сбросить название</button>
      <small id={`${nameId}-help`}>Введите название или его часть.</small>
    </form>
  </Controls>;
}
export function SecretReportControls({ query, onChange, disabled }: { query: SecretReportQuery; onChange: (query: SecretReportQuery) => void; disabled: boolean }) {
  const [ruleId, setRuleId] = useState(query.ruleId ?? '');
  const [ruleError, setRuleError] = useState(false);
  const ruleIdPrefix = useId();
  return <Controls label="Возможные секреты" limit={query.limit ?? 25} sort={query.sort ?? 'ruleId:asc'} sorts={['ruleId:asc', 'ruleId:desc', 'line:asc', 'line:desc']} disabled={disabled}
    onLimit={limit => onChange({ ...query, limit })} onSort={sort => onChange({ ...query, sort: sort as SecretReportQuery['sort'] })}>
    <label>Номер строки
      <select value={query.linePresence ?? ''} onChange={event => onChange({ ...query, linePresence: event.target.value === 'known' || event.target.value === 'unknown' ? event.target.value : null })}>
        <option value="">Все строки</option><option value="known">Известен</option><option value="unknown">Неизвестен</option>
      </select>
    </label>
    <form noValidate onSubmit={event => {
      event.preventDefault();
      if (disabled) return;
      if (ruleId && !REPORT_RULE_ID_PATTERN.test(ruleId)) { setRuleError(true); return; }
      setRuleError(false);
      onChange({ ...query, ruleId: ruleId || null });
    }}>
      <label>Код правила<input value={ruleId} maxLength={80} pattern={'[A-Za-z0-9._\\-]{1,80}'} aria-invalid={ruleError}
        aria-describedby={`${ruleIdPrefix}-help${ruleError ? ` ${ruleIdPrefix}-error` : ''}`}
        onChange={event => { setRuleId(event.target.value); setRuleError(false); }} /></label>
      {ruleError ? <p id={`${ruleIdPrefix}-error`} role="alert">Код правила: от 1 до 80 символов — буквы, цифры, точка, подчёркивание или дефис.</p> : null}
      <button type="submit">Найти по правилу</button>
      <button type="button" onClick={() => { setRuleId(''); setRuleError(false); onChange({ ...query, ruleId: null }); }}>Сбросить правило</button>
      <small id={`${ruleIdPrefix}-help`}>Поиск по точному коду правила. Значения секретов не показываются.</small>
    </form>
  </Controls>;
}
