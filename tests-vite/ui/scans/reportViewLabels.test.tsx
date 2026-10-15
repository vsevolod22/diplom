import '@testing-library/jest-dom/vitest';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { SecretReportControls, SbomReportControls, VulnReportControls } from '@/pages/scans/ReportViewControls';

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(() => { throw new Error('Network forbidden'); }));
  for (const name of ['XMLHttpRequest', 'WebSocket', 'EventSource']) {
    vi.stubGlobal(name, class { constructor() { throw new Error('Network forbidden'); } });
  }
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it('renders Russian report-control labels while preserving every option value and selection payload', () => {
  const onVuln = vi.fn();
  const onSbom = vi.fn();
  const onSecret = vi.fn();
  render(<>
    <VulnReportControls query={{ view: 'report-v1' }} disabled={false} onChange={onVuln} />
    <SbomReportControls query={{ view: 'report-v1' }} disabled={false} onChange={onSbom} />
    <SecretReportControls query={{ view: 'report-v1' }} disabled={false} onChange={onSecret} />
  </>);
  const cases = [
    { label: 'CVE', change: onVuln, sorts: [['severity:desc', 'Сначала критические'], ['severity:asc', 'Сначала низкие']] },
    { label: 'SBOM', change: onSbom, sorts: [['name:asc', 'Имя: А → Я'], ['name:desc', 'Имя: Я → А'], ['ecosystem:asc', 'Экосистема: А → Я'], ['ecosystem:desc', 'Экосистема: Я → А']] },
    { label: 'Secrets', change: onSecret, sorts: [['ruleId:asc', 'Правило: А → Я'], ['ruleId:desc', 'Правило: Я → А'], ['line:asc', 'Строка: по возрастанию'], ['line:desc', 'Строка: по убыванию']] },
  ];
  for (const { label, change, sorts } of cases) {
    const sort = screen.getByLabelText(`Сортировка · ${label}`);
    expect(within(sort).getAllByRole('option').map(option => [(option as HTMLOptionElement).value, option.textContent])).toEqual(sorts);
    for (const [value] of sorts) {
      fireEvent.change(sort, { target: { value } });
      expect(change).toHaveBeenLastCalledWith({ view: 'report-v1', sort: value });
    }
    const limit = screen.getByLabelText(`Строк на странице · ${label}`);
    expect(within(limit).getAllByRole('option').map(option => [(option as HTMLOptionElement).value, option.textContent])).toEqual(['5', '10', '25', '50'].map(value => [value, value]));
    for (const value of ['5', '10', '25', '50']) {
      fireEvent.change(limit, { target: { value } });
      expect(change).toHaveBeenLastCalledWith({ view: 'report-v1', limit: Number(value) });
    }
  }
  const severity = screen.getByLabelText('Уровень опасности (severity) · CVE');
  const severities = [
    ['', 'Все уровни опасности'],
    ['HIGH,CRITICAL', 'Высокие и критические (HIGH + CRITICAL)'],
    ['UNKNOWN', 'Не определён (UNKNOWN)'],
    ['LOW', 'Низкий (LOW)'],
    ['MEDIUM', 'Средний (MEDIUM)'],
    ['HIGH', 'Высокий (HIGH)'],
    ['CRITICAL', 'Критический (CRITICAL)'],
  ];
  expect(within(severity).getAllByRole('option').map(option => [(option as HTMLOptionElement).value, option.textContent])).toEqual(severities);
  for (const [value] of severities) {
    fireEvent.change(severity, { target: { value } });
    expect(onVuln).toHaveBeenLastCalledWith({ view: 'report-v1', severity: value ? value.split(',') : null });
  }
  fireEvent.click(screen.getByRole('button', { name: 'Высокие и критические (HIGH + CRITICAL)' }));
  expect(onVuln).toHaveBeenLastCalledWith({ view: 'report-v1', severity: ['HIGH', 'CRITICAL'] });
  expect(screen.getByText(/UNKNOWN.*всегда в конце при любом порядке сортировки/)).toBeVisible();
  expect(screen.queryByText(/\/page/)).not.toBeInTheDocument();
});
