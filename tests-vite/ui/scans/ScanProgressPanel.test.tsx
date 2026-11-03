import '@testing-library/jest-dom/vitest';
import { readFileSync } from 'node:fs';
import { StrictMode, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanProgressPanel } from '@/features/scans/ScanProgressPanel';
import { LiveScanContext, type LiveContext } from '@/features/scans/liveScanContext';
import { ScanDetailPage } from '@/pages/scans/ScanDetailPage';
import { ScanListPage } from '@/pages/scans/ScanListPage';
import { ScanAccessError } from '@/shared/api/scans/httpScanTransport';
import {
  parseCurrentStatus,
  type ScanProgress,
  type ScanStatus,
  type ScanTransport,
} from '@/shared/api/scans/scanTransport';

// Isolate decoration and unrelated report/AI IO; page queries, scope gates and SSE effects stay real.
vi.mock('@/features/scans/ScanShell', () => ({
  ScanShell: ({ children }: { children: ReactNode }) => <main>{children}</main>,
  controlClass: '',
}));
vi.mock('@/features/scans/MagicCard', () => ({
  MagicCard: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));
vi.mock('@/features/scans/ScanScene', () => ({ ScanScene: () => null }));
vi.mock('@/features/scans/ScanSummaryPanel', () => ({ ScanSummaryPanel: () => null }));
vi.mock('@/pages/scans/ScanReportSections', () => ({
  ScanReportSections: () => <p>Отдельные сохранённые результаты</p>,
}));

const id = '00000000-0000-4000-8000-000000000009';
const otherId = '00000000-0000-4000-8000-000000000010';
const scope = ['live-scans', 1, 'alice'] as const;
const snapshot = (patch: Partial<ScanStatus> = {}): ScanStatus => ({
  scanId: id,
  state: 'running',
  percent: null,
  checks: ['secret', 'sbom', 'vuln'],
  perCheck: { secret: null, sbom: null, vuln: null },
  ...patch,
});
function durableSnapshot(
  outcomes: ScanProgress['outcomes'] = {},
  state: ScanStatus['state'] = 'running',
): ScanStatus {
  const requestedChecks: ScanProgress['requestedChecks'] = ['secret', 'sbom', 'vuln', 'config'];
  const values = { secret: null, sbom: null, vuln: null, config: null, ...outcomes };
  const perCheck = Object.fromEntries(
    requestedChecks.map((check) => [
      check,
      state === 'running' || values[check] === null
        ? null
        : {
            check,
            coverage: 'image',
            outcome: values[check],
            ...(check === 'secret'
              ? { errorCode: null, scannerVersion: null, findingCount: 0 }
              : { errorCode: 'SCAN_FAILED' }),
          },
    ]),
  );
  return parseCurrentStatus({
    scanId: id,
    state,
    checks: requestedChecks,
    perCheck,
    result: null,
    progress: {
      basis: 'durable-outcomes-v1',
      requestedChecks,
      outcomes: values,
      resolvedChecks: Object.values(values).filter((value) => value !== null).length,
      checkedChecks: Object.values(values).filter((value) => value === 'checked').length,
    },
  });
}

const checked = { check: 'secret', coverage: 'image', outcome: 'checked' } as const;
const group = (scanId = id) => screen.getByRole('group', { name: `Ход сканирования ${scanId}` });
const bar = (scanId = id) => screen.getByRole('progressbar', { name: `Прогресс сканирования ${scanId}` });
const percentValue = (scanId = id) => Number(bar(scanId).getAttribute('value'));
function expectIndeterminate(scanId = id) {
  expect(bar(scanId)).not.toHaveAttribute('value');
  expect(group(scanId)).toHaveAttribute('data-progress-source', 'unknown');
  expect(bar(scanId).getAttribute('aria-valuetext')).not.toMatch(/≈\d+%|99%|100%/);
}
function expectUnresolved(count: number) {
  const outcomes = within(group()).getByRole('list', { name: 'Результаты проверок' });
  expect(outcomes.querySelectorAll('[data-outcome="unknown"]')).toHaveLength(count);
}

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(() => {
      throw new Error('Unexpected network in progress tests');
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it.each(['queued', 'running', 'cancelling'] as const)(
  'shows indeterminate %s progress without inventing a check stage or ETA',
  (state) => {
    render(<ScanProgressPanel scan={snapshot({ state })} />);
    expect(bar()).not.toHaveAttribute('value');
    expect(group()).toHaveAttribute('data-progress-source', 'unknown');
    const lifecycle = { queued: 'В очереди', running: 'Проверка продолжается', cancelling: 'Отменяем проверку' };
    expect(group()).toHaveTextContent(lifecycle[state]);
    expect(group()).toHaveTextContent('Получены результаты: 0 из 3');
    const outcomes = within(group()).getByRole('list', { name: 'Результаты проверок' });
    expect(within(outcomes).getAllByRole('listitem')).toHaveLength(3);
    expect(outcomes.querySelectorAll('[data-outcome="unknown"]')).toHaveLength(3);
    expect(group()).toHaveTextContent('Оставшееся время пока неизвестно.');
    expect(group().textContent).not.toMatch(/секунд|минут|≈\d+%|100%/);
  },
);

it('renders actual decoded active durable outcomes instead of the unpublished perCheck report', () => {
  const scan = durableSnapshot({ secret: 'checked', sbom: 'failed' });
  expect(Object.values(scan.perCheck!)).toEqual([null, null, null, null]);
  render(<ScanProgressPanel scan={scan} />);
  expect(group()).toHaveTextContent('Получены результаты: 2 из 4. Выполнено проверок: 1.');
  expectUnresolved(2);
  expectIndeterminate();
  expect(percentValue()).not.toBe(50);
  expect(group()).toHaveTextContent('Оставшееся время пока неизвестно.');
  expect(group()).toHaveTextContent('Проверка продолжается');
});

it.each(['failed', 'unsupported', 'skipped', 'not_authorized'] as const)(
  'durable %s counts as resolved, not checked or equal-share completion',
  (outcome) => {
    render(<ScanProgressPanel scan={durableSnapshot({ secret: outcome })} />);
    expect(group()).toHaveTextContent('Получены результаты: 1 из 4. Выполнено проверок: 0.');
    expectUnresolved(3);
    expectIndeterminate();
    expectIndeterminate();
  },
);

it('prefers progress requested checks and counters over legacy perCheck display data', () => {
  const scan = durableSnapshot({ secret: 'checked', sbom: 'failed' });
  render(
    <ScanProgressPanel scan={{ ...scan, checks: ['secret'], perCheck: { secret: null }, percent: 75 }} />,
  );
  expect(group()).toHaveTextContent('Получены результаты: 2 из 4. Выполнено проверок: 1.');
  expectUnresolved(2);
  expectIndeterminate();
  expect(percentValue()).not.toBe(75);
});

it.each(['partial', 'failed', 'cancelled'] as const)(
  'decoded terminal %s preserves durable missing outcomes without a full-success bar',
  (state) => {
    render(<ScanProgressPanel scan={durableSnapshot({ secret: 'checked', sbom: 'failed' }, state)} />);
    expect(group()).toHaveTextContent('Получены результаты: 2 из 4. Выполнено проверок: 1.');
    expectUnresolved(2);
    expect(screen.queryByRole('progressbar')).toBeNull();
    expect(group().textContent).not.toContain('100%');
  },
);

it('counts saved outcomes separately from checked and ignores unrequested checks without treating them as elapsed time', () => {
  render(
    <ScanProgressPanel
      scan={snapshot({
        stage: 'sbom',
        checks: ['secret', 'sbom', 'vuln'],
        perCheck: {
          secret: checked,
          sbom: { check: 'sbom', coverage: 'image', outcome: 'failed' },
          vuln: null,
          config: { check: 'config', coverage: 'image', outcome: 'checked' },
        },
      })}
    />,
  );
  expect(group()).toHaveTextContent('Состав пакетов (SBOM)');
  expect(group()).toHaveTextContent('Получены результаты: 2 из 3. Выполнено проверок: 1');
  expectUnresolved(1);
  expectIndeterminate();
  expect(percentValue()).not.toBe(66);
});

it.each(['failed', 'unsupported', 'skipped', 'not_authorized'] as const)(
  '%s is a saved outcome, never a checked result or scan completion',
  (outcome) => {
    render(
      <ScanProgressPanel
        scan={snapshot({ check: 'secret', checks: undefined, perCheck: { secret: { ...checked, outcome } } })}
      />,
    );
    expect(group()).toHaveTextContent('Получены результаты: 1 из 1. Выполнено проверок: 0');
    expect(group()).toHaveTextContent('Ожидаем завершения проверки.');
    expectIndeterminate();
    expectIndeterminate();
  },
);

it.each([
  { checks: undefined, perCheck: undefined },
  { checks: [], perCheck: {} },
  { checks: ['secret'] as const, perCheck: undefined },
])('does not turn absent metadata into zero checked or zero remaining', (patch) => {
  render(
    <ScanProgressPanel scan={snapshot({ ...patch, checks: patch.checks ? [...patch.checks] : undefined })} />,
  );
  expect(group()).toHaveTextContent('Результаты проверок пока недоступны.');
  expect(group().textContent).not.toMatch(/из 0|выполнено: 0|итога: 0/);
  if (patch.checks?.length) expectIndeterminate();
  else {
    expect(bar()).not.toHaveAttribute('value');
    expect(group()).toHaveTextContent('Процент выполнения пока неизвестен.');
  }
});

it.each([0, 12.5, 99])(
  'renders only explicit finite server percent %s, without deriving it from outcomes',
  (percent) => {
    render(<ScanProgressPanel scan={snapshot({ percent })} />);
    expect(bar()).toHaveAttribute('value', String(percent));
    expect(bar()).toHaveAttribute('aria-valuetext', expect.stringContaining(`Выполнено: ${percent}%.`));
    expectUnresolved(3);
  },
);

it.each([NaN, Infinity, -1, 101])('does not clamp invalid percent %s into a misleading value', (percent) => {
  render(<ScanProgressPanel scan={snapshot({ percent })} />);
  expectIndeterminate();
  expectIndeterminate();
});

it.each(['completed', 'partial', 'failed', 'cancelled'] as const)(
  'terminal %s removes activity and preserves missing outcomes independently of completion',
  (state) => {
    render(
      <ScanProgressPanel
        scan={snapshot({ state, percent: 100, perCheck: { secret: checked, sbom: null, vuln: null } })}
      />,
    );
    expect(screen.queryByRole('progressbar')).toBeNull();
    expect(group()).toHaveTextContent('Получены результаты: 1 из 3. Выполнено проверок: 1');
    expectUnresolved(2);
    expect(group()).toHaveTextContent('Смотрите результаты отдельных проверок.');
    if (state === 'completed') expect(group()).toHaveTextContent('100% — проверка завершена.');
    else expect(group().textContent).not.toContain('100%');
  },
);

it('removes an explicit server percentage when the new running snapshot no longer provides it', () => {
  const view = render(
    <ScanProgressPanel
      scan={snapshot({ percent: 75, perCheck: { secret: checked, sbom: null, vuln: null } })}
    />,
  );
  expect(bar()).toHaveAttribute('value', '75');
  view.rerender(<ScanProgressPanel scan={snapshot()} />);
  expectIndeterminate();
  expectIndeterminate();
  expect(group()).toHaveTextContent('Получены результаты: 0 из 3');
});

it('elapsed time and repeated polls do not invent progress or move focus, and scan replacement uses current metadata', async () => {
  vi.useFakeTimers();
  const content = (scan: ScanStatus) => <><button>Сохранить фокус</button><ScanProgressPanel scan={scan} /></>;
  const view = render(content(snapshot({ stage: 'secret' })));
  const button = screen.getByRole('button'); button.focus();
  await act(async () => { await vi.advanceTimersByTimeAsync(0); });
  const originalBar = bar();
  const descriptionId = originalBar.getAttribute('aria-describedby')!;
  expect(document.getElementById(descriptionId)).toHaveTextContent('Оставшееся время пока неизвестно.');
  expectIndeterminate(); expect(vi.getTimerCount()).toBe(0);
  await act(async () => { await vi.advanceTimersByTimeAsync(120000); });
  for (let index = 0; index < 20; index++) view.rerender(content(snapshot({ stage: 'secret' })));
  expectIndeterminate(); expect(bar()).toBe(originalBar);
  expect(bar().getAttribute('aria-describedby')).toBe(descriptionId);
  expect(document.activeElement).toBe(button); expect(vi.getTimerCount()).toBe(0);
  view.rerender(content(snapshot({ scanId: otherId, checks: undefined, perCheck: undefined })));
  expect(screen.queryByRole('group', { name: `Ход сканирования ${id}` })).toBeNull();
  expect(group(otherId)).toHaveTextContent('Результаты проверок пока недоступны.');
  expectIndeterminate(otherId);
  view.unmount(); expect(vi.getTimerCount()).toBe(0); expect(fetch).not.toHaveBeenCalled();
});

it('keeps native parser percent null and refuses an unreviewed progress shape', () => {
  const parsed = parseCurrentStatus({
    scanId: id,
    state: 'running',
    result: null,
    checks: ['secret'],
    perCheck: { secret: null },
    percent: 80,
    stage: 'invented-stage',
  });
  expect(parsed.percent).toBeNull();
  expect(parsed.stage).toBeUndefined();
  expect(() =>
    parseCurrentStatus({ scanId: id, state: 'running', result: null, progress: { done: 1 } }),
  ).toThrow();
  render(<ScanProgressPanel scan={parsed} />);
  expectIndeterminate();
  expect(parsed.percent).toBeNull();
  expect(group()).not.toHaveTextContent('invented-stage');
});

it('isolates static indeterminate styles from scroll progress and preserves forced-color support without animation', () => {
  const css = readFileSync('src/features/scans/ScanProgressPanel.css', 'utf8');
  expect(css).not.toContain('.scan-a1__progress');
  // The static unknown-work pattern needs no reduced-motion exception or local animation.
  expect(css).not.toMatch(/(?:animation|transition)\s*:/);
  expect(css).not.toContain('@keyframes');
  expect(css).toContain(':indeterminate');
  expect(css).not.toContain('infinite');
  expect(css).not.toMatch(/display:\s*none/);
  expect(css).toContain('forced-colors: active');
});

it.each(['completed', 'partial', 'failed', 'cancelled', 'cancelling'] as const)(
  'never starts a local timer and preserves authoritative %s without claiming checked-safe or unconfirmed completion',
  async (state) => {
    vi.useFakeTimers();
    const view = render(<ScanProgressPanel scan={snapshot()} />);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(120_000);
    });
    expectIndeterminate();
    view.rerender(<ScanProgressPanel scan={snapshot({ state, percent: 100 })} />);
    expect(vi.getTimerCount()).toBe(0);
    if (state === 'cancelling') {
      expect(bar()).not.toHaveAttribute('value');
      expect(group()).toHaveTextContent('Ожидаем завершения проверки.');
      expect(group()).toHaveTextContent('Отменяем проверку');
    } else expect(screen.queryByRole('progressbar')).toBeNull();
    if (state === 'completed') expect(group()).toHaveTextContent('100% — проверка завершена.');
    else expect(group().textContent).not.toContain('100%');
    expect(group()).toHaveTextContent('Выполнено проверок: 0');
    const stopped = group().textContent;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(600_000);
    });
    expect(group().textContent).toBe(stopped);
  },
);

it('StrictMode queue and running transitions never start a local percentage timer', async () => {
  vi.useFakeTimers();
  const content = (state: ScanStatus['state']) => <StrictMode><ScanProgressPanel scan={snapshot({ state })} /></StrictMode>;
  const view = render(content('queued'));
  expectIndeterminate(); expect(vi.getTimerCount()).toBe(0);
  await act(async () => { await vi.advanceTimersByTimeAsync(600000); });
  expectIndeterminate();
  view.rerender(content('running'));
  expectIndeterminate(); expect(vi.getTimerCount()).toBe(0);
  await act(async () => { await vi.advanceTimersByTimeAsync(60000); });
  expectIndeterminate();
  view.unmount(); expect(vi.getTimerCount()).toBe(0);
});

it('session/subject changes and remount never reuse local elapsed credit or previous snapshot counts', async () => {
  vi.useFakeTimers();
  const transport = transportFor();
  const content = (currentScope: LiveContext['scope'], scan = snapshot()) => (
    <LiveScanContext.Provider value={{ transport, scope: currentScope }}><ScanProgressPanel scan={scan} /></LiveScanContext.Provider>
  );
  const current = snapshot({ perCheck: { secret: checked, sbom: null, vuln: null } });
  const view = render(content(scope, current));
  await act(async () => { await vi.advanceTimersByTimeAsync(120000); });
  expectIndeterminate(); expect(group()).toHaveTextContent('Выполнено проверок: 1');
  view.rerender(content([...scope], current));
  expectIndeterminate(); expect(group()).toHaveTextContent('Выполнено проверок: 1');
  view.rerender(content(['live-scans', 2, 'alice']));
  expectIndeterminate(); expect(group()).toHaveTextContent('Выполнено проверок: 0');
  await act(async () => { await vi.advanceTimersByTimeAsync(60000); });
  view.rerender(content(['live-scans', 2, 'bob']));
  expectIndeterminate(); expect(group()).toHaveTextContent('Выполнено проверок: 0');
  expect(vi.getTimerCount()).toBe(0);
  view.unmount(); render(content(scope));
  expectIndeterminate(); expect(group()).toHaveTextContent('Выполнено проверок: 0');
});

it('running durable retry drops old outcomes without retaining elapsed credit or claiming 100%', async () => {
  vi.useFakeTimers();
  const view = render(<ScanProgressPanel scan={durableSnapshot({ secret: 'checked', config: 'failed' })} />);
  expect(group()).toHaveTextContent('Получены результаты: 2 из 4. Выполнено проверок: 1.');
  await act(async () => { await vi.advanceTimersByTimeAsync(120000); });
  expectIndeterminate();
  view.rerender(<ScanProgressPanel scan={durableSnapshot()} />);
  expectIndeterminate(); expect(group()).toHaveTextContent('Получены результаты: 0 из 4. Выполнено проверок: 0.');
  expectUnresolved(4); expect(vi.getTimerCount()).toBe(0);
  await act(async () => { await vi.advanceTimersByTimeAsync(60000); });
  expectIndeterminate(); expect(group()).not.toHaveTextContent('100%');
  view.rerender(<ScanProgressPanel scan={durableSnapshot({}, 'cancelled')} />);
  expect(group()).not.toHaveTextContent('100%'); expectUnresolved(4); expect(vi.getTimerCount()).toBe(0);
});

it('keeps compact unknown progress readable without interactive descendants in a card link', () => {
  render(<MemoryRouter><Link to={`/scans/${id}`}><ScanProgressPanel compact scan={snapshot()} /></Link></MemoryRouter>);
  expect(group()).toHaveClass('scan-progress-panel--compact'); expectIndeterminate();
  expect(group()).toHaveTextContent('Процент выполнения пока неизвестен.');
  expect(group()).toHaveTextContent('Оставшееся время пока неизвестно.');
  expect(screen.getByRole('link').querySelector('a, button, input, select, textarea, details, summary, [tabindex]')).toBeNull();
});

it('keeps terminal progress after the overview collapsed and toggleable without changing its confirmed content', async () => {
  const user = userEvent.setup();
  mount(transportFor(snapshot({ state: 'completed' })));
  const summary = await screen.findByText('Подробности · ход завершённой проверки', { selector: 'summary' });
  expect(summary.closest('details')).not.toHaveAttribute('open');
  expect(group()).not.toBeVisible();
  await user.click(summary);
  expect(summary.closest('details')).toHaveAttribute('open');
  expect(group()).toHaveTextContent('100% — проверка завершена.');
  expect(group()).toHaveTextContent('Получены результаты: 0 из 3. Выполнено проверок: 0.');
  await user.click(summary);
  expect(summary.closest('details')).not.toHaveAttribute('open');
  expect(group()).not.toBeVisible();
});

it('reduced motion does not fabricate numerical progress, check counts or ETA', async () => {
  vi.useFakeTimers(); vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: true })));
  render(<ScanProgressPanel scan={snapshot({ perCheck: undefined })} />);
  expectIndeterminate();
  await act(async () => { await vi.advanceTimersByTimeAsync(60000); });
  expectIndeterminate(); expect(vi.getTimerCount()).toBe(0);
  expect(group()).toHaveTextContent('Результаты проверок пока недоступны.');
  expect(group()).toHaveTextContent('Оставшееся время пока неизвестно.');
  expect(group()).not.toHaveTextContent('Выполнено проверок: 0');
});

it('preserves explicit server percent without elapsed drift and becomes indeterminate when it disappears', async () => {
  vi.useFakeTimers();
  const view = render(<ScanProgressPanel scan={snapshot({ percent: 5, perCheck: { secret: checked } })} />);
  expect(percentValue()).toBe(5);
  expect(group()).toHaveAttribute('data-progress-source', 'server');
  expect(group()).not.toHaveTextContent('Приблизительная оценка');
  expect(vi.getTimerCount()).toBe(0);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(120_000);
  });
  expect(percentValue()).toBe(5);
  view.rerender(<ScanProgressPanel scan={snapshot({ percent: 0, perCheck: { secret: checked } })} />);
  expect(percentValue()).toBe(0);
  expect(group()).toHaveTextContent('Выполнено: 0%.');
  view.rerender(<ScanProgressPanel scan={snapshot({ perCheck: { secret: checked } })} />);
  expectIndeterminate();
  expect(group()).toHaveAttribute('data-progress-source', 'unknown');
  expect(group()).not.toHaveTextContent('по данным сервера');
});

it('waits for completed rather than rewriting a premature server 100 to a fictitious 99', async () => {
  vi.useFakeTimers();
  const view = render(<ScanProgressPanel scan={snapshot({ percent: 100 })} />);
  expect(bar()).not.toHaveAttribute('value');
  expect(group()).toHaveTextContent('Ожидаем завершения проверки.');
  expect(group().textContent).not.toMatch(/99%|100%/);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(60_000);
  });
  expect(bar()).not.toHaveAttribute('value');
  view.rerender(<ScanProgressPanel scan={snapshot({ state: 'completed' })} />);
  expect(group()).toHaveTextContent('100% — проверка завершена.');
});

it('missing metadata stays indeterminate and never displays remembered counts as fresh', async () => {
  vi.useFakeTimers(); const value = durableSnapshot({ secret: 'checked' });
  const view = render(<ScanProgressPanel scan={value} />);
  expect(group()).toHaveTextContent('Получены результаты: 1 из 4'); expectIndeterminate();
  await act(async () => { await vi.advanceTimersByTimeAsync(120000); });
  view.rerender(<ScanProgressPanel scan={snapshot({ checks: undefined, perCheck: {} })} />);
  expectIndeterminate(); expect(group()).toHaveTextContent('Результаты проверок пока недоступны.');
  expect(group()).not.toHaveTextContent('Получены результаты'); expect(vi.getTimerCount()).toBe(0);
  await act(async () => { await vi.advanceTimersByTimeAsync(60000); }); expectIndeterminate();
  view.rerender(<ScanProgressPanel scan={value} />);
  expectIndeterminate(); expect(group()).toHaveTextContent('Получены результаты: 1 из 4');
});

it('shows the same durable outcomes in the detail checks and progress, without unpublished report metadata', async () => {
  const transport = transportFor(durableSnapshot({ secret: 'checked', sbom: 'failed' }));
  mount(transport);
  await screen.findByRole('progressbar');
  const coverage = screen.getByRole('list', { name: 'Исходы проверок' });
  const outcomes = within(coverage).getAllByRole('listitem');
  expect(outcomes).toHaveLength(2);
  expect(outcomes[0]).toHaveTextContent('Поиск секретов');
  expect(outcomes[0]).toHaveAttribute('data-outcome', 'checked');
  expect(outcomes[1]).toHaveTextContent('Состав пакетов (SBOM)');
  expect(outcomes[1]).toHaveAttribute('data-outcome', 'failed');
  expect(within(coverage).getAllByText('Исход проверки подтверждён; отчёт ещё не опубликован.')).toHaveLength(
    2,
  );
  expect(coverage.querySelector('details')).toBeNull();
  const pending = screen.getByRole('list', { name: 'Проверки без подтверждённого результата' });
  expect(within(pending).getAllByRole('listitem')).toHaveLength(2);
  expect(pending).toHaveTextContent('Уязвимости');
  expect(pending).toHaveTextContent('Конфигурация образа');
  expect(pending).not.toHaveTextContent('Поиск секретов');
  expect(group()).toHaveTextContent('Получены результаты: 2 из 4. Выполнено проверок: 1.');
  expect(screen.getByText('Отдельные сохранённые результаты')).toBeVisible();
  expect(transport.results).not.toHaveBeenCalled();
});

it.each(['failed', 'unsupported', 'skipped', 'not_authorized'] as const)(
  'detail keeps durable %s resolved but not successful',
  async (outcome) => {
    mount(transportFor(durableSnapshot({ secret: outcome })));
    await screen.findByRole('progressbar');
    const coverage = screen.getByRole('list', { name: 'Исходы проверок' });
    expect(within(coverage).getByRole('listitem')).toHaveAttribute('data-outcome', outcome);
    expect(group()).toHaveTextContent('Получены результаты: 1 из 4. Выполнено проверок: 0.');
    expect(
      screen.getByRole('list', { name: 'Проверки без подтверждённого результата' }),
    ).not.toHaveTextContent('Поиск секретов');
  },
);

it('offers an explicit retry after the first GET fails, without duplicate requests or optimistic progress', async () => {
  const transport = transportFor();
  let finish!: (value: ScanStatus) => void;
  vi.mocked(transport.get)
    .mockRejectedValueOnce(new TypeError('Failed to fetch'))
    .mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
  mount(transport);
  const retry = await screen.findByRole('button', { name: 'Повторить получение статуса' });
  expect(transport.get).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole('progressbar')).toBeNull();
  fireEvent.click(retry);
  expect(await screen.findByText('Загружаем снимок…')).toHaveAttribute('role', 'status');
  expect(screen.queryByRole('button', { name: 'Повторить получение статуса' })).toBeNull();
  fireEvent.click(retry);
  expect(transport.get).toHaveBeenCalledTimes(2);
  expect(screen.queryByRole('progressbar')).toBeNull();
  await act(async () => finish(snapshot()));
  await screen.findByRole('progressbar');
  expect(screen.queryByRole('button', { name: 'Повторить получение статуса' })).toBeNull();
});

it('keeps configuration findings visible while only diagnostic versions and source codes are collapsed', async () => {
  const digest = `sha256:${'a'.repeat(64)}`;
  const config: NonNullable<ScanStatus['config']> = {
    checksVersion: 'image-config-user-v1',
    resourcePolicyVersion: 'image-config-policy-v1',
    supportedRuleIds: ['IMGCFG_USER_ROOT'],
    completedRuleIds: ['IMGCFG_USER_ROOT'],
    config: { outcome: 'checked' },
    rules: [{ ruleId: 'IMGCFG_USER_ROOT', outcome: 'checked' }],
    history: { outcome: 'unsupported', reason: 'RULE_NOT_IMPLEMENTED' },
    dockerfile: { outcome: 'unsupported', reason: 'SOURCE_NOT_PROVIDED' },
    iac: { outcome: 'unsupported', reason: 'SOURCE_NOT_PROVIDED' },
    findings: [
      {
        findingId: digest,
        ruleId: 'IMGCFG_USER_ROOT',
        category: 'image-config',
        severity: 'MEDIUM',
        severitySource: 'image-config-user-v1',
        classification: 'DEFAULT_ROOT',
        message: 'Image metadata uses the default root user.',
        recommendation: 'Set an explicit non-zero numeric image user; verify runtime identity separately.',
        location: '/config/User',
        manifestDigest: digest,
        configDigest: digest,
        platform: { os: 'linux', architecture: 'amd64' },
      },
    ],
  };
  const value = parseCurrentStatus({
    scanId: id,
    state: 'completed',
    digest,
    platform: 'linux/amd64',
    checks: ['config'],
    config,
    result: null,
    perCheck: {
      config: {
        check: 'config',
        coverage: 'image',
        outcome: 'checked',
        checksVersion: config.checksVersion,
        resourcePolicyVersion: config.resourcePolicyVersion,
        supportedRuleIds: config.supportedRuleIds,
        completedRuleIds: config.completedRuleIds,
        findingCount: 1,
      },
    },
  });
  mount(transportFor(value));
  const section = await screen.findByRole('region', { name: 'Настройки образа' });
  expect(within(section).getByText('Не задан пользователь без прав администратора')).toBeVisible();
  expect(within(section).getByText(/Почему важно: запуск с правами администратора/)).toBeVisible();
  expect(within(section).getByText(/Что сделать: задайте явный ненулевой числовой идентификатор/)).toBeVisible();
  const versions = within(section).getByText(/checks image-config-user-v1/);
  expect(versions.closest('details')).not.toHaveAttribute('open');
  expect(versions).not.toBeVisible();
  expect(within(section).getByText(config.findings[0].message)).not.toBeVisible();
  fireEvent.click(within(section).getByText('Подробности проверки настроек', { selector: 'summary' }));
  expect(versions).toBeVisible();
  expect(within(section).getByText(/Правила: выполнено 1/)).toBeVisible();
  fireEvent.click(within(section).getByText('Подробности · данные сканера', { selector: 'summary' }));
  expect(within(section).getByText(config.findings[0].message)).toBeVisible();
  expect(within(section).getByText(config.findings[0].recommendation)).toBeVisible();
  expect(within(section).getByText(/Место: \/config\/User/)).toHaveTextContent(digest);
});

function transportFor(initial = snapshot()): ScanTransport {
  return {
    kind: 'live',
    capabilities: { list: true, create: false, cancel: false, events: false },
    list: vi.fn(async () => [{ ...initial, targetLabel: 'Synthetic scan' }]),
    get: vi.fn(async () => initial),
    results: vi.fn(async () => ({ findings: [], coverage: [], nextCursor: null })),
    sbom: vi.fn<ScanTransport['sbom']>(async () => ({
      outcome: 'failed',
      coverage: 'image',
      errorCode: 'SCAN_FAILED',
      components: [],
      nextCursor: null,
    })),
    vuln: vi.fn<ScanTransport['vuln']>(async () => ({
      outcome: 'failed',
      coverage: 'image',
      errorCode: 'SCAN_FAILED',
      findings: [],
      nextCursor: null,
    })),
    create: vi.fn(async () => {
      throw new Error('No creation in progress tests');
    }),
    cancel: vi.fn(async () => {}),
  };
}
function mount(transport: ScanTransport, path = `/scans/${id}`) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } });
  const content = (currentScope: LiveContext['scope'] = scope) => (
    <QueryClientProvider client={client}>
      <LiveScanContext.Provider value={{ scope: currentScope, transport }}>
        <MemoryRouter initialEntries={[path]}>
          <Link to={`/scans/${otherId}`}>Другой скан</Link>
          <Routes>
            <Route path="/scans" element={<ScanListPage />} />
            <Route path="/scans/:scanId" element={<ScanDetailPage />} />
          </Routes>
        </MemoryRouter>
      </LiveScanContext.Provider>
    </QueryClientProvider>
  );
  return { ...render(content()), client, content };
}

it('uses the same presentation on list/detail and performs no N+1 detail GETs for list counters', async () => {
  const scan = snapshot({ perCheck: { secret: checked, sbom: null, vuln: null } });
  const transport = transportFor(scan);
  const list = mount(transport, '/scans');
  await screen.findByRole('progressbar');
  const listCounts = within(group()).getByText(/Получены результаты/).textContent;
  expect(transport.list).toHaveBeenCalledTimes(1);
  expect(transport.get).not.toHaveBeenCalled();
  list.unmount();
  mount(transport);
  await screen.findByRole('progressbar');
  expect(within(group()).getByText(/Получены результаты/).textContent).toBe(listCounts);
  expect(transport.get).toHaveBeenCalledTimes(1);
  expect(transport.create).not.toHaveBeenCalled();
  expect(transport.cancel).not.toHaveBeenCalled();
});

it('native list remains indeterminate, never borrowing a percentage from detail cache', async () => {
  const transport = transportFor(snapshot({ checks: undefined, perCheck: undefined }));
  const view = mount(transport, '/scans');
  act(() =>
    view.client.setQueryData(
      [...scope, 'scan', id],
      snapshot({ percent: 90, perCheck: { secret: checked } }),
    ),
  );
  await screen.findByRole('progressbar');
  expect(group()).toHaveTextContent('Результаты проверок пока недоступны.');
  expect(bar()).not.toHaveAttribute('value');
  expect(group()).toHaveTextContent('Процент выполнения пока неизвестен.');
  expect(group().textContent).not.toContain('%');
  expect(transport.get).not.toHaveBeenCalled();
});

it('reload restores only the new authoritative snapshot, not the prior local count', async () => {
  const transport = transportFor(snapshot({ perCheck: { secret: checked, sbom: null, vuln: null } }));
  const first = mount(transport);
  await screen.findByRole('progressbar');
  expect(group()).toHaveTextContent('Получены результаты: 1 из 3');
  first.unmount();
  vi.mocked(transport.get).mockResolvedValue(snapshot());
  mount(transport);
  await screen.findByRole('progressbar');
  expect(group()).toHaveTextContent('Получены результаты: 0 из 3');
  expect(transport.get).toHaveBeenCalledTimes(2);
});

it('polls durable checkpoints with connected SSE and fences a late active GET behind a confirmed terminal snapshot', async () => {
  const initial = durableSnapshot();
  const updated = durableSnapshot({ secret: 'checked', sbom: 'failed' });
  const terminal = durableSnapshot({ secret: 'checked', sbom: 'failed' }, 'cancelled');
  const transport = transportFor(initial);
  let opened!: () => void;
  let finish!: (value: ScanStatus) => void;
  const close = vi.fn();
  transport.capabilities.events = true;
  transport.subscribeEvents = vi.fn((_id, _hint, _error, onOpen) => {
    opened = onOpen;
    return close;
  });
  vi.mocked(transport.get)
    .mockResolvedValueOnce(initial)
    .mockResolvedValueOnce(initial)
    .mockResolvedValueOnce(updated)
    .mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
  const view = mount(transport);
  await screen.findByRole('progressbar');
  await waitFor(() => expect(opened).toBeTypeOf('function'));
  vi.useFakeTimers();
  act(() => opened());
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1001);
  });
  expect(transport.get).toHaveBeenCalledTimes(2);
  expect(screen.getByRole('status', { name: 'Состояние realtime' })).toHaveTextContent('подключён');
  expect(group()).toHaveTextContent('Получены результаты: 0 из 4');
  // Checkpoint persistence emits no SSE event: the existing bounded GET interval must still run.
  await act(async () => {
    await vi.advanceTimersByTimeAsync(2100);
  });
  expect(transport.get).toHaveBeenCalledTimes(3);
  expect(group()).toHaveTextContent('Получены результаты: 2 из 4. Выполнено проверок: 1.');
  expectIndeterminate();
  expect(transport.subscribeEvents).toHaveBeenCalledTimes(1);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(2100);
  });
  expect(transport.get).toHaveBeenCalledTimes(4);
  expect(finish).toBeTypeOf('function');
  // A separate authorized GET observer installs its validated terminal snapshot before the older poll returns.
  act(() => {
    view.client.setQueryData([...scope, 'scan', id], terminal);
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1);
  });
  expect(screen.queryByRole('progressbar')).toBeNull();
  expect(close).toHaveBeenCalledTimes(1);
  await act(async () => {
    finish(initial);
    await vi.advanceTimersByTimeAsync(1);
  });
  expect(view.client.getQueryData<ScanStatus>([...scope, 'scan', id])?.state).toBe('cancelled');
  expect(screen.queryByRole('progressbar')).toBeNull();
  expect(group()).toHaveTextContent('Получены результаты: 2 из 4. Выполнено проверок: 1.');
  expectUnresolved(2);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(7000);
  });
  expect(transport.get).toHaveBeenCalledTimes(4);
});

it('cancel invalidates an overlapping connected-SSE poll and a late running response cannot revive activity', async () => {
  const initial = durableSnapshot({ secret: 'checked' });
  const terminal = durableSnapshot({ secret: 'checked' }, 'cancelled');
  const transport = transportFor(initial);
  transport.capabilities.cancel = true;
  transport.capabilities.events = true;
  let opened!: () => void;
  let finish!: (value: ScanStatus) => void;
  let pollSignal!: AbortSignal;
  const close = vi.fn();
  transport.subscribeEvents = vi.fn((_id, _hint, _error, onOpen) => {
    opened = onOpen;
    return close;
  });
  vi.mocked(transport.get)
    .mockResolvedValueOnce(initial)
    .mockResolvedValueOnce(initial)
    .mockImplementationOnce((_id, signal) => {
      pollSignal = signal!;
      return new Promise((resolve) => {
        finish = resolve;
      });
    })
    .mockResolvedValue(terminal);
  mount(transport);
  await screen.findByRole('progressbar');
  await waitFor(() => expect(opened).toBeTypeOf('function'));
  vi.useFakeTimers();
  act(() => opened());
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1001);
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(2100);
  });
  expect(finish).toBeTypeOf('function');
  fireEvent.click(screen.getByRole('button', { name: 'Отменить скан' }));
  const dialog = screen.getByRole('alertdialog', { name: 'Отменить скан?' });
  expect(transport.cancel).not.toHaveBeenCalled();
  fireEvent.click(within(dialog).getByRole('button', { name: 'Подтвердить отмену' }));
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1);
  });
  expect(transport.cancel).toHaveBeenCalledTimes(1);
  expect(pollSignal.aborted).toBe(true);
  expect(group()).toHaveTextContent('Итог скана: Отменён');
  expect(screen.queryByRole('progressbar')).toBeNull();
  await act(async () => {
    finish(initial);
    await vi.advanceTimersByTimeAsync(1);
  });
  expect(group()).toHaveTextContent('Итог скана: Отменён');
  expect(group()).toHaveTextContent('Получены результаты: 1 из 4. Выполнено проверок: 1.');
  expect(screen.queryByRole('progressbar')).toBeNull();
  expect(close).toHaveBeenCalledTimes(1);
  const reads = vi.mocked(transport.get).mock.calls.length;
  await act(async () => {
    await vi.advanceTimersByTimeAsync(7000);
  });
  expect(transport.get).toHaveBeenCalledTimes(reads);
});

it('SSE/reconnect hints cannot confirm completion; terminal stops activity and closes stream', async () => {
  let hint!: () => void, opened!: () => void, disconnected!: () => void;
  let finish!: (value: ScanStatus) => void;
  const close = vi.fn();
  const transport = transportFor();
  transport.capabilities.events = true;
  transport.subscribeEvents = vi.fn((_id, onHint, onError, onOpen) => {
    hint = onHint;
    opened = onOpen;
    disconnected = onError;
    return close;
  });
  vi.mocked(transport.get)
    .mockResolvedValueOnce(snapshot())
    .mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
  mount(transport);
  await screen.findByRole('progressbar');
  await waitFor(() => expect(opened).toBeTypeOf('function'));
  vi.useFakeTimers();
  act(() => {
    opened();
    for (let index = 0; index < 20; index++) hint();
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1001);
  });
  expect(transport.get).toHaveBeenCalledTimes(2);
  act(() => {
    disconnected();
    opened();
    hint();
  });
  expectIndeterminate();
  expect(group()).toHaveTextContent('Получены результаты: 0 из 3');
  expect(close).not.toHaveBeenCalled();
  await act(async () => {
    finish(snapshot({ state: 'cancelled', perCheck: { secret: checked, sbom: null, vuln: null } }));
    await vi.advanceTimersByTimeAsync(1);
  });
  expect(screen.queryByRole('progressbar')).toBeNull();
  expect(group()).toHaveTextContent('Итог скана: Отменён');
  expectUnresolved(2);
  expect(screen.getByText('Отдельные сохранённые результаты')).toBeTruthy();
  expect(close).toHaveBeenCalledTimes(1);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(6000);
  });
  expect(transport.get).toHaveBeenCalledTimes(2);
});

it.each([401, 403] as const)(
  'a GET %s refetch removes stale progress even while query cache retains its last snapshot',
  async (status) => {
    const transport = transportFor();
    const view = mount(transport);
    await screen.findByRole('progressbar');
    vi.mocked(transport.get).mockRejectedValue(new ScanAccessError(status));
    await act(async () => {
      await view.client.invalidateQueries({ queryKey: [...scope, 'scan', id] });
    });
    expect(view.client.getQueryData([...scope, 'scan', id])).toBeDefined();
    await waitFor(() => expect(screen.queryByRole('progressbar')).toBeNull());
    expect(screen.queryByRole('group', { name: `Ход сканирования ${id}` })).toBeNull();
    expect(screen.getByRole('alert')).toHaveTextContent('Не удалось получить данные скана');
    expect(screen.queryByRole('button', { name: 'Повторить получение статуса' })).toBeNull();
  },
);

it.each([401, 403] as const)(
  'list GET %s hides all prior progress and does not request individual scan details',
  async (status) => {
    const transport = transportFor();
    mount(transport, '/scans');
    await screen.findByRole('progressbar');
    vi.mocked(transport.list).mockRejectedValue(new ScanAccessError(status));
    fireEvent.click(screen.getByRole('button', { name: 'Обновить список сначала' }));
    await waitFor(() => expect(screen.queryByRole('progressbar')).toBeNull());
    expect(screen.queryByRole('group', { name: `Ход сканирования ${id}` })).toBeNull();
    expect(screen.getByRole('alert')).toBeTruthy();
    expect(transport.get).not.toHaveBeenCalled();
  },
);

it('a late old-route GET cannot replace a different scan terminal snapshot', async () => {
  let finish!: (value: ScanStatus) => void;
  let oldSignal!: AbortSignal;
  const transport = transportFor();
  vi.mocked(transport.get).mockImplementation((scanId, signal) => {
    if (scanId === id) {
      oldSignal = signal!;
      return new Promise((resolve) => {
        finish = resolve;
      });
    }
    return Promise.resolve(
      snapshot({ scanId: otherId, state: 'failed', checks: undefined, perCheck: undefined }),
    );
  });
  mount(transport);
  await waitFor(() => expect(finish).toBeTypeOf('function'));
  fireEvent.click(screen.getByRole('link', { name: 'Другой скан' }));
  await screen.findByRole('group', { name: `Ход сканирования ${otherId}` });
  expect(oldSignal.aborted).toBe(true);
  await act(async () => finish(snapshot({ percent: 99, stage: 'OLD-STAGE' })));
  expect(screen.queryByRole('progressbar')).toBeNull();
  expect(group(otherId)).toHaveTextContent('Итог скана: Ошибка');
  expect(document.body.textContent).not.toContain('OLD-STAGE');
});

it('same-owner new session denying access cannot reveal a late prior-session GET', async () => {
  let finish!: (value: ScanStatus) => void;
  let oldSignal!: AbortSignal;
  const transport = transportFor();
  vi.mocked(transport.get)
    .mockImplementationOnce((_scanId, signal) => {
      oldSignal = signal!;
      return new Promise((resolve) => {
        finish = resolve;
      });
    })
    .mockRejectedValue(new ScanAccessError(403));
  const view = mount(transport);
  await waitFor(() => expect(finish).toBeTypeOf('function'));
  view.rerender(view.content(['live-scans', 2, 'alice']));
  await screen.findByRole('alert');
  expect(oldSignal.aborted).toBe(true);
  await act(async () => finish(snapshot({ percent: 99, stage: 'OLD-OWNER-PROGRESS' })));
  expect(screen.queryByRole('group', { name: `Ход сканирования ${id}` })).toBeNull();
  expect(document.body.textContent).not.toContain('OLD-OWNER-PROGRESS');
});
