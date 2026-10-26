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
function expectEstimate(scanId = id) {
  expect(bar(scanId)).toHaveAttribute('value');
  expect(percentValue(scanId)).toBeGreaterThanOrEqual(0);
  expect(percentValue(scanId)).toBeLessThan(100);
  expect(bar(scanId)).toHaveAttribute('aria-valuetext', expect.stringContaining('Оценка прогресса: ≈'));
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
  'shows approximate %s progress without inventing a check stage or ETA',
  (state) => {
    render(<ScanProgressPanel scan={snapshot({ state })} />);
    expectEstimate();
    expect(percentValue()).toBe(0);
    expect(group()).toHaveTextContent('Этап сканирования: не предоставлен сервером');
    expect(group()).toHaveTextContent('Получены итоги: 0 из 3');
    expect(group()).toHaveTextContent('Без подтверждённого итога: 3');
    expect(group()).toHaveTextContent('Точное оставшееся время неизвестно');
    expect(group().textContent).not.toMatch(/секунд|минут/);
  },
);

it('renders actual decoded active durable outcomes instead of the unpublished perCheck report', () => {
  const scan = durableSnapshot({ secret: 'checked', sbom: 'failed' });
  expect(Object.values(scan.perCheck!)).toEqual([null, null, null, null]);
  render(<ScanProgressPanel scan={scan} />);
  expect(group()).toHaveTextContent('Получены итоги: 2 из 4. Успешно выполнено: 1.');
  expect(group()).toHaveTextContent('Без подтверждённого итога: 2.');
  expectEstimate();
  expect(percentValue()).not.toBe(50);
  expect(group()).toHaveTextContent('Точное оставшееся время неизвестно.');
  expect(group()).toHaveTextContent('Этап сканирования: не предоставлен сервером');
});

it.each(['failed', 'unsupported', 'skipped', 'not_authorized'] as const)(
  'durable %s counts as resolved, not checked or equal-share completion',
  (outcome) => {
    render(<ScanProgressPanel scan={durableSnapshot({ secret: outcome })} />);
    expect(group()).toHaveTextContent('Получены итоги: 1 из 4. Успешно выполнено: 0.');
    expect(group()).toHaveTextContent('Без подтверждённого итога: 3.');
    expectEstimate();
    expect(percentValue()).toBe(0);
  },
);

it('prefers progress requested checks and counters over legacy perCheck display data', () => {
  const scan = durableSnapshot({ secret: 'checked', sbom: 'failed' });
  render(
    <ScanProgressPanel scan={{ ...scan, checks: ['secret'], perCheck: { secret: null }, percent: 75 }} />,
  );
  expect(group()).toHaveTextContent('Получены итоги: 2 из 4. Успешно выполнено: 1.');
  expect(group()).toHaveTextContent('Без подтверждённого итога: 2.');
  expectEstimate();
  expect(percentValue()).not.toBe(75);
});

it.each(['partial', 'failed', 'cancelled'] as const)(
  'decoded terminal %s preserves durable missing outcomes without a full-success bar',
  (state) => {
    render(<ScanProgressPanel scan={durableSnapshot({ secret: 'checked', sbom: 'failed' }, state)} />);
    expect(group()).toHaveTextContent('Получены итоги: 2 из 4. Успешно выполнено: 1.');
    expect(group()).toHaveTextContent('Без сохранённого итога: 2.');
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
  expect(group()).toHaveTextContent('Этап сканирования: sbom');
  expect(group()).toHaveTextContent('Получены итоги: 2 из 3. Успешно выполнено: 1');
  expect(group()).toHaveTextContent('Без подтверждённого итога: 1');
  expectEstimate();
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
    expect(group()).toHaveTextContent('Получены итоги: 1 из 1. Успешно выполнено: 0');
    expect(group()).toHaveTextContent('Ожидаем итоговый статус скана');
    expectEstimate();
    expect(percentValue()).toBe(0);
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
  expect(group()).toHaveTextContent('Счётчики проверок не предоставлены сервером');
  expect(group().textContent).not.toMatch(/из 0|выполнено: 0|итога: 0/);
  expectEstimate();
});

it.each([0, 12.5, 99])(
  'renders only explicit finite server percent %s, without deriving it from outcomes',
  (percent) => {
    render(<ScanProgressPanel scan={snapshot({ percent })} />);
    expect(bar()).toHaveAttribute('value', String(percent));
    expect(bar()).toHaveAttribute('aria-valuetext', expect.stringContaining(`${percent}% по данным сервера`));
    expect(group()).toHaveTextContent('Без подтверждённого итога: 3');
  },
);

it.each([NaN, Infinity, -1, 101])('does not clamp invalid percent %s into a misleading value', (percent) => {
  render(<ScanProgressPanel scan={snapshot({ percent })} />);
  expectEstimate();
  expect(percentValue()).toBe(0);
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
    expect(group()).toHaveTextContent('Получены итоги: 1 из 3. Успешно выполнено: 1');
    expect(group()).toHaveTextContent('Без сохранённого итога: 2');
    expect(group()).toHaveTextContent('Скан больше не выполняется');
    if (state === 'completed') expect(group()).toHaveTextContent('100% — завершение подтверждено сервером');
    else expect(group().textContent).not.toContain('100%');
  },
);

it('resets the estimate when a new running snapshot loses checked credit', () => {
  const view = render(
    <ScanProgressPanel
      scan={snapshot({ percent: 75, perCheck: { secret: checked, sbom: null, vuln: null } })}
    />,
  );
  expect(bar()).toHaveAttribute('value', '75');
  view.rerender(<ScanProgressPanel scan={snapshot()} />);
  expectEstimate();
  expect(percentValue()).toBe(0);
  expect(group()).toHaveTextContent('Получены итоги: 0 из 3');
});

it('advances without moving focus or resetting on polls, and isolates scans with timer cleanup', async () => {
  vi.useFakeTimers();
  const content = (scan: ScanStatus) => (
    <>
      <button>Сохранить фокус</button>
      <ScanProgressPanel scan={scan} />
    </>
  );
  const view = render(content(snapshot({ stage: 'secret' })));
  const button = screen.getByRole('button');
  button.focus();
  // jsdom focus schedules its own task; isolate the panel's interval below.
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });
  const descriptionId = bar().getAttribute('aria-describedby')!;
  expect(document.getElementById(descriptionId)).toHaveTextContent('Точное оставшееся время неизвестно');
  const original = percentValue();
  expect(vi.getTimerCount()).toBe(1);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(120000);
  });
  expect(percentValue()).toBeGreaterThan(original);
  const advanced = percentValue();
  for (let index = 0; index < 20; index++) view.rerender(content(snapshot({ stage: 'secret' })));
  expect(percentValue()).toBe(advanced);
  expect(vi.getTimerCount()).toBe(1);
  expect(bar().getAttribute('aria-describedby')).toBe(descriptionId);
  expect(document.activeElement).toBe(button);
  view.rerender(content(snapshot({ scanId: otherId, checks: undefined, perCheck: undefined })));
  expect(screen.queryByRole('group', { name: `Ход сканирования ${id}` })).toBeNull();
  expect(group(otherId)).toHaveTextContent('Счётчики проверок не предоставлены сервером');
  expectEstimate(otherId);
  expect(percentValue(otherId)).toBe(0);
  expect(vi.getTimerCount()).toBe(1);
  view.unmount();
  expect(vi.getTimerCount()).toBe(0);
  expect(fetch).not.toHaveBeenCalled();
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
  expectEstimate();
  expect(parsed.percent).toBeNull();
  expect(group()).not.toHaveTextContent('invented-stage');
});

it('isolates styles from scroll progress and disables only decoration for reduced motion', () => {
  const css = readFileSync('src/features/scans/ScanProgressPanel.css', 'utf8');
  expect(css).not.toContain('.scan-a1__progress');
  expect(css).toMatch(/prefers-reduced-motion:\s*reduce/);
  expect(css).toContain('--scan-progress-transition: none');
  expect(css).toContain('transition: var(--scan-progress-transition)');
  expect(css).not.toContain('infinite');
  expect(css).not.toMatch(/display:\s*none/);
  expect(css).toContain('forced-colors: active');
});

it.each(['completed', 'partial', 'failed', 'cancelled', 'cancelling'] as const)(
  'stops its timer at %s without claiming checked-safe or unconfirmed completion',
  async (state) => {
    vi.useFakeTimers();
    const view = render(<ScanProgressPanel scan={snapshot()} />);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(120_000);
    });
    const before = percentValue();
    expect(before).toBeGreaterThan(0);
    view.rerender(<ScanProgressPanel scan={snapshot({ state, percent: 100 })} />);
    expect(vi.getTimerCount()).toBe(0);
    if (state === 'cancelling') {
      expect(percentValue()).toBe(before);
      expect(group()).toHaveTextContent('Оценка приостановлена');
    } else expect(screen.queryByRole('progressbar')).toBeNull();
    if (state === 'completed') expect(group()).toHaveTextContent('100% — завершение подтверждено');
    else expect(group().textContent).not.toContain('100%');
    expect(group()).toHaveTextContent('Успешно выполнено: 0');
    const stopped = group().textContent;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(600_000);
    });
    expect(group().textContent).toBe(stopped);
  },
);

it('starts runtime on running, not during a long queue, and cleans StrictMode timers', async () => {
  vi.useFakeTimers();
  const content = (state: ScanStatus['state']) => (
    <StrictMode>
      <ScanProgressPanel scan={snapshot({ state })} />
    </StrictMode>
  );
  const view = render(content('queued'));
  expect(vi.getTimerCount()).toBe(0);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(600_000);
  });
  expect(percentValue()).toBe(0);
  view.rerender(content('running'));
  expect(percentValue()).toBe(0);
  expect(vi.getTimerCount()).toBe(1);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(60_000);
  });
  expect(percentValue()).toBeGreaterThan(0);
  view.unmount();
  expect(vi.getTimerCount()).toBe(0);
});

it('resets observation on session/subject changes and remount, not context object churn', async () => {
  vi.useFakeTimers();
  const transport = transportFor();
  const content = (currentScope: LiveContext['scope']) => (
    <LiveScanContext.Provider value={{ transport, scope: currentScope }}>
      <ScanProgressPanel scan={snapshot()} />
    </LiveScanContext.Provider>
  );
  const view = render(content(scope));
  await act(async () => {
    await vi.advanceTimersByTimeAsync(120_000);
  });
  const before = percentValue();
  expect(before).toBeGreaterThan(0);
  view.rerender(content([...scope]));
  expect(percentValue()).toBe(before);
  view.rerender(content(['live-scans', 2, 'alice']));
  expect(percentValue()).toBe(0);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(60_000);
  });
  view.rerender(content(['live-scans', 2, 'bob']));
  expect(percentValue()).toBe(0);
  expect(vi.getTimerCount()).toBe(1);
  view.unmount();
  expect(vi.getTimerCount()).toBe(0);
  render(content(scope));
  expect(percentValue()).toBe(0);
  expect(group()).toHaveTextContent('после ухода или перезагрузки начинается заново');
});

it('resets a running -> running durable retry without retaining old elapsed credit or claiming 100%', async () => {
  vi.useFakeTimers();
  const view = render(<ScanProgressPanel scan={durableSnapshot({ secret: 'checked', config: 'failed' })} />);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(120_000);
  });
  expect(percentValue()).toBeGreaterThan(0);
  view.rerender(<ScanProgressPanel scan={durableSnapshot()} />);
  expect(percentValue()).toBe(0);
  expect(group()).toHaveTextContent('Получены итоги: 0 из 4. Успешно выполнено: 0.');
  expect(vi.getTimerCount()).toBe(1);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(60_000);
  });
  expect(percentValue()).toBeGreaterThan(0);
  expect(percentValue()).toBeLessThan(25);
  expect(group().textContent).not.toContain('100%');
  view.rerender(<ScanProgressPanel scan={durableSnapshot({}, 'cancelled')} />);
  expect(group().textContent).not.toContain('100%');
  expect(group()).toHaveTextContent('Без сохранённого итога: 4');
  expect(vi.getTimerCount()).toBe(0);
});

it('keeps compact heuristic/retry uncertainty readable without interactive descendants in a card link', () => {
  render(
    <MemoryRouter>
      <Link to={`/scans/${id}`}>
        <ScanProgressPanel compact scan={snapshot()} />
      </Link>
    </MemoryRouter>,
  );
  expect(group()).toHaveClass('scan-progress-panel--compact');
  expect(group()).toHaveTextContent('Эвристика наблюдаемого скана, не измерение текущей попытки');
  expect(group()).toHaveTextContent('Внутренний повтор без изменения итогов не распознаётся');
  expect(group()).toHaveTextContent('Без новых данных оценка тоже может расти');
  expect(
    screen
      .getByRole('link')
      .querySelector('a, button, input, select, textarea, details, summary, [tabindex]'),
  ).toBeNull();
});

it('keeps the full panel disclosure collapsed and toggleable with the same explanation', async () => {
  const user = userEvent.setup();
  render(<ScanProgressPanel scan={snapshot()} />);
  const summary = within(group()).getByText('Как считается оценка');
  const explanation = summary.closest('details');
  expect(explanation).not.toHaveAttribute('open');
  expect(explanation).toHaveTextContent('Внутренний повтор без изменения итогов не распознаётся');
  expect(explanation).toHaveTextContent('Без новых данных оценка тоже может расти');
  expect(explanation).toHaveTextContent('При потере сохранённых итогов');
  await user.click(summary);
  expect(explanation).toHaveAttribute('open');
  await user.click(summary);
  expect(explanation).not.toHaveAttribute('open');
});

it('retains numerical progress under reduced motion without fake checks or ETA', async () => {
  vi.useFakeTimers();
  vi.stubGlobal(
    'matchMedia',
    vi.fn(() => ({ matches: true })),
  );
  render(<ScanProgressPanel scan={snapshot({ checks: undefined, perCheck: undefined })} />);
  expectEstimate();
  await act(async () => {
    await vi.advanceTimersByTimeAsync(60_000);
  });
  expect(percentValue()).toBeGreaterThan(0);
  expect(group()).toHaveTextContent('Счётчики проверок не предоставлены сервером');
  expect(group()).toHaveTextContent('Это не доля успешных проверок и не гарантия безопасности');
  expect(group()).toHaveTextContent('Точное оставшееся время неизвестно');
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
  const listCounts = within(group()).getByText(/Получены итоги/).textContent;
  expect(transport.list).toHaveBeenCalledTimes(1);
  expect(transport.get).not.toHaveBeenCalled();
  list.unmount();
  mount(transport);
  await screen.findByRole('progressbar');
  expect(within(group()).getByText(/Получены итоги/).textContent).toBe(listCounts);
  expect(transport.get).toHaveBeenCalledTimes(1);
  expect(transport.create).not.toHaveBeenCalled();
  expect(transport.cancel).not.toHaveBeenCalled();
});

it('native list uses a generic local estimate, never borrowed from detail cache', async () => {
  const transport = transportFor(snapshot({ checks: undefined, perCheck: undefined }));
  const view = mount(transport, '/scans');
  act(() =>
    view.client.setQueryData(
      [...scope, 'scan', id],
      snapshot({ percent: 90, perCheck: { secret: checked } }),
    ),
  );
  await screen.findByRole('progressbar');
  expect(group()).toHaveTextContent('Счётчики проверок не предоставлены сервером');
  expectEstimate();
  expect(percentValue()).toBeLessThan(90);
  expect(group()).toHaveTextContent('Набор проверок неизвестен; используется общая модель');
  expect(transport.get).not.toHaveBeenCalled();
});

it('reload restores only the new authoritative snapshot, not the prior local count', async () => {
  const transport = transportFor(snapshot({ perCheck: { secret: checked, sbom: null, vuln: null } }));
  const first = mount(transport);
  await screen.findByRole('progressbar');
  expect(group()).toHaveTextContent('Получены итоги: 1 из 3');
  first.unmount();
  vi.mocked(transport.get).mockResolvedValue(snapshot());
  mount(transport);
  await screen.findByRole('progressbar');
  expect(group()).toHaveTextContent('Получены итоги: 0 из 3');
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
  expect(group()).toHaveTextContent('Получены итоги: 0 из 4');
  // Checkpoint persistence emits no SSE event: the existing bounded GET interval must still run.
  await act(async () => {
    await vi.advanceTimersByTimeAsync(2100);
  });
  expect(transport.get).toHaveBeenCalledTimes(3);
  expect(group()).toHaveTextContent('Получены итоги: 2 из 4. Успешно выполнено: 1.');
  expectEstimate();
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
  expect(group()).toHaveTextContent('Получены итоги: 2 из 4. Успешно выполнено: 1.');
  expect(group()).toHaveTextContent('Без сохранённого итога: 2.');
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
  vi.spyOn(window, 'confirm').mockReturnValue(true);
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
  expect(group()).toHaveTextContent('Получены итоги: 1 из 4. Успешно выполнено: 1.');
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
  expectEstimate();
  expect(group()).toHaveTextContent('Получены итоги: 0 из 3');
  expect(close).not.toHaveBeenCalled();
  await act(async () => {
    finish(snapshot({ state: 'cancelled', perCheck: { secret: checked, sbom: null, vuln: null } }));
    await vi.advanceTimersByTimeAsync(1);
  });
  expect(screen.queryByRole('progressbar')).toBeNull();
  expect(group()).toHaveTextContent('Итог скана: Отменён');
  expect(group()).toHaveTextContent('Без сохранённого итога: 2');
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
  },
);

it.each([401, 403] as const)(
  'list GET %s hides all prior progress and does not request individual scan details',
  async (status) => {
    const transport = transportFor();
    const view = mount(transport, '/scans');
    await screen.findByRole('progressbar');
    vi.mocked(transport.list).mockRejectedValue(new ScanAccessError(status));
    await act(async () => {
      await view.client.invalidateQueries({ queryKey: [...scope, 'list'] });
    });
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
