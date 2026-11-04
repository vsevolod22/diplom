import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ScanListPage } from '@/pages/scans/ScanListPage';
import { ScanDetailPage } from '@/pages/scans/ScanDetailPage';
import { ScanCreatePage } from '@/pages/scans/ScanCreatePage';
import { ScanStatusAnnouncement } from '@/features/scans/ScanStatusAnnouncement';
import { fixtureScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import { createAuthorizedScanTransport, ScanAccessError } from '@/shared/api/scans/httpScanTransport';
import { LiveScanContext } from '@/features/scans/liveScanContext';
import type { ScanCoverage, ScanStatus, ScanSummary, ScanTransport } from '@/shared/api/scans/scanTransport';

// Motion's viewport hook needs an observer in jsdom; the browser suite covers real intersections.
class TestIntersectionObserver implements IntersectionObserver {
  readonly root = null;
  readonly rootMargin = '0px';
  readonly thresholds = [0];
  constructor(callback: IntersectionObserverCallback) {
    void callback;
  }
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords(): IntersectionObserverEntry[] {
    return [];
  }
}
vi.stubGlobal('IntersectionObserver', TestIntersectionObserver);
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.stubGlobal('IntersectionObserver', TestIntersectionObserver); });

function page(path: string, element: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path={path.replace(/\/(?:partial|empty|unsupported|running)-demo$/, '/:scanId')}
            element={element}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...view, client };
}
describe('list-level active scan polling', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  const scan = (state: ScanStatus['state'], scanId = 'list-scan'): ScanSummary => ({
    scanId, state, targetLabel: `image/${scanId}`, percent: null,
  });
  const advance = async (ms: number) => {
    await act(async () => { await vi.advanceTimersByTimeAsync(ms); });
  };
  function mountList(list: ScanTransport['list'], demo = false, get: ScanTransport['get'] = vi.fn(async id => ({ ...scan('completed', id), targetLabel: `image/${id}` }))) {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } });
    const transport: ScanTransport = {
      ...fixtureScanTransport, kind: 'live', list, listPage: undefined, get,
    };
    const content = (current = transport) => (
      <QueryClientProvider client={client}>
        <LiveScanContext.Provider value={{ transport: current, scope: ['live-scans', 1, 'alice'] }}>
          <MemoryRouter initialEntries={[demo ? '/demo/scans' : '/scans']}>
            <ScanListPage demo={demo} />
          </MemoryRouter>
        </LiveScanContext.Provider>
      </QueryClientProvider>
    );
    return { ...render(content()), client, transport, content };
  }

  it('refreshes only loaded active rows without replaying the list, then confirms completion and stops polling without leaving the list', async () => {
    const intervals = vi.spyOn(window, 'setInterval');

    let finish!: (status: ScanStatus) => void;
    const pending = new Promise<ScanStatus>(resolve => { finish = resolve; });
    const list = vi.fn<ScanTransport['list']>().mockResolvedValue([scan('completed', 'saved'), scan('running')]);
    const get = vi.fn<ScanTransport['get']>().mockReturnValueOnce(pending);
    const { transport } = mountList(list, false, get);
    await advance(1);
    const link = screen.getByRole('link', { name: 'Открыть отчёт: image/list-scan, ID list-scan' });
    expect(link.querySelector('a, button, input, select, textarea, details, summary, [tabindex]')).toBeNull();
    link.focus();
    const progress = within(link).getByRole('progressbar');
    expect(progress.hasAttribute('value')).toBe(false);
    expect(within(link).getByText('Процент выполнения пока неизвестен.')).toBeTruthy();
    expect(intervals.mock.calls.some(([, delay]) => delay === 1000)).toBe(false);
    await advance(1998);
    expect(list).toHaveBeenCalledTimes(1);
    await advance(2);
    expect(list).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenCalledWith('list-scan', expect.any(AbortSignal));
    // A slow status response must not overlap or refetch terminal rows/the cursor chain.
    await advance(12_000);
    expect(list).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenCalledTimes(1);
    expect(progress.hasAttribute('value')).toBe(false);
    await act(async () => {
      finish(scan('completed'));
      await vi.advanceTimersByTimeAsync(1);
    });
    expect(screen.getByRole('link', { name: 'Открыть отчёт: image/list-scan, ID list-scan' })).toBe(link);
    expect(document.activeElement).toBe(link);
    expect(within(link).queryByRole('progressbar')).toBeNull();
    expect(within(link).getByText('100% — проверка завершена.')).toBeTruthy();
    expect(within(link).queryByText(/^Оценка прогресса:/)).toBeNull();
    expect(intervals.mock.calls.some(([, delay]) => delay === 1000)).toBe(false);
    const finalText = link.textContent;
    await advance(60_000);
    expect(list).toHaveBeenCalledTimes(1);
    expect(link.textContent).toBe(finalText);
    expect(transport.get).toHaveBeenCalledTimes(1);
  });

  it.each(['queued', 'cancelling'] as const)('polls only a %s item after a terminal row and stops after a manual empty-list reload', async state => {
    const list = vi.fn<ScanTransport['list']>()
      .mockResolvedValueOnce([scan('completed', 'saved'), scan(state)])
      .mockResolvedValue([]);
    const get = vi.fn<ScanTransport['get']>().mockResolvedValue(scan('completed'));
    mountList(list, false, get);
    await advance(1);
    expect(screen.getByRole('group', { name: 'Ход сканирования list-scan' })).toBeTruthy();
    await advance(2001);
    expect(get).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenCalledWith('list-scan', expect.any(AbortSignal));
    fireEvent.click(screen.getByRole('button', { name: 'Обновить список сначала' }));
    await advance(1);
    expect(screen.getByText(/Проверок пока нет/)).toBeTruthy();
    await advance(60_000);
    expect(list).toHaveBeenCalledTimes(2);
    expect(get).toHaveBeenCalledTimes(1);
  });

  it.each(['completed', 'partial', 'failed', 'cancelled'] as const)('does not poll a terminal-only %s list', async state => {
    const list = vi.fn<ScanTransport['list']>().mockResolvedValue([scan(state)]);
    const { transport } = mountList(list);
    await advance(1);
    expect(screen.getByRole('group', { name: 'Ход сканирования list-scan' })).toBeTruthy();
    await advance(60_000);
    expect(list).toHaveBeenCalledTimes(1);
    expect(transport.get).not.toHaveBeenCalled();
  });

  it.each([401, 403] as const)('stops polling after HTTP %s even with a cached running snapshot', async status => {
    const list = vi.fn<ScanTransport['list']>().mockResolvedValue([scan('running')]);
    const get = vi.fn<ScanTransport['get']>().mockRejectedValue(new ScanAccessError(status));
    const { transport } = mountList(list, false, get);
    await advance(1);
    expect(screen.getByRole('progressbar')).toBeTruthy();
    await advance(2001);
    expect(screen.getByRole('alert').textContent).toMatch(status === 401 ? /Сессия больше не действует/ : /не выдано разрешение/);
    expect(screen.queryByRole('progressbar')).toBeNull();
    await advance(60_000);
    expect(list).toHaveBeenCalledTimes(1);
    expect(transport.get).toHaveBeenCalledTimes(1);
  });

  it('stops polling and removes cached running cards when list access becomes unavailable', async () => {
    const list = vi.fn<ScanTransport['list']>().mockResolvedValue([scan('running')]);
    const view = mountList(list);
    await advance(1);
    expect(screen.getByRole('progressbar')).toBeTruthy();
    view.rerender(view.content({ ...view.transport, capabilities: { ...view.transport.capabilities, list: false } }));
    expect(screen.getByText(/Список недоступен без подтверждённой сессии/)).toBeTruthy();
    expect(screen.queryByRole('group', { name: 'Ход сканирования list-scan' })).toBeNull();
    await advance(60_000);
    expect(list).toHaveBeenCalledTimes(1);
    expect(view.transport.get).not.toHaveBeenCalled();
  });

  it('never periodically refreshes static demo fixtures or reads the live list in demo mode', async () => {
    const fixtures = vi.spyOn(fixtureScanTransport, 'listPage');
    const list = vi.fn<ScanTransport['list']>();
    mountList(list, true);
    await advance(1);
    expect(screen.getByRole('group', { name: 'Ход сканирования running-demo' })).toBeTruthy();
    await advance(60_000);
    expect(fixtures).toHaveBeenCalledTimes(1);
    expect(list).not.toHaveBeenCalled();
  });
});

describe('scan UI fixture versus unavailable production', () => {
  it('does not confuse unavailable GET list with empty list', () => {
    page('/scans', <ScanListPage />);
    expect(screen.getByText(/Список недоступен без подтверждённой сессии/)).toBeTruthy();
    expect(screen.queryByText(/Сканов нет \(/)).toBeNull();
  });
  it('labels every fixture and never claims 0 CVE or 100% for partial scan', async () => {
    page('/demo/scans/partial-demo', <ScanDetailPage demo />);
    expect(await screen.findByText(/Сканер недоступен/)).toBeTruthy();
    expect(screen.getByText('Выполнено')).toBeTruthy();
    expect(screen.getAllByText(/«Выполнено» означает завершение проверки/)).toHaveLength(1);
    expect(screen.queryByText(/Выполнено \(не гарантия безопасности\)/)).toBeNull();
    expect(screen.getByText(/ДЕМО · вымышленные данные/)).toBeTruthy();
    const progress = screen.getByRole('group', { name: 'Ход сканирования partial-demo' });
    expect(within(progress).getByText('Смотрите результаты отдельных проверок.')).toBeTruthy();
    expect(screen.getByText(/ожидаем подтверждения digest\/platform/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Отменить скан' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Отменить скан' })).toBeNull();
    expect(screen.queryByText(/0 CVE/)).toBeNull();
    expect(screen.queryByText(/100%/)).toBeNull();
    expect(document.body.textContent).not.toContain('secretValue');
  });
  it('distinguishes filtered-zero from fully checked empty and unsupported coverage', async () => {
    const view = page('/demo/scans/partial-demo', <ScanDetailPage demo />);
    await screen.findByText(/SECRET_DETECTED/);
    fireEvent.change(screen.getByLabelText('Показать находки'), { target: { value: 'vulnerability' } });
    expect(await screen.findByText(/Нет совпадений фильтра/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Сбросить фильтр' }));
    expect(await screen.findByText(/SECRET_DETECTED/)).toBeTruthy();
    view.unmount();
    page('/demo/scans/unsupported-demo', <ScanDetailPage demo />);
    expect(
      await screen.findByText(/Нет подтверждённых находок: область не проверена полностью/),
    ).toBeTruthy();
  });
  it('keeps an empty checked demo unknown without an explicit count and the rest unsupported', async () => {
    vi.spyOn(fixtureScanTransport, 'get').mockResolvedValue({ scanId: 'empty-demo', state: 'completed', checks: ['secret'],
      perCheck: { secret: { check: 'secret', coverage: 'image', outcome: 'checked' } } });
    vi.spyOn(fixtureScanTransport, 'results').mockResolvedValue({ findings: [], nextCursor: null, coverage: [{ check: 'Secrets', status: 'checked' }] });
    page('/demo/scans/empty-demo', <ScanDetailPage demo />);
    expect(await screen.findByText('На текущей странице находок нет; это не значит, что их нет во всём отчёте.')).toBeTruthy();
    expect(screen.getByText('Количество пока неизвестно')).toBeTruthy();
    expect(screen.queryByText(/0 находок в выполненной проверенной области/)).toBeNull();
    expect(screen.getAllByText('Не запрашивалось').length).toBeGreaterThan(0);
    expect(screen.queryByText(/0 CVE/)).toBeNull();
  });
  it('shows demo records only in the explicitly marked demo list', async () => {
    page('/demo/scans', <ScanListPage demo />);
    expect(await screen.findByText(/library\/alpine:latest \(демо\)/)).toBeTruthy();
    expect(screen.getByText(/ДЕМО · вымышленные данные/)).toBeTruthy();
  });
  it('keeps ordered records, keys, links and scan facts outside decorative animation', async () => {
    page('/demo/scans', <ScanListPage demo />);
    await screen.findByText(/library\/alpine:latest \(демо\)/);
    const list = document.querySelector<HTMLElement>('.scan-a1__records');
    if (!list) throw new Error('Missing scan records');
    const records = [...list.querySelectorAll<HTMLElement>(':scope > li')];
    expect(records.length).toBeGreaterThan(1);
    for (const record of records) {
      expect(record.getAttribute('aria-hidden')).not.toBe('true');
      const link = within(record).getByRole('link', { name: /Открыть отчёт:/ });
      expect(link.tagName).toBe('A');
      expect(link.getAttribute('href')).toMatch(/^\/demo\/scans\//);
      expect(link.getAttribute('aria-label')).toContain(within(record).getByRole('heading').textContent);
      expect(link.classList.contains('scan-a1__record-content')).toBe(true);
      expect(within(link).getByRole('heading')).toBeTruthy();
      expect(within(link).getByRole('group', { name: /Ход сканирования/ })).toBeTruthy();
      expect(within(record).getAllByRole('link')).toHaveLength(1);
      expect(link.querySelector('a, button, input, select, textarea, details, summary, [tabindex]')).toBeNull();
      expect(link.querySelector('.scan-progress-panel__stage')?.textContent).toBeTruthy();
      expect(record.textContent).toContain('Вымышленные данные');
    }
    expect(list.querySelectorAll(':scope > li')).toHaveLength(records.length);
    expect(list.querySelector('[style*="opacity: 0"]')).toBeNull();
  });
  it.each(['title', 'progress', 'keyboard'])('opens the whole record via %s', async (activation) => {
    vi.stubGlobal('matchMedia', vi.fn((media: string) => ({
      matches: false, media, onchange: null,
      addListener: vi.fn(), removeListener: vi.fn(),
      addEventListener: vi.fn(), removeEventListener: vi.fn(), dispatchEvent: vi.fn(),
    })));
    const user = userEvent.setup();
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={['/demo/scans']}>
          <Routes>
            <Route path="/demo/scans" element={<ScanListPage demo />} />
            <Route path="/demo/scans/:scanId" element={<p>Открыта запись скана</p>} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const link = await screen.findByRole('link', { name: 'Открыть отчёт: library/alpine:latest (демо), ID partial-demo' });
    if (activation === 'keyboard') {
      link.focus();
      expect(document.activeElement).toBe(link);
      await user.keyboard('{Enter}');
    } else {
      await user.click(activation === 'title'
        ? within(link).getByRole('heading')
        : within(link).getByRole('group', { name: /Ход сканирования/ }));
    }
    expect(await screen.findByText('Открыта запись скана')).toBeTruthy();
  });
  it('leaves modified and middle clicks to native link handling', async () => {
    page('/demo/scans', <ScanListPage demo />);
    const link = await screen.findByRole('link', { name: 'Открыть отчёт: library/alpine:latest (демо), ID partial-demo' });
    const preventedByRouter: boolean[] = [];
    const observeNavigation = (event: MouseEvent) => {
      preventedByRouter.push(event.defaultPrevented);
      // Observe after React's handlers, then stop navigation that jsdom cannot implement.
      event.preventDefault();
    };
    document.addEventListener('click', observeNavigation);
    document.addEventListener('auxclick', observeNavigation);
    try {
      for (const modifier of ['ctrlKey', 'metaKey', 'shiftKey', 'altKey']) {
        fireEvent.click(within(link).getByRole('heading'), { [modifier]: true });
        expect(screen.getByRole('link', { name: 'Открыть отчёт: library/alpine:latest (демо), ID partial-demo' })).toBe(link);
      }
      fireEvent(link, new MouseEvent('auxclick', { bubbles: true, cancelable: true, button: 1 }));
      expect(preventedByRouter).toEqual([false, false, false, false, false]);
      expect(link.getAttribute('href')).toBe('/demo/scans/partial-demo');
    } finally {
      document.removeEventListener('click', observeNavigation);
      document.removeEventListener('auxclick', observeNavigation);
    }
  });
  it('keeps all coverage outcomes and reasons visible with short labels and collapsible metadata', async () => {
    const user = userEvent.setup();
    const outcomes: Array<[ScanCoverage['status'], string]> = [
      ['checked', 'Выполнено'],
      ['failed', 'Сбой · не проверено'],
      ['unsupported', 'Не поддерживается'],
      ['not_authorized', 'Нет разрешения'],
      ['skipped', 'Пропущено'],
    ];
    vi.spyOn(fixtureScanTransport, 'results').mockResolvedValue({
      findings: [], nextCursor: null,
      coverage: outcomes.map(([status]) => ({
        check: status, status, reason: `Причина ${status}`,
        ...(status === 'checked' ? {
          scannerVersion: 'scanner-test', dbVersion: 'db-test',
          checksVersion: 'checks-test', resourcePolicyVersion: 'policy-test',
        } : {}),
      })),
    });
    page('/demo/scans/partial-demo', <ScanDetailPage demo />);
    fireEvent.click(await screen.findByText('Подробности · что удалось проверить'));
    const coverage = await screen.findByRole('list', { name: 'Исходы проверок' });
    const tiles = within(coverage).getAllByRole('listitem');
    expect(tiles).toHaveLength(outcomes.length);
    for (const [index, [status, label]] of outcomes.entries()) {
      const tile = tiles[index];
      expect(tile.getAttribute('data-outcome')).toBe(status);
      expect(within(tile).getByText(label)).toBeTruthy();
      expect(within(tile).getByText('Причина не описана сервером; код доступен в подробностях.').closest('details')).toBe(coverage.closest('details'));
      expect(within(tile).getByText(`Причина: Причина ${status}`).closest('details')?.open).toBe(false);
      expect(tile.querySelector('.scan-a1__coverage-status svg')?.getAttribute('aria-hidden')).toBe('true');
      expect(tile.querySelector('.scan-badge')).toBeNull();
    }
    const metadata = tiles[0].querySelector('details');
    expect(metadata?.open).toBe(false);
    expect(metadata?.textContent).toContain('checks checks-test · policy policy-test');
    expect(metadata?.textContent).toContain('scanner scanner-test · DB db-test');
    expect(tiles[1].querySelector('details')?.open).toBe(false);
    await user.click(within(tiles[0]).getByText('Технические данные · checked'));
    expect(metadata?.open).toBe(true);
    await user.click(within(tiles[0]).getByText('Технические данные · checked'));
    expect(metadata?.open).toBe(false);
    const panel = coverage.closest('details');
    expect(panel?.querySelectorAll('.scan-a1__coverage-note')).toHaveLength(1);
    expect(panel?.querySelector('.scan-a1__coverage-note')?.textContent).toContain('не гарантию безопасности');
  });
  it('keeps unavailable coverage unknown instead of inferring completed checks', async () => {
    vi.spyOn(fixtureScanTransport, 'results').mockRejectedValue(new Error('Report unavailable'));
    const { client } = page('/demo/scans/partial-demo', <ScanDetailPage demo />);
    await waitFor(() => expect(client.getQueryState(['scan-results', 'fixture', 'partial-demo'])?.status).toBe('error'));
    expect(screen.getByText(/Итоги проверок ещё не подтверждены/)).toBeTruthy();
    expect(screen.queryByRole('list', { name: 'Исходы проверок' })).toBeNull();
    expect(screen.getByText(/Итоги проверок ещё не подтверждены/).closest('details')?.querySelector('[data-outcome="checked"]')).toBeNull();
  });
  it('keeps the report compact without decorative reading cards or AI sections', async () => {
    page('/demo/scans/partial-demo', <ScanDetailPage demo />);
    expect(await screen.findByRole('heading', { name: 'Результат проверки образа' })).toBeTruthy();
    expect(document.querySelector('.scan-a1__reading-card')).toBeNull();
    expect(document.querySelector('.scan-a1__detail-divider')).toBeNull();
    expect(screen.queryByRole('heading', { name: /Сводка/ })).toBeNull();
    expect(await screen.findByText('Результаты неполны.')).toBeTruthy();
    const coverage = await screen.findByRole('list', { name: 'Исходы проверок', hidden: true });
    await userEvent.setup().click(screen.getByText('Подробности · что удалось проверить'));
    await waitFor(() => expect(coverage.closest('details')?.open).toBe(true));
    expect(within(coverage).getByText(/Сканер недоступен/).closest('details')?.open).toBe(true);
  });
  it('keeps the native category filter keyboard-accessible and retains focus/selection across filtering', async () => {
    const user = userEvent.setup();
    page('/demo/scans/partial-demo', <ScanDetailPage demo />);
    await screen.findByText(/SECRET_DETECTED/);
    const select = screen.getByLabelText('Показать находки');
    select.focus();
    await user.selectOptions(select, 'vulnerability');
    expect(await screen.findByText(/Нет совпадений фильтра/)).toBeTruthy();
    expect(document.activeElement).toBe(select);
    expect((select as HTMLSelectElement).value).toBe('vulnerability');
    await user.keyboard('{Escape}');
    expect(document.activeElement).toBe(select);
    await user.selectOptions(select, 'all');
    expect(await screen.findByText(/SECRET_DETECTED/)).toBeTruthy();
    expect(document.activeElement).toBe(select);
    expect(screen.queryByRole('dialog')).toBeNull();
  });
  it('announces only stage and terminal transitions during fixture snapshot bursts without moving focus or scroll', async () => {
    const user = userEvent.setup();
    const view = page('/demo/scans/running-demo', <ScanDetailPage demo />);
    await screen.findByRole('group', { name: 'Ход сканирования running-demo' });
    const key = ['scan', 'fixture', 'running-demo'];
    const region = document.querySelector('.scan-a1-detail > [aria-live="polite"][aria-atomic="true"]') as HTMLElement;
    expect(region.textContent).toBe('');
    const select = screen.getByLabelText('Показать находки');
    await user.click(select);
    const pageScroll = window.scrollY;
    for (let i = 0; i < 100; i++) {
      act(() => view.client.setQueryData<ScanStatus>(key, (old) => ({ ...old!, percent: i })));
      expect(region.textContent).toBe('');
    }
    expect(document.activeElement).toBe(select);
    expect(window.scrollY).toBe(pageScroll);
    act(() => view.client.setQueryData<ScanStatus>(key, (old) => ({ ...old!, stage: 'report' })));
    await waitFor(() => expect(region.textContent).toBe('Этап скана: report'));
    act(() => view.client.setQueryData<ScanStatus>(key, (old) => ({ ...old!, percent: 99 })));
    expect(region.textContent).toBe('Этап скана: report');
    act(() => view.client.setQueryData<ScanStatus>(key, (old) => ({ ...old!, state: 'partial' })));
    const currentAnnouncement = () => document.querySelector('.scan-a1-detail > [aria-live="polite"][aria-atomic="true"]');
    await screen.findByText('Результаты неполны.');
    expect(currentAnnouncement()).not.toBeNull();
    await waitFor(() => expect(currentAnnouncement()?.textContent).toBe('Итог скана: Частичный результат'));
    act(() => view.client.setQueryData<ScanStatus>(key, (old) => ({ ...old!, percent: null })));
    expect(currentAnnouncement()?.textContent).toBe('Итог скана: Частичный результат');
    expect(document.activeElement).toBe(select);
    expect(window.scrollY).toBe(pageScroll);
    expect(fixtureScanTransport.capabilities.events).toBe(false);
  });
  it('does not announce initial snapshot or reuse a prior scan announcement after scanId changes', () => {
    const initial: ScanStatus = { scanId: 'fixture-a', state: 'running', stage: 'secret', percent: 1 };
    const view = render(<ScanStatusAnnouncement scan={initial} />);
    const region = screen.getByText('', { selector: '[aria-live="polite"]' });
    expect(region.textContent).toBe('');
    view.rerender(<ScanStatusAnnouncement scan={{ ...initial, stage: 'report' }} />);
    expect(region.textContent).toBe('Этап скана: report');
    view.rerender(<ScanStatusAnnouncement scan={{ scanId: 'fixture-b', state: 'partial', percent: null }} />);
    expect(region.textContent).toBe('');
    view.rerender(<ScanStatusAnnouncement scan={{ scanId: 'fixture-b', state: 'partial', percent: 10 }} />);
    expect(region.textContent).toBe('');
  });
  it('keeps the A1 list-to-create path visible and distinguishes the separate report fixture', async () => {
    const user = userEvent.setup();
    page('/demo/scans', <ScanListPage demo />);
    expect(await screen.findByText(/library\/alpine:latest \(демо\)/)).toBeTruthy();
    expect(
      screen
        .getAllByRole('link', { name: /Новая проверка/ })
        .at(-1)
        ?.getAttribute('href'),
    ).toBe('/demo/scans/new');
    cleanup();
    page('/demo/scans/new', <ScanCreatePage demo />);
    expect(screen.getByRole('searchbox', { name: 'Репозиторий Docker Hub' }).hasAttribute('disabled')).toBe(true);
    await user.click(screen.getByRole('button', { name: /Alpine 3.16/ }));
    await user.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    expect(screen.getByText(/Демо не отправляет запросы/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Запуск недоступен' }).hasAttribute('disabled')).toBe(true);
    expect(within(screen.getByRole('form', { name: 'Параметры скана' })).getByRole('link', { name: /Посмотреть пример отчёта/ }).getAttribute('href')).toBe(
      '/demo/scans/partial-demo',
    );
  });
  it('keeps scope and launch limits in a native disclosure without enabling demo launch', async () => {
    const user = userEvent.setup();
    page('/demo/scans/new', <ScanCreatePage demo />);
    expect(screen.getByText(/Приватные образы и другие реестры не принимаются/)).toBeTruthy();
    const toggle = screen.getByText('Подробности · ограничения проверки');
    const details = toggle.closest('details')!;
    expect(details.open).toBe(false);
    expect(toggle.tagName).toBe('SUMMARY');
    await user.click(toggle);
    expect(details.open).toBe(true);
    expect(details.textContent).toContain('Ограничены размер образа и отдельных файлов');
    expect(details.textContent).toContain('Найденная в каталоге версия может не пройти эти ограничения');
    await user.click(toggle);
    expect(details.open).toBe(false);
    expect(screen.getByRole('checkbox', { name: /Уязвимости ·/ })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Запуск недоступен' }).hasAttribute('disabled')).toBe(true);
  });
  it('collapses scan metadata without hiding failed checks', async () => {
    const user = userEvent.setup();
    page('/demo/scans/partial-demo', <ScanDetailPage demo />);
    await screen.findByText('Результаты неполны.');
    const coverage = await screen.findByRole('list', { name: 'Исходы проверок', hidden: true });
    await user.click(screen.getByText('Подробности · что удалось проверить'));
    await waitFor(() => expect(coverage.closest('details')?.open).toBe(true));
    const failure = within(coverage).getByText(/Сканер недоступен/);
    expect(failure.closest('details')?.open).toBe(true);
    const trigger = screen.getByText('Подробности · точный образ и данные сканирования');
    const details = trigger.closest('details');
    expect(details?.open).toBe(false);
    await user.click(trigger);
    expect(details?.open).toBe(true);
    expect(details?.textContent).toContain('partial-demo');
  });
  it('associates canonical input and checks validation with their rendered errors and clears stale ARIA', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    page('/demo/scans/new', <ScanCreatePage demo />);
    fireEvent.click(screen.getByText('Указать адрес вручную'));
    const input = screen.getByRole('textbox', { name: 'Адрес образа в Docker Hub' });
    const checks = screen.getByRole('group', { name: '3. Что проверить в образе' });
    const form = screen.getByRole('form', { name: 'Параметры скана' });
    expect(input.getAttribute('aria-invalid')).toBe('false');
    expect(input.getAttribute('aria-describedby')).toBe('image-reference-help image-reference-error');
    expect(checks.getAttribute('aria-invalid')).toBe('false');
    fireEvent.change(input, { target: { value: 'https://docker.io/alpine:latest' } });
    fireEvent.click(screen.getByRole('checkbox', { name: /Возможные секреты ·/ }));
    fireEvent.submit(form);
    await waitFor(() => expect(screen.getAllByRole('alert')).toHaveLength(2));
    for (const field of [input, checks]) {
      expect(field.getAttribute('aria-invalid')).toBe('true');
      const errorId = field === input ? 'image-reference-error' : 'scan-checks-error';
      expect(field.getAttribute('aria-describedby')?.split(' ')).toContain(errorId);
      if (field === checks) expect(field.getAttribute('aria-errormessage')).toBe(errorId);
      const error = document.getElementById(errorId);
      expect(error?.getAttribute('role')).toBe('alert');
      expect(error?.textContent?.length).toBeGreaterThan(0);
    }
    expect(document.getElementById(checks.getAttribute('aria-describedby')!)?.textContent).toBe('Выберите хотя бы одну проверку');
    expect(screen.getByRole('group', { name: 'Выбор репозитория' }).hasAttribute('aria-describedby')).toBe(false);
    expect(screen.getByRole('searchbox').getAttribute('aria-invalid')).toBe('false');
    fireEvent.change(input, { target: { value: 'registry-1.docker.io/library/alpine:3.21' } });
    fireEvent.click(screen.getByRole('checkbox', { name: /Возможные секреты ·/ }));
    fireEvent.submit(form);
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
    for (const field of [input, checks]) {
      expect(field.getAttribute('aria-invalid')).toBe('false');
      expect(field.getAttribute('aria-describedby')).toBe(field === input ? 'image-reference-help image-reference-error' : null);
      expect(field.hasAttribute('aria-errormessage')).toBe(false);
    }
    expect(document.getElementById('image-reference-error')?.textContent).toBe('');
    expect(document.getElementById('image-reference-error')?.hasAttribute('role')).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });
  it('confirms live cancellation, waits for authoritative GET and never publishes intermediate results', async () => {
    const id = '00000000-0000-4000-8000-000000000001';
    const user = userEvent.setup();
    let resolveCancel!: (value: unknown) => void;
    const pendingCancel = new Promise<unknown>((resolve) => { resolveCancel = resolve; });
    let statusReads = 0;
    let resolveSnapshot!: (value: Response) => void;
    const pendingSnapshot = new Promise<Response>(resolve => { resolveSnapshot = resolve; });
    const snapshot = (state: string) => new Response(JSON.stringify({ scanId: id, state, checks: ['secret'], perCheck: { secret: null }, result: null }));
    const fetchMock = vi.fn((path: string, init?: RequestInit) => {
      if (path === `/api/v1/browser/scans/${id}/cancel`) {
        expect(init?.method).toBe('POST');
        return pendingCancel;
      }
      if (path !== `/api/v1/browser/scans/${id}`) throw new Error(`Unexpected request: ${path}`);
      statusReads++;
      return statusReads === 1 ? Promise.resolve(snapshot('running')) : pendingSnapshot;
    });
    vi.stubGlobal('fetch', fetchMock);

    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <LiveScanContext.Provider value={{ transport: createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => 'alice' }), scope: ['live-scans', 1, 'alice'] }}>
          <MemoryRouter initialEntries={[`/scans/${id}`]}><Routes><Route path="/scans/:scanId" element={<ScanDetailPage />} /></Routes></MemoryRouter>
        </LiveScanContext.Provider>
      </QueryClientProvider>,
    );
    expect(await screen.findByText('Статус')).toBeTruthy();
    expect(statusReads).toBe(1);
    expect(fetchMock.mock.calls.some(([path]) => path.includes('/results'))).toBe(false);
    const trigger = screen.getByRole('button', { name: 'Отменить скан' });
    await user.click(trigger);
    const dialog = screen.getByRole('alertdialog', { name: 'Отменить скан?' });
    const dismiss = within(dialog).getByRole('button', { name: 'Продолжить сканирование' });
    const accept = within(dialog).getByRole('button', { name: 'Подтвердить отмену' });
    expect(dialog.getAttribute('aria-describedby')).toBeTruthy();
    expect(document.getElementById(dialog.getAttribute('aria-describedby')!)?.textContent).toContain('Сохранённые результаты завершённых проверок останутся доступны');
    expect(document.activeElement).toBe(dismiss);
    await user.tab({ shift: true });
    expect(document.activeElement).toBe(accept);
    await user.tab();
    expect(document.activeElement).toBe(dismiss);
    expect(fetchMock.mock.calls.some(([path]) => path.endsWith('/cancel'))).toBe(false);
    await user.click(dismiss);
    await waitFor(() => expect(document.activeElement).toBe(trigger));
    expect(screen.queryByRole('alertdialog')).toBeNull();
    expect(fetchMock.mock.calls.some(([path]) => path.endsWith('/cancel'))).toBe(false);
    await user.click(trigger);
    await user.keyboard('{Escape}');
    await waitFor(() => expect(document.activeElement).toBe(trigger));
    expect(screen.queryByRole('alertdialog')).toBeNull();
    expect(fetchMock.mock.calls.some(([path]) => path.endsWith('/cancel'))).toBe(false);
    await user.click(trigger);
    await user.dblClick(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Подтвердить отмену' }));
    expect(screen.queryByRole('alertdialog')).toBeNull();
    const pending = screen.getByRole('button', { name: 'Отменяем…' });
    expect(pending.hasAttribute('disabled')).toBe(true);
    await user.click(pending);
    expect(fetchMock.mock.calls.filter(([path]) => path.endsWith('/cancel'))).toHaveLength(1);
    expect(screen.getByText('Статус').parentElement?.textContent).toContain('Выполняется');
    await act(async () => { resolveCancel({ ok: true, json: async () => ({ scanId: id, state: 'cancelled' }) }); });
    await waitFor(() => expect(statusReads).toBe(2));
    expect(screen.getByText('Статус').parentElement?.textContent).toContain('Выполняется');
    await act(async () => { resolveSnapshot(snapshot('cancelled')); });
    await waitFor(() => expect(screen.getByText('Статус').parentElement?.textContent).toContain('Отменён'));
    expect(screen.queryByRole('button', { name: 'Отменить скан' })).toBeNull();
    expect(screen.queryByText('Отмена недоступна в текущем состоянии.')).toBeNull();
    expect(fetchMock.mock.calls.some(([path]) => /\/(results|sbom|vuln)\?/.test(path))).toBe(false);
    expect(screen.queryByText(/0 находок|100%/)).toBeNull();
    expect(fetchMock.mock.calls.filter(([path]) => path.endsWith('/cancel'))).toHaveLength(1);

  });
  it.each(['cancelled', 'running'] as const)('batch4 regression: lost cancel response followed by authoritative GET %s never retries POST or keeps a false terminal error', async finalState => {
    const id = '00000000-0000-4000-8000-000000000077';
    const user = userEvent.setup();
    let reads = 0;
    let rejectCancel!: (error: Error) => void;
    let resolveStatus!: (value: Response) => void;
    const pendingCancel = new Promise<Response>((_resolve, reject) => { rejectCancel = reject; });
    const pendingStatus = new Promise<Response>(resolve => { resolveStatus = resolve; });
    const snapshot = (state: string) => new Response(JSON.stringify({ scanId: id, state, checks: ['secret'], perCheck: { secret: null }, result: null }), { headers: { 'Content-Type': 'application/json' } });
    const fetchMock = vi.fn((path: string, init?: RequestInit) => {
      if (path === `/api/v1/browser/scans/${id}/cancel`) {
        expect(init?.method).toBe('POST'); return pendingCancel;
      }
      if (path === `/api/v1/browser/scans/${id}`) return ++reads === 1 ? Promise.resolve(snapshot('running')) : pendingStatus;
      throw new Error(`Unexpected controlled cancel route: ${path}`);
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const scope = ['live-scans', 1, 'alice'] as const;
    render(<QueryClientProvider client={client}><LiveScanContext.Provider value={{ transport: createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => 'alice' }), scope }}><MemoryRouter initialEntries={[`/scans/${id}`]}><Routes><Route path="/scans/:scanId" element={<ScanDetailPage />} /></Routes></MemoryRouter></LiveScanContext.Provider></QueryClientProvider>);
    await user.click(await screen.findByRole('button', { name: 'Отменить скан' }));
    await user.click(within(screen.getByRole('alertdialog', { name: 'Отменить скан?' })).getByRole('button', { name: 'Подтвердить отмену' }));
    expect(fetchMock.mock.calls.filter(([path]) => path.endsWith('/cancel'))).toHaveLength(1);
    await act(async () => { rejectCancel(new TypeError('Controlled response lost after server dispatch')); });
    // A separate authoritative read, not optimistic success from the POST outcome.
    act(() => { void client.invalidateQueries({ queryKey: [...scope, 'scan', id] }); });
    await waitFor(() => expect(reads).toBeGreaterThanOrEqual(2));
    await act(async () => { resolveStatus(snapshot(finalState)); });
    await waitFor(() => expect(screen.getByText('Статус').parentElement?.textContent).toContain(finalState === 'cancelled' ? 'Отменён' : 'Выполняется'));
    if (finalState === 'cancelled') {
      expect(screen.queryByText(/Не удалось (?:отменить скан|подтвердить отмену):/)).toBeNull();
      expect(screen.queryByRole('button', { name: 'Проверить статус отмены' })).toBeNull();
      expect(screen.queryByRole('button', { name: 'Отменить скан' })).toBeNull();
      expect(screen.getByText(/Сохранённых результатов завершённых проверок нет/)).toBeTruthy();
    } else {
      expect(await screen.findByText('Не удалось подтвердить отмену: результат запроса неизвестен. Проверьте статус перед повторной отменой.')).toBeTruthy();
      expect(screen.getByRole('button', { name: 'Проверить статус отмены' }).hasAttribute('disabled')).toBe(false);
      expect(screen.getByRole('button', { name: 'Отменить скан' }).hasAttribute('disabled')).toBe(false);
    }
    fireEvent.focus(window); fireEvent.online(window);
    await act(async () => { await client.invalidateQueries({ queryKey: [...scope, 'scan', id] }); });
    expect(fetchMock.mock.calls.filter(([path]) => path.endsWith('/cancel'))).toHaveLength(1);
    expect(fetchMock.mock.calls.some(([path]) => /\/(?:results|sbom|vuln)(?:\?|$)/.test(path))).toBe(false);
    client.clear();
  });

  it.each([409, 404])('shows a safe message on live cancel HTTP %i without optimistic state', async (status) => {
    const user = userEvent.setup();

    const fetchMock = vi.fn((path: string) => Promise.resolve(path.endsWith('/cancel')
      ? { ok: false, status, json: async () => ({ secret: 'private' }) }
      : path.includes('/results')
        ? { ok: true, json: async () => ({ findings: [], nextCursor: null, coverage: { findingCount: 0, check: 'secret', coverage: 'image', outcome: 'unsupported', errorCode: null, scannerVersion: null } }) }
        : { ok: true, json: async () => ({ scanId: 'abc', state: 'running', result: null }) }));
    vi.stubGlobal('fetch', fetchMock);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><LiveScanContext.Provider value={{ transport: createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => 'alice' }), scope: ['live-scans', 1, 'alice'] }}><MemoryRouter initialEntries={['/scans/abc']}><Routes><Route path="/scans/:scanId" element={<ScanDetailPage />} /></Routes></MemoryRouter></LiveScanContext.Provider></QueryClientProvider>);
    await user.click(await screen.findByRole('button', { name: 'Отменить скан' }));
    await user.click(within(screen.getByRole('alertdialog', { name: 'Отменить скан?' })).getByRole('button', { name: 'Подтвердить отмену' }));
    expect((await screen.findByRole('alert')).textContent).toMatch(status === 409 ? /Сервер отклонил запрос отмены/ : /Не удалось подтвердить отмену/);
    expect(document.body.textContent).not.toContain('private');
    expect(screen.getByRole('button', { name: 'Отменить скан' }).hasAttribute('disabled')).toBe(false);

  });
  it('never sends network requests from demo create even when SBOM is selected and confirmed', () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    page('/demo/scans/new', <ScanCreatePage demo />);
    fireEvent.click(screen.getByRole('button', { name: /Alpine 3.16/ }));
    fireEvent.click(screen.getByRole('checkbox', { name: /Состав образа ·/ }));
    fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    expect(screen.getByRole('button', { name: 'Запуск недоступен' }).hasAttribute('disabled')).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });
  it('does not enable launch for fixture or unconfigured browser auth', () => {
    page('/demo/scans/new', <ScanCreatePage demo />);
    expect(screen.getByRole('button', { name: 'Запуск недоступен' }).hasAttribute('disabled')).toBe(true);
    expect(screen.getByRole('checkbox', { name: /Уязвимости ·/ })).toBeTruthy();
    expect(screen.getByRole('checkbox', { name: /Состав образа ·/ })).toBeTruthy();
    expect(screen.queryByRole('checkbox', { name: /Host|хост/i })).toBeNull();
    expect(screen.getByText(/Приватные образы и другие реестры не принимаются/)).toBeTruthy();
  });
});
