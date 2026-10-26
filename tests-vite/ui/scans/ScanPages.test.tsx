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
  function mountList(list: ScanTransport['list'], demo = false) {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity } } });
    const transport: ScanTransport = {
      ...fixtureScanTransport, kind: 'live', list, get: vi.fn(fixtureScanTransport.get),
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

  it('refreshes the list without per-row GETs, then stops polling and the estimate on completion without leaving the list', async () => {
    const intervals = vi.spyOn(window, 'setInterval');
    const clearInterval = vi.spyOn(window, 'clearInterval');
    let finish!: (rows: ScanSummary[]) => void;
    const pending = new Promise<ScanSummary[]>(resolve => { finish = resolve; });
    const list = vi.fn<ScanTransport['list']>()
      .mockResolvedValueOnce([scan('completed', 'saved'), scan('running')])
      .mockReturnValueOnce(pending);
    const { transport } = mountList(list);
    await advance(1);
    const link = screen.getByRole('link', { name: 'Открыть деталь: image/list-scan' });
    expect(link.querySelector('a, button, input, select, textarea, details, summary, [tabindex]')).toBeNull();
    link.focus();
    const progress = within(link).getByRole('progressbar');
    const initialEstimate = Number(progress.getAttribute('value'));
    expect(within(link).getByText(/^Оценка прогресса: ≈\d+%/)).toBeTruthy();
    const estimateIndex = intervals.mock.calls.findIndex(([, delay]) => delay === 1000);
    expect(estimateIndex).toBeGreaterThanOrEqual(0);
    const estimateTimer = intervals.mock.results[estimateIndex].value;
    await advance(1998);
    expect(list).toHaveBeenCalledTimes(1);
    await advance(2);
    expect(list).toHaveBeenCalledTimes(2);
    // A slow list response must not fan out status requests or overlap another list request.
    await advance(12_000);
    expect(list).toHaveBeenCalledTimes(2);
    expect(Number(progress.getAttribute('value'))).toBeGreaterThan(initialEstimate);
    await act(async () => {
      finish([scan('completed', 'saved'), scan('completed')]);
      await vi.advanceTimersByTimeAsync(1);
    });
    expect(screen.getByRole('link', { name: 'Открыть деталь: image/list-scan' })).toBe(link);
    expect(document.activeElement).toBe(link);
    expect(within(link).queryByRole('progressbar')).toBeNull();
    expect(within(link).getByText('Прогресс: 100% — завершение подтверждено сервером.')).toBeTruthy();
    expect(within(link).queryByText(/^Оценка прогресса:/)).toBeNull();
    expect(clearInterval).toHaveBeenCalledWith(estimateTimer);
    const finalText = link.textContent;
    await advance(60_000);
    expect(list).toHaveBeenCalledTimes(2);
    expect(link.textContent).toBe(finalText);
    expect(transport.get).not.toHaveBeenCalled();
  });

  it.each(['queued', 'cancelling'] as const)('polls when a %s item follows a terminal item and stops on an empty list', async state => {
    const list = vi.fn<ScanTransport['list']>()
      .mockResolvedValueOnce([scan('completed', 'saved'), scan(state)])
      .mockResolvedValue([]);
    const { transport } = mountList(list);
    await advance(1);
    expect(screen.getByRole('group', { name: 'Ход сканирования list-scan' })).toBeTruthy();
    await advance(2001);
    expect(screen.getByText('Сканов нет (успешный ответ списка).')).toBeTruthy();
    await advance(60_000);
    expect(list).toHaveBeenCalledTimes(2);
    expect(transport.get).not.toHaveBeenCalled();
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
    const list = vi.fn<ScanTransport['list']>()
      .mockResolvedValueOnce([scan('running')])
      .mockRejectedValue(new ScanAccessError(status));
    const { transport } = mountList(list);
    await advance(1);
    expect(screen.getByRole('progressbar')).toBeTruthy();
    await advance(2001);
    expect(screen.getByRole('alert').textContent).toMatch(status === 401 ? /Сессия больше не действует/ : /не выдано разрешение/);
    expect(screen.queryByRole('progressbar')).toBeNull();
    await advance(60_000);
    expect(list).toHaveBeenCalledTimes(2);
    expect(transport.get).not.toHaveBeenCalled();
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
    const fixtures = vi.spyOn(fixtureScanTransport, 'list');
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
    expect(await screen.findByText(/База уязвимостей недоступна/)).toBeTruthy();
    expect(screen.getByText('Выполнено')).toBeTruthy();
    expect(screen.getAllByText(/«Выполнено» означает завершение проверки/)).toHaveLength(1);
    expect(screen.queryByText(/Выполнено \(не гарантия безопасности\)/)).toBeNull();
    expect(screen.getByText(/ДЕМО · вымышленные данные/)).toBeTruthy();
    const progress = screen.getByRole('group', { name: 'Ход сканирования partial-demo' });
    expect(within(progress).getByText(/Отсутствующие итоги не считаются успешными проверками/)).toBeTruthy();
    expect(screen.getByText(/ожидаем подтверждения digest\/platform/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Отменить скан' })).toBeNull();
    expect(screen.getByText('Демо не отправляет серверную отмену.')).toBeTruthy();
    expect(screen.queryByText(/0 CVE/)).toBeNull();
    expect(screen.queryByText(/100%/)).toBeNull();
    expect(document.body.textContent).not.toContain('secretValue');
  });
  it('distinguishes filtered-zero from fully checked empty and unsupported coverage', async () => {
    const view = page('/demo/scans/partial-demo', <ScanDetailPage demo />);
    await screen.findByText(/SECRET_DETECTED/);
    fireEvent.change(screen.getByLabelText('Категория'), { target: { value: 'vulnerability' } });
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
    page('/demo/scans/empty-demo', <ScanDetailPage demo />);
    expect(await screen.findByText('Итог Secrets неизвестен')).toBeTruthy();
    expect(screen.getByText(/это не подтверждает нулевой итог/)).toBeTruthy();
    expect(screen.queryByText(/0 находок в выполненной проверенной области/)).toBeNull();
    expect(screen.getByText(/Не запускалась/)).toBeTruthy();
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
    const records = within(list).getAllByRole('listitem');
    expect(records.length).toBeGreaterThan(1);
    for (const record of records) {
      expect(record.querySelector('.scan-a1__magic')).not.toBeNull();
      const link = within(record).getByRole('link', { name: /Открыть деталь:/ });
      expect(link.tagName).toBe('A');
      expect(link.getAttribute('href')).toMatch(/^\/demo\/scans\//);
      expect(link.getAttribute('aria-label')).toContain(within(record).getByRole('heading').textContent);
      expect(link.classList.contains('scan-a1__record-content')).toBe(true);
      expect(within(link).getByRole('heading')).toBeTruthy();
      expect(within(link).getByRole('group', { name: /Ход сканирования/ })).toBeTruthy();
      expect(within(record).getAllByRole('link')).toHaveLength(1);
      expect(link.querySelector('a, button, input, select, textarea, details, summary, [tabindex]')).toBeNull();
      expect(within(link).getByText(/^Этап сканирования:/)).toBeTruthy();
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
    const link = await screen.findByRole('link', { name: 'Открыть деталь: library/alpine:latest (демо)' });
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
    const link = await screen.findByRole('link', { name: 'Открыть деталь: library/alpine:latest (демо)' });
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
        expect(screen.getByRole('link', { name: 'Открыть деталь: library/alpine:latest (демо)' })).toBe(link);
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
    const coverage = await screen.findByRole('list', { name: 'Исходы проверок' });
    const tiles = within(coverage).getAllByRole('listitem');
    expect(tiles).toHaveLength(outcomes.length);
    for (const [index, [status, label]] of outcomes.entries()) {
      const tile = tiles[index];
      expect(tile.getAttribute('data-outcome')).toBe(status);
      expect(within(tile).getByText(label)).toBeTruthy();
      expect(within(tile).getByText(`Причина ${status}`).closest('details')).toBeNull();
      expect(tile.querySelector('.scan-a1__coverage-status svg')?.getAttribute('aria-hidden')).toBe('true');
      expect(tile.querySelector('.scan-badge')).toBeNull();
    }
    const metadata = tiles[0].querySelector('details');
    expect(metadata?.open).toBe(false);
    expect(metadata?.textContent).toContain('checks checks-test · policy policy-test');
    expect(metadata?.textContent).toContain('scanner scanner-test · DB db-test');
    expect(tiles[1].querySelector('details')).toBeNull();
    await user.click(within(tiles[0]).getByText('Технические данные · checked'));
    expect(metadata?.open).toBe(true);
    await user.click(within(tiles[0]).getByText('Технические данные · checked'));
    expect(metadata?.open).toBe(false);
    const panel = coverage.closest('section');
    expect(panel?.querySelectorAll('.scan-a1__coverage-note')).toHaveLength(1);
    expect(panel?.querySelector('.scan-a1__coverage-note')?.textContent).toContain('не гарантию безопасности');
  });
  it('keeps unavailable coverage unknown instead of inferring completed checks', async () => {
    vi.spyOn(fixtureScanTransport, 'results').mockRejectedValue(new Error('Report unavailable'));
    const { client } = page('/demo/scans/partial-demo', <ScanDetailPage demo />);
    await waitFor(() => expect(client.getQueryState(['scan-results', 'fixture', 'partial-demo'])?.status).toBe('error'));
    expect(screen.getByText(/Нет подтверждённого coverage; тип проверки и результат неизвестны/)).toBeTruthy();
    expect(screen.queryByRole('list', { name: 'Исходы проверок' })).toBeNull();
    expect(document.querySelector('[data-outcome="checked"]')).toBeNull();
  });
  it('uses a separate non-factual MagicCard on the detail and keeps coverage outside it', async () => {
    page('/demo/scans/partial-demo', <ScanDetailPage demo />);
    expect(await screen.findByText(/Порядок чтения/)).toBeTruthy();
    const card = document.querySelector('.scan-a1__reading-card');
    expect(card?.textContent).toContain('не показывает ход проверки');
    expect(card?.textContent).not.toContain('База уязвимостей');
    expect((await screen.findByText(/База уязвимостей недоступна/)).closest('.scan-a1__magic')).toBeNull();
  });
  it('holds focus in the mobile filter Sheet, preserves selection and restores the trigger on Escape', async () => {
    const user = userEvent.setup();
    page('/demo/scans/partial-demo', <ScanDetailPage demo />);
    await screen.findByText(/SECRET_DETECTED/);
    const trigger = screen.getByRole('button', { name: 'Фильтры' });
    trigger.focus();
    await user.keyboard('{Enter}');
    const dialog = screen.getByRole('dialog', { name: 'Фильтры находок' });
    const select = within(dialog).getByLabelText('Категория');
    await waitFor(() => expect(document.activeElement).toBe(select));
    await user.selectOptions(select, 'vulnerability');
    expect(await screen.findByText(/Нет совпадений фильтра/)).toBeTruthy();
    await user.keyboard('{Tab}');
    expect(document.activeElement).toBe(within(dialog).getByRole('button', { name: 'Сбросить фильтр' }));
    await user.keyboard('{Shift>}{Tab}{/Shift}');
    expect(document.activeElement).toBe(select);
    await user.keyboard('{Escape}');
    await waitFor(() => expect(document.activeElement).toBe(trigger));
    await user.click(trigger);
    expect((within(screen.getByRole('dialog')).getByLabelText('Категория') as HTMLSelectElement).value).toBe(
      'vulnerability',
    );
  });
  it('announces only stage and terminal transitions during fixture snapshot bursts without moving focus or scroll', async () => {
    const user = userEvent.setup();
    const view = page('/demo/scans/running-demo', <ScanDetailPage demo />);
    await screen.findByText(/Этап: secret/);
    const key = ['scan', 'fixture', 'running-demo'];
    const region = document.querySelector('[aria-live="polite"][aria-atomic="true"]') as HTMLElement;
    expect(region.textContent).toBe('');
    const trigger = screen.getByRole('button', { name: 'Фильтры' });
    await user.click(trigger);
    const select = within(screen.getByRole('dialog')).getByLabelText('Категория');
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
    await waitFor(() => expect(region.textContent).toBe('Итог скана: Частичный результат'));
    act(() => view.client.setQueryData<ScanStatus>(key, (old) => ({ ...old!, percent: null })));
    expect(region.textContent).toBe('Итог скана: Частичный результат');
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
        .getAllByRole('link', { name: /Новый скан/ })
        .at(-1)
        ?.getAttribute('href'),
    ).toBe('/demo/scans/new');
    cleanup();
    page('/demo/scans/new', <ScanCreatePage demo />);
    await user.type(screen.getByRole('searchbox', { name: 'Поиск по доступным образам' }), '3.21');
    await user.click(screen.getByRole('button', { name: /Alpine · 3.21/ }));
    await user.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    expect(screen.getByText(/Демо не отправляет запросы/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Запуск недоступен' }).hasAttribute('disabled')).toBe(true);
    expect(screen.getByRole('link', { name: /отдельный образец отчёта/ }).getAttribute('href')).toBe(
      '/demo/scans/partial-demo',
    );
  });
  it('renders 21st.dev guide tabs on create without hiding scope or enabling launch', async () => {
    const user = userEvent.setup();
    page('/demo/scans/new', <ScanCreatePage demo />);
    const tabs = screen.getByRole('tablist', { name: 'Памятка о подготовке скана' });
    const target = within(tabs).getByRole('tab', { name: '01 / Цель' });
    target.focus();
    expect(target.getAttribute('aria-selected')).toBe('true');
    expect(screen.getByRole('tabpanel').textContent).toContain('Tag сам по себе');
    await user.keyboard('{ArrowRight}');
    expect(within(tabs).getByRole('tab', { name: '02 / Границы' }).getAttribute('aria-selected')).toBe(
      'true',
    );
    expect(screen.getByRole('tabpanel').textContent).toContain('авторизованный GET status');
    expect(screen.getByRole('checkbox', { name: /CVE · доступно/ })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Запуск недоступен' }).hasAttribute('disabled')).toBe(true);
  });
  it('renders 21st.dev report accordion after always-visible failed coverage', async () => {
    const user = userEvent.setup();
    page('/demo/scans/partial-demo', <ScanDetailPage demo />);
    await screen.findByText(/База уязвимостей недоступна/);
    expect(
      screen.getByText(/База уязвимостей недоступна/).closest('[data-slot="accordion-content"]'),
    ).toBeNull();
    const trigger = screen.getByRole('button', { name: 'Что означает неполный отчёт?' });
    trigger.focus();
    await user.keyboard('{Enter}');
    expect(trigger.getAttribute('aria-expanded')).toBe('true');
    expect(screen.getByText(/Сбой проверки не означает/)).toBeTruthy();
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
    const fetchMock = vi.fn((path: string) => {
      if (path === `/api/v1/browser/scans/${id}/cancel`) return pendingCancel;
      if (path !== `/api/v1/browser/scans/${id}`) throw new Error(`Unexpected request: ${path}`);
      statusReads++;
      return statusReads === 1 ? Promise.resolve(snapshot('running')) : pendingSnapshot;
    });
    vi.stubGlobal('fetch', fetchMock);
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
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
    await user.click(screen.getByRole('button', { name: 'Отменить скан' }));
    expect(fetchMock.mock.calls.some(([path]) => path.endsWith('/cancel'))).toBe(false);
    confirm.mockReturnValue(true);
    await user.click(screen.getByRole('button', { name: 'Отменить скан' }));
    expect(screen.getByRole('button', { name: 'Отменяем…' }).hasAttribute('disabled')).toBe(true);
    expect(screen.getByText('Статус').parentElement?.textContent).toContain('Выполняется');
    await act(async () => { resolveCancel({ ok: true, json: async () => ({ scanId: id, state: 'cancelled' }) }); });
    await waitFor(() => expect(statusReads).toBe(2));
    expect(screen.getByText('Статус').parentElement?.textContent).toContain('Выполняется');
    await act(async () => { resolveSnapshot(snapshot('cancelled')); });
    await waitFor(() => expect(screen.getByText('Статус').parentElement?.textContent).toContain('Отменён'));
    expect(screen.queryByRole('button', { name: 'Отменить скан' })).toBeNull();
    expect(screen.getByText('Отмена недоступна в текущем состоянии.')).toBeTruthy();
    expect(fetchMock.mock.calls.some(([path]) => /\/(results|sbom|vuln)\?/.test(path))).toBe(false);
    expect(screen.queryByText(/0 находок|100%/)).toBeNull();
    expect(fetchMock.mock.calls.filter(([path]) => path.endsWith('/cancel'))).toHaveLength(1);
    confirm.mockRestore();
  });
  it.each([409, 404])('shows a safe message on live cancel HTTP %i without optimistic state', async (status) => {
    const user = userEvent.setup();
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    const fetchMock = vi.fn((path: string) => Promise.resolve(path.endsWith('/cancel')
      ? { ok: false, status, json: async () => ({ secret: 'private' }) }
      : path.includes('/results')
        ? { ok: true, json: async () => ({ findings: [], nextCursor: null, coverage: { findingCount: 0, check: 'secret', coverage: 'image', outcome: 'unsupported', errorCode: null, scannerVersion: null } }) }
        : { ok: true, json: async () => ({ scanId: 'abc', state: 'running', result: null }) }));
    vi.stubGlobal('fetch', fetchMock);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><LiveScanContext.Provider value={{ transport: createAuthorizedScanTransport({ subject: 'alice', currentSubject: () => 'alice' }), scope: ['live-scans', 1, 'alice'] }}><MemoryRouter initialEntries={['/scans/abc']}><Routes><Route path="/scans/:scanId" element={<ScanDetailPage />} /></Routes></MemoryRouter></LiveScanContext.Provider></QueryClientProvider>);
    await user.click(await screen.findByRole('button', { name: 'Отменить скан' }));
    expect((await screen.findByRole('alert')).textContent).toMatch(/отмена невозможна/i);
    expect(document.body.textContent).not.toContain('private');
    expect(screen.getByRole('button', { name: 'Отменить скан' }).hasAttribute('disabled')).toBe(false);

  });
  it('never sends network requests from demo create even when SBOM is selected and confirmed', () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    page('/demo/scans/new', <ScanCreatePage demo />);
    fireEvent.click(screen.getByRole('button', { name: /Alpine · 3.21/ }));
    fireEvent.click(screen.getByRole('checkbox', { name: /SBOM · перечень пакетов/ }));
    fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    expect(screen.getByRole('button', { name: 'Запуск недоступен' }).hasAttribute('disabled')).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });
  it('does not enable launch for fixture or unconfigured browser auth', () => {
    page('/demo/scans/new', <ScanCreatePage demo />);
    expect(screen.getByRole('button', { name: 'Запуск недоступен' }).hasAttribute('disabled')).toBe(true);
    expect(screen.getByRole('checkbox', { name: /CVE · доступно/ })).toBeTruthy();
    expect(screen.getByRole('checkbox', { name: /SBOM · перечень пакетов/ })).toBeTruthy();
    expect(screen.getByRole('checkbox', { name: /Host · отдельный opt-in не подключён/ }).hasAttribute('disabled')).toBe(true);
  });
});
