import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ScanListPage } from '@/pages/scans/ScanListPage';
import { ScanDetailPage } from '@/pages/scans/ScanDetailPage';
import { ScanCreatePage } from '@/pages/scans/ScanCreatePage';
import { ScanStatusAnnouncement } from '@/features/scans/ScanStatusAnnouncement';
import { fixtureScanTransport } from '@/shared/api/scans/fixtureScanTransport';
import { createAuthorizedScanTransport } from '@/shared/api/scans/httpScanTransport';
import { LiveScanContext } from '@/features/scans/liveScanContext';
import type { ScanStatus } from '@/shared/api/scans/scanTransport';

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
describe('scan UI fixture versus unavailable production', () => {
  it('does not confuse unavailable GET list with empty list', () => {
    page('/scans', <ScanListPage />);
    expect(screen.getByText(/Список недоступен без подтверждённой сессии/)).toBeTruthy();
    expect(screen.queryByText(/Сканов нет \(/)).toBeNull();
  });
  it('labels every fixture and never claims 0 CVE or 100% for partial scan', async () => {
    page('/demo/scans/partial-demo', <ScanDetailPage demo />);
    expect(await screen.findByText(/База уязвимостей недоступна/)).toBeTruthy();
    expect(screen.getByText(/Выполнено \(не гарантия безопасности\)/)).toBeTruthy();
    expect(screen.getByText(/ДЕМО · вымышленные данные/)).toBeTruthy();
    expect(screen.getByText(/Прогресс: неизвестен/)).toBeTruthy();
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
      expect(
        within(record)
          .getByRole('link', { name: /Открыть деталь/ })
          .getAttribute('href'),
      ).toMatch(/^\/demo\/scans\//);
      expect(record.textContent).toMatch(/Прогресс: (неизвестен|\d+%)/);
      expect(record.textContent).toContain('Вымышленные данные');
    }
    expect(list.querySelectorAll(':scope > li')).toHaveLength(records.length);
    expect(list.querySelector('[style*="opacity: 0"]')).toBeNull();
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
