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
afterEach(cleanup);

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
    expect(screen.getByText(/Список недоступен: GET/)).toBeTruthy();
    expect(screen.queryByText(/Сканов нет \(/)).toBeNull();
  });
  it('labels every fixture and never claims 0 CVE or 100% for partial scan', async () => {
    page('/demo/scans/partial-demo', <ScanDetailPage demo />);
    expect(await screen.findByText(/База уязвимостей недоступна/)).toBeTruthy();
    expect(screen.getByText(/Выполнено \(не гарантия безопасности\)/)).toBeTruthy();
    expect(screen.getByText(/ДЕМО · вымышленные данные/)).toBeTruthy();
    expect(screen.getByText(/Прогресс: неизвестен/)).toBeTruthy();
    expect(screen.getByText(/ожидаем подтверждения digest\/platform/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Отмена недоступна' }).hasAttribute('disabled')).toBe(true);
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
  it('limits confirmed zero to the checked area and keeps the rest unsupported', async () => {
    page('/demo/scans/empty-demo', <ScanDetailPage demo />);
    expect(await screen.findByText(/0 находок в выполненной проверенной области/)).toBeTruthy();
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
    await user.type(screen.getByLabelText(/Образ в registry/), 'library/alpine:3.21');
    await user.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    expect(screen.getByText(/Цель подтверждена, но сервер недоступен/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Запуск недоступен' }).hasAttribute('disabled')).toBe(true);
    expect(screen.getByRole('link', { name: /отдельный образец отчёта/ }).getAttribute('href')).toBe(
      '/demo/scans/partial-demo',
    );
  });
  it('does not enable launch for fixture or unconfigured browser auth', () => {
    page('/demo/scans/new', <ScanCreatePage demo />);
    expect(screen.getByRole('button', { name: 'Запуск недоступен' }).hasAttribute('disabled')).toBe(true);
    expect(screen.getByText(/CVE и SBOM/)).toBeTruthy();
    expect(screen.getByText(/Container \/ host/)).toBeTruthy();
  });
});
