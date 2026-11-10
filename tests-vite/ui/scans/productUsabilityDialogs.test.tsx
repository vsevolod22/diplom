import '@testing-library/jest-dom/vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import { ScanInfoDialog } from '@/shared/ui/ScanInfoDialog';
import { ScanListPage } from '@/pages/scans/ScanListPage';
import { ScanCreatePage } from '@/pages/scans/ScanCreatePage';
import { ScanDetailPage } from '@/pages/scans/ScanDetailPage';

const clients: QueryClient[] = [];
afterEach(() => { cleanup(); clients.forEach(client => client.clear()); clients.length = 0; vi.restoreAllMocks(); });
function page(path: string, route: string, element: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  clients.push(client);
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}>
    <Routes><Route path={route} element={element} /></Routes>
  </MemoryRouter></QueryClientProvider>);
}

it('traps forward/backward focus, closes with Escape and returns focus without submitting its parent form', async () => {
  const submit = vi.fn();
  const user = userEvent.setup();
  render(<form onSubmit={event => { event.preventDefault(); submit(); }}>
    <ScanInfoDialog title="Ограничения проверки" description="Дополнительные сведения, без запуска.">
      <a href="#limits">Границы проверки</a>
    </ScanInfoDialog>
  </form>);
  const trigger = screen.getByRole('button', { name: 'Ограничения проверки' });
  await user.click(trigger);
  const dialog = screen.getByRole('dialog', { name: 'Ограничения проверки' });
  expect(dialog).toHaveAccessibleDescription('Дополнительные сведения, без запуска.');
  const close = within(dialog).getByRole('button', { name: 'Закрыть' });
  expect(close).toHaveFocus();
  await user.tab({ shift: true });
  expect(within(dialog).getByRole('link')).toHaveFocus();
  await user.tab();
  expect(close).toHaveFocus();
  await user.keyboard('{Escape}');
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(trigger).toHaveFocus();
  expect(submit).not.toHaveBeenCalled();
  await user.click(trigger);
  await user.click(screen.getByRole('button', { name: 'Закрыть' }));
  expect(trigger).toHaveFocus();
});

it('shows compact history with report links and one row status, without decorative scene or record indices', async () => {
  const { container } = page('/demo/scans', '/demo/scans', <ScanListPage demo />);
  expect(screen.getByRole('heading', { name: 'Мои проверки', level: 2 })).toBeVisible();
  const links = await screen.findAllByRole('link', { name: /^Открыть отчёт:/ });
  expect(links.length).toBeGreaterThan(0);
  expect(container.querySelector('.scan-shell--compact')).toBeInTheDocument();
  expect(container.querySelector('.scan-a1__scene, .scan-a1__index')).toBeNull();
  for (const link of links) expect(link.querySelectorAll('.scan-badge')).toHaveLength(1);
});

it('keeps launch blockers visible and test presets collapsed; the limits dialog never sends a request', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch');
  page('/demo/scans/new', '/demo/scans/new', <ScanCreatePage demo />);
  expect(screen.getByRole('heading', { name: 'Новая проверка', level: 2 })).toBeVisible();
  expect(screen.getByText('1. Образ')).toBeVisible();
  expect(screen.getByText('2. Что проверить')).toBeVisible();
  expect(screen.getByText('3. Подтверждение')).toBeVisible();
  expect(screen.getByText('Демо: запуск реальной проверки отключён.')).toBeVisible();
  const examples = screen.getByText('Тестовые образы').closest('details');
  expect(examples).not.toHaveAttribute('open');
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: 'Ограничения проверки' }));
  expect(screen.getByRole('dialog')).toHaveTextContent('число слоёв');
  expect(screen.getByRole('dialog')).toHaveTextContent('запрос может быть платным');
  await user.keyboard('{Escape}');
  expect(screen.getByRole('button', { name: 'Ограничения проверки' })).toHaveFocus();
  expect(fetcher).not.toHaveBeenCalled();
});

it('puts full scan identity in a dialog while partial results and coverage remain on the report', async () => {
  page('/demo/scans/partial-demo', '/demo/scans/:scanId', <ScanDetailPage demo />);
  const trigger = await screen.findByRole('button', { name: 'Данные проверки' });
  expect(screen.getAllByText(/частичн/i).some(element => element.closest('[role="dialog"]') === null)).toBe(true);
  fireEvent.click(trigger);
  const dialog = screen.getByRole('dialog', { name: 'Данные проверки' });
  expect(dialog).toHaveTextContent('partial-demo');
  expect(within(dialog).getByText('Указанная цель')).toBeVisible();
  fireEvent.click(within(dialog).getByRole('button', { name: 'Закрыть' }));
  expect(screen.getByRole('link', { name: 'Что проверено' })).toBeVisible();
});
