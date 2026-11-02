import '@testing-library/jest-dom/vitest';
import { lazy, Suspense } from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Link, useLocation } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import { SiteLayout } from '../../../src/widgets/layout/SiteLayout';
import { RouteErrorBoundary } from '@/app/routes/RouteErrorBoundary';
import { ScanRoutes } from '@/app/routes/ScanRoutes';

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
it('B4 unknown public route renders real404 without fetching private scan history', async () => {
  const fetcher = vi.fn(() => { throw Error('unexpected API'); }); vi.stubGlobal('fetch', fetcher);
  render(<MemoryRouter initialEntries={['/does-not-exist']}><ScanRoutes /></MemoryRouter>);
  expect(await screen.findByRole('heading', { name: 'Здесь нет такой страницы' })).toBeVisible();
  expect(document.title).toContain('Страница не найдена'); expect(fetcher).not.toHaveBeenCalled();
});
it('B4 lazy chunk rejection is safe, recoverable and does not echo raw exception or auto-replay', async () => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
  const Broken = lazy(async () => { throw Error('PRIVATE_CHUNK_PATH_TOKEN'); });
  const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
  render(<MemoryRouter><RouteErrorBoundary><Suspense fallback={<p>Loading</p>}><Broken /></Suspense></RouteErrorBoundary></MemoryRouter>);
  expect(await screen.findByRole('heading', { name: 'Не удалось открыть страницу' })).toBeVisible();
  expect(screen.getByRole('link', { name: 'Проверить список' })).toHaveAttribute('href', '/scans');
  expect(screen.getByRole('button', { name: 'Обновить страницу' })).toBeVisible();
  expect(document.body.textContent).not.toContain('PRIVATE_CHUNK_PATH_TOKEN'); expect(fetcher).not.toHaveBeenCalled();
});
function Content({ tick }: { tick: number }) {
  const location = useLocation();
  return <main><h1>{location.pathname}</h1><input aria-label="draft" defaultValue="retained" /><Link to="/scans?filter=one">Filter</Link><Link to="/scans/new">New</Link><output>{tick}</output></main>;
}
it('B4 titles/route focus/skip update only on pathname, never polling or filter navigation', async () => {
  const view = render(<MemoryRouter initialEntries={['/scans']}><SiteLayout><Content tick={0} /></SiteLayout></MemoryRouter>);
  expect(document.title).toContain('Мои проверки');
  const input = screen.getByRole('textbox', { name: 'draft' }); input.focus();
  view.rerender(<MemoryRouter initialEntries={['/scans']}><SiteLayout><Content tick={1} /></SiteLayout></MemoryRouter>);
  expect(input).toHaveFocus(); expect(input).toHaveValue('retained');
  fireEvent.click(screen.getByRole('link', { name: 'Filter' })); expect(input).toHaveFocus();
  fireEvent.click(screen.getByRole('link', { name: 'New' }));
  expect(document.title).toContain('Новая проверка');
  expect(screen.getByRole('region', { name: 'Новая проверка' })).toHaveFocus();
  fireEvent.click(screen.getByRole('link', { name: 'Перейти к содержимому' }));
  await act(async () => {}); expect(screen.getByRole('heading', { name: '/scans/new' })).toHaveFocus();
  expect(screen.getByRole('contentinfo')).toHaveTextContent('не гарантирует безопасность');
});
