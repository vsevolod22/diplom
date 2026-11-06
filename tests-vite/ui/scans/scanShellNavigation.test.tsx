import '@testing-library/jest-dom/vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ScanShell } from '@/features/scans/ScanShell';

beforeEach(() => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function mountShell(demo: boolean, path: string, compact = false) {
  const client = new QueryClient();
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <ScanShell demo={demo} compact={compact}><p>Page content</p></ScanShell>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return screen.getByRole('navigation', { name: 'Разделы сканирования' });
}

describe('ScanShell navigation destinations', () => {
  it.each([
    { path: '/demo/scans', current: 'Мои проверки' },
    { path: '/demo/scans/new', current: 'Новая проверка' },
  ])('keeps demo destinations unique and exactly one current link at $path', ({ path, current }) => {
    const nav = mountShell(true, path);
    const links = within(nav).getAllByRole('link');
    const destinations = links.map(link => link.getAttribute('href'));
    expect(new Set(destinations).size).toBe(links.length);
    expect(destinations).toEqual(['/demo/scans', '/demo/scans/new']);
    expect(within(nav).getByRole('link', { name: 'Мои проверки' })).toHaveAttribute('href', '/demo/scans');
    expect(within(nav).queryByRole('link', { name: 'Демо' })).not.toBeInTheDocument();
    expect(nav.querySelectorAll('[aria-current="page"]')).toHaveLength(1);
    expect(within(nav).getByRole('link', { name: current })).toHaveAttribute('aria-current', 'page');
  });

  it('renders demo navigation without duplicate-key console errors', () => {
    mountShell(true, '/demo/scans');
    expect(console.error).not.toHaveBeenCalled();
  });

  it.each([
    { path: '/scans', current: 'Мои проверки' },
    { path: '/demo/scans', current: 'Демо' },
    { path: '/scans/new', current: 'Новая проверка' },
  ])('preserves all three live entries and the current link at $path', ({ path, current }) => {
    const nav = mountShell(false, path);
    expect(within(nav).getAllByRole('link').map(link => link.getAttribute('href'))).toEqual([
      '/scans', '/demo/scans', '/scans/new',
    ]);
    expect(within(nav).getByRole('link', { name: 'Мои проверки' })).toHaveAttribute('href', '/scans');
    expect(within(nav).getByRole('link', { name: 'Демо' })).toHaveAttribute('href', '/demo/scans');
    expect(within(nav).getByRole('link', { name: 'Новая проверка' })).toHaveAttribute('href', '/scans/new');
    expect(nav.querySelectorAll('[aria-current="page"]')).toHaveLength(1);
    expect(within(nav).getByRole('link', { name: current })).toHaveAttribute('aria-current', 'page');
    expect(console.error).not.toHaveBeenCalled();
  });

  it.each([
    { demo: true, path: '/demo/scans', current: 'Мои проверки' },
    { demo: true, path: '/demo/scans/new', current: 'Новая проверка' },
    { demo: false, path: '/scans', current: 'Мои проверки' },
    { demo: false, path: '/scans/new', current: 'Новая проверка' },
  ])('preserves compact navigation at $path', ({ demo, path, current }) => {
    const nav = mountShell(demo, path, true);
    const prefix = demo ? '/demo' : '';
    expect(nav).toHaveClass('scan-shell__compact-nav');
    expect(within(nav).getAllByRole('link').map(link => link.getAttribute('href'))).toEqual([
      `${prefix}/scans`, `${prefix}/scans/new`,
    ]);
    expect(within(nav).getByRole('link', { name: 'Мои проверки' })).toHaveAttribute('href', `${prefix}/scans`);
    expect(within(nav).getByRole('link', { name: 'Новая проверка' })).toHaveAttribute('href', `${prefix}/scans/new`);
    expect(nav.querySelectorAll('[aria-current="page"]')).toHaveLength(1);
    expect(within(nav).getByRole('link', { name: current })).toHaveAttribute('aria-current', 'page');
    expect(console.error).not.toHaveBeenCalled();
  });
});
