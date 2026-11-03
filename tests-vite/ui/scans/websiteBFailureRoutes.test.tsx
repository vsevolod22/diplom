import '@testing-library/jest-dom/vitest';
import { lazy, Suspense } from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Link, useLocation } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import { SiteLayout } from '../../../src/widgets/layout/SiteLayout';
import { RouteErrorBoundary } from '@/app/routes/RouteErrorBoundary';
import { ScanRoutes } from '@/app/routes/ScanRoutes';
import { parseImageFailureDetail, presentImageFailure } from '@/shared/api/scans/imageFailure';
import { scanResponseError, ScanAccessError, ScanHttpError } from '@/shared/api/scans/httpScanTransport';

const reasons = ['IMAGE_NOT_ACCESSIBLE','PLATFORM_UNSUPPORTED','FORMAT_UNSUPPORTED','IMAGE_INVALID','INTEGRITY_FAILED','ARCHIVE_UNSAFE','REGISTRY_RATE_LIMITED','REGISTRY_UNAVAILABLE','DEADLINE_EXCEEDED','SCANNER_FAILED'];
const resources = ['layers','layer_bytes','download_bytes','expanded_bytes','file_bytes','entries','scratch_bytes','requests','output_bytes'];
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
it.each(reasons)('B1/B4 fixed Russian failure copy: %s', reason => {
  const detail = parseImageFailureDetail({ reason, stage: 'inspection' });
  expect(Object.isFrozen(detail)).toBe(true);
  const copy = presentImageFailure(detail);
  for (const value of Object.values(copy)) expect(value).toMatch(/[А-Яа-яЁё]/);
  expect(copy.nextStep.length).toBeGreaterThan(15);
});
it.each(resources)('B1/B4 optional resource provides distinct safe copy when present: %s', resource => {
  const parsed = parseImageFailureDetail({ reason: 'RESOURCE_LIMIT', stage: 'archive', resource });
  expect(presentImageFailure(parsed).description).not.toContain(resource);
});
it('B1/B4 RESOURCE_LIMIT without resource is valid and uses generic truthful copy', () => {
  const detail = parseImageFailureDetail({ reason: 'RESOURCE_LIMIT', stage: 'inspection' });
  expect(detail).toEqual({ reason: 'RESOURCE_LIMIT', stage: 'inspection' });
  expect(presentImageFailure(detail)).toMatchObject({
    title: 'Образ превысил ограничения проверки',
    description: 'Для обработки образа потребовалось больше ресурсов, чем разрешено сервисом.',
    stageLabel: 'Проверка образа',
  });
  expect(presentImageFailure(detail).nextStep).toContain('Выберите меньшую сборку');
});
it('B1/B4 rejects absent/null/unknown/extra/prototype/accessor and conditional-resource violations', () => {
  const invalid = [undefined, null, {}, { reason: 'READY', stage: 'scan' },
    { reason: 'SCANNER_FAILED', stage: 'upstream' }, { reason: 'RESOURCE_LIMIT', stage: 'archive', resource: null },
    { reason: 'SCANNER_FAILED', stage: 'scan', resource: 'layers' },
    { reason: 'RESOURCE_LIMIT', stage: 'scan', resource: 'cpu' },
    { reason: 'SCANNER_FAILED', stage: 'scan', message: 'PRIVATE_UPSTREAM_MARKER' },
    Object.assign(Object.create({ hidden: true }), { reason: 'SCANNER_FAILED', stage: 'scan' })];
  const getter = vi.fn(() => 'scan');
  const accessor = Object.defineProperty({ reason: 'SCANNER_FAILED' }, 'stage', { get: getter, enumerable: true });
  for (const value of [...invalid, accessor]) expect(() => parseImageFailureDetail(value)).toThrow();
  expect(getter).not.toHaveBeenCalled();
});
it('B1/B4 rejects malformed optional evidence without dropping 429 cooldown or echoing raw text', async () => {
  const error = await scanResponseError(new Response(JSON.stringify({ errorCode: 'IMAGE_SEARCH_RATE_LIMITED', retryAfterSeconds: 7,
    limitReason: 'rate', message: 'PRIVATE_UPSTREAM_MARKER', failureDetail: { reason: 'READY', stage: 'scan' } }), { status: 429, headers: { 'Retry-After': '7' } }));
  expect(error).toBeInstanceOf(ScanHttpError);
  expect(error).toMatchObject({ status: 429, retryAfterSeconds: 7, limitReason: 'rate', failureDetail: undefined });
  expect(error.message).not.toContain('PRIVATE_UPSTREAM_MARKER');
  for (const status of [401,403]) expect(await scanResponseError(new Response('PRIVATE_UPSTREAM_MARKER', { status }))).toBeInstanceOf(ScanAccessError);
});
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
