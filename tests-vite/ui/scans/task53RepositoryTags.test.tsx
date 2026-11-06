import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LiveScanSession } from '@/features/scans/LiveScanSession';
import { ScanCreatePage } from '@/pages/scans/ScanCreatePage';
import { normalizeDockerHubReference, OLDER_IMAGE_PRESETS, validDiscoveryQuery } from '@/pages/scans/imageSelection';
import { transitionScanSession } from '@/shared/api/auth/scanSession';

const clients: QueryClient[] = [];
const firstPreset = { label: 'Node 18.17.1 · сборка 2023 · только для тестов', reference: 'registry-1.docker.io/library/node@sha256:abe13b25e07ccaedcc8797120c37781f0462a0f0682105cf2d8b8d6f99070d55' };
const reply = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json' },
});
const policy = { pageSize: 12, maxPages: 5, maxCandidates: 60, maxActivePerProcess: 8,
  maxActivePerSubject: 2, maxRequestsPerSubject: 30, rateWindowMs: 60_000,
  maxSessions: 1024, maxRateEntries: 1024, scope: 'process-local' };
function page(kind: 'repository' | 'tag') {
  return { items: [{ label: kind === 'repository' ? 'acme/widget' : 'ReleaseCandidate',
    reference: `registry-1.docker.io/acme/widget:${kind === 'repository' ? 'latest' : 'ReleaseCandidate'}`,
    scannable: false, eligibility: 'public-hub-profile', reason: 'PUBLIC_HUB_REQUIRES_PREFLIGHT',
    kind, tagConfirmed: kind === 'tag', checks: { secret: false, sbom: false, vuln: 'unsupported' } }],
    nextCursor: null, state: 'terminal', loaded: 1, pages: 1, policy };
}
function installMock(discover: (url: URL) => Response | Promise<Response> = () => reply(page('repository')), eligible = false) {
  const requests: Array<{ url: string; method: string; body: Record<string, unknown> | null }> = [];
  vi.stubGlobal('fetch', vi.fn(async (input: string, init?: RequestInit) => {
    const method = (init?.method ?? 'GET').toUpperCase();
    const body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : null;
    requests.push({ url: input, method, body });
    if (input === '/api/v1/auth/me') return reply({ id: 'task53-owner', email: 'task53@example.test' });
    if (input.startsWith('/api/v1/browser/runtime/')) return reply({ errorCode: 'RUNTIME_UNAVAILABLE' }, 503);
    if (input === '/api/v1/browser/scans/images/eligibility') return reply({ imageReference: body?.imageReference,
      eligible, eligibility: eligible ? 'public-hub-profile' : 'unsupported', allowedCheckSets: eligible ? [['secret']] : [], reason: eligible ? 'READY' : 'UNSUPPORTED_SCAN' });
    if (input === '/api/v1/browser/scans' && method === 'POST') return reply({ errorCode: 'SCANNER_UNAVAILABLE' }, 503);
    if (method !== 'GET') throw new Error('Forbidden TASK53 provider/mutation request');
    if (input.startsWith('/api/v1/browser/scans/images?')) return discover(new URL(input, 'https://task53.invalid'));
    throw new Error(`Unexpected TASK53 request: ${input}`);
  }));
  return requests;
}
async function openRepository() {
  const search = await screen.findByRole('searchbox', { name: 'Репозиторий Docker Hub' });
  fireEvent.change(search, { target: { value: 'acme/widget' } });
  fireEvent.click(await screen.findByRole('button', { name: /acme\/widget/ }));
  return screen.findByRole('searchbox', { name: 'Фильтр тегов' });
}
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  clients.push(client);
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/scans/new']}>
    <LiveScanSession><ScanCreatePage /></LiveScanSession>
  </MemoryRouter></QueryClientProvider>);
  return { client, ...view };
}
beforeEach(() => {
  sessionStorage.clear();
  vi.stubGlobal('IntersectionObserver', class { observe() {} unobserve() {} disconnect() {} });
});
afterEach(() => {
  cleanup();
  for (const client of clients.splice(0)) client.clear();
  transitionScanSession(null, new QueryClient(), true);
  sessionStorage.clear();
  vi.restoreAllMocks(); vi.unstubAllGlobals();
});

describe('TASK53 repository discovery is not tag or admission authority', () => {
  it.each([
    ['nginx:ReleaseCandidate', 'registry-1.docker.io/library/nginx:ReleaseCandidate'],
    ['owner/image:Tag_V1', 'registry-1.docker.io/owner/image:Tag_V1'],
    ['docker.io/owner/image:Tag', 'registry-1.docker.io/owner/image:Tag'],
    ['ghcr.io/owner/image:Tag', null], ['localhost:5000/image:Tag', null],
    ['https://docker.io/library/nginx:Tag', null], ['owner/image', null],
  ])('normalizes syntax without inventing a tag: %s', (input, expected) => {
    expect(normalizeDockerHubReference(input)).toBe(expected);
  });

  it('bounds explicit repository filters without lowercasing or accepting foreign repositories', () => {
    for (const query of ['', 'Alpine_RC-1.2', 'A'.repeat(64)]) expect(validDiscoveryQuery(query, 'acme/widget')).toBe(true);
    for (const query of ['a b', 'a/b', 'A'.repeat(65), '?']) expect(validDiscoveryQuery(query, 'acme/widget')).toBe(false);
    expect(validDiscoveryQuery('', 'ghcr.io/acme/widget')).toBe(false);
    expect(OLDER_IMAGE_PRESETS).toHaveLength(7);
    expect(new Set(OLDER_IMAGE_PRESETS.map(item => item.reference))).toHaveLength(7);
    expect(OLDER_IMAGE_PRESETS[0]).toEqual(firstPreset);
    expect(OLDER_IMAGE_PRESETS.slice(1)).toEqual([
      { label: 'Alpine 3.16 · точная сборка', reference: 'registry-1.docker.io/library/alpine@sha256:0db9d004361b106932f8c7632ae54d56e92c18281e2dd203127d77405020abf6' },
      { label: 'nginx 1.24-alpine', reference: 'registry-1.docker.io/library/nginx:1.24-alpine' },
      { label: 'Node 18-alpine', reference: 'registry-1.docker.io/library/node:18-alpine' },
      { label: 'Python 3.10-alpine', reference: 'registry-1.docker.io/library/python:3.10-alpine' },
      { label: 'Redis 6.2-alpine', reference: 'registry-1.docker.io/library/redis:6.2-alpine' },
      { label: 'PostgreSQL 13-alpine', reference: 'registry-1.docker.io/library/postgres:13-alpine' },
    ]);
  });

  it('ends a stalled catalog read and rejects a late response without creating a scan', async () => {
    let finish!: (response: Response) => void;
    const requests = installMock(() => new Promise<Response>(resolve => { finish = resolve; }));
    mount();
    const search = await screen.findByRole('searchbox', { name: 'Репозиторий Docker Hub' });
    vi.useFakeTimers();
    try {
      fireEvent.change(search, { target: { value: 'acme/widget' } });
      await act(async () => vi.advanceTimersByTimeAsync(350));
      expect(finish).toBeTypeOf('function');
      expect(screen.getByRole('status', { name: 'Состояние поиска Docker Hub' }).textContent).toContain('Загружаем');
      await act(async () => vi.advanceTimersByTimeAsync(15_000));
      expect(screen.getByRole('status', { name: 'Состояние поиска Docker Hub' }).textContent).toContain('Каталог недоступен');
      expect(screen.getByRole('button', { name: 'Начать новый поиск' })).toBeTruthy();
      await act(async () => finish(reply(page('repository'))));
      expect(screen.queryByRole('button', { name: /acme\/widget/ })).toBeNull();
      expect(requests.some(request => request.method !== 'GET')).toBe(false);
    } finally { vi.useRealTimers(); }
  });

  it('normalizes manual blur and rejects foreign registry without launching or retaining consent', async () => {
    const requests = installMock(); mount();
    await screen.findByRole('searchbox');
    fireEvent.click(screen.getByText('Указать адрес вручную'));
    const input = screen.getByRole('textbox', { name: 'Адрес образа в Docker Hub' });
    const consent = screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель и область/ }) as HTMLInputElement;
    fireEvent.click(consent);
    fireEvent.change(input, { target: { value: 'owner/image:ReleaseCandidate' } }); fireEvent.blur(input);
    expect((input as HTMLInputElement).value).toBe('registry-1.docker.io/owner/image:ReleaseCandidate');
    expect(consent.checked).toBe(false);
    fireEvent.change(input, { target: { value: 'ghcr.io/owner/image:Tag' } });
    fireEvent.click(screen.getByRole('button', { name: 'Использовать адрес' }));
    expect(await screen.findByText(/Укажите публичный образ Docker Hub с тегом/)).toBeTruthy();
    expect(requests.filter(item => item.url === '/api/v1/browser/scans')).toHaveLength(0);
    expect(requests.some(item => String(item.body?.imageReference).startsWith('ghcr.io'))).toBe(false);
  });

  it('does not treat any of seven presets as eligible or auto-launch; changing checks resets consent', async () => {
    const requests = installMock(); mount(); await screen.findByRole('searchbox');
    const warning = screen.getByText(/устаревшая сборка Node.js сентября 2023 года/);
    expect(warning.textContent).toContain('только для тестирования, не для рабочих приложений');
    expect(warning.textContent).toContain('Число находок определяется проверкой');
    expect(requests.filter(item => item.method === 'POST')).toHaveLength(0);
    for (const preset of OLDER_IMAGE_PRESETS) {
      fireEvent.click(screen.getByRole('button', { name: new RegExp(preset.label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) }));
      await waitFor(() => expect(requests.some(item => item.body?.imageReference === preset.reference)).toBe(true));
      const consent = screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель и область/ }) as HTMLInputElement;
      expect(consent.checked).toBe(false); fireEvent.click(consent);
      expect((screen.getByRole('button', { name: 'Запустить проверку' }) as HTMLButtonElement).disabled).toBe(true);
    }
    fireEvent.click(screen.getByRole('checkbox', { name: /Состав образа/ }));
    expect((screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель и область/ }) as HTMLInputElement).checked).toBe(false);
    expect(requests.filter(item => item.url === '/api/v1/browser/scans')).toHaveLength(0);
  });

  it.each(['success', 'failure'] as const)('fences late %s after filter clear; back restores repository focus without cursor replay', async outcome => {
    let finish!: (response: Response) => void;
    const urls: URL[] = [];
    installMock(url => {
      urls.push(url);
      if (!url.searchParams.has('repository')) return reply(page('repository'));
      if (url.searchParams.get('q') === 'OLD') return new Promise<Response>(resolve => { finish = resolve; });
      return reply(page('tag'));
    }); mount();
    const filter = await openRepository();
    await screen.findByRole('button', { name: /ReleaseCandidate/ });
    expect(document.activeElement).toBe(filter);
    fireEvent.change(filter, { target: { value: 'OLD' } });
    await waitFor(() => expect(finish).toBeTypeOf('function'));
    fireEvent.change(filter, { target: { value: '' } });
    await screen.findByRole('button', { name: /ReleaseCandidate/ });
    await act(async () => finish(outcome === 'failure' ? reply({ errorCode: 'IMAGE_SEARCH_EXPIRED' }, 410) : reply({ ...page('tag'), items: [{ ...page('tag').items[0], label: 'OLD', reference: 'registry-1.docker.io/acme/widget:OLD' }] })));
    expect(screen.queryByRole('button', { name: /^OLD/ })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Начать новый поиск' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Назад к репозиториям' }));
    expect(document.activeElement).toBe(screen.getByRole('searchbox', { name: 'Репозиторий Docker Hub' }));
    await screen.findByRole('button', { name: /acme\/widget/ });
    expect(urls.every(url => !url.searchParams.has('cursor'))).toBe(true);
  });
  it.each(['success', 'failure'] as const)('discards late %s after owner session invalidation', async outcome => {
    let finish!: (response: Response) => void;
    installMock(url => url.searchParams.has('repository') ? new Promise<Response>(resolve => { finish = resolve; }) : reply(page('repository')));
    const { client } = mount(); await openRepository();
    await waitFor(() => expect(finish).toBeTypeOf('function'));
    await act(async () => { transitionScanSession(null, client, true); });
    await act(async () => finish(outcome === 'success' ? reply(page('tag')) : reply({ errorCode: 'IMAGE_SEARCH_EXPIRED' }, 410)));
    expect(screen.queryByRole('button', { name: /ReleaseCandidate/ })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Начать новый поиск' })).toBeNull();
    expect(screen.queryByRole('checkbox', { name: /Подтверждаю выбранную цель и область/ })).toBeNull();
  });

  it('pages only explicitly with owned cursor and retries an error only manually', async () => {
    const urls: URL[] = [];
    let fail = true;
    installMock(url => {
      urls.push(url);
      if (!url.searchParams.has('repository')) return reply(page('repository'));
      if (url.searchParams.has('cursor')) {
        if (fail) return reply({ errorCode: 'IMAGE_SEARCH_UNAVAILABLE' }, 503);
        return reply({ ...page('tag'), items: [{ ...page('tag').items[0], reference: 'registry-1.docker.io/acme/widget:Second' }], loaded: 2, pages: 2 });
      }
      return reply({ ...page('tag'), nextCursor: 'a'.repeat(48), state: 'more-available' });
    }); mount(); await openRepository();
    const more = await screen.findByRole('button', { name: 'Показать ещё' });
    expect(urls).toHaveLength(2);
    fireEvent.click(more);
    await screen.findByRole('button', { name: 'Начать новый поиск' });
    expect(urls).toHaveLength(3);
    expect(urls[2].searchParams.get('cursor')).toBe('a'.repeat(48));
    expect(urls[2].searchParams.get('generation')).toBe(urls[1].searchParams.get('generation'));
    fail = false;
    fireEvent.click(screen.getByRole('button', { name: 'Начать новый поиск' }));
    await screen.findByRole('button', { name: 'Показать ещё' });
    expect(urls[3].searchParams.has('cursor')).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Показать ещё' }));
    await screen.findByRole('button', { name: /^Second/ });
    expect(urls).toHaveLength(5);
    expect(screen.queryByRole('button', { name: 'Показать ещё' })).toBeNull();
  });

  it('rejects tags returned for another repository instead of granting selection authority', async () => {
    installMock(url => reply(url.searchParams.has('repository') ? { ...page('tag'), items: [{ ...page('tag').items[0], reference: 'registry-1.docker.io/foreign/image:ReleaseCandidate' }] } : page('repository')));
    mount(); await openRepository();
    await screen.findByRole('button', { name: 'Начать новый поиск' });
    expect(screen.queryByRole('button', { name: /ReleaseCandidate/ })).toBeNull();
  });

  it('requires fresh preflight before first preset POST and keeps idempotency key on explicit uncertain retry', async () => {
    const requests = installMock(undefined, true); mount(); await screen.findByRole('searchbox');
    fireEvent.click(screen.getByRole('button', { name: new RegExp(firstPreset.label) }));
    await screen.findByText('Сервер разрешает выбранные проверки. Перед запуском проверим доступность ещё раз.');
    const consent = screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель и область/ });
    expect((consent as HTMLInputElement).checked).toBe(false);
    expect(requests.filter(item => item.url === '/api/v1/browser/scans')).toHaveLength(0);
    fireEvent.click(consent);
    fireEvent.click(screen.getByRole('button', { name: 'Запустить проверку' }));
    await screen.findByText(/Запуск не подтверждён; проверьте список перед повтором/);
    const posts = () => requests.filter(item => item.url === '/api/v1/browser/scans');
    expect(posts()).toHaveLength(1);
    const eligibility = requests.filter(item => item.url.endsWith('/images/eligibility'));
    expect(eligibility.length).toBeGreaterThanOrEqual(2);
    expect(eligibility.every(item => item.body?.imageReference === firstPreset.reference)).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Запустить проверку' }));
    await waitFor(() => expect(posts()).toHaveLength(2));
    expect(posts()[1].body).toEqual(posts()[0].body);
    expect(posts()[0].body?.idempotencyKey).toEqual(expect.any(String));
  });

  it('opens actual repository tags without selecting synthetic latest, preserves returned tag case and never auto-launches', async () => {
    const discovery: URL[] = [];
    const forbidden: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (input: string, init?: RequestInit) => {
      if (input === '/api/v1/auth/me') return reply({ id: 'task53-owner', email: 'task53@example.test' });
      if (input.startsWith('/api/v1/browser/runtime/')) return reply({ errorCode: 'RUNTIME_UNAVAILABLE' }, 503);
      if (input === '/api/v1/browser/scans/images/eligibility') {
        return reply({ imageReference: JSON.parse(String(init?.body)).imageReference,
          eligible: false, eligibility: 'unsupported', allowedCheckSets: [], reason: 'UNSUPPORTED_SCAN' });
      }
      if ((init?.method ?? 'GET').toUpperCase() !== 'GET') {
        forbidden.push(input); throw new Error('TASK53 blocks scan/provider POST');
      }
      if (input.startsWith('/api/v1/browser/scans/images?')) {
        const url = new URL(input, 'https://task53.invalid'); discovery.push(url);
        return reply(page(url.searchParams.has('repository') ? 'tag' : 'repository'));
      }
      throw new Error(`Unexpected TASK53 mock request: ${input}`);
    }));
    mount();
    const search = await screen.findByRole('searchbox', { name: 'Репозиторий Docker Hub' });
    fireEvent.change(search, { target: { value: 'acme/widget' } });
    const repository = await screen.findByRole('button', { name: /acme\/widget/ });
    const reference = screen.getByRole('textbox', { name: 'Адрес образа в Docker Hub' });
    const before = (reference as HTMLInputElement).value;
    fireEvent.click(repository);
    await waitFor(() => expect(discovery.some(url => url.searchParams.get('repository') === 'acme/widget')).toBe(true));
    const tagsRequest = discovery.find(url => url.searchParams.has('repository'))!;
    expect(tagsRequest.searchParams.get('q')).toBe('');
    expect(tagsRequest.searchParams.has('cursor')).toBe(false);
    expect((reference as HTMLInputElement).value).toBe(before);
    fireEvent.click(await screen.findByRole('button', { name: /ReleaseCandidate/ }));
    expect((reference as HTMLInputElement).value).toBe('registry-1.docker.io/acme/widget:ReleaseCandidate');
    expect((screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель и область/ }) as HTMLInputElement).checked).toBe(false);
    expect(forbidden).toEqual([]);
    expect(discovery).toHaveLength(2);
  });
});
