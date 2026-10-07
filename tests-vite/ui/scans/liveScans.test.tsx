import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import userEvent from '@testing-library/user-event';
import { LiveScanSession } from '@/features/scans/LiveScanSession';
import { ScanListPage } from '@/pages/scans/ScanListPage';
import { DemoAuthPage } from '@/pages/auth/DemoAuthPage';
import { ScanCreatePage } from '@/pages/scans/ScanCreatePage';
import { ScanDetailPage } from '@/pages/scans/ScanDetailPage';
import { transitionScanSession } from '@/shared/api/auth/scanSession';

class Observer {
  observe() {}
  unobserve() {}
  disconnect() {}
}
beforeEach(() => vi.stubGlobal('IntersectionObserver', Observer));
const id = '00000000-0000-4000-8000-000000000001';
const digest = `sha256:${'a'.repeat(64)}`;
const row = { scanId: id, state: 'completed', digest, platform: 'linux/amd64', targetLabel: 'private/alpine' };
const json = (data: unknown) => ({ ok: true, status: 200, json: async () => data });
const imagePage = (items: Array<{ label: string; reference: string; scannable: boolean }>, nextCursor: string | null = null, pages = 1) => ({
  items: items.map(item => ({ ...item, eligibility: item.scannable ? 'alpine-only' : 'unsupported', reason: item.scannable ? 'Alpine only' : 'найден в Docker Hub, сканирование пока недоступно', kind: item.scannable ? 'tag' : 'repository', tagConfirmed: item.scannable, checks: { secret: item.scannable, sbom: item.scannable, vuln: item.scannable ? 'conditional' : 'unsupported' } })),
  nextCursor, state: nextCursor ? 'more-available' : 'terminal', loaded: items.length, pages, policy: { pageSize: 12, maxPages: 5, maxCandidates: 60, maxActivePerProcess: 8, maxActivePerSubject: 2, maxRequestsPerSubject: 30, rateWindowMs: 60_000, maxSessions: 1024, maxRateEntries: 1024, scope: 'process-local' },
});

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

function mount(path: string, ownEligibility = false) {
  // Existing discovery tests mock Hub pages only. Dispatch the new independent
  // read-only endpoint without consuming those pagination fixtures.
  if (!ownEligibility) {
    const original = fetch;
    vi.stubGlobal('fetch', vi.fn((input: string, init?: RequestInit) => input === '/api/v1/browser/scans/images/eligibility'
      ? Promise.resolve(json({ imageReference: JSON.parse(String(init?.body)).imageReference, eligible: false,
        eligibility: 'unsupported', allowedCheckSets: [], reason: 'UNSUPPORTED_SCAN' })) : original(input, init)));
  }
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Routes>
    <Route path="/account" element={<DemoAuthPage mode="account" />} />
    <Route path="/login" element={<DemoAuthPage mode="login" />} />
    <Route path="/scans" element={<LiveScanSession><ScanListPage /></LiveScanSession>} />
    <Route path="/scans/new" element={<LiveScanSession><ScanCreatePage /></LiveScanSession>} />
    <Route path="/scans/:scanId" element={<LiveScanSession><ScanDetailPage /></LiveScanSession>} />
  </Routes></MemoryRouter></QueryClientProvider>);
  return client;
}

function emulateDisabledBlur(element: HTMLElement) {
  // jsdom also ignores blur() on disabled controls; temporarily enable only to emulate native blur.
  const disabled = element.hasAttribute('disabled');
  element.removeAttribute('disabled');
  element.blur();
  if (disabled) element.setAttribute('disabled', '');
}

describe('LOCAL server-authoritative saved target', () => {
  const reference = 'registry-1.docker.io/library/nginx@sha256:0dcc88822d45581e65ae329f8be769762bf628d3b2bb7d2a077d4aa5c98b30e3';
  const sets = [['secret'], ['sbom'], ['vuln'], ['secret','sbom','vuln']];
  const eligibility = (eligible = true, reason = eligible ? 'READY' : 'SCANNER_UNAVAILABLE') => ({ imageReference: reference, eligible,
    eligibility: 'qualified-exact-profile', allowedCheckSets: sets, qualificationId: 'nginx-local-0dcc-v1', reason });
  beforeEach(() => sessionStorage.clear());
  afterEach(() => sessionStorage.clear());

  it('revalidates saved digest without Hub, retains four sets through readiness changes and uses historical copy', async () => {
    sessionStorage.setItem('scan-target-v1:alice', reference);
    let ready = false;
    const requests: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      requests.push(path);
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.endsWith('/images/eligibility')) return json(eligibility(ready));
      return json({ scans: [], nextCursor: null });
    }));
    mount('/scans/new', true);
    const card = await screen.findByRole('button', { name: /nginx · закреплённый пример/ });
    await screen.findByRole('radio', { name: 'Secrets + SBOM + CVE' });
    expect(card.hasAttribute('disabled')).toBe(true);
    expect(card.getAttribute('aria-pressed')).toBe('true');
    expect(screen.getByText(/72 APK.*не гарантия результата/)).toBeTruthy();
    expect(screen.queryByRole('checkbox', { name: /Image config · OCI/ })).toBeNull();
    expect(requests.some(path => path.includes('/images?'))).toBe(false);
    ready = true; fireEvent(window, new Event('focus'));
    await waitFor(() => expect(card.hasAttribute('disabled')).toBe(false));
    fireEvent.click(screen.getByRole('radio', { name: 'Secrets + SBOM + CVE' }));
    await waitFor(() => expect((screen.getByRole('radio', { name: 'Secrets + SBOM + CVE' }) as HTMLInputElement).checked).toBe(true));
    expect(screen.getAllByRole('radio')).toHaveLength(4);
    ready = false; fireEvent(window, new Event('focus'));
    await waitFor(() => expect(card.hasAttribute('disabled')).toBe(true));
    expect(screen.getAllByRole('radio')).toHaveLength(4);
    expect(sessionStorage.getItem('scan-target-v1:alice')).toBe(reference);
  });

  it('rechecks before new POST but preserves exact ambiguous replay key when eligibility closes', async () => {
    const posts: Array<{ imageReference: string; checks: string[]; idempotencyKey: string }> = [];
    let ready = true, eligibilityRequests = 0;
    vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.endsWith('/images/eligibility')) { eligibilityRequests++; return json(eligibility(ready)); }
      if (path === '/api/v1/browser/scans' && init?.method === 'POST') { posts.push(JSON.parse(String(init.body))); throw new TypeError('response lost after acceptance'); }
      return json({ scans: [], nextCursor: null });
    }));
    mount('/scans/new', true);
    const card = await screen.findByRole('button', { name: /nginx · закреплённый пример/ });
    await waitFor(() => expect(card.hasAttribute('disabled')).toBe(false)); fireEvent.click(card);
    await screen.findByRole('radio', { name: 'secret' });
    fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Запустить скан' }));
    await waitFor(() => expect(posts).toHaveLength(1));
    await screen.findByText(/результат запроса неизвестен/);
    expect(eligibilityRequests).toBeGreaterThanOrEqual(2);
    ready = false; fireEvent(window, new Event('focus'));
    await waitFor(() => expect(card.hasAttribute('disabled')).toBe(true));
    const reads = eligibilityRequests;
    fireEvent.click(screen.getByRole('button', { name: 'Запустить скан' }));
    await waitFor(() => expect(posts).toHaveLength(2));
    expect(posts[1]).toEqual(posts[0]); expect(eligibilityRequests).toBe(reads);
    expect(posts[0]).toMatchObject({ imageReference: reference, checks: ['secret'] });
  });

  it('new POST never enqueues when the fresh eligibility probe closes', async () => {
    let reads = 0, posts = 0;
    vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.endsWith('/images/eligibility')) return json(eligibility(++reads === 1));
      if (init?.method === 'POST') posts++;
      return json({ scans: [], nextCursor: null });
    }));
    mount('/scans/new', true);
    const card = await screen.findByRole('button', { name: /nginx · закреплённый пример/ });
    await waitFor(() => expect(card.hasAttribute('disabled')).toBe(false)); fireEvent.click(card);
    fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Запустить скан' }));
    await screen.findByText(/Актуальный серверный допуск недоступен/);
    expect(posts).toBe(0);
  });

  for (const change of ['checks', 'subject'] as const) it(`ignores stale eligibility after ${change}`, async () => {
    sessionStorage.setItem('scan-target-v1:alice', reference);
    let finish!: (value: ReturnType<typeof json>) => void;
    let reads = 0;
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.endsWith('/images/eligibility')) {
        if (++reads === 1) return json(eligibility());
        return new Promise<ReturnType<typeof json>>(resolve => { finish = resolve; });
      }
      return json({ scans: [], nextCursor: null });
    }));
    const client = mount('/scans/new', true);
    await screen.findByRole('radio', { name: 'sbom' });
    fireEvent.click(screen.getByRole('radio', { name: 'sbom' }));
    await waitFor(() => expect(finish).toBeTypeOf('function'));
    if (change === 'checks') fireEvent.click(screen.getByRole('radio', { name: 'vuln' }));
    else {
      act(() => { transitionScanSession('bob', client); client.setQueryData(['demo-auth', 'me'], { id: 'bob', email: 'bob@example.com' }); });
      await waitFor(() => expect(sessionStorage.getItem('scan-target-v1:alice')).toBeNull());
    }
    await act(async () => finish(json(eligibility())));
    if (change === 'checks') expect(screen.getByRole('button', { name: /nginx · закреплённый пример/ }).hasAttribute('disabled')).toBe(true);
    else expect(sessionStorage.getItem('scan-target-v1:alice')).toBeNull();
  });
});

describe('cookie-session live scans', () => {
  for (const action of ['restore', 'search', 'target', 'checks', 'moved-then-body', 'tab', 'unowned', 'pointer'] as const) it(`surviving pagination after native disabled blur: ${action}`, async () => {
    const user = userEvent.setup();
    const item = { label: 'Alpine · focused', reference: 'registry-1.docker.io/library/alpine:focused', scannable: true };
    let finish!: (value: ReturnType<typeof json>) => void;
    let requests = 0;
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (++requests === 1) return json(imagePage([item], 'a'.repeat(48)));
      return new Promise<ReturnType<typeof json>>(resolve => { finish = resolve; });
    }));
    mount('/scans/new'); const search = await screen.findByRole('searchbox');
    fireEvent.change(search, { target: { value: 'alpine focused' } });
    const target = await screen.findByRole('button', { name: /Alpine · focused/ });
    fireEvent.click(target);
    const confirmation = screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }); fireEvent.click(confirmation);
    const more = screen.getByRole('button', { name: 'Показать ещё' });
    if (action === 'unowned') { search.focus(); fireEvent.click(more); }
    else if (action === 'pointer') await user.click(more);
    else { more.focus(); await user.keyboard('{Enter}'); }
    await waitFor(() => expect(more.hasAttribute('disabled')).toBe(true));
    await waitFor(() => expect(requests).toBe(2));
    // jsdom does not reproduce Chromium's native disabled-button blur.
    act(() => emulateDisabledBlur(document.activeElement as HTMLElement));
    expect(document.activeElement).toBe(document.body);
    if (action === 'search') search.focus();
    if (action === 'target') target.focus();
    if (action === 'checks') confirmation.focus();
    if (action === 'moved-then-body') { search.focus(); search.blur(); }
    if (action === 'tab') { await user.keyboard('{Tab}'); (document.activeElement as HTMLElement).blur(); }
    const expected = action === 'restore' ? more : document.activeElement;
    await act(async () => finish(json({ ...imagePage([], 'b'.repeat(48), 2), loaded: 1 })));
    expect(more.hasAttribute('disabled')).toBe(false);
    expect(document.activeElement).toBe(expected);
    expect(target.getAttribute('aria-pressed')).toBe('true');
    expect((confirmation as HTMLInputElement).checked).toBe(true);
  });

  for (const outcome of ['success', 'failure'] as const) for (const change of ['query', 'sign-out', 'subject', 'session', 'unmount'] as const) it(`does not restore stale pagination focus after ${change}: ${outcome}`, async () => {
    const user = userEvent.setup();
    let finish!: (value: ReturnType<typeof json>) => void;
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('&cursor=')) return new Promise<ReturnType<typeof json>>(resolve => { finish = resolve; });
      return json(imagePage([], 'a'.repeat(48)));
    }));
    const client = mount('/scans/new'); const search = await screen.findByRole('searchbox');
    fireEvent.change(search, { target: { value: 'alpine old' } });
    const more = await screen.findByRole('button', { name: 'Показать ещё' }); more.focus(); await user.keyboard('{Enter}');
    await waitFor(() => expect(more.hasAttribute('disabled')).toBe(true));
    await waitFor(() => expect(finish).toBeTypeOf('function'));
    act(() => emulateDisabledBlur(more));
    const focus = vi.spyOn(more, 'focus');
    if (change === 'query') { search.focus(); fireEvent.change(search, { target: { value: '' } }); }
    else if (change === 'unmount') cleanup();
    else transitionScanSession(change === 'sign-out' ? null : change === 'session' ? 'alice' : 'bob', client, change === 'session');
    await act(async () => finish(outcome === 'success' ? json(imagePage([], 'b'.repeat(48), 2)) : { ok: false, status: 503, json: async () => ({ errorCode: 'IMAGE_SEARCH_UNAVAILABLE' }) }));
    expect(focus).not.toHaveBeenCalled(); focus.mockRestore();
  });
  for (const status of [410, 503]) it(`distinguishes ${status}, retires cursor, restarts without losing scan intent or loaded results`, async () => {
    const user = userEvent.setup();
    const item = { label: 'Alpine · retained', reference: 'registry-1.docker.io/library/alpine:retained', scannable: true };
    let finishRestart!: (value: ReturnType<typeof json>) => void;
    const restart = new Promise<ReturnType<typeof json>>(resolve => { finishRestart = resolve; });
    const requests: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      requests.push(path);
      if (requests.length === 1) return json(imagePage([item], 'a'.repeat(48)));
      if (requests.length === 2) return { ok: false, status, json: async () => ({ errorCode: status === 410 ? 'IMAGE_SEARCH_EXPIRED' : 'IMAGE_SEARCH_UNAVAILABLE' }) };
      return restart;
    }));
    mount('/scans/new');
    fireEvent.change(await screen.findByRole('searchbox'), { target: { value: 'alpine retained' } });
    fireEvent.click(await screen.findByRole('button', { name: /Alpine · retained/ }));
    fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    const more = screen.getByRole('button', { name: 'Показать ещё' }); more.focus();
    await user.keyboard('{Enter}');
    const retry = await screen.findByRole('button', { name: 'Начать новый поиск' });
    expect(screen.getByRole('status', { name: 'Состояние поиска Docker Hub' }).textContent).toContain(status === 410 ? 'Поиск истёк' : 'Поиск Docker Hub сейчас недоступен');
    expect(screen.queryByRole('button', { name: 'Показать ещё' })).toBeNull();
    expect(document.activeElement).toBe(retry);
    expect(screen.getByRole('button', { name: /Alpine · retained/ }).getAttribute('aria-pressed')).toBe('true');
    expect((screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }) as HTMLInputElement).checked).toBe(true);
    await user.keyboard('{Enter}');
    await waitFor(() => expect(requests).toHaveLength(3));
    expect(document.activeElement).toBe(screen.getByRole('status', { name: 'Состояние поиска Docker Hub' }));
    const firstUrl = new URL(requests[0], 'http://localhost'); const restartUrl = new URL(requests[2], 'http://localhost');
    expect(restartUrl.searchParams.has('cursor')).toBe(false);
    expect(restartUrl.searchParams.get('generation')).not.toBe(firstUrl.searchParams.get('generation'));
    expect(screen.getByRole('button', { name: /Alpine · retained/ })).toBeTruthy();
    expect(screen.getByText(/Предыдущие результаты сохранены как неполные/)).toBeTruthy();
    await act(async () => finishRestart(json(imagePage([]))));
    expect(screen.queryByRole('button', { name: /Alpine · retained/ })).toBeNull();
    expect(screen.getByText(/Выбранная цель.*alpine:retained/)).toBeTruthy();
    expect(document.activeElement).toBe(screen.getByRole('status', { name: 'Состояние поиска Docker Hub' }));
  });

  for (const quota of [false, true]) for (const movedFocus of [false, true]) it(`terminal pagination: quota=${quota}, movedFocus=${movedFocus}`,  async () => {
    const user = userEvent.setup();
    const item = { label: 'Alpine · focus', reference: 'registry-1.docker.io/library/alpine:focus', scannable: true };
    let finish!: (value: ReturnType<typeof json>) => void;
    let pageCalls = 0;
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      pageCalls++;
      if (pageCalls === 1) return json(imagePage([item], 'a'.repeat(48)));
      if (quota && pageCalls < 5) return json({ ...imagePage([], String(pageCalls).repeat(48), pageCalls), loaded: 1 });
      return new Promise<ReturnType<typeof json>>(resolve => { finish = resolve; });
    }));
    mount('/scans/new');
    const search = await screen.findByRole('searchbox');
    fireEvent.change(search, { target: { value: 'alpine focus' } });
    await screen.findByRole('button', { name: /Alpine · focus/ });
    if (quota) for (let page = 2; page <= 4; page++) {
      const more = screen.getByRole('button', { name: 'Показать ещё' }); more.focus(); await user.keyboard('{Enter}');
      await waitFor(() => expect(pageCalls).toBe(page));
      await waitFor(() => expect(screen.getByRole('button', { name: 'Показать ещё' }).hasAttribute('disabled')).toBe(false));
      expect(document.activeElement).toBe(more);
    }
    const more = screen.getByRole('button', { name: 'Показать ещё' }); more.focus();
    await user.keyboard('{Enter}');
    await waitFor(() => expect(pageCalls).toBe(quota ? 5 : 2));
    if (movedFocus) search.focus();
    await act(async () => finish(json({ ...imagePage([], null, quota ? 5 : 2), loaded: 1, state: quota ? 'quota-exhausted' : 'terminal' })));
    expect(document.activeElement).toBe(movedFocus ? search : screen.getByRole('status', { name: 'Состояние поиска Docker Hub' }));
    expect(screen.queryByRole('button', { name: 'Показать ещё' })).toBeNull();
  });

  for (const lateFailure of [false, true]) it(`ignores ${lateFailure ? 'failure' : 'success'} from a restarted generation after another query`, async () => {
    let resolveRestart!: (value: ReturnType<typeof json>) => void;
    let rejectRestart!: (error: Error) => void;
    const pending = new Promise<ReturnType<typeof json>>((resolve, reject) => { resolveRestart = resolve; rejectRestart = reject; });
    let calls = 0;
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('q=new')) return json(imagePage([{ label: 'new-discovery', reference: 'registry-1.docker.io/library/nginx:latest', scannable: false }], 'b'.repeat(48)));
      if (++calls === 1) return { ok: false, status: 410, json: async () => ({ errorCode: 'IMAGE_SEARCH_EXPIRED' }) };
      return pending;
    }));
    mount('/scans/new'); const search = await screen.findByRole('searchbox');
    fireEvent.change(search, { target: { value: 'old' } });
    fireEvent.click(await screen.findByRole('button', { name: 'Начать новый поиск' }));
    await waitFor(() => expect(calls).toBe(2));
    fireEvent.change(search, { target: { value: 'new' } });
    expect(await screen.findByRole('button', { name: /new-discovery/ })).toBeTruthy(); search.focus();
    await act(async () => { if (lateFailure) rejectRestart(Error('late restart')); else resolveRestart(json(imagePage([]))); });
    expect(screen.getByRole('button', { name: /new-discovery/ })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Показать ещё' }).hasAttribute('disabled')).toBe(false);
    expect(screen.queryByRole('button', { name: 'Начать новый поиск' })).toBeNull();
    expect(document.activeElement).toBe(search);
  });

  it('retries initial failure with a fresh generation', async () => {
    const requests: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      requests.push(path);
      return requests.length === 1 ? { ok: false, status: 503, json: async () => ({ errorCode: 'IMAGE_SEARCH_UNAVAILABLE' }) } : json(imagePage([]));
    }));
    mount('/scans/new'); fireEvent.change(await screen.findByRole('searchbox'), { target: { value: 'nginx' } });
    fireEvent.click(await screen.findByRole('button', { name: 'Начать новый поиск' }));
    expect(await screen.findByText('Ничего не найдено в Docker Hub.')).toBeTruthy();
    expect(new URL(requests[0], 'http://localhost').searchParams.get('generation')).not.toBe(new URL(requests[1], 'http://localhost').searchParams.get('generation'));
  });
  for (const lateFailure of [false, true]) it(`ignores stale ${lateFailure ? 'failure' : 'success'} when abort is ignored`, async () => {
    let resolveOld!: (value: ReturnType<typeof json>) => void;
    let rejectOld!: (reason: Error) => void;
    const pending = new Promise<ReturnType<typeof json>>((resolve, reject) => { resolveOld = resolve; rejectOld = reject; });
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('q=old')) return pending;
      return json(imagePage([{ label: 'new-result', reference: 'registry-1.docker.io/library/nginx:latest', scannable: false }], 'b'.repeat(48)));
    }));
    mount('/scans/new');
    const search = await screen.findByRole('searchbox');
    fireEvent.change(search, { target: { value: 'old' } });
    await waitFor(() => expect(vi.mocked(fetch).mock.calls.some(([path]) => String(path).includes('q=old'))).toBe(true));
    fireEvent.change(search, { target: { value: 'new' } });
    expect(await screen.findByRole('button', { name: /new-result/ })).toBeTruthy();
    await act(async () => { if (lateFailure) rejectOld(Error('late')); else resolveOld(json(imagePage([{ label: 'old-result', reference: 'registry-1.docker.io/library/alpine:old', scannable: true }]))); });
    expect(screen.queryByRole('button', { name: /old-result/ })).toBeNull();
    expect(screen.queryByText(/Поиск Docker Hub сейчас недоступен/)).toBeNull();
    expect(screen.getByRole('button', { name: 'Показать ещё' }).hasAttribute('disabled')).toBe(false);
    fireEvent.change(search, { target: { value: '' } });
    expect(screen.queryByRole('button', { name: /new-result/ })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Показать ещё' })).toBeNull();
  });

  for (const change of ['clear', 'invalid', 'unmount', 'sign-out', 'subject'] as const) it(`ignores a pending response after ${change}`, async () => {
      let resolveOld!: (value: ReturnType<typeof json>) => void;
      const pending = new Promise<ReturnType<typeof json>>(resolve => { resolveOld = resolve; });
      vi.stubGlobal('fetch', vi.fn(async (path: string) => path === '/api/v1/auth/me' ? json({ id: 'alice', email: 'alice@example.com' }) : pending));
      const client = mount('/scans/new');
      const search = await screen.findByRole('searchbox');
      fireEvent.change(search, { target: { value: 'pending' } });
      await waitFor(() => expect(vi.mocked(fetch).mock.calls.some(([path]) => String(path).includes('q=pending'))).toBe(true));
      if (change === 'clear' || change === 'invalid') fireEvent.change(search, { target: { value: change === 'clear' ? '' : 'https://evil.example' } });
      else if (change === 'unmount') cleanup();
      else transitionScanSession(change === 'sign-out' ? null : 'bob', client);
      await act(async () => resolveOld(json(imagePage([{ label: 'stale-result', reference: 'registry-1.docker.io/library/alpine:stale', scannable: true }], 'a'.repeat(48)))));
      expect(screen.queryByRole('button', { name: /stale-result/ })).toBeNull();
      expect(screen.queryByRole('button', { name: 'Показать ещё' })).toBeNull();
    });

    it('merges explicit pages and an empty terminal page without losing selection or focus', async () => {
      const first = { label: 'Alpine · custom-one', reference: 'registry-1.docker.io/library/alpine:custom-one', scannable: true };
      const second = { label: 'Alpine · custom-two', reference: 'registry-1.docker.io/library/alpine:custom-two', scannable: true };
      let calls = 0;
      vi.stubGlobal('fetch', vi.fn(async (path: string) => {
        if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
        calls++;
        if (calls === 1) return json(imagePage([first], 'a'.repeat(48)));
        if (calls === 2) return json({ ...imagePage([first, second], 'b'.repeat(48), 2), loaded: 2 });
        return json({ ...imagePage([], null, 3), loaded: 2 });
      }));
      mount('/scans/new');
      fireEvent.change(await screen.findByRole('searchbox'), { target: { value: 'alpine custom' } });
      const selected = await screen.findByRole('button', { name: /Alpine · custom-one/ });
      fireEvent.click(selected); selected.focus();
      fireEvent.click(screen.getByRole('button', { name: 'Показать ещё' }));
      expect(await screen.findByRole('button', { name: /Alpine · custom-two/ })).toBeTruthy();
      expect(screen.getAllByRole('button', { name: /Alpine · custom-one/ })).toHaveLength(1);
      expect(document.activeElement).toBe(selected);
      fireEvent.click(screen.getByRole('button', { name: 'Показать ещё' }));
      await waitFor(() => expect(screen.queryByRole('button', { name: 'Показать ещё' })).toBeNull());
      expect(selected.getAttribute('aria-pressed')).toBe('true');
      expect(screen.queryByText(/Ничего не найдено/)).toBeNull();
      expect(calls).toBe(3);
    });

    it('pages explicitly, keeps selection and prior results on failure, rejects unknown eligibility', async () => {
    const first = { label: 'Alpine · unique-tag', reference: 'registry-1.docker.io/library/alpine:unique-tag', scannable: true };
    const fetchMock = vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('&cursor=')) return { ok: false, status: 503, json: async () => ({}) };
      return json(imagePage([first], 'a'.repeat(48)));
    });
    vi.stubGlobal('fetch', fetchMock); mount('/scans/new');
    const search = await screen.findByRole('searchbox');
    fireEvent.change(search, { target: { value: 'alpine unique' } });
    fireEvent.click(await screen.findByRole('button', { name: /Alpine · unique-tag/ }));
    expect(fetchMock.mock.calls.filter(([path]) => path.includes('/images')).length).toBe(1);
    fireEvent.click(screen.getByRole('button', { name: 'Показать ещё' }));
    expect(await screen.findByText(/Поиск Docker Hub сейчас недоступен/)).toBeTruthy();
    expect(screen.getByRole('button', { name: /Alpine · unique-tag/ }).getAttribute('aria-pressed')).toBe('true');
    expect(screen.getByText(/Выбранная цель.*unique-tag/)).toBeTruthy();
    fireEvent.change(search, { target: { value: 'unknown' } });
    fetchMock.mockImplementation(async (path: string) => path === '/api/v1/auth/me' ? json({ id: 'alice', email: 'alice@example.com' }) : json({ ...imagePage([first]), items: [{ ...first, eligibility: 'unknown' }] }));
    await waitFor(() => expect(screen.getByText(/Поиск Docker Hub сейчас недоступен/)).toBeTruthy());
    expect(screen.queryByRole('button', { name: /Alpine · unique-tag/ })).toBeNull();
  });
  it('uses SSE only as a hint for a fresh GET and closes after terminal snapshot', async () => {
    const streams: Array<{ path: string; close: ReturnType<typeof vi.fn>; emit: (type: string, data?: unknown) => void }> = [];
    vi.stubGlobal('EventSource', class {
      close = vi.fn();
      handlers = new Map<string, (event: MessageEvent) => void>();
      constructor(public path: string) {
        streams.push({ path, close: this.close, emit: (type, data) => this.handlers.get(type)?.(new MessageEvent(type, { data: JSON.stringify(data) })) });
      }
      addEventListener(type: string, handler: (event: MessageEvent) => void) { this.handlers.set(type, handler); }
    });
    let state = 'running';
    const fetchMock = vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.endsWith('/results?limit=50')) return json({ findings: [], nextCursor: null, coverage: null });
      return json({ scanId: id, state, result: null });
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = mount(`/scans/${id}`);
    await waitFor(() => expect(streams).toHaveLength(1));
    expect(streams[0].path).toBe(`/api/v1/browser/scans/${id}/events`);
    await act(async () => { await client.invalidateQueries({ queryKey: ['demo-auth', 'me'] }); });
    expect(streams).toHaveLength(1);
    expect(streams[0].close).not.toHaveBeenCalled();
    const before = fetchMock.mock.calls.filter(([path]) => path === `/api/v1/browser/scans/${id}`).length;
    state = 'completed';
    act(() => streams[0].emit('scan', { scanId: id, state: 'completed', percent: null }));
    await waitFor(() => expect(fetchMock.mock.calls.filter(([path]) => path === `/api/v1/browser/scans/${id}`).length).toBeGreaterThan(before));
    await waitFor(() => expect(streams[0].close).toHaveBeenCalled());
    expect(screen.getAllByText('Завершён').length).toBeGreaterThan(0);
  });
  it('does not request scans or display fixtures for anonymous users', async () => {
    const fetchMock = vi.fn(async (path: string, options?: RequestInit) => { void path; void options; return { status: 401, ok: false }; });
    vi.stubGlobal('fetch', fetchMock);
    mount('/scans');
    expect(await screen.findByText(/Для доступа к сканам/)).toBeTruthy();
    expect(fetchMock.mock.calls.map(([path]) => path)).toEqual(['/api/v1/auth/me']);
    expect(screen.queryByText(/library\/alpine:latest \(демо\)/)).toBeNull();
  });

  it('explains a 403 scan permission separately from a valid login', async () => {
    vi.stubGlobal('fetch', vi.fn(async (path: string) => path === '/api/v1/auth/me'
      ? json({ id: 'alice', email: 'alice@example.com' })
      : { ok: false, status: 403 }));
    mount('/scans');
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('Аккаунту не выдано разрешение на реальные сканы'));
    expect(screen.getByRole('link', { name: 'странице аккаунта' }).getAttribute('href')).toBe('/account');
  });

  it('loads authorized list, detail and results without a token or SSE/cancel', async () => {
    const fetchMock = vi.fn(async (path: string, options?: RequestInit) => {
      void options;
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.startsWith('/api/v1/browser/scans?')) return json({ scans: [row], nextCursor: null });
      if (path.endsWith('/results?limit=50')) return json({ findings: [], nextCursor: null, coverage: { findingCount: 0, check: 'secret', coverage: 'image', outcome: 'checked', errorCode: null, scannerVersion: null } });
      return json({ scanId: id, state: 'completed', digest, platform: 'linux/amd64', result: { findingCount: 0, check: 'secret', coverage: 'image', outcome: 'checked', errorCode: null, scannerVersion: null } });
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = mount('/scans');
    expect(await screen.findByText('private/alpine')).toBeTruthy();
    expect(screen.getAllByRole('link', { name: /Новый скан/ }).some(link => link.getAttribute('href') === '/scans/new')).toBe(true);
    expect(JSON.stringify(fetchMock.mock.calls)).not.toContain('Authorization');
    expect(fetchMock.mock.calls.every(([, options]) => options?.credentials === 'same-origin')).toBe(true);
    cleanup();
    client.clear();
    mount(`/scans/${id}`);
    expect(await screen.findByText(/0 находок в выполненной проверенной области/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Отмена недоступна' }).hasAttribute('disabled')).toBe(true);
    expect(fetchMock.mock.calls.some(([path]) => path === `/api/v1/browser/scans/${id}/results?limit=50`)).toBe(true);
  });

  it('shows remote Docker Hub results but does not allow unsupported repositories to launch', async () => {
    const fetchMock = vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('/images?q=nginx')) return json(imagePage([{ label: 'nginx', reference: 'registry-1.docker.io/library/nginx:latest', scannable: false }]));
      if (path.includes('/images?q=alpine%203.16')) return json(imagePage([{ label: 'Alpine · 3.16.9', reference: 'registry-1.docker.io/library/alpine:3.16.9', scannable: true }]));
      return json({ scanId: id, state: 'queued', result: null });
    });
    vi.stubGlobal('fetch', fetchMock);
    mount('/scans/new');
    const search = await screen.findByRole('searchbox', { name: 'Поиск по доступным образам' });
    fireEvent.change(search, { target: { value: 'nginx' } });
    const nginx = await screen.findByRole('button', { name: /nginx.*сканирование пока недоступно/ });
    expect(nginx.hasAttribute('disabled')).toBe(true);
    fireEvent.change(search, { target: { value: 'Alpine 3.16' } });
    const alpine = await screen.findByRole('button', { name: /Alpine · 3.16.9/ });
    expect(alpine.hasAttribute('disabled')).toBe(false);
    fireEvent.click(alpine);
    expect(screen.getByText(/Выбранная цель.*registry-1.docker.io\/library\/alpine:3.16.9/)).toBeTruthy();
  });

  it('selects the verified old Alpine digest without substituting a mutable tag', async () => {
    const fetchMock = vi.fn(async (path: string, options?: RequestInit) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path === '/api/v1/browser/scans' && options?.method === 'POST') return json({ scanId: id });
      return json({ scanId: id, state: 'queued', result: null });
    });
    vi.stubGlobal('fetch', fetchMock);
    mount('/scans/new');
    fireEvent.change(await screen.findByRole('searchbox', { name: 'Поиск по доступным образам' }), { target: { value: '3.16' } });
    fireEvent.click(screen.getByRole('button', { name: /Alpine · 3.16/ }));
    expect(screen.getByText(/локальная DB нашла 4 CVE/)).toBeTruthy();
    fireEvent.click(screen.getByRole('checkbox', { name: /CVE · доступно/ }));
    fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Запустить скан' }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([path, options]) => path === '/api/v1/browser/scans' && options?.method === 'POST')).toBe(true));
    const request = fetchMock.mock.calls.find(([path, options]) => path === '/api/v1/browser/scans' && options?.method === 'POST');
    expect(JSON.parse(String(request?.[1]?.body))).toMatchObject({ imageReference: 'registry-1.docker.io/library/alpine@sha256:0db9d004361b106932f8c7632ae54d56e92c18281e2dd203127d77405020abf6', scope: 'image', checks: ['secret', 'vuln'] });
  });
  it('submits confirmed scope once and navigates only after a validated receipt', async () => {
    const fetchMock = vi.fn(async (path: string, options?: RequestInit) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path === '/api/v1/browser/scans' && options?.method === 'POST') return json({ scanId: id, statusUrl: `/api/v1/scans/${id}`, eventsUrl: `/api/v1/scans/${id}/events` });
      if (path.endsWith('/results?limit=50')) return json({ findings: [], nextCursor: null, coverage: null });
      return json({ scanId: id, state: 'queued', result: null });
    });
    vi.stubGlobal('fetch', fetchMock);
    mount('/scans/new');
    const button = await screen.findByRole('button', { name: 'Запустить скан' });
    expect(button.hasAttribute('disabled')).toBe(true);
    const search = screen.getByRole('searchbox', { name: 'Поиск по доступным образам' });
    fireEvent.change(search, { target: { value: 'ubuntu' } });
    expect(screen.queryByRole('button', { name: /Alpine · 3.21/ })).toBeNull();
    expect(button.hasAttribute('disabled')).toBe(true);
    fireEvent.change(search, { target: { value: '3.21' } });
    fireEvent.click(screen.getByRole('button', { name: /Alpine · 3.21/ }));
    expect(screen.queryByRole('button', { name: /Alpine · latest/ })).toBeNull();
    fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    fireEvent.click(button);
    await waitFor(() => expect(fetchMock.mock.calls.some(([path, options]) => path === '/api/v1/browser/scans' && options?.method === 'POST')).toBe(true));
    const post = fetchMock.mock.calls.find(([path]) => path === '/api/v1/browser/scans');
    expect(JSON.parse(String(post?.[1]?.body))).toMatchObject({ imageReference: 'registry-1.docker.io/library/alpine:3.21', scope: 'image', checks: ['secret'] });
    expect(await screen.findByText(/ID \/ 00000000/)).toBeTruthy();
    await waitFor(() => expect(fetchMock.mock.calls.some(([path]) => path === `/api/v1/browser/scans/${id}`)).toBe(true));
    expect(fetchMock.mock.calls.every(([path]) => !path.startsWith('/api/v1/scans'))).toBe(true);
  });

  it('launches a selected SBOM check without requesting other results' , async () => {
    const fetchMock = vi.fn(async (path: string, options?: RequestInit) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path === '/api/v1/browser/scans' && options?.method === 'POST') return json({ scanId: id });
      return json({ scanId: id, state: 'queued', result: null });
    });
    vi.stubGlobal('fetch', fetchMock);
    mount('/scans/new');
    fireEvent.click(await screen.findByRole('button', { name: /Alpine · 3.21/ }));
    fireEvent.click(screen.getByRole('checkbox', { name: /Secrets · проверка образа/ }));
    fireEvent.click(screen.getByRole('checkbox', { name: /SBOM · перечень пакетов/ }));
    expect(screen.getByRole('checkbox', { name: /CVE · доступно/ }).hasAttribute('disabled')).toBe(false);
    fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Запустить скан' }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([path, options]) => path === '/api/v1/browser/scans' && options?.method === 'POST')).toBe(true));
    const body = JSON.parse(String(fetchMock.mock.calls.find(([path]) => path === '/api/v1/browser/scans')?.[1]?.body));
    expect(body).toMatchObject({ checks: ['sbom'], scope: 'image' });
    expect(typeof body.idempotencyKey).toBe('string');
    expect(await screen.findByText(/Тип проверки пока не указан/)).toBeTruthy();
    expect(fetchMock.mock.calls.some(([path]) => path.includes('/sbom?') || path.includes('/results?'))).toBe(false);
  });
  it('submits all checks canonically and reports missing CVE DB as unavailable', async () => {
    const posts: string[][] = [];
    vi.stubGlobal('fetch', vi.fn(async (path: string, options?: RequestInit) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path === '/api/v1/browser/scans' && options?.method === 'POST') {
        posts.push(JSON.parse(String(options.body)).checks);
        return { ok: false, status: 503, json: async () => ({ errorCode: 'SCAN_UNAVAILABLE' }) };
      }
      return json({ scans: [], nextCursor: null });
    }));
    mount('/scans/new');
    fireEvent.click(await screen.findByRole('button', { name: /Alpine · 3.21/ }));
    fireEvent.click(screen.getByRole('checkbox', { name: /CVE · доступно/ }));
    fireEvent.click(screen.getByRole('checkbox', { name: /SBOM · перечень пакетов/ }));
    expect(screen.getByRole('checkbox', { name: /Host \/ running container/ }).hasAttribute('disabled')).toBe(true);
    fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Запустить скан' }));
    await waitFor(() => expect(posts).toEqual([['secret', 'sbom', 'vuln']]));
    expect((await screen.findByRole('alert')).textContent).toMatch(/база уязвимостей не настроена или недоступна/);
    expect(screen.queryByText(/0 CVE/)).toBeNull();
  });
  it('renders independent partial outcomes and paginates subject-scoped CVE findings', async () => {
    const secret = { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 0, scannerVersion: '0.69.3', errorCode: null };
    const failedSbom = { check: 'sbom', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_TIMEOUT' };
    const checkedVuln = { check: 'vuln', coverage: 'image', outcome: 'checked', findingCount: 2, scannerVersion: '0.69.3', checkedAt: 'today' };
    const finding = (n: number) => ({ findingId: `vuln-${n}`, cveId: `CVE-2026-${n}`, ecosystem: 'apk', packageName: 'busybox', installedVersion: '1', severity: 'HIGH', fixedVersion: null });
    const fetchMock = vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('/results?')) return json({ findings: [], nextCursor: null, coverage: secret });
      if (path.includes('/sbom?')) return json({ outcome: 'failed', coverage: 'image', reason: 'SCAN_TIMEOUT', errorCode: 'SCAN_TIMEOUT', components: [], nextCursor: null });
      if (path.includes('/vuln?')) return json({ outcome: 'checked', coverage: 'image', image: `registry-1.docker.io/library/alpine@${digest}`, platform: 'linux/amd64', findingCount: 2, scannerVersion: '0.69.3', checkedAt: 'today', findings: [finding(path.includes('cursor=1') ? 2 : 1)], nextCursor: path.includes('cursor=1') ? null : 1 });
      return json({ scanId: id, state: 'partial', digest, platform: 'linux/amd64', checks: ['secret', 'sbom', 'vuln'], perCheck: { secret, sbom: failedSbom, vuln: checkedVuln }, result: null });
    });
    vi.stubGlobal('fetch', fetchMock);
    mount(`/scans/${id}`);
    expect(await screen.findByText(/CVE-2026-1/)).toBeTruthy();
    expect(screen.getByText(/SBOM не проверен: SCAN_TIMEOUT/)).toBeTruthy();
    expect(screen.getByText(/Находок в проверенной области: 2/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Следующая страница CVE' }));
    expect(await screen.findByText(/CVE-2026-2/)).toBeTruthy();
    expect(fetchMock.mock.calls.some(([path]) => path === `/api/v1/browser/scans/${id}/vuln?limit=50&cursor=1`)).toBe(true);
  });
  it.each(['partial', 'failed'])('renders DB_UNAVAILABLE and unknown CVE count for %s and remount', async state => {
    const failed = { check: 'vuln', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_FAILED', reason: 'DB_UNAVAILABLE', checksVersion: 'trivy-0.69.3-archive-v1', scannerVersion: '0.69.3', checkedAt: '2026-10-06T16:00:00.000Z' };
    const secret = { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 0, scannerVersion: '0.69.3', errorCode: null };
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('/vuln?')) return json({ outcome: 'failed', coverage: 'image', errorCode: 'SCAN_FAILED', reason: 'DB_UNAVAILABLE', findings: [], nextCursor: null });
      if (path.includes('/results?')) return json({ findings: [], nextCursor: null, coverage: secret });
      return json({ scanId: id, state, digest, platform: 'linux/amd64', checks: state === 'partial' ? ['secret', 'vuln'] : ['vuln'],
        perCheck: state === 'partial' ? { secret, vuln: failed } : { vuln: failed }, result: null });
    }));
    for (let visit = 0; visit < 2; visit++) {
      mount(`/scans/${id}`);
      expect(await screen.findByText(/CVE не проверены: DB_UNAVAILABLE/)).toBeTruthy();
      expect(screen.getByText(/Число уязвимостей неизвестно/)).toBeTruthy();
      expect(screen.queryByText(/Находок в проверенной области:/)).toBeNull();
      cleanup();
    }
  });
  it('does not attribute CVE counts to a different pinned image', async () => {
    const checkedVuln = { check: 'vuln', coverage: 'image', outcome: 'checked', findingCount: 0, scannerVersion: '0.69.3', checkedAt: 'today' };
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('/vuln?')) return json({ outcome: 'checked', coverage: 'image', image: `registry-1.docker.io/library/alpine@sha256:${'b'.repeat(64)}`, platform: 'linux/amd64', findingCount: 0, scannerVersion: '0.69.3', checkedAt: 'today', findings: [], nextCursor: null });
      return json({ scanId: id, state: 'completed', digest, platform: 'linux/amd64', checks: ['vuln'], perCheck: { vuln: checkedVuln }, result: checkedVuln });
    }));
    mount(`/scans/${id}`);
    expect(await screen.findByText(/Идентичность образа в CVE-отчёте не совпадает/)).toBeTruthy();
    expect(screen.queryByText(/Находок в проверенной области:/)).toBeNull();
  });
  it('does not call a 503 CVE response a clean result', async () => {
    const fetchMock = vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('/vuln?')) return { ok: false, status: 503, json: async () => ({ errorCode: 'SCAN_UNAVAILABLE' }) };
      return json({ scanId: id, state: 'partial', checks: ['vuln'], perCheck: { vuln: { check: 'vuln', coverage: 'image', outcome: 'checked', findingCount: 1, scannerVersion: '0.69.3', checkedAt: 'today' } }, result: null });
    });
    vi.stubGlobal('fetch', fetchMock);
    mount(`/scans/${id}`);
    expect(await screen.findByText(/проверьте настройку базы уязвимостей/)).toBeTruthy();
    expect(screen.queryByText(/Находок в проверенной области:/)).toBeNull();
  });
  it('rotates the attempt key on check change after a rejected request', async () => {
    const posts: Array<{ checks: string[]; idempotencyKey: string }> = [];
    vi.stubGlobal('fetch', vi.fn(async (path: string, options?: RequestInit) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path === '/api/v1/browser/scans' && options?.method === 'POST') {
        posts.push(JSON.parse(String(options.body)));
        return { ok: false, status: 400, json: async () => ({ errorCode: 'INVALID_SCAN_REQUEST' }) };
      }
      return json({ scans: [], nextCursor: null });
    }));
    mount('/scans/new');
    fireEvent.click(await screen.findByRole('button', { name: /Alpine · 3.21/ }));
    fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Запустить скан' }));
    await waitFor(() => expect(posts).toHaveLength(1));
    fireEvent.click(screen.getByRole('checkbox', { name: /SBOM · перечень пакетов/ }));
    expect(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }).hasAttribute('checked')).toBe(false);
    fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Запустить скан' }));
    await waitFor(() => expect(posts).toHaveLength(2));
    expect(posts.map(post => post.checks)).toEqual([['secret'], ['secret', 'sbom']]);
    expect(posts[1].idempotencyKey).not.toBe(posts[0].idempotencyKey);
  });
  it('shows checked SBOM pages and failed coverage only for a status-identified SBOM', async () => {
    const checked = { outcome: 'checked', coverage: 'image', image: `registry-1.docker.io/library/alpine@${digest}`, platform: 'linux/amd64', os: { name: 'alpine', version: '3.21' }, componentCount: 2, scannerVersion: '0.69.3', checkedAt: '2026-01-01', components: [{ ecosystem: 'apk', name: 'busybox', version: '1' }], nextCursor: 1 };
    let failed = false;
    const fetchMock = vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('/sbom?')) return json(failed ? { coverage: 'image', outcome: 'failed', reason: 'SCAN_TIMEOUT', errorCode: 'SCAN_TIMEOUT', components: [], nextCursor: null } : path.includes('cursor=1') ? { ...checked, components: [{ ecosystem: 'apk', name: 'musl', version: '2' }], nextCursor: null } : checked);
      return json({ scanId: id, state: 'completed', result: failed ? { check: 'sbom', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_TIMEOUT' } : { check: 'sbom', coverage: 'image', outcome: 'checked', componentCount: 2, scannerVersion: '0.69.3', checkedAt: '2026-01-01' } });
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = mount(`/scans/${id}`);
    expect(await screen.findByText('busybox')).toBeTruthy();
    expect(screen.getByText(/ОС alpine 3.21/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Следующая страница SBOM' }));
    expect(await screen.findByText('musl')).toBeTruthy();
    expect(fetchMock.mock.calls.some(([path]) => path.includes('/results?'))).toBe(false);
    failed = true;
    await client.invalidateQueries({ queryKey: ['live-scans'] });
    expect(await screen.findByText(/SBOM не проверен/)).toBeTruthy();
    expect(screen.queryByText('musl')).toBeNull();
    expect(document.body.textContent).not.toContain('0 CVE');
  });

  it('shows a confirmed validation error rather than unknown outcome for a rejected target', async () => {
    const fetchMock = vi.fn(async (path: string, options?: RequestInit) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path === '/api/v1/browser/scans' && options?.method === 'POST') return { ok: false, status: 400, json: async () => ({ errorCode: 'INVALID_SCAN_REQUEST' }) };
      return json({ scans: [], nextCursor: null });
    });
    vi.stubGlobal('fetch', fetchMock);
    mount('/scans/new');
    fireEvent.click(await screen.findByRole('button', { name: /Alpine · 3.21/ }));
    fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Запустить скан' }));
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'Сервер отклонил цель или параметры сканирования. Скан не создан.');
  });

  it('shows logout on real scans, revokes the server cookie and clears private cache without opening account', async () => {
    const fetchMock = vi.fn(async (path: string, options?: RequestInit) => {
      void options;
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path === '/api/v1/auth/logout') return { ok: true, status: 204 };
      return json({ scans: [row], nextCursor: null });
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = mount('/scans');
    expect(await screen.findByText('private/alpine')).toBeTruthy();
    const privateKey = client.getQueryCache().findAll({ queryKey: ['live-scans'] })[0].queryKey;
    fireEvent.click(screen.getByRole('button', { name: 'Выйти' }));
    expect(await screen.findByRole('heading', { name: 'Вход' })).toBeTruthy();
    expect(fetchMock.mock.calls.some(([path, options]) => path === '/api/v1/auth/logout' && options?.method === 'POST')).toBe(true);
    expect(client.getQueryData(privateKey)).toBeUndefined();
    expect(screen.queryByText('private/alpine')).toBeNull();
  });

  it('removes authorized scans when /auth/me reports an expired or revoked session', async () => {
    let valid = true;
    const fetchMock = vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return valid ? json({ id: 'alice', email: 'alice@example.com' }) : { ok: false, status: 401 };
      return json({ scans: [row], nextCursor: null });
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = mount('/scans');
    expect(await screen.findByText('private/alpine')).toBeTruthy();
    const privateKey = client.getQueryCache().findAll({ queryKey: ['live-scans'] })[0].queryKey;
    valid = false;
    await client.invalidateQueries({ queryKey: ['demo-auth', 'me'] });
    expect(await screen.findByText(/Для доступа к сканам/)).toBeTruthy();
    expect(screen.queryByText('private/alpine')).toBeNull();
    expect(client.getQueryData(privateKey)).toBeUndefined();
  });

  it('closes the scan view and requests a new login if session verification fails', async () => {
    let fail = false;
    const fetchMock = vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') {
        if (fail) throw new TypeError('Failed to fetch');
        return json({ id: 'alice', email: 'alice@example.com' });
      }
      if (path === '/api/v1/auth/logout') return { ok: true, status: 204 };
      return json({ scans: [row], nextCursor: null });
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = mount('/scans');
    expect(await screen.findByText('private/alpine')).toBeTruthy();
    fail = true;
    await client.invalidateQueries({ queryKey: ['demo-auth', 'me'] });
    expect(await screen.findByRole('heading', { name: 'Вход' })).toBeTruthy();
    expect(screen.queryByText('private/alpine')).toBeNull();
    expect(client.getQueryCache().findAll({ queryKey: ['live-scans'] })).toHaveLength(0);
  });

  it('replaces prior subject data after /auth/me changes', async () => {
    let subject = 'alice';
    const fetchMock = vi.fn(async (path: string) => path === '/api/v1/auth/me'
      ? json({ id: subject, email: `${subject}@example.com` })
      : json({ scans: [{ ...row, targetLabel: subject }], nextCursor: null }));
    vi.stubGlobal('fetch', fetchMock);
    const client = mount('/scans');
    expect(await screen.findByText('alice')).toBeTruthy();
    const previous = client.getQueryCache().findAll({ queryKey: ['live-scans'] })[0].queryKey;
    subject = 'bob';
    await client.invalidateQueries({ queryKey: ['demo-auth', 'me'] });
    expect(await screen.findByText('bob')).toBeTruthy();
    expect(screen.queryByText('alice')).toBeNull();
    expect(client.getQueryData(previous)).toBeUndefined();
  });

  it('clears live caches on logout and subject change', async () => {
    const fetchMock = vi.fn(async (path: string, options?: RequestInit) => {
      void options;
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path === '/api/v1/auth/logout') return json({});
      return json({ scans: [row], nextCursor: null });
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = mount('/scans');
    expect(await screen.findByText('private/alpine')).toBeTruthy();
    const old = client.getQueryCache().findAll({ queryKey: ['live-scans'] });
    expect(old.length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole('link', { name: 'Аккаунт' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Выйти из аккаунта' }));
    expect(await screen.findByRole('heading', { name: 'Вход', level: 2 })).toBeTruthy();
    expect(client.getQueryCache().findAll({ queryKey: ['live-scans'] })).toHaveLength(0);
    expect(client.getQueryData(old[0].queryKey)).toBeUndefined();
    transitionScanSession('bob', client, true);
    expect(client.getQueryCache().findAll({ queryKey: ['live-scans'] })).toHaveLength(0);
  });
});
