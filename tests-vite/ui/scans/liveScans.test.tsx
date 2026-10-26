import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom';
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

// Independent synthetic server: complete datasets are sliced at the requested legal page size.
// No client normalizer/parser generates the response or silently repairs malformed row data.
function reportPage(path: string, payload: Record<string, unknown>) {
  const url = new URL(path, window.location.origin);
  expect(url.searchParams.get('view')).toBe('report-v1');
  const kind = url.pathname.endsWith('/results') ? 'secret' : url.pathname.endsWith('/sbom') ? 'sbom' : 'vuln';
  const limit = Number(url.searchParams.get('limit'));
  expect([5, 10, 25, 50]).toContain(limit);
  const cursor = url.searchParams.get('cursor');
  if (cursor !== null) expect(cursor).toMatch(/^fixture:\d+$/);
  const offset = cursor === null ? 0 : Number(cursor.slice('fixture:'.length));
  const key = kind === 'sbom' ? 'components' : 'findings';
  const all = payload[key] as unknown[];
  const rows = all.slice(offset, offset + limit);
  const coverage = kind === 'secret' ? payload.coverage as Record<string, unknown> | null : payload;
  const checked = coverage?.outcome === 'checked';
  const total = checked ? kind === 'sbom' ? payload.componentCount : kind === 'secret' ? coverage?.findingCount : payload.findingCount : null;
  const sort = kind === 'vuln' ? 'severity:desc' : kind === 'sbom' ? 'name:asc' : 'ruleId:asc';
  expect(url.searchParams.get('sort')).toBe(sort);
  return { ...payload, [key]: rows, nextCursor: offset + rows.length < all.length ? `fixture:${offset + rows.length}` : null,
    page: { version: 1, limit, offset, returnedCount: rows.length, totalCount: total, matchedCount: total, sort,
      filters: kind === 'vuln' ? { severity: null } : kind === 'sbom' ? { ecosystem: null, name: null } : { ruleId: null, linePresence: null } } };
}
async function expectCve(cveId: string) {
  const id = await screen.findByText(cveId, { selector: '.scan-vuln-row__id' });
  const row = within(id.closest('li')!);
  expect(row.getByText('HIGH', { exact: true })).toBeTruthy();
  return row;
}
const imagePage = (items: Array<{ label: string; reference: string; scannable: boolean }>, nextCursor: string | null = null, pages = 1) => ({
  items: items.map(item => ({ ...item, eligibility: item.scannable ? 'alpine-only' : 'unsupported', reason: item.scannable ? 'Alpine only' : 'найден в Docker Hub, сканирование пока недоступно', kind: item.scannable ? 'tag' : 'repository', tagConfirmed: item.scannable, checks: { secret: item.scannable, sbom: item.scannable, vuln: item.scannable ? 'conditional' : 'unsupported' } })),
  nextCursor, state: nextCursor ? 'more-available' : 'terminal', loaded: items.length, pages, policy: { pageSize: 12, maxPages: 5, maxCandidates: 60, maxActivePerProcess: 8, maxActivePerSubject: 2, maxRequestsPerSubject: 30, rateWindowMs: 60_000, maxSessions: 1024, maxRateEntries: 1024, scope: 'process-local' },
});

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function mount(path: string, ownEligibility = false) {
  // Runtime has its own contract and must not consume image-search or eligibility responses.
  const scanFetch = fetch;
  vi.stubGlobal('fetch', vi.fn((input: string, init?: RequestInit) => input.startsWith('/api/v1/browser/runtime/')
    ? Promise.resolve(new Response(JSON.stringify({ errorCode: 'RUNTIME_UNAVAILABLE' }), { status: 503 }))
    : scanFetch(input, init)));
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

  it('TASK35 counts slow overlap, settled rerenders and focus TTL without an identity storm', async () => {
    let finish!: (value: ReturnType<typeof json>) => void;
    let reads = 0;
    let now = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.endsWith('/images/eligibility')) {
        reads++;
        if (reads === 1) return new Promise<ReturnType<typeof json>>(resolve => { finish = resolve; });
        return json(eligibility());
      }
      return json({ scans: [], nextCursor: null });
    }));
    mount('/scans/new', true);
    await waitFor(() => expect(finish).toBeTypeOf('function'));
    const pause = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 180)); });
    fireEvent(window, new Event('focus')); await pause();
    fireEvent(window, new Event('focus')); await pause();
    expect(reads).toBe(1);
    await act(async () => finish(json(eligibility())));
    const card = screen.getByRole('button', { name: /nginx · закреплённый пример/ });
    fireEvent.click(card);
    fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    fireEvent(window, new Event('focus')); await pause();
    expect(reads).toBe(1);
    now += 5001;
    fireEvent(window, new Event('focus')); await pause();
    await waitFor(() => expect(card.hasAttribute('disabled')).toBe(false));
    expect(reads).toBe(2);
  });

  it('TASK35 drops superseded queued SBOM behind slow Secrets and sends only latest CVE', async () => {
    sessionStorage.setItem('scan-target-v1:alice', reference);
    const reads: string[] = [];
    let finish!: (value: ReturnType<typeof json>) => void;
    let activeSignal!: AbortSignal;
    let now = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.endsWith('/images/eligibility')) {
        reads.push(JSON.parse(String(init?.body)).checks.join(','));
        if (reads.length === 2) {
          activeSignal = init?.signal as AbortSignal;
          return new Promise<ReturnType<typeof json>>(resolve => { finish = resolve; });
        }
        return json(eligibility());
      }
      return json({ scans: [], nextCursor: null });
    }));
    mount('/scans/new', true);
    await screen.findByRole('radio', { name: 'sbom' });
    now += 5001; fireEvent(window, new Event('focus'));
    await waitFor(() => expect(finish).toBeTypeOf('function'));
    const debounce = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 180)); });
    fireEvent.click(screen.getByRole('radio', { name: 'sbom' })); await debounce();
    fireEvent.click(screen.getByRole('radio', { name: 'vuln' })); await debounce();
    expect(reads).toEqual(['secret', 'secret']);
    expect(activeSignal.aborted).toBe(false);
    await act(async () => finish(json(eligibility())));
    await waitFor(() => expect(screen.getByRole('button', { name: /nginx · закреплённый пример/ }).hasAttribute('disabled')).toBe(false));
    expect(reads).toEqual(['secret', 'secret', 'vuln']);
    expect((screen.getByRole('radio', { name: 'vuln' }) as HTMLInputElement).checked).toBe(true);
  });

  it('revalidates saved digest without Hub, retains four sets through readiness changes and uses historical copy', async () => {
    sessionStorage.setItem('scan-target-v1:alice', reference);
    let ready = false, now = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => now);
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
    ready = true; now += 5001; fireEvent(window, new Event('focus'));
    await waitFor(() => expect(card.hasAttribute('disabled')).toBe(false));
    fireEvent.click(screen.getByRole('radio', { name: 'Secrets + SBOM + CVE' }));
    await waitFor(() => expect((screen.getByRole('radio', { name: 'Secrets + SBOM + CVE' }) as HTMLInputElement).checked).toBe(true));
    expect(screen.getAllByRole('radio')).toHaveLength(4);
    ready = false; now += 5001; fireEvent(window, new Event('focus'));
    await waitFor(() => expect(card.hasAttribute('disabled')).toBe(true));
    expect(screen.getAllByRole('radio')).toHaveLength(4);
    expect(sessionStorage.getItem('scan-target-v1:alice')).toBe(reference);
  });

  it('rechecks before new POST but preserves exact ambiguous replay key when eligibility closes', async () => {
    const posts: Array<{ imageReference: string; checks: string[]; idempotencyKey: string }> = [];
    let ready = true, eligibilityRequests = 0, now = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => now);
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
    expect(eligibilityRequests).toBe(2);
    ready = false; now += 5001; fireEvent(window, new Event('focus'));
    await waitFor(() => expect(card.hasAttribute('disabled')).toBe(true));
    const reads = eligibilityRequests;
    fireEvent.click(screen.getByRole('button', { name: 'Запустить скан' }));
    await waitFor(() => expect(posts).toHaveLength(2));
    expect(posts[1]).toEqual(posts[0]); expect(eligibilityRequests).toBe(reads);
    expect(posts[0]).toMatchObject({ imageReference: reference, checks: ['secret'] });
  });

  for (const change of ['checks', 'target', 'consent', 'checks-back', 'target-back', 'consent-back', 'subject', 'unmount'] as const) it(`cancels pending submit after ${change}, even if eligibility later succeeds`, async () => {
    const posts: Array<{ imageReference: string; checks: string[]; idempotencyKey: string }> = [];
    let holdNext = false;
    let finish!: (value: ReturnType<typeof json>) => void;
    vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.endsWith('/images/eligibility')) {
        if (holdNext) {
          holdNext = false;
          return new Promise<ReturnType<typeof json>>(resolve => { finish = resolve; });
        }
        return json(eligibility());
      }
      if (path === '/api/v1/browser/scans' && init?.method === 'POST') {
        posts.push(JSON.parse(String(init.body)));
        return json({ scanId: id });
      }
      if (path.endsWith('/results?limit=50')) return json({ findings: [], nextCursor: null, coverage: null });
      return json({ scanId: id, state: 'queued', result: null });
    }));
    const client = mount('/scans/new', true);
    const card = await screen.findByRole('button', { name: /nginx · закреплённый пример/ });
    await waitFor(() => expect(card.hasAttribute('disabled')).toBe(false));
    fireEvent.click(card);
    const consent = screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }) as HTMLInputElement;
    fireEvent.click(consent);
    holdNext = true;
    fireEvent.click(screen.getByRole('button', { name: 'Запустить скан' }));
    await waitFor(() => expect(finish).toBeTypeOf('function'));
    if (change.startsWith('checks')) {
      fireEvent.click(screen.getByRole('radio', { name: 'sbom' }));
      if (change === 'checks-back') fireEvent.click(screen.getByRole('radio', { name: 'secret' }));
    } else if (change.startsWith('target')) {
      fireEvent.click(screen.getByRole('button', { name: /Alpine · latest/ }));
      if (change === 'target-back') fireEvent.click(card);
    } else if (change.startsWith('consent')) {
      fireEvent.click(consent);
      if (change === 'consent-back') fireEvent.click(consent);
    } else if (change === 'subject') {
      act(() => { transitionScanSession('bob', client); client.setQueryData(['demo-auth', 'me'], { id: 'bob', email: 'bob@example.com' }); });
    } else cleanup();
    await act(async () => finish(json(eligibility())));
    expect(posts).toHaveLength(0);
    if (change === 'subject' || change === 'unmount') return;
    const submit = await screen.findByRole('button', { name: 'Запустить скан' });
    if (!consent.checked) fireEvent.click(consent);
    await waitFor(() => expect(submit.hasAttribute('disabled')).toBe(false));
    fireEvent.click(submit);
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0]).toMatchObject({
      imageReference: change === 'target' ? 'registry-1.docker.io/library/alpine:latest' : reference,
      checks: change === 'checks' ? ['sbom'] : ['secret'],
    });
    expect(await screen.findByText(/ID \/ 00000000/)).toBeTruthy();
  });

  it('TASK35 rate wait spans checks, retains consent and never automatically launches or polls eligibility', async () => {
    let reads = 0, posts = 0, now = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.endsWith('/images/eligibility')) {
        if (++reads === 2 || reads === 4) return { ok: false, status: 429, headers: new Headers({ 'Retry-After': '5' }),
          json: async () => ({ errorCode: 'IMAGE_SEARCH_RATE_LIMITED', limitReason: 'rate', retryAfterSeconds: 5 }) };
        return json({ ...eligibility(), allowedCheckSets: sets });
      }
      if (init?.method === 'POST') posts++;
      return json({ scans: [], nextCursor: null });
    }));
    const client = mount('/scans/new', true);
    const card = await screen.findByRole('button', { name: /nginx · закреплённый пример/ });
    await waitFor(() => expect(card.hasAttribute('disabled')).toBe(false)); fireEvent.click(card);
    const consent = screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }) as HTMLInputElement;
    fireEvent.click(consent);
    fireEvent.click(screen.getByRole('button', { name: 'Запустить скан' }));
    await screen.findByRole('status', { name: 'Ожидание сервера' });
    expect(consent.checked).toBe(true); expect(posts).toBe(0); expect(reads).toBe(2);
    expect(card.getAttribute('aria-pressed')).toBe('true'); expect(screen.getAllByRole('radio')).toHaveLength(4);
    fireEvent.click(screen.getByRole('radio', { name: 'sbom' }));
    fireEvent(window, new Event('focus'));
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 180)); });
    expect(reads).toBe(2); expect(posts).toBe(0);
    now += 5001;
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 1050)); });
    expect(reads).toBe(2); // Expiry is not an automatic request.
    fireEvent.click(screen.getByRole('button', { name: 'Проверить допуск снова' }));
    await waitFor(() => expect(reads).toBe(3));
    await waitFor(() => expect(card.hasAttribute('disabled')).toBe(false));
    expect((screen.getByRole('radio', { name: 'sbom' }) as HTMLInputElement).checked).toBe(true);
    expect(posts).toBe(0);
    now += 5001; fireEvent(window, new Event('focus'));
    await waitFor(() => expect(reads).toBe(4));
    expect(screen.getByRole('status', { name: 'Ожидание сервера' })).toBeTruthy();
    act(() => { transitionScanSession('bob', client); client.setQueryData(['demo-auth', 'me'], { id: 'bob', email: 'bob@example.com' }); });
    await waitFor(() => expect(sessionStorage.getItem('scan-target-v1:alice')).toBeNull());
    expect(screen.queryByRole('status', { name: 'Ожидание сервера' })).toBeNull();
    expect(screen.queryByText(/Выбранная цель \(сохраняется отдельно/)).toBeNull();
  });

  for (const status of [401, 403]) it(`TASK35 auth ${status} never schedules eligibility retry`, async () => {
    let reads = 0, now = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      reads++;
      return { ok: false, status };
    }));
    mount('/scans/new', true);
    const message = status === 401 ? /Сессия недействительна/ : /Аккаунту не выдан доступ/;
    await screen.findByRole('button', { name: message });
    now += 60_001; fireEvent(window, new Event('focus'));
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 180)); });
    expect(reads).toBe(1); expect(screen.queryByRole('status', { name: 'Ожидание сервера' })).toBeNull();
  });

  it('TASK35 admission wait blocks repeat POST until manual retry, without eligibility polling', async () => {
    const posts: unknown[] = [];
    let reads = 0, now = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.endsWith('/images/eligibility')) { reads++; return json(eligibility()); }
      if (init?.method === 'POST') {
        posts.push(JSON.parse(String(init.body)));
        return { ok: false, status: 429, headers: new Headers({ 'Retry-After': '60' }), json: async () => ({ errorCode: 'SCAN_CAPACITY', retryAfterSeconds: 60 }) };
      }
      return json({ scans: [], nextCursor: null });
    }));
    mount('/scans/new', true);
    const card = await screen.findByRole('button', { name: /nginx · закреплённый пример/ });
    await waitFor(() => expect(card.hasAttribute('disabled')).toBe(false)); fireEvent.click(card);
    fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    const submit = screen.getByRole('button', { name: 'Запустить скан' }); fireEvent.click(submit);
    await screen.findByText(/Сервер пока не принимает новый запуск/);
    expect(screen.getByRole('status', { name: 'Ожидание сервера' }).textContent).toContain('Ожидание допуска запуска');
    expect(submit.hasAttribute('disabled')).toBe(true); fireEvent.click(submit);
    expect(posts).toHaveLength(1); expect(reads).toBe(2);
    now += 60_001;
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 1050)); });
    expect(posts).toHaveLength(1); expect(reads).toBe(2);
    fireEvent.click(submit); await waitFor(() => expect(posts).toHaveLength(2));
    expect(posts[1]).toEqual(posts[0]); expect(reads).toBe(2);
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
  it('TASK35 GET access fence stops disconnected polling after session rejection', async () => {
    let reads = 0;
    vi.stubGlobal('EventSource', undefined);
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      reads++;
      return reads === 1 ? json({ scanId: id, state: 'running', checks: ['sbom'], perCheck: { sbom: null }, result: null }) : { ok: false, status: 401 };
    }));
    mount(`/scans/${id}`);
    await screen.findByText(/^Оценка прогресса: ≈\d+%/);
    await screen.findByText(/Не удалось получить данные скана/, {}, { timeout: 3000 });
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 2100)); });
    expect(reads).toBe(2);
  });

  it('TASK35 SSE bursts coalesce around a slow GET; stage/checks stay authoritative and terminal closes stream', async () => {
    let emit!: (type: string, data?: unknown) => void;
    const close = vi.fn();
    vi.stubGlobal('EventSource', class {
      close = close;
      handlers = new Map<string, (event: MessageEvent) => void>();
      constructor() { emit = (type, data) => this.handlers.get(type)?.(new MessageEvent(type, { data: JSON.stringify(data) })); }
      addEventListener(type: string, handler: (event: MessageEvent) => void) { this.handlers.set(type, handler); }
    });
    let reads = 0;
    let finish!: (value: ReturnType<typeof json>) => void;
    const snapshot = (state = 'running') => ({ scanId: id, state, checks: ['secret', 'sbom'], perCheck: { secret: null, sbom: null }, result: null });
    const statusUrl = `/api/v1/browser/scans/${id}`;
    const contextUrl = `${statusUrl}/llm/context`;
    const fetchMock = vi.fn(async (path: string, _init?: RequestInit) => {
      void _init;
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path === `${statusUrl}/results?limit=50`) return json({ findings: [], nextCursor: null, coverage: null });
      if (path === contextUrl) return new Response(JSON.stringify({ errorCode: 'LLM_REPORT_UNAVAILABLE' }), {
        status: 409, headers: { 'Content-Type': 'application/json' },
      });
      if (path !== statusUrl) throw new Error(`Unexpected request: ${path}`);
      if (++reads === 2) return new Promise<ReturnType<typeof json>>(resolve => { finish = resolve; });
      return json(snapshot(reads >= 3 ? 'completed' : 'running'));
    });
    vi.stubGlobal('fetch', fetchMock);
    mount(`/scans/${id}`);
    await waitFor(() => expect(emit).toBeTypeOf('function'));
    expect(screen.getByText('Этап: не предоставлен')).toBeTruthy();
    expect(screen.getByText(/^Оценка прогресса: ≈\d+%/)).toBeTruthy();
    const pending = screen.getByRole('list', { name: 'Проверки без подтверждённого результата' });
    expect(pending.textContent).not.toContain('Пропущено');
    expect(pending.textContent).toContain('внутренний этап не предоставлен сервером');
    expect(pending.textContent).not.toContain('текущий этап указан сервером выше');
    act(() => { emit('open'); for (let index = 0; index < 20; index++) emit('scan', { scanId: id, state: 'completed', percent: null }); });
    expect(screen.getByRole('status', { name: 'Состояние realtime' }).textContent).toContain('подключён');
    await waitFor(() => expect(finish).toBeTypeOf('function'), { timeout: 2000 });
    act(() => { for (let index = 0; index < 20; index++) emit('scan', { scanId: id, state: 'completed', percent: null }); });
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 180)); });
    expect(reads).toBe(2); expect(screen.getByText(/^Оценка прогресса: ≈\d+%/)).toBeTruthy();
    act(() => emit('error'));
    expect(screen.getByRole('status', { name: 'Состояние realtime' }).textContent).toContain('переподключение');
    act(() => emit('open'));
    await act(async () => finish(json(snapshot())));
    await waitFor(() => expect(close).toHaveBeenCalled(), { timeout: 2000 });
    expect(reads).toBe(3);
    expect(fetchMock.mock.calls.filter(([path]) => path === statusUrl)).toHaveLength(3);
    await waitFor(() => expect(fetchMock.mock.calls.filter(([path, init]) => path === contextUrl && init?.method === 'GET')).toHaveLength(1));
    expect(fetchMock.mock.calls.filter(([path, init]) => path === `${statusUrl}/llm/summary` && init?.method === 'POST')).toHaveLength(0);
    expect(screen.getByRole('status', { name: 'Состояние realtime' }).textContent).toContain('realtime остановлен');
    expect(fetchMock.mock.calls.some(([path]) => path.includes('eligibility'))).toBe(false);
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
    await waitFor(() => expect(fetchMock.mock.calls.filter(([path]) => path === `/api/v1/browser/scans/${id}`).length).toBeGreaterThan(before), { timeout: 2000 });
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
      if (path.includes('/results?')) return json(reportPage(path, { findings: [], nextCursor: null, coverage: { findingCount: 0, check: 'secret', coverage: 'image', outcome: 'checked', errorCode: null, scannerVersion: null } }));
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
    expect(screen.queryByRole('button', { name: 'Отменить скан' })).toBeNull();
    expect(screen.getByText('Отмена недоступна в текущем состоянии.')).toBeTruthy();
    expect(fetchMock.mock.calls.some(([path]) => path === `/api/v1/browser/scans/${id}/results?view=report-v1&limit=25&sort=ruleId%3Aasc`)).toBe(true);
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

  for (const tag of ['3.16.9', '3.21.3']) it(`submits server-discovered Alpine ${tag} outside presets, retaining selection after pagination failure`, async () => {
    const reference = `registry-1.docker.io/library/alpine:${tag}`;
    const posts: Array<{ imageReference: string; scope: string; checks: string[]; idempotencyKey: string }> = [];
    vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('/images?')) {
        if (path.includes('cursor=')) return { ok: false, status: 503 };
        return json(imagePage([{ label: `Alpine · ${tag}`, reference, scannable: true }], 'a'.repeat(48)));
      }
      if (path === '/api/v1/browser/scans' && init?.method === 'POST') {
        posts.push(JSON.parse(String(init.body)));
        return json({ scanId: id });
      }
      if (path.endsWith('/results?limit=50')) return json({ findings: [], nextCursor: null, coverage: null });
      return json({ scanId: id, state: 'queued', result: null });
    }));
    mount('/scans/new');
    fireEvent.change(await screen.findByRole('searchbox'), { target: { value: `alpine ${tag}` } });
    fireEvent.click(await screen.findByRole('button', { name: new RegExp(`Alpine · ${tag.replaceAll('.', '\\.')}`) }));
    fireEvent.click(screen.getByRole('button', { name: 'Показать ещё' }));
    await screen.findByText(/Поиск Docker Hub сейчас недоступен/);
    fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Запустить скан' }));
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0]).toEqual({ imageReference: reference, scope: 'image', checks: ['secret'], idempotencyKey: expect.any(String) });
    expect(posts[0].idempotencyKey).toMatch(/^[a-f0-9-]{36}$/);
    expect(await screen.findByText(/ID \/ 00000000/)).toBeTruthy();
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
    expect(screen.getByRole('checkbox', { name: /Host · отдельный opt-in не подключён/ }).hasAttribute('disabled')).toBe(true);
    fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Запустить скан' }));
    await waitFor(() => expect(posts).toEqual([['secret', 'sbom', 'vuln']]));
    expect((await within(screen.getByRole('form', { name: 'Параметры скана' })).findByRole('alert')).textContent).toMatch(/база уязвимостей не настроена или недоступна/);
    expect(screen.queryByText(/0 CVE/)).toBeNull();
  });
  it('renders independent partial outcomes and paginates subject-scoped CVE findings', async () => {
    const secret = { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 0, scannerVersion: '0.69.3', errorCode: null };
    const failedSbom = { check: 'sbom', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_TIMEOUT' };
    const checkedVuln = { check: 'vuln', coverage: 'image', outcome: 'checked', findingCount: 6, scannerVersion: '0.69.3', checkedAt: 'today' };
    const finding = (n: number) => ({ findingId: `vuln-${n}`, cveId: `CVE-2026-${n}`, ecosystem: 'apk', packageName: 'busybox', installedVersion: '1', severity: 'HIGH', fixedVersion: null });
    const fetchMock = vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('/results?')) return json(reportPage(path, { findings: [], nextCursor: null, coverage: secret }));
      if (path.includes('/sbom?')) return json(reportPage(path, { outcome: 'failed', coverage: 'image', reason: 'SCAN_TIMEOUT', errorCode: 'SCAN_TIMEOUT', components: [], nextCursor: null }));
      if (path.includes('/vuln?')) return json(reportPage(path, { outcome: 'checked', coverage: 'image', image: `registry-1.docker.io/library/alpine@${digest}`, platform: 'linux/amd64', findingCount: 6, scannerVersion: '0.69.3', checkedAt: 'today', findings: Array.from({ length: 6 }, (_, index) => finding(index + 1)), nextCursor: null }));
      return json({ scanId: id, state: 'partial', digest, platform: 'linux/amd64', checks: ['secret', 'sbom', 'vuln'], perCheck: { secret, sbom: failedSbom, vuln: checkedVuln }, result: null });
    });
    vi.stubGlobal('fetch', fetchMock);
    mount(`/scans/${id}`);
    await expectCve('CVE-2026-1');
    expect(screen.getByText(/SBOM не проверен: SCAN_TIMEOUT/)).toBeTruthy();
    expect(screen.getByText(/Находок в проверенной области: 6/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Строк на странице · CVE'), { target: { value: '5' } });
    await screen.findByText('Строки 1–5');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE · сверху' }));
    await expectCve('CVE-2026-6');
    expect(fetchMock.mock.calls.some(([path]) => path === `/api/v1/browser/scans/${id}/vuln?view=report-v1&limit=5&sort=severity%3Adesc&cursor=fixture%3A5`)).toBe(true);
  });
  it.each(['partial', 'failed'])('renders DB_UNAVAILABLE and unknown CVE count for %s and remount', async state => {
    const failed = { check: 'vuln', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_FAILED', reason: 'DB_UNAVAILABLE', checksVersion: 'trivy-0.69.3-archive-v1', scannerVersion: '0.69.3', checkedAt: '2026-10-06T16:00:00.000Z' };
    const secret = { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 0, scannerVersion: '0.69.3', errorCode: null };
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('/vuln?')) return json(reportPage(path, { outcome: 'failed', coverage: 'image', errorCode: 'SCAN_FAILED', reason: 'DB_UNAVAILABLE', findings: [], nextCursor: null }));
      if (path.includes('/results?')) return json(reportPage(path, { findings: [], nextCursor: null, coverage: secret }));
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
      if (path.includes('/vuln?')) return json(reportPage(path, { outcome: 'checked', coverage: 'image', image: `registry-1.docker.io/library/alpine@sha256:${'b'.repeat(64)}`, platform: 'linux/amd64', findingCount: 0, scannerVersion: '0.69.3', checkedAt: 'today', findings: [], nextCursor: null }));
      return json({ scanId: id, state: 'completed', digest, platform: 'linux/amd64', checks: ['vuln'], perCheck: { vuln: checkedVuln }, result: checkedVuln });
    }));
    mount(`/scans/${id}`);
    expect(await screen.findByText(/Идентичность или версия отчёта изменилась/)).toBeTruthy();
        expect(screen.queryByText(/Полный итог CVE/)).toBeNull();
        expect(screen.queryByRole('navigation', { name: /Пагинация CVE/ })).toBeNull();
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
    expect(await screen.findByText(/Не удалось подтвердить страницу CVE/)).toBeTruthy();
        expect(screen.getByText('Число CVE неизвестно до подтверждения выполненной проверки.')).toBeTruthy();
        expect(screen.getByRole('button', { name: 'Повторить загрузку CVE' })).toBeTruthy();
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
    const checked = { outcome: 'checked', coverage: 'image', image: `registry-1.docker.io/library/alpine@${digest}`, platform: 'linux/amd64', os: { name: 'alpine', version: '3.21' }, componentCount: 6, scannerVersion: '0.69.3', checkedAt: '2026-01-01', components: ['busybox', 'lib-a', 'lib-b', 'lib-c', 'lib-d', 'musl'].map(name => ({ ecosystem: 'apk', name, version: '1' })), nextCursor: null };
    let failed = false;
    const fetchMock = vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('/sbom?')) return json(reportPage(path, failed ? { coverage: 'image', outcome: 'failed', reason: 'SCAN_TIMEOUT', errorCode: 'SCAN_TIMEOUT', components: [], nextCursor: null } : checked));
      return json({ scanId: id, digest, platform: 'linux/amd64', state: 'completed', result: failed ? { check: 'sbom', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_TIMEOUT' } : { check: 'sbom', coverage: 'image', outcome: 'checked', componentCount: 6, scannerVersion: '0.69.3', checkedAt: '2026-01-01' } });
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = mount(`/scans/${id}`);
    expect(await screen.findByText('busybox')).toBeTruthy();
    expect(screen.getByText(/ОС alpine 3.21/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Строк на странице · SBOM'), { target: { value: '5' } });
    await screen.findByText('Строки 1–5');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · SBOM · сверху' }));
    expect(await screen.findByText('musl')).toBeTruthy();
    expect(screen.getByText('Строки 6–6')).toBeTruthy();
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
    await waitFor(() => expect(within(screen.getByRole('form', { name: 'Параметры скана' })).getByRole('alert')).toHaveProperty('textContent', 'Сервер отклонил цель или параметры сканирования. Скан не создан.'));
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

describe('durable cancellation detail', () => {
  it.each(['button', 'SSE'] as const)('refreshes the authoritative snapshot after %s, preserves checkpoints and stops realtime', async mode => {
    let cancelled = false;
    let emit: (value: unknown) => void = () => {};
    const close = vi.fn();
    vi.stubGlobal('EventSource', class {
      close = close;
      addEventListener(name: string, handler: (event: { data: string }) => void) {
        if (name === 'scan') emit = value => handler({ data: JSON.stringify(value) });
      }
    });
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    const secret = { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 1, errorCode: null, scannerVersion: '0.69.3' };
    const calls: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
      calls.push(path);
      if (path === '/api/v1/auth/me') return json({ id: 'cancel-owner', email: 'cancel@example.com' });
      if (path.endsWith('/cancel')) {
        expect(init?.method).toBe('POST'); expect(init?.body).toBe('{}');
        cancelled = true;
        return json({ scanId: id, state: 'cancelled' });
      }
      if (path.includes('/results?')) return json(reportPage(path, { findings: [{ findingId: 'saved-secret', ruleId: 'saved-rule', line: 0, evidenceRef: 'redacted-ref' }], coverage: secret, nextCursor: null }));
      if (path === `/api/v1/browser/scans/${id}`) return json({ scanId: id, state: cancelled ? 'cancelled' : 'running',
        digest, platform: 'linux/amd64', checks: ['secret', 'sbom', 'vuln'],
        perCheck: { secret: cancelled ? secret : null, sbom: null, vuln: null }, result: null });
      return new Response('{}', { status: 404 });
    }));
    let client = mount(`/scans/${id}`);
    await screen.findByRole('button', { name: 'Отменить скан' });
    if (mode === 'button') fireEvent.click(screen.getByRole('button', { name: 'Отменить скан' }));
    else {
      // An event is only a hint: a false terminal hint cannot publish coverage.
      act(() => emit({ scanId: id, state: 'cancelled', percent: null }));
      expect(screen.queryByText('ID: saved-secret')).toBeNull();
      cancelled = true;
      act(() => emit({ scanId: id, state: 'cancelled', percent: null }));
    }
    await screen.findByText('ID: saved-secret', {}, { timeout: 3000 });
    expect(screen.getByText(/Сканирование отменено\. Сохранены результаты завершённых проверок/)).toBeTruthy();
    expect(screen.getByText('Скан отменён; realtime остановлен')).toBeTruthy();
    expect(screen.getAllByText(/завершённый результат не сохранён/)).toHaveLength(2);
    expect(screen.queryByText(/без публикации промежуточных результатов/)).toBeNull();
    expect(screen.queryByRole('button', { name: 'Отменить скан' })).toBeNull();
    await waitFor(() => expect(close).toHaveBeenCalledTimes(1));
    expect(calls.some(path => /\/(sbom|vuln)\?/.test(path))).toBe(false);
    cleanup(); client.clear();
    client = mount(`/scans/${id}`);
    await screen.findByText('ID: saved-secret');
    expect(screen.getByText(/Сканирование отменено\. Сохранены результаты/)).toBeTruthy();
    cleanup(); client.clear();
  });
  it('states honestly that cancellation without checkpoints saved no completed results', async () => {
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'cancel-owner', email: 'cancel@example.com' });
      if (path === `/api/v1/browser/scans/${id}`) return json({ scanId: id, state: 'cancelled', checks: ['secret', 'sbom', 'vuln'],
        perCheck: { secret: null, sbom: null, vuln: null }, result: null });
      return new Response('{}', { status: 404 });
    }));
    const client = mount(`/scans/${id}`);
    await screen.findByText(/Сканирование отменено\. Сохранённых результатов завершённых проверок нет/);
    expect(screen.getAllByText(/завершённый результат не сохранён/)).toHaveLength(3);
    expect(screen.queryByText(/Полный итог|0 CVE|0 находок/)).toBeNull();
    cleanup(); client.clear();
  });
});

describe('Stage2 unified Findings detail', () => {
  const image = `registry-1.docker.io/library/alpine@${digest}`;
  const checkedAt = '2026-10-07T08:00:00.000Z';
  const source = (name: string, severity = 'HIGH') => ({ source: name, provenanceRef: `target-${'a'.repeat(64)}`,
    title: { value: 'Bounds: 1 < 2 & 3 > 2', state: 'available', redacted: false },
    description: { value: 'Safe source text', state: 'truncated', redacted: true }, language: null, severity, fixedVersion: null,
    cvss: { family: 'v3', version: '3.1', versionState: 'available', reportedScore: 0, scoreState: 'available', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', vectorState: 'available' } });
  const finding = (n: number, advisory = true) => ({ findingId: `vuln-${n}`, cveId: `CVE-2026-${String(n).padStart(4, '0')}`, ecosystem: 'apk', packageName: `package-${n}`, installedVersion: '1', severity: 'HIGH', fixedVersion: null,
    severitySources: ['alpine'], provenanceRef: `target-${'a'.repeat(64)}`,
    ...(advisory ? { advisory: { schemaVersion: 1, state: 'available', assessments: [source('alpine'), source('nvd', 'LOW')], references: [], conflicts: ['severity'], conflictState: 'present', limitations: ['redaction', 'field_limit'] } } : {}) });
  const vulnPage = (path: string, count = 51, advisory = false) => reportPage(path, { outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64', findingCount: count,
    scannerVersion: '0.69.3', checkedAt, findings: Array.from({ length: count }, (_, n) => finding(n + 1, advisory)), nextCursor: null });
  const secret = (count: number) => ({ check: 'secret', coverage: 'image', outcome: 'checked', findingCount: count, scannerVersion: '0.69.3', errorCode: null });
  const secretPage = (path: string, count = 52) => reportPage(path, { findings: Array.from({ length: count }, (_, n) => ({ findingId: `secret-${n + 1}`, ruleId: `secret-rule-${n + 1}`, line: 1, evidenceRef: 'redacted' })), nextCursor: null, coverage: secret(count) });
  const status = (checks = ['secret', 'vuln'], scanId = id, secrets = 52, cves = 51) => ({ scanId, state: 'completed', digest, platform: 'linux/amd64', checks,
    perCheck: { ...(checks.includes('secret') ? { secret: secret(secrets) } : {}), ...(checks.includes('vuln') ? { vuln: { check: 'vuln', coverage: 'image', outcome: 'checked', findingCount: cves, scannerVersion: '0.69.3', checkedAt } } : {}) }, result: null });

  it('shows CVE-only cards in the single visible Findings section, escaped source rows and explicit safe links without external requests', async () => {
    // Less-than/plain ampersand remain text; no HTML, Markdown or source URL rendering.
    const f = finding(1234);
    f.advisory!.assessments.forEach(item => { item.title.value = 'Bounds 1 < 2 & comparison'; });
    const user = userEvent.setup();
    const writeText = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue();
    const requests: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      requests.push(path);
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('/vuln?')) return json({ ...vulnPage(path, 1), findings: [f] });
      return json(status(['vuln'], id, 0, 1));
    }));
    mount(`/scans/${id}`);
    const row = await expectCve('CVE-2026-1234');
    fireEvent.click(row.getByText('Подробности CVE-2026-1234 · описание, CVSS и ссылки'));
    const findings = screen.getByRole('region', { name: 'Результаты проверок' });
    expect(screen.getAllByRole('heading', { name: 'Результаты проверок' })).toHaveLength(1);
    expect(within(findings).getAllByText(/Bounds 1 < 2 & comparison/)).toHaveLength(2);
    expect(within(findings).getAllByText(/Язык источника: не указан/)).toHaveLength(2);
    expect(within(findings).getByText(/Источники расходятся: severity/)).toBeTruthy();
    expect(within(findings).getAllByText(/оценка источника: 0/)).toHaveLength(2);
    expect(within(findings).getAllByText(/Текст сокращён/)).toHaveLength(2);
    expect(within(findings).getByText(/наличие записи и её содержимое не проверены/)).toBeTruthy();
    expect(within(findings).getByText(/Проверенный русский источник/)).toBeTruthy();
    const links = within(findings).getAllByRole('link');
    expect(links.map(link => link.getAttribute('href'))).toEqual(['https://www.cve.org/CVERecord?id=CVE-2026-1234', 'https://nvd.nist.gov/vuln/detail/CVE-2026-1234', 'https://www.first.org/cvss/calculator/3.1']);
    for (const link of links) {
      expect(link.getAttribute('rel')).toBe('noopener noreferrer');
      expect(link.getAttribute('target')).toBe('_blank');
      expect(link.getAttribute('referrerpolicy')).toBe('no-referrer');
      fireEvent.mouseOver(link);
    }
    expect(findings.querySelector('img, iframe, script')).toBeNull();
    expect(requests.every(path => path.startsWith('/api/v1/'))).toBe(true);
    expect(requests.some(path => path.includes('/results?'))).toBe(false);
    await user.click(within(findings).getAllByRole('button', { name: 'Копировать вектор CVSS 3.1' })[0]);
    expect(writeText).toHaveBeenCalledWith(f.advisory!.assessments[0].cvss.vector);
    expect(await within(findings).findByText('Вектор скопирован')).toBeTruthy();
    writeText.mockRestore();
  });

  it('keeps independent cursors for >50 rows and totals across actual all/CVE/Secrets filters', async () => {
    const requests: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      requests.push(path);
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('/vuln?')) return json(vulnPage(path));
      if (path.includes('/results?')) return json(secretPage(path));
      return json(status());
    }));
    mount(`/scans/${id}`);
    await expectCve('CVE-2026-0001');
    await screen.findByText('secret-rule-1');
    for (const [label, region] of [['CVE', 'Результаты CVE'], ['Secrets', 'Результаты Secrets']]) {
      fireEvent.change(screen.getByLabelText(`Строк на странице · ${label}`), { target: { value: '50' } });
      await within(screen.getByRole('region', { name: region })).findByText('Строки 1–50');
    }
    fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE · сверху' }));
    await expectCve('CVE-2026-0051');
    expect(screen.getByText('secret-rule-1')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Далее · Secrets · сверху' }));
    await screen.findByText('secret-rule-51');
    const beforeFilter = requests.length;
    fireEvent.change(screen.getByRole('combobox', { name: 'Категория' }), { target: { value: 'cve' } });
    expect(screen.queryByRole('region', { name: 'Результаты Secrets' })).toBeNull();
    expect(screen.getByRole('region', { name: 'Результаты CVE' })).toBeTruthy();
    expect(screen.getByText('CVE-2026-0051', { selector: '.scan-vuln-row__id' })).toBeTruthy();
    fireEvent.change(screen.getByRole('combobox', { name: 'Категория' }), { target: { value: 'secret' } });
    expect(screen.queryByRole('region', { name: 'Результаты CVE' })).toBeNull();
    expect(screen.getByRole('region', { name: 'Результаты Secrets' })).toBeTruthy();
    expect(screen.getByText('secret-rule-51')).toBeTruthy();
    fireEvent.change(screen.getByRole('combobox', { name: 'Категория' }), { target: { value: 'all' } });
    expect(screen.getByText('CVE-2026-0051', { selector: '.scan-vuln-row__id' })).toBeTruthy();
    expect(screen.getByText('Полный итог CVE: 51')).toBeTruthy();
    expect(screen.getByText('Полный итог Secrets: 52')).toBeTruthy();
    expect(document.body.textContent).not.toContain('103');
    expect(requests).toHaveLength(beforeFilter);
  });

  it('renders Secrets checked zero alongside CVE without substituting a combined zero', async () => {
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('/vuln?')) return json(vulnPage(path, 1));
      if (path.includes('/results?')) return json(secretPage(path, 0));
      return json(status(['secret', 'vuln'], id, 0, 1));
    }));
    mount(`/scans/${id}`);
    await expectCve('CVE-2026-0001');
    await screen.findByText('Полный итог Secrets: 0');
    expect(screen.getByText(/0 находок в выполненной проверенной области Secrets/)).toBeTruthy();
    expect(screen.getByText(/исторический отчёт без advisory/)).toBeTruthy();
    expect(screen.queryByRole('link', { name: /FIRST/ })).toBeNull();
  });

  it('retains confirmed totals on independent later-page failures, without hiding the other dataset', async () => {
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (new URL(path, window.location.origin).searchParams.has('cursor')) return { ok: false, status: 503, json: async () => ({}) };
      if (path.includes('/vuln?')) return json(vulnPage(path));
      if (path.includes('/results?')) return json(secretPage(path));
      return json(status());
    }));
    mount(`/scans/${id}`);
    await expectCve('CVE-2026-0001');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE · сверху' }));
    await within(screen.getByRole('region', { name: 'Результаты CVE' })).findByText(/Показана предыдущая подтверждённая страница/);
    expect(screen.getByText('Полный итог CVE: 51')).toBeTruthy();
    expect(screen.getByText('secret-rule-1')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Далее · Secrets · сверху' }));
    await within(screen.getByRole('region', { name: 'Результаты Secrets' })).findByText(/Показана предыдущая подтверждённая страница/);
    expect(screen.getByText('Полный итог Secrets: 52')).toBeTruthy();
  });

  it('keeps unknown schema and nonchecked Secrets outcomes unknown, with no raw fallback', async () => {
    const failed = { check: 'secret', coverage: 'image', outcome: 'failed', findingCount: null, scannerVersion: '0.69.3', errorCode: 'SCAN_FAILED' };
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('/vuln?')) return json({ ...vulnPage(path, 1), findings: [{ ...finding(1), advisory: { schemaVersion: 99, raw: 'DO_NOT_RENDER_RAW' } }] });
      if (path.includes('/results?')) return json(reportPage(path, { findings: [], nextCursor: null, coverage: failed }));
      const snapshot = status(['secret', 'vuln'], id, 0, 1);
            return json({ ...snapshot, perCheck: { ...snapshot.perCheck, secret: failed } });
    }));
    mount(`/scans/${id}`);
    await within(await screen.findByRole('region', { name: 'Результаты CVE' })).findByText(/Прежние данные и cursors сброшены/);
    expect(screen.getByText('Число Secrets неизвестно до подтверждения выполненной проверки.')).toBeTruthy();
    expect(document.body.textContent).not.toContain('DO_NOT_RENDER_RAW');
    expect(screen.queryByText(/Полный итог CVE:|Полный итог Secrets:/)).toBeNull();
    expect(screen.queryByText(/0 находок/)).toBeNull();
  });

  it.each(['subject', 'session', 'route'] as const)('resets filters and all cursors and discards a pending CVE page after %s changes', async change => {
    const nextId = '00000000-0000-4000-8000-000000000002';
    let changed = false;
    let pendingPath = '';
    let finish!: (value: ReturnType<typeof json>) => void;
    const requests: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      requests.push(path);
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.includes('/vuln?') && new URL(path, window.location.origin).searchParams.has('cursor')) {
        pendingPath = path;
        return new Promise<ReturnType<typeof json>>(resolve => { finish = resolve; });
      }
      if (path.includes('/vuln?')) return json(vulnPage(path, changed ? 1 : 51));
      if (path.includes('/results?')) return json(secretPage(path, changed ? 1 : 52));
      return json(status(['secret', 'vuln'], path.includes(nextId) ? nextId : id, changed ? 1 : 52, changed ? 1 : 51));
    }));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/scans/${id}`]}>
      <Link to={`/scans/${nextId}`}>Другой скан</Link>
      <Routes><Route path="/scans/:scanId" element={<LiveScanSession><ScanDetailPage /></LiveScanSession>} /></Routes>
    </MemoryRouter></QueryClientProvider>);
    await expectCve('CVE-2026-0001');
    fireEvent.change(screen.getByLabelText('Строк на странице · Secrets'), { target: { value: '50' } });
    await within(screen.getByRole('region', { name: 'Результаты Secrets' })).findByText('Строки 1–50');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · Secrets · сверху' }));
    await screen.findByText('secret-rule-51');
    fireEvent.click(screen.getByRole('button', { name: 'Далее · CVE · сверху' }));
    await waitFor(() => expect(finish).toBeTypeOf('function'));
    fireEvent.change(screen.getByRole('combobox', { name: 'Категория' }), { target: { value: 'secret' } });
    changed = true;
    const boundary = requests.length;
    if (change === 'route') fireEvent.click(screen.getByRole('link', { name: 'Другой скан' }));
    else act(() => {
      const subject = change === 'subject' ? 'bob' : 'alice';
      transitionScanSession(subject, client, change === 'session');
      client.setQueryData(['demo-auth', 'me'], { id: subject, email: `${subject}${change === 'session' ? '+renewed' : ''}@example.com` });
    });
    await screen.findByText('Полный итог CVE: 1');
    expect((screen.getByRole('combobox', { name: 'Категория' }) as HTMLSelectElement).value).toBe('all');
    expect(screen.getByText('secret-rule-1')).toBeTruthy();
    await act(async () => finish(json(vulnPage(pendingPath))));
    expect(screen.queryByText('CVE-2026-0026', { selector: '.scan-vuln-row__id' })).toBeNull();
    expect(screen.queryByText('secret-rule-51')).toBeNull();
    expect(screen.getByText('Полный итог CVE: 1')).toBeTruthy();
    expect(screen.queryByRole('navigation', { name: /Пагинация CVE/ })).toBeNull();
    expect(requests.slice(boundary).some(path => path.includes('cursor='))).toBe(false);
  });
});
