import '@testing-library/jest-dom/vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LiveScanSession } from '@/features/scans/LiveScanSession';
import { DemoAuthPage } from '@/pages/auth/DemoAuthPage';
import { ScanCreatePage } from '@/pages/scans/ScanCreatePage';
import { ScanListPage } from '@/pages/scans/ScanListPage';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { readPendingCreateIntent, rememberPendingCreateIntent } from '@/shared/api/scans/pendingCreateIntent';

const owner = { id: 'recovery-owner', email: 'recovery@example.invalid' };
const scanId = '00000000-0000-4000-8000-000000000061';
const reportPath = `/scans/${scanId}`;
const reference = 'registry-1.docker.io/library/nginx@sha256:0dcc88822d45581e65ae329f8be769762bf628d3b2bb7d2a077d4aa5c98b30e3';
const sets = [['secret'], ['sbom'], ['vuln'], ['secret', 'sbom', 'vuln']];
const clients: QueryClient[] = [];
const reply = (status: number, body: unknown = {}) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json' },
});
const eligibility = (target = reference, publicProfile = false) => ({
  imageReference: target, eligible: true, reason: 'READY',
  eligibility: publicProfile ? 'public-hub-profile' : 'qualified-exact-profile',
  allowedCheckSets: publicProfile ? [['secret'], ['secret', 'sbom', 'vuln', 'config']] : sets,
  ...(!publicProfile ? { qualificationId: 'nginx-local-0dcc-v1' } : {}),
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
function LocationProbe() {
  const location = useLocation();
  return <output aria-label="Current route">{location.pathname}{location.search}{location.hash}</output>;
}
function mount(path: string, state?: object) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[{ pathname: path, state }]}>
    <LocationProbe />
    <Routes>
      <Route path="/account" element={<DemoAuthPage mode="account" />} />
      <Route path="/login" element={<DemoAuthPage mode="login" />} />
      <Route path="/scans" element={<LiveScanSession><ScanListPage /></LiveScanSession>} />
      <Route path="/scans/new" element={<LiveScanSession><ScanCreatePage /></LiveScanSession>} />
      <Route path="/scans/:scanId" element={<LiveScanSession><p>Private report boundary</p></LiveScanSession>} />
    </Routes>
  </MemoryRouter></QueryClientProvider>);
  return client;
}
const pause = (ms = 220) => act(async () => { await new Promise(resolve => setTimeout(resolve, ms)); });
function installFetch(handler: (path: string, init?: RequestInit) => Response | Promise<Response>) {
  const mock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    if (typeof input !== 'string' || !input.startsWith('/api/v1/')) throw new Error('Unexpected test request');
    if (input.startsWith('/api/v1/browser/runtime/')) return Promise.resolve(reply(404));
    return Promise.resolve(handler(input, init));
  });
  vi.stubGlobal('fetch', mock);
  return mock;
}
beforeEach(() => {
  localStorage.clear(); sessionStorage.clear();
  vi.stubGlobal('IntersectionObserver', class { observe() {} unobserve() {} disconnect() {} });
});
afterEach(() => {
  cleanup();
  for (const client of clients.splice(0)) { transitionScanSession(null, client, true); client.clear(); }
  vi.restoreAllMocks(); vi.unstubAllGlobals();
  localStorage.clear(); sessionStorage.clear();
});

describe('batch4 regression: optional scan target storage', () => {
  it('failed optional storage read preserves the exact owner-bound pending key and still requires manual fresh eligibility plus new consent', async () => {
    const user = userEvent.setup();
    const target = 'registry-1.docker.io/library/node:22.14.0-alpine3.21';
    const posts: Array<{ imageReference: string; checks: string[]; idempotencyKey: string }> = [];
    let reads = 0;
    installFetch((path, init) => {
      if (path === '/api/v1/auth/me') return reply(200, owner);
      if (path.endsWith('/images/eligibility')) {
        reads++; return reply(200, eligibility(JSON.parse(String(init?.body)).imageReference, true));
      }
      if (path === '/api/v1/browser/scans' && init?.method === 'POST') {
        posts.push(JSON.parse(String(init.body))); return reply(202, { scanId });
      }
      throw new Error(`Unexpected request: ${path}`);
    });
    mount('/scans/new');
    await screen.findByRole('form', { name: 'Параметры скана' });
    expect(reads).toBe(0);
    const pending = { target, checks: 'secret', key: 'storage-preserved-idempotency-key' };
    expect(rememberPendingCreateIntent(scanSession(), pending)).toBe(true);
    cleanup();
    const storage = window.sessionStorage, get = Storage.prototype.getItem;
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(function(this: Storage, key: string) {
      if (this === storage && key.startsWith('scan-target-v1:')) throw new DOMException('Optional storage unavailable', 'SecurityError');
      return get.call(this, key);
    });
    mount('/scans/new');
    const form = await screen.findByRole('form', { name: 'Параметры скана' });
    expect(within(form).getByLabelText('Адрес образа в Docker Hub')).toHaveValue(target);
    expect(readPendingCreateIntent(scanSession())).toEqual(pending);
    expect(readPendingCreateIntent({ subject: 'other-owner', generation: scanSession().generation })).toBeNull();
    const consent = within(form).getByRole('checkbox', { name: /Подтверждаю выбранную цель/ });
    expect(consent).not.toBeChecked();
    const before = reads;
    fireEvent.focus(window); fireEvent.online(window); await pause();
    expect(reads).toBe(before); expect(posts).toHaveLength(0);
    await user.click(consent);
    expect(within(form).getByRole('button', { name: 'Запустить проверку' })).toBeDisabled();
    await user.click(consent);
    await user.click(within(form).getByRole('button', { name: 'Проверить допуск снова' }));
    await waitFor(() => expect(reads).toBe(before + 1));
    await waitFor(() => expect(within(form).getByRole('button', { name: 'Проверить допуск снова' })).toBeEnabled());
    expect(consent).not.toBeChecked();
    await user.click(consent);
    const launch = within(form).getByRole('button', { name: 'Запустить проверку' });
    await waitFor(() => expect(launch).toBeEnabled()); await user.click(launch);
    await screen.findByText('Private report boundary');
    expect(posts).toEqual([{ imageReference: target, checks: ['secret'], scope: 'image', idempotencyKey: pending.key }]);
    expect(reads).toBe(before + 2);
    expect(readPendingCreateIntent(scanSession())).toBeNull();
  });
  it.each(['getItem', 'removeItem'] as const)('%s failure leaves the private create form usable without granting intent/consent', async method => {
    const storage = window.sessionStorage;
    if (method === 'removeItem') storage.setItem(`scan-target-v1:${owner.id}`, 'invalid-saved-target');
    const original = { getItem: Storage.prototype.getItem, removeItem: Storage.prototype.removeItem };
    vi.spyOn(Storage.prototype, method).mockImplementation(function(this: Storage, key: string) {
      if (this === storage && key.startsWith('scan-target-v1:')) throw new DOMException('Optional storage unavailable', 'SecurityError');
      return method === 'getItem' ? original.getItem.call(this, key) : original.removeItem.call(this, key);
    });
    const fetchMock = installFetch((path, init) => {
      if (path === '/api/v1/auth/me') return reply(200, owner);
      if (path.endsWith('/images/eligibility')) return reply(200, eligibility(JSON.parse(String(init?.body)).imageReference));
      throw new Error(`Unexpected request: ${path}`);
    });
    expect(() => mount('/scans/new')).not.toThrow();
    const form = await screen.findByRole('form', { name: 'Параметры скана' });
    expect(within(form).getByLabelText('Адрес образа в Docker Hub')).toBeEnabled();
    expect(within(form).getByRole('checkbox', { name: /Подтверждаю выбранную цель/ })).not.toBeChecked();
    expect(within(form).getByRole('button', { name: 'Запустить проверку' })).toBeDisabled();
    expect(fetchMock.mock.calls.some(([path, init]) => path === '/api/v1/browser/scans' && init?.method === 'POST')).toBe(false);
    if (method === 'getItem') {
      fireEvent.change(within(form).getByRole('searchbox'), { target: { value: 'node' } });
      fireEvent.change(within(form).getByRole('searchbox'), { target: { value: '' } });
      expect(screen.getByRole('form', { name: 'Параметры скана' })).toBe(form);
    }
  });

  it('setItem failure cannot interrupt selecting the pinned target or create launch authority', async () => {
    const user = userEvent.setup();
    const storage = window.sessionStorage;
    const original = Storage.prototype.setItem;
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(function(this: Storage, key: string, value: string) {
      if (this === storage && key.startsWith('scan-target-v1:')) throw new DOMException('Optional storage unavailable', 'QuotaExceededError');
      return original.call(this, key, value);
    });
    const fetchMock = installFetch((path, init) => {
      if (path === '/api/v1/auth/me') return reply(200, owner);
      if (path.endsWith('/images/eligibility')) return reply(200, eligibility(JSON.parse(String(init?.body)).imageReference));
      throw new Error(`Unexpected request: ${path}`);
    });
    mount('/scans/new');
    const form = await screen.findByRole('form', { name: 'Параметры скана' });
    fireEvent.click(within(form).getByText('Указать адрес вручную'));
    fireEvent.click(within(form).getByText('Сохранённый пример для прежнего профиля'));
    const card = await within(form).findByRole('button', { name: /Выбрать закреплённый nginx/ });
    await waitFor(() => expect(card).toBeEnabled());
    await user.click(card);
    expect(within(form).getByLabelText('Адрес образа в Docker Hub')).toHaveValue(reference);
    expect(within(form).getByRole('checkbox', { name: /Подтверждаю выбранную цель/ })).not.toBeChecked();
    expect(within(form).getByRole('button', { name: 'Запустить проверку' })).toBeDisabled();
    expect(fetchMock.mock.calls.some(([path, init]) => path === '/api/v1/browser/scans' && init?.method === 'POST')).toBe(false);
    expect(screen.getByRole('form', { name: 'Параметры скана' })).toBe(form);
  });
});

describe('submitted scan intent stays immutable until receipt', () => {
  it.each(['local radios', 'public checkboxes'])('disables every target/check/consent control and keeps the receipt: %s', async profile => {
    const user = userEvent.setup();
    const pending = deferred<Response>();
    const posts: unknown[] = [];
    const publicProfile = profile === 'public checkboxes';
    const target = publicProfile ? 'registry-1.docker.io/library/node:22.14.0-alpine3.21' : reference;
    installFetch((path, init) => {
      if (path === '/api/v1/auth/me') return reply(200, owner);
      if (path.endsWith('/images/eligibility')) return reply(200, eligibility(JSON.parse(String(init?.body)).imageReference, publicProfile));
      if (path === '/api/v1/browser/scans' && init?.method === 'POST') {
        posts.push(JSON.parse(String(init.body))); return pending.promise;
      }
      throw new Error(`Unexpected request: ${path}`);
    });
    if (!publicProfile) sessionStorage.setItem('scan-target-v1:recovery-owner', reference);
    mount('/scans/new');
    const form = await screen.findByRole('form', { name: 'Параметры скана' });
    if (publicProfile) {
      fireEvent.click(within(form).getByText('Указать адрес вручную'));
      await user.type(within(form).getByLabelText('Адрес образа в Docker Hub'), target);
      await within(form).findByText('Сервер разрешает выбранные проверки. Перед запуском проверим доступность ещё раз.');
    } else {
      fireEvent.click(within(form).getByText('Указать адрес вручную'));
    fireEvent.click(within(form).getByText('Сохранённый пример для прежнего профиля'));
    const card = await within(form).findByRole('button', { name: /Выбрать закреплённый nginx/ });
      await waitFor(() => expect(card).toBeEnabled());
      await user.click(card);
      await within(form).findByRole('radio', { name: 'Состав пакетов (SBOM)' });
    }
    const consent = within(form).getByRole('checkbox', { name: /Подтверждаю выбранную цель/ });
    await user.click(consent);
    const launch = within(form).getByRole('button', { name: 'Запустить проверку' });
    await waitFor(() => expect(launch).toBeEnabled());
    await user.click(launch);
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(screen.getByLabelText('Current route')).toHaveTextContent('/scans/new');
    expect(launch).toBeDisabled();
    for (const control of form.querySelectorAll('input, select, textarea, button')) {
      expect(control, control.getAttribute('id') ?? control.textContent ?? 'form control').toBeDisabled();
    }
    const submitted = JSON.stringify(posts[0]);
    await user.click(consent);
    await user.type(within(form).getByLabelText('Адрес образа в Docker Hub'), ':changed');
    for (const control of within(form).queryAllByRole(publicProfile ? 'checkbox' : 'radio')) await user.click(control);
    await user.dblClick(launch);
    fireEvent.submit(form);
    await pause();
    expect(posts).toHaveLength(1);
    expect(JSON.stringify(posts[0])).toBe(submitted);
    expect(consent).toBeChecked();
    expect(within(form).getByLabelText('Адрес образа в Docker Hub')).toHaveValue(target);
    await act(async () => pending.resolve(reply(202, { scanId, statusUrl: `/api/v1/scans/${scanId}`, eventsUrl: `/api/v1/scans/${scanId}/events` })));
    expect(await screen.findByText('Private report boundary')).toBeVisible();
    expect(screen.getByLabelText('Current route')).toHaveTextContent(reportPath);
    expect(posts).toHaveLength(1);
  });
});

describe('transient auth verification is not logout', () => {
  it.each([
    ['/account', 'network'], [reportPath, 'network'], ['/account', '503'], [reportPath, '503'],
  ])('closes stale private UI and recovers only by manual GET retry at %s after %s', async (path, failure) => {
    const user = userEvent.setup();
    let reads = 0;
    const fetchMock = installFetch((url) => {
      if (url === '/api/v1/auth/me') {
        reads++;
        if (reads === 2) {
          if (failure === '503') return reply(503);
          throw new TypeError('Synthetic transient network failure');
        }
        return reply(200, owner);
      }
      // Record an accidental logout without allowing a real request or hanging the old recovery hook.
      if (url === '/api/v1/auth/logout') return reply(200);
      throw new Error(`Unexpected request: ${url}`);
    });
    const client = mount(path);
    const privateText = path === '/account' ? owner.email : 'Private report boundary';
    expect(await screen.findByText(privateText)).toBeVisible();
    await act(async () => { await client.refetchQueries({ queryKey: ['demo-auth', 'me'] }); });
    await waitFor(() => expect(screen.queryByText(privateText)).not.toBeInTheDocument());
    expect(scanSession().subject).toBeNull();
    expect(fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0);
    expect(screen.getByLabelText('Current route')).toHaveTextContent(path);
    const retry = screen.getByRole('button', { name: /Повторить.*сесси|Проверить.*сесси/i });
    await pause();
    expect(reads).toBe(2);
    await user.click(retry);
    expect(await screen.findByText(privateText)).toBeVisible();
    expect(reads).toBe(3);
    expect(fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0);
  });

  it('handles auth/me 401 as unauthenticated, not a transient retry or logout POST', async () => {
    const fetchMock = installFetch(path => {
      if (path === '/api/v1/auth/me') return reply(401);
      throw new Error(`Unexpected request: ${path}`);
    });
    mount(reportPath);
    expect(await screen.findByRole('link', { name: /войдите/i })).toBeVisible();
    expect(screen.queryByText('Private report boundary')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Повторить.*сесси|Проверить.*сесси/i })).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(scanSession().subject).toBeNull();
  });
});

describe('manual request recovery', () => {
  it('does not automatically retry denied eligibility, but explicit retry sends a new request after 403', async () => {
    const user = userEvent.setup();
    let reads = 0;
    let now = Date.now();
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const fetchMock = installFetch((path) => {
      if (path === '/api/v1/auth/me') return reply(200, owner);
      if (path.endsWith('/images/eligibility')) return ++reads === 1 ? reply(403) : reply(200, eligibility());
      throw new Error(`Unexpected request: ${path}`);
    });
    mount('/scans/new');
    const retry = await screen.findByRole('button', { name: 'Проверить допуск снова' });
    fireEvent.click(screen.getByText('Указать адрес вручную'));
    fireEvent.click(screen.getByText('Сохранённый пример для прежнего профиля'));
    fireEvent.click(screen.getByRole('button', { name: 'Выбрать закреплённый nginx' }));
    await waitFor(() => expect(reads).toBe(1));
    await waitFor(() => expect(retry).toBeEnabled());
    expect(screen.getByRole('button', { name: 'Запустить проверку' })).toBeDisabled();
    now += 60_001;
    fireEvent(window, new Event('focus'));
    fireEvent(window, new Event('online'));
    await pause();
    expect(reads).toBe(1);
    await user.click(retry);
    await waitFor(() => expect(reads).toBe(2));
    const card = screen.getByRole('button', { name: /Выбрать закреплённый nginx/ });
    await waitFor(() => expect(card).toBeEnabled());
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/browser/scans')).toHaveLength(0);
  });

  it('initial list failure stays unknown without automatic retries and manual retry restores the list', async () => {
    const user = userEvent.setup();
    let reads = 0;
    const fetchMock = installFetch(path => {
      if (path === '/api/v1/auth/me') return reply(200, owner);
      if (path === '/api/v1/browser/scans?limit=50') return ++reads === 1 ? reply(503) : reply(200, {
        scans: [{ scanId, state: 'completed', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', targetLabel: 'restored synthetic target' }], nextCursor: null,
      });
      throw new Error(`Unexpected request: ${path}`);
    });
    mount('/scans');
    expect(await screen.findByRole('alert')).toHaveTextContent('Не удалось загрузить список');
    expect(screen.queryByText('Сканов нет (успешный ответ списка).')).not.toBeInTheDocument();
    await pause();
    expect(reads).toBe(1);
    await user.click(screen.getByRole('button', { name: /Повторить.*спис|Загрузить.*снова/i }));
    expect(await screen.findByRole('link', { name: 'Открыть отчёт: restored synthetic target, ID 00000000-0000-4000-8000-000000000061' })).toHaveAttribute('href', reportPath);
    expect(reads).toBe(2);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0);
  });
});

describe('login returnTo boundary', () => {
  it.each([reportPath, '/scans/new'])('preserves the requested private destination %s through login', async destination => {
    const user = userEvent.setup();
    let loggedIn = false;
    installFetch((path, init) => {
      if (path === '/api/v1/auth/me') return reply(loggedIn ? 200 : 401, loggedIn ? owner : {});
      if (path === '/api/v1/auth/login' && init?.method === 'POST') { loggedIn = true; return reply(200, owner); }
      if (path.endsWith('/images/eligibility')) return reply(200, eligibility());
      throw new Error(`Unexpected request: ${path}`);
    });
    mount(destination);
    await user.click(await screen.findByRole('link', { name: /войдите/i }));
    await user.type(screen.getByLabelText('Email'), owner.email);
    await user.type(screen.getByLabelText('Пароль'), 'synthetic-password-1234');
    await user.click(screen.getByRole('button', { name: 'Войти' }));
    await waitFor(() => expect(screen.getByLabelText('Current route').textContent).toBe(destination));
    if (destination === reportPath) expect(await screen.findByText('Private report boundary')).toBeVisible();
    else expect(await screen.findByRole('form', { name: 'Параметры скана' })).toBeVisible();
  });

  it.each(['https://outside.invalid/scans/new', '//outside.invalid/scans/new', '/\\outside.invalid/scans/new', 'javascript:alert(1)'])(
    'rejects unsafe returnTo %s after successful login', async returnTo => {
      const user = userEvent.setup();
      let loggedIn = false;
      installFetch((path, init) => {
        if (path === '/api/v1/auth/me') return reply(loggedIn ? 200 : 401, loggedIn ? owner : {});
        if (path === '/api/v1/auth/login' && init?.method === 'POST') { loggedIn = true; return reply(200, owner); }
        throw new Error(`Unexpected request: ${path}`);
      });
      mount('/login', { returnTo });
      await screen.findByRole('heading', { name: 'Вход' });
      await user.type(screen.getByLabelText('Email'), owner.email);
      await user.type(screen.getByLabelText('Пароль'), 'synthetic-password-1234');
      await user.click(screen.getByRole('button', { name: 'Войти' }));
      await waitFor(() => expect(screen.getByLabelText('Current route').textContent).toBe('/account'));
      expect(await screen.findByText(owner.email)).toBeVisible();
    },
  );
});
