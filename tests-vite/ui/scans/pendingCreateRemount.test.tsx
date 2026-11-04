import '@testing-library/jest-dom/vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Link, MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LiveScanSession } from '@/features/scans/LiveScanSession';
import { DemoAuthPage } from '@/pages/auth/DemoAuthPage';
import { ScanCreatePage } from '@/pages/scans/ScanCreatePage';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { readPendingCreateIntent } from '@/shared/api/scans/pendingCreateIntent';

const owner = { id: 'pending-owner', email: 'pending@example.invalid' };
const other = { id: 'different-owner', email: 'different@example.invalid' };
const target = 'registry-1.docker.io/library/node:22.14.0-alpine3.21';
const scanId = '00000000-0000-4000-8000-000000000062';
const oldScanId = '00000000-0000-4000-8000-000000000063';
const scans = '/api/v1/browser/scans';
type Intent = { imageReference: string; checks: string[]; scope: string; idempotencyKey: string };
const clients: QueryClient[] = [];
const response = (status: number, body: unknown = {}) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json' },
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
function Navigation() {
  const location = useLocation();
  return <><output aria-label="Route">{location.pathname}</output>
    <Link to="/account">Test account route</Link><Link to="/scans/new">Test create route</Link></>;
}
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/scans/new']}>
    <Navigation /><Routes>
      <Route path="/scans/new" element={<LiveScanSession><ScanCreatePage /></LiveScanSession>} />
      <Route path="/scans/:scanId" element={<LiveScanSession><p>Accepted report route</p></LiveScanSession>} />
      <Route path="/account" element={<DemoAuthPage mode="account" />} />
      <Route path="/login" element={<DemoAuthPage mode="login" />} />
    </Routes>
  </MemoryRouter></QueryClientProvider>);
  return client;
}
function server(uncertain = false) {
  let auth: typeof owner | 401 | 503 = owner;
  let eligibilityReads = 0;
  const first = deferred<Response>();
  const replay = deferred<Response>();
  const posts: Intent[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (typeof input !== 'string' || !input.startsWith('/api/v1/')) throw new Error('Unexpected test destination');
    if (input === '/api/v1/auth/me') return typeof auth === 'number' ? response(auth) : response(200, auth);
    if (input === '/api/v1/auth/logout' && init?.method === 'POST') { auth = 401; return response(200); }
    if (input === '/api/v1/auth/login' && init?.method === 'POST') { auth = owner; return response(200, owner); }
    if (input.startsWith('/api/v1/browser/runtime/')) return response(404);
    if (input === `${scans}/images/eligibility`) {
      eligibilityReads++;
      return response(200, { imageReference: JSON.parse(String(init?.body)).imageReference,
        eligible: true, reason: 'READY', eligibility: 'public-hub-profile', allowedCheckSets: [['secret'], ['secret', 'config']] });
    }
    if (input === scans && init?.method === 'POST') {
      posts.push(JSON.parse(String(init.body)));
      if (uncertain) throw new TypeError('Synthetic response lost after dispatch');
      return posts.length === 1 ? first.promise : replay.promise;
    }
    throw new Error(`Unexpected test endpoint: ${input}`);
  });
  vi.stubGlobal('fetch', fetchMock);
  return { posts, first, replay, fetchMock, setAuth: (next: typeof auth) => { auth = next; }, reads: () => eligibilityReads };
}
const pause = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 300)); });
async function prepare(targetReference = target, config = true) {
  const form = await screen.findByRole('form', { name: 'Параметры скана' });
  fireEvent.click(within(form).getByText('Указать адрес вручную'));
  fireEvent.change(within(form).getByLabelText('Адрес образа в Docker Hub'), { target: { value: targetReference } });
  if (config) fireEvent.click(within(form).getByRole('checkbox', { name: /Настройки ·/ }));
  await within(form).findByText('Сервер разрешает выбранные проверки. Перед запуском проверим доступность ещё раз.');
  fireEvent.click(within(form).getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
  const launch = within(form).getByRole('button', { name: 'Запустить проверку' });
  await waitFor(() => expect(launch).toBeEnabled());
  fireEvent.click(launch);
  return form;
}
async function outage(client: QueryClient, api: ReturnType<typeof server>) {
  api.setAuth(503);
  await act(async () => { await client.refetchQueries({ queryKey: ['demo-auth', 'me'] }); });
  expect(await screen.findByText(/Не удалось проверить сессию\. Данные скрыты/)).toHaveAttribute('role', 'alert');
  expect(screen.queryByRole('form', { name: 'Параметры скана' })).not.toBeInTheDocument();
  expect(scanSession().subject).toBeNull();
  expect(readPendingCreateIntent(scanSession())).toBeNull();
}
async function loginOwner() {
  const user = userEvent.setup();
  await user.type(await screen.findByLabelText('Email'), owner.email);
  await user.type(screen.getByLabelText('Пароль'), 'synthetic-pending-password');
  await user.click(screen.getByRole('button', { name: 'Войти' }));
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

describe('pending create survives a real private form remount, not consent or authorization', () => {
  it.each(['before replay', 'during replay'])('retains the same key after /me503 and ignores the old receipt %s', async lateReceipt => {
    const user = userEvent.setup();
    const api = server();
    const client = mount();
    const oldForm = await prepare();
    await waitFor(() => expect(api.posts).toHaveLength(1));
    const sent = { ...api.posts[0], checks: [...api.posts[0].checks] };
    expect(sent.checks).toEqual(['secret', 'config']);
    await outage(client, api);
    expect(oldForm).not.toBeInTheDocument();
    const reads = api.reads();
    api.setAuth(owner);
    await user.click(screen.getByRole('button', { name: 'Повторить проверку сессии' }));
    const restored = await screen.findByRole('form', { name: 'Параметры скана' });
    expect(restored).not.toBe(oldForm);
    expect(within(restored).getByLabelText('Адрес образа в Docker Hub')).toHaveValue(sent.imageReference);
    expect(within(restored).getByRole('checkbox', { name: /Возможные секреты ·/ })).toBeChecked();
    expect(within(restored).getByRole('checkbox', { name: /Настройки ·/ })).toBeChecked();
    const consent = within(restored).getByRole('checkbox', { name: /Подтверждаю выбранную цель/ });
    expect(consent).not.toBeChecked();
    expect(within(restored).getByRole('button', { name: 'Запустить проверку' })).toBeDisabled();
    fireEvent(window, new Event('focus')); fireEvent(window, new Event('online'));
    await pause();
    expect(api.reads()).toBe(reads);
    expect(api.posts).toHaveLength(1);
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    const retained = () => readPendingCreateIntent(scanSession(), { target: sent.imageReference, checks: sent.checks.join(',') });
    expect(retained()?.key).toBe(sent.idempotencyKey);
    if (lateReceipt === 'before replay') {
      await act(async () => api.first.resolve(response(202, { scanId: oldScanId })));
      expect(screen.getByLabelText('Route').textContent).toBe('/scans/new');
      expect(retained()?.key).toBe(sent.idempotencyKey);
    }
    // Restoring consent alone must not authorize a replay before a manual eligibility read.
    await user.click(consent);
    expect(within(restored).getByRole('button', { name: 'Запустить проверку' })).toBeDisabled();
    fireEvent.submit(restored);
    await pause();
    expect(api.posts).toHaveLength(1);
    await user.click(consent);
    await user.click(within(restored).getByRole('button', { name: 'Проверить допуск снова' }));
    await waitFor(() => expect(api.reads()).toBe(reads + 1));
    await waitFor(() => expect(within(restored).getByRole('button', { name: 'Проверить допуск снова' })).toBeEnabled());
    expect(consent).not.toBeChecked();
    expect(api.posts).toHaveLength(1);
    await user.click(consent);
    const launch = within(restored).getByRole('button', { name: 'Запустить проверку' });
    await waitFor(() => expect(launch).toBeEnabled());
    await user.click(launch);
    await waitFor(() => expect(api.posts).toHaveLength(2));
    expect(api.posts[1]).toEqual(sent);
    expect(api.reads()).toBe(reads + 2); // Manual approval and fresh submit-time preflight.
    if (lateReceipt === 'during replay') {
      await act(async () => api.first.resolve(response(202, { scanId: oldScanId })));
      expect(screen.getByLabelText('Route').textContent).toBe('/scans/new');
      expect(retained()?.key).toBe(sent.idempotencyKey);
      expect(restored).toHaveAttribute('aria-busy', 'true');
    }
    await act(async () => api.replay.resolve(response(202, { scanId })));
    expect(await screen.findByText('Accepted report route')).toBeVisible();
    expect(screen.getByLabelText('Route').textContent).toBe(`/scans/${scanId}`);
    expect(retained()).toBeNull();
    expect(api.posts).toHaveLength(2);
    expect(api.fetchMock.mock.calls.some(([path]) => path === '/api/v1/auth/logout')).toBe(false);
  });

  it.each(['different owner', 'confirmed 401', 'explicit logout'])('clears uncertain intents after %s, including a subsequent same-owner remount', async boundary => {
    const user = userEvent.setup();
    const api = server();
    const client = mount();
    await prepare();
    await waitFor(() => expect(api.posts).toHaveLength(1));
    await outage(client, api);
    if (boundary === 'different owner') {
      api.setAuth(other);
      await user.click(screen.getByRole('button', { name: 'Повторить проверку сессии' }));
      const foreign = await screen.findByRole('form', { name: 'Параметры скана' });
      expect(within(foreign).getByLabelText('Адрес образа в Docker Hub')).toHaveValue('');
      expect(readPendingCreateIntent(scanSession())).toBeNull();
      api.setAuth(owner);
      await act(async () => { await client.refetchQueries({ queryKey: ['demo-auth', 'me'] }); });
      await waitFor(() => expect(foreign).not.toBeInTheDocument());
    } else if (boundary === 'confirmed 401') {
      api.setAuth(401);
      await user.click(screen.getByRole('button', { name: 'Повторить проверку сессии' }));
      await user.click(await screen.findByRole('link', { name: 'войдите' }));
      await loginOwner();
    } else {
      api.setAuth(owner);
      await user.click(screen.getByRole('button', { name: 'Повторить проверку сессии' }));
      await screen.findByRole('form', { name: 'Параметры скана' });
      await user.click(screen.getByRole('link', { name: 'Test account route' }));
      await user.click(await screen.findByRole('button', { name: 'Выйти из аккаунта' }));
      await loginOwner();
      expect(await screen.findByText(owner.email)).toBeVisible();
      await user.click(screen.getByRole('link', { name: 'Test create route' }));
    }
    const fresh = await screen.findByRole('form', { name: 'Параметры скана' });
    expect(scanSession().subject).toBe(owner.id);
    expect(readPendingCreateIntent(scanSession())).toBeNull();
    expect(within(fresh).getByLabelText('Адрес образа в Docker Hub')).toHaveValue('');
    expect(within(fresh).getByRole('checkbox', { name: /Подтверждаю выбранную цель/ })).not.toBeChecked();
    expect(screen.queryByText(/Восстановлены параметры неподтверждённого запуска/)).not.toBeInTheDocument();
    await act(async () => api.first.resolve(response(202, { scanId: oldScanId })));
    await pause();
    expect(screen.getByLabelText('Route').textContent).toBe('/scans/new');
    expect(api.posts).toHaveLength(1);
    const logouts = api.fetchMock.mock.calls.filter(([path]) => path === '/api/v1/auth/logout');
    expect(logouts).toHaveLength(boundary === 'explicit logout' ? 1 : 0);
  });

  it('keeps all eight uncertain UI submissions without eviction and refuses a ninth POST', async () => {
    const api = server(true);
    const client = mount();
    for (let index = 0; index < 8; index++) {
      await prepare(`registry-1.docker.io/library/alpine:uncertain-${index}`, false);
      await waitFor(() => expect(api.posts).toHaveLength(index + 1));
      expect(await within(screen.getByRole('form', { name: 'Параметры скана' })).findByRole('alert')).toHaveTextContent('результат запроса неизвестен');
    }
    const saved = api.posts.map(post => ({ target: post.imageReference, checks: post.checks.join(','), key: post.idempotencyKey }));
    expect(new Set(saved.map(intent => intent.key)).size).toBe(8);
    await prepare('registry-1.docker.io/library/alpine:ninth', false);
    expect(await within(screen.getByRole('form', { name: 'Параметры скана' })).findByRole('alert')).toHaveTextContent('слишком много неподтверждённых запусков');
    expect(api.posts).toHaveLength(8);
    for (const intent of saved) expect(readPendingCreateIntent(scanSession(), intent)).toEqual(intent);
    await outage(client, api);
    api.setAuth(owner);
    fireEvent.click(screen.getByRole('button', { name: 'Повторить проверку сессии' }));
    const restored = await screen.findByRole('form', { name: 'Параметры скана' });
    expect(within(restored).getByLabelText('Адрес образа в Docker Hub')).toHaveValue(saved[7].target);
    for (const intent of saved) expect(readPendingCreateIntent(scanSession(), intent)).toEqual(intent);
    await pause();
    expect(api.posts).toHaveLength(8);
  });
});
