import '@testing-library/jest-dom/vitest';
import { StrictMode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { BrowserRouter, Link, MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import { DemoAuthPage } from '@/pages/auth/DemoAuthPage';
import { PasswordResetPage } from '@/pages/auth/PasswordResetPage';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import {
  changePassword,
  revokeAllSessions,
  confirmPasswordReset,
  requestPasswordReset,
  validAuthPassword,
  shouldRecheckSession,
} from '@/shared/api/auth/accountSecurity';
const owner = { id: 'task54-owner', email: 'synthetic54@example.test' };
const other = { id: 'task54-other', email: 'other54@example.test' };
const oldPassword = 'я'.repeat(6),
  newPassword = ' new-password-54 ';
const token = 'Synthetic54_'.padEnd(43, 'x');
const clients: QueryClient[] = [];
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
function deferred() {
  let resolve!: (value: Response) => void;
  const promise = new Promise<Response>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
function Location() {
  const value = useLocation();
  return (
    <>
      <output aria-label="location">{value.pathname}</output>
      <output aria-label="return destination">{value.state?.returnTo ?? ''}</output>
      <Link to="/elsewhere">Leave screen</Link>
    </>
  );
}
function mount(path = '/account', strict = false, state?: { returnTo?: unknown; extra?: string }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  clients.push(client);
  client.setQueryData(['unrelated'], { keep: true });
  const routes = (
    <>
      <Location />
      <Routes>
        <Route path="/account" element={<DemoAuthPage mode="account" />} />
        <Route path="/login" element={<DemoAuthPage mode="login" />} />
        <Route path="/forgot-password" element={<PasswordResetPage mode="request" />} />
        <Route path="/reset-password" element={<PasswordResetPage mode="confirm" />} />
        <Route path="/elsewhere" element={<p>Public destination</p>} />
      </Routes>
    </>
  );
  if (path.startsWith('/reset-password')) window.history.replaceState(state ? { usr: state, key: 'reset-test', idx: 0 } : null, '', path);
  const tree = (
    <QueryClientProvider client={client}>
      {path.startsWith('/reset-password') ? (
        <BrowserRouter>{routes}</BrowserRouter>
      ) : (
        <MemoryRouter initialEntries={[{ pathname: path, state }]}>{routes}</MemoryRouter>
      )}
    </QueryClientProvider>
  );
  const view = render(strict ? <StrictMode>{tree}</StrictMode> : tree);
  return { client, ...view };
}
function api(
  mutation: (path: string, init: RequestInit) => Promise<Response>,
  me: () => Response | Promise<Response> = () => json(owner),
  available = true,
) {
  const calls: Array<{ path: string; init: RequestInit }> = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (path: string, init: RequestInit = {}) => {
      calls.push({ path, init });
      if (path === '/api/v1/auth/me') return me();
      if (path === '/api/v1/auth/password-reset/status')
        return json(
          available
            ? { available: true, delivery: 'configured' }
            : { available: false, reason: 'DELIVERY_NOT_CONFIGURED', action: 'CONTACT_OPERATOR' },
        );
      if (init.method === 'POST' && path.startsWith('/api/v1/auth/')) return mutation(path, init);
      throw Error('Unexpected mocked auth request');
    }),
  );
  return calls;
}
function fillAccount(change = true) {
  const section = screen
    .getByText(change ? 'Сменить пароль' : 'Выйти со всех устройств', {
      selector: 'summary .demo-auth__disclosure-title',
    })
    .closest('summary')!;
  expect(section.closest('details')).not.toHaveAttribute('open');
  fireEvent.click(section);
  const form = screen.getByRole('form', { name: change ? 'Смена пароля' : 'Выход со всех устройств' });
  fireEvent.change(within(form).getByLabelText(change ? 'Текущий пароль' : 'Текущий пароль для выхода'), {
    target: { value: oldPassword },
  });
  if (change) {
    fireEvent.change(within(form).getByLabelText('Новый пароль', { exact: true }), {
      target: { value: newPassword },
    });
    fireEvent.change(within(form).getByLabelText('Повторите новый пароль'), {
      target: { value: newPassword },
    });
  }
  const confirmation = within(form).getByRole('checkbox', {
    name: change
      ? 'Подтверждаю смену пароля и выход на всех устройствах, включая это.'
      : 'Подтверждаю выход на всех устройствах, включая это.',
  });
  expect(confirmation).not.toBeChecked();
  fireEvent.click(confirmation);
  expect(confirmation).toBeChecked();
}
const posts = (calls: ReturnType<typeof api>) => calls.filter((call) => call.init.method === 'POST');
afterEach(() => {
  cleanup();
  for (const client of clients.splice(0)) {
    transitionScanSession(null, client, true);
    client.clear();
  }
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  localStorage.clear();
  sessionStorage.clear();
  window.history.replaceState(null, '', '/');
});

it.each(['change-password', 'revoke-all'] as const)(
  'TASK54 %s requires a fresh explicit confirmation before any POST',
  async (action) => {
    const calls = api(async () => {
      throw Error('Unconfirmed mutation forbidden');
    });
    mount();
    await screen.findByText(owner.email);
    fillAccount(action === 'change-password');
    const form = screen.getByRole('form', {
      name: action === 'change-password' ? 'Смена пароля' : 'Выход со всех устройств',
    });
    const confirmation = within(form).getByRole('checkbox');
    fireEvent.click(confirmation);
    fireEvent.submit(form);
    expect(confirmation).not.toBeChecked();
    expect(posts(calls)).toHaveLength(0);
    expect(scanSession().subject).toBe(owner.id);
  },
);

it('TASK54 client exact bodies/status/no204JSON, UTF8 boundaries and no trimming', async () => {
  const calls = api(async () => new Response(null, { status: 204 }));
  expect(validAuthPassword(oldPassword)).toBe(true);
  expect(validAuthPassword('я'.repeat(65))).toBe(false);
  await changePassword(oldPassword, newPassword);
  await revokeAllSessions(oldPassword);
  await confirmPasswordReset(token, newPassword);
  expect(posts(calls).map((call) => [call.path, JSON.parse(String(call.init.body))])).toEqual([
    ['/api/v1/auth/change-password', { currentPassword: oldPassword, newPassword }],
    ['/api/v1/auth/revoke-all', { currentPassword: oldPassword }],
    ['/api/v1/auth/password-reset/confirm', { token, newPassword }],
  ]);
  for (const { init } of posts(calls))
    expect(init).toMatchObject({
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      headers: { 'Content-Type': 'application/json' },
    });
});
it('TASK54 strict unknown/malformed/unexpected success responses stay uncertain and never retry', async () => {
  const replies = [
    json({ errorCode: 'INVALID_CREDENTIALS' }, 401),
    json({ errorCode: 'INVALID_CREDENTIALS', raw: 'PRIVATE' }, 401),
    json({ status: 'accepted' }, 200),
    json({ errorCode: 'UNKNOWN' }, 503),
  ];
  const calls = api(async () => replies.shift()!);
  for (let index = 0; index < 4; index++) {
    const result = await revokeAllSessions(oldPassword).then(
      () => null,
      (error) => error,
    );
    expect(result).toBeInstanceOf(Error);
    expect(shouldRecheckSession(result)).toBe(index !== 0);
    expect(result.message).not.toContain('PRIVATE');
  }
  expect(posts(calls)).toHaveLength(4);
});
it.each(['change-password', 'revoke-all'] as const)(
  'TASK54 %s current204 fences session, unrelated cache survives and navigates login once',
  async (action) => {
    const pending = deferred();
    let anonymous = false;
    const calls = api(
      async () => pending.promise,
      () => (anonymous ? json({}, 401) : json(owner)),
    );
    const { client } = mount();
    await screen.findByText(owner.email);
    const generation = scanSession().generation;
    const privateKey = ['live-scans', generation, owner.id, 'private-sentinel'];
    client.setQueryData(privateKey, { private: true });
    fillAccount(action === 'change-password');
    const button = screen.getByRole('button', {
      name: action === 'change-password' ? 'Сменить пароль и выйти везде' : 'Выйти со всех устройств',
    });
    fireEvent.click(button);
    fireEvent.click(button);
    await waitFor(() => expect(posts(calls)).toHaveLength(1));
    expect(JSON.parse(String(posts(calls)[0].init.body))).toEqual(
      action === 'change-password'
        ? { currentPassword: oldPassword, newPassword }
        : { currentPassword: oldPassword },
    );
    expect(screen.getByLabelText('Текущий пароль')).toBeDisabled();
    expect(screen.getByLabelText('Текущий пароль для выхода')).toBeDisabled();
    anonymous = true;
    await act(async () => pending.resolve(new Response(null, { status: 204 })));
    await waitFor(() => expect(screen.getByLabelText('location')).toHaveTextContent('/login'));
    expect(scanSession().subject).toBeNull();
    expect(scanSession().generation).toBeGreaterThan(generation);
    expect(client.getQueryData(privateKey)).toBeUndefined();
    expect(client.getQueryData(['unrelated'])).toEqual({ keep: true });
    expect(posts(calls)).toHaveLength(1);
  },
);
it('TASK54 wrong current password keeps verified account/drafts and does not revalidate or logout', async () => {
  const calls = api(async () => json({ errorCode: 'INVALID_CREDENTIALS' }, 401));
  mount();
  await screen.findByText(owner.email);
  fillAccount();
  const before = calls.filter((call) => call.path.endsWith('/me')).length;
  fireEvent.click(screen.getByRole('button', { name: 'Сменить пароль и выйти везде' }));
  await screen.findByText('Текущий пароль не подошёл. Проверьте его и попробуйте снова.');
  expect(scanSession().subject).toBe(owner.id);
  expect(screen.getByText(owner.email)).toBeVisible();
  expect(screen.getByLabelText('Новый пароль', { exact: true })).toHaveValue(newPassword);
  expect(calls.filter((call) => call.path.endsWith('/me'))).toHaveLength(before);
  expect(posts(calls)).toHaveLength(1);
});
it('TASK54 uncertain POST hides private UI during fresh/me, restores same-owner draft without duplicate mutation', async () => {
  const pending = deferred();
  let recheck = false;
  const calls = api(
    async () => {
      recheck = true;
      throw Error('PRIVATE_NETWORK_PAYLOAD');
    },
    () => (recheck ? pending.promise : json(owner)),
  );
  const { client } = mount();
  await screen.findByText(owner.email);
  fillAccount();
  fireEvent.click(screen.getByRole('button', { name: 'Сменить пароль и выйти везде' }));
  await waitFor(() => expect(scanSession().subject).toBeNull());
  expect(screen.queryByText(owner.email)).toBeNull();
  expect(screen.queryByLabelText('Текущий пароль')).toBeNull();
  expect(posts(calls)).toHaveLength(1);
  await act(async () => pending.resolve(json(owner)));
  await screen.findByText(/Не удалось подтвердить результат запроса/);
  expect(screen.getByLabelText('Текущий пароль')).toHaveValue(oldPassword);
  expect(screen.getByLabelText('Новый пароль', { exact: true })).toHaveValue(newPassword);
  expect(posts(calls)).toHaveLength(1);
  expect(client.getQueryData(['unrelated'])).toEqual({ keep: true });
  expect(document.body.textContent).not.toContain('PRIVATE_NETWORK_PAYLOAD');
});
it.each(['navigation', 'owner'] as const)(
  'TASK54 late204 after %s revalidates but never stale redirects',
  async (change) => {
    const pending = deferred();
    let next = owner;
    const calls = api(
      async () => pending.promise,
      () => json(next),
    );
    const { client } = mount();
    await screen.findByText(owner.email);
    fillAccount(false);
    fireEvent.click(screen.getByRole('button', { name: 'Выйти со всех устройств' }));
    await waitFor(() => expect(posts(calls)).toHaveLength(1));
    if (change === 'navigation') fireEvent.click(screen.getByRole('link', { name: 'Leave screen' }));
    else {
      next = other;
      await act(async () => {
        client.setQueryData(['demo-auth', 'me'], other);
        transitionScanSession(other.id, client, true);
      });
    }
    await act(async () => pending.resolve(new Response(null, { status: 204 })));
    await waitFor(() => expect(calls.filter((call) => call.path.endsWith('/me')).length).toBeGreaterThan(1));
    expect(screen.getByLabelText('location')).not.toHaveTextContent('/login');
    expect(posts(calls)).toHaveLength(1);
    if (change === 'owner') {
      await screen.findByText(other.email);
      expect(screen.getByLabelText('Текущий пароль для выхода')).toHaveValue('');
    }
  },
);
it.each(['/scans', '/scans/new', '/scans/00000000-0000-4000-8000-000000000038'])(
  'preserves a safe login destination through password recovery: %s', async returnTo => {
    const calls = api(async () => { throw Error('POST forbidden'); }, () => json({ errorCode: 'AUTH_REQUIRED' }, 401), false);
    mount('/login', false, { returnTo });
    fireEvent.click(await screen.findByRole('link', { name: 'Забыли пароль?' }));
    await screen.findByRole('heading', { name: 'Восстановить доступ' });
    expect(screen.getByLabelText('return destination')).toHaveTextContent(returnTo);
    fireEvent.click(screen.getByRole('link', { name: 'Вернуться ко входу' }));
    await screen.findByRole('heading', { name: 'Вход' });
    expect(screen.getByLabelText('return destination')).toHaveTextContent(returnTo);
    expect(posts(calls)).toHaveLength(0);
  },
);

it.each(['https://evil.invalid', '//evil.invalid', '/scans?token=not-allowed', '/scans/new#not-allowed'])(
  'does not forward an unsafe recovery destination: %s', async returnTo => {
    const calls = api(async () => { throw Error('POST forbidden'); }, () => json({ errorCode: 'AUTH_REQUIRED' }, 401), false);
    mount('/forgot-password', false, { returnTo });
    await screen.findByRole('heading', { name: 'Восстановить доступ' });
    fireEvent.click(screen.getByRole('link', { name: 'Ко входу' }));
    await screen.findByRole('heading', { name: 'Вход' });
    expect(screen.getByLabelText('return destination')).toHaveTextContent('/account');
    expect(posts(calls)).toHaveLength(0);
  },
);

it('retains only a safe return destination while scrubbing a reset token', async () => {
  const calls = api(async () => { throw Error('POST forbidden'); });
  mount(`/reset-password#token=${token}`, false, { returnTo: '/scans/new', extra: 'must-not-survive' });
  await waitFor(() => expect(window.location.hash).toBe(''));
  expect(window.history.state.usr).toEqual({ returnTo: '/scans/new' });
  expect(JSON.stringify(window.history.state)).not.toContain(token);
  fireEvent.click(screen.getByRole('link', { name: 'Ко входу' }));
  await screen.findByRole('heading', { name: 'Вход' });
  expect(screen.getByLabelText('return destination')).toHaveTextContent('/scans/new');
  expect(posts(calls)).toHaveLength(0);
});

it('TASK54 unavailable recovery is truthful, disabled, GET-only manual retry and never claims mail delivery', async () => {
  const calls = api(
    async () => {
      throw Error('POST forbidden');
    },
    undefined,
    false,
  );
  mount('/forgot-password');
  await screen.findByText(/Оператору сайта нужно настроить и проверить доставку/);
  expect(screen.getByRole('button', { name: 'Запросить восстановление' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Повторить проверку доступности' }));
  await waitFor(() => expect(calls.filter((call) => call.path.endsWith('/status'))).toHaveLength(2));
  expect(posts(calls)).toHaveLength(0);
});
it.each([
  { available: true, delivery: 'unknown' },
  { available: false, reason: 'UNKNOWN', action: 'CONTACT_OPERATOR' },
  { available: false, reason: 'DELIVERY_NOT_CONFIGURED', action: 'CONTACT_OPERATOR', delivered: true },
])('TASK54 malformed readiness keeps reset disabled and does not retry: %j', async (body) => {
  const calls: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (path: string) => {
      calls.push(path);
      return json(body);
    }),
  );
  mount('/forgot-password');
  await screen.findByText(
    'Не удалось проверить доступность восстановления. Запрос на смену пароля не отправлен.',
  );
  expect(screen.getByRole('button', { name: 'Запросить восстановление' })).toBeDisabled();
  expect(calls).toEqual(['/api/v1/auth/password-reset/status']);
});
it('TASK54 ambiguous reset confirmation rechecks/me and retains transient draft with no duplicate POST', async () => {
  const pending = deferred();
  const calls = api(
    async () => {
      throw Error('PRIVATE_CONFIRM_NETWORK');
    },
    () => pending.promise,
  );
  mount(`/reset-password#token=${token}`);
  const button = screen.getByRole('button', { name: 'Сохранить новый пароль' });
  await waitFor(() => expect(button).toBeEnabled());
  fireEvent.change(screen.getByLabelText('Новый пароль', { exact: true }), {
    target: { value: newPassword },
  });
  fireEvent.change(screen.getByLabelText('Повторите новый пароль'), { target: { value: newPassword } });
  fireEvent.click(button);
  await waitFor(() => expect(calls.some((call) => call.path.endsWith('/me'))).toBe(true));
  expect(posts(calls)).toHaveLength(1);
  expect(screen.getByLabelText('Новый пароль', { exact: true })).toHaveValue(newPassword);
  await act(async () => pending.resolve(json(owner)));
  await screen.findByText(/Не удалось подтвердить результат запроса/);
  expect(screen.getByLabelText('Новый пароль', { exact: true })).toHaveValue(newPassword);
  expect(posts(calls)).toHaveLength(1);
  expect(window.location.hash).toBe('');
  expect(document.body.textContent).not.toContain('PRIVATE_CONFIRM_NETWORK');
});
it('TASK54 configured mock202 acknowledges only acceptance, normalized email, no delivery promise', async () => {
  const calls = api(async () => json({ status: 'accepted' }, 202));
  mount('/forgot-password');
  const button = screen.getByRole('button', { name: 'Запросить восстановление' });
  await waitFor(() => expect(button).toBeEnabled());
  fireEvent.change(screen.getByLabelText('Email аккаунта'), { target: { value: 'Known54@Example.Test' } });
  fireEvent.click(button);
  await screen.findByText(/Это не подтверждение отправки или доставки письма/);
  expect(JSON.parse(String(posts(calls)[0].init.body))).toEqual({ email: 'known54@example.test' });
  expect(posts(calls)).toHaveLength(1);
});
it.each([true, false])(
  'TASK54 fragment token scrubbed into RAM only, StrictMode=%s, confirm204 exact/noautoPOST',
  async (strict) => {
    const calls = api(
      async () => new Response(null, { status: 204 }),
      () => json({}, 401),
    );
    const { client } = mount(`/reset-password#token=${token}`, strict, { returnTo: '/scans/new' });
    await waitFor(() =>
      expect(window.location.pathname + window.location.search + window.location.hash).toBe(
        '/reset-password',
      ),
    );
    const button = screen.getByRole('button', { name: 'Сохранить новый пароль' });
    await waitFor(() => expect(button).toBeEnabled());
    expect(document.body.innerHTML).not.toContain(token);
    expect(
      JSON.stringify(
        client
          .getQueryCache()
          .getAll()
          .map((query) => query.queryKey),
      ),
    ).not.toContain(token);
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain(token);
    expect(posts(calls)).toHaveLength(0);
    fireEvent.change(screen.getByLabelText('Новый пароль', { exact: true }), {
      target: { value: newPassword },
    });
    fireEvent.change(screen.getByLabelText('Повторите новый пароль'), { target: { value: newPassword } });
    fireEvent.click(button);
    await waitFor(() => expect(screen.getByLabelText('location')).toHaveTextContent('/login'));
    expect(screen.getByLabelText('return destination')).toHaveTextContent('/scans/new');
    expect(JSON.parse(String(posts(calls)[0].init.body))).toEqual({ token, newPassword });
    expect(calls.every((call) => !call.path.includes(token))).toBe(true);
    expect(posts(calls)).toHaveLength(1);
  },
);
it.each([`?token=${token}`, `#token=${token}&extra=1`, '#token=bad'])(
  'TASK54 invalid token location rejects without echo or confirmation POST',
  async (suffix) => {
    const calls = api(async () => {
      throw Error('POST forbidden');
    });
    mount(`/reset-password${suffix}`);
    await screen.findByText(/Действительная ссылка не найдена/);
    expect(window.location.pathname + window.location.search + window.location.hash).toBe('/reset-password');
    expect(screen.getByRole('button', { name: 'Сохранить новый пароль' })).toBeDisabled();
    expect(document.body.innerHTML).not.toContain(token);
    expect(posts(calls)).toHaveLength(0);
  },
);
it('TASK54 request client malformed202 is not success and does not retry', async () => {
  const calls = api(async () => json({ status: 'accepted', delivered: true }, 202));
  await expect(requestPasswordReset('Synthetic@Example.Test')).rejects.toThrow(/Не удалось подтвердить/);
  expect(posts(calls)).toHaveLength(1);
});
