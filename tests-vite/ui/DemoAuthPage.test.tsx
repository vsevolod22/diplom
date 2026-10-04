import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DemoAuthPage } from '@/pages/auth/DemoAuthPage';

const fetchMock = vi.fn<typeof fetch>();
vi.stubGlobal('fetch', fetchMock);
afterEach(() => { cleanup(); fetchMock.mockReset(); });

function setup(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Routes>
    <Route path="/register" element={<DemoAuthPage mode="register" />} />
    <Route path="/login" element={<DemoAuthPage mode="login" />} />
    <Route path="/account" element={<DemoAuthPage mode="account" />} />
  </Routes></MemoryRouter></QueryClientProvider>);
  return client;
}
const response = (status: number, body?: object) => ({ status, ok: status >= 200 && status < 300, json: async () => body }) as Response;

describe('optional demo account', () => {
  it('registers with same-origin cookie requests, clears cached data and logs out', async () => {
    const user = userEvent.setup();
    const identity = { id: 'u1', email: 'test@example.org' };
    fetchMock.mockResolvedValueOnce(response(401)).mockResolvedValueOnce(response(201, identity)).mockResolvedValueOnce(response(204));
    const client = setup('/register');
    client.setQueryData(['private-snapshot'], { secret: 'must clear' });
    expect(screen.getByRole('link', { name: /Смотреть демо без регистрации/ }).getAttribute('href')).toBe('/demo/scans');
    await user.type(screen.getByLabelText('Email'), identity.email);
    await user.type(screen.getByLabelText('Пароль'), 'long-unique-password');
    await user.click(screen.getByRole('button', { name: 'Создать аккаунт' }));
    expect(await screen.findByText(identity.email)).toBeTruthy();
    expect(screen.getByText(identity.id)).toBeTruthy();
    expect(client.getQueryData(['private-snapshot'])).toBeUndefined();
    expect(fetchMock.mock.calls[1][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
    expect(JSON.parse(String(fetchMock.mock.calls[1][1]?.body))).toEqual({ email: identity.email, password: 'long-unique-password' });
    expect(fetchMock.mock.calls[1][0]).toBe('/api/v1/auth/register');
    client.setQueryData(['another-snapshot'], 1);
    await user.click(screen.getByRole('button', { name: 'Выйти из аккаунта' }));
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Вход' })).toBeTruthy());
    expect(client.getQueryData(['another-snapshot'])).toBeUndefined();
    expect(fetchMock.mock.calls[2][0]).toBe('/api/v1/auth/logout');
    expect(fetchMock.mock.calls[2][1]).toMatchObject({ method: 'POST', credentials: 'same-origin' });
  });
  it('shows invalid credentials without storing the password and offers guest demo', async () => {
    const user = userEvent.setup();
    fetchMock.mockResolvedValueOnce(response(401)).mockResolvedValueOnce(response(401));
    setup('/login');
    await user.type(screen.getByLabelText('Email'), 'test@example.org');
    await user.type(screen.getByLabelText('Пароль'), 'long-unique-password');
    await user.click(screen.getByRole('button', { name: 'Войти' }));
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'Неверный email или пароль.');
    expect(screen.getByRole('link', { name: /Смотреть демо без регистрации/ })).toBeTruthy();
  });
  it('revokes and redirects to login when account verification fails', async () => {
    fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'))
      .mockResolvedValueOnce(response(204)).mockResolvedValueOnce(response(401));
    const client = setup('/account');
    client.setQueryData(['private-snapshot'], { secret: 'must clear' });
    expect(await screen.findByRole('heading', { name: 'Вход' })).toBeTruthy();
    expect(screen.getByRole('alert')).toHaveProperty('textContent', 'Не удалось проверить сессию. Доступ закрыт, выполните вход заново.');
    expect(client.getQueryData(['private-snapshot'])).toBeUndefined();
    expect(fetchMock.mock.calls.some(([path, options]) => path === '/api/v1/auth/logout' && options?.method === 'POST')).toBe(true);
  });
  it('closes the private view but does not claim server logout if auth backend is unavailable', async () => {
    fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'))
      .mockRejectedValueOnce(new TypeError('Failed to fetch')).mockResolvedValueOnce(response(401));
    const client = setup('/account');
    client.setQueryData(['private-snapshot'], { secret: 'must clear' });
    expect(await screen.findByRole('heading', { name: 'Вход' })).toBeTruthy();
    expect(screen.getByRole('alert')).toHaveProperty('textContent', 'Не удалось проверить сессию. Доступ закрыт, но сервер не подтвердил выход. Проверьте подключение и войдите заново.');
    expect(client.getQueryData(['private-snapshot'])).toBeUndefined();
    expect(screen.getByRole('link', { name: /Смотреть демо без регистрации/ })).toBeTruthy();
  });
});
