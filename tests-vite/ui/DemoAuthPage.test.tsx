import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DemoAuthPage } from '@/pages/auth/DemoAuthPage';
import { transitionScanSession } from '@/shared/api/auth/scanSession';
import { readReportPreferences, REPORT_AUTOMATION_REVISION } from '@/shared/api/preferences/reportPreferences';

const fetchMock = vi.fn<typeof fetch>();
vi.stubGlobal('fetch', fetchMock);
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  transitionScanSession(null, new QueryClient(), true);
  localStorage.clear();
  fetchMock.mockReset();
});

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
  it('saves report language and automatic summary only after explicit account confirmation', async () => {
    const user = userEvent.setup();
    fetchMock.mockResolvedValueOnce(response(200, { id: 'preferences-owner', email: 'owner@example.org' }));
    setup('/account');
    const panel = await screen.findByRole('region', { name: 'Язык и сводка отчётов' });
    const language = within(panel).getByRole('combobox', { name: 'Язык отчёта' });
    const summary = within(panel).getByRole('combobox', { name: 'Краткая ИИ-сводка' });
    expect(language).toHaveProperty('value', 'original');
    expect(summary).toHaveProperty('value', 'off');
    expect(within(panel).queryByRole('checkbox')).toBeNull();
    expect(panel.textContent).toContain('для аккаунта в этом браузере');
    for (const disclosure of ['OpenRouter', 'xingchen-agi/xing4.0-29b-a4b:free', 'Phala',
      'бесплатном режиме', 'заголовка и', 'очищенные находки', 'машинная интерпретация',
      'квоты пользователя и отчёта', 'новой версии согласия']) {
      expect(panel.textContent).toContain(disclosure);
    }
    expect(localStorage.length).toBe(0);
    await user.selectOptions(language, 'ru');
    await user.selectOptions(summary, 'on');
    expect(localStorage.length).toBe(0);
    expect(readReportPreferences()).toMatchObject({ language: 'original', autoSummary: false, authorized: false });
    await user.click(within(panel).getByRole('button', { name: 'Сохранить настройки отчётов' }));
    expect(await within(panel).findByRole('status')).toHaveProperty('textContent', 'Настройки сохранены для аккаунта в этом браузере.');
    expect(readReportPreferences()).toMatchObject({ language: 'ru', autoSummary: true, authorized: true });
    expect(JSON.parse(localStorage.getItem('report-preferences:v1:preferences-owner')!)).toEqual({
      version: 1, automationRevision: REPORT_AUTOMATION_REVISION, language: 'ru', autoSummary: true,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await user.selectOptions(language, 'original');
    await user.selectOptions(summary, 'off');
    expect(readReportPreferences()).toMatchObject({ language: 'ru', autoSummary: true });
    await user.click(within(panel).getByRole('button', { name: 'Сохранить настройки отчётов' }));
    expect(readReportPreferences()).toMatchObject({ language: 'original', autoSummary: false });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('shows a storage failure without enabling automatic requests', async () => {
    const user = userEvent.setup();
    fetchMock.mockResolvedValueOnce(response(200, { id: 'storage-owner', email: 'owner@example.org' }));
    setup('/account');
    const language = await screen.findByRole('combobox', { name: 'Язык отчёта' });
    await user.selectOptions(language, 'ru');
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('Unavailable'); });
    await user.click(screen.getByRole('button', { name: 'Сохранить настройки отчётов' }));
    expect(await screen.findByRole('alert')).toHaveProperty('textContent',
      'Не удалось сохранить настройки. Автоматика отключена; проверьте доступ к хранилищу браузера.');
    expect(readReportPreferences()).toMatchObject({ language: 'original', autoSummary: false, authorized: false });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('discards unsaved choices on a new session generation and disables a stale account form', async () => {
    const user = userEvent.setup();
    fetchMock.mockResolvedValueOnce(response(200, { id: 'session-owner', email: 'owner@example.org' }));
    const client = setup('/account');
    const language = await screen.findByRole('combobox', { name: 'Язык отчёта' });
    await user.selectOptions(language, 'ru');
    await user.selectOptions(screen.getByRole('combobox', { name: 'Краткая ИИ-сводка' }), 'on');
    act(() => transitionScanSession('session-owner', client, true));
    expect(language).toHaveProperty('value', 'original');
    expect(screen.getByRole('combobox', { name: 'Краткая ИИ-сводка' })).toHaveProperty('value', 'off');
    act(() => transitionScanSession('other-owner', client, true));
    expect(screen.getByRole('button', { name: 'Сохранить настройки отчётов' })).toHaveProperty('disabled', true);
    expect(localStorage.length).toBe(0);
  });
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
    expect(screen.queryByRole('combobox')).toBeNull();
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
