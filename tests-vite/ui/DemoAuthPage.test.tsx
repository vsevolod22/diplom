import '@testing-library/jest-dom/vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Link, MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DemoAuthPage } from '@/pages/auth/DemoAuthPage';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
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

describe('batch4 regression: obsolete auth operations', () => {
  it.each(['login', 'register', 'logout'] as const)('late %s response cannot navigate/transition/cache-clear after route unmount; fresh GET revalidates server auth', async action => {
    const user = userEvent.setup();
    const identity = { id: 'late-auth-owner', email: 'late-auth@example.invalid' };
    let resolvePost!: (value: Response) => void;
    let resolveFresh!: (value: Response) => void;
    const post = new Promise<Response>(resolve => { resolvePost = resolve; });
    const fresh = new Promise<Response>(resolve => { resolveFresh = resolve; });
    let meReads = 0;
    fetchMock.mockImplementation(async input => {
      const path = String(input);
      if (path === '/api/v1/auth/me') return ++meReads === 1
        ? action === 'logout' ? response(200, identity) : response(401)
        : fresh;
      if (path === `/api/v1/auth/${action}`) return post;
      throw new Error(`Unexpected controlled auth route: ${path}`);
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    transitionScanSession(null, client, true);
    function Probe() { return <output aria-label="Obsolete auth route">{useLocation().pathname}</output>; }
    render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[action === 'logout' ? '/account' : `/${action}`]}>
      <Probe /><Routes>
        <Route path="/login" element={<DemoAuthPage mode="login" />} />
        <Route path="/register" element={<DemoAuthPage mode="register" />} />
        <Route path="/account" element={<DemoAuthPage mode="account" />} />
        <Route path="/" element={<><p>Unchanged public route</p><Link to="/account">Revalidate account by GET</Link></>} />
      </Routes>
    </MemoryRouter></QueryClientProvider>);
    await waitFor(() => expect(client.getQueryState(['demo-auth', 'me'])?.status).toBe('success'));
    if (action !== 'logout') {
      await user.type(screen.getByLabelText('Email'), identity.email);
      await user.type(screen.getByLabelText('Пароль'), 'synthetic-long-auth-password');
      await user.click(screen.getByRole('button', { name: action === 'register' ? 'Создать аккаунт' : 'Войти' }));
    } else await user.click(await screen.findByRole('button', { name: 'Выйти из аккаунта' }));
    await waitFor(() => expect(fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1));
    await user.click(screen.getByRole('link', { name: 'На главную' }));
    await screen.findByText('Unchanged public route');
    const accepted = scanSession();
    client.setQueryData(['private-sentinel'], { untouched: true });
    await act(async () => { resolvePost(action === 'logout' ? response(204) : response(action === 'register' ? 201 : 200, identity)); });
    expect(screen.getByLabelText('Obsolete auth route')).toHaveTextContent(/^\/$/);
    // Revalidation may close private UI as unverified; the obsolete POST must never publish its user.
    expect(scanSession().subject).toBeNull();
    expect(scanSession().generation).toBeGreaterThanOrEqual(accepted.generation);
    expect(client.getQueryData(['private-sentinel'])).toEqual({ untouched: true });
    await user.click(screen.getByRole('link', { name: 'Revalidate account by GET' }));
    await waitFor(() => expect(meReads).toBeGreaterThanOrEqual(2));
    await act(async () => { resolveFresh(action === 'logout' ? response(401) : response(200, identity)); });
    await waitFor(() => expect(scanSession().subject).toBe(action === 'logout' ? null : identity.id));
    expect(client.getQueryData(['demo-auth', 'me'])).toEqual(action === 'logout' ? null : identity);
    expect(screen.getByLabelText('Obsolete auth route')).toHaveTextContent('/account');
    expect(fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    expect(localStorage.length).toBe(0);
    client.clear();
  });
});

describe('optional demo account', () => {
  it('saves report language without automatic summary only after explicit account confirmation', async () => {
    const user = userEvent.setup();
    fetchMock.mockResolvedValueOnce(response(200, { id: 'preferences-owner', email: 'owner@example.org' }));
    setup('/account');
    const panel = await screen.findByRole('region', { name: 'Настройки отчётов' });
    const language = within(panel).getByRole('combobox', { name: 'Язык исходных описаний уязвимостей' });
    expect(language).toHaveProperty('value', 'original');
    expect(language).toHaveAttribute('id', 'report-preferences-language');
    expect(language).toHaveAccessibleDescription('Эта настройка относится только к заголовкам и описаниям уязвимостей из источников. ИИ-отчёт и ответы в чате сразу формируются на русском — отдельный перевод для них не нужен.');
    expect(within(language).getAllByRole('option').map(option => (option as HTMLOptionElement).value)).toEqual(['original', 'ru']);
    expect(within(panel).getAllByRole('combobox')).toHaveLength(2);
    expect(within(panel).queryByText('Краткая ИИ-сводка')).toBeNull();
    const terms = within(panel).getByText('Условия ИИ-разбора и перевода');
    expect(terms.closest('details')).not.toHaveAttribute('open');
    expect(within(panel).getByText(/dots-studio\/dots-3-note-preview:free/)).not.toBeVisible();
    expect(within(panel).getByText(/Сохраняя «Русский»/)).toBeVisible();
    expect(within(panel).getByText(/Сохраняя «Русский»/)).toHaveTextContent(
      'передать внешнему ИИ только исходные заголовок и описание выбранной уязвимости для перевода. Данные могут сохраняться.',
    );
    expect(within(panel).queryByRole('checkbox')).toBeNull();
    expect(panel.textContent).toContain('для аккаунта в этом браузере');
        expect(panel.querySelector('#report-preferences-disclosure')?.getAttribute('data-automation-revision'))
          .toBe('report-automation-v4-remediation');
    await user.click(terms);
    expect(within(panel).getByText(/dots-studio\/dots-3-note-preview:free/)).toBeVisible();
    for (const disclosure of ['OpenRouter', 'dots-studio/dots-3-note-preview:free', 'Atlas Cloud', 'atlas-cloud/fp8', 'no-training',
          'но не отсутствие хранения', 'могут сохраняться', 'не Zero Data Retention (ZDR)', 'качество в продукте ещё не проверено',
      'бесплатном режиме', 'заголовка и', 'машинная интерпретация',
      'квоты пользователя и отчёта', 'новой версии согласия']) {
      expect(panel.textContent).toContain(disclosure);
    }
    expect(localStorage.length).toBe(0);
    await user.selectOptions(language, 'ru');
    expect(localStorage.length).toBe(0);
    expect(readReportPreferences()).toMatchObject({ language: 'original', autoSummary: false, authorized: false });
    await user.click(within(panel).getByRole('button', { name: 'Сохранить настройки отчётов' }));
    expect(await within(panel).findByRole('status')).toHaveProperty('textContent', 'Настройки сохранены для аккаунта в этом браузере.');
    expect(readReportPreferences()).toMatchObject({ language: 'ru', autoSummary: false, authorized: true });
    expect(JSON.parse(localStorage.getItem('report-preferences:v1:preferences-owner')!)).toEqual({
      version: 1, automationRevision: REPORT_AUTOMATION_REVISION, language: 'ru', autoSummary: false,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const summary = within(panel).getByRole('combobox', { name: 'ИИ-разбор' });
    await user.selectOptions(summary, 'on');
    expect(readReportPreferences()).toMatchObject({ autoSummary: false });
    await user.click(within(panel).getByRole('button', { name: 'Сохранить настройки отчётов' }));
    expect(readReportPreferences()).toMatchObject({ language: 'ru', autoSummary: true });
    await user.selectOptions(summary, 'off');
    await user.selectOptions(language, 'original');
    expect(readReportPreferences()).toMatchObject({ language: 'ru', autoSummary: true });
    await user.click(within(panel).getByRole('button', { name: 'Сохранить настройки отчётов' }));
    expect(readReportPreferences()).toMatchObject({ language: 'original', autoSummary: false });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each([REPORT_AUTOMATION_REVISION, 'report-automation-v2'])('keeps stored %s consent untouched until explicit save, then disables only automatic summary', async (revision) => {
    const user = userEvent.setup();
    const key = 'report-preferences:v1:existing-owner';
    const raw = JSON.stringify({ version: 1, automationRevision: revision, language: 'ru', autoSummary: true });
    localStorage.setItem(key, raw);
    localStorage.setItem('unrelated-preference', 'keep');
    fetchMock.mockResolvedValueOnce(response(200, { id: 'existing-owner', email: 'owner@example.org' }));
    setup('/account');
    const panel = await screen.findByRole('region', { name: 'Настройки отчётов' });
    const session = scanSession();
    const currentPolicy = revision === REPORT_AUTOMATION_REVISION;
    expect(readReportPreferences()).toMatchObject({
      language: currentPolicy ? 'ru' : 'original',
      autoSummary: currentPolicy,
      authorized: currentPolicy,
      revision: currentPolicy ? REPORT_AUTOMATION_REVISION : null,
    });
    await user.click(within(panel).getByText('Условия ИИ-разбора и перевода'));
    await user.selectOptions(within(panel).getByRole('combobox', { name: 'Язык исходных описаний уязвимостей' }), 'ru');
    await user.selectOptions(within(panel).getByRole('combobox', { name: 'ИИ-разбор' }), 'off');
    expect(localStorage.getItem(key)).toBe(raw);
    expect(readReportPreferences().authorized).toBe(currentPolicy);
    await user.click(within(panel).getByRole('button', { name: 'Сохранить настройки отчётов' }));
    expect(readReportPreferences()).toMatchObject({
      language: 'ru', autoSummary: false, authorized: true, revision: REPORT_AUTOMATION_REVISION,
    });
    expect(JSON.parse(localStorage.getItem(key)!)).toEqual({
      version: 1, automationRevision: REPORT_AUTOMATION_REVISION, language: 'ru', autoSummary: false,
    });
    expect(localStorage.getItem('unrelated-preference')).toBe('keep');
    expect(scanSession()).toEqual(session);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('shows a storage failure without enabling automatic requests', async () => {
    const user = userEvent.setup();
    fetchMock.mockResolvedValueOnce(response(200, { id: 'storage-owner', email: 'owner@example.org' }));
    setup('/account');
    const language = await screen.findByRole('combobox', { name: 'Язык исходных описаний уязвимостей' });
    await user.selectOptions(language, 'ru');
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('Unavailable'); });
    await user.click(screen.getByRole('button', { name: 'Сохранить настройки отчётов' }));
    expect(await screen.findByRole('alert')).toHaveProperty('textContent',
      'Не удалось сохранить настройки. Автоматические функции отключены; проверьте доступ к хранилищу браузера.');
    expect(readReportPreferences()).toMatchObject({ language: 'original', autoSummary: false, authorized: false });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('discards unsaved choices on a new session generation and disables a stale account form', async () => {
    const user = userEvent.setup();
    fetchMock.mockResolvedValueOnce(response(200, { id: 'session-owner', email: 'owner@example.org' }));
    const client = setup('/account');
    const language = await screen.findByRole('combobox', { name: 'Язык исходных описаний уязвимостей' });
    await user.selectOptions(language, 'ru');

    act(() => transitionScanSession('session-owner', client, true));
    expect(language).toHaveProperty('value', 'original');
    expect(screen.queryByRole('combobox', { name: 'Краткая ИИ-сводка' })).toBeNull();
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
  it.each(['network', '503'])('keeps account verification failure %s closed locally without logging out, then retries manually', async failure => {
    const user = userEvent.setup();
    const identity = { id: 'retry-owner', email: 'retry@example.org' };
    if (failure === 'network') fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'));
    else fetchMock.mockResolvedValueOnce(response(503));
    fetchMock.mockResolvedValueOnce(response(200, identity));
    const client = setup('/account');
    client.setQueryData(['live-scans', 0, 'retry-owner', 'private-snapshot'], { secret: 'must clear' });
    expect(await screen.findByRole('alert')).toHaveTextContent('Не удалось проверить сессию');
    expect(screen.queryByText(identity.email)).not.toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: 'Язык исходных описаний уязвимостей' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Выйти из аккаунта' })).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(scanSession().subject).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Повторить проверку сессии' }));
    expect(await screen.findByText(identity.email)).toBeVisible();
    expect(client.getQueryData(['live-scans', 0, 'retry-owner', 'private-snapshot'])).toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls.every(([path, options]) => path === '/api/v1/auth/me' && options?.method !== 'POST')).toBe(true);
    expect(screen.getByRole('link', { name: /Смотреть демо без регистрации/ })).toBeVisible();
  });
});
