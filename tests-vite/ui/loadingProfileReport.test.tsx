import '@testing-library/jest-dom/vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import { RouteLoading } from '@/shared/ui/RouteLoading';
import { DemoAuthPage } from '@/pages/auth/DemoAuthPage';
import { ScanReportOverview } from '@/pages/scans/ScanReportOverview';
import { VulnAdvisoryCard } from '@/pages/scans/VulnAdvisoryCard';
import { transitionScanSession } from '@/shared/api/auth/scanSession';
import type { ScanStatus, VulnFinding } from '@/shared/api/scans/scanTransport';

const fetchMock = vi.fn<typeof fetch>();
const clients: QueryClient[] = [];
const identity = { id: 'synthetic-ux-owner', email: 'synthetic-ux@example.invalid' };
const response = (status: number, body?: object) => new Response(body ? JSON.stringify(body) : null, { status, headers: { 'content-type': 'application/json' } });
function mountAccount(mode: 'account' | 'login' = 'account') {
  vi.stubGlobal('fetch', fetchMock);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter><DemoAuthPage mode={mode} /></MemoryRouter></QueryClientProvider>);
  return client;
}
afterEach(() => {
  cleanup(); for (const client of clients.splice(0)) client.clear();
  transitionScanSession(null, new QueryClient(), true);
  fetchMock.mockReset(); vi.unstubAllGlobals(); localStorage.clear();
});

it('route loading politely announces readiness without fictional percentage or estimate', () => {
  render(<RouteLoading />);
  expect(screen.getByRole('main', { name: 'Загрузка страницы' })).toBeVisible();
  expect(screen.getByRole('status')).toHaveAttribute('aria-live', 'polite');
  expect(screen.getByRole('status')).toHaveTextContent('Загружаем страницу');
  expect(screen.queryByRole('progressbar')).toBeNull();
  expect(document.body.textContent).not.toMatch(/\d+%|\d+ секунд/);
});
it('pending identity hides private controls, then confirmed anonymous gets login and register', async () => {
  let finish!: (value: Response) => void;
  fetchMock.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const client = mountAccount();
    client.setQueryDefaults(['unrelated-public'], { gcTime: Infinity });
    client.setQueryData(['unrelated-public'], 'preserved');
  expect(await screen.findByRole('status')).toHaveTextContent('Проверяем сессию');
  expect(screen.queryByLabelText('Текущий пароль')).toBeNull();
  expect(screen.queryByText(identity.email)).toBeNull();
  await act(async () => finish(response(401)));
  expect(await screen.findByRole('link', { name: 'Войти' })).toBeVisible();
  expect(screen.getByRole('link', { name: 'Создать аккаунт' })).toBeVisible();
  expect(client.getQueryData(['unrelated-public'])).toBe('preserved');
  expect(fetchMock.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
});
it('verified account uses collapsed disclosures and one-attempt confirmation reset on draft edits', async () => {
  fetchMock.mockResolvedValue(response(200, identity)); mountAccount();
  expect(await screen.findByText(identity.email)).toBeVisible();
  const summary = screen.getByText('Сменить пароль', { exact: true });
  expect(summary.closest('details')).not.toHaveAttribute('open');
  const preferences = screen.getAllByText('Настройки отчётов').find(node => node.closest('summary'))!;
  expect(preferences.closest('details')).not.toHaveAttribute('open');
  fireEvent.click(summary);
  const form = screen.getByRole('form', { name: 'Смена пароля' });
  expect(form).toHaveAccessibleDescription(/все сеансы завершатся/);
  fireEvent.change(within(form).getByLabelText('Текущий пароль'), { target: { value: 'synthetic-old-password' } });
  fireEvent.change(within(form).getByLabelText('Новый пароль'), { target: { value: 'synthetic-new-password' } });
  fireEvent.change(within(form).getByLabelText('Повторите новый пароль'), { target: { value: 'synthetic-new-password' } });
  fireEvent.submit(form);
  expect(fetchMock).toHaveBeenCalledTimes(1);
  const consent = within(form).getByRole('checkbox'); fireEvent.click(consent); expect(consent).toBeChecked();
  fireEvent.change(within(form).getByLabelText('Новый пароль'), { target: { value: 'changed-synthetic-password' } });
  expect(consent).not.toBeChecked(); fireEvent.submit(form);
  expect(fetchMock).toHaveBeenCalledTimes(1);
});
it('login pending locks duplicate submit; invalid credentials retain draft and never retry POST', async () => {
  let finish!: (value: Response) => void;
  fetchMock.mockImplementation(async (_input, init) => init?.method === 'POST' ? new Promise(resolve => { finish = resolve; }) : response(401));
  mountAccount('login');
  const email = screen.getByLabelText('Email'), password = screen.getByLabelText('Пароль');
  fireEvent.change(email, { target: { value: identity.email } });
  fireEvent.change(password, { target: { value: 'synthetic-login-password' } });
  const form = email.closest('form')!; fireEvent.submit(form); fireEvent.submit(form);
  await waitFor(() => expect(finish).toBeTypeOf('function'));
  expect(email).toBeDisabled(); expect(password).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Подождите…' })).toBeDisabled();
  await act(async () => finish(response(401, { errorCode: 'INVALID_CREDENTIALS' })));
  expect(await screen.findByRole('alert')).toBeVisible();
  expect(email).toHaveValue(identity.email); expect(password).toHaveValue('synthetic-login-password');
  expect(fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
});
it('partial overview preserves checked zero, unknown failures, visible next steps and exact singular', () => {
  const status: ScanStatus = { scanId: 'synthetic', state: 'partial', checks: ['secret', 'vuln', 'config'], perCheck: {
    secret: { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 1 },
    vuln: { check: 'vuln', coverage: 'image', outcome: 'failed', errorCode: 'SCAN_FAILED' },
    config: { check: 'config', coverage: 'image', outcome: 'checked', findingCount: 0 },
  } };
  const findings = vi.fn(), coverage = vi.fn();
  render(<ScanReportOverview status={status} onShowFindings={findings} onShowCoverage={coverage} />);
  const row = (name: string) => screen.getByText(name, { exact: true }).closest('div')!;
  expect(row('Уязвимости пакетов')).toHaveAttribute('data-result', 'unknown');
  expect(row('Настройки образа')).toHaveAttribute('data-result', 'zero');
  expect.soft(row('Возможные секреты')).toHaveTextContent('1 находка');
  expect.soft(document.body.textContent).not.toContain('1 находок');
  expect(screen.getByText(/Результаты неполны/)).toBeVisible();
  fireEvent.click(screen.getByRole('link', { name: 'Посмотреть возможные секреты' })); expect(findings).toHaveBeenCalledWith('secret');
  fireEvent.click(screen.getByRole('link', { name: 'Посмотреть ограничения' })); expect(coverage).toHaveBeenCalledTimes(1);
});
// Owner-scoped disclosure/draft regression, selected independently from report tests.
it('background identity GET hides private data then restores same-owner context/draft but clears changed owner without POST', async () => {
  let finish!: (value: Response) => void;
  fetchMock.mockResolvedValueOnce(response(200, identity));
  const client = mountAccount();
  await screen.findByText(identity.email);
  const summary = () => screen.getByText('Сменить пароль', { exact: true }).closest('summary')!;
  fireEvent.click(summary());
  fireEvent.change(screen.getByLabelText('Текущий пароль', { exact: true }), { target: { value: 'synthetic-preserved-current' } });
  fireEvent.change(screen.getByLabelText('Новый пароль', { exact: true }), { target: { value: 'synthetic-preserved-new' } });
  fireEvent.change(screen.getByLabelText('Повторите новый пароль', { exact: true }), { target: { value: 'synthetic-preserved-new' } });
  const preferences = screen.getAllByText('Настройки отчётов').find(node => node.closest('summary'))!.closest('details')!;
  fireEvent.click(preferences.querySelector('summary')!);
  for (const next of [identity, { id: 'synthetic-next-owner', email: 'next-owner@example.invalid' }]) {
    fetchMock.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    await act(async () => { void client.refetchQueries({ queryKey: ['demo-auth', 'me'], exact: true }); });
    await waitFor(() => expect(client.getQueryState(['demo-auth', 'me'])?.fetchStatus).toBe('fetching'));
    expect(screen.queryByText(identity.email)).toBeNull();
    expect(screen.queryByRole('form', { name: 'Смена пароля' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Выйти из аккаунта' })).toBeNull();
    await act(async () => finish(response(200, next)));
    await screen.findByText(next.email);
    if (next.id === identity.id) {
      expect(summary().closest('details')).toHaveAttribute('open');
      expect(screen.getByLabelText('Текущий пароль', { exact: true })).toHaveValue('synthetic-preserved-current');
      expect(screen.getByLabelText('Новый пароль', { exact: true })).toHaveValue('synthetic-preserved-new');
      expect(screen.getByLabelText('Повторите новый пароль', { exact: true })).toHaveValue('synthetic-preserved-new');
      const restored = screen.getAllByText('Настройки отчётов').find(node => node.closest('summary'))!.closest('details')!;
      expect.soft(restored, 'Same-owner report-preferences disclosure context').toHaveAttribute('open');
    } else {
      expect(summary().closest('details')).not.toHaveAttribute('open');
      fireEvent.click(summary());
      expect(screen.getByLabelText('Текущий пароль', { exact: true })).toHaveValue('');
      expect(screen.getByLabelText('Новый пароль', { exact: true })).toHaveValue('');
      expect(screen.getByLabelText('Повторите новый пароль', { exact: true })).toHaveValue('');
    }
  }
  expect(fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(0);
});
it('DLA is a Debian bulletin not a CVE/NVD link; overview counts findings rather than unique CVEs', () => {
  const finding: VulnFinding = { findingId: 'synthetic-dla', cveId: 'DLA-3500-1', ecosystem: 'deb', packageName: 'synthetic-package', installedVersion: '1.0', fixedVersion: '1.1', severity: 'HIGH' };
  const status: ScanStatus = { scanId: 'synthetic-dla-report', state: 'completed', checks: ['vuln'], perCheck: {
    vuln: { check: 'vuln', coverage: 'image', outcome: 'checked', findingCount: 2 },
  } };
  const view = render(<><ScanReportOverview status={status} onShowFindings={vi.fn()} onShowCoverage={vi.fn()} /><ul><VulnAdvisoryCard finding={finding} /><VulnAdvisoryCard finding={{ ...finding, findingId: 'synthetic-cve', cveId: 'CVE-2026-1234' }} /></ul></>);
  const rows = view.container.querySelectorAll('.scan-vuln-row');
  fireEvent.click(within(rows[0] as HTMLElement).getByText('Подробности · описание уязвимости и источники'));
  fireEvent.click(within(rows[1] as HTMLElement).getByText('Подробности · описание уязвимости и источники'));
  expect(rows[0]).toHaveTextContent('Бюллетень Debian DLA (не CVE)');
  expect(rows[0].querySelector('a[href*="nvd.nist.gov"], a[href*="cve.org"]')).toBeNull();
  expect(within(rows[1] as HTMLElement).getByRole('link', { name: 'NVD · открыть запись' })).toHaveAttribute('href', 'https://nvd.nist.gov/vuln/detail/CVE-2026-1234');
  const count = screen.getByText('Уязвимости пакетов', { exact: true }).closest('div')!;
  expect(count).toHaveTextContent('2 находки'); expect(count).not.toHaveTextContent(/2 CVE|2 уникальн/);
});
it('legacy missing coverage is unknown rather than fabricated zero or a safety guarantee', () => {
  render(<ScanReportOverview status={{ scanId: 'legacy', state: 'completed' }} onShowFindings={vi.fn()} onShowCoverage={vi.fn()} />);
  expect(document.querySelectorAll('[data-result="unknown"]')).toHaveLength(4);
  expect(document.querySelectorAll('[data-result="zero"]')).toHaveLength(0);
  expect(screen.getByText('Данных недостаточно для полного вывода')).toBeVisible();
  expect(screen.getByText(/Неизвестно — не значит ноль/)).toBeVisible();
});
