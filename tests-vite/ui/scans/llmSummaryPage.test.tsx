import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { webcrypto } from 'node:crypto';
import { saveReportPreferences } from '@/shared/api/preferences/reportPreferences';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { LiveScanSession } from '@/features/scans/LiveScanSession';
import { ScanDetailPage } from '@/pages/scans/ScanDetailPage';
import { transitionScanSession } from '@/shared/api/auth/scanSession';
import { PUBLIC_IMAGE_PROFILE } from '@/shared/api/scans/publicImageProfile';
import { context as chatContext, history as chatHistory, usage } from './llmChatFixtures';

const id = '00000000-0000-4000-8000-000000000038';
const other = '00000000-0000-4000-8000-000000000039';
const digest = `sha256:${'a'.repeat(64)}`;
const tuple = { scanId: id, digest, platform: 'linux/amd64', reportVersion: 'b'.repeat(64) };
const coverage = {
  check: 'secret',
  coverage: 'image',
  outcome: 'checked',
  errorCode: null,
  scannerVersion: '0.69.3',
  findingCount: 2,
};
const context = {
  ...tuple,
  enabled: true,
  policyVersion: 'c'.repeat(64),
  disclosure: {
    provider: 'OpenRouter',
    model: 'xingchen-agi/xing4.0-29b-a4b:free',
    providers: ['phala'],
    region: 'global',
    retention: 'no-storage',
    operatorApprovedRouting: true,
    providerComplianceNotProvenByDeclaration: true,
    requestBudgetUsd: 0,
    freeOnly: true,
    maxPrice: { prompt: 0, completion: 0, request: 0 },
    data: 'Sanitized scanner findings and coverage; no raw evidence or credentials.',
  },
};
const reply = {
  ...tuple,
  hypotheses: [{ kind: 'hypothesis', text: 'Late-page hypothesis', citations: ['secret-0-1'] }],
  scannerFacts: [{ findingId: 'secret-0-1', check: 'secret', severity: 'UNKNOWN' }],
};
const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const requests: Array<{ path: string; init?: RequestInit }> = [];
class Observer {
  observe() {}
  unobserve() {}
  disconnect() {}
}
beforeEach(() => {
  requests.length = 0;
  localStorage.clear();
  sessionStorage.clear();
  vi.stubGlobal('crypto', webcrypto);
  vi.stubGlobal('IntersectionObserver', Observer);
  transitionScanSession('alice', new QueryClient(), true);
  saveReportPreferences({ language: 'original', autoSummary: true });
  transitionScanSession(null, new QueryClient(), true);
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
function mockApi(
  state = 'completed',
  summary: () => Response | Promise<Response> = () => json(reply),
  policy: unknown = context,
  existing: () => Response | Promise<Response> = () => json({ errorCode: 'LLM_SUMMARY_MISSING' }, 404),
  profile?: typeof PUBLIC_IMAGE_PROFILE,
) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (path: string, init?: RequestInit) => {
      requests.push({ path, init });
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.endsWith('/llm/context')) return json(policy);
      if (path.endsWith('/llm/summary')) return init?.method === 'GET' ? existing() : summary();
      if (path.endsWith('/llm/usage'))
        return json({ ...usage, ...tuple, integrationEnabled: true, quotaEnabled: true });
      if (path.includes('/results')) {
        const url = new URL(path, window.location.origin);
        if (url.searchParams.get('view') === 'report-v1')
          return json({
            findings: [0, 1].map((index) => ({
              findingId: `secret-0-${index}`,
              ruleId: 'rule-0000000000000000',
              line: 1,
              evidenceRef: `result-0-secret-${index}`,
            })),
            nextCursor: null,
            coverage,
            page: {
              version: 1,
              limit: 25,
              offset: 0,
              returnedCount: 2,
              totalCount: 2,
              matchedCount: 2,
              sort: 'ruleId:asc',
              filters: { ruleId: null, linePresence: null },
            },
          });
        // Citation resolution deliberately retains the separate legacy scanner API.
        const late = path.includes('cursor=1');
        return json({
          findings: [
            {
              findingId: late ? 'secret-0-1' : 'secret-0-0',
              ruleId: 'rule-0000000000000000',
              line: 1,
              evidenceRef: late ? 'result-0-secret-1' : 'result-0-secret-0',
            },
          ],
          nextCursor: late ? null : 1,
          coverage,
        });
      }
      return json({
        ...(profile ? { profile, imageReference: `registry-1.docker.io/library/alpine@${digest}` } : {}),
        scanId: path.endsWith(other) ? other : id,
        digest,
        platform: tuple.platform,
        state,
        checks: ['secret'],
        perCheck: { secret: coverage },
        result: coverage,
      });
    }),
  );
}
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/scans/${id}`]}>
        <Link to={`/scans/${other}`}>Другой скан</Link>
        <Routes>
          <Route
            path="/scans/:scanId"
            element={
              <LiveScanSession>
                <ScanDetailPage />
              </LiveScanSession>
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
async function generate() {
  await waitFor(() => expect(requests.filter((request) => request.init?.method === 'POST')).toHaveLength(1));
}
it('terminal ScanDetail replaces placeholder; hidden current category and late-page source remain reachable', async () => {
  mockApi();
  mount();
  await screen.findByText(/только бесплатный режим/);
  expect(screen.queryByRole('textbox', { name: 'Ваш вопрос' })).toBeNull();
  fireEvent.change(screen.getByLabelText('Категория'), { target: { value: 'cve' } });
  expect(screen.queryByRole('region', { name: 'Результаты Secrets' })).toBeNull();
  await generate();
  await screen.findByText('Late-page hypothesis');
  const link = screen.getByRole('link', { name: 'Находка secret-0-1' });
  expect(
    document.getElementById(decodeURIComponent(link.getAttribute('href')!.slice(1)))?.textContent,
  ).toContain('secret-0-1');
  expect(requests.filter((request) => request.init?.method === 'POST')).toHaveLength(1);
  expect(requests.some((request) => request.path.includes('/results?limit=50&cursor=1'))).toBe(true);
  expect(screen.getByRole('heading', { name: 'Покрытие проверок' })).toBeTruthy();
});
it('a previous summary is recovered on a public-profile report page with autoSummary disabled, without a provider POST', async () => {
  transitionScanSession('alice', new QueryClient(), true);
  saveReportPreferences({ language: 'original', autoSummary: false });
  transitionScanSession(null, new QueryClient(), true);
  mockApi('completed', undefined, context, () => json(reply), PUBLIC_IMAGE_PROFILE);
  mount();
  await screen.findByText('Late-page hypothesis');
  expect(screen.getByText(/Сводка восстановлена из кэша процесса сервера/)).toBeTruthy();
  expect(requests.filter((r) => r.path.endsWith('/llm/summary') && r.init?.method === 'GET')).toHaveLength(1);
  expect(requests.some((r) => r.init?.method === 'POST')).toBe(false);
  expect(sessionStorage.getItem('report-automation-v1:attempts')).toBeNull();
});

it('owner report navigation reaches the existing chat independently of a failed summary, without provider calls', async () => {
  mockApi('completed', undefined, { invalid: true });
  const scannerFetch = globalThis.fetch;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (path: string, init?: RequestInit) => {
      if (path.endsWith('/llm/chat/context')) return json({ ...chatContext, ...tuple });
      if (path.endsWith('/llm/history')) return json({ ...chatHistory, ...tuple });
      if (path.endsWith('/llm/chat/usage'))
        return json({ ...tuple, available: false, admission: { status: 'unavailable' } });
      return scannerFetch(path, init);
    }),
  );
  mount();
  const entry = await screen.findByRole('link', { name: /Чат по отчёту/ });
  expect(entry.getAttribute('href')).toBe('#scan-report-chat');
  const target = document.getElementById('scan-report-chat');
  expect(target?.getAttribute('tabindex')).toBe('-1');
  expect(screen.getByRole('region', { name: 'Чат по отчёту' })).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Открыть чат' })).toBeNull();
  await screen.findByLabelText('Вопрос чату');
  await waitFor(() =>
    expect(screen.getByRole('status', { name: 'Состояние подключения чата' }).textContent).toContain(
      'История подключена',
    ),
  );
  expect(screen.getByRole('status', { name: 'Состояние подключения чата' }).textContent).toContain(
    'История подключена',
  );
  expect(requests.some((request) => request.init?.method === 'POST')).toBe(false);
  expect(screen.getByRole('heading', { name: 'Покрытие проверок' })).toBeTruthy();
});
it('queued ScanDetail has no context request or summary POST', async () => {
  mockApi('queued');
  mount();
  await screen.findByText(/ИИ-сводка доступна только/);
  expect(requests.some((request) => request.path.includes('/llm/'))).toBe(false);
  expect(screen.queryByRole('checkbox')).toBeNull();
  expect(screen.queryByRole('link', { name: /Чат по отчёту/ })).toBeNull();
});
it('malformed/offline summary context leaves original status, coverage and findings visible', async () => {
  mockApi('completed', undefined, { secret: 'PRIVATE_CANARY' });
  mount();
  await screen.findByText(/Не удалось безопасно получить сводку/);
  expect(await screen.findByText('ID: secret-0-0')).toBeTruthy();
  expect(screen.getByText('Полный итог Secrets: 2')).toBeTruthy();
  expect(screen.queryByText(/Прежние данные и cursors сброшены/)).toBeNull();
  expect(screen.getByRole('heading', { name: 'Покрытие проверок' })).toBeTruthy();
  expect(document.body.textContent).not.toContain('PRIVATE_CANARY');
  expect(requests.some((request) => request.init?.method === 'POST')).toBe(false);
});
it('actual route change aborts pending summary and requires a matching authorized report before another request', async () => {
  let resolve!: (value: Response) => void;
  mockApi(
    'completed',
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  mount();
  await generate();
  await waitFor(() => expect(requests.some((request) => request.init?.method === 'POST')).toBe(true));
  const signal = requests.find((request) => request.init?.method === 'POST')!.init!.signal!;
  fireEvent.click(screen.getByRole('link', { name: 'Другой скан' }));
  await screen.findByText(`ID / ${other}`);
  expect(signal.aborted).toBe(true);
  resolve(json(reply));
  await screen.findByText(/Условия передачи пока не подтверждены/);
  expect(screen.queryByText('Late-page hypothesis')).toBeNull();
  expect(screen.queryByRole('checkbox')).toBeNull();
});
