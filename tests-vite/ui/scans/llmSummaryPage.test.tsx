import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { LiveScanSession } from '@/features/scans/LiveScanSession';
import { ScanDetailPage } from '@/pages/scans/ScanDetailPage';
import { transitionScanSession } from '@/shared/api/auth/scanSession';

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
    model: 'vendor/model',
    providers: ['vendor'],
    region: 'global',
    retention: 'no-training',
    operatorApprovedRouting: true,
    providerComplianceNotProvenByDeclaration: true,
    requestBudgetUsd: 0.1,
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
  vi.stubGlobal('IntersectionObserver', Observer);
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
) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (path: string, init?: RequestInit) => {
      requests.push({ path, init });
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      if (path.endsWith('/llm/context')) return json(policy);
      if (path.endsWith('/llm/summary')) return summary();
      if (path.includes('/results')) {
        const url = new URL(path, window.location.origin);
        if (url.searchParams.get('view') === 'report-v1') return json({
          findings: [0, 1].map(index => ({ findingId: `secret-0-${index}`, ruleId: 'rule-0000000000000000', line: 1, evidenceRef: `result-0-secret-${index}` })),
          nextCursor: null,
          coverage,
          page: { version: 1, limit: 25, offset: 0, returnedCount: 2, totalCount: 2, matchedCount: 2, sort: 'ruleId:asc', filters: { ruleId: null, linePresence: null } },
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
  await screen.findByText(/Бесплатный режим не подтверждён/);
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'Получить сводку' }));
}
it('terminal ScanDetail replaces placeholder; hidden current category and late-page source remain reachable', async () => {
  mockApi();
  mount();
  await screen.findByText(/Бесплатный режим не подтверждён/);
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
it('queued ScanDetail has no context request or summary POST', async () => {
  mockApi('queued');
  mount();
  await screen.findByText(/ИИ-сводка доступна только/);
  expect(requests.some((request) => request.path.includes('/llm/'))).toBe(false);
  expect(screen.queryByRole('checkbox')).toBeNull();
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
it('actual route change aborts pending summary and resets consent before another report', async () => {
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
  expect((screen.getByRole('checkbox') as HTMLInputElement).checked).toBe(false);
});
