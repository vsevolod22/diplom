import '@testing-library/jest-dom/vitest';
import { webcrypto } from 'node:crypto';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { LiveScanSession } from '@/features/scans/LiveScanSession';
import { ScanDetailPage } from '@/pages/scans/ScanDetailPage';
import {
  readReportPreferences,
  REPORT_AUTOMATION_REVISION,
  saveReportPreferences,
} from '@/shared/api/preferences/reportPreferences';
import { transitionScanSession } from '@/shared/api/auth/scanSession';
import { PUBLIC_IMAGE_PROFILE } from '@/shared/api/scans/publicImageProfile';
import type { ScanStatus } from '@/shared/api/scans/scanTransport';
import { context, frameLines, history, json, ndjson, turnId, usage } from './llmChatFixtures';
import {
  policyModule,
  publicPolicy,
  publicDisclosure,
  publicMetadata,
  readinessWire,
} from './publicLlmFixtures';
import { checkedAt, v2Evidence } from './reportViewSynthetic';

const id = '00000000-0000-4000-8000-000000000038';
const other = '00000000-0000-4000-8000-000000000039';
const digest = `sha256:${'a'.repeat(64)}`;
const tuple = { scanId: id, digest, platform: 'linux/amd64' as const, reportVersion: 'b'.repeat(64) };
const findingId = `vuln-${'f'.repeat(64)}`;
const row = {
  findingId,
  cveId: 'CVE-2026-12345',
  ecosystem: 'deb',
  severity: 'HIGH',
  severitySources: ['nvd'],
  provenanceRef: `target-${'d'.repeat(64)}`,
  packageName: 'libssl3',
  installedVersion: '3.0.1-1',
  fixedVersion: '3.0.2-1',
};
const evidence = {
  ...v2Evidence(),
  os: { outcome: 'checked' },
  node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_UNKNOWN' },
};
const coverage = {
  ...evidence,
  check: 'vuln',
  coverage: 'image',
  outcome: 'checked',
  scannerVersion: '0.69.3',
  checkedAt,
  findingCount: 1,
};
const metadata = {
  ...publicMetadata,
  findingCount: 1,
  findingCounts: {
    byCheck: { secret: null, sbom: null, vuln: 1, config: null },
    bySeverity: { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0 },
  },
  identifierCounts: { cve: 1, debianTemp: 0 },
  coverage: { ...publicMetadata.coverage, vuln: { ...publicMetadata.coverage.vuln, findingCount: 1 } },
};
const paragraphs = [
  'Сначала проверьте обновление libssl3: сканер сообщил версию 3.0.1-1 и исправление в 3.0.2-1.',
  'Высокая серьёзность помогает выбрать приоритет проверки, но не доказывает возможность эксплуатации.',
  'После изменения зависимости пересоберите образ и повторите сканирование, проверив совместимость.',
  'Проверка состава пакетов языка не поддерживается; это не позволяет считать весь образ безопасным.',
];
const clients: QueryClient[] = [];
class Observer {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  vi.stubGlobal('IntersectionObserver', Observer);
  localStorage.clear();
  sessionStorage.clear();
  const client = new QueryClient();
  transitionScanSession('alice', client, true);
  saveReportPreferences({ language: 'original', autoSummary: true });
  transitionScanSession(null, client, true);
  client.clear();
});
afterEach(() => {
  cleanup();
  for (const client of clients.splice(0)) client.clear();
  transitionScanSession(null, new QueryClient(), true);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  localStorage.clear();
  sessionStorage.clear();
});

function summaryReply(current = tuple, fixedVersion: string | null = row.fixedVersion) {
  return {
    ...current,
    hypotheses: paragraphs.map((text, index) => ({
      kind: 'hypothesis',
      text:
        index === 0 && fixedVersion === null
          ? 'Сканер сообщил libssl3 версии 3.0.1-1; исправленная версия неизвестна. Проверьте сведения поставщика.'
          : current.scanId === other && index === 0
            ? 'Приоритет другого отчёта: проверьте исходную находку.'
            : text,
      citations: [findingId],
    })),
    ...metadata,
    contextSelection: {
      totalFindings: 1,
      selectedFindings: 1,
      omittedFindings: 0,
      strategy: 'all-critical-and-unknown-then-severity',
      selectedFindingIds: [findingId],
    },
    scannerFacts: [
      {
        ...row,
        check: 'vuln',
        identifierKind: 'cve',
        advisoryState: 'unknown',
        fixedVersion,
        fixedVersionReported: fixedVersion !== null,
      },
    ],
  };
}

function languageFailureReply() {
  return new Response(JSON.stringify({ errorCode: 'LLM_INVALID_RESPONSE' }), {
    status: 502,
    headers: { 'Content-Type': 'application/json', 'X-LLM-Failure-Phase': 'language', 'X-LLM-Failure-Reason': 'not_russian',
      'X-LLM-Language-Reason': 'residual_latin', 'X-LLM-Language-Index': '0', 'X-LLM-Language-Token-Class': 'unknown' },
  });
}
function mockApi() {
  const requests: Array<{ path: string; method: string; body: unknown }> = [];
  const summaries = new Map<string, unknown>();
  const heads = new Map<string, { revision: number; turns: unknown[] }>();
  const api = {
    state: 'completed' as ScanStatus['state'],
    failSummary: false,
    languageFailure: false,
    chatAvailable: true,
    fixedVersion: row.fixedVersion as string | null,
    transformSummary: (reply: ReturnType<typeof summaryReply>): unknown => reply,
    requests,
    summaryPosts: () => requests.filter((r) => r.path.endsWith('/llm/summary') && r.method === 'POST'),
    chatPosts: () => requests.filter((r) => r.path.endsWith('/llm/chat') && r.method === 'POST'),
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const method = init?.method ?? 'GET';
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      requests.push({ path, method, body });
      if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      const current = path.includes(other) ? { ...tuple, scanId: other } : tuple;
      const head = heads.get(current.scanId) ?? { revision: 0, turns: [] };
      if (path.endsWith('/llm/context')) {
        // Use the actual public disclosure, without chat-only additions.
        return json({
          ...current,
          enabled: true,
          policyVersion: context.policyVersion,
          disclosure: policyModule.disclosure(publicPolicy),
          ...metadata,
        });
      }
      if (path.endsWith('/llm/summary')) {
        if (method === 'GET')
          return summaries.has(current.scanId)
            ? json(summaries.get(current.scanId))
            : json({ errorCode: 'LLM_SUMMARY_MISSING' }, 404);
        if (api.languageFailure) return languageFailureReply();
                if (api.failSummary)
          return json({ errorCode: 'LLM_PROVIDER_UNAVAILABLE', diagnostic: 'PRIVATE_CANARY' }, 503);
        const reply = api.transformSummary(summaryReply(current, api.fixedVersion));
        summaries.set(current.scanId, reply);
        return json(reply);
      }
      if (path.endsWith('/llm/chat/context'))
        return api.chatAvailable
          ? json({
              ...context,
              ...current,
              revision: head.revision,
              disclosure: publicDisclosure,
              ...metadata,
            })
          : json({ errorCode: 'LLM_UNAVAILABLE' }, 503);
      if (path.endsWith('/llm/history'))
        return json({ ...history, ...current, revision: head.revision, turns: head.turns });
      if (path.endsWith('/llm/readiness')) return json({ ...readinessWire(), ...current });
      if (path.endsWith('/llm/usage') || path.endsWith('/llm/chat/usage'))
        return json({ ...usage, ...current, integrationEnabled: true, quotaEnabled: true });
      if (path.endsWith('/llm/chat') && method === 'POST') {
        if (api.languageFailure) return languageFailureReply();
        const reply = {
          ...current,
          kind: 'hypothesis',
          text: 'Проверьте обновление пакета, затем пересоберите образ.',
          sources: [{ ...current, finding: summaryReply(current, api.fixedVersion).scannerFacts[0] }],
        };
        const revision = head.revision + 2;
        heads.set(current.scanId, {
          revision,
          turns: [
            {
              id: turnId,
              mutationId: body.mutationId,
              state: 'completed',
              question: body.question,
              report: current,
              createdAt: 0,
              reply,
            },
          ],
        });
        return ndjson(
          frameLines(body.mutationId, reply.text, revision).map((frame) => ({
            ...frame,
            ...current,
            ...(frame.type === 'citation' ? { source: reply.sources[0] } : {}),
          })),
        );
      }
      const url = new URL(path, window.location.origin);
      if (url.pathname.endsWith('/vuln')) {
        const limit = Number(url.searchParams.get('limit'));
        return json({
          ...evidence,
          profile: PUBLIC_IMAGE_PROFILE,
          identifierCounts: metadata.identifierCounts,
          outcome: 'checked',
          coverage: 'image',
          image: `registry-1.docker.io/library/debian@${digest}`,
          platform: tuple.platform,
          findingCount: 1,
          scannerVersion: '0.69.3',
          checkedAt,
          findings: [{ ...row, fixedVersion: api.fixedVersion }],
          nextCursor: null,
          ...(url.searchParams.get('view') === 'report-v1'
            ? {
                page: {
                  version: 1,
                  limit,
                  offset: 0,
                  returnedCount: 1,
                  totalCount: 1,
                  matchedCount: 1,
                  sort: 'severity:desc',
                  filters: { severity: null },
                },
              }
            : {}),
        });
      }
      if (url.pathname === `/api/v1/browser/scans/${current.scanId}`)
        return json({
          ...current,
          profile: PUBLIC_IMAGE_PROFILE,
          ...(api.state === 'queued' ? {} : { identifierCounts: metadata.identifierCounts }),
          imageReference: `registry-1.docker.io/library/debian@${digest}`,
          state: api.state,
          checks: ['vuln'],
          perCheck: { vuln: api.state === 'queued' ? null : coverage },
          result: api.state === 'queued' ? null : coverage,
        });
      throw new Error(`Unexpected page-test request: ${method} ${path}`);
    }),
  );
  return api;
}

function mount(demo = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  clients.push(client);
  const view = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[demo ? '/demo/scans/empty-demo' : `/scans/${id}`]}>
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
          <Route path="/demo/scans/:scanId" element={<ScanDetailPage demo />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...view, client };
}
const summary = () => screen.getByRole('region', { name: 'ИИ-отчёт' });
async function loaded() {
  await within(await screen.findByRole('region', { name: 'ИИ-отчёт' })).findByText(paragraphs[0]);
  await screen.findByText('Задайте вопрос по отчёту.');
}

it.each([
  { language: 'original', failure: false }, { language: 'ru', failure: false },
  { language: 'original', failure: true }, { language: 'ru', failure: true },
] as const)('summary/chat under $language with language failure=$failure never request advisory translation', async ({ language, failure }) => {
  const preferencesClient = new QueryClient();
  transitionScanSession('alice', preferencesClient, true);
  saveReportPreferences({ language, autoSummary: true });
  transitionScanSession(null, preferencesClient, true);
  preferencesClient.clear();
  const api = mockApi(); api.languageFailure = failure;
  const view = mount();
  if (failure) await within(await screen.findByRole('region', { name: 'ИИ-отчёт' })).findByRole('alert');
  else await within(await screen.findByRole('region', { name: 'ИИ-отчёт' })).findByText(paragraphs[0]);
  await screen.findByText('Задайте вопрос по отчёту.');
  const chat = within(screen.getByRole('region', { name: 'Чат по отчёту' }));
  fireEvent.change(chat.getByRole('textbox', { name: 'Вопрос чату' }), { target: { value: 'Что проверить?' } });
  fireEvent.click(chat.getByRole('button', { name: 'Отправить вопрос' }));
  if (failure) await chat.findByRole('alert');
  else await chat.findByText('Проверьте обновление пакета, затем пересоберите образ.');
  fireEvent.focus(window); fireEvent(window, new Event('online'));
  await act(async () => { await view.client.invalidateQueries({ queryKey: ['live-scans'] }); });
  expect(api.summaryPosts()).toHaveLength(1); expect(api.chatPosts()).toHaveLength(1);
  expect(api.requests.filter(request => request.path.includes('/llm/translation'))).toEqual([]);
  expect(screen.queryByRole('region', { name: /^Перевод / })).not.toBeInTheDocument();
});

it('autoloads exactly once only after queued becomes completed, before coverage/findings, with independent chat', async () => {
  const api = mockApi();
  api.state = 'queued';
  const view = mount();
  await screen.findByRole('heading', { name: 'Отчёт сканирования' });
  await screen.findByRole('navigation', { name: 'Разделы отчёта' });
  expect(screen.queryByRole('region', { name: 'ИИ-отчёт' })).toBeNull();
  expect(screen.queryByRole('region', { name: 'Чат по отчёту' })).toBeNull();
  expect(api.requests.some((r) => r.path.includes('/llm/'))).toBe(false);
  api.state = 'completed';
  await act(async () => {
    await view.client.invalidateQueries({ queryKey: ['live-scans'] });
  });
  await loaded();
  const coveragePanel = screen.getByRole('region', { name: 'Проверки' });
  const findings = screen.getByRole('region', { name: 'Отчёт' });
  expect(summary().compareDocumentPosition(coveragePanel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(summary().compareDocumentPosition(findings) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(api.summaryPosts()).toHaveLength(1);
  expect(api.summaryPosts()[0].body).toEqual({
    reportVersion: tuple.reportVersion,
    consent: { accepted: true, policyVersion: context.policyVersion },
  });
  expect(screen.getAllByRole('region', { name: 'Чат по отчёту' })).toHaveLength(1);
  expect(summary().contains(screen.getByRole('region', { name: 'Чат по отчёту' }))).toBe(false);
  fireEvent.focus(window);
  fireEvent(window, new Event('online'));
  await act(async () => {
    await view.client.invalidateQueries({ queryKey: ['live-scans'] });
  });
  expect(api.summaryPosts()).toHaveLength(1);
  expect(api.chatPosts()).toHaveLength(0);
});

it('has three live navigation links, actual paragraphs and closed sources, without a technical AI wall', async () => {
  mockApi();
  mount();
  await loaded();
  const nav = screen.getByRole('navigation', { name: 'Разделы отчёта' });
  expect([...nav.querySelectorAll('a')].map((a) => [a.textContent, a.getAttribute('href')])).toEqual([
    ['ИИ-отчёт', '#scan-a1-ai'],
    ['Находки', '#scan-a1-findings'],
    ['Чат по отчёту', '#scan-report-chat'],
  ]);
  expect(
    [...summary().querySelectorAll('[aria-label="ИИ-разбор отчёта"] > p')].map((p) => p.textContent),
  ).toEqual(paragraphs);
  expect(summary().querySelector('details')?.open).toBe(false);
  expect(summary().textContent).not.toMatch(
    /OpenRouter|dots-studio|atlas-cloud|no-training|ZDR|бюджет|квот|маршрутизац|гипотез|Пункт 1/i,
  );
  expect(summary().textContent).not.toContain(tuple.reportVersion);
  expect(summary().textContent).not.toContain(context.policyVersion);
  expect(within(summary()).queryByRole('button', { name: /Получить|Обновить условия/ })).toBeNull();
  const details = screen.getByText('Данные сканирования').closest('details');
  expect(details?.open).toBe(false);
  expect(details?.textContent).toContain(id);
  expect(details?.textContent).toContain(digest);
});

it('recovers the current report after a fresh owner session without another generation POST', async () => {
  const api = mockApi();
  const view = mount();
  await loaded();
  view.unmount();
  view.client.clear();
  transitionScanSession(null, view.client, true);
  mount();
  await loaded();
  expect(api.summaryPosts()).toHaveLength(1);
  expect(api.requests.filter((r) => r.path.endsWith('/llm/summary') && r.method === 'GET')).toHaveLength(2);
});

it('keeps findings and an operational separate chat when AI summary fails; only a manual retry generates again', async () => {
  const api = mockApi();
  api.failSummary = true;
  mount();
  expect(
    await within(await screen.findByRole('region', { name: 'ИИ-отчёт' })).findByRole('alert'),
  ).toHaveTextContent('Не удалось получить разбор ИИ');
  await screen.findByText(row.cveId, { selector: '.scan-vuln-row__id' });
  expect(screen.getByRole('region', { name: 'Проверки' })).toBeVisible();
  await screen.findByText('Задайте вопрос по отчёту.');
  const chat = within(screen.getByRole('region', { name: 'Чат по отчёту' }));
  fireEvent.change(chat.getByRole('textbox', { name: 'Вопрос чату' }), {
    target: { value: 'Что исправить первым?' },
  });
  fireEvent.click(chat.getByRole('button', { name: 'Отправить вопрос' }));
  await chat.findByText('Проверьте обновление пакета, затем пересоберите образ.');
  expect(api.chatPosts()).toHaveLength(1);
  expect(api.summaryPosts()).toHaveLength(1);
  expect(within(summary()).queryByText(paragraphs[0])).toBeNull();
  expect(document.body.textContent).not.toContain('PRIVATE_CANARY');
  api.failSummary = false;
  fireEvent.click(within(summary()).getByRole('button', { name: 'Повторить разбор' }));
  await within(summary()).findByText(paragraphs[0]);
  expect(api.summaryPosts()).toHaveLength(2);
  expect(api.chatPosts()).toHaveLength(1);
});

it('keeps a successful summary and findings visible if the independent chat cannot connect', async () => {
  const api = mockApi();
  api.chatAvailable = false;
  mount();
  await within(await screen.findByRole('region', { name: 'ИИ-отчёт' })).findByText(paragraphs[0]);
  await screen.findByText(row.cveId, { selector: '.scan-vuln-row__id' });
  expect(screen.getByRole('textbox', { name: 'Вопрос чату' })).toBeVisible();
  await waitFor(() =>
    expect(screen.getByRole('status', { name: 'Состояние подключения чата' })).not.toHaveTextContent(
      'Подключаем',
    ),
  );
  expect(api.summaryPosts()).toHaveLength(1);
  expect(api.chatPosts()).toHaveLength(0);
});

it.each([row.fixedVersion, null])(
  'accepts the atomic scanner package/version trio with reported fix %s and verifies its source',
  async (fixedVersion) => {
    const api = mockApi();
    api.fixedVersion = fixedVersion;
    mount();
    const text = summaryReply(tuple, fixedVersion).hypotheses[0].text;
    await within(await screen.findByRole('region', { name: 'ИИ-отчёт' })).findByText(text);
    fireEvent.click(within(summary()).getByText(/Находки — источники разбора/));
    const link = within(summary()).getByRole('link', { name: `Находка ${findingId}` });
    expect(
      document.getElementById(decodeURIComponent(link.getAttribute('href')!.slice(1))),
    ).toHaveTextContent(row.cveId);
    expect(api.requests.some((r) => r.path.endsWith('/vuln?limit=50'))).toBe(true);
    expect(api.summaryPosts()).toHaveLength(1);
  },
);

it.each(['partial-trio', 'credential-name', 'invalid-version', 'foreign-source', 'foreign-report'] as const)(
  'withholds model output for %s without hiding scanner findings or chat',
  async (invalid) => {
    const api = mockApi();
    api.transformSummary = (reply) => ({
      ...reply,
      ...(invalid === 'foreign-report' ? { reportVersion: 'e'.repeat(64) } : {}),
      scannerFacts: [
        {
          ...reply.scannerFacts[0],
          ...{
            'partial-trio': { fixedVersion: undefined },
            'credential-name': { packageName: 'api-key=PRIVATE_CANARY' },
            'invalid-version': { installedVersion: 'https://PRIVATE_CANARY.invalid' },
            'foreign-source': { findingId: `vuln-${'e'.repeat(64)}` },
            'foreign-report': {},
          }[invalid],
        },
      ],
    });
    mount();
    await within(await screen.findByRole('region', { name: 'ИИ-отчёт' })).findByRole('alert');
    await screen.findByText(row.cveId, { selector: '.scan-vuln-row__id' });
    await screen.findByText('Задайте вопрос по отчёту.');
    expect(within(summary()).queryByText(paragraphs[0])).toBeNull();
    expect(document.body.textContent).not.toContain('PRIVATE_CANARY');
    expect(api.summaryPosts()).toHaveLength(1);
    expect(api.chatPosts()).toHaveLength(0);
  },
);

it('does not migrate old consent or generate until one explicit enable click saves v4', async () => {
  const raw = JSON.stringify({
    version: 1,
    automationRevision: 'report-automation-v3-dots-no-training',
    language: 'original',
    autoSummary: true,
  });
  localStorage.setItem('report-preferences:v1:alice', raw);
  const api = mockApi();
  mount();
  const enable = await screen.findByRole('button', { name: 'Включить авторазбор' });
  await waitFor(() => expect(enable).toBeEnabled());
  await screen.findByText('Задайте вопрос по отчёту.');
  expect(within(summary()).getAllByRole('button')).toHaveLength(1);
  expect(within(summary()).getByText(/Находки отчёта, имена пакетов и версии/)).toBeVisible();
  expect(localStorage.getItem('report-preferences:v1:alice')).toBe(raw);
  expect(readReportPreferences().authorized).toBe(false);
  expect(api.summaryPosts()).toHaveLength(0);
  expect(api.requests.some((r) => r.path.endsWith('/llm/usage'))).toBe(false);
  fireEvent.click(enable);
  await loaded();
  expect(readReportPreferences()).toMatchObject({
    language: 'original',
    autoSummary: true,
    revision: REPORT_AUTOMATION_REVISION,
  });
  expect(JSON.parse(localStorage.getItem('report-preferences:v1:alice')!)).toEqual({
    version: 1,
    automationRevision: 'report-automation-v4-remediation',
    language: 'original',
    autoSummary: true,
  });
  expect(api.summaryPosts()).toHaveLength(1);
  expect(api.chatPosts()).toHaveLength(0);
});

it('generates once for each new report scope, without sending a chat question automatically', async () => {
  const api = mockApi();
  mount();
  await loaded();
  fireEvent.click(screen.getByRole('link', { name: 'Другой скан' }));
  await within(await screen.findByRole('region', { name: 'ИИ-отчёт' })).findByText(
    'Приоритет другого отчёта: проверьте исходную находку.',
  );
  await screen.findByText('Задайте вопрос по отчёту.');
  expect(api.summaryPosts().map((r) => r.path)).toEqual([
    `/api/v1/browser/scans/${id}/llm/summary`,
    `/api/v1/browser/scans/${other}/llm/summary`,
  ]);
  expect(within(summary()).queryByText(paragraphs[0])).toBeNull();
  expect(api.chatPosts()).toHaveLength(0);
});

it('demo navigation contains only findings and makes no LLM requests even with saved opt-in', async () => {
  const api = mockApi();
  mount(true);
  const nav = await screen.findByRole('navigation', { name: 'Разделы отчёта' });
  expect([...nav.querySelectorAll('a')].map((a) => a.textContent)).toEqual(['Находки']);
  expect(screen.queryByRole('region', { name: 'ИИ-отчёт' })).toBeNull();
  expect(screen.queryByRole('region', { name: 'Чат по отчёту' })).toBeNull();
  expect(api.requests).toHaveLength(0);
});
