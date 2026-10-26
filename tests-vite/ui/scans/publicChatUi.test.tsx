import '@testing-library/jest-dom/vitest';
import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanChatPanel } from '@/features/scans/ScanChatPanel';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { createAuthorizedScanTransport } from '@/shared/api/scans/httpScanTransport';
import { ChatError, createChatClient } from '@/shared/api/scans/llmChatClient';
import { chatSourceSchema } from '@/shared/api/scans/llmChatContract';
import { publicChatApi, readinessWire, unknownPublicMetadata } from './publicLlmFixtures';
import { collectSummarySources } from '@/shared/api/scans/llmSummaryClient';
import { PUBLIC_IMAGE_PROFILE } from '@/shared/api/scans/publicImageProfile';
import type { ScanStatus } from '@/shared/api/scans/scanTransport';
import {
  binding,
  chatApi,
  context,
  history,
  json,
  sourceTransport,
  status,
  turnId,
  frameLines,
  ndjson,
} from './llmChatFixtures';

beforeEach(() => transitionScanSession('alice', new QueryClient(), true));
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function mount(api = chatApi(), fetcher: typeof fetch = api.fetcher) {
  const client = createChatClient(scanSession(), fetcher);
  return render(<ScanChatPanel status={status} transport={sourceTransport()} client={client} />);
}
async function open() {
  fireEvent.click(screen.getByRole('button', { name: 'Открыть чат' }));
  await screen.findByLabelText('Вопрос чату');
}
function prepare(question = 'Что проверить дальше?') {
  fireEvent.change(screen.getByLabelText('Вопрос чату'), { target: { value: question } });
}
const connection = () => screen.getByRole('status', { name: 'Состояние подключения чата' });

it('announces manual connection, request wait and continuation; submitting twice dispatches once and requires a fresh send for the next turn', async () => {
  const api = chatApi();
  let finish!: () => void;
  const gate = new Promise<void>((resolve) => {
    finish = resolve;
  });
  const fetcher: typeof fetch = vi.fn(async (path, init) => {
    if (init?.method === 'POST') await gate;
    const response = await api.fetcher(path, init);
    if (init?.method === 'POST' && api.head.turns.length === 2) {
      const nextId = '00000000-0000-4000-8000-000000000003';
      api.head = {
        ...api.head,
        turns: api.head.turns.map((turn, index) => (index === 1 ? { ...turn, id: nextId } : turn)),
      };
      const frames = (await response.text())
        .trim()
        .split('\n')
        .map((line) => ({ ...JSON.parse(line), turnId: nextId }));
      return new Response(frames.map((frame) => JSON.stringify(frame) + '\n').join(''), {
        headers: { 'Content-Type': 'application/x-ndjson' },
      });
    }
    return response;
  });
  mount(api, fetcher);
  expect(connection()).toHaveTextContent('Чат не подключён');
  expect(api.requests).toHaveLength(0);
  await open();
  expect(connection()).toHaveTextContent('доступность провайдера проверяется только при отправке');
  prepare();
  fireEvent.submit(screen.getByRole('form', { name: 'Отправка вопроса по отчёту' }));
  fireEvent.submit(screen.getByRole('form', { name: 'Отправка вопроса по отчёту' }));
  expect(connection()).toHaveTextContent('Ожидаем проверенный полный ответ');
  expect(screen.queryByText('Ответ ИИ · требует проверки')).toBeNull();
  await act(async () => finish());
  await screen.findByText(/Последний ответ/);
  expect(api.requests.filter((r) => r.init.method === 'POST')).toHaveLength(1);
  expect(screen.getByText(/Продолжите чат новым вопросом/)).toBeVisible();
  expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
  prepare('Как проверить исправление?');
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
  await waitFor(() => expect(api.requests.filter((r) => r.init.method === 'POST')).toHaveLength(2));
  const posts = api.requests.filter((r) => r.init.method === 'POST');
  expect(JSON.parse(String(posts[1].init.body))).toMatchObject({
    revision: 2,
    question: 'Как проверить исправление?',
    consent: { accepted: true, policyVersion: context.policyVersion },
  });
  await screen.findByText('Как проверить исправление?');
  expect(screen.getAllByText('Ответ ИИ · требует проверки')).toHaveLength(2);
  expect(screen.queryByRole('checkbox', { name: /Разрешаю один запрос/ })).toBeNull();
});

it('prepares a failed question without POST, focuses the composer and requires an explicit send', async () => {
  const api = chatApi();
  api.head = {
    ...history,
    revision: 2,
    turns: [
      {
        id: turnId,
        mutationId: crypto.randomUUID(),
        question: 'Как проверить находку?',
        state: 'failed',
        report: binding,
        createdAt: 0,
      },
    ],
  };
  mount(api);
  await open();
  fireEvent.click(screen.getByRole('button', { name: 'Подготовить повтор вопроса' }));
  expect(screen.getByLabelText('Вопрос чату')).toHaveValue('Как проверить находку?');
  expect(screen.getByLabelText('Вопрос чату')).toHaveFocus();
  expect(screen.queryByRole('checkbox', { name: /Разрешаю один запрос/ })).toBeNull();
  expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeEnabled();
  expect(api.requests.every((r) => r.init.method === 'GET')).toBe(true);
});

it.each([
  ['LLM_CONFIGURATION_UNAVAILABLE', /Серверный ключ или политика/],
  ['LLM_PROVIDER_UNAVAILABLE', /Провайдер недоступен/],
  ['LLM_UNAVAILABLE', /Провайдер недоступен/],
  ['LLM_QUOTA_EXCEEDED', /лимит запросов или квоты/],
  ['LLM_NO_EVIDENCE', /Нет подтверждённых источников/],
] as const)(
  'recovers %s only through a manual history GET; never auto-resends or exposes backend diagnostics',
  async (code, message) => {
    const api = chatApi();
    const fetcher: typeof fetch = vi.fn(async (path, init) =>
      init?.method === 'POST'
        ? json({ errorCode: code, message: 'PRIVATE_CANARY' }, 503)
        : api.fetcher(path, init),
    );
    mount(api, fetcher);
    await open();
    prepare();
    fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(message);
    expect(document.body.textContent).not.toContain('PRIVATE_CANARY');
    expect(connection()).toHaveTextContent('Подключение не подтверждено');
    fireEvent.click(screen.getByRole('button', { name: 'Обновить историю и условия чата' }));
    await screen.findByLabelText('Вопрос чату');
    expect(screen.queryByRole('checkbox', { name: /Разрешаю один запрос/ })).toBeNull();
    expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeEnabled();
    expect(vi.mocked(fetcher).mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  },
);

it.each([401, 403])(
  'a %i usage denial fails closed instead of publishing history with unknown quota',
  async (code) => {
    const api = chatApi();
    const fetcher: typeof fetch = vi.fn(async (path, init) =>
      String(path).endsWith('/chat/usage')
        ? new Response('PRIVATE_CANARY', { status: code })
        : api.fetcher(path, init),
    );
    mount(api, fetcher);
    fireEvent.click(screen.getByRole('button', { name: 'Открыть чат' }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(
      code === 401 ? 'Сессия изменилась или истекла' : 'Доступ к чату этого отчёта не подтверждён',
    );
    expect(document.body.textContent).not.toContain('PRIVATE_CANARY');
    expect(screen.queryByLabelText('Вопрос чату')).toBeNull();
    expect(api.requests.every((r) => r.init.method === 'GET')).toBe(true);
  },
);

it('an unknown usage failure remains unknown, not zero or guaranteed provider admission', async () => {
  const api = chatApi();
  const fetcher: typeof fetch = vi.fn(async (path, init) =>
    String(path).endsWith('/chat/usage')
      ? json({ errorCode: 'LLM_QUOTA_UNAVAILABLE' }, 503)
      : api.fetcher(path, init),
  );
  mount(api, fetcher);
  await open();
  expect(screen.getByText(/Учёт недоступен, не ноль/)).toBeVisible();
});

it('shows duplicate-only delivery as recovery, not an answer; rereads history only on explicit refresh', async () => {
  const api = chatApi();
  const client = createChatClient(scanSession(), api.fetcher);
  client.chat = vi.fn(async () => {
    throw new ChatError('DUPLICATE');
  });
  render(<ScanChatPanel status={status} transport={sourceTransport()} client={client} />);
  await open();
  prepare();
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Запрос уже зарегистрирован');
  expect(client.chat).toHaveBeenCalledTimes(1);
  expect(screen.queryByText('Ответ ИИ · требует проверки')).toBeNull();
  const reads = api.requests.length;
  fireEvent.focus(window);
  expect(api.requests).toHaveLength(reads);
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю и условия чата' }));
  await screen.findByLabelText('Вопрос чату');
  expect(api.requests.length).toBeGreaterThan(reads);
  expect(client.chat).toHaveBeenCalledTimes(1);
});

// Public browser wire, not a provider/live-8081 observation. No backend fixture imports.
const counts = { cve: 51, debianTemp: 1 };
const publicStatus: ScanStatus = {
  ...status,
  profile: PUBLIC_IMAGE_PROFILE,
  checks: ['vuln'],
  identifierCounts: counts,
  perCheck: {
    vuln: {
      check: 'vuln',
      coverage: 'image',
      outcome: 'checked',
      findingCount: 52,
      os: { outcome: 'checked' },
      node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_UNKNOWN' },
    },
  },
};
const rows = Array.from({ length: 52 }, (_, index) => ({
  findingId: `vuln-${String(index).padStart(64, '0')}`,
  cveId: index === 51 ? 'TEMP-1234567-ABCDEF' : `CVE-2026-${1000 + index}`,
  ecosystem: 'deb',
  packageName: 'package',
  installedVersion: '1',
  fixedVersion: null,
  severity: 'UNKNOWN',
  severitySources: ['debian'],
  provenanceRef: `target-${'d'.repeat(64)}`,
}));
function publicTransport(partitionMismatch = false) {
  const pages: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (path: string) => {
      pages.push(path);
      const url = new URL(path, 'https://public-wire.invalid');
      if (url.pathname !== `/api/v1/browser/scans/${binding.scanId}/vuln`)
        throw new Error('Unexpected source request');
      const offset = Number(url.searchParams.get('cursor') ?? 0);
      return json({
        profile: PUBLIC_IMAGE_PROFILE,
        identifierCounts: partitionMismatch ? { cve: 50, debianTemp: 2 } : counts,
        outcome: 'checked',
        coverage: 'image',
        image: `registry-1.docker.io/library/debian@${binding.digest}`,
        platform: binding.platform,
        findingCount: 52,
        scannerVersion: '0.69.3',
        checkedAt: '2026-10-20T00:00:00.000Z',
        findings: rows.slice(offset, offset + 50),
        nextCursor: offset === 0 ? 50 : null,
      });
    }),
  );
  return {
    transport: createAuthorizedScanTransport({
      subject: 'alice',
      currentSubject: () => scanSession().subject,
    }),
    pages,
  };
}

it('reads every public page through the existing cookie transport, preserving CVE/TEMP labels and honest Node unknown coverage', async () => {
  const api = publicChatApi();
  const { transport, pages } = publicTransport();
  const client = createChatClient(scanSession(), api.fetcher);
  render(<ScanChatPanel status={publicStatus} transport={transport} client={client} />);
  await open();
  const scope = within(screen.getByLabelText('Границы отчёта публичного образа в чате'));
  expect(scope.getByText(/CVE: 51; уведомления Debian: 1/)).toBeVisible();
  expect(scope.getByText(/Node.js: не поддерживается · состав пакетов Node.js не установлен/)).toBeVisible();
  expect(
    screen.getByRole('checkbox', { name: /TEMP-1234567-ABCDEF · Уведомление Debian \(не CVE\)/ }),
  ).toBeInTheDocument();
  expect(pages).toEqual([
    `/api/v1/browser/scans/${binding.scanId}/vuln?limit=50`,
    `/api/v1/browser/scans/${binding.scanId}/vuln?limit=50&cursor=50`,
  ]);
  expect(api.requests.every((r) => r.init.method === 'GET')).toBe(true);
  expect(document.body.textContent).not.toContain('52 CVE');
});

it('publishes a public TEMP citation only after framed completion and matching history, then reloads it without a provider call', async () => {
  const api = publicChatApi();
  const { transport } = publicTransport();
  const temp = chatSourceSchema.parse({
    ...binding,
    finding: {
      check: 'vuln',
      findingId: rows[51].findingId,
      cveId: rows[51].cveId,
      identifierKind: 'debian-temp',
      ecosystem: 'deb',
      severity: 'UNKNOWN',
      severitySources: ['debian'],
      provenanceRef: rows[51].provenanceRef,
      fixedVersionReported: false,
      advisoryState: 'unknown',
    },
  });
  const fetcher: typeof fetch = vi.fn(async (path, init) => {
    const response = await api.fetcher(path, init);
    if (init?.method !== 'POST') return response;
    api.head = {
      ...api.head,
      turns: api.head.turns.map((turn) =>
        turn.state === 'completed' ? { ...turn, reply: { ...turn.reply, sources: [temp] } } : turn,
      ),
    };
    const body = JSON.parse(String(init.body));
    return ndjson(
      frameLines(body.mutationId).map((frame) =>
        frame.type === 'citation' ? { ...frame, source: temp } : frame,
      ),
    );
  });
  const first = render(
    <ScanChatPanel
      status={publicStatus}
      transport={transport}
      client={createChatClient(scanSession(), fetcher)}
    />,
  );
  await open();
  prepare();
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
  await screen.findByText(/Последний ответ/);
  expect(screen.getByText('TEMP-1234567-ABCDEF · Уведомление Debian (не CVE)')).toBeVisible();
  const link = screen.getByRole('link', { name: `Находка ${rows[51].findingId}` });
  expect(document.getElementById(link.getAttribute('href')!.slice(1))).toHaveTextContent(
    'Источник текущего отчёта',
  );
  expect(screen.queryByRole('link', { name: /CVERecord|NVD/ })).toBeNull();
  first.unmount();
  render(
    <ScanChatPanel
      status={publicStatus}
      transport={transport}
      client={createChatClient(scanSession(), fetcher)}
    />,
  );
  await open();
  expect(screen.getByText('TEMP-1234567-ABCDEF · Уведомление Debian (не CVE)')).toBeVisible();
  expect(screen.queryByRole('checkbox', { name: /Разрешаю один запрос/ })).toBeNull();
  expect(api.requests.filter((r) => r.init.method === 'POST')).toHaveLength(1);
});

it('requires the explicit public identifier kind and Debian ecosystem for TEMP; refuses mismatched kinds and extra free text', () => {
  const base = {
    ...binding,
    finding: {
      check: 'vuln',
      findingId: rows[51].findingId,
      cveId: rows[51].cveId,
      identifierKind: 'debian-temp',
      ecosystem: 'deb',
      severity: 'UNKNOWN',
      severitySources: ['debian'],
      provenanceRef: rows[51].provenanceRef,
      fixedVersionReported: false,
      advisoryState: 'unknown',
    },
  };
  expect(chatSourceSchema.safeParse(base).success).toBe(true);
  for (const patch of [
    { identifierKind: undefined },
    { identifierKind: 'cve' },
    { ecosystem: 'npm' },
    { cveId: 'CVE-2026-1234' },
    { cveId: 'TEMP-1234567-abcdef' },
    { rawEvidence: 'PRIVATE_CANARY' },
  ]) {
    expect(chatSourceSchema.safeParse({ ...base, finding: { ...base.finding, ...patch } }).success).toBe(
      false,
    );
  }
  expect(
    chatSourceSchema.safeParse({
      ...base,
      finding: { ...base.finding, cveId: 'CVE-2026-1234', identifierKind: 'cve' },
    }).success,
  ).toBe(true);
});

it('rejects public source pages with a different whole-report partition before enabling consent', async () => {
  const { transport } = publicTransport(true);
  await expect(
    collectSummarySources(transport, publicStatus, new AbortController().signal),
  ).rejects.toMatchObject({ code: 'STALE' });
});

it.each([
  ['missing', true, /Серверный ключ не настроен или отсутствует/],
  ['unsafe', true, /не прошли проверку безопасности/],
  ['metadata-valid', false, /Хранилище квоты недоступно/],
] as const)(
  'public readiness %s / quota %s blocks generation but preserves owner history and manual decisions',
  async (credential, quota, reason) => {
    const api = publicChatApi();
    const { transport } = publicTransport();
    const fetcher: typeof fetch = vi.fn(async (path, init) =>
      String(path).endsWith('/readiness') ? json(readinessWire(credential, quota)) : api.fetcher(path, init),
    );
    render(
      <ScanChatPanel
        status={publicStatus}
        transport={transport}
        client={createChatClient(scanSession(), fetcher)}
      />,
    );
    await open();
    expect(screen.getByRole('region', { name: 'Готовность генерации' })).toHaveTextContent(reason);
    expect(connection()).toHaveTextContent('Готовность генерации не подтверждена');
    expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
    fireEvent.submit(screen.getByRole('form', { name: 'Отправка вопроса по отчёту' }));
    expect(api.requests.filter((r) => r.init.method === 'POST')).toHaveLength(0);
    fireEvent.change(screen.getByLabelText('Текст решения'), {
      target: { value: 'Проверить найденные advisories' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить решение' }));
    await screen.findByText('Решение пользователя · не вывод сканера');
    expect(api.requests.filter((r) => r.init.method === 'POST').map((r) => r.path)).toEqual([
      `/api/v1/browser/scans/${binding.scanId}/llm/history/decision`,
    ]);
  },
);

it('keeps public readiness blockers visible even when the history store prevents reading chat context', async () => {
  const api = publicChatApi();
  const { transport } = publicTransport();
  const fetcher: typeof fetch = vi.fn(async (path, init) =>
    String(path).endsWith('/readiness')
      ? json(readinessWire('missing', false, false))
      : String(path).endsWith('/chat/context')
        ? json({ errorCode: 'LLM_HISTORY_UNAVAILABLE', message: 'PRIVATE_CANARY' }, 503)
        : api.fetcher(path, init),
  );
  render(
    <ScanChatPanel
      status={publicStatus}
      transport={transport}
      client={createChatClient(scanSession(), fetcher)}
    />,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Открыть чат' }));
  await screen.findByRole('alert');
  expect(screen.getByRole('region', { name: 'Готовность генерации' })).toHaveTextContent(
    'Хранилище истории недоступно',
  );
  expect(document.body.textContent).not.toContain('PRIVATE_CANARY');
  expect(api.requests.filter((r) => r.init.method === 'POST')).toHaveLength(0);
});

it('local public readiness is explicitly unverified generation, not a provider success or substitute for consent', async () => {
  const api = publicChatApi();
  const { transport } = publicTransport();
  render(
    <ScanChatPanel
      status={publicStatus}
      transport={transport}
      client={createChatClient(scanSession(), api.fetcher)}
    />,
  );
  await open();
  expect(screen.getByRole('region', { name: 'Готовность генерации' })).toHaveTextContent(
    'Генерация не проверена.',
  );
  expect(screen.getByText(/xingchen-agi\/xing4.0-29b-a4b:free/)).toHaveTextContent('phala');
  expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
  expect(screen.queryByRole('checkbox', { name: /Разрешаю один запрос/ })).toBeNull();
  expect(api.requests.every((r) => r.init.method === 'GET')).toBe(true);
});

it('malformed readiness remains unknown without hiding valid history or revealing extra fields', async () => {
  const api = publicChatApi();
  const { transport } = publicTransport();
  const fetcher: typeof fetch = vi.fn(async (path, init) =>
    String(path).endsWith('/readiness')
      ? json({ ...readinessWire(), apiKey: 'PRIVATE_CANARY' })
      : api.fetcher(path, init),
  );
  render(
    <ScanChatPanel
      status={publicStatus}
      transport={transport}
      client={createChatClient(scanSession(), fetcher)}
    />,
  );
  await open();
  expect(screen.getByRole('region', { name: 'Готовность генерации' })).toHaveTextContent(
    'Готовность генерации неизвестна',
  );
  expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
  expect(document.body.textContent).not.toContain('PRIVATE_CANARY');
});

it('rechecks readiness before public send and dispatches no POST when the key becomes missing', async () => {
  const api = publicChatApi();
  const { transport } = publicTransport();
  let checks = 0;
  const fetcher: typeof fetch = vi.fn(async (path, init) =>
    String(path).endsWith('/readiness')
      ? json(readinessWire(++checks === 1 ? 'metadata-valid' : 'missing'))
      : api.fetcher(path, init),
  );
  render(
    <ScanChatPanel
      status={publicStatus}
      transport={transport}
      client={createChatClient(scanSession(), fetcher)}
    />,
  );
  await open();
  prepare();
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
  await screen.findByRole('alert');
  expect(screen.getByRole('region', { name: 'Готовность генерации' })).toHaveTextContent(
    'Серверный ключ не настроен или отсутствует',
  );
  expect(api.requests.filter((r) => r.init.method === 'POST')).toHaveLength(0);
});

it('allows public history with absent generation policy while showing configuration and provider blockers', async () => {
  const api = publicChatApi();
  api.policy = { ...api.policy, enabled: false, disclosure: null, policyVersion: null };
  const { transport } = publicTransport();
  const fetcher: typeof fetch = vi.fn(async (path, init) =>
    String(path).endsWith('/readiness')
      ? json(readinessWire('metadata-valid', true, true, null))
      : api.fetcher(path, init),
  );
  render(
    <ScanChatPanel
      status={publicStatus}
      transport={transport}
      client={createChatClient(scanSession(), fetcher)}
    />,
  );
  await open();
  const status = screen.getByRole('region', { name: 'Готовность генерации' });
  expect(status).toHaveTextContent('Требуется настройка политики генерации');
  expect(status).toHaveTextContent('Профиль провайдера недоступен');
  expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
  expect(api.requests.every((r) => r.init.method === 'GET')).toBe(true);
});

it.each([401, 403, 404])(
  'a public readiness %i denial hides owner history before reading chat context',
  async (code) => {
    const { transport } = publicTransport();
    const fetcher: typeof fetch = vi.fn(async () => new Response('PRIVATE_CANARY', { status: code }));
    render(
      <ScanChatPanel
        status={publicStatus}
        transport={transport}
        client={createChatClient(scanSession(), fetcher)}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Открыть чат' }));
    await screen.findByRole('alert');
    expect(screen.queryByLabelText('Вопрос чату')).toBeNull();
    expect(vi.mocked(fetcher).mock.calls).toHaveLength(1);
    expect(document.body.textContent).not.toContain('PRIVATE_CANARY');
  },
);

it('rejects readiness for a different report revision even when its local setup looks ready', async () => {
  const api = publicChatApi();
  const { transport } = publicTransport();
  const fetcher: typeof fetch = vi.fn(async (path, init) =>
    String(path).endsWith('/readiness')
      ? json({ ...readinessWire(), reportVersion: 'e'.repeat(64) })
      : api.fetcher(path, init),
  );
  render(
    <ScanChatPanel
      status={publicStatus}
      transport={transport}
      client={createChatClient(scanSession(), fetcher)}
    />,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Открыть чат' }));
  await screen.findByRole('alert');
  expect(screen.queryByLabelText('Вопрос чату')).toBeNull();
  expect(screen.getByRole('region', { name: 'Готовность генерации' })).toHaveTextContent(
    'Готовность генерации неизвестна',
  );
});

it('never reconstructs unknown public counts as checked zero when vulnerability coverage is missing', async () => {
  const api = publicChatApi(unknownPublicMetadata);
  const unknown: ScanStatus = { ...publicStatus, identifierCounts: undefined, perCheck: { vuln: null } };
  const transport = sourceTransport();
  render(
    <ScanChatPanel
      status={unknown}
      transport={transport}
      client={createChatClient(scanSession(), api.fetcher)}
    />,
  );
  await open();
  expect(screen.getByText(/число CVE и уведомлений Debian неизвестно/)).toBeVisible();
  expect(
    screen.getByText(/Покрытие уязвимостей: неизвестно; ОС: неизвестно; Node.js: неизвестно/),
  ).toBeVisible();
  expect(transport.results).not.toHaveBeenCalled();
});
