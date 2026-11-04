import '@testing-library/jest-dom/vitest';
import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanChatPanel } from '@/features/scans/ScanChatPanel';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { ChatError, createChatClient } from '@/shared/api/scans/llmChatClient';
import { chatContextSchema, type ChatHistory } from '@/shared/api/scans/llmChatContract';
import {
  binding,
  chatApi,
  context,
  history,
  reply,
  source,
  sourceTransport,
  status,
  turnId,
} from './llmChatFixtures';

const QUESTION = 'Как проверить сохранённую находку?';
const DRAFT = 'Сначала проверим пакет';
const OWNER = 'batch26-synthetic-owner';
const queryClient = new QueryClient();
const completed: ChatHistory = {
  ...history,
  revision: 2,
  turns: [
    {
      id: turnId,
      mutationId: '00000000-0000-4000-8000-000000000026',
      state: 'completed',
      question: QUESTION,
      report: binding,
      createdAt: 0,
      reply,
    },
  ],
};
function terminal(state: 'failed' | 'cancelled' | 'interrupted' | 'pending'): ChatHistory {
  return {
    ...history,
    revision: 2,
    pending: state === 'pending' ? { turnId, state: 'pending' } : null,
    turns: [
      {
        id: turnId,
        mutationId: '00000000-0000-4000-8000-000000000026',
        state,
        question: QUESTION,
        report: binding,
        createdAt: 0,
      },
    ],
  };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
function mount(head = completed) {
  const api = chatApi();
  api.head = structuredClone(head);
  const client = createChatClient(scanSession(), api.fetcher);
  const transport = sourceTransport();
  const view = render(<ScanChatPanel status={status} transport={transport} client={client} />);
  return { api, client, transport, view };
}
const refresh = () => screen.getByRole('button', { name: 'Обновить историю' });
const input = () => screen.getByRole('textbox', { name: 'Вопрос чату' });
const send = () => screen.getByRole('button', { name: 'Отправить вопрос' });
const region = () => screen.getByRole('region', { name: 'Чат по отчёту' });
async function ready() {
  await waitFor(() => expect(region()).toHaveAttribute('aria-busy', 'false'));
}
function prepare() {
  fireEvent.change(input(), { target: { value: DRAFT } });
  input().focus();
}
function noPosts(api: ReturnType<typeof chatApi>) {
  expect(api.requests.filter((r) => r.init.method === 'POST')).toHaveLength(0);
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  transitionScanSession(OWNER, queryClient, true);
  // Uninjected network is an error, never a fallback to an existing deployment.
  vi.stubGlobal(
    'fetch',
    vi.fn(() => Promise.reject(new Error('OFFLINE_UNEXPECTED_NETWORK'))),
  );
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  queryClient.clear();
});

it.each(['failed', 'cancelled', 'interrupted'] as const)(
  'persisted %s is terminal, not a still-pending answer, and invents no persisted reason',
  async (state) => {
    const { api, view } = mount(terminal(state));
    await ready();
    const article = region().querySelector('article')!;
    expect(article).not.toHaveTextContent('Ответ пока не получен.');
    expect(article).toHaveTextContent(/обнов|повтор|провер|заверш|отмен|прерван/i);
    expect(article).not.toHaveTextContent(
      /LLM_|invalid_content|429|rate_limited|списан|возвращён|ошибк[аи] провайдера/i,
    );
    expect(article).toHaveTextContent(QUESTION);
    noPosts(api);
    view.unmount();
    const remount = mount(terminal(state));
    await ready();
    expect(region().querySelectorAll('article')).toHaveLength(1);
    noPosts(remount.api);
  },
);

it('authoritative pending is distinct, blocks mutation and never auto-resends on mount/focus/reconnect/refresh', async () => {
  const { api } = mount(terminal('pending'));
  await ready();
  prepare();
  expect(screen.getByRole('status', { name: 'Состояние подключения чата' })).toHaveTextContent(
    /выполняется|ожида/i,
  );
  expect(send()).toBeDisabled();
  fireEvent.focus(window);
  fireEvent(window, new Event('online'));
  fireEvent.click(refresh());
  await ready();
  expect(send()).toBeDisabled();
  noPosts(api);
});

it('failed-question preparation is draft-only and focuses the composer without paid retry', async () => {
  const { api } = mount(terminal('failed'));
  await ready();
  fireEvent.click(screen.getByRole('button', { name: 'Подготовить повтор вопроса' }));
  expect(input()).toHaveValue(QUESTION);
  expect(input()).toHaveFocus();
  noPosts(api);
  fireEvent.focus(window);
  fireEvent(window, new Event('online'));
  await act(async () => {});
  noPosts(api);
});

it('same-owner/report refresh retains an explicitly stale prior view, draft and focus while all mutation actions are fenced', async () => {
  const { api, client } = mount();
  await ready();
  prepare();
  const oldInput = input();
  const gate = deferred<typeof context>();
  vi.spyOn(client, 'context').mockImplementationOnce(() => gate.promise);
  fireEvent.click(refresh());
  expect(region()).toHaveAttribute('aria-busy', 'true');
  expect(screen.getByText(QUESTION)).toBeVisible();
  expect(region()).toHaveTextContent(/предыдущ|сохранённ|обновля/i);
  expect(input()).toBe(oldInput);
  expect(input()).toHaveValue(DRAFT);
  expect(input()).toHaveFocus();
  expect(send()).toBeDisabled();
  fireEvent.click(
    screen.getByText('Подробности · история решений, условия и использование', { selector: 'summary' }),
  );
  expect(screen.getByRole('button', { name: 'Сохранить решение' })).toBeDisabled();
  expect(screen.queryByText('Отмена остановит ожидание, но запрос ещё может завершиться.')).toBeNull();
  await act(async () => gate.resolve(chatContextSchema.parse({ ...context, revision: 2 })));
  await ready();
  expect(screen.getByText(QUESTION)).toBeVisible();
  expect(input()).toHaveValue(DRAFT);
  expect(input()).toHaveFocus();
  noPosts(api);
});

it('stale prior terminal retry action cannot dispatch or replace a draft during metadata refresh', async () => {
  const { api, client } = mount(terminal('failed'));
  await ready();
  prepare();
  const gate = deferred<typeof context>();
  vi.spyOn(client, 'context').mockImplementationOnce(() => gate.promise);
  fireEvent.click(refresh());
  expect(screen.getByRole('button', { name: 'Подготовить повтор вопроса' })).toBeDisabled();
  expect(send()).toBeDisabled();
  noPosts(api);
  await act(async () => gate.resolve(chatContextSchema.parse({ ...context, revision: 2 })));
  await ready();
  expect(input()).toHaveValue(DRAFT);
  noPosts(api);
});

it.each(['SESSION', 'ACCESS', 'INVALID', 'STALE', 'LLM_HISTORY_UNAVAILABLE', 'UNRECOGNIZED'] as const)(
  'refresh %s hides private prior history/sources and disables send, never fabricates a successful read',
  async (code) => {
    const { api, client } = mount();
    await ready();
    prepare();
    const gate = deferred<typeof context>();
    vi.spyOn(client, 'context').mockImplementationOnce(() => gate.promise);
    fireEvent.click(refresh());
    await act(async () =>
      gate.reject(code === 'UNRECOGNIZED' ? new Error('PRIVATE_BATCH26_INTERNAL') : new ChatError(code)),
    );
    await ready();
    expect(screen.queryByText(QUESTION)).toBeNull();
    expect(screen.queryByText('Источники (1)')).toBeNull();
    if (code === 'SESSION' || code === 'ACCESS') expect(input()).toHaveValue('');
    expect(send()).toBeDisabled();
    expect(screen.getByRole('alert')).not.toHaveTextContent(/PRIVATE_BATCH26_INTERNAL|LLM_|INVALID/);
    noPosts(api);
  },
);

it('new owner immediately resets history, draft, disclosure and blocks a late old-owner publish', async () => {
  const { api, client } = mount();
  await ready();
  prepare();
  const gate = deferred<typeof context>();
  vi.spyOn(client, 'context').mockImplementationOnce(() => gate.promise);
  fireEvent.click(refresh());
  act(() => transitionScanSession('batch26-new-owner', queryClient));
  expect(screen.queryByText(QUESTION)).toBeNull();
  expect(input()).toHaveValue('');
  expect(send()).toBeDisabled();
  await act(async () => gate.resolve(chatContextSchema.parse({ ...context, revision: 2 })));
  expect(screen.queryByText(QUESTION)).toBeNull();
  expect(input()).toHaveValue('');
  noPosts(api);
});

it('different report immediately discards private prior view and draft instead of carrying stale data across report identities', async () => {
  const { api, client, transport, view } = mount();
  await ready();
  prepare();
  const other = { ...status, scanId: '00000000-0000-4000-8000-000000000099' };
  view.rerender(<ScanChatPanel status={other} transport={transport} client={client} />);
  expect(screen.queryByText(QUESTION)).toBeNull();
  expect(input()).toHaveValue('');
  await ready();
  expect(send()).toBeDisabled();
  noPosts(api);
});

it('completed answer and exact immutable source remain explicitly navigable after remount, with no automatic POST', async () => {
  const first = mount();
  await ready();
  noPosts(first.api);
  first.view.unmount();
  const { api } = mount();
  await ready();
  const sources = screen.getByLabelText('Источники ответа');
  expect(screen.getByText('Источники (1)')).toBeVisible();
  expect(sources.closest('details')).toBeNull();
  expect(sources.querySelector('details')).toBeNull();
  const row = document.getElementById(`chat-${turnId}-${source.finding.findingId}`)!;
  expect(sources.contains(row)).toBe(true);
  expect(row).toBeVisible();
  if (source.finding.check !== 'secret') throw new Error('Wrong synthetic fixture');
  expect(row).toHaveTextContent(source.finding.ruleId);
  expect(row).toHaveTextContent(source.finding.evidenceRef);
  expect(row).toHaveTextContent(`Строка: ${source.finding.line}`);
  noPosts(api);
});

it('capacity failure describes shared storage/admission rather than asserting this chat alone is too long', async () => {
  const { api, client } = mount();
  await ready();
  vi.spyOn(client, 'chat').mockRejectedValueOnce(new ChatError('LLM_HISTORY_CAPACITY'));
  prepare();
  fireEvent.click(send());
  const alert = await screen.findByRole('alert');
  expect(alert).not.toHaveTextContent('В чате слишком много данных');
  expect(alert).toHaveTextContent(/хранилищ|мест|ёмкост|сервис|общ|лимит/i);
  expect(alert).not.toHaveTextContent(/удалите|очистите|возврат выполнен|PRIVATE/);
  await ready();
  fireEvent.click(refresh());
  await ready();
  noPosts(api);
});

it.each(['cancel', 'deadline'] as const)(
  'metadata %s ends within bounds, hides old private view, never claims generation and rejects late publication',
  async (mode) => {
    const { api, client } = mount();
    await ready();
    prepare();
    const gate = deferred<typeof context>();
    vi.spyOn(client, 'context').mockImplementationOnce(() => gate.promise);
    if (mode === 'deadline') vi.useFakeTimers();
    fireEvent.click(refresh());
    expect(screen.getByText(QUESTION)).toBeVisible();
    if (mode === 'cancel')
      fireEvent.click(screen.getByRole('button', { name: 'Отменить обновление истории' }));
    else
      await act(async () => {
        await vi.advanceTimersByTimeAsync(45_001);
      });
    vi.useRealTimers();
    await ready();
    expect(screen.queryByText(QUESTION)).toBeNull();
    expect(send()).toBeDisabled();
    expect(screen.getByRole('alert')).toHaveTextContent(/только чтение|новый вопрос не отправлялся/i);
    expect(screen.getByRole('alert')).not.toHaveTextContent('Ответ ещё может сохраниться');
    await act(async () => gate.resolve(chatContextSchema.parse({ ...context, revision: 2 })));
    expect(screen.queryByText(QUESTION)).toBeNull();
    noPosts(api);
  },
);

it('changed policy clears the stale prior view before an unconfirmed history read finishes', async () => {
  const { api, client } = mount();
  await ready();
  prepare();
  api.policy = { ...api.policy, policyVersion: 'd'.repeat(64) };
  const gate = deferred<ChatHistory>();
  vi.spyOn(client, 'history').mockImplementationOnce(() => gate.promise);
  fireEvent.click(refresh());
  await waitFor(() => expect(screen.queryByText(QUESTION)).toBeNull());
  expect(send()).toBeDisabled();
  noPosts(api);
  await act(async () => gate.reject(new ChatError('STALE')));
  await ready();
  noPosts(api);
});

it('paid disclosure stays honest and failed retry preparation remains zero paid POST', async () => {
  const api = chatApi();
  api.head = terminal('failed');
  const data =
    'Sanitized scanner findings, package names, installed and reported fixed versions, and coverage; no raw evidence or credentials.' as const;
  api.policy = {
    ...context,
    disclosure: {
      provider: 'OpenAI',
      model: 'gpt-5.4-mini-2026-03-17',
      retention: 'no-training',
      operatorApprovedRouting: true,
      providerComplianceNotProvenByDeclaration: true,
      zeroDataRetentionVerified: false,
      costBasis: 'server-estimated-configured-rates-not-invoice',
      estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 750000, output: 4500000 },
      data,
      monetaryLimit: 'uncapped',
      requestBudgetMicros: null,
      userBudgetMicros: null,
      scanBudgetMicros: null,
      sentData:
        'Cleaned question, all user history/accepted decisions and selected findings with complete coverage.',
      localRetention:
        'Durable owner+scan history until separately authorized operator lifecycle; capacity can refuse; context cache only, not output cache.',
    },
  };
  const client = createChatClient(scanSession(), api.fetcher);
  vi.spyOn(client, 'readiness').mockResolvedValue({
    ...binding,
    status: 'locally-configured',
    localReady: true,
    blockers: [],
    credential: 'environment-valid',
    accounting: 'configured',
    quota: 'available',
    history: 'available',
    provider: {
      name: 'OpenAI',
      model: 'gpt-5.4-mini-2026-03-17',
      status: 'configured-unprobed',
      liveVerified: false,
    },
    generationVerified: false,
    requiresConsent: true,
    acceptsCredentials: false,
    setupAction: 'operator-server-environment-configuration',
  });
  vi.spyOn(client, 'usage').mockResolvedValue({
    ...binding,
    available: false,
    reason: 'unavailable',
    integrationEnabled: true,
    quotaEnabled: false,
  });
  render(<ScanChatPanel status={status} transport={sourceTransport()} client={client} />);
  await ready();
  expect(screen.getByLabelText('Условия OpenAI')).toBeVisible();
  expect(region()).toHaveTextContent(/платн/);
  expect(region()).toHaveTextContent(/без.*лимит|не огранич|не установлен/i);
  fireEvent.click(screen.getByRole('button', { name: 'Подготовить повтор вопроса' }));
  expect(input()).toHaveValue(QUESTION);
  expect(input()).toHaveFocus();
  noPosts(api);
});
