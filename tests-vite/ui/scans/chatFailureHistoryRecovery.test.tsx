import '@testing-library/jest-dom/vitest';
import './mockChatEditor';
import { webcrypto } from 'node:crypto';
import { QueryClient } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanChatPanel } from '@/features/scans/ScanChatPanel';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { createChatClient } from '@/shared/api/scans/llmChatClient';
import type { ChatHistory } from '@/shared/api/scans/llmChatContract';
import {
  binding,
  chatApi,
  history,
  json,
  reply,
  sourceTransport,
  status,
  turnId,
} from './llmChatFixtures';

const { encodeDelivery } = await import(
  /* @vite-ignore */ '../../../server/api/src/llm/' + 'history-delivery.ts'
);

const previousQuestion = 'Что проверить в сохранённом отчёте?';
const previousAnswer = 'Сохранённый ответ до ошибки провайдера';
const question = 'Как дела?';
const unexpectedAnswer = 'Неожиданный ответ после явной ошибки';
const originalError = 'Сервис ответов недоступен. Обновите историю перед повтором.';
const beforeRevision = 2;
type FailureCode = 'LLM_UNAVAILABLE' | 'LLM_PROVIDER_UNAVAILABLE';
type Contradiction = 'epoch' | 'policy' | 'unrelated revision' | 'pending' | 'question' | 'mutation' | 'report' | 'completed';

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  localStorage.clear();
  sessionStorage.clear();
  transitionScanSession('failure-recovery-owner', new QueryClient(), true);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function settled() {
  await waitFor(() => expect(screen.getByRole('button', { name: 'Обновить историю' })).toBeEnabled());
}

function mountFailure(
  errorCode: FailureCode = 'LLM_UNAVAILABLE',
  contradiction?: Contradiction,
  representation: 'frame' | 'json' = 'frame',
) {
  const api = chatApi();
  api.head = {
    ...history,
    revision: beforeRevision,
    turns: [{
      id: '00000000-0000-4000-8000-000000000010',
      mutationId: '00000000-0000-4000-8000-000000000011',
      state: 'completed',
      question: previousQuestion,
      report: binding,
      createdAt: 0,
      reply: { ...reply, text: previousAnswer },
    }],
  };
  const calls: Array<{ path: string; method: string }> = [];
  const fetcher = vi.fn<typeof fetch>(async (input, init) => {
    const path = String(input);
    const method = init?.method ?? 'GET';
    calls.push({ path, method });
    if (method !== 'POST') return api.fetcher(input, init);
    expect(path.endsWith('/llm/chat')).toBe(true);
    const body = JSON.parse(String(init?.body));
    expect(body).toMatchObject({ epoch: history.epoch, revision: beforeRevision, question });
    const failed: ChatHistory['turns'][number] = {
      id: turnId,
      mutationId: body.mutationId,
      state: 'failed',
      question: body.question,
      report: binding,
      createdAt: 1,
    };
    api.head = { ...api.head, revision: beforeRevision + 2, turns: [...api.head.turns, failed] };
    switch (contradiction) {
      case 'epoch':
        api.head = { ...api.head, epoch: crypto.randomUUID() };
        break;
      case 'policy':
        api.policy = { ...api.policy, policyVersion: 'd'.repeat(64) };
        break;
      case 'unrelated revision':
        api.head = { ...api.head, revision: beforeRevision + 3 };
        break;
      case 'pending':
        api.head = {
          ...api.head,
          turns: [...api.head.turns.slice(0, -1), { ...failed, state: 'pending' }],
          pending: { turnId, state: 'pending' },
        };
        break;
      case 'question':
        api.head = { ...api.head, turns: [...api.head.turns.slice(0, -1), { ...failed, question: 'Другой вопрос' }] };
        break;
      case 'mutation':
        api.head = { ...api.head, turns: [...api.head.turns.slice(0, -1), { ...failed, mutationId: crypto.randomUUID() }] };
        break;
      case 'report':
        api.head = {
          ...api.head,
          turns: [...api.head.turns.slice(0, -1), { ...failed, report: { ...binding, reportVersion: 'e'.repeat(64) } }],
        };
        break;
      case 'completed':
        api.head = {
          ...api.head,
          turns: [...api.head.turns.slice(0, -1), {
            ...failed, state: 'completed', reply: { ...reply, text: unexpectedAnswer },
          }],
        };
        break;
    }
    const failure = errorCode === 'LLM_PROVIDER_UNAVAILABLE'
      ? { errorCode, providerFailure: { kind: 'unavailable' as const, status: 502 } }
      : undefined;
    if (representation === 'json') return json(failure ?? { errorCode }, failure ? 502 : 503);
    return new Response(encodeDelivery({
      ...binding,
      epoch: history.epoch,
      revision: beforeRevision + 2,
      mutationId: body.mutationId,
      turnId,
      outcome: 'failed',
      receipt: 'unavailable',
      ...(failure ? { failure } : {}),
    }).lines.join(''), { headers: { 'Content-Type': 'application/x-ndjson' } });
  });
  const transport = sourceTransport();
  const client = createChatClient(scanSession(), fetcher);
  render(<ScanChatPanel status={status} transport={transport} client={client} />);
  return { api, calls, transport };
}

async function sendFailure() {
  await settled();
  expect(screen.getByText(previousQuestion)).toBeVisible();
  expect(screen.getByText(previousAnswer)).toBeVisible();
  fireEvent.change(screen.getByLabelText('Вопрос чату'), { target: { value: question } });
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
  await settled();
}

function expectOneReadOnlyRecovery(calls: Array<{ path: string; method: string }>) {
  expect(calls.filter(call => call.method === 'POST')).toHaveLength(1);
  const postIndex = calls.findIndex(call => call.method === 'POST');
  const recovery = calls.slice(postIndex + 1);
  expect(recovery.length).toBeGreaterThan(0);
  expect(recovery.every(call => call.method === 'GET')).toBe(true);
  expect(recovery.filter(call => call.path.endsWith('/chat/context'))).toHaveLength(2);
  expect(recovery.filter(call => call.path.endsWith('/history'))).toHaveLength(1);
  expect(recovery.filter(call => call.path.endsWith('/chat/usage'))).toHaveLength(1);
}

it.each([
  ['LLM_UNAVAILABLE', 'frame'],
  ['LLM_PROVIDER_UNAVAILABLE', 'frame'],
  ['LLM_UNAVAILABLE', 'json'],
  ['LLM_PROVIDER_UNAVAILABLE', 'json'],
] as const)('%s %s failure restores exact failed attempt and prior history through one GET-only snapshot', async (code, representation) => {
  const { calls } = mountFailure(code, undefined, representation);
  await sendFailure();
  expect(screen.getByText(previousQuestion)).toBeVisible();
  expect(screen.getByText(previousAnswer)).toBeVisible();
  expect(screen.getByText(question, { selector: ':not(textarea)' })).toBeVisible();
  expect(screen.getByRole('heading', { name: 'Вопрос · ошибка' })).toBeVisible();
  expect(screen.getByRole('alert')).toHaveTextContent(originalError);
  expect(screen.queryByText(/Ответ сохранён\. Соединение прервалось/)).not.toBeInTheDocument();
  expect(screen.getByLabelText('Вопрос чату')).toHaveValue(question);
  expect(screen.getAllByRole('heading', { name: 'Ответ · проверьте по источникам' })).toHaveLength(1);
  expectOneReadOnlyRecovery(calls);
});

it.each<Contradiction>([
  'epoch', 'policy', 'unrelated revision', 'pending', 'question', 'mutation', 'report', 'completed',
])('keeps contradictory %s recovery hidden and preserves the original typed failure', async contradiction => {
  const { calls } = mountFailure('LLM_PROVIDER_UNAVAILABLE', contradiction);
  await sendFailure();
  expect(screen.getByRole('alert')).toHaveTextContent(originalError);
  expect(screen.queryByText(previousQuestion)).not.toBeInTheDocument();
  expect(screen.queryByText(previousAnswer)).not.toBeInTheDocument();
  expect(screen.queryByText(question, { selector: ':not(textarea)' })).not.toBeInTheDocument();
  expect(screen.queryByText('Другой вопрос')).not.toBeInTheDocument();
  expect(screen.queryByText(unexpectedAnswer)).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Вопрос · ошибка' })).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Ответ · проверьте по источникам' })).not.toBeInTheDocument();
  expect(screen.getByLabelText('Вопрос чату')).toHaveValue(question);
  expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
  expectOneReadOnlyRecovery(calls);
});

it('explicit refresh rechecks source pages as well as context and history', async () => {
  const { calls, transport } = mountFailure();
  await settled();
  expect(transport.results).toHaveBeenCalledTimes(2);
  const initialCalls = calls.length;
  for (let refresh = 0; refresh < 2; refresh++) {
    fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
    await settled();
    expect(screen.getByText(previousAnswer)).toBeVisible();
  }
  const refreshCalls = calls.slice(initialCalls);
  expect(refreshCalls.every(call => call.method === 'GET')).toBe(true);
  expect(refreshCalls.filter(call => call.path.endsWith('/chat/context'))).toHaveLength(4);
  expect(refreshCalls.filter(call => call.path.endsWith('/history'))).toHaveLength(2);
  expect(refreshCalls.filter(call => call.path.endsWith('/chat/usage'))).toHaveLength(2);
  expect(transport.results).toHaveBeenCalledTimes(6);
});


it("a context rejection preserves verified history without a second POST", async () => {
  const api = chatApi();
  const fetcher = vi.fn<typeof fetch>((input, init) => init?.method === "POST"
    ? Promise.resolve(json({ errorCode: "LLM_CONTEXT_LIMIT" }, 409))
    : api.fetcher(input, init));
  render(<ScanChatPanel status={status} transport={sourceTransport()} client={createChatClient(scanSession(), fetcher)} />);
  await settled();
  fireEvent.change(screen.getByLabelText("Вопрос чату"), { target: { value: question } });
  fireEvent.click(screen.getByRole("button", { name: "Отправить вопрос" }));
  await settled();
  expect(screen.getByRole("alert")).toHaveTextContent("Обязательный контекст");
  expect(screen.getByRole("button", { name: "Отправить вопрос" })).toBeEnabled();
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === "POST")).toHaveLength(1);
});
