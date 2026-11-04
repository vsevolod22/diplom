import '@testing-library/jest-dom/vitest';
import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanChatPanel } from '@/features/scans/ScanChatPanel';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { saveReportPreferences } from '@/shared/api/preferences/reportPreferences';
import { createChatClient } from '@/shared/api/scans/llmChatClient';
import { binding, chatApi, history, json, reply, sourceTransport, status, turnId } from './llmChatFixtures';

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  transitionScanSession('chat-navigation-owner', new QueryClient(), true);
  saveReportPreferences({ language: 'ru', autoSummary: false });
  vi.stubGlobal(
    'fetch',
    vi.fn(() => {
      throw Error('Unexpected network outside controlled chat client');
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
function mount(historical = false) {
  const api = chatApi();
  const report = historical ? { ...binding, reportVersion: 'd'.repeat(64) } : binding;
  api.head = {
    ...history,
    turns: [
      {
        id: turnId,
        mutationId: turnId,
        question: 'Как проверить находку?',
        report,
        state: 'completed',
        createdAt: 0,
        reply: { ...reply, ...report, sources: reply.sources.map((source) => ({ ...source, ...report })) },
      },
    ],
  };
  let blocked: Promise<Response> | undefined;
  const calls: Array<{ path: string; method: string }> = [];
  const fetcher: typeof fetch = async (input, init) => {
    const path = String(input),
      method = init?.method ?? 'GET';
    calls.push({ path, method });
    if (method !== 'GET') throw Error('No automatic mutations in navigation test');
    if (blocked && path.endsWith('/chat/context')) return (await blocked).clone();
    return api.fetcher(input, init);
  };
  const navigate = vi.fn(() => true);
  const view = render(
    <ScanChatPanel
      status={status}
      transport={sourceTransport()}
      client={createChatClient(scanSession(), fetcher)}
      onNavigateSource={navigate}
    />,
  );
  return {
    ...view,
    api,
    navigate,
    calls,
    block: (promise: Promise<Response>) => {
      blocked = promise;
    },
  };
}
function noDispatch(calls: ReturnType<typeof mount>['calls']) {
  expect(calls.every((call) => call.method === 'GET')).toBe(true);
  expect(calls.some((call) => call.path.includes('/translation'))).toBe(false);
  expect(fetch).not.toHaveBeenCalled();
}
it('saved current chat citations expose canonical section navigation with no duplicate technical accordion or automatic send/translation', async () => {
  const view = mount();
  const link = await screen.findByRole('link', { name: 'Открыть раздел «Возможные секреты»' });
  expect(link).toHaveAttribute('href', '#scan-report-secrets');
  expect(link.closest('details')).toBeNull();
  fireEvent.click(link);
  expect(view.navigate).toHaveBeenCalledExactlyOnceWith('secret');
  expect(screen.getByText(/Переход к разделу, не к точной находке/)).toBeVisible();
  noDispatch(view.calls);
});
it('historical source remains readable but never authorizes navigation into current report', async () => {
  const view = mount(true);
  await screen.findByText(/Исторический источник — не разрешён как находка текущего отчёта/);
  expect(screen.queryByRole('link', { name: 'Открыть раздел «Возможные секреты»' })).not.toBeInTheDocument();
  expect(screen.getByText(/Открыть раздел «Возможные секреты».*переход сейчас недоступен/)).toBeVisible();
  expect(view.navigate).not.toHaveBeenCalled();
  noDispatch(view.calls);
});
it('same-scope chat refresh disables source navigation and preserves draft until successful read without auto POST', async () => {
  const view = mount();
  await screen.findByRole('link', { name: 'Открыть раздел «Возможные секреты»' });
  const question = screen.getByRole('textbox', { name: 'Вопрос чату' });
  fireEvent.change(question, { target: { value: 'Не отправлять этот черновик' } });
  let resolve!: (response: Response) => void;
  view.block(
    new Promise<Response>((done) => {
      resolve = done;
    }),
  );
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
  await screen.findByRole('button', { name: 'Отменить обновление истории' });
  expect(screen.queryByRole('link', { name: 'Открыть раздел «Возможные секреты»' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
  expect(question).toHaveValue('Не отправлять этот черновик');
  expect(view.navigate).not.toHaveBeenCalled();
  await act(async () => resolve(json(view.api.policy)));
  await screen.findByRole('link', { name: 'Открыть раздел «Возможные секреты»' });
  expect(question).toHaveValue('Не отправлять этот черновик');
  noDispatch(view.calls);
});
it('failed refresh clears source navigation instead of treating a prior source as fresh', async () => {
  const view = mount();
  await screen.findByRole('link', { name: 'Открыть раздел «Возможные секреты»' });
  view.block(Promise.resolve(json({ errorCode: 'LLM_UNAVAILABLE' }, 503)));
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
  await waitFor(() =>
    expect(
      screen.queryByRole('link', { name: 'Открыть раздел «Возможные секреты»' }),
    ).not.toBeInTheDocument(),
  );
  await waitFor(() =>
    expect(screen.queryByText(/Источник текущего отчёта, проверен/)).not.toBeInTheDocument(),
  );
  expect(view.navigate).not.toHaveBeenCalled();
  noDispatch(view.calls);
});
