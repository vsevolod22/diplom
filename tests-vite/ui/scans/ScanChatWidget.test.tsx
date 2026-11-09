import '@testing-library/jest-dom/vitest';
import userEvent from '@testing-library/user-event';
import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanChatWidget } from '@/features/scans/ScanChatWidget';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { createChatClient } from '@/shared/api/scans/llmChatClient';
import type { ReportSourceNavigate } from '@/features/scans/reportSourceNavigation';
import { chatApi, sourceTransport, status } from './llmChatFixtures';

beforeEach(() => transitionScanSession('widget-test', new QueryClient(), true));
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function mount(fetcher?: typeof fetch, onNavigateSource?: ReportSourceNavigate) {
  const api = chatApi();
  const client = createChatClient(scanSession(), fetcher ?? api.fetcher);
  const transport = sourceTransport();
  const view = render(
    <ScanChatWidget
      status={status}
      transport={transport}
      client={client}
      onNavigateSource={onNavigateSource}
    />,
  );
  return { api, client, transport, view };
}
async function open() {
  fireEvent.click(screen.getByRole('button', { name: 'Открыть чат по отчёту' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Обновить историю' })).not.toBeDisabled());
  return screen.getByRole('textbox', { name: 'Вопрос чату' });
}

it('does not mount the panel or read chat until first open; opening only reads', async () => {
  const { api, transport } = mount();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(screen.queryByLabelText('Вопрос чату')).not.toBeInTheDocument();
  expect(api.requests).toHaveLength(0);
  expect(transport.results).not.toHaveBeenCalled();
  await open();
  expect(screen.getByRole('dialog', { name: 'Ассистент отчёта' })).toBeVisible();
  await waitFor(() => expect(screen.getByLabelText('Вопрос чату')).toHaveFocus());
  expect(api.requests.length).toBeGreaterThan(0);
  expect(api.requests.every((request) => request.init.method === 'GET')).toBe(true);
});

it('minimizes without unmounting or losing draft and reopens without new reads', async () => {
  const { api } = mount();
  const input = await open();
  fireEvent.change(input, { target: { value: '**Проверить** образ' } });
  const reads = api.requests.length;
  fireEvent.click(screen.getByRole('button', { name: 'Свернуть чат' }));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(input).toBeInTheDocument();
  expect(input).not.toBeVisible();
  expect(screen.getByRole('button', { name: 'Открыть чат по отчёту' })).toHaveFocus();
  expect(await open()).toBe(input);
  expect(input).toHaveValue('**Проверить** образ');
  expect(api.requests).toHaveLength(reads);
});

it('Escape returns focus to the launcher, and keyboard reopening focuses the composer', async () => {
  mount();
  const user = userEvent.setup();
  await open();
  await waitFor(() => expect(screen.getByLabelText('Вопрос чату')).toHaveFocus());
  await user.keyboard('{Escape}');
  const launcher = screen.getByRole('button', { name: 'Открыть чат по отчёту' });
  expect(launcher).toHaveFocus();
  await user.keyboard('{Enter}');
  await waitFor(() => expect(screen.getByLabelText('Вопрос чату')).toHaveFocus());
});

it('does not intercept Escape on the report while the retained window is minimized', async () => {
  mount(); await open();
  fireEvent.click(screen.getByRole('button', { name: 'Свернуть чат' }));
  const event = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true });
  document.body.dispatchEvent(event);
  expect(event.defaultPrevented).toBe(false);
});

it('keeps one in-flight POST alive while minimized, publishes its reply and never resends on reopen', async () => {
  const api = chatApi();
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  let signal: AbortSignal | null | undefined;
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).endsWith('/chat')) {
      signal = init?.signal;
      await gate;
    }
    return api.fetcher(input, init);
  });
  mount(fetcher);
  const input = await open();
  fireEvent.change(input, { target: { value: 'Что проверить?' } });
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
  await screen.findByText('ИИ готовит ответ');
  fireEvent.click(screen.getByRole('button', { name: 'Свернуть чат' }));
  expect(signal?.aborted).toBe(false);
  fireEvent.click(screen.getByRole('button', { name: 'Открыть чат по отчёту' }));
  expect(screen.getByText('ИИ готовит ответ')).toBeVisible();
  expect(input).toHaveValue('Что проверить?');
  expect(input).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Свернуть чат' }));
  await act(async () => release());
  await waitFor(() => expect(input).toHaveValue(''));
  await open();
  expect(screen.getByText(/исходную находку/)).toBeVisible();
  expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
  expect(api.requests.filter((request) => request.init.method === 'POST')).toHaveLength(1);
});

it('dismisses on source navigation without stealing report focus', async () => {
  const target = document.createElement('button');
  target.textContent = 'Раздел отчёта';
  document.body.append(target);
  const navigate = vi.fn(() => {
    target.focus();
    return true;
  });
  try {
    mount(undefined, navigate);
    await open();
    fireEvent.change(screen.getByLabelText('Вопрос чату'), { target: { value: 'Что проверить?' } });
    fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
    fireEvent.click(await screen.findByRole('link', { name: 'Открыть раздел «Возможные секреты»' }));
    expect(navigate).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await waitFor(() => expect(target).toHaveFocus());
  } finally {
    target.remove();
  }
});

it('keeps the window open when source navigation is refused', async () => {
  const navigate = vi.fn(() => false);
  mount(undefined, navigate); await open();
  fireEvent.change(screen.getByLabelText('Вопрос чату'), { target: { value: 'Что проверить?' } });
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
  fireEvent.click(await screen.findByRole('link', { name: 'Открыть раздел «Возможные секреты»' }));
  expect(navigate).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('dialog', { name: 'Ассистент отчёта' })).toBeVisible();
});

it('preserves the panel byte limit through formatting/preview and sends Markdown unchanged only on explicit submit', async () => {
  const { api } = mount();
  const input = (await open()) as HTMLTextAreaElement;
  const boundary = 'я '.repeat(682) + 'я';
  fireEvent.change(input, { target: { value: boundary } });
  expect(input).toHaveAttribute('aria-invalid', 'false');
  expect(document.getElementById('scan-chat-input-count')).toHaveTextContent('2048 / 2048');
  input.setSelectionRange(0, boundary.length);
  fireEvent.click(screen.getByRole('button', { name: 'Жирный текст' }));
  expect(input).toHaveValue(`**${boundary}**`);
  expect(input).toHaveAttribute('aria-invalid', 'true');
  expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Предпросмотр Markdown' }));
  expect(api.requests.filter((request) => request.init.method === 'POST')).toHaveLength(0);
  fireEvent.click(screen.getByRole('button', { name: 'Редактировать Markdown' }));
  const markdown = '**Проверить** образ\n\n- Пересобрать\n\n```text\nпример\n```';
  fireEvent.change(input, { target: { value: markdown } });
  expect(input).toHaveAttribute('aria-invalid', 'false');
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
  await screen.findByText(/исходную находку/);
  const posts = api.requests.filter((request) => request.init.method === 'POST');
  expect(posts).toHaveLength(1);
  expect(JSON.parse(String(posts[0].init.body)).question).toBe(markdown);
});

it('a new parent scope key resets the window and discards the old mounted draft', async () => {
  const { view, client, transport } = mount();
  await open();
  fireEvent.change(screen.getByLabelText('Вопрос чату'), { target: { value: 'Старый черновик' } });
  view.rerender(<ScanChatWidget key="new-scope" status={status} client={client} transport={transport} />);
  expect(screen.queryByLabelText('Вопрос чату')).not.toBeInTheDocument();
  expect(await open()).toHaveValue('');
});
