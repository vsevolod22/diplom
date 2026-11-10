import '@testing-library/jest-dom/vitest';
import './mockChatEditor';
import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanChatWidget } from '@/features/scans/ScanChatWidget';
import { createChatClient } from '@/shared/api/scans/llmChatClient';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { MODULEAPI_COST_BASIS, MODULEAPI_MODEL, moduleApiDisclosureSchema } from '@/shared/api/scans/llmPublicContract';
import { binding, chatApi, json, sourceTransport, status, usage } from './llmChatFixtures';
import { lifetimeContext, lifetimeUsage } from './lifetimeBudgetFixtures';

beforeEach(() => { localStorage.clear(); transitionScanSession('usability-owner', new QueryClient(), true); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

async function mount(paid = false, exhausted = false) {
  const api = chatApi();
  if (paid) {
    api.policy.disclosure = {
      ...moduleApiDisclosureSchema.options[1].parse({
        ...lifetimeContext.disclosure, provider: 'ModuleAPI', model: MODULEAPI_MODEL,
        costBasis: MODULEAPI_COST_BASIS, retention: 'unknown', tariffVerified: false,
      }),
      sentData: api.policy.disclosure!.sentData,
      localRetention: api.policy.disclosure!.localRetention,
    };
  }
  const fetcher = vi.fn<typeof fetch>(async (input, init) => {
    const path = String(input);
    if (path.endsWith('/readiness')) return json({ errorCode: 'LLM_DISABLED' }, 503);
    if (path.endsWith('/chat/usage')) return json(paid ? { ...lifetimeUsage(), admission: { status: 'unavailable' } } : {
      ...usage, integrationEnabled: true, quotaEnabled: true,
      ...(exhausted ? { reason: 'exhausted', user: { ...usage.user, exhausted: true, warning: true,
        limits: { input: 150, output: 60, costMicros: 0 }, remaining: { input: 0, output: 0, costMicros: 0 } } } : {}),
    });
    return api.fetcher(input, init);
  });
  render(<ScanChatWidget status={status} transport={sourceTransport()} client={createChatClient(scanSession(), fetcher)} />);
  fireEvent.click(screen.getByRole('button', { name: 'Открыть чат по отчёту' }));
  await screen.findByRole('heading', { name: 'Напишите первое сообщение' });
  return { api, fetcher };
}

it('keeps quota and free-profile conditions inline, with dialog Escape returning to trigger without minimizing chat or losing draft', async () => {
  const { fetcher } = await mount(false, true);
  const user = userEvent.setup();
  expect(screen.getByLabelText('Состояние квот чата')).toHaveTextContent('Квота исчерпана');
  expect(document.getElementById('scan-chat-send-help')).toHaveTextContent('Бесплатный профиль OpenRouter');
  const editor = screen.getByRole('textbox', { name: 'Вопрос чату' });
  fireEvent.change(editor, { target: { value: 'Что исправить сначала?' } });
  const calls = fetcher.mock.calls.length;
  const trigger = screen.getByRole('button', { name: 'Данные и использование' });
  await user.click(trigger);
  const dialog = screen.getByRole('dialog', { name: 'Данные и использование' });
  expect(dialog).toHaveTextContent(binding.reportVersion);
  expect(within(dialog).queryByRole('textbox')).toBeNull();
  await user.keyboard('{Escape}');
  expect(trigger).toHaveFocus();
  expect(screen.getByRole('dialog', { name: 'Ассистент отчёта' })).toBeVisible();
  expect(editor).toHaveValue('Что исправить сначала?');
  expect(document.getElementById('scan-chat-input-help')).toBeVisible();
  expect(fetcher).toHaveBeenCalledTimes(calls);
  expect(fetcher.mock.calls.every(([, init]) => init?.method === 'GET')).toBe(true);
  expect(screen.getByText('Решения · 0').closest('details')).not.toHaveAttribute('open');
});

it('keeps paid lifetime budget, transfer, unknown retention and send blocker visible; closes portaled data on owner loss', async () => {
  const { fetcher } = await mount(true);
  const notice = document.getElementById('scan-chat-send-help');
  expect(notice).toHaveTextContent('платный запрос через ModuleAPI');
  expect(notice).toHaveTextContent('Бюджет аккаунта $5 за всё время');
  expect(notice).not.toHaveTextContent('Без локального денежного лимита');
  expect(notice).toHaveTextContent('вопрос, историю и контекст отчёта');
  expect(notice).toHaveTextContent('Хранение и обучение у провайдера не подтверждены');
  expect(screen.getByLabelText('Состояние подключения чата')).toBeVisible();
  expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
  expect(screen.getByLabelText('Состояние квот чата')).not.toHaveTextContent('Квота исчерпана');
  fireEvent.click(screen.getByRole('button', { name: 'Данные и использование' }));
  expect(screen.getByRole('dialog', { name: 'Данные и использование' })).toHaveTextContent('Оконные счётчики — статистика');
  expect(within(screen.getByRole('dialog', { name: 'Данные и использование' })).getByText(/Условия хранения и использования данных для обучения неизвестны/)).toBeVisible();
  act(() => transitionScanSession(null, new QueryClient(), true));
  await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Данные и использование' })).not.toBeInTheDocument());
  expect(fetcher.mock.calls.every(([, init]) => init?.method === 'GET')).toBe(true);
});
