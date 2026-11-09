import '@testing-library/jest-dom/vitest';
import userEvent from '@testing-library/user-event';
import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanChatPanel } from '@/features/scans/ScanChatPanel';
import type { ReportSourceNavigate } from '@/features/scans/reportSourceNavigation';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import {
  readReportPreferences,
  REPORT_AUTOMATION_REVISION,
  saveReportPreferences,
} from '@/shared/api/preferences/reportPreferences';
import { createChatClient } from '@/shared/api/scans/llmChatClient';
import type { ChatContext, ChatHistory } from '@/shared/api/scans/llmChatContract';
import {
  binding,
  chatApi,
  context,
  epoch,
  history,
  json,
  reply,
  source,
  sourceTransport,
  status,
  turnId,
} from './llmChatFixtures';

const { encodeDelivery } = await import(
  /* @vite-ignore */ '../../../server/api/src/llm/' + 'history-delivery.ts'
);

beforeEach(() => transitionScanSession('alice', new QueryClient(), true));
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});
function mount(api = chatApi(), fetcher: typeof fetch = api.fetcher, onNavigateSource?: ReportSourceNavigate) {
  const transport = sourceTransport();
  const client = createChatClient(scanSession(), fetcher);
  return {
    api,
    client,
    transport,
    view: render(
      <>
        <p>Исходный отчёт · UNKNOWN coverage · findings сохранны</p>
        <ScanChatPanel status={status} transport={transport} client={client} onNavigateSource={onNavigateSource} />
      </>,
    ),
  };
}
async function open() {
  await waitFor(() =>
    expect((screen.getByRole('button', { name: 'Обновить историю' }) as HTMLButtonElement).disabled).toBe(
      false,
    ),
  );
}
function send(question = 'Что проверить?') {
  fireEvent.change(screen.getByLabelText('Вопрос чату'), { target: { value: question } });
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
}
it('recovers a committed answer after an HTML 502 through GETs without repeating the paid POST', async () => {
  const api = chatApi();
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const response = await api.fetcher(input, init);
    if (String(input).endsWith('/chat')) return new Response('Bad Gateway', { status: 502, headers: { 'content-type': 'text/html' } });
    return response;
  });
  mount(api, fetcher); await open(); send();
  await screen.findByText(/Ответ сохранён. Соединение прервалось/);
  expect(screen.getByText(/исходную находку/)).toBeVisible();
  expect(screen.getByLabelText('Вопрос чату')).toHaveValue('');
  expect(api.requests.filter(request => request.init.method === 'POST')).toHaveLength(1);
});

it('does not recover another mutation after uncertain delivery and never resends', async () => {
  const api = chatApi();
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const response = await api.fetcher(input, init);
    if (String(input).endsWith('/chat')) {
      api.head = { ...api.head, turns: api.head.turns.map(turn => ({ ...turn, mutationId: crypto.randomUUID() })) };
      return new Response('Bad Gateway', { status: 502, headers: { 'content-type': 'text/html' } });
    }
    return response;
  });
  mount(api, fetcher); await open(); send();
  await waitFor(() => expect(screen.getByRole('button', { name: 'Обновить историю' })).not.toBeDisabled());
  expect(screen.queryByText(/Ответ сохранён. Соединение прервалось/)).not.toBeInTheDocument();
  expect(screen.queryByText(/исходную находку/)).not.toBeInTheDocument();
  expect(api.requests.filter(request => request.init.method === 'POST')).toHaveLength(1);
});

it('shows an honest thinking indicator while the explicit chat request is pending', async () => {
  const api = chatApi(); let complete!: () => void;
  const gate = new Promise<void>(resolve => { complete = resolve; });
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).endsWith('/chat')) await gate;
    return api.fetcher(input, init);
  });
  mount(api, fetcher); await open(); send();
  await screen.findByText('ИИ готовит ответ');
  expect(screen.getByText(/Ответ появится после проверки и сохранения/)).toBeVisible();
  await act(async () => complete());
  await waitFor(() => expect(screen.queryByText('ИИ готовит ответ')).not.toBeInTheDocument());
});

it.each(['partial', 'failed', 'cancelled'] as const)('B2 %s explains summary/translation limitation without claiming unchecked results are safe', async state => {
  const api = chatApi();
  render(<ScanChatPanel status={{ ...status, state }} transport={sourceTransport()} client={createChatClient(scanSession(), api.fetcher)} />);
  await open();
  expect(screen.getByText(/Авторазбор и отдельный перевод описаний доступны только/)).toBeVisible();
  expect(screen.getByText(/непроверенное не означает отсутствие проблем/)).toBeVisible();
  expect(screen.getByRole('textbox', { name: 'Вопрос чату' })).toBeVisible();
  expect(api.requests.filter(request => request.init.method === 'POST')).toHaveLength(0);
});

it.each([
  ['я'.repeat(1025), 'Текст слишком длинный: 2050 из 2048 байт UTF-8'],
  ['Ссылка https://example.test', 'Уберите ссылки'],
  ['<script>пример</script>', 'Уберите угловые скобки'],
  ['token=synthetic', 'Уберите конструкции с паролями'],
  ['A'.repeat(40), 'Уберите длинные непрерывные последовательности'],
  ['CANARY', 'Уберите служебный маркер'],
  ['Вопрос\u202e', 'Уберите управляющие символы'],
])('B2 invalid question/decision explains rejection, keeps draft and sends no POST: %s', async (draft, message) => {
  const { api } = mount(); await open();
  fireEvent.click(screen.getByText('Подробности · история решений, условия и использование', { selector: 'summary' }));
  for (const label of ['Вопрос чату', 'Текст решения']) {
    const input = screen.getByLabelText(label);
    fireEvent.change(input, { target: { value: draft } });
    expect(input).toHaveValue(draft); expect(input).toHaveAttribute('aria-invalid', 'true');
    const descriptionIds = input.getAttribute('aria-describedby')!.split(' ');
    expect(descriptionIds.every(id => document.getElementById(id))).toBe(true);
    expect(document.getElementById(label === 'Вопрос чату' ? 'scan-chat-input-error' : 'scan-chat-decision-error')).toHaveTextContent(message);
  }
  expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Сохранить решение' })).toBeDisabled();
  expect(api.requests.filter(request => request.init.method === 'POST')).toHaveLength(0);
  fireEvent.change(screen.getByLabelText('Вопрос чату'), { target: { value: 'я'.repeat(1024) } });
  expect(screen.getByLabelText('Вопрос чату')).toHaveAttribute('aria-invalid', 'false');
  expect(document.getElementById('scan-chat-input-count')).toHaveTextContent('2048 / 2048 байт UTF-8');
});

it('cross-tab preference replacement aborts an explicit POST preflight synchronously, not only during React cleanup', async () => {
  saveReportPreferences({ language: 'ru', autoSummary: true });
  const { client, api } = mount();
  await open();
  const accepted = readReportPreferences();
  let abortedImmediately: boolean | undefined;
  let observedRevision: typeof accepted.revision | undefined;
  const context = api.policy;
  vi.spyOn(client, 'context').mockImplementationOnce(async (_id, signal) => {
    localStorage.setItem(
      'report-preferences:v1:alice',
      JSON.stringify({
        version: 1,
        automationRevision: REPORT_AUTOMATION_REVISION,
        language: 'original',
        autoSummary: false,
      }),
    );
    window.dispatchEvent(
      new StorageEvent('storage', { key: 'report-preferences:v1:alice', storageArea: localStorage }),
    );
    abortedImmediately = signal.aborted;
    observedRevision = readReportPreferences().revision;
    return context;
  });
  send();
  await waitFor(() => expect(abortedImmediately).toBeDefined());
  expect(abortedImmediately).toBe(true);
  expect(observedRevision).toBe(accepted.revision);
  expect(api.requests.filter((request) => request.init.method === 'POST')).toHaveLength(0);
  expect((screen.getByLabelText('Вопрос чату') as HTMLTextAreaElement).value).toBe('');
});

it('opens history and composer automatically, exposes disclosure and never dispatches a question on mount or focus', async () => {
  const { api } = mount();
  fireEvent.focus(window);
  expect(screen.getByLabelText('Вопрос чату')).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Открыть чат' })).toBeNull();
  await open();
  expect(api.requests.every((r) => r.init.method === 'GET')).toBe(true);
  expect(screen.getByRole('heading', { name: 'Задать вопрос по отчёту' })).toBeVisible();
  expect(screen.getByText('Подробности · история решений, условия и использование').closest('details')).not.toHaveAttribute('open');
  expect(screen.getByText(/apodex\/apodex-1.1-mini:free/)).not.toBeVisible();
  expect(screen.getByLabelText('Текст решения')).not.toBeVisible();
  for (const usage of screen.getAllByText(/остаток входных токенов 9850/)) expect(usage).not.toBeVisible();
  expect(screen.getByText(new RegExp(binding.scanId))).not.toBeVisible();
  expect(screen.getByText(/Нажимая «Отправить вопрос»/)).toBeVisible();
  expect(screen.getByText(/Нажимая «Отправить вопрос»/)).toHaveTextContent(
    'внешнему ИИ вопрос и контекст отчёта',
  );
  expect(screen.getByText(/Нажимая «Отправить вопрос»/)).toHaveTextContent(
    'Запрет обучения не гарантирует отсутствие хранения',
  );
  expect(document.body.textContent).toContain('apodex/apodex-1.1-mini:free');
  expect(document.body.textContent).toContain('novita/bf16');
  expect(document.body.textContent).toContain('остаток входных токенов 9850, выходных токенов 9940');
  expect(document.body.textContent).toContain('Допуск запроса неизвестен');
  expect(document.body.textContent).toContain('без автоматического срока удаления');
  expect(screen.queryByRole('checkbox', { name: /Разрешаю один запрос/ })).toBeNull();
  expect((screen.getByRole('button', { name: 'Отправить вопрос' }) as HTMLButtonElement).disabled).toBe(true);
});
it('supports a labelled keyboard composer without sending on typing, and disables send while waiting', async () => {
  const user = userEvent.setup();
  const { client, api } = mount();
  await open();
  const chat = vi.spyOn(client, 'chat').mockImplementation(() => new Promise(() => {}));
  const input = screen.getByRole('textbox', { name: 'Вопрос чату' });
  await user.click(input);
  await user.type(input, 'Что проверить?{Enter}');
  expect(chat).not.toHaveBeenCalled();
  expect(api.requests.every((request) => request.init.method === 'GET')).toBe(true);
  await user.tab();
  expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toHaveFocus();
  await user.keyboard('{Enter}');
  await waitFor(() => expect(chat).toHaveBeenCalledTimes(1));
  expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
  expect(input).toBeDisabled();
  expect(screen.getByRole('status', { name: 'Состояние подключения чата' })).toHaveTextContent(
    'Ожидаем ответ',
  );
  await user.click(screen.getByRole('button', { name: 'Отменить ожидание чата' }));
  expect(screen.getByRole('alert')).toHaveTextContent('Ожидание остановлено');
  expect(chat).toHaveBeenCalledTimes(1);
});

it('uses the current question without a consent checkbox, submits once, verifies late-page citations and rereads durable completion', async () => {
  const { api, transport } = mount();
  await open();
  fireEvent.change(screen.getByLabelText('Вопрос чату'), { target: { value: 'Вопрос' } });
  fireEvent.change(screen.getByLabelText('Вопрос чату'), { target: { value: 'Новый вопрос' } });
  expect(screen.queryByRole('checkbox', { name: /Разрешаю один запрос/ })).toBeNull();
  send();
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
  await screen.findByText(/Последний ответ: входных токенов 100/);
  expect(api.requests.filter((r) => r.init.method === 'POST')).toHaveLength(1);
  const sources = screen.getByLabelText('Источники ответа');
  expect(within(sources).getByText('Источники (1)')).toBeVisible();
  expect(sources.closest('details')).toBeNull();
  expect(sources.querySelector('details')).toBeNull();
  expect(screen.getByText(/Источник текущего отчёта/)).toBeVisible();
  const row = document.getElementById(`chat-${turnId}-${source.finding.findingId}`)!;
  expect(sources.querySelectorAll(':scope > ul > li')).toHaveLength(1);
  expect(sources.contains(row)).toBe(true);
  expect(row).toBeVisible();
  if (source.finding.check !== 'secret') throw new Error('Expected secret source fixture');
  expect([...row.querySelectorAll('code')].map(code => code.textContent)).toEqual([
    source.finding.ruleId, source.finding.evidenceRef,
  ]);
  expect(row).toHaveTextContent(`Строка: ${source.finding.line}`);
  expect(screen.getByText(/Источник текущего отчёта/)).toBeVisible();
  expect(screen.getByText(/Последний ответ: входных токенов 100/)).not.toBeVisible();
  expect(row).toHaveTextContent('Источник текущего отчёта');
  expect(transport.results).toHaveBeenCalledTimes(4);
  expect(screen.queryByRole('checkbox', { name: /Разрешаю один запрос/ })).toBeNull();
  expect(api.head.turns).toHaveLength(1);
  expect(api.head.revision).toBe(2);
});
it('does not resend after an error or refreshed context; a new send builds fresh consent and mutation ID', async () => {
  const api = chatApi();
  let fail = true;
  const fetcher = vi.fn<typeof fetch>(async (input, init) => {
    if (init?.method === 'POST' && fail) {
      fail = false;
      return json({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' }, 503);
    }
    return api.fetcher(input, init);
  });
  mount(api, fetcher);
  await open();
  send('Что подтверждено отчётом?');
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).toContain('Сервис ответов недоступен');
  expect(screen.queryByRole('heading', { name: 'Ответ · проверьте по источникам' })).toBeNull();
  const postBodies = () =>
    fetcher.mock.calls
      .filter(([, init]) => init?.method === 'POST')
      .map(([, init]) => JSON.parse(String(init?.body)));
  expect(postBodies()).toHaveLength(1);
  api.policy = { ...api.policy, policyVersion: 'd'.repeat(64) };
  fireEvent.focus(window);
  fireEvent(window, new Event('online'));
  await act(async () => {});
  expect(postBodies()).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
  await open();
  expect(screen.queryByRole('alert')).toBeNull();
  expect(screen.getByLabelText('Вопрос чату')).toHaveValue('Что подтверждено отчётом?');
  expect(postBodies()).toHaveLength(1);
  const sendButton = screen.getByRole('button', { name: 'Отправить вопрос' });
  expect(sendButton.getAttribute('aria-describedby')?.split(/\s+/)).toEqual([
      'scan-chat-send-help',
      'scan-chat-input-help',
      'scan-chat-input-count',
      'scan-chat-connection',
    ]);
    for (const id of sendButton.getAttribute('aria-describedby')!.split(/\s+/)) {
      expect(document.getElementById(id)).toBeInTheDocument();
    }
  expect(screen.getByText(/Нажимая «Отправить вопрос»/).textContent).toContain('внешнему ИИ');
  expect(screen.getByText(/Нажимая «Отправить вопрос»/).textContent).toContain('отсутствие хранения');
  fireEvent.click(sendButton);
  fireEvent.click(sendButton);
  await screen.findByRole('heading', { name: 'Ответ · проверьте по источникам' });
  expect(postBodies()).toHaveLength(2);
  expect(postBodies()[1].consent).toEqual({ accepted: true, policyVersion: api.policy.policyVersion });
  expect(postBodies()[1].mutationId).not.toBe(postBodies()[0].mutationId);
  expect(screen.getByRole('heading', { name: 'Вопрос · ответ сохранён' })).toBeTruthy();
  expect(screen.getByRole('heading', { name: 'Задать вопрос по отчёту' })).toBeVisible();
});

it('keeps historical English answers verbatim under Russian UI labels without pretending to translate or generating again', async () => {
  const api = chatApi();
  const text = 'Previously saved English explanation.';
  api.head = {
    ...history,
    turns: [
      {
        id: turnId,
        mutationId: turnId,
        question: 'Сохранённый вопрос',
        state: 'completed',
        report: binding,
        createdAt: 0,
        reply: { ...reply, text },
      },
    ],
  };
  mount(api);
  await open();
  expect(screen.getByText(text).textContent).toBe(text);
  expect(screen.getByRole('heading', { name: 'Ответ · проверьте по источникам' })).toBeTruthy();
  expect(screen.getByText('Источники (1)')).toBeVisible();
  expect(screen.queryByText(/Гипотеза ·/)).toBeNull();
  expect(api.requests.every((request) => request.init.method === 'GET')).toBe(true);
});

it('reopens same-owner durable history after reauthentication, while never borrowing previous local consent', async () => {
  const { api } = mount();
  await open();
  send();
  await screen.findByText(/Последний ответ/);
  act(() => transitionScanSession('alice', new QueryClient(), true));
  expect(screen.queryByText('Что проверить?')).toBeNull();
  cleanup();
  mount(api);
  await open();
  await screen.findByText('Что проверить?');
  expect(api.requests.filter((r) => r.init.method === 'POST')).toHaveLength(1);
  expect(screen.queryByRole('checkbox', { name: /Разрешаю один запрос/ })).toBeNull();
});
it('allows provider-disabled history and an explicit user decision with current sources, CAS and zero chat calls', async () => {
  const api = chatApi();
  api.policy = { ...context, enabled: false, disclosure: null, policyVersion: null };
  mount(api);
  await open();
  fireEvent.click(screen.getByText('Подробности · история решений, условия и использование'));
  fireEvent.click(screen.getByText('Основания решения'));
  fireEvent.change(screen.getByLabelText('Текст решения'), {
    target: { value: 'Сначала проверить конфигурацию' },
  });
  fireEvent.click(screen.getByRole('checkbox', { name: /secret-0-1/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить решение' }));
  await screen.findByText('Решение пользователя · не вывод сканера');
  const posts = api.requests.filter((r) => r.init.method === 'POST');
  expect(posts).toHaveLength(1);
  expect(posts[0].path.endsWith('/history/decision')).toBe(true);
  expect(JSON.parse(String(posts[0].init.body))).toMatchObject({
    revision: 0,
    text: 'Сначала проверить конфигурацию',
    findingIds: ['secret-0-1'],
  });
  expect(api.head.decisions).toHaveLength(1);
});
for (const change of ['revision', 'epoch', 'report', 'policy', 'disabled'] as const) {
  it(`rechecks ${change} before dispatch, produces zero POST and resets consent`, async () => {
    const api = chatApi();
    mount(api);
    await open();
    if (change === 'revision') api.head = { ...api.head, revision: 1 };
    else if (change === 'epoch') api.head = { ...api.head, epoch: turnId };
    else if (change === 'report') api.policy = { ...api.policy, reportVersion: 'd'.repeat(64) };
    else if (change === 'policy') api.policy = { ...api.policy, policyVersion: 'd'.repeat(64) };
    else api.policy = { ...context, enabled: false, policyVersion: null, disclosure: null };
    send();
    await screen.findByRole('alert');
    expect(api.requests.filter((r) => r.init.method === 'POST')).toHaveLength(0);
    expect(screen.getByText(/Исходный отчёт/)).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Отправить вопрос' }) as HTMLButtonElement).disabled).toBe(
      true,
    );
  });
}
for (const code of [
  'LLM_HISTORY_CONFLICT',
  'LLM_HISTORY_CAPACITY',
  'LLM_CONTEXT_LIMIT',
  'LLM_QUOTA_EXCEEDED',
  'LLM_HISTORY_UNAVAILABLE',
  'LLM_CONFIGURATION_UNAVAILABLE',
  'LLM_PROVIDER_UNAVAILABLE',
  'LLM_UNAVAILABLE',
  'LLM_NO_EVIDENCE',
  'LLM_REPORT_UNAVAILABLE',
]) {
  it(`${code} does not retry, echo diagnostics, remove findings or optimistically confirm anything`, async () => {
    const api = chatApi();
    const fetcher: typeof fetch = vi.fn(async (input, init) =>
      init?.method === 'POST'
        ? json({ errorCode: code, message: 'PRIVATE_CANARY' }, 409)
        : api.fetcher(input, init),
    );
    mount(api, fetcher);
    await open();
    send();
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).not.toContain('PRIVATE_CANARY');
    expect(screen.getByText('Исходный отчёт · UNKNOWN coverage · findings сохранны')).toBeTruthy();
    expect(api.head.turns).toHaveLength(0);
    expect(
      (fetcher as ReturnType<typeof vi.fn>).mock.calls.filter(
        (c) => (c[1] as RequestInit)?.method === 'POST',
      ),
    ).toHaveLength(1);
  });
}
it.each([429, 503, 401])(
  'shows classified provider HTTP %s from backend frames and recovers failed history only manually',
  async (providerStatus) => {
    const api = chatApi();
    const auth = providerStatus === 401;
    const errorCode = auth ? 'LLM_PROVIDER_AUTH_FAILED' : 'LLM_PROVIDER_RATE_LIMITED';
    const fetcher = vi.fn<typeof fetch>(async (input, init) => {
      if (init?.method !== 'POST') return api.fetcher(input, init);
      const body = JSON.parse(String(init.body));
      api.head = {
        ...history,
        revision: 2,
        turns: [
          {
            id: turnId,
            mutationId: body.mutationId,
            question: body.question,
            report: binding,
            createdAt: 0,
            state: 'failed',
          },
        ],
      };
      return new Response(
        encodeDelivery({
          ...binding,
          epoch,
          revision: 2,
          mutationId: body.mutationId,
          turnId,
          outcome: 'failed',
          receipt: 'unavailable',
          failure: {
            errorCode,
            providerFailure: {
              kind: auth ? 'auth_failed' : 'rate_limited',
              status: providerStatus,
              ...(auth ? {} : { retryAfterSeconds: 0 }),
            },
          },
        }).lines.join(''),
        { headers: { 'Content-Type': 'application/x-ndjson' } },
      );
    });
    mount(api, fetcher);
    await open();
    send();
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain(auth ? 'Чат временно недоступен' : 'Сервис ответов занят');
    expect(alert.textContent).not.toMatch(/HTTP|LLM_|квот|receipt|0 с/);
    expect(screen.queryByText('Ответ · проверьте по источникам')).toBeNull();
    expect((screen.getByRole('button', { name: 'Отправить вопрос' }) as HTMLButtonElement).disabled).toBe(
      true,
    );
    vi.useFakeTimers();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(86400001);
    });
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    vi.useRealTimers();
    fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
    await screen.findByText('Вопрос · ошибка');
    expect(screen.queryByRole('checkbox', { name: /Разрешаю один запрос/ })).toBeNull();
    expect((screen.getByRole('button', { name: 'Отправить вопрос' }) as HTMLButtonElement).disabled).toBe(
      false,
    );
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    expect(screen.getByText('Исходный отчёт · UNKNOWN coverage · findings сохранны')).toBeTruthy();
  },
);

it('discard invalid current-report citation; historical sources are marked unresolved rather than current facts', async () => {
  const api = chatApi();
  api.head = {
    ...history,
    turns: [
      {
        id: turnId,
        mutationId: turnId,
        question: 'Исторический вопрос',
        state: 'completed',
        report: { ...binding, reportVersion: 'd'.repeat(64) },
        createdAt: 0,
        reply: {
          ...reply,
          reportVersion: 'd'.repeat(64),
          sources: [{ ...source, reportVersion: 'd'.repeat(64) }],
        },
      },
    ],
  };
  const onNavigateSource = vi.fn(() => true);
  const { view, transport, client } = mount(api, api.fetcher, onNavigateSource);
  await open();
  await screen.findByText('Источники (1)');
  const sources = screen.getByLabelText('Источники ответа');
  const historical = document.getElementById(`chat-${turnId}-${source.finding.findingId}`)!;
  expect(sources.closest('details')).toBeNull();
  expect(sources.contains(historical)).toBe(true);
  expect(historical).toBeVisible();
  expect(within(historical).getByText(/Исторический источник/)).toBeVisible();
  expect(historical).not.toHaveTextContent('Источник текущего отчёта, проверен по результатам сканирования.');
  expect(within(historical).queryByRole('link')).toBeNull();
  const unavailable = within(historical).getByText('Открыть раздел «Возможные секреты» · переход сейчас недоступен');
  fireEvent.click(unavailable);
  expect(onNavigateSource).not.toHaveBeenCalled();
  expect(api.requests.filter(request => request.init.method === 'POST')).toHaveLength(0);
  view.unmount();
  api.head = {
    ...history,
    turns: [
      {
        ...api.head.turns[0],
        report: binding,
        state: 'completed',
        reply: {
          ...reply,
          sources: [{ ...source, finding: { ...source.finding, findingId: 'secret-0-9' } }],
        },
      },
    ],
  };
  render(<ScanChatPanel status={status} transport={transport} client={client} onNavigateSource={onNavigateSource} />);
  await screen.findByRole('alert');
  expect(screen.queryByText('Исторический вопрос')).toBeNull();
  expect(onNavigateSource).not.toHaveBeenCalled();
});
it('cancel suppresses a late response, requires history refresh and never resends automatically', async () => {
  const api = chatApi();
  let resolve!: (value: Response) => void;
  const fetcher: typeof fetch = vi.fn((input, init) =>
    init?.method === 'POST'
      ? new Promise<Response>((r) => {
          resolve = r;
        })
      : api.fetcher(input, init),
  );
  mount(api, fetcher);
  await open();
  send();
  await waitFor(() => expect(resolve).toBeTypeOf('function'));
  fireEvent.click(screen.getByRole('button', { name: 'Отменить ожидание чата' }));
  await screen.findByText(/Ответ ещё может сохраниться/);
  resolve(
    json({
      ...binding,
      epoch: context.epoch,
      revision: 2,
      turnId,
      deliveryMode: 'completed-response',
      reply,
      usage: { input: 1, output: 1, costMicros: 0, source: 'server-validated-provider-reported-not-invoice' },
    }),
  );
  await act(async () => {});
  expect(screen.queryByText(/Последний ответ/)).toBeNull();
  expect((screen.getByRole('button', { name: 'Отправить вопрос' }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByText(/Исходный отчёт/)).toBeTruthy();
});
it('whole chat operation is bounded at 120 seconds even when an injected client ignores abort', async () => {
  const { client } = mount();
  await open();
  const chat = vi.spyOn(client, 'chat').mockImplementation(() => new Promise(() => {}));
  vi.useFakeTimers();
  send();
  await act(async () => vi.advanceTimersByTimeAsync(45_001));
  expect(screen.queryByRole('alert')).toBeNull();
  expect((screen.getByRole('button', { name: 'Отправить вопрос' }) as HTMLButtonElement).disabled).toBe(true);
  await act(async () => vi.advanceTimersByTimeAsync(74_998));
  expect(screen.queryByRole('alert')).toBeNull();
  expect(chat.mock.calls[0][3].aborted).toBe(false);
  await act(async () => vi.advanceTimersByTimeAsync(1));
  expect(chat.mock.calls[0][3].aborted).toBe(true);
  expect(chat).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('alert').textContent).toContain('Ожидание остановлено');
  expect((screen.getByRole('button', { name: 'Отправить вопрос' }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByText(/Исходный отчёт/)).toBeTruthy();
});
it('preflight and postflight reads share the same 120-second generation budget', async () => {
  const { client } = mount();
  await open();
  const read = client.context;
  const generate = client.chat;
  let reads = 0;
  let finish!: (value: ChatContext) => void;
  vi.spyOn(client, 'context').mockImplementation(async (id, signal) => {
    if (++reads > 1)
      return new Promise((resolve) => {
        finish = resolve;
      });
    await new Promise((resolve) => setTimeout(resolve, 10_000));
    return read(id, signal);
  });
  const chat = vi.spyOn(client, 'chat').mockImplementation(async (...args) => {
    await new Promise((resolve) => setTimeout(resolve, 100_000));
    return generate(...args);
  });
  vi.useFakeTimers();
  send();
  await act(async () => vi.advanceTimersByTimeAsync(110_001));
  expect(chat).toHaveBeenCalledTimes(1);
  expect(reads).toBe(2);
  expect(screen.queryByRole('alert')).toBeNull();
  await act(async () => vi.advanceTimersByTimeAsync(9_998));
  expect(chat.mock.calls[0][3].aborted).toBe(false);
  await act(async () => vi.advanceTimersByTimeAsync(1));
  expect(chat.mock.calls[0][3].aborted).toBe(true);
  expect(screen.getByRole('alert').textContent).toContain('обновите историю перед повтором');
  await act(async () => finish({ ...context, revision: 2 }));
  expect(screen.queryByText('**Проверьте** исходную находку')).toBeNull();
  expect(chat).toHaveBeenCalledTimes(1);
});

it('passive chat refresh still stops at 45 seconds', async () => {
  const { client } = mount();
  await open();
  const read = vi.spyOn(client, 'context').mockImplementation(() => new Promise(() => {}));
  vi.useFakeTimers();
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
  await act(async () => vi.advanceTimersByTimeAsync(44_999));
  expect(read.mock.calls[0][1].aborted).toBe(false);
  await act(async () => vi.advanceTimersByTimeAsync(1));
  expect(read.mock.calls[0][1].aborted).toBe(true);
  expect(screen.getByRole('alert')).toBeTruthy();
});

it('scan A→B→A, owner switch and same-owner reauth never carry draft, consent or late answer', async () => {
  const api = chatApi();
  let resolve!: (value: Response) => void;
  const fetcher: typeof fetch = vi.fn((input, init) =>
    init?.method === 'POST'
      ? new Promise<Response>((r) => {
          resolve = r;
        })
      : api.fetcher(input, init),
  );
  const { view, client, transport } = mount(api, fetcher);
  await open();
  send('Старый вопрос');
  await waitFor(() => expect(resolve).toBeTypeOf('function'));
  view.rerender(
    <ScanChatPanel status={{ ...status, scanId: turnId }} transport={transport} client={client} />,
  );
  expect((screen.getByRole('button', { name: 'Отправить вопрос' }) as HTMLButtonElement).disabled).toBe(true);
  view.rerender(<ScanChatPanel status={status} transport={transport} client={client} />);
  resolve(json(reply));
  await act(async () => {});
  expect(screen.queryByText('Старый вопрос')).toBeNull();
  await open();
  expect((screen.getByLabelText('Вопрос чату') as HTMLTextAreaElement).value).toBe('');
  act(() => transitionScanSession('bob', new QueryClient(), true));
  expect((screen.getByRole('button', { name: 'Отправить вопрос' }) as HTMLButtonElement).disabled).toBe(true);
});
it('a cancelled noncooperative snapshot cannot overwrite a newer refresh generation', async () => {
  const api = chatApi();
  const client = createChatClient(scanSession(), api.fetcher);
  let resolve!: (value: ChatContext) => void;
  const next = { ...context, epoch: turnId };
  client.context = vi
    .fn()
    .mockImplementationOnce(
      () =>
        new Promise<ChatContext>((r) => {
          resolve = r;
        }),
    )
    .mockResolvedValueOnce(next)
    .mockResolvedValueOnce(next)
    .mockResolvedValueOnce(context);
  client.history = vi.fn(async (value) => {
    const captured = value as ChatContext;
    const old: ChatHistory = {
      ...history,
      turns: [
        {
          id: turnId,
          mutationId: turnId,
          question: 'Старый снимок',
          state: 'failed',
          report: binding,
          createdAt: 0,
        },
      ],
    };
    return captured.epoch === next.epoch ? { ...history, epoch: next.epoch } : old;
  });
  render(<ScanChatPanel status={status} transport={sourceTransport()} client={client} />);
  fireEvent.click(screen.getByRole('button', { name: 'Отменить обновление истории' }));
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
  await open();
  resolve(context);
  await act(async () => {});
  expect(screen.queryByText('Старый снимок')).toBeNull();
  expect(document.body.textContent).toContain(`поколение ${next.epoch}`);
});
it('public pending state prevents overlapping chat/decision and is reread manually, never polled or resent', async () => {
  const api = chatApi();
  api.head = {
    ...history,
    revision: 1,
    pending: { turnId, state: 'pending' },
    turns: [
      {
        id: turnId,
        mutationId: turnId,
        state: 'pending',
        question: 'Чужая вкладка',
        report: binding,
        createdAt: 0,
      },
    ],
  };
  mount(api);
  await open();
  expect(screen.getByText('Чужая вкладка')).toBeTruthy();
  expect((screen.getByRole('button', { name: 'Отправить вопрос' }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByText('Подробности · история решений, условия и использование'));
  expect((screen.getByRole('button', { name: 'Сохранить решение' }) as HTMLButtonElement).disabled).toBe(
    true,
  );
  expect(api.requests.every((r) => r.init.method === 'GET')).toBe(true);
  const count = api.requests.length;
  await act(async () => {});
  expect(api.requests).toHaveLength(count);
});
it('policy change after completion withholds publication but recovers committed history on manual refresh', async () => {
  const api = chatApi();
  const fetcher: typeof fetch = vi.fn(async (input, init) => {
    const result = await api.fetcher(input, init);
    if (init?.method === 'POST') api.policy = { ...api.policy, policyVersion: 'd'.repeat(64) };
    return result;
  });
  mount(api, fetcher);
  await open();
  send();
  await screen.findByRole('alert');
  expect(api.head.turns).toHaveLength(1);
  expect(screen.queryByRole('heading', { name: 'Ответ · проверьте по источникам' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
  await screen.findByRole('heading', { name: 'Ответ · проверьте по источникам' });
  expect(screen.queryByRole('checkbox', { name: /Разрешаю один запрос/ })).toBeNull();
});

it('framed panel keeps partial nested fence inert/unpublished until done, EOF and full durable reply equality', async () => {
  const api = chatApi(),
    text = '- ```js\n  unfinished hypothesis';
  let writer!: ReadableStreamDefaultController<Uint8Array>,
    done = '';
  const fetcher: typeof fetch = vi.fn(async (input, init) => {
    const response = await api.fetcher(input, init);
    if (init?.method !== 'POST') return response;
    const frames = (await response.text())
      .trimEnd()
      .split('\n')
      .map((line) => JSON.parse(line));
    frames[2].text = text;
    frames[3].textBytes = new TextEncoder().encode(text).length;
    done = JSON.stringify(frames[3]) + '\n';
    api.head = {
      ...api.head,
      turns: api.head.turns.map((t) => (t.state === 'completed' ? { ...t, reply: { ...t.reply, text } } : t)),
    };
    return new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          writer = controller;
          controller.enqueue(
            new TextEncoder().encode(
              frames
                .slice(0, -1)
                .map((f) => JSON.stringify(f) + '\n')
                .join(''),
            ),
          );
        },
      }),
      { headers: { 'Content-Type': 'application/x-ndjson' } },
    );
  });
  const { view } = mount(api, fetcher);
  await open();
  send();
  await waitFor(() => expect(writer).toBeTruthy());
  await act(async () => {});
  expect(screen.queryByRole('heading', { name: 'Ответ · проверьте по источникам' })).toBeNull();
  expect(screen.queryByText(/Последний ответ/)).toBeNull();
  expect(view.container.querySelector('pre')).toBeNull();
  await act(async () => {
    writer.enqueue(new TextEncoder().encode(done));
  });
  expect(screen.queryByRole('heading', { name: 'Ответ · проверьте по источникам' })).toBeNull();
  await act(async () => writer.close());
  await screen.findByText(/Последний ответ: входных токенов 100/);
  expect(view.container.querySelector('pre')?.textContent).toBe(text);
  for (const markdown of view.container.querySelectorAll('.scan-chat-conversation .scan-markdown'))
      expect(markdown.querySelector('script,img,svg,iframe')).toBeNull();
  expect(api.requests.filter((r) => r.init.method === 'POST')).toHaveLength(1);
  expect(screen.getByText(/Исходный отчёт/)).toBeTruthy();
});
it.each(['reply', 'source', 'question', 'revision'])(
  'framed panel refuses mismatching durable %s after valid done without optimistic confirmation',
  async (field) => {
    const api = chatApi();
    const fetcher: typeof fetch = vi.fn(async (input, init) => {
      const response = await api.fetcher(input, init);
      if (init?.method === 'POST') {
        api.head = {
          ...api.head,
          revision: field === 'revision' ? api.head.revision + 1 : api.head.revision,
          turns: api.head.turns.map((t) =>
            t.state !== 'completed'
              ? t
              : {
                  ...t,
                  question: field === 'question' ? 'Different retained question' : t.question,
                  reply: {
                    ...t.reply,
                    text: field === 'reply' ? 'Different retained explanation' : t.reply.text,
                    sources:
                      field === 'source'
                        ? [{ ...source, finding: { ...source.finding, line: 2 } }]
                        : t.reply.sources,
                  },
                },
          ),
        };
      }
      return response;
    });
    mount(api, fetcher);
    await open();
    send();
    await screen.findByRole('alert');
    expect(screen.queryByRole('heading', { name: 'Ответ · проверьте по источникам' })).toBeNull();
    expect(screen.queryByText(/Последний ответ/)).toBeNull();
    expect(api.requests.filter((r) => r.init.method === 'POST')).toHaveLength(1);
    expect(screen.getByText(/Исходный отчёт/)).toBeTruthy();
  },
);
it.each(['cancel', 'scan', 'session', 'error'])(
  'framed panel %s after partial usage/delta hides delivery without resend or refund claims',
  async (mode) => {
    const api = chatApi();
    let writer!: ReadableStreamDefaultController<Uint8Array>;
    let errorFrame = '';
    const fetcher: typeof fetch = vi.fn(async (input, init) => {
      const response = await api.fetcher(input, init);
      if (init?.method !== 'POST') return response;
      const frames = (await response.text())
        .trimEnd()
        .split('\n')
        .map((line) => JSON.parse(line));
      const common = { ...frames[0] };
      delete common.usage;
      errorFrame =
        JSON.stringify({
          ...common,
          type: 'error',
          seq: 3,
          errorCode: 'LLM_UNAVAILABLE',
          receipt: 'accepted',
        }) + '\n';
      return new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            writer = controller;
            controller.enqueue(
              new TextEncoder().encode(
                frames
                  .slice(0, -1)
                  .map((f) => JSON.stringify(f) + '\n')
                  .join(''),
              ),
            );
          },
        }),
        { headers: { 'Content-Type': 'application/x-ndjson' } },
      );
    });
    const { view, transport, client } = mount(api, fetcher);
    await open();
    send();
    await waitFor(() => expect(writer).toBeTruthy());
    if (mode === 'cancel') fireEvent.click(screen.getByRole('button', { name: 'Отменить ожидание чата' }));
    else if (mode === 'scan') {
      view.rerender(
        <ScanChatPanel status={{ ...status, scanId: turnId }} transport={transport} client={client} />,
      );
      view.rerender(<ScanChatPanel status={status} transport={transport} client={client} />);
    } else if (mode === 'session') act(() => transitionScanSession('alice', new QueryClient(), true));
    else
      await act(async () => {
        writer.enqueue(new TextEncoder().encode(errorFrame));
        writer.close();
      });
    await act(async () => {});
    if (mode === 'scan') {
      // Returning to the report automatically recovers independently validated durable history.
      await screen.findByRole('heading', { name: 'Ответ · проверьте по источникам' });
    } else expect(screen.queryByRole('heading', { name: 'Ответ · проверьте по источникам' })).toBeNull();
    expect(screen.queryByText(/Последний ответ/)).toBeNull();
    expect(api.head.turns).toHaveLength(1);
    expect(api.head.turns[0].state).toBe('completed');
    expect(api.requests.filter((r) => r.init.method === 'POST')).toHaveLength(1);
  },
);
