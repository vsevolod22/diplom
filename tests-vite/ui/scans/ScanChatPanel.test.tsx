import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanChatPanel } from '@/features/scans/ScanChatPanel';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { readReportPreferences, saveReportPreferences } from '@/shared/api/preferences/reportPreferences';
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
function mount(api = chatApi(), fetcher: typeof fetch = api.fetcher) {
  const transport = sourceTransport();
  const client = createChatClient(scanSession(), fetcher);
  return {
    api,
    client,
    transport,
    view: render(
      <>
        <p>Исходный отчёт · UNKNOWN coverage · findings сохранны</p>
        <ScanChatPanel status={status} transport={transport} client={client} />
      </>,
    ),
  };
}
async function open() {
  await waitFor(() =>
    expect(
      (screen.getByRole('button', { name: 'Обновить историю и условия чата' }) as HTMLButtonElement).disabled,
    ).toBe(false),
  );
}
function send(question = 'Что проверить?') {
  fireEvent.change(screen.getByLabelText('Вопрос чату'), { target: { value: question } });
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
}
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
        automationRevision: 'report-automation-v1',
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
  expect(document.body.textContent).toContain('Провайдер возвращает полный ответ, а не поток токенов');
  expect(document.body.textContent).toContain('совпадения с сохранённой историей');
  expect(document.body.textContent).toContain('apodex/apodex-1.1-mini:free');
  expect(document.body.textContent).toContain('novita/bf16');
  expect(document.body.textContent).toContain('остаток входных токенов 9850, выходных токенов 9940');
  expect(document.body.textContent).toContain('Допуск запроса неизвестен');
  expect(document.body.textContent).toContain('без автоматического срока удаления');
  expect(screen.queryByRole('checkbox', { name: /Разрешаю один запрос/ })).toBeNull();
  expect((screen.getByRole('button', { name: 'Отправить вопрос' }) as HTMLButtonElement).disabled).toBe(true);
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
  expect(document.body.textContent).toContain('secret-0-1');
  const link = screen.getByRole('link', { name: 'Находка secret-0-1' });
  expect(document.getElementById(link.getAttribute('href')!.slice(1))?.textContent).toContain(
    'Источник текущего отчёта',
  );
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
  expect(alert.textContent).toContain('Провайдер недоступен');
  expect(screen.queryByRole('heading', { name: 'Ответ ИИ · требует проверки' })).toBeNull();
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
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю и условия чата' }));
  await open();
  expect(screen.getByRole('alert')).toBe(alert);
  expect(postBodies()).toHaveLength(1);
  const sendButton = screen.getByRole('button', { name: 'Отправить вопрос' });
  expect(sendButton.getAttribute('aria-describedby')).toBe('scan-chat-send-help');
  expect(screen.getByText(/Нажимая «Отправить вопрос»/).textContent).toContain('OpenRouter');
  expect(screen.getByText(/Нажимая «Отправить вопрос»/).textContent).toContain('Только бесплатный');
  fireEvent.click(sendButton);
  fireEvent.click(sendButton);
  await screen.findByRole('heading', { name: 'Ответ ИИ · требует проверки' });
  expect(postBodies()).toHaveLength(2);
  expect(postBodies()[1].consent).toEqual({ accepted: true, policyVersion: api.policy.policyVersion });
  expect(postBodies()[1].mutationId).not.toBe(postBodies()[0].mutationId);
  expect(screen.getByRole('heading', { name: 'Вопрос · ответ сохранён' })).toBeTruthy();
  expect(screen.getByText(/Находки и покрытие — результаты сканирования/)).toBeTruthy();
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
  expect(screen.getByRole('heading', { name: 'Ответ ИИ · требует проверки' })).toBeTruthy();
  expect(screen.getByText(/Основания ответа\/решения:/)).toBeTruthy();
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
    expect(alert.textContent).toContain(auth ? 'Провайдер отклонил серверный ключ' : 'Провайдер занят');
    expect(alert.textContent).toContain(`HTTP ${providerStatus}`);
    expect(alert.textContent).toContain('возврат квоты не гарантирован');
    if (!auth) expect(alert.textContent).toContain('0 с');
    expect(screen.queryByText('Ответ ИИ · требует проверки')).toBeNull();
    expect((screen.getByRole('button', { name: 'Отправить вопрос' }) as HTMLButtonElement).disabled).toBe(
      true,
    );
    vi.useFakeTimers();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(86400001);
    });
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    vi.useRealTimers();
    fireEvent.click(screen.getByRole('button', { name: 'Обновить историю и условия чата' }));
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
  const { view, transport, client } = mount(api);
  await open();
  await screen.findByText(/Исторический источник/);
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
  render(<ScanChatPanel status={status} transport={transport} client={client} />);
  await screen.findByRole('alert');
  expect(screen.queryByText('Исторический вопрос')).toBeNull();
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
  await screen.findByText(/Передача уже могла начаться/);
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
it('timeout is bounded and does not imply a refund or deletion of possibly committed history', async () => {
  const api = chatApi();
  const fetcher: typeof fetch = vi.fn((input, init) =>
    init?.method === 'POST' ? new Promise<Response>(() => {}) : api.fetcher(input, init),
  );
  mount(api, fetcher);
  await open();
  vi.useFakeTimers();
  send();
  await act(async () => {
    await vi.advanceTimersByTimeAsync(45001);
  });
  expect(screen.getByRole('alert').textContent).toContain('автоматического повтора и возврата квоты нет');
  expect((screen.getByRole('button', { name: 'Отправить вопрос' }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByText(/Исходный отчёт/)).toBeTruthy();
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
  fireEvent.click(screen.getByRole('button', { name: 'Отменить ожидание чата' }));
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю и условия чата' }));
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
  expect(screen.queryByRole('heading', { name: 'Ответ ИИ · требует проверки' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю и условия чата' }));
  await screen.findByRole('heading', { name: 'Ответ ИИ · требует проверки' });
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
  expect(screen.queryByRole('heading', { name: 'Ответ ИИ · требует проверки' })).toBeNull();
  expect(screen.queryByText(/Последний ответ/)).toBeNull();
  expect(view.container.querySelector('pre')).toBeNull();
  await act(async () => {
    writer.enqueue(new TextEncoder().encode(done));
  });
  expect(screen.queryByRole('heading', { name: 'Ответ ИИ · требует проверки' })).toBeNull();
  await act(async () => writer.close());
  await screen.findByText(/Последний ответ: входных токенов 100/);
  expect(view.container.querySelector('pre')?.textContent).toBe(text);
  expect(view.container.querySelector('script,img,svg,iframe')).toBeNull();
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
    expect(screen.queryByRole('heading', { name: 'Ответ ИИ · требует проверки' })).toBeNull();
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
      await screen.findByRole('heading', { name: 'Ответ ИИ · требует проверки' });
    } else expect(screen.queryByRole('heading', { name: 'Ответ ИИ · требует проверки' })).toBeNull();
    expect(screen.queryByText(/Последний ответ/)).toBeNull();
    expect(api.head.turns).toHaveLength(1);
    expect(api.head.turns[0].state).toBe('completed');
    expect(api.requests.filter((r) => r.init.method === 'POST')).toHaveLength(1);
  },
);
