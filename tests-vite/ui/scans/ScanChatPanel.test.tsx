import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanChatPanel } from '@/features/scans/ScanChatPanel';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { createChatClient } from '@/shared/api/scans/llmChatClient';
import type { ChatContext, ChatHistory } from '@/shared/api/scans/llmChatContract';
import {
  binding,
  chatApi,
  context,
  history,
  json,
  reply,
  source,
  sourceTransport,
  status,
  turnId,
} from './llmChatFixtures';

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
  fireEvent.click(screen.getByRole('button', { name: 'Открыть чат и прочитать условия' }));
  await screen.findByLabelText('Вопрос чату');
}
function send(question = 'Что проверить?') {
  fireEvent.change(screen.getByLabelText('Вопрос чату'), { target: { value: question } });
  fireEvent.click(screen.getByRole('checkbox', { name: /Разрешаю один запрос чата/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
}
it('is manual-only, exposes separate exact disclosure/retention/current report/usage, never dispatches on mount or focus', async () => {
  const { api } = mount();
  fireEvent.focus(window);
  expect(api.requests).toHaveLength(0);
  await open();
  expect(api.requests.every((r) => r.init.method === 'GET')).toBe(true);
  expect(document.body.textContent).toContain('stream:false');
  expect(document.body.textContent).toContain('NDJSON-кадрами');
  expect(document.body.textContent).toContain('apodex/apodex-1.1-mini:free');
  expect(document.body.textContent).toContain('novita/bf16');
  expect(document.body.textContent).toContain('остаток input 9850, output 9940');
  expect(document.body.textContent).toContain('Допуск запроса неизвестен');
  expect(document.body.textContent).toContain('без автоматического срока удаления');
  expect((screen.getByRole('checkbox', { name: /Разрешаю один запрос/ }) as HTMLInputElement).checked).toBe(
    false,
  );
  expect((screen.getByRole('button', { name: 'Отправить вопрос' }) as HTMLButtonElement).disabled).toBe(true);
});
it('resets consent on question change, submits once, verifies late-page citations and rereads durable completion', async () => {
  const { api, transport } = mount();
  await open();
  fireEvent.change(screen.getByLabelText('Вопрос чату'), { target: { value: 'Вопрос' } });
  fireEvent.click(screen.getByRole('checkbox', { name: /Разрешаю один запрос/ }));
  fireEvent.change(screen.getByLabelText('Вопрос чату'), { target: { value: 'Новый вопрос' } });
  expect((screen.getByRole('checkbox', { name: /Разрешаю один запрос/ }) as HTMLInputElement).checked).toBe(
    false,
  );
  send();
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
  await screen.findByText(/Последний ответ: input 100/);
  expect(api.requests.filter((r) => r.init.method === 'POST')).toHaveLength(1);
  expect(document.body.textContent).toContain('secret-0-1');
  const link = screen.getByRole('link', { name: 'Находка secret-0-1' });
  expect(document.getElementById(link.getAttribute('href')!.slice(1))?.textContent).toContain(
    'Источник текущего отчёта',
  );
  expect(transport.results).toHaveBeenCalledTimes(4);
  expect((screen.getByRole('checkbox', { name: /Разрешаю один запрос/ }) as HTMLInputElement).checked).toBe(
    false,
  );
  expect(api.head.turns).toHaveLength(1);
  expect(api.head.revision).toBe(2);
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
  expect((screen.getByRole('checkbox', { name: /Разрешаю один запрос/ }) as HTMLInputElement).checked).toBe(
    false,
  );
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
    expect(screen.queryByLabelText('Вопрос чату')).toBeNull();
  });
}
for (const code of [
  'LLM_HISTORY_CONFLICT',
  'LLM_HISTORY_CAPACITY',
  'LLM_CONTEXT_LIMIT',
  'LLM_QUOTA_EXCEEDED',
  'LLM_HISTORY_UNAVAILABLE',
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
    expect(screen.getByText(/Исходный отчёт/)).toBeTruthy();
    expect(api.head.turns).toHaveLength(0);
    expect(
      (fetcher as ReturnType<typeof vi.fn>).mock.calls.filter(
        (c) => (c[1] as RequestInit)?.method === 'POST',
      ),
    ).toHaveLength(1);
  });
}
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
  fireEvent.click(screen.getByRole('button', { name: 'Открыть чат и прочитать условия' }));
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
  expect(screen.queryByLabelText('Вопрос чату')).toBeNull();
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
  expect(screen.queryByLabelText('Вопрос чату')).toBeNull();
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
  expect(screen.queryByLabelText('Вопрос чату')).toBeNull();
  view.rerender(<ScanChatPanel status={status} transport={transport} client={client} />);
  resolve(json(reply));
  await act(async () => {});
  expect(screen.queryByText('Старый вопрос')).toBeNull();
  await open();
  expect((screen.getByLabelText('Вопрос чату') as HTMLTextAreaElement).value).toBe('');
  act(() => transitionScanSession('bob', new QueryClient(), true));
  expect(screen.queryByLabelText('Вопрос чату')).toBeNull();
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
  fireEvent.click(screen.getByRole('button', { name: 'Открыть чат и прочитать условия' }));
  fireEvent.click(screen.getByRole('button', { name: 'Отменить ожидание чата' }));
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю и условия чата' }));
  await screen.findByLabelText('Вопрос чату');
  resolve(context);
  await act(async () => {});
  expect(screen.queryByText('Старый снимок')).toBeNull();
  expect(document.body.textContent).toContain(`epoch ${next.epoch}`);
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
  expect((screen.getByRole('checkbox', { name: /Разрешаю один запрос/ }) as HTMLInputElement).disabled).toBe(
    true,
  );
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
  expect(screen.queryByText('Что проверить?')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю и условия чата' }));
  await screen.findByRole('heading', { name: 'Гипотеза · не доказанный факт' });
  expect((screen.getByRole('checkbox', { name: /Разрешаю один запрос/ }) as HTMLInputElement).checked).toBe(
    false,
  );
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
  expect(screen.queryByRole('heading', { name: 'Гипотеза · не доказанный факт' })).toBeNull();
  expect(screen.queryByText(/Последний ответ/)).toBeNull();
  expect(view.container.querySelector('pre')).toBeNull();
  await act(async () => {
    writer.enqueue(new TextEncoder().encode(done));
  });
  expect(screen.queryByRole('heading', { name: 'Гипотеза · не доказанный факт' })).toBeNull();
  await act(async () => writer.close());
  await screen.findByText(/Последний ответ: input 100/);
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
    expect(screen.queryByRole('heading', { name: 'Гипотеза · не доказанный факт' })).toBeNull();
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
    expect(screen.queryByRole('heading', { name: 'Гипотеза · не доказанный факт' })).toBeNull();
    expect(screen.queryByText(/Последний ответ/)).toBeNull();
    expect(api.head.turns).toHaveLength(1);
    expect(api.head.turns[0].state).toBe('completed');
    expect(api.requests.filter((r) => r.init.method === 'POST')).toHaveLength(1);
  },
);
