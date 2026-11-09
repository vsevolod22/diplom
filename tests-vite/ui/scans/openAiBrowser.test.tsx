import '@testing-library/jest-dom/vitest';
import './mockChatEditor';
import { webcrypto } from 'node:crypto';
import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanSummaryPanel } from '@/features/scans/ScanSummaryPanel';
import { ScanChatPanel } from '@/features/scans/ScanChatPanel';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import {
  REPORT_AUTOMATION_REVISION,
  readReportPreferences,
  saveReportPreferences,
} from '@/shared/api/preferences/reportPreferences';
import { allowSummaryAutomation, reportPreferencesCurrent } from '@/shared/api/scans/reportAutomation';
import {
  createSummaryClient,
  summaryContextSchema,
  type SummaryContext,
} from '@/shared/api/scans/llmSummaryClient';
import { createChatClient } from '@/shared/api/scans/llmChatClient';
import {
  chatContextSchema,
  chatResultSchema,
  chatReceiptMatchesProvider,
  type ChatContext,
} from '@/shared/api/scans/llmChatContract';
import {
  OPENAI_COST_BASIS,
  OPENAI_MODEL,
  openAiDisclosureSchema,
  type OpenAiDisclosure,
} from '@/shared/api/scans/llmPublicContract';
import {
  binding,
  context as freeChat,
  epoch,
  frameLines,
  history,
  json,
  ndjson,
  receipt,
  reply,
  sourceTransport,
  status,
  turnId,
  usage,
} from './llmChatFixtures';

// Pure producer projection only: no controller, stores, environment, credentials or provider transport.
const { openAiDisclosure } = await import(
  /* @vite-ignore */ '../../../server/api/src/llm/' + 'provider-browser-contract.ts'
);
const data =
  'Sanitized scanner findings, package names, installed and reported fixed versions, and coverage; no raw evidence or credentials.' as const;
const commonDisclosure = {
  provider: 'OpenAI',
  model: OPENAI_MODEL,
  retention: 'no-training',
  operatorApprovedRouting: true,
  providerComplianceNotProvenByDeclaration: true,
  zeroDataRetentionVerified: false,
  costBasis: OPENAI_COST_BASIS,
  estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 750000, output: 4500000 },
  data,
} as const;
function disclosure(mode: 'capped' | 'uncapped'): OpenAiDisclosure {
  return mode === 'capped'
    ? {
        ...commonDisclosure,
        monetaryLimit: mode,
        requestBudgetMicros: 10000,
        userBudgetMicros: 100000,
        scanBudgetMicros: 50000,
      }
    : {
        ...commonDisclosure,
        monetaryLimit: mode,
        requestBudgetMicros: null,
        userBudgetMicros: null,
        scanBudgetMicros: null,
      };
}
function summaryContext(mode: 'capped' | 'uncapped'): SummaryContext {
  return {
    ...binding,
    enabled: true,
    policyVersion: 'c'.repeat(64),
    summaryResultRead: true,
    disclosure: disclosure(mode),
  };
}
function chatContext(mode: 'capped' | 'uncapped'): ChatContext {
  if (freeChat.disclosure?.provider !== 'OpenRouter') throw new Error('Expected free chat fixture');
  return {
    ...freeChat,
    disclosure: {
      ...disclosure(mode),
      sentData: freeChat.disclosure.sentData,
      localRetention: freeChat.disclosure.localRetention,
    },
  };
}
function paidUsage(mode: 'capped' | 'uncapped') {
  const scope = (limit: number) => ({
    ...usage.user,
    limits: { ...usage.user.limits, costMicros: mode === 'uncapped' ? null : limit },
    remaining: { ...usage.user.remaining, costMicros: mode === 'uncapped' ? null : limit },
  });
  return {
    ...usage,
    integrationEnabled: true,
    quotaEnabled: true,
    monetaryLimit: mode,
    user: scope(100000),
    scan: scope(50000),
  };
}
const summaryReply = {
  ...binding,
  hypotheses: [{ kind: 'hypothesis', text: 'Проверьте исходную находку', citations: ['secret-0-1'] }],
  scannerFacts: [{ findingId: 'secret-0-1', check: 'secret', severity: 'UNKNOWN' }],
};
function summaryApi(
  initial: SummaryContext,
  cached = false,
  post: () => Response | Promise<Response> = () => json(summaryReply),
  summaryAdmission: 'fits' | 'unavailable' = 'fits',
) {
  let current = initial;
  const calls: Array<{ path: string; method: string }> = [];
  const fetcher = vi.fn<typeof fetch>(async (input, init) => {
    const path = String(input),
      method = init?.method ?? 'GET';
    calls.push({ path, method });
    if (path.endsWith('/context')) return json(current);
    if (path.endsWith('/usage')) {
      if (current.disclosure?.provider !== 'OpenAI') throw new Error('Expected paid usage');
      return json({
        ...paidUsage(current.disclosure.monetaryLimit),
        admission:
          summaryAdmission === 'fits'
            ? { status: 'fits', reserve: { input: 4096, output: 4096, costMicros: 1000 }, signals: [] }
            : { status: 'unavailable' },
      });
    }
    if (path.endsWith('/summary'))
      return method === 'GET'
        ? cached
          ? json(summaryReply)
          : json({ errorCode: 'LLM_SUMMARY_MISSING' }, 404)
        : post();
    throw new Error(`Unexpected controlled route: ${path}`);
  });
  vi.stubGlobal('fetch', fetcher);
  return {
    calls,
    fetcher,
    setContext(value: SummaryContext) {
      current = value;
    },
    posts: () => calls.filter((c) => c.method === 'POST'),
  };
}
function mountSummary() {
  return render(<ScanSummaryPanel status={status} transport={sourceTransport()} />);
}
function grant(value: SummaryContext) {
  if (value.disclosure?.provider !== 'OpenAI' || !value.policyVersion)
    throw new Error('Expected paid context');
  expect(
    saveReportPreferences({
      language: 'original',
      autoSummary: true,
      openAiSummaryConsent: { version: 1, policyVersion: value.policyVersion, disclosure: value.disclosure },
    }),
  ).toBe(true);
}

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  localStorage.clear();
  sessionStorage.clear();
  transitionScanSession('openai-browser-owner', new QueryClient(), true);
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it.each(['save', 'parsed-storage'] as const)(
  'nested paid grant mutation from %s cannot authorize changed policy/uncapped UI dispatch',
  async (origin) => {
    const old = summaryContext('capped');
    if (old.disclosure?.provider !== 'OpenAI' || !old.policyVersion) throw new Error('Expected paid context');
    if (origin === 'save') grant(old);
    else
      localStorage.setItem(
        'report-preferences:v1:openai-browser-owner',
        JSON.stringify({
          version: 1,
          automationRevision: REPORT_AUTOMATION_REVISION,
          language: 'original',
          autoSummary: true,
          openAiSummaryConsent: { version: 1, policyVersion: old.policyVersion, disclosure: old.disclosure },
        }),
      );
    const accepted = readReportPreferences();
    const nested = accepted.openAiSummaryConsent;
    if (!nested) throw new Error('Expected saved paid grant');
    const persisted = localStorage.getItem('report-preferences:v1:openai-browser-owner');
    const target: SummaryContext = {
      ...old,
      policyVersion: 'd'.repeat(64),
      disclosure: disclosure('uncapped'),
    };
    // Replacing both nested fields forged valid exact consent before the deep-freeze fix.
    const writes = [
      Reflect.set(nested, 'policyVersion', target.policyVersion),
      Reflect.set(nested, 'disclosure', target.disclosure),
    ];
    expect(readReportPreferences()).toBe(accepted);
    expect(reportPreferencesCurrent(accepted, 'summary')).toBe(true);
    expect(allowSummaryAutomation(accepted, target)).toBe(false);
    const api = summaryApi(target);
    mountSummary();
    expect(await screen.findByRole('alert')).toHaveTextContent('требуется новое согласие');
    fireEvent.focus(window);
    fireEvent(window, new Event('online'));
    await act(async () => {});
    expect(api.posts()).toHaveLength(0);
    expect(accepted.openAiSummaryConsent).toEqual({
      version: 1,
      policyVersion: old.policyVersion,
      disclosure: old.disclosure,
    });
    expect(localStorage.getItem('report-preferences:v1:openai-browser-owner')).toBe(persisted);
    expect(writes).toEqual([false, false]);
  },
);

it.each(['capped', 'uncapped'] as const)(
  'actual backend projection is exact and browser-decodable for %s',
  (mode) => {
    const policy = {
      model: OPENAI_MODEL,
      retention: 'no-training',
      inputPriceMicrosPerMillion: 750000,
      outputPriceMicrosPerMillion: 4500000,
      monetaryLimit: mode,
      requestBudgetMicros: mode === 'uncapped' ? null : 10000,
    };
    const quota = {
      monetaryLimit: mode,
      user: { costMicros: mode === 'uncapped' ? null : 100000 },
      scan: { costMicros: mode === 'uncapped' ? null : 50000 },
    };
    const wire = openAiDisclosure(policy, quota, true);
    expect(wire).toEqual(disclosure(mode));
    expect(openAiDisclosureSchema.parse(wire)).toEqual(wire);
    expect(summaryContextSchema.parse({ ...summaryContext(mode), disclosure: wire }).disclosure).toEqual(
      wire,
    );
    expect(chatContextSchema.parse(chatContext(mode)).disclosure).toEqual(chatContext(mode).disclosure);
  },
);

it.each(['capped', 'uncapped'] as const)(
  'unknown paid %s summary admission never dispatches despite an exact saved grant',
  async (mode) => {
    const context = summaryContext(mode);
    grant(context);
    const api = summaryApi(context, false, () => json(summaryReply), 'unavailable');
    mountSummary();
    expect(await screen.findByRole('alert')).toHaveTextContent('Генерация остановлена; остаток неизвестен');
    fireEvent.focus(window);
    fireEvent(window, new Event('online'));
    await act(async () => {});
    expect(api.posts()).toHaveLength(0);
    expect(readReportPreferences().openAiSummaryConsent?.policyVersion).toBe(context.policyVersion);
  },
);

it.each(['capped', 'uncapped'] as const)(
  'old free opt-in never sends paid %s POST; explicit visible action saves exact grant',
  async (mode) => {
    saveReportPreferences({ language: 'original', autoSummary: true });
    const value = summaryContext(mode),
      api = summaryApi(value);
    mountSummary();
    const enable = await screen.findByRole('button', { name: 'Включить платный авторазбор OpenAI' });
    expect(await screen.findByRole('alert')).toHaveTextContent('Прежний opt-in не применяется');
    expect(api.posts()).toHaveLength(0);
    expect(screen.getByText(/Платный ИИ:/)).toBeVisible();
    expect(screen.getByText(/Стоимость рассчитывается сервером/)).toBeVisible();
    expect(screen.getByText(/ZDR не подтверждён/)).toBeVisible();
    if (mode === 'uncapped')
      expect(screen.getByText(/без локального денежного лимита — это не бесплатный режим/)).toBeVisible();
    else expect(screen.getByText(/с серверными денежными лимитами/)).toBeVisible();
    fireEvent.click(screen.getByText('Стоимость и ограничения', { selector: 'summary' }));
    expect(screen.getByText(/За миллион токенов:/)).toHaveTextContent(
      'вход — 750000 микро-USD, выход — 4500000 микро-USD',
    );
    if (mode === 'capped')
      expect(screen.getByText(/Денежные лимиты, микро-USD:/)).toHaveTextContent(
        'запрос — 10000; пользователь — 100000; скан — 50000',
      );
    else expect(screen.getByText(/Локальный предел расходов не установлен/)).toBeVisible();
    fireEvent.click(enable);
    await screen.findByText('Проверьте исходную находку');
    expect(api.posts()).toHaveLength(1);
    expect(readReportPreferences().openAiSummaryConsent).toEqual({
      version: 1,
      policyVersion: value.policyVersion,
      disclosure: value.disclosure,
    });
    const request = api.fetcher.mock.calls.find(([, init]) => init?.method === 'POST');
    expect(JSON.parse(String(request?.[1]?.body))).toEqual({
      reportVersion: binding.reportVersion,
      consent: { accepted: true, policyVersion: value.policyVersion },
    });
  },
);

it.each(['policy', 'price', 'money-mode'] as const)(
  'a saved paid grant is invalidated by changed %s, with zero POST',
  async (change) => {
    const old = summaryContext('capped');
    grant(old);
    if (old.disclosure?.provider !== 'OpenAI') throw new Error('Expected paid disclosure');
    const current: SummaryContext =
      change === 'policy'
        ? { ...old, policyVersion: 'd'.repeat(64) }
        : change === 'money-mode'
          ? { ...old, disclosure: disclosure('uncapped') }
          : {
              ...old,
              disclosure: {
                ...old.disclosure,
                estimatedPrice: { ...old.disclosure.estimatedPrice, input: 900000 },
              },
            };
    const api = summaryApi(current);
    mountSummary();
    expect(await screen.findByRole('alert')).toHaveTextContent('требуется новое согласие');
    fireEvent.focus(window);
    fireEvent(window, new Event('online'));
    await act(async () => {});
    expect(api.posts()).toHaveLength(0);
    expect(readReportPreferences().openAiSummaryConsent?.policyVersion).toBe(old.policyVersion);
  },
);

it.each(['capped', 'uncapped'] as const)(
  'owner %s summary restores on remount/new session via GET without paid consent or POST',
  async (mode) => {
    const api = summaryApi(summaryContext(mode), true);
    const first = mountSummary();
    await screen.findByText('Проверьте исходную находку');
    first.unmount();
    transitionScanSession('openai-browser-owner', new QueryClient(), true);
    mountSummary();
    await screen.findByText('Проверьте исходную находку');
    expect(api.calls.filter((c) => c.path.endsWith('/summary') && c.method === 'GET')).toHaveLength(2);
    expect(api.posts()).toHaveLength(0);
    expect(readReportPreferences().openAiSummaryConsent).toBeUndefined();
    expect(api.calls.some((c) => c.path.includes('translation'))).toBe(false);
  },
);

it.each([
  { monetaryLimit: undefined },
  { monetaryLimit: 'unlimited' },
  { monetaryLimit: 'uncapped' },
  { requestBudgetMicros: null },
  { requestBudgetMicros: 0 },
  { userBudgetMicros: -1 },
  { monetaryLimit: 'uncapped', requestBudgetMicros: 1, userBudgetMicros: null, scanBudgetMicros: null },
  { monetaryLimit: 'uncapped', requestBudgetMicros: null, userBudgetMicros: 1, scanBudgetMicros: null },
  { monetaryLimit: 'uncapped', requestBudgetMicros: null, userBudgetMicros: null, scanBudgetMicros: 1 },
  { estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 0, output: 2 } },
  { zeroDataRetentionVerified: true },
  { model: 'gpt-other' },
  { costBasis: 'invoice' },
  { freeOnly: true },
  { providers: ['openai'] },
  { estimatedPrice: { unit: 'USD', input: 1, output: 2 } },
  { estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 1, output: 2, hiddenFee: 1 } },
])('malformed paid disclosure fails decoding and UI never grants/sends: %j', async (patch) => {
  const raw = { ...summaryContext('capped'), disclosure: { ...disclosure('capped'), ...patch } };
  expect(summaryContextSchema.safeParse(raw).success).toBe(false);
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json(raw));
  vi.stubGlobal('fetch', fetcher);
  await expect(
    createSummaryClient(scanSession(), fetcher).context(binding.scanId, new AbortController().signal),
  ).rejects.toMatchObject({ name: 'ZodError' });
  mountSummary();
  expect(await screen.findByRole('alert')).toHaveTextContent('Отчёт сканеров доступен');
  expect(screen.queryByRole('button', { name: 'Включить платный авторазбор OpenAI' })).toBeNull();
  expect(fetcher.mock.calls.every(([, init]) => init?.method === 'GET')).toBe(true);
});

const paidReceipt = { input: 100, output: 10, costMicros: 120, source: OPENAI_COST_BASIS };
it.each(['ndjson', 'json'] as const)(
  'paid/free provider receipt must match context in %s, with no retry',
  async (format) => {
    for (const paid of [true, false]) {
      const context = paid ? chatContext('uncapped') : freeChat;
      for (const match of [true, false]) {
        const mutationId = crypto.randomUUID();
        const selected = paid === match ? paidReceipt : receipt;
        const response = () =>
          format === 'ndjson'
            ? ndjson(
                frameLines(mutationId).map((frame) =>
                  frame.type === 'usage' ? { ...frame, usage: selected } : frame,
                ),
              )
            : json({
                ...binding,
                epoch,
                revision: 2,
                turnId,
                deliveryMode: 'completed-response',
                reply,
                usage: selected,
              });
        const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => response());
        const promise = createChatClient(scanSession(), fetcher).chat(
          context,
          'Что проверить?',
          mutationId,
          new AbortController().signal,
        );
        if (format === 'json') {
          const decoded = chatResultSchema.parse(await response().json());
          if ('duplicate' in decoded) throw new Error('Expected completed result');
          expect(chatReceiptMatchesProvider(decoded.usage, context)).toBe(match);
          // The browser explicitly negotiates NDJSON and rejects JSON success, even a valid receipt.
          await expect(promise).rejects.toMatchObject({ code: 'INVALID' });
        } else if (match) await expect(promise).resolves.toMatchObject({ usage: selected });
        else await expect(promise).rejects.toMatchObject({ code: 'INVALID' });
        expect(fetcher).toHaveBeenCalledTimes(1);
      }
    }
  },
);

it.each(['LLM_PROVIDER_UNAVAILABLE', 'LLM_PROVIDER_TIMEOUT'] as const)(
  'paid uncapped summary displays Russian %s and does not retry',
  async (errorCode) => {
    const context = summaryContext('uncapped');
    grant(context);
    const api = summaryApi(context, false, () => json({ errorCode }, 502));
    mountSummary();
    expect(await screen.findByRole('alert')).toHaveTextContent(
      errorCode === 'LLM_PROVIDER_TIMEOUT'
        ? 'Не дождались ответа ИИ. Можно повторить разбор вручную.'
        : 'Не удалось получить разбор ИИ. Отчёт сканеров доступен; можно повторить вручную.',
    );
    expect(screen.getByText(/без локального денежного лимита — это не бесплатный режим/)).toBeVisible();
    fireEvent.focus(window);
    fireEvent(window, new Event('online'));
    await act(async () => {});
    expect(api.posts()).toHaveLength(1);
  },
);

it('paid summary ignored-abort generation times out visibly without automatic resend', async () => {
  const context = summaryContext('uncapped');
  grant(context);
  const api = summaryApi(context, false, () => new Promise<Response>(() => {}));
  vi.useFakeTimers();
  mountSummary();
  await act(async () => {
    await vi.waitFor(() => expect(api.posts()).toHaveLength(1));
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(120001);
  });
  expect(screen.getByRole('alert')).toHaveTextContent(
    'Не дождались ответа ИИ. Можно повторить разбор вручную.',
  );
  expect(screen.getByText(/без локального денежного лимита — это не бесплатный режим/)).toBeVisible();
  expect(api.posts()).toHaveLength(1);
});

it.each(['ndjson', 'json', 'timeout'] as const)(
  'paid uncapped chat shows separate Russian consent and fails closed for %s',
  async (format) => {
    const context = chatContext('uncapped');
    const calls: string[] = [];
    const ready = {
      ...binding,
      status: 'locally-configured',
      localReady: true,
      blockers: [],
      credential: 'environment-valid',
      quota: 'available',
      history: 'available',
      accounting: 'configured',
      provider: { name: 'OpenAI', model: OPENAI_MODEL, status: 'configured-unprobed', liveVerified: false },
      generationVerified: false,
      requiresConsent: true,
      acceptsCredentials: false,
      setupAction: 'operator-server-environment-configuration',
    };
    const fetcher = vi.fn<typeof fetch>(async (input, init) => {
      const path = String(input);
      calls.push(init?.method ?? 'GET');
      if (path.endsWith('/chat/context')) return json(context);
      if (path.endsWith('/readiness')) return json(ready);
      if (path.endsWith('/chat/usage')) return json(paidUsage('uncapped'));
      if (path.endsWith('/history')) return json(history);
      if (path.endsWith('/chat') && format === 'timeout') return new Promise<Response>(() => {});
      if (path.endsWith('/chat'))
        return format === 'json'
          ? json({
              ...binding,
              epoch,
              revision: 2,
              turnId,
              deliveryMode: 'completed-response',
              reply,
              usage: receipt,
            })
          : ndjson(frameLines(JSON.parse(String(init?.body)).mutationId));
      throw new Error(`Unexpected controlled route: ${path}`);
    });
    render(
      <ScanChatPanel
        status={status}
        transport={sourceTransport()}
        client={createChatClient(scanSession(), fetcher)}
      />,
    );
    await waitFor(() => expect(screen.getByRole('button', { name: 'Обновить историю' })).toBeEnabled());
    const notice = document.querySelector('.scan-chat-paid-notice');
    expect(notice).toBeVisible();
    expect(notice).toHaveTextContent('платный запрос OpenAI');
    expect(screen.getByText(/Это отдельное согласие, не прежний бесплатный opt-in/)).not.toBeVisible();
    fireEvent.click(screen.getByText('Об использовании ИИ', { selector: 'summary' }));
    expect(screen.getAllByText(/без локального денежного лимита — это не бесплатный режим/)[0]).toBeVisible();
    expect(screen.getByText(/Это отдельное согласие, не прежний бесплатный opt-in/)).toBeVisible();
    expect(calls.filter((m) => m === 'POST')).toHaveLength(0);
    fireEvent.change(screen.getByLabelText('Вопрос чату'), { target: { value: 'Что проверить?' } });
    expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeEnabled();
    if (format === 'timeout') vi.useFakeTimers();
    fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
    if (format === 'timeout') {
      await act(async () => {
        await vi.waitFor(() => expect(calls.filter((m) => m === 'POST')).toHaveLength(1));
      });
      await act(async () => {
        await vi.advanceTimersByTimeAsync(120001);
      });
      expect(screen.getByRole('alert')).toHaveTextContent(
        'Ожидание остановлено. Ответ ещё может сохраниться — обновите историю перед повтором.',
      );
    } else expect(await screen.findByRole('alert')).toHaveTextContent(/Ответ|ответ|провер/);
    expect(screen.queryByText('**Проверьте** исходную находку')).toBeNull();
    expect(calls.filter((m) => m === 'POST')).toHaveLength(1);
  },
);
