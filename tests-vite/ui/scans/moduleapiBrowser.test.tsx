import '@testing-library/jest-dom/vitest';
import { webcrypto } from 'node:crypto';
import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanSummaryPanel } from '@/features/scans/ScanSummaryPanel';
import { ScanChatPanel } from '@/features/scans/ScanChatPanel';
import { OpenAiDisclosure } from '@/features/scans/OpenAiDisclosure';
import { LlmUsagePanel } from '@/features/scans/LlmUsagePanel';
import { ReportPreferencesPanel } from '@/features/auth/ReportPreferencesPanel';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { readReportPreferences, saveReportPreferences } from '@/shared/api/preferences/reportPreferences';
import { createChatClient } from '@/shared/api/scans/llmChatClient';
import { chatContextSchema, chatReadinessSchema } from '@/shared/api/scans/llmChatContract';
import { summaryContextSchema, type SummaryContext } from '@/shared/api/scans/llmSummaryClient';
import {
  MODULEAPI_COST_BASIS,
  MODULEAPI_MODEL,
  OPENAI_COST_BASIS,
  moduleApiDisclosureSchema,
} from '@/shared/api/scans/llmPublicContract';
import { usageSchema } from '@/shared/api/scans/llmUsageClient';
import { moduleApiReadinessWire } from './moduleapiReadinessFixture';
import {
  binding,
  context as freeChat,
  epoch,
  frameLines,
  history,
  json,
  ndjson,
  reply,
  sourceTransport,
  status,
  turnId,
} from './llmChatFixtures';
import {
  insufficientLifetimeUsage,
  lifetimeContext,
  lifetimeReply,
  lifetimeUsage,
} from './lifetimeBudgetFixtures';

const owner = 'moduleapi-ui-owner';
const disclosure = moduleApiDisclosureSchema.options[1].parse({
  provider: 'ModuleAPI',
  model: MODULEAPI_MODEL,
  retention: 'unknown',
  operatorApprovedRouting: true,
  providerComplianceNotProvenByDeclaration: true,
  zeroDataRetentionVerified: false,
  tariffVerified: false,
  costBasis: MODULEAPI_COST_BASIS,
  // Synthetic rates for UI tests only, not a provider tariff assertion.
  estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 900000, output: 5000000 },
  data: 'Sanitized scanner findings, package names, installed and reported fixed versions, and coverage; no raw evidence or credentials.',
  monetaryLimit: 'uncapped',
  lifetimeUserCostMicros: 5000000,
  requestBudgetMicros: null,
  userBudgetMicros: null,
  scanBudgetMicros: null,
});
const summaryContext = summaryContextSchema.parse({
  ...binding,
  enabled: true,
  policyVersion: 'c'.repeat(64),
  summaryResultRead: true,
  disclosure,
});
const chatContext = chatContextSchema.parse({
  ...freeChat,
  disclosure: {
    ...disclosure,
    sentData: freeChat.disclosure!.sentData,
    localRetention: freeChat.disclosure!.localRetention,
  },
});
const ready = chatReadinessSchema.parse({ ...binding, ...moduleApiReadinessWire() });
const moduleReceipt = { input: 100, output: 10, costMicros: 140, source: MODULEAPI_COST_BASIS };
function grant(value = summaryContext) {
  if (value.disclosure?.provider !== 'ModuleAPI' || !value.policyVersion)
    throw new Error('Expected ModuleAPI fixture');
  expect(
    saveReportPreferences({
      language: 'original',
      autoSummary: true,
      moduleApiSummaryConsent: {
        version: 1,
        policyVersion: value.policyVersion,
        disclosure: value.disclosure,
      },
    }),
  ).toBe(true);
}
function summaryApi(
  options: {
    cached?: boolean;
    failure?: boolean;
    usage?: unknown;
    drift?: SummaryContext;
    deferred?: Promise<Response>;
  } = {},
) {
  let cached = options.cached ?? false;
  let contexts = 0;
  const fetcher = vi.fn<typeof fetch>(async (input, init) => {
    const path = String(input);
    if (path.endsWith('/context'))
      return json(++contexts > 1 && options.drift ? options.drift : summaryContext);
    if (path.endsWith('/usage')) return json(options.usage ?? lifetimeUsage());
    if (path.endsWith('/summary') && init?.method === 'GET')
      return cached ? json(lifetimeReply) : json({ errorCode: 'LLM_SUMMARY_MISSING' }, 404);
    if (path.endsWith('/summary') && init?.method === 'POST') {
      if (options.deferred) return options.deferred;
      if (options.failure) return json({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' }, 502);
      cached = true;
      return json(lifetimeReply);
    }
    throw new Error('Unexpected synthetic summary route');
  });
  vi.stubGlobal('fetch', fetcher);
  return { fetcher, posts: () => fetcher.mock.calls.filter(([, init]) => init?.method === 'POST') };
}
const mountSummary = () => render(<ScanSummaryPanel status={status} transport={sourceTransport()} />);
function chatApi(
  options: { receiptSource?: string; ready?: unknown; drift?: boolean; failure?: boolean } = {},
) {
  let head = structuredClone(history);
  let contexts = 0;
  const fetcher = vi.fn<typeof fetch>(async (input, init) => {
    const path = String(input);
    if (path.endsWith('/chat/context')) {
      contexts++;
      return json({
        ...chatContext,
        epoch: head.epoch,
        revision: head.revision,
        ...(options.drift && contexts > 2 ? { policyVersion: 'd'.repeat(64) } : {}),
      });
    }
    if (path.endsWith('/readiness')) return json(options.ready ?? ready);
    if (path.endsWith('/chat/usage')) return json(lifetimeUsage());
    if (path.endsWith('/history')) return json(head);
    if (path.endsWith('/chat') && init?.method === 'POST') {
      if (options.failure) return json({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' }, 502);
      const body = JSON.parse(String(init.body));
      head = {
        ...head,
        revision: head.revision + 2,
        turns: [
          {
            id: turnId,
            mutationId: body.mutationId,
            state: 'completed',
            question: body.question,
            report: binding,
            createdAt: 0,
            reply,
          },
        ],
      };
      return ndjson(
        frameLines(body.mutationId, reply.text, head.revision).map((frame) =>
          frame.type === 'usage'
            ? { ...frame, usage: { ...moduleReceipt, source: options.receiptSource ?? MODULEAPI_COST_BASIS } }
            : frame,
        ),
      );
    }
    throw new Error('Unexpected synthetic chat route');
  });
  const mount = () =>
    render(
      <ScanChatPanel
        status={status}
        transport={sourceTransport()}
        client={createChatClient(scanSession(), fetcher)}
      />,
    );
  return { fetcher, mount, posts: () => fetcher.mock.calls.filter(([, init]) => init?.method === 'POST') };
}
async function openChat(api: ReturnType<typeof chatApi>) {
  api.mount();
  await waitFor(() => expect(screen.getByRole('button', { name: 'Обновить историю' })).toBeEnabled());
}
const enterQuestion = () =>
  fireEvent.change(screen.getByLabelText('Вопрос чату'), { target: { value: 'Что проверить?' } });

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  localStorage.clear();
  sessionStorage.clear();
  transitionScanSession(owner, new QueryClient(), true);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it('truthful ModuleAPI disclosure never labels recipient OpenAI or promises no training, storage, model or tariff verification', () => {
  render(<OpenAiDisclosure disclosure={disclosure} chat />);
  const conditions = screen.getByLabelText('Условия ModuleAPI');
  expect(conditions).toHaveTextContent('ModuleAPI · gpt-5.4-mini');
  expect(conditions).toHaveTextContent('Стороннему провайдеру ModuleAPI');
  expect(conditions).toHaveTextContent('Условия хранения и использования данных для обучения неизвестны');
  expect(conditions).toHaveTextContent('Тариф аккаунта и группы ModuleAPI не проверен');
  expect(conditions).toHaveTextContent('не гарантия эквивалентности прямому OpenAI');
  expect(conditions).toHaveTextContent('$5 на аккаунт за всё время');
  expect(conditions).toHaveTextContent('включая неопределённый расход');
  expect(conditions).toHaveTextContent('это оценка, не счёт провайдера');
  expect(screen.queryByLabelText('Условия OpenAI')).toBeNull();
  expect(conditions).not.toHaveTextContent('Запрет обучения (no-training) не гарантирует');
});

it.each(['none', 'free', 'OpenAI'] as const)(
  'mount/focus/reload with %s consent never posts ModuleAPI',
  async (kind) => {
    if (kind === 'free')
      expect(saveReportPreferences({ language: 'original', autoSummary: true })).toBe(true);
    if (kind === 'OpenAI') {
      if (lifetimeContext.disclosure?.provider !== 'OpenAI' || !lifetimeContext.policyVersion)
        throw new Error('Expected historical OpenAI fixture');
      expect(
        saveReportPreferences({
          language: 'original',
          autoSummary: true,
          openAiSummaryConsent: {
            version: 1,
            policyVersion: lifetimeContext.policyVersion,
            disclosure: lifetimeContext.disclosure,
          },
        }),
      ).toBe(true);
    }
    const api = summaryApi();
    const first = mountSummary();
    await screen.findByRole('button', { name: 'Включить платный авторазбор ModuleAPI' });
    fireEvent.focus(window);
    fireEvent(window, new Event('online'));
    first.unmount();
    mountSummary();
    await screen.findByRole('button', { name: 'Включить платный авторазбор ModuleAPI' });
    expect(api.posts()).toHaveLength(0);
    expect(readReportPreferences().moduleApiSummaryConsent).toBeUndefined();
  },
);

it('explicit fresh grant sends once with original wire and durable GET reload never regenerates', async () => {
  const api = summaryApi();
  const first = mountSummary();
  const enable = await screen.findByRole('button', { name: 'Включить платный авторазбор ModuleAPI' });
  await screen.findByText(/Сохранённого ИИ-разбора пока нет/);
  expect(api.posts()).toHaveLength(0);
  expect(
    api.fetcher.mock.calls.some(
      ([path, init]) => String(path).endsWith('/summary') && init?.method === 'GET',
    ),
  ).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Проверить сохранённый разбор' }));
  await waitFor(() => expect(enable).toBeEnabled());
  expect(api.posts()).toHaveLength(0);
  fireEvent.click(enable);
  await screen.findByText('Проверьте исходную находку');
  expect(api.posts()).toHaveLength(1);
  expect(JSON.parse(String(api.posts()[0][1]?.body))).toEqual({
    reportVersion: binding.reportVersion,
    consent: { accepted: true, policyVersion: summaryContext.policyVersion },
  });
  expect(readReportPreferences().moduleApiSummaryConsent).toEqual({
    version: 1,
    policyVersion: summaryContext.policyVersion,
    disclosure,
  });
  expect(readReportPreferences().openAiSummaryConsent).toBeUndefined();
  first.unmount();
  transitionScanSession(owner, new QueryClient(), true);
  mountSummary();
  await screen.findByText('Проверьте исходную находку');
  expect(api.posts()).toHaveLength(1);
  expect(
    api.fetcher.mock.calls.filter(
      ([path, init]) => String(path).endsWith('/summary') && init?.method === 'GET',
    ).length,
  ).toBeGreaterThanOrEqual(3);
  expect(api.fetcher.mock.calls.some(([path]) => String(path).includes('translation'))).toBe(false);
});

it('saved report recovery is GET-only even with no ModuleAPI consent', async () => {
  const api = summaryApi({ cached: true });
  mountSummary();
  await screen.findByText('Проверьте исходную находку');
  expect(api.posts()).toHaveLength(0);
  expect(readReportPreferences().moduleApiSummaryConsent).toBeUndefined();
});

it('failed authorized summary does not automatically retry on focus, reconnect or remount', async () => {
  grant();
  const api = summaryApi({ failure: true });
  const first = mountSummary();
  await screen.findByRole('alert');
  expect(api.posts()).toHaveLength(1);
  fireEvent.focus(window);
  fireEvent(window, new Event('online'));
  first.unmount();
  mountSummary();
  await screen.findByRole('alert');
  expect(api.posts()).toHaveLength(1);
});

it.each(['policy', 'report', 'rates', 'lifetime'] as const)(
  'changed %s after grant fences summary before POST',
  async (change) => {
    grant();
    const next: SummaryContext =
      change === 'policy'
        ? { ...summaryContext, policyVersion: 'd'.repeat(64) }
        : change === 'report'
          ? { ...summaryContext, reportVersion: 'd'.repeat(64) }
          : {
              ...summaryContext,
              disclosure:
                change === 'lifetime'
                  ? { ...disclosure, lifetimeUserCostMicros: 6000000 }
                  : { ...disclosure, estimatedPrice: { ...disclosure.estimatedPrice, input: 1 } },
            };
    const api = summaryApi({ drift: next });
    mountSummary();
    await screen.findByRole('alert');
    expect(api.posts()).toHaveLength(0);
  },
);

it('UNKNOWN holds/$5 admission remain visible and block a new summary without resetting history', async () => {
  grant();
  const api = summaryApi({ usage: insufficientLifetimeUsage() });
  mountSummary();
  await screen.findByRole('alert');
  const budget = screen.getByRole('region', { name: 'Бюджет ИИ за всё время' });
  expect(budget).toHaveTextContent('$5 на аккаунт за всё время');
  expect(budget).toHaveTextContent('$0.59');
  expect(budget).toHaveTextContent('$0.01');
  expect(budget).toHaveTextContent('неопределённые обязательства сохраняются');
  expect(api.posts()).toHaveLength(0);
});

it('owner/session change during ignored-abort summary suppresses stale publication without resending', async () => {
  grant();
  let resolve!: (value: Response) => void;
  const api = summaryApi({
    deferred: new Promise<Response>((done) => {
      resolve = done;
    }),
  });
  mountSummary();
  await waitFor(() => expect(api.posts()).toHaveLength(1));
  act(() => transitionScanSession('other-moduleapi-ui-owner', new QueryClient(), true));
  await act(async () => resolve(json(lifetimeReply)));
  await screen.findByRole('button', { name: 'Включить платный авторазбор ModuleAPI' });
  expect(screen.queryByText('Проверьте исходную находку')).toBeNull();
  expect(api.posts()).toHaveLength(1);
});

it('preferences preserve only the existing ModuleAPI grant, revoke it on off and cannot recreate it from a generic on', () => {
  grant();
  render(<ReportPreferencesPanel subject={owner} />);
  expect(screen.getByLabelText('Условия ModuleAPI')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить настройки отчётов' }));
  expect(readReportPreferences().moduleApiSummaryConsent).toBeDefined();
  fireEvent.change(screen.getByLabelText('ИИ-разбор'), { target: { value: 'off' } });
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить настройки отчётов' }));
  expect(readReportPreferences().moduleApiSummaryConsent).toBeUndefined();
  fireEvent.change(screen.getByLabelText('ИИ-разбор'), { target: { value: 'on' } });
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить настройки отчётов' }));
  expect(readReportPreferences().moduleApiSummaryConsent).toBeUndefined();
});

it('usage GET has provider-neutral paid wording and all-time held liabilities, with no generation', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json(lifetimeUsage()));
  vi.stubGlobal('fetch', fetcher);
  render(<LlmUsagePanel binding={binding} refreshVersion={0} />);
  expect(fetcher).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Обновить остаток ИИ' }));
  await screen.findByRole('region', { name: 'Бюджет ИИ за всё время' });
  expect(screen.getByText(/Платный ИИ: стоимость оценена/)).toBeVisible();
  expect(screen.queryByText(/Платный OpenAI/)).toBeNull();
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(fetcher.mock.calls[0][1]?.method).toBe('GET');
  expect(usageSchema.safeParse(lifetimeUsage()).success).toBe(true);
});

it('chat typing/GET never sends; explicit Send uses ModuleAPI receipt then durable history reload without another POST', async () => {
  const api = chatApi();
  await openChat(api);
  expect(screen.getByLabelText('Условия ModuleAPI')).toBeVisible();
  expect(screen.queryByLabelText('Условия OpenAI')).toBeNull();
  enterQuestion();
  expect(api.posts()).toHaveLength(0);
  expect(screen.getByText(/платный запрос ModuleAPI/)).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
  await screen.findByRole('heading', { name: 'Ответ · проверьте по источникам' });
  expect(api.posts()).toHaveLength(1);
  expect(screen.getByText(/Оценка сервера по настроенным ставкам, не счёт провайдера/)).toBeInTheDocument();
  expect(screen.queryByText(/Проверенное сервером сообщение провайдера, не счёт/)).toBeNull();
  expect(JSON.parse(String(api.posts()[0][1]?.body))).toMatchObject({
    epoch,
    revision: 0,
    reportVersion: binding.reportVersion,
    question: 'Что проверить?',
    consent: { accepted: true, policyVersion: chatContext.policyVersion },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Обновить историю' })).toBeEnabled());
  expect(api.posts()).toHaveLength(1);
  expect(readReportPreferences().moduleApiSummaryConsent).toBeUndefined();
});

it.each([OPENAI_COST_BASIS, 'server-validated-provider-reported-not-invoice'])(
  'chat rejects substituted receipt %s without retry',
  async (receiptSource) => {
    const api = chatApi({ receiptSource });
    await openChat(api);
    enterQuestion();
    fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
    await screen.findByRole('alert');
    expect(api.posts()).toHaveLength(1);
    expect(screen.queryByRole('heading', { name: 'Ответ · проверьте по источникам' })).toBeNull();
    fireEvent.focus(window);
    await act(async () => {});
    expect(api.posts()).toHaveLength(1);
  },
);

it('ready OpenAI identity cannot authorize ModuleAPI chat and no automatic readiness fallback occurs', async () => {
  const wrong = {
    ...ready,
    provider: {
      name: 'OpenAI',
      model: 'gpt-5.4-mini-2026-03-17',
      status: 'configured-unprobed',
      liveVerified: false,
    },
  };
  const api = chatApi({ ready: wrong });
  await openChat(api);
  enterQuestion();
  expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
  expect(api.posts()).toHaveLength(0);
});

it('policy changed after displayed chat consent is fenced before POST', async () => {
  const api = chatApi({ drift: true });
  await openChat(api);
  enterQuestion();
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
  await screen.findByRole('alert');
  expect(api.posts()).toHaveLength(0);
});

it('failed explicit ModuleAPI chat does not retry on reload/focus/history GET', async () => {
  const api = chatApi({ failure: true });
  await openChat(api);
  enterQuestion();
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
  await screen.findByRole('alert');
  fireEvent.focus(window);
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Обновить историю' })).toBeEnabled());
  expect(api.posts()).toHaveLength(1);
  expect(within(screen.getByLabelText('Условия ModuleAPI')).getByText(/Условия хранения/)).toBeVisible();
});
