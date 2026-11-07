import '@testing-library/jest-dom/vitest';
import { webcrypto } from 'node:crypto';
import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { LlmUsagePanel } from '@/features/scans/LlmUsagePanel';
import { ScanSummaryPanel } from '@/features/scans/ScanSummaryPanel';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { saveReportPreferences } from '@/shared/api/preferences/reportPreferences';
import { createUsageClient, type LlmUsage } from '@/shared/api/scans/llmUsageClient';
import type { SummaryContext } from '@/shared/api/scans/llmSummaryClient';
import { binding, json, sourceTransport, status } from './llmChatFixtures';
import {
  insufficientLifetimeUsage,
  lifetimeContext,
  lifetimeReply,
  lifetimeUsage,
} from './lifetimeBudgetFixtures';

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  localStorage.clear();
  sessionStorage.clear();
  transitionScanSession('lifetime-ui-owner', new QueryClient(), true);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function mountUsage(payload: unknown) {
  const fetcher = vi.fn<typeof fetch>(async () => json(payload));
  render(
    <LlmUsagePanel binding={binding} refreshVersion={0} client={createUsageClient(scanSession(), fetcher)} />,
  );
  return fetcher;
}
function grant(context: SummaryContext = lifetimeContext) {
  const { disclosure, policyVersion } = context;
  if (disclosure?.provider !== 'OpenAI' || !policyVersion) throw new Error('Expected paid context');
  expect(
    saveReportPreferences({
      language: 'original',
      autoSummary: true,
      openAiSummaryConsent: { version: 1, disclosure, policyVersion },
    }),
  ).toBe(true);
}
function summaryApi(payload: unknown, context: SummaryContext = lifetimeContext) {
  const calls: Array<{ path: string; method: string }> = [];
  let existing = false;
  vi.stubGlobal(
    'fetch',
    vi.fn<typeof fetch>(async (input, init) => {
      const path = String(input),
        method = init?.method ?? 'GET';
      calls.push({ path, method });
      if (path.endsWith('/context')) return json(context);
      if (path.endsWith('/usage')) return json(payload);
      if (path.endsWith('/summary'))
        return method === 'POST' || existing
          ? json(lifetimeReply)
          : json({ errorCode: 'LLM_SUMMARY_MISSING' }, 404);
      throw new Error(`Unexpected controlled route: ${path}`);
    }),
  );
  return {
    calls,
    posts: () => calls.filter((call) => call.method === 'POST'),
    recover: () => {
      existing = true;
    },
  };
}
function mountSummary() {
  return render(
    <>
      <p>Исходные находки и покрытие сканеров</p>
      <ScanSummaryPanel status={status} transport={sourceTransport()} />
    </>,
  );
}
function assertBudget(used: string, held: string, remaining: string) {
  const budget = screen.getByRole('region', { name: 'Бюджет ИИ за всё время' });
  expect(within(budget).getByRole('heading', { name: '$5 на аккаунт за всё время' })).toBeVisible();
  const rows = within(budget).getAllByRole('definition');
  expect(rows.map((row) => row.textContent)).toEqual([used, held, remaining]);
  expect(budget).toHaveTextContent('не счёт провайдера');
  expect(budget).toHaveTextContent('расход, который пока неизвестен');
  expect(budget).toHaveTextContent('не обновляется со сменой суток');
  return budget;
}

it('shows account lifetime used/held/remaining separately from non-blocking window counters, without passive generation', async () => {
  const fetcher = mountUsage(lifetimeUsage());
  expect(fetcher).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Обновить остаток ИИ' }));
  await screen.findByRole('heading', { name: '$5 на аккаунт за всё время' });
  assertBudget('$1', '$0.5', '$3.5');
  expect(
    screen.getByText(/Оконные счётчики токенов и стоимости — статистика, не блокирующие бюджеты/),
  ).toBeVisible();
  expect(screen.getByText(/Окно счётчиков UTC:/)).toBeVisible();
  expect(screen.getAllByText(/расчётный остаток счётчика 0 \(не бюджет допуска\)/)).toHaveLength(4);
  expect(screen.queryByText(/остаток не ограничен/)).not.toBeInTheDocument();
  expect(screen.queryByText(/Установленная квота исчерпана/)).not.toBeInTheDocument();
  expect(fetcher.mock.calls.every(([, init]) => init?.method === 'GET')).toBe(true);
});

it('renders micro-USD exactly at the maximum configured lifetime limit', async () => {
  const usage = lifetimeUsage();
  usage.admission = { status: 'unavailable' };
  usage.lifetimeBudget = {
    limitMicros: 1_000_000_000,
    usedMicros: 100000,
    heldMicros: 1,
    remainingMicros: 999899999,
  };
  mountUsage(usage);
  fireEvent.click(screen.getByRole('button'));
  const budget = await screen.findByRole('region', { name: 'Бюджет ИИ за всё время' });
  expect(within(budget).getByRole('heading', { name: '$1000 на аккаунт за всё время' })).toBeVisible();
  expect(
    within(budget)
      .getAllByRole('definition')
      .map((row) => row.textContent),
  ).toEqual(['$0.1', '$0.000001', '$999.899999']);
});

it('renders safe-integer lifetime overages exactly without rejecting usage above the configured limit', async () => {
  const usage = lifetimeUsage();
  usage.admission = { status: 'unavailable' };
  usage.reason = 'exhausted';
  usage.lifetimeBudget = {
    limitMicros: 1_000_000_000,
    usedMicros: Number.MAX_SAFE_INTEGER,
    heldMicros: Number.MAX_SAFE_INTEGER,
    remainingMicros: 0,
  };
  mountUsage(usage);
  fireEvent.click(screen.getByRole('button'));
  const budget = await screen.findByRole('region', { name: 'Бюджет ИИ за всё время' });
  expect(within(budget).getByRole('heading', { name: '$1000 на аккаунт за всё время' })).toBeVisible();
  expect(
    within(budget)
      .getAllByRole('definition')
      .map((row) => row.textContent),
  ).toEqual(['$9007199254.740991', '$9007199254.740991', '$0']);
});

it('renders lifetime full-reserve shortage despite null daily cost remaining, not a zero/unlimited balance', async () => {
  mountUsage(insufficientLifetimeUsage());
  fireEvent.click(screen.getByRole('button'));
  await screen.findByText('Полный резерв следующего запроса не помещается в квоту.');
  assertBudget('$4.4', '$0.59', '$0.01');
  expect(screen.getByText(/Пользователь · стоимость: требуется 30000, осталось 10000/)).toBeVisible();
  expect(screen.queryByText(/Полный резерв текущего запроса помещается/)).not.toBeInTheDocument();
});

it('does not infer lifetime budget or globally unlimited funds from an older uncapped snapshot', async () => {
  const usage = lifetimeUsage();
  delete usage.lifetimeBudget;
  usage.admission = { status: 'unavailable' };
  mountUsage(usage);
  fireEvent.click(screen.getByRole('button'));
  await screen.findByText(/Счётчики доступны; ёмкость следующего полного запроса неизвестна/);
  expect(screen.queryByRole('region', { name: 'Бюджет ИИ за всё время' })).not.toBeInTheDocument();
  expect(
    screen.getAllByText(
      /Без денежного лимита запроса и суток.*отдельный бюджет аккаунта может ограничивать расход/,
    ),
  ).toHaveLength(2);
  expect(screen.queryByText(/остаток не ограничен/)).not.toBeInTheDocument();
});

it('clears lifetime balances while refreshing and on failure, showing unknown rather than zero', async () => {
  let finish!: (response: Response) => void;
  const fetcher = vi
    .fn<typeof fetch>()
    .mockResolvedValueOnce(json(lifetimeUsage()))
    .mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
  render(
    <LlmUsagePanel binding={binding} refreshVersion={0} client={createUsageClient(scanSession(), fetcher)} />,
  );
  fireEvent.click(screen.getByRole('button'));
  await screen.findByRole('region', { name: 'Бюджет ИИ за всё время' });
  fireEvent.click(screen.getByRole('button'));
  expect(screen.getByText('Читаем счётчики…')).toBeVisible();
  expect(screen.queryByRole('region', { name: 'Бюджет ИИ за всё время' })).not.toBeInTheDocument();
  await act(async () => finish(json({ ...lifetimeUsage(), lifetimeBudget: {} })));
  expect(await screen.findByText(/Счётчики временно недоступны; остаток неизвестен/)).toBeVisible();
  expect(screen.queryByText('$0')).not.toBeInTheDocument();
});

it('does not publish a late lifetime snapshot after owner-session transition', async () => {
  let finish!: (response: Response) => void;
  const fetcher = vi.fn<typeof fetch>(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  render(
    <LlmUsagePanel binding={binding} refreshVersion={0} client={createUsageClient(scanSession(), fetcher)} />,
  );
  fireEvent.click(screen.getByRole('button'));
  act(() => transitionScanSession('other-lifetime-owner', new QueryClient(), true));
  await act(async () => finish(json(lifetimeUsage())));
  expect(screen.queryByRole('region', { name: 'Бюджет ИИ за всё время' })).not.toBeInTheDocument();
});

it('summary admits a lifetime fits snapshot even when retained daily token counters are exhausted', async () => {
  grant();
  const api = summaryApi(lifetimeUsage());
  mountSummary();
  expect(await screen.findByText('ИИ-разбор готов')).toBeVisible();
  expect(api.posts()).toHaveLength(1);
  assertBudget('$1', '$0.5', '$3.5');
  expect(screen.getByText(/показан снимок перед отправкой/)).toBeVisible();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it.each(['shortage', 'exhausted', 'policy_fault'] as const)(
  'summary blocks %s using server lifetime admission/reason rather than daily flags',
  async (mode) => {
    grant();
    const usage = mode === 'shortage' ? insufficientLifetimeUsage() : lifetimeUsage();
    usage.user.exhausted = false;
    usage.scan.exhausted = false;
    if (mode !== 'shortage') {
      usage.reason = mode;
      usage.admission = { status: 'unavailable' };
      if (mode === 'exhausted')
        usage.lifetimeBudget = {
          limitMicros: 5000000,
          usedMicros: 4400000,
          heldMicros: 600000,
          remainingMicros: 0,
        };
    } else usage.reason = 'ready';
    const api = summaryApi(usage);
    mountSummary();
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Локальная квота ИИ не допускает новый разбор',
    );
    expect(api.posts()).toHaveLength(0);
    expect(api.calls.filter((call) => call.path.endsWith('/context'))).toHaveLength(3);
    assertBudget(
      mode === 'policy_fault' ? '$1' : '$4.4',
      mode === 'shortage' ? '$0.59' : mode === 'exhausted' ? '$0.6' : '$0.5',
      mode === 'shortage' ? '$0.01' : mode === 'exhausted' ? '$0' : '$3.5',
    );
    expect(screen.getByText(/Предыдущие запросы уже могли быть обработаны или учтены/)).toBeVisible();
    expect(
      screen
        .getAllByText(/Оконные счётчики токенов — статистика, не блокирующие бюджеты/)
        .find((element) => !element.closest('details')),
    ).toBeVisible();
    expect(screen.getByText('Исходные находки и покрытие сканеров')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Повторить разбор' })).not.toBeInTheDocument();
    fireEvent.focus(window);
    fireEvent(window, new Event('online'));
    await act(async () => {});
    expect(api.posts()).toHaveLength(0);
  },
);

it.each(['malformed', 'unavailable', 'forged-fit', 'fake-zero'] as const)(
  'summary fails closed for %s lifetime usage without inventing a zero balance',
  async (mode) => {
    grant();
    const payload =
      mode === 'malformed'
        ? { ...lifetimeUsage(), lifetimeBudget: {} }
        : mode === 'forged-fit'
          ? { ...insufficientLifetimeUsage(), admission: lifetimeUsage().admission }
          : mode === 'fake-zero'
            ? {
                ...lifetimeUsage(),
                lifetimeBudget: {
                  limitMicros: 5000000,
                  usedMicros: 0,
                  heldMicros: 0,
                  remainingMicros: 5000000,
                },
              }
            : {
                ...binding,
                available: false,
                integrationEnabled: true,
                quotaEnabled: true,
                reason: 'unavailable',
              };
    const api = summaryApi(payload);
    mountSummary();
    expect(await screen.findByRole('alert')).toHaveTextContent('остаток неизвестен');
    expect(api.posts()).toHaveLength(0);
    expect(screen.queryByRole('region', { name: 'Бюджет ИИ за всё время' })).not.toBeInTheDocument();
    expect(screen.queryByText('$0')).not.toBeInTheDocument();
  },
);

it('a quota-blocked summary can still recover the saved result without POST or another budget claim', async () => {
  grant();
  const api = summaryApi(insufficientLifetimeUsage());
  mountSummary();
  await screen.findByRole('alert');
  api.recover();
  fireEvent.click(screen.getByRole('button', { name: 'Проверить квоту и сохранённый разбор' }));
  expect(await screen.findByText('ИИ-разбор готов')).toBeVisible();
  expect(api.posts()).toHaveLength(0);
  expect(api.calls.filter((call) => call.path.endsWith('/usage'))).toHaveLength(1);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it.each(['mismatch', 'missing-usage', 'unexpected-usage'] as const)(
  'summary refuses a lifetime disclosure/usage %s before POST',
  async (mode) => {
    const context = structuredClone(lifetimeContext);
    if (context.disclosure?.provider !== 'OpenAI' || context.disclosure.monetaryLimit !== 'uncapped')
      throw new Error('Expected uncapped paid context');
    const usage = lifetimeUsage();
    if (mode === 'mismatch')
      usage.lifetimeBudget = {
        limitMicros: 6000000,
        usedMicros: 1000000,
        heldMicros: 500000,
        remainingMicros: 4500000,
      };
    if (mode === 'missing-usage') {
      delete usage.lifetimeBudget;
      usage.admission = { status: 'unavailable' };
    }
    if (mode === 'unexpected-usage') delete context.disclosure.lifetimeUserCostMicros;
    grant(context);
    const api = summaryApi(usage, context);
    mountSummary();
    expect(await screen.findByRole('alert')).toHaveTextContent('остаток неизвестен');
    expect(api.posts()).toHaveLength(0);
    expect(screen.queryByRole('region', { name: 'Бюджет ИИ за всё время' })).not.toBeInTheDocument();
  },
);

it('keeps daily token blocking for legacy uncapped snapshots without lifetime metadata', async () => {
  const legacyContext = structuredClone(lifetimeContext);
  if (
    legacyContext.disclosure?.provider !== 'OpenAI' ||
    legacyContext.disclosure.monetaryLimit !== 'uncapped'
  )
    throw new Error('Expected uncapped paid context');
  delete legacyContext.disclosure.lifetimeUserCostMicros;
  grant(legacyContext);
  const usage: LlmUsage = lifetimeUsage();
  if (!usage.available) throw new Error('Expected available usage');
  delete usage.lifetimeBudget;
  usage.admission = { status: 'unavailable' };
  const api = summaryApi(usage, legacyContext);
  mountSummary();
  await screen.findByRole('alert');
  await waitFor(() => expect(api.posts()).toHaveLength(0));
  expect(screen.queryByRole('region', { name: 'Бюджет ИИ за всё время' })).not.toBeInTheDocument();
  expect(screen.getByText(/Технические лимиты токенов остаются отдельными/)).toBeVisible();
});
