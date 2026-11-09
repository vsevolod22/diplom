import '@testing-library/jest-dom/vitest';
import './mockChatEditor';
import { webcrypto } from 'node:crypto';
import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanChatPanel } from '@/features/scans/ScanChatPanel';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { ChatError, createChatClient } from '@/shared/api/scans/llmChatClient';
import { OPENAI_COST_BASIS, OPENAI_MODEL } from '@/shared/api/scans/llmPublicContract';
import { PUBLIC_IMAGE_PROFILE } from '@/shared/api/scans/publicImageProfile';
import type { ScanStatus } from '@/shared/api/scans/scanTransport';
import {
  binding,
  chatApi,
  context,
  history,
  source,
  sourceTransport,
  status,
  turnId,
} from './llmChatFixtures';
import { publicChatApi, unknownPublicMetadata } from './publicLlmFixtures';

const savedQuestion = 'Сохранённый вопрос о проверке образа';
const decisionDraft = 'Сначала проверить исходную находку';
const sourceName = 'rule-0000000000000000 · Секреты · secret-0-1';
const paidDisclosure = {
  provider: 'OpenAI',
  model: OPENAI_MODEL,
  retention: 'no-training',
  operatorApprovedRouting: true,
  providerComplianceNotProvenByDeclaration: true,
  zeroDataRetentionVerified: false,
  costBasis: OPENAI_COST_BASIS,
  estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 750000, output: 4500000 },
  data: 'Sanitized scanner findings, package names, installed and reported fixed versions, and coverage; no raw evidence or credentials.',
  monetaryLimit: 'capped',
  requestBudgetMicros: 10000,
  userBudgetMicros: 100000,
  scanBudgetMicros: 50000,
  sentData: context.disclosure!.sentData,
  localRetention: context.disclosure!.localRetention,
} as const;

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  localStorage.clear();
  sessionStorage.clear();
  transitionScanSession('chat-draft-owner', new QueryClient(), true);
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function paidHistory(profile: 'public' | 'legacy') {
  const api = profile === 'public' ? publicChatApi(unknownPublicMetadata) : chatApi();
  api.policy = { ...api.policy, disclosure: paidDisclosure };
  api.head = {
    ...history,
    revision: 2,
    turns: [
      {
        id: turnId,
        mutationId: crypto.randomUUID(),
        state: 'failed',
        question: savedQuestion,
        report: binding,
        createdAt: 0,
      },
    ],
  };
  const client = createChatClient(scanSession(), api.fetcher);
  const value: ScanStatus =
    profile === 'public' ? { ...status, profile: PUBLIC_IMAGE_PROFILE, checks: [], perCheck: {} } : status;
  return {
    api,
    client,
    mount: () => render(<ScanChatPanel status={value} transport={sourceTransport()} client={client} />),
  };
}
async function settled() {
  await waitFor(() => expect(screen.getByRole('button', { name: 'Обновить историю' })).toBeEnabled());
}
function question() {
  fireEvent.change(screen.getByLabelText('Вопрос чату'), { target: { value: 'Как проверить исправление?' } });
}
function details() {
  const toggle = screen.getByText('Подробности · история решений, условия и использование', {
    selector: 'summary',
  });
  if (!toggle.closest('details')!.open) fireEvent.click(toggle);
}
function selectedSource() {
  return screen.getByRole('checkbox', { name: sourceName });
}
async function draftPanel() {
  const api = chatApi();
  const client = createChatClient(scanSession(), api.fetcher);
  const transport = sourceTransport();
  const view = render(<ScanChatPanel status={status} transport={transport} client={client} />);
  await settled();
  details();
  fireEvent.click(screen.getByText('Основания решения', { selector: 'summary' }));
  fireEvent.change(screen.getByLabelText('Текст решения'), { target: { value: decisionDraft } });
  fireEvent.click(selectedSource());
  expect(selectedSource()).toBeChecked();
  return { api, client, transport, view };
}
const posts = (api: ReturnType<typeof chatApi>) =>
  api.requests.filter((request) => request.init.method === 'POST');

it.each(['public', 'legacy'] as const)(
  '%s OpenAI readiness TIMEOUT still publishes authoritative saved history, never paid-send permission',
  async (profile) => {
    const { api, client, mount } = paidHistory(profile);
    const read = vi.spyOn(client, 'history');
    const readiness = vi.spyOn(client, 'readiness').mockRejectedValue(new ChatError('TIMEOUT'));
    mount();
    await settled();
    expect(readiness).toHaveBeenCalledTimes(1);
    expect(read).toHaveBeenCalledTimes(1);
    expect(screen.getByText(savedQuestion)).toBeVisible();
    expect(screen.getByRole('heading', { name: 'Вопрос · ошибка' })).toBeVisible();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.getByRole('status', { name: 'Состояние подключения чата' })).toHaveTextContent(
      'Не удалось проверить готовность чата',
    );
    question();
    expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
    fireEvent.submit(screen.getByRole('form', { name: 'Отправка вопроса по отчёту' }));
    expect(posts(api)).toHaveLength(0);
    details();
    expect(screen.getByText(/Готовность генерации неизвестна/)).toBeVisible();
    expect(screen.getByLabelText('Текст решения')).toBeEnabled();
  },
);

it.each([false, true])(
  'successful same-scope refresh preserves decision draft and selected finding through save: revision advanced=%s',
  async (advanced) => {
    const { api } = await draftPanel();
    if (advanced) api.head = { ...api.head, revision: api.head.revision + 1 };
    fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
    expect(screen.getByRole('button', { name: 'Сохранить решение' })).toBeDisabled();
    await settled();
    expect(screen.getByLabelText('Текст решения')).toHaveValue(decisionDraft);
    expect(selectedSource()).toBeChecked();
    expect(posts(api)).toHaveLength(0);
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить решение' }));
    await settled();
    expect(api.head.decisions).toHaveLength(1);
    expect(api.head.decisions[0]).toMatchObject({ text: decisionDraft, sources: [source] });
    expect(JSON.parse(String(posts(api)[0].init.body))).toMatchObject({
      findingIds: [source.finding.findingId],
    });
    expect(screen.getByLabelText('Текст решения')).toHaveValue('');
    expect(selectedSource()).not.toBeChecked();
  },
);

it('unrelated successful chat preserves the decision draft and selected finding', async () => {
  const { api } = await draftPanel();
  question();
  fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
  await settled();
  expect(api.head.turns).toHaveLength(1);
  expect(screen.getByRole('heading', { name: 'Ответ · проверьте по источникам' })).toBeVisible();
  expect(screen.getByLabelText('Вопрос чату')).toHaveValue('');
  expect(screen.getByLabelText('Текст решения')).toHaveValue(decisionDraft);
  expect(selectedSource()).toBeChecked();
  expect(posts(api)).toHaveLength(1);
  expect(posts(api)[0].path).toMatch(/\/chat$/);
});

it.each(['public', 'legacy'] as const)(
  '%s readiness cancellation, session/access denial and stale binding stay fail-closed',
  async (profile) => {
    for (const code of ['ABORTED', 'SESSION', 'ACCESS', 'REPORT_UNAVAILABLE', 'STALE']) {
      const { api, client, mount } = paidHistory(profile);
      vi.spyOn(client, 'readiness').mockRejectedValue(new ChatError(code));
      const view = mount();
      await settled();
      expect(screen.getByRole('alert')).toBeVisible();
      expect(screen.queryByText(savedQuestion)).not.toBeInTheDocument();
      expect(screen.queryByLabelText('Текст решения')).not.toBeInTheDocument();
      question();
      expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
      fireEvent.submit(screen.getByRole('form', { name: 'Отправка вопроса по отчёту' }));
      expect(posts(api)).toHaveLength(0);
      view.unmount();
    }
  },
);

it.each(['public', 'legacy'] as const)(
  '%s overall 45-second read deadline still aborts and withholds late history despite readiness TIMEOUT fallback',
  async (profile) => {
    vi.useFakeTimers();
    const { api, client, mount } = paidHistory(profile);
    let rejectReadiness!: (error: ChatError) => void;
    let readinessSignal!: AbortSignal;
    const readiness = vi.spyOn(client, 'readiness').mockImplementation((_id, signal) => {
      readinessSignal = signal;
      return new Promise((_, reject) => {
        rejectReadiness = reject;
      });
    });
    mount();
    await act(async () => vi.advanceTimersByTimeAsync(44_999));
    expect(readiness).toHaveBeenCalledTimes(1);
    expect(readinessSignal.aborted).toBe(false);
    expect(screen.getByRole('button', { name: 'Обновить историю' })).toBeDisabled();
    expect(screen.queryByText(savedQuestion)).not.toBeInTheDocument();
    await act(async () => vi.advanceTimersByTimeAsync(1));
    expect(readinessSignal.aborted).toBe(true);
    expect(screen.getByRole('alert')).toHaveTextContent('Обновление истории остановлено');
    expect(screen.getByRole('button', { name: 'Обновить историю' })).toBeEnabled();
    await act(async () => rejectReadiness(new ChatError('TIMEOUT')));
    expect(screen.queryByText(savedQuestion)).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Текст решения')).not.toBeInTheDocument();
    question();
    expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
    expect(posts(api)).toHaveLength(0);
  },
);

it.each(['refresh', 'chat'] as const)(
  'failed %s revokes selected source authorization even after a later successful refresh',
  async (operation) => {
    const { api, client } = await draftPanel();
    if (operation === 'refresh') {
      vi.spyOn(client, 'history').mockRejectedValueOnce(new ChatError('INVALID'));
      fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
    } else {
      vi.spyOn(client, 'chat').mockRejectedValueOnce(new ChatError('LLM_PROVIDER_UNAVAILABLE'));
      question();
      fireEvent.click(screen.getByRole('button', { name: 'Отправить вопрос' }));
    }
    await settled();
    expect(screen.getByRole('alert')).toBeVisible();
    expect(screen.queryByRole('checkbox', { name: sourceName })).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Текст решения')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
    await settled();
    expect(screen.getByLabelText('Текст решения')).toHaveValue(decisionDraft);
    expect(selectedSource()).not.toBeChecked();
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить решение' }));
    await settled();
    expect(posts(api)).toHaveLength(1);
    expect(JSON.parse(String(posts(api)[0].init.body))).toMatchObject({
      text: decisionDraft,
      findingIds: [],
    });
    expect(api.head.decisions[0].sources).toEqual([]);
  },
);

it.each(['epoch', 'policy'] as const)(
  'successful refresh with changed %s does not retain private source authorization',
  async (changed) => {
    const { api } = await draftPanel();
    if (changed === 'epoch') api.head = { ...api.head, epoch: crypto.randomUUID() };
    else api.policy = { ...api.policy, policyVersion: 'd'.repeat(64) };
    fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
    await settled();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Текст решения')).toHaveValue(decisionDraft);
    expect(selectedSource()).not.toBeChecked();
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить решение' }));
    await settled();
    expect(JSON.parse(String(posts(api)[0].init.body))).toMatchObject({ findingIds: [] });
    expect(api.head.decisions[0].sources).toEqual([]);
  },
);

it('same-policy refresh drops a selected finding absent from the newly verified sources', async () => {
  const { api, transport } = await draftPanel();
  const results = vi.mocked(transport.results).getMockImplementation()!;
  vi.mocked(transport.results).mockImplementation(async (...args) => {
    const page = await results(...args);
    return {
      ...page,
      findings: page.findings.map((finding) =>
        finding.findingId === source.finding.findingId ? { ...finding, findingId: 'secret-0-2' } : finding,
      ),
    };
  });
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
  await settled();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.queryByRole('checkbox', { name: sourceName })).not.toBeInTheDocument();
  expect(
    screen.getByRole('checkbox', { name: 'rule-0000000000000000 · Секреты · secret-0-2' }),
  ).not.toBeChecked();
  expect(screen.getByLabelText('Текст решения')).toHaveValue(decisionDraft);
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить решение' }));
  await settled();
  expect(JSON.parse(String(posts(api)[0].init.body))).toMatchObject({ findingIds: [] });
  expect(api.head.decisions[0].sources).toEqual([]);
});

it('public readiness timeout on refresh preserves a decision selection after unchanged history and two real secret sources verify', async () => {
  const unknown = { outcome: 'unknown', reason: 'NOT_REPORTED' };
  const metadata = {
    ...unknownPublicMetadata,
    findingCount: 2,
    findingCounts: {
      byCheck: { secret: 2, sbom: null, vuln: null, config: null },
      bySeverity: { UNKNOWN: 2, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    },
    coverage: {
      ...unknownPublicMetadata.coverage,
      secret: {
        outcome: 'checked',
        scope: 'image',
        reason: null,
        errorCode: null,
        findingCount: 2,
        os: unknown,
        node: unknown,
        db: unknown,
      },
    },
  };
  const api = publicChatApi(metadata);
  const client = createChatClient(scanSession(), api.fetcher);
  const readiness = vi.spyOn(client, 'readiness');
  const read = vi.spyOn(client, 'history');
  const transport = sourceTransport();
  render(
    <ScanChatPanel
      status={{ ...status, profile: PUBLIC_IMAGE_PROFILE }}
      transport={transport}
      client={client}
    />,
  );
  await settled();
  expect(readiness).toHaveBeenCalledTimes(1);
  expect(api.requests.filter((request) => request.path.endsWith('/readiness'))).toHaveLength(1);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  question();
  expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeEnabled();
  details();
  fireEvent.click(screen.getByText('Основания решения', { selector: 'summary' }));
  expect(screen.getAllByRole('checkbox')).toHaveLength(2);
  fireEvent.change(screen.getByLabelText('Текст решения'), { target: { value: decisionDraft } });
  fireEvent.click(selectedSource());
  expect(selectedSource()).toBeChecked();

  readiness.mockRejectedValueOnce(new ChatError('TIMEOUT'));
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
  expect(screen.getByRole('button', { name: 'Сохранить решение' })).toBeDisabled();
  await settled();
  expect(readiness).toHaveBeenCalledTimes(2);
  expect(read).toHaveBeenCalledTimes(2);
  expect(transport.results).toHaveBeenCalledTimes(4);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Текст решения')).toHaveValue(decisionDraft);
  expect(selectedSource()).toBeChecked();
  expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
  expect(screen.getByRole('status', { name: 'Состояние подключения чата' })).toHaveTextContent(
    'Не удалось проверить готовность чата',
  );
  fireEvent.submit(screen.getByRole('form', { name: 'Отправка вопроса по отчёту' }));
  expect(posts(api)).toHaveLength(0);
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить решение' }));
  await settled();
  expect(posts(api)).toHaveLength(1);
  expect(posts(api)[0].path).toMatch(/\/history\/decision$/);
  expect(JSON.parse(String(posts(api)[0].init.body))).toMatchObject({
    text: decisionDraft,
    findingIds: [source.finding.findingId],
  });
  expect(api.head.decisions[0]).toMatchObject({ text: decisionDraft, sources: [source] });
  expect(screen.getByLabelText('Текст решения')).toHaveValue('');
  expect(selectedSource()).not.toBeChecked();
  expect(screen.getByRole('button', { name: 'Отправить вопрос' })).toBeDisabled();
});

it('same-ID source content change revokes the selected finding without losing the decision draft', async () => {
  const { api, transport } = await draftPanel();
  const results = vi.mocked(transport.results).getMockImplementation()!;
  vi.mocked(transport.results).mockImplementation(async (...args) => {
    const page = await results(...args);
    return {
      ...page,
      findings: page.findings.map((finding) =>
        finding.findingId === source.finding.findingId
          ? { ...finding, ruleId: 'rule-1111111111111111' }
          : finding,
      ),
    };
  });
  fireEvent.click(screen.getByRole('button', { name: 'Обновить историю' }));
  await settled();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Текст решения')).toHaveValue(decisionDraft);
  const changedSource = screen.getByRole('checkbox', {
    name: 'rule-1111111111111111 · Секреты · secret-0-1',
  });
  expect(changedSource).not.toBeChecked();
  expect(screen.queryByRole('checkbox', { name: sourceName })).not.toBeInTheDocument();
  expect(posts(api)).toHaveLength(0);
  fireEvent.click(screen.getByRole('button', { name: 'Сохранить решение' }));
  await settled();
  expect(posts(api)).toHaveLength(1);
  expect(JSON.parse(String(posts(api)[0].init.body))).toMatchObject({ text: decisionDraft, findingIds: [] });
  expect(api.head.decisions[0].sources).toEqual([]);
  expect(screen.getByLabelText('Текст решения')).toHaveValue('');
  expect(changedSource).not.toBeChecked();
});

it.each(['another-owner', 'chat-draft-owner'])(
  'session transition to %s clears draft and source authorization, including same-owner reauthentication',
  async (owner) => {
    const { api, transport, view } = await draftPanel();
    act(() => transitionScanSession(owner, new QueryClient(), true));
    expect(screen.queryByRole('checkbox', { name: sourceName })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Вопрос чату')).toHaveValue('');
    const client = createChatClient(scanSession(), api.fetcher);
    view.rerender(<ScanChatPanel status={status} transport={transport} client={client} />);
    await settled();
    details();
    fireEvent.click(screen.getByText('Основания решения', { selector: 'summary' }));
    expect(screen.getByLabelText('Текст решения')).toHaveValue('');
    expect(selectedSource()).not.toBeChecked();
    expect(screen.getByRole('button', { name: 'Сохранить решение' })).toBeDisabled();
    expect(posts(api)).toHaveLength(0);
  },
);
