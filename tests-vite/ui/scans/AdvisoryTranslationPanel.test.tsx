import '@testing-library/jest-dom/vitest';
import { webcrypto } from 'node:crypto';
import { StrictMode } from 'react';
import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import {
  AdvisoryTranslationPanel,
  AdvisoryTranslationScope,
} from '@/features/scans/AdvisoryTranslationPanel';
import { VulnAdvisoryCard } from '@/pages/scans/VulnAdvisoryCard';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { readReportPreferences, saveReportPreferences } from '@/shared/api/preferences/reportPreferences';
import { createAdvisoryTranslationClient } from '@/shared/api/scans/advisoryTranslationClient';
import type { TranslationContext } from '@/shared/api/scans/advisoryTranslationContract';
import type { VulnFinding } from '@/shared/api/scans/scanTransport';
import { reportAutomationKey, runReportAutomation } from '@/shared/api/scans/reportAutomation';
import { finding, replyFor, status, translationApi } from './advisoryTranslationFixtures';
import { json } from './llmChatFixtures';
import { readinessWire } from './publicLlmFixtures';

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  localStorage.clear();
  sessionStorage.clear();
  transitionScanSession('alice', new QueryClient(), true);
  saveReportPreferences({ language: 'ru', autoSummary: false });
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
const posts = (api: ReturnType<typeof translationApi>) =>
  api.requests.filter((r) => r.init.method === 'POST');
function mount(api = translationApi(), value = finding, fetcher: typeof fetch = api.fetcher) {
  vi.stubGlobal('fetch', fetcher);
  const view = render(
    <AdvisoryTranslationScope status={status}>
      <ul>
        <VulnAdvisoryCard finding={value} />
      </ul>
    </AdvisoryTranslationScope>,
  );
  const summary = screen.getByText(/Подробности /);
  fireEvent.click(summary);
  fireEvent(summary.closest('details')!, new Event('toggle'));
  return view;
}
const translated = () => screen.findByText('Пакет содержит уязвимость.');
const retry = () => screen.getByRole('button', { name: 'Повторить перевод' });
function direct(client: ReturnType<typeof createAdvisoryTranslationClient>) {
  return (
    <AdvisoryTranslationScope status={status}>
      <AdvisoryTranslationPanel
        findingId={finding.findingId}
        vulnerabilityId={finding.cveId}
        assessmentIndex={0}
        assessment={finding.advisory!.assessments[0]}
        client={client}
      />
    </AdvisoryTranslationScope>
  );
}

it.each(['before-post', 'before-publication'] as const)(
  'cross-tab language revocation %s aborts synchronously although revision is unchanged',
  async (phase) => {
    const api = translationApi();
    const client = createAdvisoryTranslationClient(scanSession(), api.fetcher);
    const accepted = readReportPreferences();
    let abortedImmediately: boolean | undefined;
    let observedRevision: typeof accepted.revision | undefined;
    const revoke = (signal: AbortSignal) => {
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
    };
    const read = client.context;
    let reads = 0;
    vi.spyOn(client, 'context').mockImplementation(async (id, selection, signal) => {
      if (++reads === 2 && phase === 'before-post') revoke(signal);
      return read(id, selection, signal);
    });
    const translate = vi.spyOn(client, 'translate').mockImplementation(async (_context, _consent, signal) => {
      if (phase === 'before-publication') revoke(signal);
      return { ...replyFor(), machineTranslated: true, provider: 'OpenRouter' };
    });
    render(direct(client));
    await waitFor(() => expect(abortedImmediately).toBeDefined());
    expect(abortedImmediately).toBe(true);
    expect(observedRevision).toBe(accepted.revision);
    await act(async () => {});
    expect(translate).toHaveBeenCalledTimes(phase === 'before-post' ? 0 : 1);
    expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
  },
);

it('fresh flags block a translation even before the storage notification reaches React', async () => {
  const api = translationApi();
  const client = createAdvisoryTranslationClient(scanSession(), api.fetcher);
  const read = client.readiness;
  let reads = 0;
  vi.spyOn(client, 'readiness').mockImplementation(async (id, signal) => {
    const value = await read(id, signal);
    if (++reads === 2)
      localStorage.setItem(
        'report-preferences:v1:alice',
        JSON.stringify({
          version: 1,
          automationRevision: 'report-automation-v1',
          language: 'original',
          autoSummary: false,
        }),
      );
    return value;
  });
  const translate = vi.spyOn(client, 'translate');
  render(direct(client));
  await waitFor(() => expect(reads).toBe(2));
  await act(async () => {});
  expect(translate).not.toHaveBeenCalled();
  expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
});

it.each([
  { model: 'other/model:free' },
  { providers: ['phala', 'other'] },
  { retention: 'no-training' },
  { requestBudgetUsd: 0.1 },
  { data: 'Entire report and history.' },
  { freeOnly: false },
])('a fresh server policy with unallowed translation disclosure %j never creates consent', async (change) => {
  const api = translationApi();
  const client = createAdvisoryTranslationClient(scanSession(), api.fetcher);
  const unsafe = {
    ...api.context,
    policyVersion: 'f'.repeat(64),
    disclosure: { ...api.context.disclosure, ...change },
  } as unknown as TranslationContext;
  vi.spyOn(client, 'context').mockResolvedValue(unsafe);
  vi.spyOn(client, 'readiness').mockResolvedValue({
    ...api.ready,
    provider: {
      ...api.ready.provider,
      model: unsafe.disclosure!.model,
      endpoint: unsafe.disclosure!.providers[0],
    },
  } as Awaited<ReturnType<typeof client.readiness>>);
  const translate = vi.spyOn(client, 'translate');
  render(direct(client));
  expect(await screen.findByRole('alert')).toHaveTextContent('не совпадают с разрешением аккаунта');
  expect(translate).not.toHaveBeenCalled();
});

it('many opened assessments bound passive metadata GETs to two and a finite queue without recording provider attempts', async () => {
  const api = translationApi();
  let active = 0,
    peak = 0;
  const signals: AbortSignal[] = [];
  const fetcher = vi.fn<typeof fetch>((_input, init) => {
    const signal = init!.signal!;
    signals.push(signal);
    peak = Math.max(peak, ++active);
    signal.addEventListener(
      'abort',
      () => {
        active--;
      },
      { once: true },
    );
    return new Promise(() => {});
  });
  const client = createAdvisoryTranslationClient(scanSession(), fetcher);
  const view = render(
    <AdvisoryTranslationScope status={status}>
      {Array.from({ length: 16 }, (_, index) => (
        <AdvisoryTranslationPanel
          key={index}
          findingId={`vuln-${index.toString(16).padStart(64, '0')}`}
          vulnerabilityId={`CVE-2026-${1234 + index}`}
          assessmentIndex={0}
          assessment={finding.advisory!.assessments[0]}
          client={client}
        />
      ))}
    </AdvisoryTranslationScope>,
  );
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(screen.getAllByRole('alert')).toHaveLength(7));
  expect(peak).toBe(2);
  expect(sessionStorage.getItem('report-automation-v1:attempts')).toBeNull();
  expect(fetcher.mock.calls.every(([, init]) => init!.method === 'GET')).toBe(true);
  view.unmount();
  await waitFor(() => expect(signals.every((signal) => signal.aborted)).toBe(true));
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(posts(api)).toHaveLength(0);
});

it('identical passive source reads are single-flight and closing one consumer does not cancel the other', async () => {
  const fetcher = vi.fn<typeof fetch>(() => new Promise(() => {}));
  const client = createAdvisoryTranslationClient(scanSession(), fetcher);
  const view = render(
    <>
      {direct(client)}
      {direct(client)}
    </>,
  );
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  const signals = fetcher.mock.calls.map(([, init]) => init!.signal!);
  view.rerender(<>{direct(client)}</>);
  await act(async () => {});
  expect(signals.every((signal) => !signal.aborted)).toBe(true);
  view.unmount();
  await waitFor(() => expect(signals.every((signal) => signal.aborted)).toBe(true));
  expect(fetcher).toHaveBeenCalledTimes(2);
});

it('collapsed cards do no I/O; opening translates automatically once and focus/reconnect/reopening reuse memory', async () => {
  const api = translationApi();
  vi.stubGlobal('fetch', api.fetcher);
  const findings = [
    finding,
    ...['a', 'b'].map((letter, index) => ({
      ...finding,
      findingId: `vuln-${letter.repeat(64)}`,
      cveId: `CVE-2026-${1235 + index}`,
    })),
  ];
  render(
    <AdvisoryTranslationScope status={status}>
      <ul>
        {findings.map((value) => (
          <VulnAdvisoryCard key={value.findingId} finding={value} />
        ))}
      </ul>
    </AdvisoryTranslationScope>,
  );
  await act(async () => {
    fireEvent.focus(window);
  });
  expect(api.requests).toHaveLength(0);
  const summary = screen.getByText(`Подробности ${finding.cveId} · описание, CVSS и ссылки`);
  fireEvent.click(summary);
  await translated();
  expect(posts(api)).toHaveLength(1);
  expect(screen.getAllByRole('region', { name: /Перевод / })).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', { name: 'Обновить условия перевода' }));
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Обновить условия перевода' })).toBeEnabled(),
  );
  expect(screen.getByText('Пакет содержит уязвимость.')).toBeVisible();
  const reads = api.requests.length;
  await act(async () => {
    fireEvent.focus(window);
    fireEvent(window, new Event('online'));
  });
  expect(api.requests).toHaveLength(reads);
  fireEvent.click(summary);
  await waitFor(() => expect(screen.queryByRole('region', { name: /Перевод / })).toBeNull());
  fireEvent.click(summary);
  await translated();
  expect(posts(api)).toHaveLength(1);
});

it.each(['unsaved', 'original', 'anonymous'] as const)(
  '%s settings never invoke translation and explain account opt-in',
  async (setting) => {
    if (setting === 'unsaved') localStorage.clear();
    if (setting === 'original') saveReportPreferences({ language: 'original', autoSummary: false });
    if (setting === 'anonymous') transitionScanSession(null, new QueryClient(), true);
    const api = translationApi();
    mount(api);
    await act(async () => {});
    expect(api.requests).toHaveLength(0);
    expect(await screen.findByRole('link', { name: 'настройках аккаунта' })).toHaveAttribute(
      'href',
      '/account',
    );
    expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
  },
);

it('automatic translation keeps exact per-POST consent, provenance and original text/toggle without rewriting findings', async () => {
  const api = translationApi();
  const original = JSON.stringify(finding);
  mount(api);
  await translated();
  expect(posts(api)).toHaveLength(1);
  expect(JSON.parse(String(posts(api)[0].init.body))).toEqual({
    reportVersion: api.context.reportVersion,
    findingId: finding.findingId,
    assessmentIndex: 0,
    sourceVersion: api.context.sourceVersion,
    targetLanguage: 'ru',
    consent: { accepted: true, policyVersion: api.context.policyVersion },
  });
  expect(screen.queryByRole('checkbox')).toBeNull();
  expect(screen.getByText(/Машинный перевод на русский · не официальный текст/)).toBeVisible();
  expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
  expect(screen.getByText(/Язык источника: en/)).toBeVisible();
  expect(screen.getByText(/Severity источника: HIGH/)).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Оригинал' }));
  expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Перевод' }));
  expect(screen.getByText('Пакет содержит уязвимость.')).toBeVisible();
  expect(JSON.stringify(finding)).toBe(original);
  expect(posts(api)).toHaveLength(1);
});

it('StrictMode replay has a single source-specific POST', async () => {
  const api = translationApi();
  render(<StrictMode>{direct(createAdvisoryTranslationClient(scanSession(), api.fetcher))}</StrictMode>);
  await translated();
  expect(posts(api)).toHaveLength(1);
});

it('closing native details aborts metadata GETs; focus does not reopen them', async () => {
  const api = translationApi();
  const fetcher = vi.fn<typeof fetch>(() => new Promise(() => {}));
  mount(api, finding, fetcher);
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  const signals = fetcher.mock.calls.map(([, init]) => init!.signal!);
  fireEvent.click(screen.getByText(/Подробности /));
  await waitFor(() => expect(signals.every((s) => s.aborted)).toBe(true));
  fireEvent.focus(window);
  expect(fetcher).toHaveBeenCalledTimes(2);
});

it('closing native details aborts translation and reopening cannot replay or publish its late result', async () => {
  const api = translationApi();
  let finish!: () => void;
  api.post = () =>
    new Promise((resolve) => {
      finish = () => resolve(json(replyFor()));
    });
  mount(api);
  await waitFor(() => expect(posts(api)).toHaveLength(1));
  const summary = screen.getByText(/Подробности /);
  fireEvent.click(summary);
  await waitFor(() => expect(posts(api)[0].init.signal?.aborted).toBe(true));
  fireEvent.click(summary);
  await screen.findByRole('alert');
  await act(async () => finish());
  expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
  expect(posts(api)).toHaveLength(1);
  expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
});

it('a failed attempt remains failed on focus and remount; retry requires an explicit action and fresh consent', async () => {
  const api = translationApi();
  api.post = async () => json({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' }, 503);
  const view = mount(api);
  await screen.findByRole('alert');
  fireEvent.focus(window);
  fireEvent(window, new Event('online'));
  view.unmount();
  mount(api);
  await screen.findByRole('alert');
  expect(posts(api)).toHaveLength(1);
  api.post = async () => json(replyFor(api.context));
  const button = retry();
  fireEvent.click(button);
  fireEvent.click(button);
  await translated();
  expect(posts(api)).toHaveLength(2);
});

it('missing-key readiness blocks translation without claiming provider success', async () => {
  const api = translationApi();
  api.ready = readinessWire('missing');
  mount(api);
  await screen.findByText(/Серверный ключ не настроен или отсутствует/);
  expect(posts(api)).toHaveLength(0);
  expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
});

it.each(['policy', 'source', 'report', 'readiness'] as const)(
  'fresh %s change before POST fails closed',
  async (changed) => {
    const api = translationApi();
    const fetcher: typeof fetch = async (input, init) => {
      const response = await api.fetcher(input, init);
      if (api.requests.length === 2) {
        if (changed === 'policy') api.context = { ...api.context, policyVersion: 'f'.repeat(64) };
        if (changed === 'source') api.context = { ...api.context, sourceVersion: 'f'.repeat(64) };
        if (changed === 'report') api.context = { ...api.context, reportVersion: 'f'.repeat(64) };
        if (changed === 'readiness') api.ready = readinessWire('missing');
      }
      return response;
    };
    mount(api, finding, fetcher);
    await screen.findByRole('alert');
    expect(posts(api)).toHaveLength(0);
  },
);

it.each(['policy', 'source', 'report'] as const)(
  '%s changes during POST withhold the complete translation',
  async (changed) => {
    const api = translationApi();
    const reply = replyFor();
    api.post = async () => {
      if (changed === 'policy') api.context = { ...api.context, policyVersion: 'f'.repeat(64) };
      if (changed === 'source') api.context = { ...api.context, sourceVersion: 'f'.repeat(64) };
      if (changed === 'report') api.context = { ...api.context, reportVersion: 'f'.repeat(64) };
      return json(reply);
    };
    mount(api);
    await screen.findByRole('alert');
    expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
    expect(posts(api)).toHaveLength(1);
  },
);

it.each(['original', 'preferences', 'bob', 'reauth', 'A-B-A'] as const)(
  '%s transition aborts delivery and stale replies cannot reappear',
  async (change) => {
    const api = translationApi();
    let finish!: () => void;
    api.post = () =>
      new Promise((resolve) => {
        finish = () => resolve(json(replyFor()));
      });
    mount(api);
    await waitFor(() => expect(posts(api)).toHaveLength(1));
    await act(async () => {
      if (change === 'original') saveReportPreferences({ language: 'original', autoSummary: false });
      else if (change === 'preferences') saveReportPreferences({ language: 'ru', autoSummary: true });
      else if (change === 'A-B-A') {
        transitionScanSession('bob', new QueryClient());
        transitionScanSession('alice', new QueryClient());
      } else transitionScanSession(change === 'reauth' ? 'alice' : 'bob', new QueryClient(), true);
      finish();
    });
    expect(posts(api)[0].init.signal?.aborted).toBe(true);
    expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
    expect(posts(api)).toHaveLength(1);
    expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
  },
);

it('noncooperative metadata read times out at 45 seconds and cannot continue after late completion', async () => {
  const api = translationApi();
  const client = createAdvisoryTranslationClient(scanSession(), api.fetcher);
  let finish!: (value: TranslationContext) => void;
  const read = vi.spyOn(client, 'context').mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  vi.useFakeTimers();
  render(direct(client));
  await act(async () => {
    await vi.advanceTimersByTimeAsync(45001);
  });
  expect(screen.getByRole('alert')).toHaveTextContent('Ожидание перевода остановлено');
  await act(async () => finish(api.context));
  expect(read).toHaveBeenCalledTimes(1);
  expect(posts(api)).toHaveLength(0);
});

it('noncooperative translation times out at 45 seconds; late completion is never published', async () => {
  const api = translationApi();
  const client = createAdvisoryTranslationClient(scanSession(), api.fetcher);
  let finish!: () => void;
  const translate = vi.spyOn(client, 'translate').mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = () => resolve({ ...replyFor(), machineTranslated: true, provider: 'OpenRouter' });
      }),
  );
  const timers = vi.spyOn(globalThis, 'setTimeout');
  render(direct(client));
  await waitFor(() => expect(translate).toHaveBeenCalledTimes(1));
  const deadline = timers.mock.calls.filter(([, delay]) => delay === 45_000).at(-1)![0] as () => void;
  await act(async () => {
    deadline();
  });
  expect(screen.getByRole('alert')).toBeTruthy();
  expect(translate.mock.calls[0][2].aborted).toBe(true);
  await act(async () => finish());
  expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
  expect(translate).toHaveBeenCalledTimes(1);
});

it('redacted/truncated source fields stay redacted/truncated and only eligible text is translated', async () => {
  const partial: VulnFinding = {
    ...finding,
    advisory: {
      ...finding.advisory!,
      assessments: [
        {
          ...finding.advisory!.assessments[0],
          title: { value: null, state: 'redacted', redacted: true },
          description: { value: 'A shortened description', state: 'truncated', redacted: false },
        },
      ],
    },
  };
  const api = translationApi(partial);
  api.post = async () =>
    json({ ...replyFor(api.context), translation: { title: null, description: 'Сокращённое описание' } });
  mount(api, partial);
  await screen.findByText('Сокращённое описание');
  expect(screen.getByText(/Скрытые поля не переводились/)).toBeVisible();
  expect(screen.getByText(/Исходный текст сокращён; перевод/)).toBeVisible();
  expect(screen.queryByText('Перевод заголовка:')).toBeNull();
});

it('missing/omitted/redacted/invalid text never schedules any request', () => {
  const api = translationApi();
  const original = finding.advisory!.assessments[0];
  for (const state of ['omitted', 'redacted', 'missing', 'invalid'] as const) {
    const view = render(
      <AdvisoryTranslationScope status={status}>
        <AdvisoryTranslationPanel
          findingId={finding.findingId}
          vulnerabilityId={finding.cveId}
          assessmentIndex={0}
          assessment={{
            ...original,
            title: { value: null, state, redacted: state === 'redacted' },
            description: { value: null, state, redacted: state === 'redacted' },
          }}
          client={createAdvisoryTranslationClient(scanSession(), api.fetcher)}
        />
      </AdvisoryTranslationScope>,
    );
    expect(screen.getByRole('button', { name: 'Обновить условия перевода' })).toBeDisabled();
    view.unmount();
  }
  expect(api.requests).toHaveLength(0);
});

it('TEMP stays a Debian advisory and malicious translated fields never become markup', async () => {
  const temp: VulnFinding = {
    ...finding,
    findingId: `vuln-${'f'.repeat(64)}`,
    cveId: 'TEMP-1234567-ABCDEF',
    ecosystem: 'deb',
  };
  const api = translationApi(temp);
  const view = mount(api, temp);
  await translated();
  expect(screen.getByText('Advisory ID: TEMP-1234567-ABCDEF')).toBeVisible();
  expect(screen.getByText('Debian advisory (не CVE)')).toBeVisible();
  view.unmount();
  const malicious = translationApi();
  malicious.post = async () =>
    json({
      ...replyFor(),
      translation: { title: '<script>bad</script>', description: '[click](https://example.invalid)' },
    });
  const second = mount(malicious);
  await screen.findByRole('alert');
  expect(second.container.querySelector('script')).toBeNull();
  expect(screen.queryByRole('link', { name: 'click' })).toBeNull();
  expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
});

it('opened source panels serialize their real POSTs and keep independent source bindings', async () => {
  const first = translationApi();
  const secondFinding = { ...finding, findingId: `vuln-${'e'.repeat(64)}`, cveId: 'CVE-2026-1235' };
  const second = translationApi(secondFinding);
  let finish!: () => void;
  first.post = () =>
    new Promise((resolve) => {
      finish = () => resolve(json(replyFor(first.context)));
    });
  render(
    <AdvisoryTranslationScope status={status}>
      <AdvisoryTranslationPanel
        findingId={finding.findingId}
        vulnerabilityId={finding.cveId}
        assessmentIndex={0}
        assessment={finding.advisory!.assessments[0]}
        client={createAdvisoryTranslationClient(scanSession(), first.fetcher)}
      />
      <AdvisoryTranslationPanel
        findingId={secondFinding.findingId}
        vulnerabilityId={secondFinding.cveId}
        assessmentIndex={0}
        assessment={secondFinding.advisory!.assessments[0]}
        client={createAdvisoryTranslationClient(scanSession(), second.fetcher)}
      />
    </AdvisoryTranslationScope>,
  );
  await waitFor(() => expect(posts(first)).toHaveLength(1));
  expect(posts(second)).toHaveLength(0);
  await act(async () => finish());
  await waitFor(() => expect(screen.getAllByText('Пакет содержит уязвимость.')).toHaveLength(2));
  expect(posts(first)).toHaveLength(1);
  expect(posts(second)).toHaveLength(1);
  expect(JSON.parse(String(posts(second)[0].init.body)).sourceVersion).toBe(second.context.sourceVersion);
});

it.each(['index', 'finding', 'text', 'report'] as const)(
  'changing %s aborts the old source and withholds its late translation',
  async (change) => {
    const api = translationApi();
    const client = createAdvisoryTranslationClient(scanSession(), api.fetcher);
    let finish!: () => void;
    api.post = () =>
      new Promise((resolve) => {
        finish = () => resolve(json(replyFor()));
      });
    const view = render(direct(client));
    await waitFor(() => expect(posts(api)).toHaveLength(1));
    view.rerender(
      <AdvisoryTranslationScope
        status={change === 'report' ? { ...status, scanId: '00000000-0000-4000-8000-000000000099' } : status}
      >
        <AdvisoryTranslationPanel
          findingId={change === 'finding' ? `vuln-${'f'.repeat(64)}` : finding.findingId}
          vulnerabilityId={finding.cveId}
          assessmentIndex={change === 'index' ? 1 : 0}
          client={client}
          assessment={
            change === 'text'
              ? {
                  ...finding.advisory!.assessments[0],
                  description: { value: 'New source text', state: 'available', redacted: false },
                }
              : finding.advisory!.assessments[0]
          }
        />
      </AdvisoryTranslationScope>,
    );
    await act(async () => finish());
    expect(posts(api)[0].init.signal?.aborted).toBe(true);
    expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
    expect(posts(api)).toHaveLength(1);
  },
);

it('unavailable attempt storage fails closed without a provider call', async () => {
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new Error('blocked');
  });
  const api = translationApi();
  mount(api);
  await screen.findByRole('alert');
  expect(posts(api)).toHaveLength(0);
  expect(screen.getByRole('alert')).toHaveTextContent('отправка остановлена');
});

it('serializes different source POSTs with a finite queue and never replays overflow automatically', async () => {
  const controllers = Array.from({ length: 11 }, () => new AbortController());
  let finish!: () => void;
  let active = 0,
    peak = 0;
  const task = vi.fn(async () => {
    peak = Math.max(peak, ++active);
    await new Promise<void>((resolve) => {
      finish = resolve;
    });
    active--;
    return 'validated';
  });
  const jobs = controllers.map((controller, index) =>
    runReportAutomation(
      reportAutomationKey('translation', 'report-automation-v1', `source-${index}`),
      controller.signal,
      task,
    ).then(
      () => 'done',
      (error: { code: string }) => error.code,
    ),
  );
  await waitFor(() => expect(task).toHaveBeenCalledTimes(1));
  expect(await jobs[9]).toBe('CAPACITY');
  expect(await jobs[10]).toBe('CAPACITY');
  controllers[1].abort();
  await act(async () => {
    finish();
  });
  await waitFor(() => expect(task).toHaveBeenCalledTimes(2));
  expect(peak).toBe(1);
  for (const controller of controllers) controller.abort();
  await Promise.all(jobs);
});

it('result capacity and persistent attempt ledger fail closed rather than evicting and replaying', async () => {
  const task = vi.fn(async () => 'validated');
  for (let index = 0; index < 64; index++) {
    await runReportAutomation(`cache-${index}`, new AbortController().signal, task);
  }
  await expect(runReportAutomation('overflow', new AbortController().signal, task)).rejects.toMatchObject({
    code: 'CAPACITY',
  });
  expect(await runReportAutomation('cache-0', new AbortController().signal, task)).toBe('validated');
  expect(task).toHaveBeenCalledTimes(64);
  transitionScanSession('alice', new QueryClient(), true);
  await expect(runReportAutomation('cache-0', new AbortController().signal, task)).rejects.toMatchObject({
    code: 'ATTEMPTED',
  });
  expect(task).toHaveBeenCalledTimes(64);
  expect(sessionStorage.getItem('report-automation-v1:attempts')).not.toContain('validated');
});
