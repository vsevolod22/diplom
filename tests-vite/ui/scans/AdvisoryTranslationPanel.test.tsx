import '@testing-library/jest-dom/vitest';
import { webcrypto } from 'node:crypto';
import { QueryClient } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import {
  AdvisoryTranslationPanel,
  AdvisoryTranslationScope,
} from '@/features/scans/AdvisoryTranslationPanel';
import { VulnAdvisoryCard } from '@/pages/scans/VulnAdvisoryCard';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { createAdvisoryTranslationClient } from '@/shared/api/scans/advisoryTranslationClient';
import type { TranslationContext } from '@/shared/api/scans/advisoryTranslationContract';
import type { VulnFinding } from '@/shared/api/scans/scanTransport';
import { finding, replyFor, status, translationApi } from './advisoryTranslationFixtures';
import { json } from './llmChatFixtures';
import { readinessWire } from './publicLlmFixtures';

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  transitionScanSession('alice', new QueryClient(), true);
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});
const posts = (api: ReturnType<typeof translationApi>) =>
  api.requests.filter((request) => request.init.method === 'POST');
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
  // Flush the native toggle after activation for tests that inspect the initial pending panel synchronously.
  fireEvent(summary.closest('details')!, new Event('toggle'));
  return view;
}
const noConsentCheckbox = () => expect(screen.queryByRole('checkbox')).toBeNull();
const send = () => screen.getByRole('button', { name: 'Перевести на русский' });
async function open() {
  await waitFor(() => expect(send()).toBeEnabled());
}
async function translate() {
  await open();
  fireEvent.click(send());
}

it('multiple collapsed cards make no metadata GETs; only the opened card loads and closed cards ignore focus', async () => {
  const api = translationApi();
  vi.stubGlobal('fetch', api.fetcher);
  const findings = [finding, ...['a', 'b'].map((letter, index) => ({
    ...finding,
    findingId: `vuln-${letter.repeat(64)}`,
    cveId: `CVE-2026-${1235 + index}`,
  }))];
  render(
    <AdvisoryTranslationScope status={status}>
      <ul>{findings.map((value) => <VulnAdvisoryCard key={value.findingId} finding={value} />)}</ul>
    </AdvisoryTranslationScope>,
  );
  await act(async () => { fireEvent.focus(window); });
  expect(api.requests).toHaveLength(0);
  expect(screen.queryByRole('region', { name: /Перевод /, hidden: true })).toBeNull();

  const summary = screen.getByText(`Подробности ${finding.cveId} · описание, CVSS и ссылки`);
  fireEvent.click(summary);
  await open();
  expect(summary.closest('details')).toHaveAttribute('open');
  expect(screen.getAllByRole('region', { name: /Перевод /, hidden: true })).toHaveLength(1);
  expect(api.requests.map(({ path, init }) => ({ path, method: init.method }))).toEqual([
    { path: expect.stringContaining(`/translation/context?findingId=${finding.findingId}&assessmentIndex=0`), method: 'GET' },
    { path: expect.stringContaining('/readiness'), method: 'GET' },
  ]);

  await act(async () => { fireEvent.focus(window); });
  await open();
  expect(api.requests).toHaveLength(4);
  expect(posts(api)).toHaveLength(0);
  fireEvent.click(summary);
  await waitFor(() => expect(screen.queryByRole('region', { name: /Перевод /, hidden: true })).toBeNull());
  expect(summary.closest('details')).not.toHaveAttribute('open');
  await act(async () => { fireEvent.focus(window); });
  expect(api.requests).toHaveLength(4);

  fireEvent.click(summary);
  await open();
  expect(api.requests).toHaveLength(6);
  expect(posts(api)).toHaveLength(0);
});

it('closing native details aborts pending context/readiness GETs and does not revalidate on focus', async () => {
  const api = translationApi();
  const fetcher = vi.fn<typeof fetch>(() => new Promise<Response>(() => {}));
  mount(api, finding, fetcher);
  expect(fetcher).toHaveBeenCalledTimes(2);
  const signals = fetcher.mock.calls.map(([, init]) => init!.signal!);
  expect(signals.every((signal) => !signal.aborted)).toBe(true);
  fireEvent.click(screen.getByText(/Подробности /));
  await waitFor(() => expect(screen.queryByRole('region', { name: /Перевод /, hidden: true })).toBeNull());
  expect(signals.every((signal) => signal.aborted)).toBe(true);
  await act(async () => { fireEvent.focus(window); });
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(fetcher.mock.calls.every(([, init]) => init?.method === 'GET')).toBe(true);
});

it('closing native details aborts a pending translation and reopening cannot publish its late reply or resend', async () => {
  const api = translationApi();
  let finish!: () => void;
  api.post = () => new Promise((resolve) => { finish = () => resolve(json(replyFor())); });
  mount(api);
  await translate();
  await waitFor(() => expect(posts(api)).toHaveLength(1));
  expect(posts(api)[0].init.signal?.aborted).toBe(false);
  const summary = screen.getByText(/Подробности /);
  fireEvent.click(summary);
  await waitFor(() => expect(screen.queryByRole('region', { name: /Перевод /, hidden: true })).toBeNull());
  expect(posts(api)[0].init.signal?.aborted).toBe(true);
  const reads = api.requests.length;
  await act(async () => { fireEvent.focus(window); });
  expect(api.requests).toHaveLength(reads);

  fireEvent.click(summary);
  await open();
  expect(api.requests).toHaveLength(reads + 2);
  await act(async () => { finish(); });
  expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
  expect(posts(api)).toHaveLength(1);
  expect(send()).toBeEnabled();
  expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
});

it('opening a source loads only GET context; one translate click produces one exact POST without a checkbox and preserves original facts', async () => {
  const api = translationApi();
  const original = JSON.stringify(finding);
  mount(api);
  expect(api.requests.every((request) => request.init.method === 'GET')).toBe(true);
  expect(send()).toBeDisabled();
  await open();
  noConsentCheckbox();
  expect(send()).toBeEnabled();
  expect(screen.queryByRole('button', { name: 'Прочитать условия перевода' })).toBeNull();
  expect(api.requests.every((request) => request.init.method === 'GET')).toBe(true);
  expect(screen.getByText(/Внешнему провайдеру передаётся разрешённый текст/)).toBeVisible();
  fireEvent.click(send());
  fireEvent.click(send());
  await screen.findByText('Пакет содержит уязвимость.');
  expect(posts(api)).toHaveLength(1);
  expect(JSON.parse(String(posts(api)[0].init.body))).toEqual({
    reportVersion: api.context.reportVersion,
    findingId: finding.findingId,
    assessmentIndex: 0,
    sourceVersion: api.context.sourceVersion,
    targetLanguage: 'ru',
    consent: { accepted: true, policyVersion: api.context.policyVersion },
  });
  expect(screen.getByText(/Машинный перевод на русский · не официальный текст NVD или БДУ/)).toBeVisible();
  expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
  expect(screen.getByText(/Язык источника: en/)).toBeVisible();
  expect(screen.getByText(/Severity источника: HIGH/)).toBeVisible();
  expect(screen.getByText('CVE ID: CVE-2026-1234')).toBeVisible();
  noConsentCheckbox();
  expect(send()).toBeEnabled();
  fireEvent.click(screen.getByRole('button', { name: 'Оригинал' }));
  expect(screen.queryByText('Пакет содержит уязвимость.')).not.toBeInTheDocument();
  expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Перевод' }));
  expect(screen.getByText('Пакет содержит уязвимость.')).toBeVisible();
  expect(posts(api)).toHaveLength(1);
  expect(JSON.stringify(finding)).toBe(original);
});

it('keeps a real error visible across GET revalidation and sends again only on a new click with current policy', async () => {
  const api = translationApi();
  api.post = async () => json({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' }, 503);
  mount(api);
  await translate();
  const alert = await screen.findByRole('alert');
  expect(alert).toHaveTextContent('Провайдер недоступен');
  expect(posts(api)).toHaveLength(1);
  api.context = { ...api.context, policyVersion: 'f'.repeat(64) };
  fireEvent.focus(window);
  fireEvent(window, new Event('online'));
  await open();
  expect(posts(api)).toHaveLength(1);
  expect(screen.getByRole('alert')).toBe(alert);
  expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
  expect(send()).toHaveAccessibleDescription(/Нажимая «Перевести на русский»/);
  expect(send()).toHaveAccessibleDescription(/OpenRouter/);
  expect(send()).toHaveAccessibleDescription(/Только бесплатный профиль/);
  api.post = async () => json(replyFor(api.context));
  fireEvent.click(send());
  fireEvent.click(send());
  await screen.findByText('Пакет содержит уязвимость.');
  expect(posts(api)).toHaveLength(2);
  expect(JSON.parse(String(posts(api)[1].init.body)).consent).toEqual({
    accepted: true,
    policyVersion: api.context.policyVersion,
  });
  noConsentCheckbox();
});

it('uses actual missing-key readiness to disable generation, without a POST or provider probe', async () => {
  const api = translationApi();
  api.ready = readinessWire('missing');
  mount(api);
  await screen.findByText(/Серверный ключ не настроен или отсутствует/);
  noConsentCheckbox();
  expect(send()).toBeDisabled();
  fireEvent.click(send());
  expect(posts(api)).toHaveLength(0);
  expect(api.requests).toHaveLength(2);
  expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
});

for (const errorCode of ['LLM_PROVIDER_UNAVAILABLE', 'LLM_QUOTA_EXCEEDED', 'LLM_TRANSLATION_UNAVAILABLE']) {
  it(`${errorCode} keeps the original, requires fresh intent and never retries or echoes server diagnostics`, async () => {
    const api = translationApi();
    api.post = async () => json({ errorCode, diagnostic: 'private provider diagnostic' }, 503);
    mount(api);
    await translate();
    await screen.findByRole('alert');
    expect(posts(api)).toHaveLength(1);
    noConsentCheckbox();
    expect(send()).toBeEnabled();
    expect(screen.queryByText(/Машинный перевод на русский ·/)).toBeNull();
    expect(document.body.textContent).not.toContain('private provider diagnostic');
    expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
  });
}

it.each([429, 503, 401])(
  'shows provider HTTP %s and its safe hint without retrying or replacing the original',
  async (providerStatus) => {
    const api = translationApi();
    const auth = providerStatus === 401;
    api.post = async () =>
      json(
        {
          errorCode: auth ? 'LLM_PROVIDER_AUTH_FAILED' : 'LLM_PROVIDER_RATE_LIMITED',
          providerFailure: {
            kind: auth ? 'auth_failed' : 'rate_limited',
            status: providerStatus,
            ...(auth ? {} : { retryAfterSeconds: 0 }),
          },
        },
        auth ? 503 : providerStatus,
      );
    mount(api);
    await translate();
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(auth ? 'Провайдер отклонил серверный ключ' : 'Провайдер занят');
    expect(alert).toHaveTextContent(`HTTP ${providerStatus}`);
    expect(alert).toHaveTextContent('возврат квоты не гарантирован');
    if (!auth) expect(alert).toHaveTextContent('0 с');
    expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
    expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
    noConsentCheckbox();
    expect(send()).toBeEnabled();
    vi.useFakeTimers();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(86400001);
    });
    expect(posts(api)).toHaveLength(1);
    vi.useRealTimers();
    fireEvent.click(screen.getByRole('button', { name: 'Обновить условия перевода' }));
    await open();
    noConsentCheckbox();
    expect(send()).toBeEnabled();
    expect(screen.getByRole('alert')).toBe(alert);
    expect(posts(api)).toHaveLength(1);
  },
);

for (const changed of ['policy', 'source', 'report', 'readiness'] as const) {
  it(`fresh ${changed} change before send prevents POST and requires a new click`, async () => {
    const api = translationApi();
    mount(api);
    await open();
    if (changed === 'policy') api.context = { ...api.context, policyVersion: 'f'.repeat(64) };
    if (changed === 'source') api.context = { ...api.context, sourceVersion: 'f'.repeat(64) };
    if (changed === 'report') api.context = { ...api.context, reportVersion: 'f'.repeat(64) };
    if (changed === 'readiness') api.ready = readinessWire('missing');
    fireEvent.click(send());
    await screen.findByRole('alert');
    expect(posts(api)).toHaveLength(0);
    noConsentCheckbox();
    expect(send().hasAttribute('disabled')).toBe(changed !== 'policy');
    expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
  });
}

it('withholds a complete response if source/policy changes during POST, and does not silently reuse the old consent', async () => {
  const api = translationApi();
  const reply = replyFor(api.context);
  api.post = async () => {
    api.context = { ...api.context, sourceVersion: 'f'.repeat(64) };
    return json(reply);
  };
  mount(api);
  await translate();
  await screen.findByRole('alert');
  expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
  expect(posts(api)).toHaveLength(1);
  noConsentCheckbox();
});

for (const next of ['bob', 'same-owner', 'A-B-A'] as const) {
  it(`aborts and hides late text after ${next} authentication transition`, async () => {
    const api = translationApi();
    let finish!: () => void;
    api.post = () =>
      new Promise((resolve) => {
        finish = () => resolve(json(replyFor()));
      });
    mount(api);
    await translate();
    await waitFor(() => expect(posts(api)).toHaveLength(1));
    await act(async () => {
      if (next === 'A-B-A') {
        transitionScanSession('bob', new QueryClient());
        transitionScanSession('alice', new QueryClient());
      } else transitionScanSession(next === 'same-owner' ? 'alice' : next, new QueryClient(), true);
      finish();
    });
    expect(posts(api)[0].init.signal?.aborted).toBe(true);
    expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
    noConsentCheckbox();
    expect(posts(api)).toHaveLength(1);
    expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
  });
}

it('unmount aborts pending delivery without publishing or issuing another request', async () => {
  const api = translationApi();
  let finish!: () => void;
  api.post = () =>
    new Promise((resolve) => {
      finish = () => resolve(json(replyFor()));
    });
  const view = mount(api);
  await translate();
  await waitFor(() => expect(posts(api)).toHaveLength(1));
  view.unmount();
  await act(async () => finish());
  expect(posts(api)[0].init.signal?.aborted).toBe(true);
  expect(posts(api)).toHaveLength(1);
  expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
});

for (const changed of ['index', 'finding', 'text', 'language', 'report'] as const) {
  it(`keyed ${changed} swap discards pending translation and consent before rendering the new scope`, async () => {
    const api = translationApi();
    vi.stubGlobal('fetch', api.fetcher);
    const assessment = finding.advisory!.assessments[0];
    let index = 0,
      id = finding.findingId,
      selected = assessment,
      report = status;
    const content = () => (
      <AdvisoryTranslationScope status={report}>
        <AdvisoryTranslationPanel
          findingId={id}
          vulnerabilityId={finding.cveId}
          assessmentIndex={index}
          assessment={selected}
        />
      </AdvisoryTranslationScope>
    );
    let finish!: () => void;
    api.post = () =>
      new Promise((resolve) => {
        finish = () => resolve(json(replyFor()));
      });
    const view = render(content());
    await translate();
    await waitFor(() => expect(posts(api)).toHaveLength(1));
    if (changed === 'index') index = 1;
    if (changed === 'finding') id = `vuln-${'f'.repeat(64)}`;
    if (changed === 'text')
      selected = {
        ...assessment,
        description: { ...assessment.description, value: 'Different source description' },
      };
    if (changed === 'language') selected = { ...assessment, language: null };
    if (changed === 'report') report = { ...status, updatedAt: '2026-10-23T12:01:00.000Z' };
    view.rerender(content());
    await act(async () => finish());
    expect(posts(api)[0].init.signal?.aborted).toBe(true);
    noConsentCheckbox();
    expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
    expect(posts(api)).toHaveLength(1);
  });
}

it('rejects an initially newer server text even when source, language and provenance still match the displayed original', async () => {
  const newer = {
    ...finding,
    advisory: {
      ...finding.advisory!,
      assessments: [
        {
          ...finding.advisory!.assessments[0],
          description: {
            value: 'Newer description on the server',
            state: 'available' as const,
            redacted: false,
          },
        },
      ],
    },
  };
  const api = translationApi(newer);
  mount(api, finding);
  await screen.findByRole('alert');
  noConsentCheckbox();
  expect(posts(api)).toHaveLength(0);
  expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
});

it('cancel aborts pending delivery and requires a context refresh and new click without retry or refund claims', async () => {
  const api = translationApi();
  let finish!: () => void;
  api.post = () =>
    new Promise((resolve) => {
      finish = () => resolve(json(replyFor()));
    });
  mount(api);
  await translate();
  await waitFor(() => expect(posts(api)).toHaveLength(1));
  fireEvent.click(screen.getByRole('button', { name: 'Отменить ожидание перевода' }));
  await act(async () => finish());
  expect(posts(api)[0].init.signal?.aborted).toBe(true);
  expect(screen.getByRole('alert')).toHaveTextContent('возврат квоты не гарантирован');
  noConsentCheckbox();
  expect(send()).toBeDisabled();
  expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
  expect(posts(api)).toHaveLength(1);
});

it.each([
  [401, 'Сессия изменилась'],
  [403, 'Доступ к переводу этого отчёта не подтверждён'],
])(
  'shows the concrete readiness denial for HTTP %s without sending a translation',
  async (statusCode, message) => {
    const api = translationApi();
    const fetcher: typeof fetch = (input, init) =>
      String(input).endsWith('/readiness')
        ? Promise.resolve(json({ diagnostic: 'private readiness diagnostic' }, statusCode))
        : api.fetcher(input, init);
    mount(api, finding, fetcher);
    expect(await screen.findByRole('alert')).toHaveTextContent(message);
    expect(document.body.textContent).not.toContain('private readiness diagnostic');
    noConsentCheckbox();
    expect(send()).toBeDisabled();
    expect(posts(api)).toHaveLength(0);
    expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
  },
);

it('bounds a noncooperative read, discards its late result and recovers only on manual read without POST', async () => {
  const api = translationApi();
  let finish!: (context: TranslationContext) => void;
  let requestSignal!: AbortSignal;
  const client = createAdvisoryTranslationClient(scanSession(), api.fetcher);
  const read = vi.spyOn(client, 'context').mockImplementationOnce((_scanId, _selection, signal) => {
    requestSignal = signal;
    return new Promise((resolve) => {
      finish = resolve;
    });
  });
  vi.useFakeTimers();
  render(
    <AdvisoryTranslationScope status={status}>
      <AdvisoryTranslationPanel
        findingId={finding.findingId}
        vulnerabilityId={finding.cveId}
        assessmentIndex={0}
        assessment={finding.advisory!.assessments[0]}
        client={client}
      />
    </AdvisoryTranslationScope>,
  );
  await act(async () => {
    await vi.advanceTimersByTimeAsync(45001);
  });
  expect(screen.getByRole('alert')).toHaveTextContent('Ожидание перевода остановлено');
  expect(requestSignal.aborted).toBe(true);
  expect(screen.getByRole('region', { name: /Перевод CVE/ })).toHaveAttribute('aria-busy', 'false');
  noConsentCheckbox();
  expect(send()).toBeDisabled();
  await act(async () => {
    finish(api.context);
  });
  noConsentCheckbox();
  expect(read).toHaveBeenCalledTimes(1);
  vi.useRealTimers();
  fireEvent.click(screen.getByRole('button', { name: 'Обновить условия перевода' }));
  await open();
  noConsentCheckbox();
  expect(send()).toBeEnabled();
  expect(read).toHaveBeenCalledTimes(2);
  expect(posts(api)).toHaveLength(0);
});

it('bounds even a noncooperative translation at 45 seconds and never publishes its late reply or retries', async () => {
  const api = translationApi();
  const client = createAdvisoryTranslationClient(scanSession(), api.fetcher);
  let finish!: () => void;
  const translateRequest = vi.spyOn(client, 'translate').mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = () => resolve({ ...replyFor(api.context), machineTranslated: true, provider: 'OpenRouter' });
      }),
  );
  render(
    <AdvisoryTranslationScope status={status}>
      <AdvisoryTranslationPanel
        findingId={finding.findingId}
        vulnerabilityId={finding.cveId}
        assessmentIndex={0}
        assessment={finding.advisory!.assessments[0]}
        client={client}
      />
    </AdvisoryTranslationScope>,
  );
  await open();
  vi.useFakeTimers();
  fireEvent.click(send());
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });
  expect(translateRequest).toHaveBeenCalledTimes(1);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(44999);
  });
  expect(screen.queryByRole('alert')).toBeNull();
  await act(async () => {
    await vi.advanceTimersByTimeAsync(2);
  });
  expect(screen.getByRole('alert')).toHaveTextContent('Ожидание перевода остановлено');
  expect(translateRequest.mock.calls[0][2].aborted).toBe(true);
  await act(async () => {
    finish();
    await vi.advanceTimersByTimeAsync(86400001);
  });
  expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
  expect(translateRequest).toHaveBeenCalledTimes(1);
});

it('focus rereads only bounded GET context and never translates automatically', async () => {
  const api = translationApi();
  mount(api);
  await open();
  fireEvent.focus(window);
  noConsentCheckbox();
  expect(send()).toBeDisabled();
  await open();
  expect(posts(api)).toHaveLength(0);
  expect(api.requests).toHaveLength(4);
});

it('omitted/redacted/missing text and absent authorized report cannot enable any request', () => {
  const api = translationApi();
  vi.stubGlobal('fetch', api.fetcher);
  const original = finding.advisory!.assessments[0];
  for (const state of ['omitted', 'redacted', 'missing', 'invalid'] as const) {
    const assessment = {
      ...original,
      title: { value: null, state, redacted: state === 'redacted' },
      description: { value: null, state, redacted: state === 'redacted' },
    };
    const view = render(
      <AdvisoryTranslationScope status={status}>
        <AdvisoryTranslationPanel
          findingId={finding.findingId}
          vulnerabilityId={finding.cveId}
          assessmentIndex={0}
          assessment={assessment}
        />
      </AdvisoryTranslationScope>,
    );
    expect(screen.getByRole('button', { name: 'Обновить условия перевода' })).toBeDisabled();
    expect(send()).toBeDisabled();
    view.unmount();
  }
  render(
    <AdvisoryTranslationPanel
      findingId={finding.findingId}
      vulnerabilityId={finding.cveId}
      assessmentIndex={0}
      assessment={original}
    />,
  );
  expect(send()).toBeDisabled();
  expect(api.requests).toHaveLength(0);
});

it('translates only an eligible field and keeps redaction/truncation warnings without restoring hidden text', async () => {
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
  await translate();
  await screen.findByText('Сокращённое описание');
  expect(screen.getByText(/Скрытые поля не переводились/)).toBeVisible();
  expect(screen.getByText(/Исходный текст сокращён; перевод/)).toBeVisible();
  expect(screen.queryByText('Перевод заголовка:')).toBeNull();
});

it('TEMP translation stays a Debian advisory, not an official Russian CVE/NVD record', async () => {
  const temp: VulnFinding = {
    ...finding,
    findingId: `vuln-${'f'.repeat(64)}`,
    cveId: 'TEMP-1234567-ABCDEF',
    ecosystem: 'deb',
  };
  const api = translationApi(temp);
  mount(api, temp);
  await translate();
  await screen.findByText('Пакет содержит уязвимость.');
  expect(screen.getByText('Advisory ID: TEMP-1234567-ABCDEF')).toBeVisible();
  expect(screen.getByText('Debian advisory (не CVE)')).toBeVisible();
  expect(screen.queryByRole('link', { name: /NVD · открыть запись/ })).toBeNull();
  expect(JSON.parse(String(posts(api)[0].init.body)).findingId).toBe(temp.findingId);
});

it('a malicious generated field is never rendered as HTML or Markdown and leaves original visible', async () => {
  const api = translationApi();
  api.post = async () =>
    json({
      ...replyFor(),
      translation: { title: '<script>bad</script>', description: '[нажми](https://example.invalid)' },
    });
  const view = mount(api);
  await translate();
  await screen.findByRole('alert');
  expect(view.container.querySelector('script')).toBeNull();
  expect(screen.queryByRole('link', { name: 'нажми' })).toBeNull();
  expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
});

it('each source has its own assessment index and independent user intent', async () => {
  const first = finding.advisory!.assessments[0];
  const value: VulnFinding = {
    ...finding,
    advisory: { ...finding.advisory!, assessments: [first, { ...first, source: 'ghsa' }] },
  };
  const api = translationApi(value, 1);
  mount(api, value);
  const firstPanel = screen.getByRole('region', { name: /источник nvd, оценка 1/ });
  const secondPanel = screen.getByRole('region', { name: /источник ghsa, оценка 2/ });
  await waitFor(() =>
    expect(within(secondPanel).getByRole('button', { name: 'Перевести на русский' })).toBeEnabled(),
  );
  expect(within(firstPanel).getByRole('button', { name: 'Перевести на русский' })).toBeDisabled();
  expect(screen.queryByRole('checkbox')).toBeNull();
  fireEvent.click(within(secondPanel).getByRole('button', { name: 'Перевести на русский' }));
  await within(secondPanel).findByText('Пакет содержит уязвимость.');
  expect(JSON.parse(String(posts(api)[0].init.body)).assessmentIndex).toBe(1);
  expect(within(firstPanel).queryByText('Пакет содержит уязвимость.')).toBeNull();
});
