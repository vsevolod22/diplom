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
import { transitionScanSession } from '@/shared/api/auth/scanSession';
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
});
const posts = (api: ReturnType<typeof translationApi>) =>
  api.requests.filter((request) => request.init.method === 'POST');
function mount(api = translationApi(), value = finding) {
  vi.stubGlobal('fetch', api.fetcher);
  const view = render(
    <AdvisoryTranslationScope status={status}>
      <ul>
        <VulnAdvisoryCard finding={value} />
      </ul>
    </AdvisoryTranslationScope>,
  );
  fireEvent.click(screen.getByText(/Подробности /));
  return view;
}
const checkbox = () => screen.getByRole('checkbox', { name: /Разрешаю один запрос перевода/ });
const send = () => screen.getByRole('button', { name: 'Перевести на русский' });
async function open() {
  fireEvent.click(screen.getByRole('button', { name: 'Прочитать условия перевода' }));
  await waitFor(() => expect(checkbox()).toBeEnabled());
}
async function translate() {
  await open();
  fireEvent.click(checkbox());
  fireEvent.click(send());
}

it('opening details and reading conditions never dispatch a translation; separate explicit consent produces one exact POST and preserves original facts', async () => {
  const api = translationApi();
  const original = JSON.stringify(finding);
  mount(api);
  expect(api.requests).toHaveLength(0);
  expect(send()).toBeDisabled();
  await open();
  expect(checkbox()).not.toBeChecked();
  expect(send()).toBeDisabled();
  expect(api.requests.every((request) => request.init.method === 'GET')).toBe(true);
  expect(screen.getByText(/Внешнему провайдеру передаётся разрешённый текст/)).toBeVisible();
  fireEvent.click(checkbox());
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
  expect(checkbox()).not.toBeChecked();
  expect(send()).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Оригинал' }));
  expect(screen.queryByText('Пакет содержит уязвимость.')).not.toBeInTheDocument();
  expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Перевод' }));
  expect(screen.getByText('Пакет содержит уязвимость.')).toBeVisible();
  expect(posts(api)).toHaveLength(1);
  expect(JSON.stringify(finding)).toBe(original);
});

it('uses actual missing-key readiness to disable consent and generation, without a POST or provider probe', async () => {
  const api = translationApi();
  api.ready = readinessWire('missing');
  mount(api);
  fireEvent.click(screen.getByRole('button', { name: 'Прочитать условия перевода' }));
  await screen.findByText(/Серверный ключ не настроен или отсутствует/);
  expect(checkbox()).toBeDisabled();
  expect(send()).toBeDisabled();
  fireEvent.click(send());
  expect(posts(api)).toHaveLength(0);
  expect(api.requests).toHaveLength(2);
  expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
});

for (const errorCode of ['LLM_PROVIDER_UNAVAILABLE', 'LLM_QUOTA_EXCEEDED', 'LLM_TRANSLATION_UNAVAILABLE']) {
  it(`${errorCode} keeps the original, resets consent and never retries or echoes server diagnostics`, async () => {
    const api = translationApi();
    api.post = async () => json({ errorCode, diagnostic: 'private provider diagnostic' }, 503);
    mount(api);
    await translate();
    await screen.findByRole('alert');
    expect(posts(api)).toHaveLength(1);
    expect(checkbox()).not.toBeChecked();
    expect(send()).toBeDisabled();
    expect(screen.queryByText(/Машинный перевод на русский ·/)).toBeNull();
    expect(document.body.textContent).not.toContain('private provider diagnostic');
    expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
  });
}

for (const changed of ['policy', 'source', 'report', 'readiness'] as const) {
  it(`fresh ${changed} change before send prevents POST and requires new consent`, async () => {
    const api = translationApi();
    mount(api);
    await open();
    fireEvent.click(checkbox());
    if (changed === 'policy') api.context = { ...api.context, policyVersion: 'f'.repeat(64) };
    if (changed === 'source') api.context = { ...api.context, sourceVersion: 'f'.repeat(64) };
    if (changed === 'report') api.context = { ...api.context, reportVersion: 'f'.repeat(64) };
    if (changed === 'readiness') api.ready = readinessWire('missing');
    fireEvent.click(send());
    await screen.findByRole('alert');
    expect(posts(api)).toHaveLength(0);
    expect(checkbox()).not.toBeChecked();
    expect(send()).toBeDisabled();
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
  expect(checkbox()).not.toBeChecked();
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
    expect(checkbox()).not.toBeChecked();
    expect(send()).toBeDisabled();
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
    expect(checkbox()).not.toBeChecked();
    expect(send()).toBeDisabled();
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
  fireEvent.click(screen.getByRole('button', { name: 'Прочитать условия перевода' }));
  await screen.findByRole('alert');
  expect(checkbox()).toBeDisabled();
  expect(posts(api)).toHaveLength(0);
  expect(screen.getByText('The package contains a vulnerability.')).toBeVisible();
});

it('cancel aborts pending delivery and requires manual conditions and new consent without retry or refund claims', async () => {
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
  expect(checkbox()).not.toBeChecked();
  expect(send()).toBeDisabled();
  expect(screen.queryByText('Пакет содержит уязвимость.')).toBeNull();
  expect(posts(api)).toHaveLength(1);
});

it('focus clears previous consent/translation and never dispatches automatically', async () => {
  const api = translationApi();
  mount(api);
  await open();
  fireEvent.click(checkbox());
  fireEvent.focus(window);
  expect(checkbox()).not.toBeChecked();
  expect(send()).toBeDisabled();
  expect(posts(api)).toHaveLength(0);
  expect(api.requests).toHaveLength(2);
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
    expect(screen.getByRole('button', { name: 'Прочитать условия перевода' })).toBeDisabled();
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

it('each source has its own assessment index and independent consent', async () => {
  const first = finding.advisory!.assessments[0];
  const value: VulnFinding = {
    ...finding,
    advisory: { ...finding.advisory!, assessments: [first, { ...first, source: 'ghsa' }] },
  };
  const api = translationApi(value, 1);
  mount(api, value);
  const firstPanel = screen.getByRole('region', { name: /источник nvd, оценка 1/ });
  const secondPanel = screen.getByRole('region', { name: /источник ghsa, оценка 2/ });
  fireEvent.click(within(secondPanel).getByRole('button', { name: 'Прочитать условия перевода' }));
  await waitFor(() => expect(within(secondPanel).getByRole('checkbox')).toBeEnabled());
  expect(within(firstPanel).getByRole('checkbox')).toBeDisabled();
  fireEvent.click(within(secondPanel).getByRole('checkbox'));
  fireEvent.click(within(secondPanel).getByRole('button', { name: 'Перевести на русский' }));
  await within(secondPanel).findByText('Пакет содержит уязвимость.');
  expect(JSON.parse(String(posts(api)[0].init.body)).assessmentIndex).toBe(1);
  expect(within(firstPanel).queryByText('Пакет содержит уязвимость.')).toBeNull();
});
