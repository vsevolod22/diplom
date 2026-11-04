import '@testing-library/jest-dom/vitest';
import { QueryClient } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ScanSummaryPanel } from '@/features/scans/ScanSummaryPanel';
import { ScanChatPanel } from '@/features/scans/ScanChatPanel';
import { LlmFindingDetails } from '@/features/scans/LlmFindingDetails';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { saveReportPreferences } from '@/shared/api/preferences/reportPreferences';
import { publicSafeFinding, type LlmFinding } from '@/shared/api/scans/llmFindingContract';
import { imageConfigReport } from '@/shared/api/scans/imageConfigReport';
import {
  createSummaryClient,
  summaryContextSchema,
  summaryReplySchema,
  collectSummarySources,
  verifiedSummarySources,
  type SummaryContext,
  type SummaryReply,
} from '@/shared/api/scans/llmSummaryClient';
import { createChatClient } from '@/shared/api/scans/llmChatClient';
import type { ChatReply } from '@/shared/api/scans/llmChatContract';
import { OPENAI_COST_BASIS, OPENAI_MODEL } from '@/shared/api/scans/llmPublicContract';
import type { ScanStatus, ScanTransport } from '@/shared/api/scans/scanTransport';
import {
  binding,
  chatApi,
  context as freeContext,
  history,
  json,
  sourceTransport,
  turnId,
} from './llmChatFixtures';

function vulnerability(letter: string, name: string, fixed: string | null) {
  const value = publicSafeFinding.parse({
    check: 'vuln',
    findingId: `vuln-${letter.repeat(64)}`,
    severity: 'HIGH',
    cveId: `CVE-2026-${letter === 'a' ? '1234' : letter === 'b' ? '2345' : '3456'}`,
    identifierKind: 'cve',
    ecosystem: 'deb',
    severitySources: ['nvd', 'debian'],
    provenanceRef: `target-${'d'.repeat(64)}`,
    fixedVersionReported: fixed !== null,
    packageName: name,
    installedVersion: '1:3.0.1-1+deb12u1',
    fixedVersion: fixed,
    advisoryState: 'available',
    conflictState: 'present',
    conflicts: ['cvss'],
    limitations: [],
    assessments: [
      {
        source: 'nvd',
        severity: 'HIGH',
        fixedVersionReported: fixed !== null,
        cvss: {
          family: 'v3',
          version: '3.1',
          versionState: 'available',
          reportedScore: 8.1,
          scoreState: 'available',
          vectorState: 'available',
        },
      },
      {
        source: 'ghsa',
        severity: 'MEDIUM',
        fixedVersionReported: fixed !== null,
        cvss: {
          family: 'v3',
          version: '3.0',
          versionState: 'available',
          reportedScore: null,
          scoreState: 'missing',
          vectorState: 'missing',
        },
      },
    ],
  });
  if (value.check !== 'vuln') throw new Error('Expected vulnerability');
  return value;
}
const first = vulnerability('a', 'libssl3', '1:3.0.2-1+deb12u2');
const second = vulnerability('b', 'libcrypto3', null);
const uncited = vulnerability('c', 'not-cited-package', '4.0.0-1');
const secret = (() => {
  const value = publicSafeFinding.parse({
    check: 'secret',
    findingId: 'secret-0-1',
    severity: 'UNKNOWN',
    ruleId: 'rule-0123456789abcdef',
    line: 73,
    evidenceRef: 'result-0-secret-1',
  });
  if (value.check !== 'secret') throw new Error('Expected secret fact');
  return value;
})();
const config = (() => {
  const value = publicSafeFinding.parse({
    check: 'config',
    findingId: `sha256:${'e'.repeat(64)}`,
    severity: 'MEDIUM',
    ruleId: 'IMGCFG_USER_ROOT',
    classification: 'NUMERIC_ROOT',
    configDigest: `sha256:${'f'.repeat(64)}`,
    manifestDigest: binding.digest,
    location: '/config/User',
  });
  if (value.check !== 'config') throw new Error('Expected config fact');
  return value;
})();
const configReport = imageConfigReport.parse({
  checksVersion: 'image-config-user-v1',
  resourcePolicyVersion: 'image-config-policy-v1',
  supportedRuleIds: ['IMGCFG_USER_ROOT'],
  completedRuleIds: ['IMGCFG_USER_ROOT'],
  config: { outcome: 'checked' },
  rules: [{ ruleId: 'IMGCFG_USER_ROOT', outcome: 'checked' }],
  history: { outcome: 'unsupported', reason: 'RULE_NOT_IMPLEMENTED' },
  dockerfile: { outcome: 'unsupported', reason: 'SOURCE_NOT_PROVIDED' },
  iac: { outcome: 'unsupported', reason: 'SOURCE_NOT_PROVIDED' },
  findings: [
    {
      findingId: config.findingId,
      ruleId: config.ruleId,
      severity: config.severity,
      classification: config.classification,
      configDigest: config.configDigest,
      manifestDigest: config.manifestDigest,
      location: config.location,
      category: 'image-config',
      severitySource: 'image-config-user-v1',
      message: 'Image metadata declares numeric UID 0.',
      recommendation: 'Set an explicit non-zero numeric image user; verify runtime identity separately.',
      platform: { os: 'linux', architecture: 'amd64' },
    },
  ],
});
const status: ScanStatus = {
  ...binding,
  state: 'completed',
  checks: ['secret', 'vuln', 'config'],
  config: configReport,
  perCheck: {
    secret: { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 1 },
    vuln: { check: 'vuln', coverage: 'image', outcome: 'checked', findingCount: 3 },
    config: { check: 'config', coverage: 'image', outcome: 'checked', findingCount: 1 },
  },
};
function transport(): ScanTransport {
  return {
    ...sourceTransport(),
    results: vi.fn<ScanTransport['results']>(async () => ({
      findings: [
        {
          findingId: secret.findingId,
          category: 'secret',
          severity: 'unknown',
          ruleId: secret.ruleId,
          line: secret.line,
          evidenceRef: secret.evidenceRef,
        },
      ],
      nextCursor: null,
      coverage: [{ check: 'Secrets', status: 'checked', findingCount: 1 }],
    })),
    vuln: vi.fn<ScanTransport['vuln']>(async () => ({
      outcome: 'checked',
      coverage: 'image',
      image: `registry-1.docker.io/library/debian@${binding.digest}`,
      platform: 'linux/amd64',
      findingCount: 3,
      scannerVersion: '0.69.3',
      checkedAt: '2026-01-02T00:00:00.000Z',
      findings: [first, second, uncited].map((f) => ({
        findingId: f.findingId,
        cveId: f.cveId,
        ecosystem: f.ecosystem,
        packageName: f.packageName!,
        installedVersion: f.installedVersion!,
        fixedVersion: f.fixedVersion!,
        severity: f.severity,
      })),
      nextCursor: null,
    })),
  };
}
const prose = [
  'Сначала проверьте подтверждённые находки и ограничьте доступ.',
  'Сопоставьте состояние пакета и настройки пользователя образа.',
  'После исправления повторите проверку исходного отчёта.',
];
const facts: LlmFinding[] = [first, second, secret, config];
const reply: SummaryReply = summaryReplySchema.parse({
  ...binding,
  hypotheses: [
    { kind: 'hypothesis', text: prose[0], citations: [first.findingId, secret.findingId] },
    { kind: 'hypothesis', text: prose[1], citations: [second.findingId, config.findingId] },
    { kind: 'hypothesis', text: prose[2], citations: [first.findingId] },
  ],
  scannerFacts: facts,
});
function context(provider: 'OpenAI' | 'OpenRouter'): SummaryContext {
  if (freeContext.disclosure?.provider !== 'OpenRouter') throw new Error('Expected OpenRouter fixture');
  const disclosure = Object.fromEntries(
    Object.entries(freeContext.disclosure).filter(([key]) => !['sentData', 'localRetention'].includes(key)),
  );
  return summaryContextSchema.parse({
    ...binding,
    enabled: true,
    policyVersion: 'c'.repeat(64),
    summaryResultRead: true,
    disclosure:
      provider === 'OpenRouter'
        ? disclosure
        : {
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
          },
  });
}
function summaryApi(provider: 'OpenAI' | 'OpenRouter', value: unknown = reply) {
  const calls: Array<{ path: string; method: string }> = [];
  const fetcher = vi.fn<typeof fetch>(async (input, init) => {
    const path = String(input),
      method = init?.method ?? 'GET';
    calls.push({ path, method });
    if (method !== 'GET') throw new Error('Unexpected generation in recovery-only test');
    if (path === `/api/v1/browser/scans/${binding.scanId}/llm/context`) return json(context(provider));
    if (path === `/api/v1/browser/scans/${binding.scanId}/llm/summary`) return json(value);
    throw new Error(`Unexpected controlled route: ${path}`);
  });
  return { calls, fetcher };
}
const navigateSource = vi.fn(() => true);
function mountSummary(provider: 'OpenAI' | 'OpenRouter', value: unknown = reply) {
  const api = summaryApi(provider, value);
  const view = render(
    <ScanSummaryPanel
      status={status}
      transport={transport()}
      client={createSummaryClient(scanSession(), api.fetcher)}
        onNavigateSource={navigateSource}
    />,
  );
  return { api, view };
}
function paragraphDetails(index: number) {
  const sources = screen.getByLabelText(`Источники абзаца ${index + 1}`);
  const details = sources.closest('details');
  if (!details) throw new Error('Expected collapsed explanation with paragraph-local sources');
  const label = within(details).getByText('Прочитать объяснение и проверить его источники');
  return { label, details, sources, block: sources.parentElement! };
}
function chatReply(): ChatReply {
  return {
    ...binding,
    kind: 'hypothesis',
    text: `${prose[0]}\n\n${prose[1]}`,
    sources: facts.map((finding) => ({ ...binding, finding })),
  };
}
function storedChat(value = chatReply()) {
  const api = chatApi();
  api.head = {
    ...history,
    turns: [
      {
        id: turnId,
        mutationId: turnId,
        question: 'Что проверить в первую очередь?',
        report: binding,
        createdAt: 0,
        state: 'completed',
        reply: value,
      },
    ],
  };
  return api;
}
beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  transitionScanSession('citation-owner', new QueryClient(), true);
  saveReportPreferences({ language: 'original', autoSummary: false });
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it.each(['OpenAI', 'OpenRouter'] as const)(
  '%s recovered summary maps EACH paragraph only to its exact validated findings and keeps facts outside prose',
  async (provider) => {
    const { api } = mountSummary(provider);
    await screen.findByText(prose[0]);
    const output = screen.getByLabelText('ИИ-разбор отчёта');
    expect(within(output).getAllByLabelText(/^Источники абзаца /)).toHaveLength(3);
    expect(paragraphDetails(0).details.open).toBe(false);
    fireEvent.click(paragraphDetails(0).label);
    expect(paragraphDetails(0).details.open).toBe(true);
    for (let i = 0; i < 3; i++) {
      const { sources, block } = paragraphDetails(i);
      expect(block.querySelector(':scope > p')?.textContent).toBe(prose[i]);
      expect(sources.querySelectorAll(':scope > ul > li')).toHaveLength(reply.hypotheses[i].citations.length);
    }
    const a = paragraphDetails(0).sources,
      b = paragraphDetails(1).sources,
      again = paragraphDetails(2).sources;
    expect(within(a).getByText('libssl3', { selector: 'code' })).toBeVisible();
    expect(a).toHaveTextContent(secret.ruleId);
    const secretLink = within(a).getByRole('link', { name: 'Открыть раздел «Возможные секреты»' });
    expect(secretLink).toHaveAttribute('href', '#scan-report-secrets');
    fireEvent.click(secretLink);
    expect(navigateSource).toHaveBeenLastCalledWith('secret');
    expect(a).not.toHaveTextContent('libcrypto3');
    expect(a).not.toHaveTextContent('IMGCFG_USER_ROOT');
    expect(within(b).getByText('libcrypto3', { selector: 'code' })).toBeVisible();
    expect(b).toHaveTextContent('IMGCFG_USER_ROOT');
    const configLink = within(b).getByRole('link', { name: 'Открыть раздел «Настройки образа»' });
    expect(configLink).toHaveAttribute('href', '#scan-report-config');
    fireEvent.click(configLink);
    expect(navigateSource).toHaveBeenLastCalledWith('config');
    expect(b).not.toHaveTextContent('libssl3');
    expect(b).not.toHaveTextContent(secret.ruleId);
    expect(again.querySelectorAll(':scope > ul > li')).toHaveLength(1);
    expect(again).toHaveTextContent('libssl3');
    expect(again).not.toHaveTextContent(secret.ruleId);
    expect(output).not.toHaveTextContent('not-cited-package');
    expect(within(a).getByText(first.installedVersion!, { selector: 'code' })).toBeVisible();
    expect(within(a).getByText(first.fixedVersion!, { selector: 'code' })).toBeVisible();
    expect(a).toHaveTextContent('Источники расходятся. Сверьте отдельные оценки в отчёте');
    expect(b).toHaveTextContent('Исправленная версия неизвестна');
    const vulnLink = within(again).getByRole('link', { name: 'Открыть раздел «Уязвимости пакетов»' });
    expect(vulnLink).toHaveAttribute('href', '#scan-report-vulnerabilities');
    fireEvent.click(vulnLink);
    expect(navigateSource).toHaveBeenLastCalledWith('vuln');
    expect(api.calls.every((call) => call.method === 'GET')).toBe(true);
  },
);

it('verification preserves full validated server findings rather than only pooled labels/IDs', async () => {
  const sources = await collectSummarySources(transport(), status, new AbortController().signal);
  expect(sources.every((source) => source.finding === undefined)).toBe(true);
  const verified = verifiedSummarySources(summaryReplySchema.parse(reply), sources);
  expect(verified).toHaveLength(4);
  for (const fact of facts)
    expect(verified.find((source) => source.findingId === fact.findingId)?.finding).toEqual(fact);
  expect(verified.some((source) => source.findingId === uncited.findingId)).toBe(false);
});

it.each(['OpenAI', 'OpenRouter'] as const)(
  '%s remount/new same-owner session restores paragraph details by GET without generation or consent',
  async (provider) => {
    const { api, view } = mountSummary(provider);
    await screen.findByText(prose[0]);
    view.unmount();
    transitionScanSession('citation-owner', new QueryClient(), true);
    render(
      <ScanSummaryPanel
        status={status}
        transport={transport()}
        client={createSummaryClient(scanSession(), api.fetcher)}
        onNavigateSource={navigateSource}
      />,
    );
    await screen.findByText(prose[1]);
    fireEvent.click(paragraphDetails(1).label);
    expect(paragraphDetails(1).sources).toHaveTextContent('libcrypto3');
    expect(api.calls.filter((call) => call.path.endsWith('/summary'))).toHaveLength(2);
    expect(api.calls.every((call) => call.method === 'GET')).toBe(true);
  },
);

it.each([
  'unknown-citation',
  'wrong-check',
  'duplicate-facts',
  'model-fact-in-paragraph',
  'foreign-scan',
] as const)('summary %s never publishes prose/details or falls back to POST', async (kind) => {
  const raw = structuredClone(reply);
  if (kind === 'unknown-citation') raw.hypotheses[0].citations = [uncited.findingId];
  if (kind === 'wrong-check')
    raw.scannerFacts = raw.scannerFacts.map((fact) =>
      fact.findingId === first.findingId
        ? { findingId: first.findingId, check: 'secret', severity: 'UNKNOWN' }
        : fact,
    );
  if (kind === 'duplicate-facts') raw.scannerFacts.push(raw.scannerFacts[0]);
  if (kind === 'foreign-scan') raw.scanId = '00000000-0000-4000-8000-000000000099';
  const wire: unknown =
    kind === 'model-fact-in-paragraph'
      ? { ...raw, hypotheses: [{ ...raw.hypotheses[0], packageName: 'model-invented-package' }] }
      : raw;
  const { api } = mountSummary('OpenAI', wire);
  await screen.findByRole('alert');
  expect(screen.queryByText(prose[0])).toBeNull();
  expect(screen.queryByLabelText(/^Источники абзаца /)).toBeNull();
  expect(screen.queryByText('model-invented-package')).toBeNull();
  expect(api.calls.every((call) => call.method === 'GET')).toBe(true);
});

it('OpenRouter chat retains whole-answer attribution without inventing paragraph citation mapping and restores all exact server details without POST', async () => {
  const api = storedChat();
  const view = render(
    <ScanChatPanel
      status={status}
      transport={transport()}
      client={createChatClient(scanSession(), api.fetcher)}
      onNavigateSource={navigateSource}
    />,
  );
  await screen.findByRole('heading', { name: 'Ответ · проверьте по источникам' });
  expect(screen.queryByLabelText(/^Источники абзаца /)).toBeNull();
  const details = screen.getByLabelText('Источники ответа');
  expect(details.querySelectorAll(':scope > ul > li')).toHaveLength(4);
  for (const fact of facts) {
    const row = document.getElementById(`chat-${turnId}-${fact.findingId}`);
    expect(row).not.toBeNull();
    expect(details.contains(row)).toBe(true);
    expect(row).toHaveTextContent('Источник текущего отчёта, проверен по результатам сканирования');
    if (fact.check === 'vuln') {
      expect(within(row!).getByText(fact.packageName!, { selector: 'code' })).toBeVisible();
      expect(row).toHaveTextContent(fact.installedVersion!);
      expect(within(row!).getByRole('link', { name: 'Открыть раздел «Уязвимости пакетов»' })).toHaveAttribute('href', '#scan-report-vulnerabilities');
      expect(row).toHaveTextContent('Подходящий тег и безопасность образа не установлены');
    } else {
      const category = fact.check === 'secret' ? 'Возможные секреты' : 'Настройки образа';
      const link = within(row!).getByRole('link', { name: `Открыть раздел «${category}»` });
      expect(link).toHaveAttribute('href', fact.check === 'secret' ? '#scan-report-secrets' : '#scan-report-config');
      fireEvent.click(link);
      expect(navigateSource).toHaveBeenLastCalledWith(fact.check);
    }
  }
  expect(details).not.toHaveTextContent('not-cited-package');
  expect(screen.queryByText('model-invented-package')).toBeNull();
  view.unmount();
  transitionScanSession('citation-owner', new QueryClient(), true);
  render(
    <ScanChatPanel
      status={status}
      transport={transport()}
      client={createChatClient(scanSession(), api.fetcher)}
      onNavigateSource={navigateSource}
    />,
  );
  await screen.findByText('Источники (4)');
  expect(api.requests.every((request) => request.init.method === 'GET')).toBe(true);
});

it.each(['unknown-owned-finding', 'foreign-source-report', 'model-field-in-source'] as const)(
  'chat %s refuses retained reply instead of presenting it as current scanner facts',
  async (kind) => {
    const raw = chatReply();
    if (kind === 'unknown-owned-finding')
      raw.sources[0] = { ...binding, finding: { ...first, findingId: `vuln-${'9'.repeat(64)}` } };
    if (kind === 'foreign-source-report')
      raw.sources[0] = { ...raw.sources[0], reportVersion: 'f'.repeat(64) };
    const api = storedChat(raw);
    const fetcher = vi.fn<typeof fetch>(async (input, init) => {
      const response = await api.fetcher(input, init);
      if (kind !== 'model-field-in-source' || !String(input).endsWith('/history')) return response;
      const value = await response.json();
      value.turns[0].reply.sources[0].finding.modelExplanation = 'Выдуманное поле модели';
      return json(value);
    });
    render(
      <ScanChatPanel
        status={status}
        transport={transport()}
        client={createChatClient(scanSession(), fetcher)}
      />,
    );
    await screen.findByRole('alert');
    expect(screen.queryByRole('heading', { name: 'Ответ · проверьте по источникам' })).toBeNull();
    expect(screen.queryByText('Источники (4)')).toBeNull();
    expect(api.requests.every((request) => request.init.method === 'GET')).toBe(true);
  },
);

it('absent exact fix/CVSS/secret line values remain explicitly unknown rather than inferred from narrative', () => {
  const unknownSecret = publicSafeFinding.parse({ ...secret, line: null });
  const withoutPackage = Object.fromEntries(
    Object.entries(second).filter(
      ([key]) => !['packageName', 'installedVersion', 'fixedVersion'].includes(key),
    ),
  );
  const unknownFix = publicSafeFinding.parse({ ...withoutPackage, fixedVersionReported: true });
  render(
    <>
      <LlmFindingDetails finding={unknownSecret} />
      <LlmFindingDetails finding={unknownFix} />
    </>,
  );
  expect(screen.getByText(/Строка: не указана/)).toBeVisible();
  expect(screen.getByText(/точное значение не включено в источник/)).toBeVisible();
  expect(screen.getByText(/оценка недоступна/)).toBeVisible();
  expect(screen.queryByText(first.fixedVersion!)).toBeNull();
});
