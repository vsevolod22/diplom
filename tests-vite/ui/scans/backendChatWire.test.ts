import { QueryClient } from '@tanstack/react-query';
import { beforeEach, expect, it, vi } from 'vitest';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { createChatClient } from '@/shared/api/scans/llmChatClient';
import { chatContextSchema, chatReadinessSchema, chatResultSchema } from '@/shared/api/scans/llmChatContract';
import { binding, context, epoch, history, json, receipt, reply, turnId } from './llmChatFixtures';
import {
  policyModule,
  publicDisclosure,
  publicMetadata,
  publicPolicy,
  readinessWire,
  unknownPublicMetadata,
} from './publicLlmFixtures';

// Invoke the actual context producer, with in-memory seams only. No auth/store/key/network side effects.
vi.mock('../../../server/api/src/auth/auth.store.js', () => ({ AuthStore: class {} }));
vi.mock('../../../server/api/src/auth/auth.controller.js', () => ({
  originForRequest: vi.fn(),
  tokenFrom: vi.fn(),
}));
vi.mock('../../../server/api/src/llm/browser-identity.js', () => ({ browserIdentity: vi.fn() }));
vi.mock('../../../server/api/src/llm/history-runtime.js', () => ({ HistoryRuntime: class {} }));
vi.mock('../../../server/api/src/llm/history-ingress.js', () => ({ historyBodyParsed: vi.fn() }));
const { HistoryService } = await import(
  /* @vite-ignore */ '../../../server/api/src/llm/' + 'history.service.ts'
);

beforeEach(() => transitionScanSession('alice', new QueryClient(), true));
function backendContext(metadata: object = publicMetadata, policy: unknown = publicPolicy) {
  const scope = {
    reports: { read: () => ({ ...binding, profile: 'public-hub-amd64-v1', ...metadata }) },
    runtime: { store: () => ({ snapshot: () => history }) },
    providerRuntime: { policy: () => policy },
    access: () => ({ identity: { subject: 'alice' } }),
    guard: (_access: unknown, action: () => unknown) => action(),
    result: (_access: unknown, _report: unknown, _head: unknown, value: unknown) => ({ value }),
  };
  return HistoryService.prototype.context.call(scope, {}, binding.scanId).value;
}

it('accepts the actual HistoryService.context public wire via the real cookie client: Xing/Phala, complete counts and saved coverage', async () => {
  const wire = backendContext();
  const fetcher = vi.fn(async () => json(wire));
  const client = createChatClient(scanSession(), fetcher);
  const result = await client.context(binding.scanId, new AbortController().signal);
  expect(result).toMatchObject({ ...publicMetadata, disclosure: publicDisclosure });
  expect(result.disclosure?.model).toBe('xingchen-agi/xing4.0-29b-a4b:free');
  expect(result.disclosure?.providers).toEqual(['phala']);
  expect(fetcher.mock.calls).toHaveLength(1);
  expect(chatContextSchema.parse(wire)).toEqual(wire);
});

it('accepts only the two exact approved pairs, never mixed pairs, extra providers, paid caps or arbitrary profiles', () => {
  for (const [model, providers] of [
    ['xingchen-agi/xing4.0-29b-a4b:free', ['phala']],
    ['apodex/apodex-1.1-mini:free', ['novita/bf16']],
  ] as const) {
    const wire = backendContext(publicMetadata, { ...publicPolicy, model, providers });
    expect(chatContextSchema.safeParse(wire).success).toBe(true);
    expect(policyModule.supportedFreeProfile(model, providers)).toBe(true);
  }
  for (const patch of [
    { providers: ['novita/bf16'] },
    { model: 'apodex/apodex-1.1-mini:free' },
    { providers: ['phala', 'novita/bf16'] },
    { model: 'openrouter/free' },
    { maxPrice: { prompt: 1, completion: 0, request: 0 } },
    { freeOnly: false },
  ])
    expect(
      chatContextSchema.safeParse({ ...backendContext(), disclosure: { ...publicDisclosure, ...patch } })
        .success,
    ).toBe(false);
});

it('strictly validates public metadata on both context and default JSON chatResult, including selected-vs-whole counts', () => {
  const wire = backendContext();
  const response = {
    ...binding,
    epoch,
    revision: 2,
    turnId,
    deliveryMode: 'completed-response',
    reply: {
      ...reply,
      sources: [
        {
          ...binding,
          finding: {
            check: 'vuln',
            findingId: `vuln-${'f'.repeat(64)}`,
            cveId: 'TEMP-1234567-ABCDEF',
            identifierKind: 'debian-temp',
            ecosystem: 'deb',
            severity: 'UNKNOWN',
            severitySources: ['debian'],
            provenanceRef: `target-${'d'.repeat(64)}`,
            fixedVersionReported: false,
            advisoryState: 'unknown',
          },
        },
      ],
    },
    usage: receipt,
    ...publicMetadata,
    contextSelection: {
      findings: 51,
      explanations: 0,
      selectedFindingIds: [`vuln-${'f'.repeat(64)}`],
    },
  };
  expect(chatResultSchema.parse(response)).toEqual(response);
  expect(
    chatResultSchema.safeParse({
      ...response,
      findingCount: undefined,
      findingCounts: undefined,
      identifierCounts: undefined,
      coverage: undefined,
      contextSelection: undefined,
    }).success,
  ).toBe(false);
  for (const patch of [
    { findingCount: 51 },
    { findingCounts: undefined },
    { coverage: undefined },
    { identifierCounts: undefined },
    { identifierCounts: { cve: 52, debianTemp: 1 } },
    { rawEvidence: 'PRIVATE_CANARY' },
    {
      findingCounts: {
        ...publicMetadata.findingCounts,
        bySeverity: { ...publicMetadata.findingCounts.bySeverity, UNKNOWN: 51 },
      },
    },
    {
      coverage: {
        ...publicMetadata.coverage,
        vuln: { ...publicMetadata.coverage.vuln, rawOutput: 'PRIVATE_CANARY' },
      },
    },
  ]) {
    expect(chatContextSchema.safeParse({ ...wire, ...patch }).success).toBe(false);
    expect(chatResultSchema.safeParse({ ...response, ...patch }).success).toBe(false);
  }
  for (const contextSelection of [
    undefined,
    { findings: 52, explanations: 0, selectedFindingIds: [`vuln-${'f'.repeat(64)}`] },
    { findings: 51, explanations: 0, selectedFindingIds: ['secret-999-999'] },
  ]) {
    expect(chatResultSchema.safeParse({ ...response, contextSelection }).success).toBe(false);
  }
});

it('keeps public unknown coverage distinct from checked zero, and accepts history context when generation policy is absent', () => {
  const unknownWire = backendContext(unknownPublicMetadata, null);
  expect(chatContextSchema.parse(unknownWire)).toMatchObject({
    enabled: false,
    disclosure: null,
    findingCount: 0,
    coverage: { vuln: { outcome: 'unknown' } },
  });
  expect(
    chatContextSchema.safeParse({ ...unknownWire, identifierCounts: { cve: 0, debianTemp: 0 } }).success,
  ).toBe(false);
  expect(chatContextSchema.safeParse(context).success).toBe(true);
});

it('parses the production readiness result without claiming provider verification, and rejects secret/contradictory fields', async () => {
  const wire = readinessWire('missing');
  const fetcher = vi.fn(async () => json(wire));
  const result = await createChatClient(scanSession(), fetcher).readiness(
    binding.scanId,
    new AbortController().signal,
  );
  expect(result).toMatchObject({
    localReady: false,
    generationVerified: false,
    blockers: ['public-key-required'],
    acceptsCredentials: false,
  });
  for (const patch of [
    { generationVerified: true },
    { localReady: true },
    { credential: 'metadata-valid' },
    { blockers: [] },
    { apiKey: 'PRIVATE_CANARY' },
    { provider: { ...wire.provider, liveVerified: true } },
  ]) {
    expect(chatReadinessSchema.safeParse({ ...wire, ...patch }).success).toBe(false);
  }
  expect(chatReadinessSchema.safeParse(readinessWire()).success).toBe(true);
});
