import { vi } from 'vitest';
import { binding, chatApi, context, json } from './llmChatFixtures';
import { v2Evidence } from './reportViewSynthetic';

// Actual non-secret policy disclosure/readiness producers. No environment, key or provider access.
export const policyModule = await import(/* @vite-ignore */ '../../../server/api/src/llm/' + 'policy.ts');
export const readinessModule = await import(
  /* @vite-ignore */ '../../../server/api/src/llm/' + 'public-readiness.ts'
);
export const publicPolicy = {
  version: 'c'.repeat(64),
  model: 'xingchen-agi/xing4.0-29b-a4b:free',
  providers: ['phala'],
  region: 'global',
  retention: 'no-storage',
  freeOnly: true,
  budgetUsd: 0,
  inputPricePerMillion: 0,
  outputPricePerMillion: 0,
  requestPriceUsd: 0,
  timeoutMs: 30000,
  requestBytes: 262144,
  responseBytes: 65536,
  findings: 1000,
  outputTokens: 2048,
};
const unknown = { outcome: 'unknown', reason: 'NOT_REPORTED' };
export const publicMetadata = {
  findingCount: 52,
  findingCounts: {
    byCheck: { secret: null, sbom: null, vuln: 52, config: null },
    bySeverity: { UNKNOWN: 52, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
  },
  identifierCounts: { cve: 51, debianTemp: 1 },
  coverage: {
    secret: { outcome: 'unknown', reason: 'CHECK_NOT_REQUESTED' },
    sbom: { outcome: 'unknown', reason: 'CHECK_NOT_REQUESTED' },
    config: { outcome: 'unknown', reason: 'CHECK_NOT_REQUESTED' },
    vuln: {
      outcome: 'checked',
      scope: 'image',
      reason: null,
      errorCode: null,
      findingCount: 52,
      scannerVersion: '0.69.3',
      checkedAt: '2026-01-02T00:00:00.000Z',
      os: { outcome: 'checked', scope: 'image', reason: null, errorCode: null },
      node: { outcome: 'unsupported', scope: 'image', reason: 'NODE_INVENTORY_UNKNOWN', errorCode: null },
      db: Object.fromEntries(Object.entries(v2Evidence().db).filter(([key]) => key !== 'source')),
      dbPolicy: v2Evidence().dbPolicy,
    },
  },
};
export const unknownPublicMetadata = {
  findingCount: 0,
  findingCounts: {
    byCheck: { secret: null, sbom: null, vuln: null, config: null },
    bySeverity: { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
  },
  coverage: {
    secret: unknown,
    sbom: unknown,
    vuln: { outcome: 'unknown', reason: 'NO_RESULT' },
    config: unknown,
  },
};
export const publicDisclosure = {
  ...policyModule.disclosure(publicPolicy),
  sentData:
    'Cleaned question, all user history/accepted decisions and selected findings with complete coverage.',
  localRetention:
    'Durable owner+scan history until separately authorized operator lifecycle; capacity can refuse; context cache only, not output cache.',
};
export const readinessWire = (
  credential = 'metadata-valid',
  quota = true,
  history = true,
  policy: typeof publicPolicy | null = publicPolicy,
) => ({
  ...binding,
  ...readinessModule.publicReadiness(policy, credential, quota, history),
});
export function publicChatApi(metadata: object = publicMetadata) {
  const api = chatApi();
  // The client parses the wire; do not narrow this fixture to the old frontend type.
  api.policy = { ...context, ...metadata, disclosure: publicDisclosure };
  const baseFetch = api.fetcher;
  api.fetcher = vi.fn(async (input, init) => {
    if (String(input).endsWith('/readiness')) {
      api.requests.push({ path: String(input), init: init ?? {} });
      return json(readinessWire());
    }
    return baseFetch(input, init);
  });
  return api;
}
