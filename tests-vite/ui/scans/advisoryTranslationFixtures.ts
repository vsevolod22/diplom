import { vi } from 'vitest';
import type { VulnFinding, ScanStatus } from '@/shared/api/scans/scanTransport';
import {
  translationContextSchema,
  type TranslationContext,
} from '@/shared/api/scans/advisoryTranslationContract';
import { binding, json } from './llmChatFixtures';
import { publicPolicy, readinessWire } from './publicLlmFixtures';

// Use the backend's actual non-secret contract producers, never its runtime or provider.
export const backendTranslation = await import(
  /* @vite-ignore */ '../../../server/api/src/llm/' + 'translation-contract.ts'
);
export const finding: VulnFinding = {
  findingId: `vuln-${'d'.repeat(64)}`,
  cveId: 'CVE-2026-1234',
  ecosystem: 'apk',
  packageName: 'busybox',
  installedVersion: '1.2',
  fixedVersion: '1.3',
  severity: 'HIGH',
  severitySources: ['nvd'],
  provenanceRef: `target-${'e'.repeat(64)}`,
  advisory: {
    schemaVersion: 1,
    state: 'available',
    conflicts: [],
    conflictState: 'none',
    limitations: [],
    references: [],
    assessments: [
      {
        source: 'nvd',
        provenanceRef: `target-${'e'.repeat(64)}`,
        language: 'en',
        title: { value: 'Package issue', state: 'available', redacted: false },
        description: { value: 'The package contains a vulnerability.', state: 'available', redacted: false },
        severity: 'HIGH',
        fixedVersion: '1.3',
        cvss: null,
      },
    ],
  },
};
export const status: ScanStatus = { ...binding, state: 'completed' };
export function contextFor(value = finding, assessmentIndex = 0): TranslationContext {
  const selected = backendTranslation.selectedTranslation(value.advisory, assessmentIndex, value.cveId);
  return translationContextSchema.parse({
    ...binding,
    findingId: value.findingId,
    assessmentIndex,
    sourceVersion: selected.sourceVersion,
    source: selected.source,
    targetLanguage: 'ru',
    enabled: true,
    policyVersion: backendTranslation.translationPolicy(publicPolicy),
    disclosure: backendTranslation.translationDisclosure(publicPolicy),
  });
}
export function replyFor(context = contextFor()) {
  const {
    scanId,
    digest,
    platform,
    reportVersion,
    findingId,
    assessmentIndex,
    sourceVersion,
    source,
    targetLanguage,
  } = context;
  return {
    scanId,
    digest,
    platform,
    reportVersion,
    findingId,
    assessmentIndex,
    sourceVersion,
    source,
    targetLanguage,
    translation: { title: 'Проблема пакета', description: 'Пакет содержит уязвимость.' },
    machineTranslated: true,
    model: publicPolicy.model,
    provider: 'OpenRouter',
    generatedAt: '2026-10-23T12:00:00.000Z',
  };
}
export function translationApi(value = finding, index = 0) {
  const api = {
    context: contextFor(value, index),
    ready: readinessWire(),
    requests: [] as Array<{ path: string; init: RequestInit }>,
    post: async (): Promise<Response> => json(replyFor(api.context)),
    fetcher: vi.fn<typeof fetch>(),
  };
  api.fetcher.mockImplementation(async (input, init) => {
    const path = String(input);
    api.requests.push({ path, init: init ?? {} });
    if (path.endsWith('/readiness')) return json(api.ready);
    if (path.includes('/translation/context?')) return json(api.context);
    if (path.endsWith('/translation') && init?.method === 'POST') return api.post();
    throw new Error('Unexpected translation route');
  });
  return api;
}
