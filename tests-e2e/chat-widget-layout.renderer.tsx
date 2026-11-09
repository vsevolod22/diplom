import { createRoot } from 'react-dom/client';
import { QueryClient } from '@tanstack/react-query';
import { ScanChatWidget } from '@/features/scans/ScanChatWidget';
import { transitionScanSession } from '@/shared/api/auth/scanSession';
import type { ChatClient } from '@/shared/api/scans/llmChatClient';
import type { ScanTransport } from '@/shared/api/scans/scanTransport';
import '@/app/styles/index.css';
import '@/features/scans/scan-a1.css';
import '@/pages/scans/scan-detail-a1.css';

// All data is synthetic and in memory: this fixture has no API/provider connection.
const binding = {
  scanId: '00000000-0000-4000-8000-000000000016',
  digest: `sha256:${'a'.repeat(64)}`,
  platform: 'linux/amd64' as const,
  reportVersion: 'b'.repeat(64),
};
const report = { ...binding, reportVersion: 'd'.repeat(64) };
const markdown =
  '**Приоритет исправлений** и *проверка*\n\n- Пересоберите образ\n- Проверьте источники\n\n| Пакет | Состояние |\n| --- | --- |\n| библиотека | требуется проверка |\n\n```text\nпример_команды --проверка\n' +
  'длинная_строка_'.repeat(18) +
  '\n```';
const context = {
  ...binding,
  epoch: '00000000-0000-4000-8000-000000000001',
  revision: 2,
  enabled: true,
  policyVersion: 'c'.repeat(64),
  pending: false,
  limits: { questionBytes: 2048, bodyBytes: 8192 },
  deliveryMode: 'completed-response',
  disclosure: {
    provider: 'OpenRouter',
    model: 'synthetic/free',
    providers: ['synthetic'],
    region: 'global',
    retention: 'no-storage',
    operatorApprovedRouting: true,
    providerComplianceNotProvenByDeclaration: true,
    requestBudgetUsd: 0,
    freeOnly: true,
    maxPrice: { prompt: 0, completion: 0, request: 0 },
    data: 'Synthetic findings only.',
    sentData: 'Synthetic context only.',
    localRetention: 'Synthetic memory only.',
  },
};
const history = {
  ...binding,
  epoch: context.epoch,
  revision: 2,
  decisions: [],
  pending: null,
  retention:
    'Confirmed history persists until separately authorized operator lifecycle; no automatic expiry or reset.',
  turns: [
    {
      id: '00000000-0000-4000-8000-000000000002',
      mutationId: '00000000-0000-4000-8000-000000000003',
      state: 'completed',
      question: 'Что **проверить** в образе?',
      report,
      createdAt: 0,
      reply: { ...report, kind: 'hypothesis', text: markdown, sources: [] },
    },
  ],
};
const forbidden = async () => {
  throw new Error('Mutation/network forbidden in layout fixture');
};
const client = {
  current: () => true,
  context: async () => context,
  history: async () => history,
  usage: async () => null,
  readiness: async () => {
    throw new Error('Synthetic legacy profile');
  },
  chat: forbidden,
  decision: forbidden,
} as unknown as ChatClient;
const transport = {
  results: async () => ({ findings: [], nextCursor: null, coverage: [] }),
} as unknown as ScanTransport;
transitionScanSession('offline-layout-test', new QueryClient(), true);
createRoot(document.getElementById('root')!).render(
  <main className="scan-a1">
    <h1>Синтетический отчёт</h1>
    <button id="report-target">Раздел отчёта</button>
    <ScanChatWidget
      status={{ ...binding, state: 'completed', checks: [], perCheck: {} }}
      transport={transport}
      client={client}
    />
  </main>,
);
