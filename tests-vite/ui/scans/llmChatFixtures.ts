import { vi } from 'vitest';
import type { ChatContext, ChatHistory, ChatReply, ChatSource } from '@/shared/api/scans/llmChatContract';
import type { ScanStatus, ScanTransport } from '@/shared/api/scans/scanTransport';

export const scanId = '00000000-0000-4000-8000-000000000016';
export const epoch = '00000000-0000-4000-8000-000000000001';
export const turnId = '00000000-0000-4000-8000-000000000002';
export const binding = {
  scanId,
  digest: `sha256:${'a'.repeat(64)}`,
  platform: 'linux/amd64' as const,
  reportVersion: 'b'.repeat(64),
};
export const context: ChatContext = {
  ...binding,
  epoch,
  revision: 0,
  enabled: true,
  policyVersion: 'c'.repeat(64),
  pending: false,
  limits: { questionBytes: 2048, bodyBytes: 8192 },
  deliveryMode: 'completed-response',
  disclosure: {
    provider: 'OpenRouter',
    model: 'apodex/apodex-1.1-mini:free',
    providers: ['novita/bf16'],
    region: 'global',
    retention: 'no-storage',
    operatorApprovedRouting: true,
    providerComplianceNotProvenByDeclaration: true,
    requestBudgetUsd: 0,
    freeOnly: true,
    maxPrice: { prompt: 0, completion: 0, request: 0 },
    data: 'Sanitized scanner findings and coverage; no raw evidence or credentials.',
    sentData:
      'Cleaned question, all user history/accepted decisions and selected findings with complete coverage.',
    localRetention:
      'Durable owner+scan history until separately authorized operator lifecycle; capacity can refuse; context cache only, not output cache.',
  },
};
export const source: ChatSource = {
  ...binding,
  finding: {
    check: 'secret',
    findingId: 'secret-0-1',
    severity: 'UNKNOWN',
    ruleId: 'rule-0000000000000000',
    line: 1,
    evidenceRef: 'result-0-secret-1',
  },
};
export const reply: ChatReply = {
  ...binding,
  kind: 'hypothesis',
  text: '**Проверьте** исходную находку',
  sources: [source],
};
export const retention =
  'Confirmed history persists until separately authorized operator lifecycle; no automatic expiry or reset.' as const;
export const history: ChatHistory = {
  ...binding,
  epoch,
  revision: 0,
  turns: [],
  decisions: [],
  pending: null,
  retention,
};
export const status: ScanStatus = {
  scanId,
  digest: binding.digest,
  platform: binding.platform,
  state: 'completed',
  checks: ['secret'],
  perCheck: { secret: { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 2 } },
};
export const json = (value: unknown, code = 200) =>
  new Response(JSON.stringify(value), { status: code, headers: { 'Content-Type': 'application/json' } });
export function sourceTransport() {
  return {
    results: vi.fn(async (_id: string, cursor?: string) => ({
      findings: [
        {
          findingId: cursor ? 'secret-0-1' : 'secret-0-0',
          category: 'secret',
          ruleId: 'rule-0000000000000000',
          severity: 'unknown',
        },
      ],
      nextCursor: cursor ? null : '1',
      coverage: [{ check: 'Secrets', status: 'checked', findingCount: 2 }],
    })),
  } as unknown as ScanTransport;
}
const counters = {
  limits: { input: 10000, output: 10000, costMicros: 0 },
  used: { input: 100, output: 10, costMicros: 0 },
  held: { input: 20, output: 20, costMicros: 0 },
  carried: { input: 30, output: 30, costMicros: 0 },
  remaining: { input: 9850, output: 9940, costMicros: 0 },
  warning: false,
  exhausted: false,
};
export const usage = {
  ...binding,
  available: true,
  reason: 'ready',
  admission: { status: 'unavailable' },
  window: { start: 0, end: 86400000 },
  signals: [],
  user: counters,
  scan: counters,
};
export const receipt = {
  input: 100,
  output: 10,
  costMicros: 0 as const,
  source: 'server-validated-provider-reported-not-invoice' as const,
};
export function frameLines(mutationId: string, text = reply.text, revision = 2) {
  const common = {
    ...binding,
    epoch,
    revision,
    mutationId,
    turnId,
    v: 1,
    deliveryMode: 'validated-completed-reply',
    nativeProviderStream: false,
  };
  return [
    { ...common, type: 'usage', seq: 0, usage: receipt },
    { ...common, type: 'citation', seq: 1, index: 0, source },
    { ...common, type: 'delta', seq: 2, index: 0, text },
    {
      ...common,
      type: 'done',
      seq: 3,
      outcome: 'completed',
      kind: 'hypothesis',
      textBytes: new TextEncoder().encode(text).length,
      citationCount: 1,
      deltaCount: 1,
    },
  ];
}
export const ndjson = (frames: unknown[]) =>
  new Response(frames.map((f) => JSON.stringify(f) + '\n').join(''), {
    headers: { 'Content-Type': 'application/x-ndjson; charset=utf-8' },
  });
export function chatApi() {
  let head: ChatHistory = structuredClone(history);
  let policy: ChatContext = structuredClone(context);
  const requests: Array<{ path: string; init: RequestInit }> = [];
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    requests.push({ path, init: init ?? {} });
    if (path.endsWith('/chat/context'))
      return json({ ...policy, epoch: head.epoch, revision: head.revision, pending: !!head.pending });
    if (path.endsWith('/chat/usage')) return json(usage);
    if (path.endsWith('/history')) return json(head);
    const body = JSON.parse(String(init?.body));
    if (body.epoch !== head.epoch || body.revision !== head.revision)
      return json({ errorCode: 'LLM_HISTORY_CONFLICT' }, 409);
    if (path.endsWith('/history/decision')) {
      head = {
        ...head,
        revision: head.revision + 1,
        decisions: [
          ...head.decisions,
          {
            id: crypto.randomUUID(),
            mutationId: body.mutationId,
            kind: 'user-decision',
            text: body.text,
            report: binding,
            sources: body.findingIds.length ? [source] : [],
          },
        ],
      };
      return json(head);
    }
    if (path.endsWith('/chat')) {
      head = {
        ...head,
        revision: head.revision + 2,
        turns: [
          ...head.turns,
          {
            id: turnId,
            mutationId: body.mutationId,
            state: 'completed',
            question: body.question,
            report: binding,
            createdAt: 0,
            reply,
          },
        ],
      };
      return ndjson(frameLines(body.mutationId, reply.text, head.revision));
    }
    throw new Error('Unexpected endpoint');
  });
  return {
    fetcher,
    requests,
    get head() {
      return head;
    },
    set head(value: ChatHistory) {
      head = value;
    },
    get policy() {
      return policy;
    },
    set policy(value: ChatContext) {
      policy = value;
    },
  };
}
