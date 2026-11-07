import type { LlmUsage } from '@/shared/api/scans/llmUsageClient';
import type { SummaryContext, SummaryReply } from '@/shared/api/scans/llmSummaryClient';
import { OPENAI_COST_BASIS, OPENAI_MODEL } from '@/shared/api/scans/llmPublicContract';
import { binding } from './llmChatFixtures';

export function lifetimeUsage(): Extract<LlmUsage, { available: true }> {
  const counters = {
    limits: { input: 10000, output: 10000, costMicros: null },
    used: { input: 10000, output: 10000, costMicros: 100000 },
    held: { input: 0, output: 0, costMicros: 0 },
    carried: { input: 0, output: 0, costMicros: 0 },
    remaining: { input: 0, output: 0, costMicros: null },
    warning: true,
    exhausted: true,
  };
  return {
    ...binding,
    available: true,
    integrationEnabled: true,
    quotaEnabled: true,
    monetaryLimit: 'uncapped',
    lifetimeBudget: {
      limitMicros: 5000000,
      usedMicros: 1000000,
      heldMicros: 500000,
      remainingMicros: 3500000,
    },
    reason: 'ready',
    window: { start: 0, end: 86400000 },
    signals: [],
    admission: { status: 'fits', reserve: { input: 2048, output: 2048, costMicros: 30000 }, signals: [] },
    user: structuredClone(counters),
    scan: structuredClone(counters),
  };
}

export function insufficientLifetimeUsage(): Extract<LlmUsage, { available: true }> {
  const usage = lifetimeUsage();
  usage.lifetimeBudget = {
    limitMicros: 5000000,
    usedMicros: 4400000,
    heldMicros: 590000,
    remainingMicros: 10000,
  };
  usage.reason = 'warning';
  usage.signals = [{ scope: 'user', dimension: 'costMicros', reason: 'warning' }];
  usage.admission = {
    status: 'insufficient',
    reserve: { input: 2048, output: 2048, costMicros: 30000 },
    signals: [
      { scope: 'user', dimension: 'costMicros', reason: 'insufficient', required: 30000, remaining: 10000 },
    ],
  };
  return usage;
}

export const lifetimeContext: SummaryContext = {
  ...binding,
  enabled: true,
  policyVersion: 'c'.repeat(64),
  summaryResultRead: true,
  disclosure: {
    provider: 'OpenAI',
    model: OPENAI_MODEL,
    monetaryLimit: 'uncapped',
    lifetimeUserCostMicros: 5000000,
    requestBudgetMicros: null,
    userBudgetMicros: null,
    scanBudgetMicros: null,
    retention: 'no-training',
    operatorApprovedRouting: true,
    providerComplianceNotProvenByDeclaration: true,
    zeroDataRetentionVerified: false,
    costBasis: OPENAI_COST_BASIS,
    estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 750000, output: 4500000 },
    data: 'Sanitized scanner findings, package names, installed and reported fixed versions, and coverage; no raw evidence or credentials.',
  },
};

export const lifetimeReply: SummaryReply = {
  ...binding,
  hypotheses: [{ kind: 'hypothesis', text: 'Проверьте исходную находку', citations: ['secret-0-1'] }],
  scannerFacts: [{ findingId: 'secret-0-1', check: 'secret', severity: 'UNKNOWN' }],
};
