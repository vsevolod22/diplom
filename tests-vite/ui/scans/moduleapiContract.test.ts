import { QueryClient } from '@tanstack/react-query';
import { beforeEach, expect, it } from 'vitest';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import {
  LEGACY_SCANNER_DISCLOSURE,
  MODULEAPI_COST_BASIS,
  MODULEAPI_MODEL,
  OPENAI_COST_BASIS,
  OPENAI_MODEL,
  moduleApiDisclosureSchema,
  openAiDisclosureSchema,
} from '@/shared/api/scans/llmPublicContract';
import {
  chatContextSchema,
  chatReadinessSchema,
  chatReceiptMatchesProvider,
  chatReceiptSchema,
} from '@/shared/api/scans/llmChatContract';
import { summaryContextSchema } from '@/shared/api/scans/llmSummaryClient';
import { usageMatchesDisclosure, usageSchema } from '@/shared/api/scans/llmUsageClient';
import {
  REPORT_AUTOMATION_REVISION,
  moduleApiSummaryConsentSchema,
  readReportPreferences,
  saveReportPreferences,
} from '@/shared/api/preferences/reportPreferences';
import { allowSummaryAutomation, reportPreferencesCurrent } from '@/shared/api/scans/reportAutomation';
import { binding, context as freeChat } from './llmChatFixtures';
import { moduleApiReadinessWire } from './moduleapiReadinessFixture';

const base = {
  provider: 'ModuleAPI',
  model: MODULEAPI_MODEL,
  retention: 'unknown',
  operatorApprovedRouting: true,
  providerComplianceNotProvenByDeclaration: true,
  zeroDataRetentionVerified: false,
  tariffVerified: false,
  costBasis: MODULEAPI_COST_BASIS,
  // Synthetic configured rates, not a claim about ModuleAPI's tariff.
  estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 900000, output: 5000000 },
  data: LEGACY_SCANNER_DISCLOSURE,
} as const;
function disclosure(mode: 'capped' | 'uncapped' = 'uncapped') {
  return moduleApiDisclosureSchema.parse(
    mode === 'capped'
      ? {
          ...base,
          monetaryLimit: mode,
          requestBudgetMicros: 1000,
          userBudgetMicros: 2000,
          scanBudgetMicros: 1500,
        }
      : {
          ...base,
          monetaryLimit: mode,
          requestBudgetMicros: null,
          userBudgetMicros: null,
          scanBudgetMicros: null,
          lifetimeUserCostMicros: 5000000,
        },
  );
}
function context(mode: 'capped' | 'uncapped' = 'uncapped') {
  return summaryContextSchema.parse({
    ...binding,
    enabled: true,
    policyVersion: 'c'.repeat(64),
    disclosure: disclosure(mode),
  });
}
const ready = {
  ...binding,
  status: 'locally-configured',
  localReady: true,
  blockers: [],
  credential: 'environment-valid',
  quota: 'available',
  history: 'available',
  accounting: 'configured',
  costBasis: MODULEAPI_COST_BASIS,
  provider: {
    name: 'ModuleAPI',
    model: MODULEAPI_MODEL,
    status: 'configured-unprobed',
    liveVerified: false,
    retention: 'unknown',
    operatorApprovedRouting: true,
    zeroDataRetentionVerified: false,
    tariffVerified: false,
  },
  generationVerified: false,
  requiresConsent: true,
  acceptsCredentials: false,
  setupAction: 'operator-server-environment-configuration',
};
function openAi() {
  const { tariffVerified, ...common } = disclosure();
  expect(tariffVerified).toBe(false);
  return openAiDisclosureSchema.parse({
    ...common,
    provider: 'OpenAI',
    model: OPENAI_MODEL,
    retention: 'no-training',
    costBasis: OPENAI_COST_BASIS,
  });
}
const grant = () => ({ version: 1 as const, policyVersion: 'c'.repeat(64), disclosure: disclosure() });
const ownerKey = 'report-preferences:v1:moduleapi-contract-owner';

beforeEach(() => {
  localStorage.clear();
  transitionScanSession('moduleapi-contract-owner', new QueryClient(), true);
});

it.each(['capped', 'uncapped'] as const)(
  'strict ModuleAPI %s summary/chat branches preserve exact metadata',
  (mode) => {
    const value = disclosure(mode);
    expect(context(mode).disclosure).toEqual(value);
    if (!freeChat.disclosure) throw new Error('Expected synthetic chat disclosure');
    const chatDisclosure = {
      ...value,
      sentData: freeChat.disclosure.sentData,
      localRetention: freeChat.disclosure.localRetention,
    };
    expect(chatContextSchema.parse({ ...freeChat, disclosure: chatDisclosure }).disclosure).toEqual(
      chatDisclosure,
    );
    expect(openAiDisclosureSchema.safeParse(value).success).toBe(false);
    expect(moduleApiDisclosureSchema.safeParse(openAi()).success).toBe(false);
  },
);

it.each([
  { provider: 'OpenAI' },
  { provider: 'moduleapi' },
  { model: OPENAI_MODEL },
  { model: 'other' },
  { retention: 'no-training' },
  { retention: 'no-storage' },
  { retention: undefined },
  { tariffVerified: true },
  { tariffVerified: undefined },
  { zeroDataRetentionVerified: true },
  { operatorApprovedRouting: false },
  { providerComplianceNotProvenByDeclaration: false },
  { costBasis: OPENAI_COST_BASIS },
  { costBasis: 'invoice' },
  { freeOnly: true },
  { providers: ['ModuleAPI'] },
  { requestBudgetMicros: 1 },
  { monetaryLimit: 'unlimited' },
  { lifetimeUserCostMicros: 0 },
  { lifetimeUserCostMicros: 5000000.1 },
  { lifetimeUserCostMicros: 1000000001 },
  { data: 'Raw report and credentials' },
  { estimatedPrice: { unit: 'USD', input: 1, output: 2 } },
  { estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 0, output: 2 } },
  { estimatedPrice: { unit: 'microUSD-per-million-tokens', input: 1, output: 2, hiddenFee: 1 } },
])('rejects inaccurate, permissive or malformed ModuleAPI disclosure %j', (patch) => {
  const raw = { ...disclosure(), ...patch };
  expect(moduleApiDisclosureSchema.safeParse(raw).success).toBe(false);
  expect(summaryContextSchema.safeParse({ ...context(), disclosure: raw }).success).toBe(false);
  if (!freeChat.disclosure) throw new Error('Expected synthetic chat disclosure');
  expect(
    chatContextSchema.safeParse({
      ...freeChat,
      disclosure: {
        ...raw,
        sentData: freeChat.disclosure.sentData,
        localRetention: freeChat.disclosure.localRetention,
      },
    }).success,
  ).toBe(false);
});

it('decodes the exact actual backend readiness projection, including unavailable model/null and ordered blockers', () => {
  const actual = { ...binding, ...moduleApiReadinessWire() };
  expect(actual).toEqual(ready);
  expect(chatReadinessSchema.parse(actual)).toEqual(ready);
  const unavailable = {
    ...ready,
    status: 'setup-required',
    localReady: false,
    credential: 'unavailable',
    accounting: 'unavailable',
    quota: 'unavailable',
    history: 'unavailable',
    provider: { ...ready.provider, status: 'configuration-unavailable', model: null },
    blockers: [
      'configuration-required',
      'environment-key-required',
      'accounting-configuration-required',
      'quota-store-unavailable',
      'history-store-unavailable',
    ],
  };
  const actualUnavailable = {
    ...binding,
    ...moduleApiReadinessWire({
      configured: false,
      credential: false,
      accounting: false,
      quota: false,
      history: false,
    }),
  };
  expect(actualUnavailable).toEqual(unavailable);
  expect(chatReadinessSchema.parse(actualUnavailable)).toEqual(unavailable);
  expect(
    chatReadinessSchema.safeParse({ ...unavailable, blockers: [...unavailable.blockers].reverse() }).success,
  ).toBe(false);
});
it.each([
  { provider: { ...ready.provider, model: OPENAI_MODEL } },
  { provider: { ...ready.provider, name: 'OpenAI' } },
  { provider: { ...ready.provider, model: null } },
  { provider: { ...ready.provider, liveVerified: true } },
  { provider: { ...ready.provider, arbitrary: true } },
  { provider: { ...ready.provider, retention: 'no-training' } },
  { provider: { ...ready.provider, retention: undefined } },
  { provider: { ...ready.provider, operatorApprovedRouting: false } },
  { provider: { ...ready.provider, operatorApprovedRouting: undefined } },
  { provider: { ...ready.provider, zeroDataRetentionVerified: true } },
  { provider: { ...ready.provider, zeroDataRetentionVerified: undefined } },
  { provider: { ...ready.provider, tariffVerified: true } },
  { provider: { ...ready.provider, tariffVerified: undefined } },
  { costBasis: OPENAI_COST_BASIS },
  { costBasis: undefined },
  { localReady: false },
  { blockers: ['environment-key-required'] },
  { credential: 'unavailable' },
  { accounting: 'unavailable' },
  { generationVerified: true },
  { acceptsCredentials: true },
  { extra: true },
])('rejects internally inconsistent/unrecognized readiness %j', (patch) => {
  expect(chatReadinessSchema.safeParse({ ...ready, ...patch }).success).toBe(false);
});

it('separates ModuleAPI, OpenAI and free receipt provenance without accepting invoice semantics', () => {
  const moduleReceipt = chatReceiptSchema.parse({
    input: 100,
    output: 10,
    costMicros: 140,
    source: MODULEAPI_COST_BASIS,
  });
  const moduleChat = chatContextSchema.parse({
    ...freeChat,
    disclosure: {
      ...disclosure(),
      sentData: freeChat.disclosure!.sentData,
      localRetention: freeChat.disclosure!.localRetention,
    },
  });
  const openAiChat = chatContextSchema.parse({
    ...freeChat,
    disclosure: {
      ...openAi(),
      sentData: freeChat.disclosure!.sentData,
      localRetention: freeChat.disclosure!.localRetention,
    },
  });
  expect(chatReceiptMatchesProvider(moduleReceipt, moduleChat)).toBe(true);
  expect(chatReceiptMatchesProvider(moduleReceipt, freeChat)).toBe(false);
  expect(chatReceiptMatchesProvider(moduleReceipt, openAiChat)).toBe(false);
  expect(chatReceiptMatchesProvider({ ...moduleReceipt, source: OPENAI_COST_BASIS }, moduleChat)).toBe(false);
  for (const patch of [
    { source: 'invoice' },
    { costMicros: 0 },
    { input: 0 },
    { output: 4097 },
    { hiddenFee: 1 },
  ]) {
    expect(chatReceiptSchema.safeParse({ ...moduleReceipt, ...patch }).success).toBe(false);
  }
});

it.each(['free', 'OpenAI'] as const)('old %s permission is never migrated into ModuleAPI consent', (kind) => {
  expect(
    saveReportPreferences({
      language: 'original',
      autoSummary: true,
      ...(kind === 'OpenAI'
        ? { openAiSummaryConsent: { version: 1, policyVersion: 'c'.repeat(64), disclosure: openAi() } }
        : {}),
    }),
  ).toBe(true);
  const before = localStorage.getItem(ownerKey);
  const preferences = readReportPreferences();
  expect(preferences.moduleApiSummaryConsent).toBeUndefined();
  expect(allowSummaryAutomation(preferences, context())).toBe(false);
  expect(localStorage.getItem(ownerKey)).toBe(before);
});

it.each(['save', 'storage'] as const)('fresh %s ModuleAPI grant is deeply immutable and exact', (origin) => {
  const callerGrant = grant();
  if (origin === 'save')
    expect(
      saveReportPreferences({
        language: 'original',
        autoSummary: true,
        moduleApiSummaryConsent: callerGrant,
      }),
    ).toBe(true);
  else
    localStorage.setItem(
      ownerKey,
      JSON.stringify({
        version: 1,
        automationRevision: REPORT_AUTOMATION_REVISION,
        language: 'original',
        autoSummary: true,
        moduleApiSummaryConsent: callerGrant,
      }),
    );
  const preferences = readReportPreferences();
  const saved = preferences.moduleApiSummaryConsent!;
  expect(allowSummaryAutomation(preferences, context())).toBe(true);
  expect(reportPreferencesCurrent(preferences, 'summary')).toBe(true);
  expect(Object.isFrozen(saved)).toBe(true);
  expect(Object.isFrozen(saved.disclosure)).toBe(true);
  expect(Object.isFrozen(saved.disclosure.estimatedPrice)).toBe(true);
  expect(Reflect.set(saved, 'policyVersion', 'd'.repeat(64))).toBe(false);
  expect(Reflect.set(saved.disclosure, 'provider', 'OpenAI')).toBe(false);
  expect(Reflect.set(saved.disclosure.estimatedPrice, 'input', 1)).toBe(false);
  callerGrant.disclosure.estimatedPrice.input = 1;
  expect(saved.disclosure.estimatedPrice.input).toBe(900000);
  expect(moduleApiSummaryConsentSchema.safeParse({ ...grant(), version: 2 }).success).toBe(false);
  const changes = [
    { policyVersion: 'd'.repeat(64) },
    { disclosure: { ...saved.disclosure, lifetimeUserCostMicros: 6000000 } },
    { disclosure: { ...saved.disclosure, estimatedPrice: { ...saved.disclosure.estimatedPrice, input: 1 } } },
    { disclosure: disclosure('capped') },
    { disclosure: openAi() },
    { disclosure: freeChat.disclosure },
  ];
  for (const change of changes)
    expect(allowSummaryAutomation(preferences, { ...context(), ...change })).toBe(false);
});

it('rejects dual-provider grants, stale owner/session saves and revocation without authorizing another recipient', () => {
  expect(
    saveReportPreferences({
      language: 'original',
      autoSummary: true,
      moduleApiSummaryConsent: grant(),
      openAiSummaryConsent: { version: 1, policyVersion: 'c'.repeat(64), disclosure: openAi() },
    }),
  ).toBe(false);
  expect(
    saveReportPreferences({ language: 'original', autoSummary: false, moduleApiSummaryConsent: grant() }),
  ).toBe(false);
  const oldSession = scanSession();
  expect(
    saveReportPreferences({ language: 'original', autoSummary: true, moduleApiSummaryConsent: grant() }),
  ).toBe(true);
  const accepted = readReportPreferences();
  transitionScanSession('other-moduleapi-owner', new QueryClient(), true);
  expect(reportPreferencesCurrent(accepted, 'summary')).toBe(false);
  expect(readReportPreferences().authorized).toBe(false);
  expect(
    saveReportPreferences(
      { language: 'original', autoSummary: true, moduleApiSummaryConsent: grant() },
      oldSession,
    ),
  ).toBe(false);
  transitionScanSession('moduleapi-contract-owner', new QueryClient(), true);
  expect(saveReportPreferences({ language: 'original', autoSummary: false })).toBe(true);
  expect(readReportPreferences().moduleApiSummaryConsent).toBeUndefined();
  expect(allowSummaryAutomation(readReportPreferences(), context())).toBe(false);
});

it('ModuleAPI accounting requires the exact disclosed $5 lifetime cap including historical holds', () => {
  const vector = { input: 100, output: 10, costMicros: 1000000 };
  const counters = {
    limits: { input: 10000, output: 10000, costMicros: null },
    used: vector,
    held: { ...vector, costMicros: 500000 },
    carried: { ...vector, costMicros: 500000 },
    remaining: { input: 9700, output: 9970, costMicros: null },
    warning: false,
    exhausted: false,
  };
  const usage = usageSchema.parse({
    ...binding,
    available: true,
    integrationEnabled: true,
    quotaEnabled: true,
    monetaryLimit: 'uncapped',
    lifetimeBudget: {
      limitMicros: 5000000,
      usedMicros: 2000000,
      heldMicros: 1000000,
      remainingMicros: 2000000,
    },
    reason: 'ready',
    admission: { status: 'fits', reserve: { input: 1025, output: 10, costMicros: 100 }, signals: [] },
    window: { start: 0, end: 86400000 },
    signals: [],
    user: counters,
    scan: counters,
  });
  expect(usageMatchesDisclosure(usage, disclosure())).toBe(true);
  expect(usageMatchesDisclosure(usage, { ...disclosure(), lifetimeUserCostMicros: 6000000 })).toBe(false);
  expect(usageMatchesDisclosure(usage, { provider: 'OpenRouter' })).toBe(false);
  expect(
    usageSchema.safeParse({
      ...usage,
      lifetimeBudget: {
        limitMicros: 5000000,
        usedMicros: 2000000,
        heldMicros: 1000000,
        remainingMicros: 3000000,
      },
    }).success,
  ).toBe(false);
});
