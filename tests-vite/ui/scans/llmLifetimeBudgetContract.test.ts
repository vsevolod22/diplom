import { QueryClient } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { createUsageClient, usageMatchesDisclosure, usageSchema } from '@/shared/api/scans/llmUsageClient';
import { binding, json } from './llmChatFixtures';
import { insufficientLifetimeUsage, lifetimeContext, lifetimeUsage } from './lifetimeBudgetFixtures';

beforeEach(() => transitionScanSession('lifetime-contract-owner', new QueryClient(), true));
afterEach(() => vi.restoreAllMocks());

it('decodes additive lifetime metadata without changing uncapped disclosure or nullable daily cost', async () => {
  const payload = insufficientLifetimeUsage();
  const fetcher = vi.fn<typeof fetch>(async () => json(payload));
  const usage = await createUsageClient(scanSession(), fetcher).get(binding, new AbortController().signal);
  expect(usage).toEqual(payload);
  expect(usageMatchesDisclosure(usage, lifetimeContext.disclosure)).toBe(true);
  expect(fetcher).toHaveBeenCalledWith(
    expect.stringContaining('/llm/usage'),
    expect.objectContaining({
      method: 'GET',
      cache: 'no-store',
      credentials: 'same-origin',
      redirect: 'error',
    }),
  );
  if (!usage.available) throw new Error('Expected available usage');
  expect(usage.user.remaining.costMicros).toBeNull();
  expect(usage.admission).toMatchObject({ status: 'insufficient', signals: [{ remaining: 10000 }] });
});

it.each([
  { usageLimit: 5000000, disclosedLimit: 5000000, matches: true },
  { usageLimit: 6000000, disclosedLimit: 5000000, matches: false },
  { usageLimit: undefined, disclosedLimit: 5000000, matches: false },
  { usageLimit: 5000000, disclosedLimit: undefined, matches: false },
  { usageLimit: undefined, disclosedLimit: undefined, matches: true },
])(
  'matches lifetime disclosure exactly: usage=$usageLimit disclosure=$disclosedLimit',
  ({ usageLimit, disclosedLimit, matches }) => {
    const usage = lifetimeUsage();
    usage.admission = { status: 'unavailable' };
    if (usageLimit === undefined) delete usage.lifetimeBudget;
    else
      usage.lifetimeBudget = {
        limitMicros: usageLimit,
        usedMicros: 1000000,
        heldMicros: 500000,
        remainingMicros: usageLimit - 1500000,
      };
    expect(usageSchema.safeParse(usage).success).toBe(true);
    expect(
      usageMatchesDisclosure(usage, {
        provider: 'OpenAI',
        monetaryLimit: 'uncapped',
        lifetimeUserCostMicros: disclosedLimit,
      }),
    ).toBe(matches);
  },
);

it('keeps disclosure availability/provider/mode checks alongside lifetime equality', () => {
  const usage = lifetimeUsage();
  expect(
    usageMatchesDisclosure(usage, {
      provider: 'OpenAI',
      monetaryLimit: 'capped',
      lifetimeUserCostMicros: 5000000,
    }),
  ).toBe(false);
  expect(usageMatchesDisclosure(usage, { provider: 'OpenRouter' })).toBe(false);
  expect(usageMatchesDisclosure(usage, null)).toBe(false);
  expect(
    usageMatchesDisclosure(
      { ...binding, available: false, integrationEnabled: true, quotaEnabled: true, reason: 'unavailable' },
      lifetimeContext.disclosure,
    ),
  ).toBe(false);
  delete usage.lifetimeBudget;
  usage.monetaryLimit = undefined;
  expect(usageMatchesDisclosure(usage, { provider: 'OpenRouter' })).toBe(true);
});

it('ignores daily token shortages only with explicit valid lifetime metadata and accepts the exact cost boundary', () => {
  const usage = lifetimeUsage();
  expect(usageSchema.safeParse(usage).success).toBe(true);
  usage.lifetimeBudget = { limitMicros: 5000000, usedMicros: 4970000, heldMicros: 0, remainingMicros: 30000 };
  expect(usageSchema.safeParse(usage).success).toBe(true);
  delete usage.lifetimeBudget;
  expect(usageSchema.safeParse(usage).success).toBe(false);
  usage.admission = { status: 'unavailable' };
  expect(usageSchema.safeParse(usage).success).toBe(true);
});

it('requires a user cost shortage even at zero lifetime remaining and never treats it as uncapped', () => {
  const usage = insufficientLifetimeUsage();
  usage.lifetimeBudget = {
    limitMicros: 5000000,
    usedMicros: 4900000,
    heldMicros: 100001,
    remainingMicros: 0,
  };
  usage.reason = 'exhausted';
  usage.signals = [{ scope: 'user', dimension: 'costMicros', reason: 'exhausted' }];
  if (usage.admission.status === 'unavailable') throw new Error('Expected admission');
  usage.admission.signals = [
    { scope: 'user', dimension: 'costMicros', reason: 'insufficient', required: 30000, remaining: 0 },
  ];
  expect(usageSchema.safeParse(usage).success).toBe(true);
  usage.admission.status = 'fits';
  usage.admission.signals = [];
  expect(usageSchema.safeParse(usage).success).toBe(false);
});

it.each(['legacy-free', 'capped', 'uncapped'] as const)(
  'keeps old %s daily admission checks unchanged',
  (mode) => {
    const usage = lifetimeUsage();
    delete usage.lifetimeBudget;
    usage.monetaryLimit = mode === 'legacy-free' ? undefined : mode;
    for (const scope of [usage.user, usage.scan]) {
      scope.limits.costMicros = mode === 'uncapped' ? null : 100000;
      scope.remaining.costMicros = mode === 'uncapped' ? null : 0;
    }
    const cost = mode === 'legacy-free' ? 0 : 30000;
    const signals = (['user', 'scan'] as const).flatMap((scope) => [
      { scope, dimension: 'input', reason: 'insufficient', required: 2048, remaining: 0 },
      { scope, dimension: 'output', reason: 'insufficient', required: 2048, remaining: 0 },
      ...(mode === 'capped'
        ? [{ scope, dimension: 'costMicros', reason: 'insufficient', required: cost, remaining: 0 }]
        : []),
    ]);
    const payload = {
      ...usage,
      admission: {
        status: 'insufficient',
        reserve: { input: 2048, output: 2048, costMicros: cost },
        signals,
      },
    };
    expect(usageSchema.safeParse(payload).success).toBe(true);
    expect(
      usageSchema.safeParse({ ...payload, admission: { ...payload.admission, signals: [] } }).success,
    ).toBe(false);
  },
);

describe('strict lifetime fields', () => {
  it.each(['limitMicros', 'usedMicros', 'heldMicros', 'remainingMicros'] as const)(
    'rejects malformed %s without a validation exception',
    (field) => {
      for (const value of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, Infinity, NaN, '5000000', null, undefined]) {
        const payload = lifetimeUsage();
        const lifetimeBudget = { ...payload.lifetimeBudget, [field]: value };
        expect(usageSchema.safeParse({ ...payload, lifetimeBudget }).success).toBe(false);
      }
    },
  );

  it.each([
    null,
    {},
    { limitMicros: 5000000 },
    { limitMicros: 5000000, usedMicros: 1000000, heldMicros: 500000, remainingMicros: 3500001 },
    { limitMicros: 5000000, usedMicros: 1000000, heldMicros: 500000, remainingMicros: 3500000, extra: true },
  ])('rejects malformed metadata %j', (lifetimeBudget) => {
    expect(usageSchema.safeParse({ ...lifetimeUsage(), lifetimeBudget }).success).toBe(false);
  });

  it.each([1, 1_000_000_000])('accepts the configured lifetime limit boundary %i', (limitMicros) => {
    const payload = lifetimeUsage();
    payload.admission = { status: 'unavailable' };
    payload.lifetimeBudget = {
      limitMicros,
      usedMicros: 100000,
      heldMicros: 0,
      remainingMicros: Math.max(0, limitMicros - 100000),
    };
    expect(usageSchema.safeParse(payload).success).toBe(true);
  });

  it.each([0, 1_000_000_001, Number.MAX_SAFE_INTEGER])(
    'rejects out-of-policy lifetime limit %i even with a balanced snapshot',
    (limitMicros) => {
      const payload = lifetimeUsage();
      payload.admission = { status: 'unavailable' };
      payload.lifetimeBudget = {
        limitMicros,
        usedMicros: 100000,
        heldMicros: 0,
        remainingMicros: Math.max(0, limitMicros - 100000),
      };
      expect(usageSchema.safeParse(payload).success).toBe(false);
    },
  );

  it('uses exact arithmetic within the configured limit and allows safe-integer used/held overages', () => {
    const payload = lifetimeUsage();
    payload.admission = { status: 'unavailable' };
    payload.lifetimeBudget = {
      limitMicros: 1_000_000_000,
      usedMicros: 999_999_998,
      heldMicros: 1,
      remainingMicros: 1,
    };
    expect(usageSchema.safeParse(payload).success).toBe(true);
    payload.lifetimeBudget.remainingMicros = 2;
    expect(usageSchema.safeParse(payload).success).toBe(false);
    payload.lifetimeBudget = {
      limitMicros: 1_000_000_000,
      usedMicros: Number.MAX_SAFE_INTEGER,
      heldMicros: Number.MAX_SAFE_INTEGER,
      remainingMicros: 0,
    };
    expect(usageSchema.safeParse(payload).success).toBe(true);
    payload.lifetimeBudget.remainingMicros = 1;
    expect(usageSchema.safeParse(payload).success).toBe(false);
  });

  it.each(['capped', undefined])(
    'rejects lifetime on monetary mode %s even if daily cost vectors match',
    (monetaryLimit) => {
      const payload = lifetimeUsage();
      for (const scope of [payload.user, payload.scan]) {
        scope.limits.costMicros = 100000;
        scope.remaining.costMicros = 0;
      }
      expect(usageSchema.safeParse({ ...payload, monetaryLimit }).success).toBe(false);
    },
  );

  it('rejects lifetime on unavailable snapshots', () => {
    expect(
      usageSchema.safeParse({
        ...binding,
        available: false,
        integrationEnabled: false,
        quotaEnabled: false,
        reason: 'unavailable',
        lifetimeBudget: lifetimeUsage().lifetimeBudget,
      }).success,
    ).toBe(false);
  });
});

describe('lifetime cross-counter consistency', () => {
  it('rejects balanced fake zero lifetime use despite 4m daily cost, including unavailable admission', () => {
    const payload = lifetimeUsage();
    payload.user.used.costMicros = 4000000;
    payload.lifetimeBudget = { limitMicros: 5000000, usedMicros: 0, heldMicros: 0, remainingMicros: 5000000 };
    expect(usageSchema.safeParse(payload).success).toBe(false);
    payload.admission = { status: 'unavailable' };
    expect(usageSchema.safeParse(payload).success).toBe(false);
  });

  it('requires lifetime used to cover daily user used, allowing equality', () => {
    const payload = lifetimeUsage();
    payload.admission = { status: 'unavailable' };
    payload.lifetimeBudget = {
      limitMicros: 5000000,
      usedMicros: 99999,
      heldMicros: 500000,
      remainingMicros: 4400001,
    };
    expect(usageSchema.safeParse(payload).success).toBe(false);
    payload.lifetimeBudget.usedMicros++;
    payload.lifetimeBudget.remainingMicros--;
    expect(usageSchema.safeParse(payload).success).toBe(true);
  });

  it('requires lifetime held to cover daily held plus carried unknown cost, allowing equality', () => {
    const payload = lifetimeUsage();
    payload.admission = { status: 'unavailable' };
    payload.user.held.costMicros = 100000;
    payload.user.carried.costMicros = 200000;
    payload.lifetimeBudget = {
      limitMicros: 5000000,
      usedMicros: 1000000,
      heldMicros: 299999,
      remainingMicros: 3700001,
    };
    expect(usageSchema.safeParse(payload).success).toBe(false);
    payload.lifetimeBudget.heldMicros++;
    payload.lifetimeBudget.remainingMicros--;
    expect(usageSchema.safeParse(payload).success).toBe(true);
  });

  const buckets = ['used', 'held', 'carried'] as const;
  const dimensions = ['input', 'output', 'costMicros'] as const;
  it.each(buckets.flatMap((bucket) => dimensions.map((dimension) => ({ bucket, dimension }))))(
    'rejects scan $bucket.$dimension larger than owner only in lifetime mode',
    ({ bucket, dimension }) => {
      const payload = lifetimeUsage();
      payload.admission = { status: 'unavailable' };
      payload.scan[bucket][dimension]++;
      if (dimension !== 'costMicros') {
        payload.scan.remaining[dimension] = Math.max(
          0,
          payload.scan.limits[dimension] -
            payload.scan.used[dimension] -
            payload.scan.held[dimension] -
            payload.scan.carried[dimension],
        );
      }
      expect(usageSchema.safeParse(payload).success).toBe(false);
      delete payload.lifetimeBudget;
      expect(usageSchema.safeParse(payload).success).toBe(true);
    },
  );

  it('accepts owner counters larger than scan counters in every bucket/dimension', () => {
    const payload = lifetimeUsage();
    for (const bucket of buckets) for (const dimension of dimensions) payload.user[bucket][dimension]++;
    for (const dimension of ['input', 'output'] as const) {
      payload.user.remaining[dimension] = Math.max(
        0,
        payload.user.limits[dimension] -
          payload.user.used[dimension] -
          payload.user.held[dimension] -
          payload.user.carried[dimension],
      );
    }
    expect(usageSchema.safeParse(payload).success).toBe(true);
  });
});

it('requires exactly the lifetime cost shortage, including required/remaining/status and unique scope', () => {
  const payload = insufficientLifetimeUsage();
  if (payload.admission.status === 'unavailable') throw new Error('Expected admission');
  const admission = payload.admission;
  const signal = admission.signals[0];
  for (const changed of [
    { ...admission, status: 'fits' },
    { ...admission, signals: [] },
    { ...admission, signals: [signal, signal] },
    { ...admission, signals: [{ ...signal, scope: 'scan' }] },
    { ...admission, signals: [{ ...signal, required: 30001 }] },
    { ...admission, signals: [{ ...signal, remaining: 9999 }] },
    { ...admission, signals: [{ ...signal, remaining: null }] },
    {
      ...admission,
      signals: [{ scope: 'user', dimension: 'input', reason: 'insufficient', required: 2048, remaining: 0 }],
    },
    { ...admission, reserve: { ...admission.reserve, costMicros: 0 } },
  ])
    expect(usageSchema.safeParse({ ...payload, admission: changed }).success).toBe(false);
  expect(
    usageSchema.safeParse({
      ...payload,
      signals: [{ scope: 'scan', dimension: 'costMicros', reason: 'warning' }],
    }).success,
  ).toBe(false);
  const missing = { ...payload, lifetimeBudget: undefined, signals: [] };
  expect(usageSchema.safeParse(missing).success).toBe(false);
});

it('preserves policy-fault admission with valid lifetime shortage evidence', () => {
  const payload = insufficientLifetimeUsage();
  if (payload.admission.status === 'unavailable') throw new Error('Expected admission');
  payload.admission.status = 'policy_fault';
  payload.admission.signals.push({ scope: 'scan', dimension: 'all', reason: 'policy_fault' });
  expect(usageSchema.safeParse(payload).success).toBe(true);
  payload.admission.status = 'insufficient';
  expect(usageSchema.safeParse(payload).success).toBe(false);
});

it('fails closed through the real browser client for forged fits and malformed lifetime metadata', async () => {
  for (const payload of [
    { ...lifetimeUsage(), lifetimeBudget: {} },
    {
      ...lifetimeUsage(),
      lifetimeBudget: { ...lifetimeUsage().lifetimeBudget, remainingMicros: Number.MAX_SAFE_INTEGER },
    },
    { ...insufficientLifetimeUsage(), admission: lifetimeUsage().admission },
    {
      ...lifetimeUsage(),
      lifetimeBudget: { limitMicros: 5000000, usedMicros: 0, heldMicros: 0, remainingMicros: 5000000 },
    },
  ]) {
    await expect(
      createUsageClient(scanSession(), async () => json(payload)).get(binding, new AbortController().signal),
    ).rejects.toThrow('Учёт ИИ недоступен');
  }
});
