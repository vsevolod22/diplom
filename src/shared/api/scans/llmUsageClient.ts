import { z } from 'zod';
import { scanSession, subscribeScanSession } from '@/shared/api/auth/scanSession';
import { BROWSER_SCANS_PATH } from './scanTransport';

const count = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const vector = z.strictObject({ input: count, output: count, costMicros: count });
const limitVector = vector.extend({ costMicros: count.nullable() });
const lifetimeBudgetSchema = z
  .strictObject({
    limitMicros: count.min(1).max(1_000_000_000),
    usedMicros: count,
    heldMicros: count,
    remainingMicros: count,
  })
  .refine((value) => {
    // Individual safe integers can still overflow when added; compare the exact balance.
    const remaining = BigInt(value.limitMicros) - BigInt(value.usedMicros) - BigInt(value.heldMicros);
    return BigInt(value.remainingMicros) === (remaining > 0n ? remaining : 0n);
  });
export type LifetimeBudget = z.infer<typeof lifetimeBudgetSchema>;
const scope = z
  .strictObject({
    limits: limitVector,
    used: vector,
    held: vector,
    carried: vector,
    remaining: limitVector,
    warning: z.boolean(),
    exhausted: z.boolean(),
  })
  .refine((value) =>
    (['input', 'output', 'costMicros'] as const).every((d) => {
      const total = value.used[d] + value.held[d] + value.carried[d];
      const limit = value.limits[d];
      return (
        Number.isSafeInteger(total) &&
        (limit === null ? value.remaining[d] === null : value.remaining[d] === Math.max(0, limit - total))
      );
    }),
  );
const binding = {
  scanId: z.string().uuid(),
  digest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  platform: z.literal('linux/amd64'),
  reportVersion: z.string().regex(/^[a-f0-9]{64}$/),
  integrationEnabled: z.boolean(),
  quotaEnabled: z.boolean(),
};
const admission = z.union([
  z.strictObject({ status: z.literal('unavailable') }),
  z.strictObject({
    status: z.enum(['fits', 'insufficient', 'policy_fault']),
    reserve: z.strictObject({
      input: count.min(1025).max(65536),
      output: count.min(1).max(4096),
      costMicros: count,
    }),
    signals: z
      .array(
        z.union([
          z
            .strictObject({
              scope: z.enum(['user', 'scan']),
              dimension: z.enum(['input', 'output', 'costMicros']),
              reason: z.literal('insufficient'),
              required: count,
              remaining: count,
            })
            .refine((s) => s.required > s.remaining),
          z.strictObject({
            scope: z.enum(['user', 'scan']),
            dimension: z.literal('all'),
            reason: z.literal('policy_fault'),
          }),
        ]),
      )
      .max(8),
  }),
]);
export const usageSchema = z.discriminatedUnion('available', [
  z.strictObject({ ...binding, available: z.literal(false), reason: z.enum(['disabled', 'unavailable']) }),
  z
    .strictObject({
      ...binding,
      available: z.literal(true),
      monetaryLimit: z.enum(['capped', 'uncapped']).optional(),
      lifetimeBudget: lifetimeBudgetSchema.optional(),
      admission,
      reason: z.enum(['ready', 'warning', 'exhausted', 'policy_fault']),
      window: z
        .strictObject({ start: count, end: count })
        .refine((v) => v.start % 86400000 === 0 && v.end === v.start + 86400000 && v.end <= 8640000000000000),
      signals: z
        .array(
          z.strictObject({
            scope: z.enum(['user', 'scan']),
            dimension: z.enum(['input', 'output', 'costMicros', 'all']),
            reason: z.enum(['warning', 'exhausted', 'policy_fault']),
          }),
        )
        .max(8),
      user: scope,
      scan: scope,
    })
    .refine((value) => {
      const next = value.admission;
      const lifetime = value.lifetimeBudget;
      if (lifetime) {
        if (value.monetaryLimit !== 'uncapped') return false;
        if (lifetime.usedMicros < value.user.used.costMicros) return false;
        if (
          BigInt(lifetime.heldMicros) <
          BigInt(value.user.held.costMicros) + BigInt(value.user.carried.costMicros)
        )
          return false;
        // The owner's daily totals include this scan, in every accounting bucket and dimension.
        if (
          (['used', 'held', 'carried'] as const).some((bucket) =>
            (['input', 'output', 'costMicros'] as const).some(
              (dimension) => value.user[bucket][dimension] < value.scan[bucket][dimension],
            ),
          )
        )
          return false;
      }
      for (const name of ['user', 'scan'] as const) {
        const cost = value[name].limits.costMicros;
        if (value.monetaryLimit === 'uncapped' ? cost !== null : cost === null) return false;
        if (value.monetaryLimit === 'capped' && (cost === null || cost <= 0)) return false;
      }
      if (
        value.monetaryLimit === 'uncapped' &&
        value.signals.some((s) => s.dimension === 'costMicros' && (!lifetime || s.scope !== 'user'))
      )
        return false;
      if (next.status === 'unavailable') return true;
      if (value.monetaryLimit === undefined ? next.reserve.costMicros !== 0 : next.reserve.costMicros <= 0)
        return false;
      const remainingFor = (name: 'user' | 'scan', dimension: 'input' | 'output' | 'costMicros') =>
        lifetime
          ? name === 'user' && dimension === 'costMicros'
            ? lifetime.remainingMicros
            : null
          : value[name].remaining[dimension];
      const expected = (['user', 'scan'] as const).flatMap((name) =>
        (['input', 'output', 'costMicros'] as const)
          .filter((d) => {
            const remaining = remainingFor(name, d);
            return remaining !== null && next.reserve[d] > remaining;
          })
          .map((d) => `${name}:${d}`),
      );
      const shortages = next.signals.filter((s) => s.reason === 'insufficient');
      if (new Set(next.signals.map((s) => `${s.scope}:${s.dimension}`)).size !== next.signals.length)
        return false;
      if (
        shortages.length !== expected.length ||
        !shortages.every(
          (s) =>
            expected.includes(`${s.scope}:${s.dimension}`) &&
            s.required === next.reserve[s.dimension] &&
            s.remaining === remainingFor(s.scope, s.dimension),
        )
      )
        return false;
      const fault = next.signals.some((s) => s.reason === 'policy_fault');
      return next.status === (fault ? 'policy_fault' : shortages.length ? 'insufficient' : 'fits');
    }),
]);
export type LlmUsage = z.infer<typeof usageSchema>;
/** Accounting must match the disclosed provider, monetary mode and lifetime cap exactly. */
export function usageMatchesDisclosure(
  usage: LlmUsage,
  disclosure:
    | {
        provider: 'OpenAI' | 'ModuleAPI';
        monetaryLimit: 'capped' | 'uncapped';
        lifetimeUserCostMicros?: number;
      }
    | { provider: 'OpenRouter' }
    | null,
) {
  if (!usage.available || !disclosure) return false;
  return disclosure.provider !== 'OpenRouter'
    ? usage.monetaryLimit === disclosure.monetaryLimit &&
        usage.lifetimeBudget?.limitMicros === disclosure.lifetimeUserCostMicros
    : usage.monetaryLimit === undefined;
}
export type UsageBinding = Pick<LlmUsage, 'scanId' | 'digest' | 'platform' | 'reportVersion'>;
export class UsageError extends Error {
  constructor() {
    super('Учёт ИИ недоступен');
  }
}
export function createUsageClient(session = scanSession(), fetcher: typeof fetch = fetch) {
  const current = () => {
    const now = scanSession();
    return !!session.subject && session.subject === now.subject && session.generation === now.generation;
  };
  async function get(binding: UsageBinding, signal: AbortSignal): Promise<LlmUsage> {
    if (!current() || !z.string().uuid().safeParse(binding.scanId).success) throw new UsageError();
    const controller = new AbortController();
    const abort = () => controller.abort();
    const unsubscribe = subscribeScanSession(abort);
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    const timer = setTimeout(abort, 15000);
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    const stopped = new Promise<never>((_, reject) => {
      const stop = () => {
        void reader?.cancel().catch(() => {});
        reject(new UsageError());
      };
      controller.signal.addEventListener('abort', stop, { once: true });
      if (controller.signal.aborted) stop();
    });
    const operation = async () => {
      if (controller.signal.aborted) throw new UsageError();
      const response = await fetcher(`${BROWSER_SCANS_PATH}/${binding.scanId}/llm/usage`, {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        signal: controller.signal,
      });
      if (
        !current() ||
        controller.signal.aborted ||
        !response.ok ||
        response.redirected ||
        !/^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? '')
      ) {
        void response.body?.cancel().catch(() => {});
        throw new UsageError();
      }
      const length = response.headers.get('content-length');
      if (length !== null && (!/^\d+$/.test(length) || Number(length) > 16384)) {
        void response.body?.cancel().catch(() => {});
        throw new UsageError();
      }
      reader = response.body?.getReader();
      if (!reader) throw new UsageError();
      const chunks: Uint8Array[] = [];
      let size = 0;
      for (;;) {
        const part = await reader.read();
        if (!current() || controller.signal.aborted) throw new UsageError();
        if (part.done) break;
        size += part.value.byteLength;
        if (size > 16384) throw new UsageError();
        chunks.push(part.value);
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
      }
      const value = usageSchema.parse(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
      if (
        !current() ||
        controller.signal.aborted ||
        value.scanId !== binding.scanId ||
        value.digest !== binding.digest ||
        value.platform !== binding.platform ||
        value.reportVersion !== binding.reportVersion
      )
        throw new UsageError();
      return value;
    };
    try {
      return await Promise.race([operation(), stopped]);
    } catch {
      throw new UsageError();
    } finally {
      clearTimeout(timer);
      signal.removeEventListener('abort', abort);
      unsubscribe();
      controller.abort();
      void reader?.cancel().catch(() => {});
    }
  }
  return { get, current };
}
export type UsageClient = ReturnType<typeof createUsageClient>;
