import { z } from 'zod';
import { scanSession, subscribeScanSession } from '@/shared/api/auth/scanSession';
import { BROWSER_SCANS_PATH } from './scanTransport';

const count = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const vector = z.strictObject({ input: count, output: count, costMicros: count });
const scope = z
  .strictObject({
    limits: vector,
    used: vector,
    held: vector,
    carried: vector,
    remaining: vector,
    warning: z.boolean(),
    exhausted: z.boolean(),
  })
  .refine((value) =>
    (['input', 'output', 'costMicros'] as const).every((d) => {
      const total = value.used[d] + value.held[d] + value.carried[d];
      return Number.isSafeInteger(total) && value.remaining[d] === Math.max(0, value.limits[d] - total);
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
      output: count.min(1).max(2048),
      costMicros: z.literal(0),
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
      if (next.status === 'unavailable') return true;
      const expected = (['user', 'scan'] as const).flatMap((name) =>
        (['input', 'output', 'costMicros'] as const)
          .filter((d) => next.reserve[d] > value[name].remaining[d])
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
            s.remaining === value[s.scope].remaining[s.dimension],
        )
      )
        return false;
      const fault = next.signals.some((s) => s.reason === 'policy_fault');
      return next.status === (fault ? 'policy_fault' : shortages.length ? 'insufficient' : 'fits');
    }),
]);
export type LlmUsage = z.infer<typeof usageSchema>;
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
