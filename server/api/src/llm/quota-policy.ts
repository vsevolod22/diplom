import { createHash } from 'node:crypto';
import { HttpException, ServiceUnavailableException } from '@nestjs/common';

export type Vector = Readonly<{ input: number; output: number; costMicros: number }>;
export type UsageObservation = Readonly<{ normal: boolean; input?: number; output?: number; costMicros?: number }>;
export type QuotaPolicy = Readonly<{
  revision: string; version: string; user: Vector; scan: Vector; warningPercent: number; requestInput: number;
  observationTokens: number; observationCostMicros: number; receiptMs: number; replayDays: number;
  maxRows: number; dbBytes: number; diskHeadroomBytes: number; busyMs: number; cleanupBatch: number;
}>;
export const DAY = 86400000;
export const quotaUnavailable = () => new ServiceUnavailableException({ errorCode: 'LLM_QUOTA_UNAVAILABLE' });
export type AdmissionSignal = Readonly<
  { scope: 'user' | 'scan'; dimension: keyof Vector; reason: 'insufficient'; required: number; remaining: number } |
  { scope: 'user' | 'scan'; dimension: 'all'; reason: 'policy_fault' }>;
export type QuotaAdmission = Readonly<{ status: 'unavailable' } |
  { status: 'fits' | 'insufficient' | 'policy_fault'; reserve: Vector; signals: readonly AdmissionSignal[] }>;
// Only factory-created refusals can pass metadata through the HTTP filter. Never
// echo arbitrary HttpException bodies, provider diagnostics or client accounting.
const denials = new WeakMap<object, QuotaAdmission>();
export const quotaDenial = (error: unknown): QuotaAdmission | undefined =>
  error !== null && typeof error === 'object' ? denials.get(error) : undefined;
export function quotaExceeded(admission: QuotaAdmission): HttpException {
  const error = new HttpException({ errorCode: 'LLM_QUOTA_EXCEEDED' }, 429);
  denials.set(error, admission);
  return error;
}
export function integer(value: unknown, max = 1_000_000_000): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > max) throw quotaUnavailable();
  return value;
}
// JSON numbers are converted to an exact six-place product currency, never rounded down.
export function usdMicros(value: unknown): number | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) return undefined;
  const text = String(value);
  if (!/^(?:0|1)(?:\.\d{1,6})?$/.test(text)) return undefined;
  const [whole, fraction = ''] = text.split('.');
  return Number(whole) * 1_000_000 + Number(fraction.padEnd(6, '0'));
}
export function quotaPolicyFromEnvironment(env: NodeJS.ProcessEnv = process.env): QuotaPolicy | null {
  if (env.LLM_QUOTA_ENABLED !== 'true') return null;
  try {
    const number = (key: string, max: number, min = 0) => {
      const text = env[`LLM_QUOTA_${key}`];
      if (!text || !/^(?:0|[1-9]\d*)$/.test(text)) throw quotaUnavailable();
      const value = integer(Number(text), max);
      if (value < min) throw quotaUnavailable();
      return value;
    };
    const cost = (key: string) => {
      const text = env[`LLM_QUOTA_${key}_USD`];
      if (text === undefined || !/^(?:0|1)(?:\.\d{1,6})?$/.test(text)) throw quotaUnavailable();
      const value = usdMicros(Number(text));
      if (value === undefined) throw quotaUnavailable();
      return value;
    };
    const revision = env.LLM_QUOTA_REVISION;
    if (!revision || revision === 'undecided' || !/^[A-Za-z0-9._-]{1,80}$/.test(revision) || env.LLM_QUOTA_WINDOW !== 'utc-day') return null;
    const scope = (key: string): Vector => Object.freeze({ input: number(`${key}_INPUT`, 1e9), output: number(`${key}_OUTPUT`, 1e9), costMicros: cost(`${key}_COST`) });
    const settings = { revision, user: scope('USER'), scan: scope('SCAN'),
      warningPercent: number('WARNING_PERCENT', 80, 80), requestInput: number('REQUEST_INPUT', 65536, 1025),
      observationTokens: number('OBSERVATION_TOKENS', 1048576, 65536), observationCostMicros: cost('OBSERVATION_COST'),
      receiptMs: number('RECEIPT_MS', 300000, 30000), replayDays: number('REPLAY_DAYS', 7, 7),
      maxRows: number('MAX_ROWS', 100000, 2), dbBytes: number('DB_BYTES', 67108864, 1048576),
      diskHeadroomBytes: number('DISK_HEADROOM_BYTES', 268435456, 134217728), busyMs: number('BUSY_MS', 1000, 1),
      cleanupBatch: number('CLEANUP_BATCH', 256, 1) };
    if (settings.dbBytes % 4096 !== 0 || settings.observationCostMicros === 0) return null;
    return Object.freeze({ ...settings, version: createHash('sha256').update(JSON.stringify(settings)).digest('hex') });
  } catch { return null; }
}

export function usageObservation(usage: unknown, reserve: Vector, policy: QuotaPolicy): UsageObservation {
  if (!usage || typeof usage !== 'object' || Array.isArray(usage)) return { normal: false };
  const data = usage as Record<string, unknown>;
  const token = (value: unknown) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= policy.observationTokens ? value : undefined;
  const input = token(data.prompt_tokens), output = token(data.completion_tokens);
  const cost = usdMicros(data.cost);
  const costMicros = cost !== undefined && cost <= policy.observationCostMicros ? cost : undefined;
  const consistent = data.total_tokens === undefined || input !== undefined && output !== undefined && data.total_tokens === input + output;
  // Contradictory total tokens make both token observations untrusted, not a refund.
  const knownInput = consistent ? input : undefined, knownOutput = consistent ? output : undefined;
  return Object.freeze({ normal: knownInput !== undefined && knownOutput !== undefined && costMicros === 0 &&
    knownInput <= reserve.input && knownOutput <= reserve.output,
    input: knownInput, output: knownOutput, costMicros });
}
