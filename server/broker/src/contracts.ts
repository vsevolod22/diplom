export const HEX_ID = /^[a-f0-9]{64}$/;
export const IDENTIFIER = /^[a-z][a-z0-9-]{0,31}$/;
export const LIMITS = Object.freeze({
  ingressBytes: 8192,
  targetBytes: 256,
  headers: 32,
  headerMs: 1000,
  upstreamBytes: 1_048_576,
  outputBytes: 32_768,
  depth: 32,
  nodes: 50_000,
  fields: 256,
  stringBytes: 65_536,
  connectMs: 1000,
  totalMs: 5000,
  active: 2,
  burst: 2,
  ratePerMinute: 10,
  auditRecords: 512,
});
export type Limits = Readonly<Record<keyof typeof LIMITS, number>>;
export function limits(overrides: Partial<Limits> = {}): Limits {
  for (const [key, value] of Object.entries(overrides)) {
    if (!(key in LIMITS) || !Number.isSafeInteger(value) || value <= 0 || value > LIMITS[key as keyof Limits])
      throw new Error('invalid_limits');
  }
  return Object.freeze({ ...LIMITS, ...overrides });
}
export interface Clock {
  wall(): number;
  mono(): number;
}
export const clock: Clock = { wall: () => Date.now(), mono: () => performance.now() };
export interface Target {
  id: string;
  context: string;
  credential: string;
  grant: string;
}
export type Status = 'checked' | 'not_authorized' | 'failed' | 'unsupported';
export type Reason =
  | 'allowed'
  | 'invalid_request'
  | 'authorization'
  | 'disabled'
  | 'overload'
  | 'audit_unavailable'
  | 'upstream'
  | 'cancelled'
  | 'deadline'
  | 'unsupported';
export class SafeFailure extends Error {
  constructor(public readonly reason: Reason) {
    super(reason);
  }
}
