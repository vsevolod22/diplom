import type { Capture, Target } from './contract.js';
export type Invalidation = { subject: string; consentId: string; epoch: number };
export const fenceKey = (f: Invalidation): string => JSON.stringify([f.subject, f.consentId, f.epoch]);
export type LiveIntent = {
  subject: string;
  target: Target;
  consentId: string;
  nonce: string;
  expiresAt: number;
  epoch: number;
  brokerSubject: string;
  captureId: string;
  attempt: number;
};
// This is an application job port, not Engine transport. No socket/path/grant appears in HTTP DTOs.
export interface QualifiedCapturePort {
  available(): boolean;
  revoke(fence: Invalidation): Promise<void>;
  capture(
    intent: LiveIntent,
    signal: AbortSignal,
    current: () => boolean,
    commit: (capture: Capture) => boolean,
  ): Promise<void>;
}
export type DispatchAck = 'dispatched' | 'aborted';
export interface EnrolledCaller {
  inspect(
    intent: LiveIntent,
    signal: AbortSignal,
    ack: (decision: DispatchAck) => void,
    permit?: string,
  ): Promise<Capture>;
  invalidate(fence: Invalidation): Promise<void>;
}
export type Qualification = {
  schema: 'runtime-qualification-v1';
  fixtureAccepted: true;
  applicationAccepted: true;
  protocolAccepted: true;
  platform: 'linux';
  context: string;
  contextVersion: number;
  sourceHash: string;
  topologyHash: string;
  epoch: number;
  expiresAt: number;
};
const qualifications = new WeakSet<object>();
// Only an operator bootstrap holding actual independently reviewed acceptance can mint a local permit.
// A public record or cast is NOT the permit; this function never provisions or attests anything.
export function acceptOperatorQualification(
  record: Qualification,
  independentReview: (record: Readonly<Qualification>) => boolean,
  now = Date.now(),
): object {
  if (
    process.platform !== 'linux' ||
    record.schema !== 'runtime-qualification-v1' ||
    record.fixtureAccepted !== true ||
    record.applicationAccepted !== true ||
    record.protocolAccepted !== true ||
    record.platform !== 'linux' ||
    !/^[a-z][a-z0-9-]{0,31}$/.test(record.context) ||
    !Number.isSafeInteger(record.contextVersion) ||
    record.contextVersion < 1 ||
    !Number.isSafeInteger(record.epoch) ||
    record.epoch < 1 ||
    !/^[a-f0-9]{64}$/.test(record.sourceHash) ||
    !/^[a-f0-9]{64}$/.test(record.topologyHash) ||
    !Number.isSafeInteger(record.expiresAt) ||
    record.expiresAt <= now ||
    record.expiresAt - now > 300000 ||
    !independentReview(Object.freeze({ ...record }))
  )
    throw new Error('QUALIFICATION_MISSING');
  const permit = Object.freeze({ record: Object.freeze({ ...record }), review: independentReview });
  qualifications.add(permit);
  return permit;
}
// A finite FIFO: expired waiting operations are removed and can never later run effects.
export class AuthorityQueue {
  private active = false;
  private readonly waiting: { run: () => void; timer: ReturnType<typeof setTimeout> }[] = [];
  constructor(
    private readonly limit = 16,
    private readonly waitMs = 5000,
  ) {}
  get pending(): number {
    return this.waiting.length + Number(this.active);
  }
  run<T>(fn: () => Promise<T>): Promise<T> {
    if (this.pending >= this.limit) return Promise.reject(new Error('RUNTIME_CAPACITY'));
    return new Promise<T>((resolve, reject) => {
      const deadline = Date.now() + this.waitMs;
      const entry = {
        run: () => {
          clearTimeout(entry.timer);
          if (Date.now() >= deadline) {
            reject(new Error('INDETERMINATE'));
            this.waiting.shift()?.run();
            return;
          }
          this.active = true;
          Promise.resolve()
            .then(fn)
            .then(resolve, reject)
            .finally(() => {
              this.active = false;
              this.waiting.shift()?.run();
            });
        },
        timer: setTimeout(() => {
          const index = this.waiting.indexOf(entry);
          if (index >= 0) {
            this.waiting.splice(index, 1);
            reject(new Error('INDETERMINATE'));
          }
        }, this.waitMs),
      };
      if (this.active) this.waiting.push(entry);
      else entry.run();
    });
  }
}
export class SerializedCaptureCoordinator implements QualifiedCapturePort {
  private readonly queue = new AuthorityQueue();
  private readonly revoked = new Set<string>();
  private disabled = false;
  private readonly record: Qualification;
  private readonly review: (record: Readonly<Qualification>) => boolean;
  constructor(
    permit: object,
    private readonly caller: EnrolledCaller,
    private readonly now: () => number = Date.now,
  ) {
    if (!qualifications.has(permit)) throw new Error('QUALIFICATION_MISSING');
    this.record = (permit as { record: Qualification }).record;
    this.review = (permit as { review: (r: Readonly<Qualification>) => boolean }).review;
  }
  available(): boolean {
    try {
      return !this.disabled && this.now() < this.record.expiresAt && this.review(this.record);
    } catch {
      this.disabled = true;
      return false;
    }
  }
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    return this.queue.run(fn).catch((error: unknown) => {
      if (error instanceof Error && ['RUNTIME_CAPACITY', 'INDETERMINATE'].includes(error.message))
        this.disabled = true;
      throw error;
    });
  }
  revoke(fence: Invalidation): Promise<void> {
    const key = fenceKey(fence);
    if (this.revoked.has(key)) return Promise.resolve();
    if (this.revoked.size >= 10000) {
      this.disabled = true;
      return Promise.reject(new Error('INDETERMINATE'));
    }
    // Local durable API fence is already committed. Deny publication immediately, even if queued IPC fails.
    this.revoked.add(key);
    return this.serial(async () => {
      try {
        await this.bounded(this.caller.invalidate(fence));
      } catch {
        this.disabled = true;
        throw new Error('INDETERMINATE');
      }
    });
  }
  private async bounded<T>(promise: Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        promise,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error('INDETERMINATE')), 5000);
        }),
      ]);
    } catch (error: unknown) {
      if (
        error instanceof Error &&
        ['TARGET_NOT_RUNNING', 'INVALID_RUNTIME_INPUT', 'NOT_AUTHORIZED'].includes(error.message)
      )
        throw error;
      this.disabled = true;
      throw new Error('INDETERMINATE');
    } finally {
      clearTimeout(timer);
    }
  }
  async capture(
    intent: LiveIntent,
    signal: AbortSignal,
    current: () => boolean,
    commit: (capture: Capture) => boolean,
  ): Promise<void> {
    let response: Promise<Capture> | undefined;
    let ack: DispatchAck | undefined;
    await this.serial(async () => {
      if (
        !this.available() ||
        signal.aborted ||
        !current() ||
        this.revoked.has(fenceKey(intent)) ||
        intent.target.context !== this.record.context ||
        intent.target.contextVersion !== this.record.contextVersion ||
        intent.expiresAt <= this.now()
      )
        throw new Error('NOT_AUTHORIZED');
      let acknowledge: (value: DispatchAck) => void = () => {};
      const acknowledged = new Promise<DispatchAck>((resolve) => {
        acknowledge = resolve;
      });
      response = this.caller.inspect(
        Object.freeze({ ...intent, target: Object.freeze({ ...intent.target }) }),
        signal,
        (decision) => {
          if (ack) {
            this.disabled = true;
            return;
          }
          ack = decision;
          acknowledge(decision);
        },
      );
      // A rejected/lost response without a definitive dispatch/abort ack is indeterminate.
      response.catch(() => {});
      await this.bounded(acknowledged);
    });
    const evidence = await this.bounded(response!);
    await this.serial(async () => {
      if (
        ack !== 'dispatched' ||
        !this.available() ||
        signal.aborted ||
        !current() ||
        this.revoked.has(fenceKey(intent)) ||
        intent.expiresAt <= this.now()
      )
        throw new Error('NOT_AUTHORIZED');
      if (!commit(evidence)) throw new Error('NOT_AUTHORIZED');
    });
  }
}
