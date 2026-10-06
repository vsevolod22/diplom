import { AuditBuffer, correlation, record, type AuditTicket } from './audit.js';
import { boundaryCurrent, type PrivateBoundary } from './boundary.js';
import {
  clock,
  limits,
  SafeFailure,
  type Clock,
  type Limits,
  type Reason,
  type Status,
  type Target,
} from './contracts.js';
import type { EngineTransport } from './engine.js';
import { PolicyStore, type Pin } from './policy.js';
import { project, canonical } from './projection.js';
import { strictJson } from './strict-json.js';
export interface Reply {
  status: Status;
  snapshot?: ReturnType<typeof project>;
}
export interface Barriers {
  beforeDispatch?: () => Promise<void>;
  beforePublication?: () => Promise<void>;
}
export interface BrokerOptions {
  policy: PolicyStore;
  engine: EngineTransport;
  audit: AuditBuffer;
  enabled?: boolean;
  boundary?: PrivateBoundary;
  clock?: Clock;
  limits?: Partial<Limits>;
  barriers?: Barriers;
}
export class Broker {
  readonly bound: Limits;
  readonly #options: BrokerOptions;
  readonly #clock: Clock;
  #active = 0;
  #tokens: number;
  #last: number;
  constructor(options: BrokerOptions) {
    this.bound = limits(options.limits);
    if (options.audit.capacity > this.bound.auditRecords) throw new Error('audit_capacity_exceeds_limit');
    this.#options = { ...options, barriers: { ...options.barriers } };
    this.#clock = options.clock ?? clock;
    this.#tokens = this.bound.burst;
    this.#last = this.#clock.mono();
  }
  get active(): number {
    return this.#active;
  }
  #rate(): boolean {
    const now = this.#clock.mono();
    this.#tokens = Math.min(
      this.bound.burst,
      this.#tokens + (Math.max(0, now - this.#last) * this.bound.ratePerMinute) / 60_000,
    );
    this.#last = Math.max(this.#last, now);
    if (this.#tokens < 1) return false;
    this.#tokens--;
    return true;
  }
  deny(reason: Reason = 'invalid_request'): Reply {
    this.#options.audit.deny(
      record(correlation(), this.#clock.wall(), undefined, 'admission', 'not_authorized', reason, false),
    );
    return { status: 'not_authorized' };
  }
  async handle(
    target: Target,
    disconnect: AbortSignal,
    publish: (reply: Reply, preparedBody: string) => void = () => {},
  ): Promise<Reply> {
    const { policy, audit, engine, boundary, barriers } = this.#options;
    const correlationId = correlation();
    const start = this.#clock.mono();
    let pin: Pin | undefined;
    let ticket: AuditTicket | undefined;
    let dispatched = false;
    let admitted = false;
    const controller = new AbortController();
    const abort = () => controller.abort();
    const timer = setTimeout(abort, this.bound.totalMs);
    disconnect.addEventListener('abort', abort, { once: true });
    if (disconnect.aborted) abort();
    const live = () => !controller.signal.aborted && this.#clock.mono() - start < this.bound.totalMs;
    const final = (status: Status, reason: Reason, snapshot?: Reply['snapshot']): Reply => {
      const entry = record(
        correlationId,
        this.#clock.wall(),
        pin,
        ticket ? 'publication' : 'admission',
        status,
        reason,
        dispatched,
      );
      const accepted = ticket ? audit.finish(ticket, entry) : audit.deny(entry);
      ticket = undefined;
      let reply: Reply =
        !accepted && dispatched ? { status: 'failed' } : { status, ...(snapshot ? { snapshot } : {}) };
      // Complete bounded serialization BEFORE the last authorization/time check.
      let preparedBody = canonical(reply);
      // No await between final audit, current state/time check and the actual response commit.
      if (snapshot && (!live() || !pin || !policy.recheck(target, this.#clock.wall(), pin))) {
        reply = { status: live() ? 'not_authorized' : 'failed' };
        audit.correctPublication(
          correlationId,
          record(
            correlationId,
            this.#clock.wall(),
            pin,
            'publication',
            reply.status,
            live() ? 'authorization' : 'deadline',
            dispatched,
          ),
        );
      }
      if (reply.status !== status) preparedBody = canonical(reply);
      if (!disconnect.aborted) publish(reply, preparedBody);
      return reply;
    };
    try {
      if (!this.#rate() || this.#active >= this.bound.active) return final('not_authorized', 'overload');
      if (!this.#options.enabled) return final('not_authorized', 'disabled');
      pin = policy.authorize(target, this.#clock.wall());
      if (!pin) return final('not_authorized', 'authorization');
      if (pin.context.transport !== 'unix') return final('unsupported', 'unsupported');
      if (!boundaryCurrent(boundary, pin.context.endpoint)) return final('not_authorized', 'disabled');
      this.#active++;
      admitted = true;
      // Barriers never create an unbounded wait: abort/deadline races every asynchronous step.
      await interruptible(barriers?.beforeDispatch?.() ?? Promise.resolve(), controller.signal);
      if (!live()) return final('failed', 'deadline');
      if (
        !boundaryCurrent(boundary, pin.context.endpoint) ||
        !policy.recheck(target, this.#clock.wall(), pin)
      )
        return final('not_authorized', 'authorization');
      ticket = audit.reserve(
        record(correlationId, this.#clock.wall(), pin, 'admission', 'allowed', 'allowed', false),
      );
      if (!ticket) return final('not_authorized', 'audit_unavailable');
      // Recheck after synchronous audit/FS work; transport start follows without yielding.
      if (!live() || !policy.recheck(target, this.#clock.wall(), pin))
        return final('not_authorized', 'authorization');
      const body = await interruptible(
        engine.inspect(pin, controller.signal, this.bound, () => {
          dispatched = true;
        }),
        controller.signal,
      );
      if (!live()) return final('failed', 'deadline');
      const parsed = strictJson(body, this.bound);
      const snapshot = project(parsed, pin, this.#clock.wall(), this.bound);
      await interruptible(barriers?.beforePublication?.() ?? Promise.resolve(), controller.signal);
      if (!live()) return final('failed', 'deadline');
      if (!policy.recheck(target, this.#clock.wall(), pin)) return final('not_authorized', 'authorization');
      return final('checked', 'allowed', snapshot);
    } catch (error) {
      return final(
        'failed',
        disconnect.aborted
          ? 'cancelled'
          : controller.signal.aborted
            ? 'deadline'
            : error instanceof SafeFailure
              ? error.reason
              : 'upstream',
      );
    } finally {
      controller.abort();
      clearTimeout(timer);
      disconnect.removeEventListener('abort', abort);
      if (admitted) this.#active--;
    }
  }
}
function interruptible<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = () => reject(new SafeFailure('deadline'));
    if (signal.aborted) {
      promise.catch(() => {});
      abort();
      return;
    }
    signal.addEventListener('abort', abort, { once: true });
    promise.then(
      (v) => {
        signal.removeEventListener('abort', abort);
        resolve(v);
      },
      (e) => {
        signal.removeEventListener('abort', abort);
        reject(e);
      },
    );
  });
}
