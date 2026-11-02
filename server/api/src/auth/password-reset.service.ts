import { Inject, Injectable, OnModuleDestroy, Optional, ServiceUnavailableException } from '@nestjs/common';
import { AuthStore } from './auth.store.js';

export const PASSWORD_RESET_DELIVERY = Symbol('PASSWORD_RESET_DELIVERY');

// Server composition only. The adapter must honor abort, send only to `to`, never log
// its arguments/provider errors, and report acceptance only after the transport accepts.
// No SMTP/provider credentials or transport are inferred from environment or requests.
export type PasswordResetDelivery = Readonly<{
  resetPageUrl: string;
  send(message: Readonly<{ to: string; resetUrl: string; expiresAt: number; signal: AbortSignal }>): Promise<{ accepted: true }>;
}>;
export type PasswordResetStatus =
  | { available: true; delivery: 'configured' }
  | { available: false; reason: 'DELIVERY_NOT_CONFIGURED' | 'DELIVERY_CONFIGURATION_INVALID' | 'AUTH_UNAVAILABLE'; action: 'CONTACT_OPERATOR' };

const DELIVERY_WINDOW_MS = 10_000;
const MAX_PENDING = 4;

@Injectable()
export class PasswordResetService implements OnModuleDestroy {
  private readonly origin = process.env.AUTH_ORIGIN;
  private readonly pending = new Set<() => void>();
  private stopped = false;
  private failures = 0;

  constructor(
    @Inject(AuthStore) private readonly store: AuthStore,
    @Optional() @Inject(PASSWORD_RESET_DELIVERY) private readonly delivery?: PasswordResetDelivery,
  ) {}

  status(): PasswordResetStatus {
    if (!this.delivery) return { available: false, reason: 'DELIVERY_NOT_CONFIGURED', action: 'CONTACT_OPERATOR' };
    try {
      const url = new URL(this.delivery.resetPageUrl);
      if (typeof this.delivery.send !== 'function' || url.protocol !== 'https:' || url.username || url.password ||
        url.search || url.hash || url.origin !== this.origin || this.origin !== process.env.AUTH_ORIGIN ||
        url.href !== this.delivery.resetPageUrl) throw new Error('invalid configuration');
    } catch { return { available: false, reason: 'DELIVERY_CONFIGURATION_INVALID', action: 'CONTACT_OPERATOR' }; }
    try {
      if (this.stopped) throw new Error('stopped');
      this.store.assertAvailable();
    } catch { return { available: false, reason: 'AUTH_UNAVAILABLE', action: 'CONTACT_OPERATOR' }; }
    return { available: true, delivery: 'configured' };
  }

  requireAvailable(): void {
    if (!this.status().available) throw new ServiceUnavailableException({ errorCode: 'PASSWORD_RESET_UNAVAILABLE' });
  }

  // Aggregate operator diagnostics only; never expose recipient, token, URL or raw errors.
  diagnostics(): { pending: number; failures: number } { return { pending: this.pending.size, failures: this.failures }; }

  request(email: string): void {
    this.requireAvailable();
    if (this.pending.size >= MAX_PENDING) throw new ServiceUnavailableException({ errorCode: 'PASSWORD_RESET_BUSY' });
    const controller = new AbortController();
    let token: string | undefined;
    let accepted = false;
    let failed = false;
    const invalidate = (): void => {
      if (failed) return;
      failed = true;
      this.failures++;
      if (token) {
        try { this.store.cancelPasswordReset(token); } catch { /* Finite TTL remains if storage is unavailable. */ }
      }
    };
    const abort = (): void => { controller.abort(); if (!accepted) invalidate(); };
    this.pending.add(abort);
    // Every admitted address occupies a slot for the same window, including unknown
    // accounts and failures. Response latency/capacity must not reveal SMTP outcomes.
    let timer: ReturnType<typeof setTimeout>;
    const window = new Promise<void>(resolve => {
      timer = setTimeout(() => { abort(); resolve(); }, DELIVERY_WINDOW_MS);
      timer.unref();
    });
    const deliver = async (): Promise<void> => {
      try {
        const issued = this.store.issuePasswordReset(email);
        if (!issued) { accepted = true; return; }
        token = issued.token;
        const url = new URL(this.delivery!.resetPageUrl);
        // A fragment does not reach HTTP access logs or Referer. The frontend must
        // scrub it immediately and POST the token in a body, never a URL/query.
        url.hash = `token=${token}`;
        const receipt = await this.delivery!.send({ to: email, resetUrl: url.href, expiresAt: issued.expiresAt, signal: controller.signal });
        if (controller.signal.aborted || receipt?.accepted !== true) { invalidate(); return; }
        accepted = true;
      } catch { invalidate(); }
    };
    // An adapter ignoring abort retains its permit until it settles: no unbounded
    // background fan-out. A restart loses unsent work; 202 never claims delivery.
    void Promise.all([deliver(), window]).finally(() => {
      clearTimeout(timer);
      this.pending.delete(abort);
    });
  }

  onModuleDestroy(): void {
    this.stopped = true;
    for (const abort of this.pending) abort();
  }
}
