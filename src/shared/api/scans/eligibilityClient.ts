import { ScanAccessError, ScanHttpError, scanResponseError } from './httpScanTransport';

export type ScanWait = { until: number; reason: 'rate' | 'concurrency' | 'capacity' | 'admission' };

/** One mounted subject/session owns this coordinator; no cached hint authorizes a POST. */
export class EligibilityClient {
  private flight: { key: string; promise: Promise<unknown>; controller: AbortController } | null = null;
  private lastCompleted = -Infinity;
  private lastFocus = -Infinity;
  private wait: ScanWait | null = null;
  private accessError: ScanAccessError | null = null;
  private retired = false;

  constructor(private readonly current: () => boolean, private readonly onWait: (wait: ScanWait) => void) {}

  focusAllowed(): boolean {
    const now = Date.now();
    if (this.retired || this.accessError || this.wait && this.wait.until > now || this.flight ||
        now - this.lastCompleted < 5000 || now - this.lastFocus < 5000) return false;
    this.lastFocus = now;
    return true;
  }

  activate(): void { this.retired = false; }
  retire(): void { this.retired = true; this.flight?.controller.abort(); }

  async request(imageReference: string, checks: readonly string[], fresh = false): Promise<unknown> {
    if (this.retired || !this.current()) throw new Error('Сессия изменилась');
    if (this.accessError) throw this.accessError;
    if (this.wait && this.wait.until > Date.now()) {
      this.onWait(this.wait);
      throw new ScanHttpError(429, 'IMAGE_SEARCH_RATE_LIMITED', Math.max(1, Math.ceil((this.wait.until - Date.now()) / 1000)), this.wait.reason === 'admission' ? null : this.wait.reason);
    }
    const key = JSON.stringify([imageReference, checks]);
    if (this.flight) {
      if (!fresh && this.flight.key === key) return this.flight.promise;
      // Changed targets serialize too; aborted browser reads may still occupy server work.
      await this.flight.promise.catch(() => undefined);
      return this.request(imageReference, checks, fresh);
    }
    const controller = new AbortController();
    const promise = this.fetchEligibility(imageReference, checks, controller);
    this.flight = { key, promise, controller };
    try { return await promise; }
    finally { if (this.flight?.promise === promise) this.flight = null; }
  }

  private async fetchEligibility(imageReference: string, checks: readonly string[], controller: AbortController): Promise<unknown> {
    const timeout = window.setTimeout(() => controller.abort(), 10_000);
    try {
      const response = await fetch('/api/v1/browser/scans/images/eligibility', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal,
        headers: { 'content-type': 'application/json' }, body: JSON.stringify({ imageReference, checks }),
      });
      if (!response.ok) throw await scanResponseError(response);
      const result: unknown = await response.json();
      if (this.retired || !this.current()) throw new Error('Сессия изменилась');
      return result;
    } catch (error) {
      if (!this.retired && this.current()) {
        if (error instanceof ScanAccessError) this.accessError = error;
        if (error instanceof ScanHttpError && error.status === 429) {
          this.wait = { until: Date.now() + (error.retryAfterSeconds ?? 60) * 1000, reason: error.limitReason ?? 'rate' };
          this.onWait(this.wait);
        }
      }
      throw error;
    } finally { window.clearTimeout(timeout); this.lastCompleted = Date.now(); }
  }
}
