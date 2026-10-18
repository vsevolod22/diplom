import { archiveLimits, ArchiveRejected, type ArchiveResourceProfile } from './layer-tar-validator.js';
export class ArchiveAttemptBudget {
  requests = 0;
  wireBytes = 0;
  compressedBytes = 0;
  reservedBytes = 0;
  reservationPeak = 0;
  private failed = false;
  private started: number;
  private readonly limits;
  constructor(private now = () => performance.now(), profile: ArchiveResourceProfile = 'legacy') {
    this.limits = archiveLimits(profile); this.started = now();
  }
  private reject(): never { this.failed = true; throw new ArchiveRejected(); }
  remaining(): number {
    const remaining = this.limits.deadlineMs - (this.now() - this.started);
    if (this.failed || remaining <= 0) return this.reject();
    return remaining;
  }
  request(): number { this.remaining(); if (++this.requests > this.limits.requests) this.reject(); return this.remaining(); }
  wire(bytes: number): void {
    this.remaining(); if (!Number.isSafeInteger(bytes) || bytes < 0 || (this.wireBytes += bytes) > this.limits.wireBytes) this.reject();
  }
  layer(bytes: number): void {
    this.remaining(); if (!Number.isSafeInteger(bytes) || bytes < 0 || (this.compressedBytes += bytes) > this.limits.compressedTotal) this.reject();
  }
  reserve(bytes: number): void {
    this.remaining(); if (!Number.isSafeInteger(bytes) || bytes < 0 || (this.reservedBytes += bytes) > this.limits.scratchBytes) this.reject();
    this.reservationPeak = Math.max(this.reservationPeak, this.reservedBytes);
  }
  release(bytes: number): void {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > this.reservedBytes) this.reject();
    this.reservedBytes -= bytes;
  }
}
