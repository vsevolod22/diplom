import { ARCHIVE_LIMITS as L, ArchiveRejected } from './layer-tar-validator.js';
export class ArchiveAttemptBudget {
  requests = 0;
  wireBytes = 0;
  compressedBytes = 0;
  reservedBytes = 0;
  reservationPeak = 0;
  private failed = false;
  private started: number;
  constructor(private now = () => performance.now()) { this.started = now(); }
  private reject(): never { this.failed = true; throw new ArchiveRejected(); }
  remaining(): number {
    const remaining = L.deadlineMs - (this.now() - this.started);
    if (this.failed || remaining <= 0) return this.reject();
    return remaining;
  }
  request(): number { this.remaining(); if (++this.requests > L.requests) this.reject(); return this.remaining(); }
  wire(bytes: number): void {
    this.remaining(); if (!Number.isSafeInteger(bytes) || bytes < 0 || (this.wireBytes += bytes) > L.wireBytes) this.reject();
  }
  layer(bytes: number): void {
    this.remaining(); if (!Number.isSafeInteger(bytes) || bytes < 0 || (this.compressedBytes += bytes) > L.compressedTotal) this.reject();
  }
  reserve(bytes: number): void {
    this.remaining(); if (!Number.isSafeInteger(bytes) || bytes < 0 || (this.reservedBytes += bytes) > L.scratchBytes) this.reject();
    this.reservationPeak = Math.max(this.reservationPeak, this.reservedBytes);
  }
  release(bytes: number): void {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > this.reservedBytes) this.reject();
    this.reservedBytes -= bytes;
  }
}
