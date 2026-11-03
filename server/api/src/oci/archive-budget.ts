import { archiveLimits, ArchiveRejected, type ArchiveResourceProfile } from './layer-tar-validator.js';
import type { ImageFailureDetail } from './image-failure.js';
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
  private reject(detail?: ImageFailureDetail): never { this.failed = true; throw new ArchiveRejected(undefined, detail); }
  remaining(): number {
    const remaining = this.limits.deadlineMs - (this.now() - this.started);
    if (this.failed) return this.reject();
        if (remaining <= 0) return this.reject({ reason: 'DEADLINE_EXCEEDED', stage: 'download' });
    return remaining;
  }
  request(): number { this.remaining(); if (++this.requests > this.limits.requests) this.reject({ reason: 'RESOURCE_LIMIT', stage: 'download', resource: 'requests' }); return this.remaining(); }
  wire(bytes: number): void {
    this.remaining(); if (!Number.isSafeInteger(bytes) || bytes < 0 || (this.wireBytes += bytes) > this.limits.wireBytes) this.reject({ reason: 'RESOURCE_LIMIT', stage: 'download', resource: 'download_bytes' });
  }
  layer(bytes: number): void {
    this.remaining(); if (!Number.isSafeInteger(bytes) || bytes < 0 || (this.compressedBytes += bytes) > this.limits.compressedTotal) this.reject({ reason: 'RESOURCE_LIMIT', stage: 'download', resource: 'download_bytes' });
  }
  reserve(bytes: number): void {
    this.remaining(); if (!Number.isSafeInteger(bytes) || bytes < 0 || (this.reservedBytes += bytes) > this.limits.scratchBytes) this.reject({ reason: 'RESOURCE_LIMIT', stage: 'archive', resource: 'scratch_bytes' });
    this.reservationPeak = Math.max(this.reservationPeak, this.reservedBytes);
  }
  release(bytes: number): void {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > this.reservedBytes) this.reject();
    this.reservedBytes -= bytes;
  }
}
