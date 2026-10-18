import Database from 'better-sqlite3';
import { Inject, Injectable } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { createVerifier } from '../image-config/verified-input.js';
import { loadPinnedConfig, admittedConfigTarget, type ConfigLoader } from '../oci/pinned-image-config.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import type { Job } from '../ledger/ledger.js';
import {
  canonical,
  link,
  timestamp,
  type Capture,
  type ImageLink,
  type Outcome,
} from '../../../runtime/src/contract.js';
import { fault } from './runtime-store.js';
export type OwnerImageJobPort = (subject: string, scanId: string) => Job | undefined;
function imageCheckedAt(value: unknown): string {
  // SQLite CURRENT_TIMESTAMP is UTC with second precision; never parse it in the host timezone.
  // Preserve the observed instant, not the link time. All other inputs must already be canonical ISO.
  const normalized =
    typeof value === 'string' && /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/.test(value)
      ? `${value.replace(' ', 'T')}.000Z`
      : value;
  return timestamp(normalized);
}
// New read-only adapter; shared ledger migrator/schema/worker remain exclusively peer-owned.
export function ownerImageJob(path: string | undefined): OwnerImageJobPort {
  return (subject, scanId) => {
    if (!path) return;
    const db = new Database(path, { readonly: true, fileMustExist: true });
    try {
      const row = db
        .prepare(
          "SELECT id AS scanId,registry,repository,digest,platform,checks,scope FROM scans WHERE subject=? AND id=? AND scope='image'",
        )
        .get(subject, scanId) as Omit<Job, 'attempts'> | undefined;
      if (!row || !admittedConfigTarget(row)) return;
      return { ...row, attempts: 0 };
    } finally {
      db.close();
    }
  };
}
@Injectable()
export class RuntimeImageLinkAdapter {
  private readonly jobs: OwnerImageJobPort;
  private readonly loader: ConfigLoader;
  constructor(@Inject(LedgerStore) private readonly images: LedgerStore) {
    this.jobs = ownerImageJob(process.env.SCAN_LEDGER_PATH);
    this.loader = loadPinnedConfig;
  }
  // Dedicated controlled integration uses actual verifier/chain with injected authorized byte loader.
  static controlled(
    images: LedgerStore,
    jobs: OwnerImageJobPort,
    loader: ConfigLoader,
  ): RuntimeImageLinkAdapter {
    const adapter = new RuntimeImageLinkAdapter(images);
    Object.assign(adapter, { jobs, loader });
    return adapter;
  }
  async resolve(
    subject: string,
    imageScanId: string,
    capture: Capture,
    signal?: AbortSignal,
  ): Promise<ImageLink> {
    const job = this.jobs(subject, imageScanId);
    if (
      !job ||
      !this.images.ledger ||
      !capture.imageConfigDigest ||
      capture.imageSemantics !== 'docker-config-sha256-v1'
    )
      fault('IMAGE_LINK_UNAVAILABLE', 409);
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) controller.abort();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      if (controller.signal.aborted) fault('IMAGE_LINK_UNAVAILABLE', 409);
      const input = await this.loader(job, controller.signal);
      if (controller.signal.aborted) fault('IMAGE_LINK_UNAVAILABLE', 409);
      const verifier = createVerifier();
      const checked = verifier.read(verifier.verify(input));
      if (
        checked.configDigest !== capture.imageConfigDigest ||
        checked.manifestDigest !== job.digest ||
        `${checked.platform.os}/${checked.platform.architecture}${checked.platform.variant ? `/${checked.platform.variant}` : ''}` !==
          job.platform
      )
        fault('IMAGE_IDENTITY_MISMATCH', 409);
      const current = this.jobs(subject, imageScanId);
      if (!current || canonical(current) !== canonical(job)) fault('IMAGE_LINK_UNAVAILABLE', 409);
      const sbom = this.images.ledger.sbom(imageScanId, subject, 0, 1);
      const vuln = this.images.ledger.vuln(imageScanId, subject, 0, 1);
      const outcome = (
        value:
          | { outcome: string; scannerVersion?: string; checkedAt?: string; dbEvidence?: unknown }
          | undefined,
      ): Outcome => ({
        outcome:
          value?.outcome === 'checked' ? 'checked' : value?.outcome === 'failed' ? 'failed' : 'unsupported',
        reason: value?.outcome === 'checked' ? 'READY' : 'IMAGE_RESULT_UNAVAILABLE',
        scannerVersion: value?.outcome === 'checked' ? (value.scannerVersion ?? null) : null,
        checkedAt: value?.outcome === 'checked' ? imageCheckedAt(value.checkedAt) : null,
        dbEvidenceHash:
          value?.outcome === 'checked' && value.dbEvidence
            ? createHash('sha256').update(canonical(value.dbEvidence)).digest('hex')
            : null,
      });
      return link({
        imageScanId,
        manifestDigest: checked.manifestDigest,
        configDigest: checked.configDigest,
        platform: job.platform,
        verificationVersion: 'image-config-chain-v1',
        captureHash: capture.hash,
        linkedAt: new Date().toISOString(),
        sbom: outcome(sbom),
        vuln: outcome(vuln),
      });
    } catch (e) {
      if (e instanceof Error && ['IMAGE_IDENTITY_MISMATCH', 'IMAGE_LINK_UNAVAILABLE'].includes(e.message))
        throw e;
      return fault('IMAGE_LINK_UNAVAILABLE', 409);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      controller.abort();
    }
  }
}
