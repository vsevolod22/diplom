import { Inject, Injectable, OnModuleDestroy } from '@nestjs/common';
import {
  canonical,
  exact,
  ID,
  one,
  str,
  payload,
  HEX,
  type Capture,
  type Report,
} from '../../../runtime/src/contract.js';
import { digest, verifyImport, validateCaptureHash } from './runtime-evidence.js';
import { fault, RuntimeStore, RuntimeFault } from './runtime-store.js';
import { RuntimeImageLinkAdapter } from './runtime-image-link.adapter.js';
import type { QualifiedCapturePort } from '../../../runtime/src/live-port.js';
export const RUNTIME_STORE = Symbol('runtime-store');
export const RUNTIME_LIVE = Symbol('runtime-application-capture-port');
@Injectable()
export class RuntimeApiService implements OnModuleDestroy {
  private rawIntakeConfigured = false;
  // Bootstrap descriptor only: no assertion about nginx activation, DB health or LIVE qualification.
  configureRawIntake(): void {
    this.rawIntakeConfigured = true;
  }
  private readonly pending = new Set<Promise<void>>();
  private readonly active = new Map<string, AbortController>();
  private readonly links = new Map<
    string,
    { subject: string; controller: AbortController; result: Promise<unknown> }
  >();
  constructor(
    @Inject(RUNTIME_STORE) readonly store: RuntimeStore | undefined,
    @Inject(RUNTIME_LIVE) readonly live: QualifiedCapturePort | undefined,
    @Inject(RuntimeImageLinkAdapter) private readonly images: RuntimeImageLinkAdapter,
  ) {}
  database(): RuntimeStore {
    return this.store ?? fault('RUNTIME_UNAVAILABLE', 503);
  }
  capabilities() {
    const liveCapture = !!this.store && !!this.live?.available();
    return {
      schemaVersion: 'runtime-capabilities-v1',
      historicalImport: !!this.store,
      liveCapture,
      liveReason: liveCapture ? 'READY' : 'QUALIFICATION_MISSING',
      host: 'not_authorized',
      rawIntake: this.rawIntakeConfigured ? 'authenticated-pre-json' : 'parent-bootstrap-required',
    };
  }
  consents(subject: string, body: unknown) {
    const c = exact(body, ['targetId', 'mode', 'confirmed']);
    if (c.confirmed !== true) fault('NOT_AUTHORIZED', 403);
    const mode = one(c.mode, ['imported-historical', 'broker-capture']);
    const a = this.database().consent(subject, str(c.targetId, ID), mode);
    return {
      consentId: a.consentId,
      nonce: a.nonce,
      expiresAt: a.expiresAt,
      epoch: a.epoch,
      target: a.target,
      mode,
    };
  }
  async revoke(subject: string, id: string) {
    const result = this.database().revoke(subject, str(id, ID));
    if (result.changed && this.live) {
      try {
        await this.live.revoke(result.fence);
      } catch {
        fault('INDETERMINATE', 503);
      }
    }
    return { revoked: true, changed: result.changed };
  }
  private schedule(
    id: string,
    subject: string,
    attempt: number,
    fn: (signal: AbortSignal) => Promise<void>,
  ): void {
    const controller = new AbortController();
    this.active.set(id, controller);
    const task = Promise.resolve()
      .then(() => fn(controller.signal))
      .catch((error: unknown) => {
        const reason =
          error instanceof Error &&
          ['TARGET_NOT_RUNNING', 'INVALID_RUNTIME_INPUT', 'NOT_AUTHORIZED'].includes(error.message)
            ? (error.message as Report['reason'])
            : 'INDETERMINATE';
        try {
          this.database().fail(subject, id, reason, attempt);
        } catch {
          /* no successful response after durable loss */
        }
      })
      .finally(() => {
        this.pending.delete(task);
        this.active.delete(id);
      });
    this.pending.add(task);
  }
  async settled(): Promise<void> {
    await Promise.all([...this.pending]);
  }
  import(subject: string, body: unknown): { captureId: string; created: boolean } {
    const b = exact(body, ['idempotencyKey', 'package']);
    const key = str(b.idempotencyKey, ID);
    const p = exact(exact(b.package, ['payload', 'hash', 'signature']).payload, [
      'schema',
      'subject',
      'targetId',
      'targetVersion',
      'consentId',
      'nonce',
      'signerId',
      'sourceVersion',
      'capture',
    ]);
    const store = this.database();
    const closed = payload(p);
    validateCaptureHash(closed.capture);
    const envelope = exact(b.package, ['payload', 'hash', 'signature']);
    str(envelope.hash, HEX);
    str(envelope.signature, /^[A-Za-z0-9_-]{86}$/);
    if (digest(closed, 'runtime-import-v1') !== envelope.hash) fault('INVALID_RUNTIME_INPUT');
    if (closed.subject !== subject) fault('NOT_AUTHORIZED', 403);
    const prior = store.replay(subject, key, digest(closed, 'runtime-import-intent-v1'));
    if (prior) return { captureId: prior.captureId, created: false };
    const a = store.authority(subject, str(p.consentId, ID), 'imported-historical', true);
    const enrollment = store.enrollment(subject, a.target.targetId)!;
    const checked = verifyImport(b.package, enrollment, a, store.clock());
    const result = store.begin(subject, key, checked.fingerprint, a.consentId, 'imported-historical');
    if (result.created)
      this.schedule(result.captureId, subject, result.attempt, async (signal) => {
        if (signal.aborted) return;
        store.commit(
          subject,
          result.captureId,
          result.attempt,
          checked.payload.capture,
          { signerId: checked.payload.signerId, sourceVersion: checked.payload.sourceVersion },
          checked.payload.nonce,
        );
      });
    return { captureId: result.captureId, created: result.created };
  }
  capture(subject: string, body: unknown): { captureId: string; created: boolean } {
    const b = exact(body, ['idempotencyKey', 'consentId', 'targetId']);
    const store = this.database();
    const consentId = str(b.consentId, ID),
      targetId = str(b.targetId, ID),
      key = str(b.idempotencyKey, ID);
    const fingerprint = digest({ targetId, consentId, mode: 'broker-capture' }, 'runtime-live-intent-v1');
    const prior = store.replay(subject, key, fingerprint);
    if (prior) return { captureId: prior.captureId, created: false };
    const a = store.authority(subject, consentId, 'broker-capture', true);
    if (a.target.targetId !== targetId) fault('NOT_AUTHORIZED', 403);
    if (!this.live?.available()) fault('QUALIFICATION_MISSING', 403);
    const result = store.begin(subject, key, fingerprint, a.consentId, 'broker-capture');
    if (result.created)
      this.schedule(result.captureId, subject, result.attempt, async (signal) => {
        const port = this.live!;
        const permitted = () =>
          store.active(subject, result.captureId, result.attempt) &&
          (() => {
            try {
              store.authority(subject, a.consentId, 'broker-capture');
              return true;
            } catch {
              return false;
            }
          })();
        await port.capture(
          { ...a, captureId: result.captureId, attempt: result.attempt },
          signal,
          permitted,
          (evidence: Capture) => store.commit(subject, result.captureId, result.attempt, evidence, null),
        );
      });
    return { captureId: result.captureId, created: result.created };
  }
  async cancel(subject: string, id: string) {
    const result = this.database().cancel(subject, str(id, ID));
    if (result.changed) {
      this.active.get(id)?.abort();
      if (this.live && result.fence) {
        try {
          await this.live.revoke(result.fence);
        } catch {
          fault('INDETERMINATE', 503);
        }
      }
    }
    return { changed: result.changed, cancelled: result.cancelled, state: result.state };
  }
  async imageLink(subject: string, id: string, body: unknown) {
    const b = exact(body, ['imageScanId']);
    const store = this.database();
    const r = store.read(subject, str(id, ID));
    const imageScanId = str(b.imageScanId, /^[a-f0-9-]{36}$/);
    if (r.state !== 'completed' || !r.evidence?.imageConfigDigest) fault('IMAGE_LINK_UNAVAILABLE', 409);
    const prior = r.links.find((l) => l.imageScanId === imageScanId);
    if (prior) return prior;
    if (r.links.length >= 8) fault('RUNTIME_CAPACITY', 429);
    const key = canonical([subject, id, imageScanId]);
    const running = this.links.get(key);
    if (running) return running.result;
    if (this.links.size >= 2 || [...this.links.values()].some((l) => l.subject === subject))
      fault('RUNTIME_CAPACITY', 429);
    store.admit(subject);
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const work = Promise.resolve()
      .then(() => this.images.resolve(subject, imageScanId, r.evidence!, controller.signal))
      .then((association) => {
        if (controller.signal.aborted) fault('IMAGE_LINK_UNAVAILABLE', 409);
        return store.associate(subject, id, association);
      })
      .finally(() => {
        clearTimeout(timer);
        this.links.delete(key);
      });
    // An uncooperative loader retains its slot until actual settlement; timeout must not reopen aggregate I/O.
    const result = Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new RuntimeFault('IMAGE_LINK_UNAVAILABLE', 409));
        }, 5000);
      }),
    ]);
    this.links.set(key, { subject, controller, result });
    return result;
  }
  onModuleDestroy(): void {
    for (const a of this.active.values()) a.abort();
    for (const l of this.links.values()) l.controller.abort();
  }
}
