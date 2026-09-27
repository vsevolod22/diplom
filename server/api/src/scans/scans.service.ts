import { BadRequestException, ConflictException, Inject, Injectable, NotFoundException, ServiceUnavailableException, HttpException, HttpStatus } from '@nestjs/common';
import { LedgerStore } from '../ledger/ledger-store.js';
import { AdmissionLimited, IdempotencyConflict } from '../ledger/ledger.js';
import { OciResolver } from '../oci/oci-resolver.js';
import { parseScanRequest } from './scan-request.js';
import { chainReady } from './scan-readiness.js';
import type { Identity } from '../security/identity.js';

const allowed = new Set(['registry-1.docker.io']);
const unavailable = () => new ServiceUnavailableException({ errorCode: 'SCANNER_UNAVAILABLE' });
type Receipt = { scanId: string; statusUrl: string; eventsUrl: string };
const receipt = (scanId: string): Receipt => ({ scanId, statusUrl: `/api/v1/scans/${scanId}`,
  eventsUrl: `/api/v1/scans/${scanId}/events` });

@Injectable()
export class ScansService {
  constructor(
    @Inject(LedgerStore) private readonly ledgerStore: LedgerStore,
    @Inject(OciResolver) private readonly resolver: OciResolver,
  ) {}

  protected readiness(): Promise<boolean> { return chainReady(); }

  async create(identity: Identity, body: unknown): Promise<Receipt> {
    const ledger = this.ledgerStore.ledger;
    if (!ledger) throw unavailable();
    const reject = (reason: 'INVALID_REQUEST' | 'UNSUPPORTED' | 'CAPACITY' | 'EGRESS') => {
      try { ledger.audit(identity.subject, 'unknown', 'unknown', 'rejected', reason); }
      catch { throw unavailable(); }
    };
    let request;
    try { request = parseScanRequest(body, allowed); }
    catch { reject('INVALID_REQUEST'); throw new BadRequestException({ errorCode: 'INVALID_SCAN_REQUEST' }); }
    // The deliberately narrow first release supports a single public repo, secret
    // checks without a runtime vulnerability DB, and one explicit platform only.
    if (request.reference.repository !== 'library/alpine' ||
        request.checks.length !== 1 || request.checks[0] !== 'secret') {
      reject('UNSUPPORTED');
      throw new BadRequestException({ errorCode: 'UNSUPPORTED_SCAN' });
    }
    let existing;
    try { existing = ledger.findByKey(identity.subject, request.idempotencyKey); }
    catch { throw unavailable(); }
    if (existing) {
      if (existing.fingerprint !== request.fingerprint) throw new ConflictException({ errorCode: 'IDEMPOTENCY_CONFLICT' });
      return receipt(existing.scanId);
    }
    try {
      ledger.checkAdmission(identity.subject);
      ledger.reserveAttempt(identity.subject);
      if (!(await this.readiness())) { reject('EGRESS'); throw unavailable(); }
      const pinned = await this.resolver.resolvePublicAlpine(request.reference);
      // A worker/gateway outage during resolution must not enqueue a new task.
      if (!(await this.readiness())) { reject('EGRESS'); throw unavailable(); }
      const { scanId } = ledger.enqueue({ subject: identity.subject, idempotencyKey: request.idempotencyKey,
        registry: pinned.registry, repository: pinned.repository, digest: pinned.digest, platform: pinned.platform,
        fingerprint: request.fingerprint, checks: JSON.stringify(request.checks), scope: request.scope });
      return receipt(scanId);
    } catch (error) {
      if (error instanceof IdempotencyConflict || error instanceof AdmissionLimited) {
        // A concurrent enqueue may have won while the mutable tag changed. Compare
        // only the original request fingerprint, never the second resolution's digest.
        let replay;
        try { replay = ledger.findByKey(identity.subject, request.idempotencyKey); }
        catch { throw unavailable(); }
        if (replay?.fingerprint === request.fingerprint) return receipt(replay.scanId);
        if (error instanceof AdmissionLimited && !replay) {
          reject('CAPACITY');
          throw new HttpException({ errorCode: 'SCAN_CAPACITY', retryAfterSeconds: 60 }, HttpStatus.TOO_MANY_REQUESTS);
        }
        throw new ConflictException({ errorCode: 'IDEMPOTENCY_CONFLICT' });
      }
      if (error instanceof ServiceUnavailableException || error instanceof HttpException) throw error;
      reject('EGRESS');
      // No registry response, raw SQLite diagnostic or signed redirect URL in HTTP.
      throw unavailable();
    }
  }

  status(identity: Identity, scanId: string) {
    if (!/^[a-f0-9-]{36}$/.test(scanId)) throw new NotFoundException();
    const state = this.ledgerStore.ledger?.state(scanId, identity.subject);
    if (!state) throw new NotFoundException();
    return { scanId, state, result: this.ledgerStore.ledger?.result(scanId, identity.subject) ?? null };
  }

  results(identity: Identity, scanId: string, cursor: string | undefined, limit: string | undefined) {
    if (!/^[a-f0-9-]{36}$/.test(scanId)) throw new NotFoundException();
    if (cursor !== undefined && !/^(0|[1-9]\d{0,5})$/.test(cursor) ||
        limit !== undefined && !/^(?:[1-9]|[1-9]\d|100)$/.test(limit)) throw new BadRequestException({ errorCode: 'INVALID_PAGINATION' });
    const ledger = this.ledgerStore.ledger;
    const result = ledger?.findings(scanId, identity.subject, Number(cursor ?? 0), Number(limit ?? 50));
    if (!result) throw new NotFoundException();
    return { ...result, coverage: ledger?.result(scanId, identity.subject) ?? null };
  }

  events(identity: Identity, scanId: string, lastId: string | undefined) {
    if (!/^[a-f0-9-]{36}$/.test(scanId)) throw new NotFoundException();
    if (lastId !== undefined && !/^(0|[1-9]\d{0,15})$/.test(lastId)) throw new BadRequestException({ errorCode: 'INVALID_EVENT_ID' });
    const events = this.ledgerStore.ledger?.events(scanId, identity.subject, lastId === undefined ? null : Number(lastId));
    if (!events) throw new NotFoundException();
    return events.map(event => `id: ${event.id}\nevent: scan\ndata: ${JSON.stringify({ scanId, state: event.state, percent: null })}\n\n`).join('') + ': snapshot response complete\n\n';
  }
}
