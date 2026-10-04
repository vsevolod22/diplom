import { BadRequestException, ConflictException, ForbiddenException, Inject, Injectable, NotFoundException, ServiceUnavailableException, HttpException, HttpStatus } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { createHash, createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { isAbsolute } from 'node:path';

import { LedgerStore } from '../ledger/ledger-store.js';
import { AdmissionLimited, IdempotencyConflict } from '../ledger/ledger.js';
import { OciResolver } from '../oci/oci-resolver.js';
import { parseScanRequest } from './scan-request.js';
import { preflightVulnDbBundle } from '../worker/vuln-db-bundle.js';
import { chainReady } from './scan-readiness.js';
import type { Identity } from '../security/identity.js';
import type { ImageReference } from './image-reference.js';
import type { ImageSuggestion } from './image-search.js';

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

  // Production is closed to archive candidates. Only a separately composed proof
  // server overrides these hooks; there is deliberately no environment enable flag.
  protected acceptsReference(reference: ImageReference): boolean {
    return reference.registry === 'registry-1.docker.io' && reference.repository === 'library/alpine';
  }
  protected resolveTarget(reference: ImageReference) { return this.resolver.resolvePublicAlpine(reference); }
  protected acceptsPinned(pinned: { registry: string; repository: string; platform: string; digest: string }): boolean {
    return pinned.registry === 'registry-1.docker.io' && pinned.repository === 'library/alpine' && pinned.platform === 'linux/amd64';
  }
  imageSuggestion(suggestion: ImageSuggestion): ImageSuggestion { return suggestion; }

  protected async vulnDbReady(): Promise<boolean> {
    const directory = process.env.SCAN_VULN_RELEASE_DIR;
    const manifest = process.env.SCAN_VULN_MANIFEST_DIGEST;
    const artifact = process.env.SCAN_VULN_ARTIFACT_SHA256;
    if (!directory || !isAbsolute(directory) || !/^sha256:[a-f0-9]{64}$/.test(manifest ?? '') ||
        !/^[a-f0-9]{64}$/.test(artifact ?? '')) return false;
    try {
      const key = await readFile(new URL('../../../deploy/trust/db-signing-key.pub.pem', import.meta.url));
      // Reject a replaced trust anchor, even if the path exists in a local installation.
      const publicKey = createPublicKey(key);
      if (createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex') !==
          'd75c6f6b2384de68978090fc837387ab4f3e878ee004bccf27ea98a84fbee078') return false;
      await preflightVulnDbBundle({ directory, trustedPublicKeyPem: key.toString('utf8'),
        expectedSigner: 'local-db-operator-v1', expectedSource: `ghcr.io/aquasecurity/trivy-db@${manifest}`,
        expectedSchemaVersion: 2, expectedManifestDigest: manifest!, expectedArtifactSha256: artifact!, now: new Date() });
      return true;
    } catch { return false; }
  }

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
    // Check policy before replay too: a seeded closed candidate cannot gain public admission.
    if (!this.acceptsReference(request.reference)) {
      reject('UNSUPPORTED');
      throw new BadRequestException({ errorCode: 'UNSUPPORTED_SCAN' });
    }
    if (request.checks.includes('vuln')) {
      if (process.env.SCAN_VULN_ENABLED !== 'true') {
        reject('UNSUPPORTED');
        throw unavailable();
      }
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
      // Charge admission before hashing the operator's DB release (up to 2 GiB).
      if (request.checks.includes('vuln') && !(await this.vulnDbReady())) { reject('UNSUPPORTED'); throw unavailable(); }
      if (!(await this.readiness())) { reject('EGRESS'); throw unavailable(); }
      const pinned = await this.resolveTarget(request.reference);
      if (!this.acceptsPinned(pinned)) { reject('UNSUPPORTED'); throw unavailable(); }
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

  cancel(identity: Identity, scanId: string, body: unknown) {
    if (!identity.scope.includes('scan:cancel')) throw new ForbiddenException();
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length !== 0)
      throw new BadRequestException({ errorCode: 'INVALID_CANCEL_REQUEST' });
    if (!/^[a-f0-9-]{36}$/.test(scanId)) throw new NotFoundException();
    const ledger = this.ledgerStore.ledger;
    if (!ledger) throw unavailable();
    const outcome = ledger.cancel(scanId, identity.subject);
    if (outcome === 'not_found') throw new NotFoundException();
    if (outcome === 'conflict') throw new ConflictException({ errorCode: 'SCAN_TERMINAL' });
    return { scanId, state: 'cancelled' };
  }

  list(identity: Identity, cursor: string | undefined, limit: string | undefined) {
    if (!identity.scope.includes('scan:list')) throw new ForbiddenException();
    if (cursor !== undefined && !/^[1-9]\d{0,14}:[1-9]\d{0,14}$/.test(cursor) ||
        limit !== undefined && !/^(?:[1-9]|[1-9]\d|100)$/.test(limit)) throw new BadRequestException({ errorCode: 'INVALID_PAGINATION' });
    if (cursor !== undefined) {
      const [bound, last] = cursor.split(':').map(Number);
      if (!Number.isSafeInteger(bound) || !Number.isSafeInteger(last) || last > bound + 1)
        throw new BadRequestException({ errorCode: 'INVALID_PAGINATION' });
    }
    const ledger = this.ledgerStore.ledger;
    if (!ledger) throw unavailable();
    return ledger.list(identity.subject, cursor, Number(limit ?? 50));
  }

  status(identity: Identity, scanId: string) {
    if (!/^[a-f0-9-]{36}$/.test(scanId)) throw new NotFoundException();
    const ledger = this.ledgerStore.ledger;
    const snapshot = ledger?.snapshot(scanId, identity.subject);
    if (!snapshot) throw new NotFoundException();
    const archive = ledger?.archiveResult(scanId, identity.subject);
    if (archive) {
      const checks = ledger!.requestedChecks(scanId, identity.subject);
      const perCheck = Object.fromEntries(checks.map(check => {
        const result = archive[check as 'secret' | 'sbom' | 'vuln'];
        return [check, result ? { check, coverage: 'image', outcome: result.outcome,
          errorCode: result.outcome === 'failed' ? (result.reason === 'SCAN_TIMEOUT' ? 'SCAN_TIMEOUT' : 'SCAN_FAILED') : null,
          ...(result.outcome !== 'checked' ? { reason: result.reason } : {}),
          ...(check === 'secret' && archive.secret?.outcome === 'checked' ? { findingCount: archive.secret.findings.length } : {}),
          ...(check === 'sbom' && archive.sbom?.outcome === 'checked' ? { componentCount: archive.sbom.sbom.components.length } : {}),
          ...(check === 'vuln' && archive.vuln?.outcome === 'checked' ? { findingCount: archive.vuln.findings.length } : {}),
          ...(check === 'vuln' && archive.vuln && archive.vuln.outcome !== 'failed' ?
            { os: archive.vuln.os, node: archive.vuln.node, db: archive.vuln.db } : {}),
          scannerVersion: archive.scannerVersion, checksVersion: archive.receipt.checksVersion, checkedAt: new Date(archive.checkedAt).toISOString() } : null];
      }));
      return { scanId, ...snapshot, imageReference: `${archive.receipt.registry}/${archive.receipt.repository}@${archive.receipt.digest}`,
        checks, perCheck, result: checks.length === 1 ? perCheck[checks[0]] : null,
        imageProfile: { version: archive.receipt.profileVersion, configDigest: archive.receipt.configDigest,
          resourcePolicyVersion: archive.receipt.resourcePolicyVersion, qualified: false },
        coverage: 'image', checkedIsNotSafe: true };
    }
    const sbom = ledger?.sbom(scanId, identity.subject);
    const sbomCoverage = sbom?.outcome === 'checked'
      ? { check: 'sbom', coverage: sbom.coverage, outcome: sbom.outcome, componentCount: sbom.componentCount,
          scannerVersion: sbom.scannerVersion, checkedAt: sbom.checkedAt }
      : sbom?.outcome === 'failed'
        ? { check: 'sbom', coverage: sbom.coverage, outcome: sbom.outcome, errorCode: sbom.errorCode }
        : null;
    const checks = ledger!.requestedChecks(scanId, identity.subject);
    const secret = ledger?.result(scanId, identity.subject);
    const vuln = checks.includes('vuln') ? ledger?.vuln(scanId, identity.subject, 0, 1) : undefined;
    const vulnCoverage = vuln?.outcome === 'checked'
      ? { check: 'vuln', coverage: vuln.coverage, outcome: vuln.outcome, findingCount: vuln.findingCount,
          scannerVersion: vuln.scannerVersion, checkedAt: vuln.checkedAt }
      : vuln?.outcome === 'failed'
        ? { check: 'vuln', coverage: vuln.coverage, outcome: vuln.outcome, errorCode: vuln.errorCode }
        : null;
    const perCheck = Object.fromEntries(checks.map(check => [check,
      check === 'secret' ? secret ?? null : check === 'sbom' ? sbomCoverage : vulnCoverage]));
    const check = checks.length === 1 ? checks[0] : undefined;
    return { scanId, ...snapshot, ...(checks.length ? { checks, perCheck } : {}), ...(check ? { check } : {}),
      result: checks.length === 1 ? perCheck[checks[0]] : null };
  }

  results(identity: Identity, scanId: string, cursor: string | undefined, limit: string | undefined) {
    if (!/^[a-f0-9-]{36}$/.test(scanId)) throw new NotFoundException();
    if (cursor !== undefined && !/^(0|[1-9]\d{0,5})$/.test(cursor) ||
        limit !== undefined && !/^(?:[1-9]|[1-9]\d|100)$/.test(limit)) throw new BadRequestException({ errorCode: 'INVALID_PAGINATION' });
    const ledger = this.ledgerStore.ledger;
    const archive = ledger?.archiveResult(scanId, identity.subject);
        if (archive?.secret) {
          const result = archive.secret;
          if (result.outcome !== 'checked') return { findings: [], nextCursor: null, coverage: {
            check: 'secret', coverage: 'image', outcome: result.outcome, reason: result.reason, findingCount: 0,
            errorCode: result.reason === 'SCAN_TIMEOUT' ? 'SCAN_TIMEOUT' : 'SCAN_FAILED', scannerVersion: archive.scannerVersion } };
          const start = Number(cursor ?? 0), end = Math.min(start + Number(limit ?? 50), result.findings.length);
          if (start > result.findings.length) throw new BadRequestException({ errorCode: 'INVALID_PAGINATION' });
          return { findings: result.findings.slice(start, end), nextCursor: end < result.findings.length ? end : null,
            coverage: { check: 'secret', outcome: 'checked', coverage: 'image', findingCount: result.findings.length, errorCode: null,
              scannerVersion: archive.scannerVersion, checkedAt: new Date(archive.checkedAt).toISOString() } };
        }
        const result = ledger?.findings(scanId, identity.subject, Number(cursor ?? 0), Number(limit ?? 50));
    if (!result) throw new NotFoundException();
    return { ...result, coverage: ledger?.result(scanId, identity.subject) ?? null };
  }

  sbom(identity: Identity, scanId: string, cursor: string | undefined, limit: string | undefined) {
    if (!/^[a-f0-9-]{36}$/.test(scanId)) throw new NotFoundException();
    if (cursor !== undefined && !/^(0|[1-9]\d{0,5})$/.test(cursor) ||
        limit !== undefined && !/^(?:[1-9]|[1-9]\d|100)$/.test(limit))
      throw new BadRequestException({ errorCode: 'INVALID_PAGINATION' });
    const ledger = this.ledgerStore.ledger;
    if (!ledger) throw unavailable();
    const archive = ledger.archiveResult(scanId, identity.subject);
        if (archive?.sbom) {
          const result = archive.sbom;
          if (result.outcome !== 'checked') return { outcome: result.outcome, reason: result.reason,
            errorCode: result.reason === 'SCAN_TIMEOUT' ? 'SCAN_TIMEOUT' : 'SCAN_FAILED', coverage: 'image', components: [], nextCursor: null };
          const start = Number(cursor ?? 0), end = Math.min(start + Number(limit ?? 50), result.sbom.components.length);
          if (start > result.sbom.components.length) throw new BadRequestException({ errorCode: 'INVALID_PAGINATION' });
          return { outcome: 'checked', coverage: 'image', image: result.sbom.image, platform: result.sbom.platform,
            os: result.sbom.os, components: result.sbom.components.slice(start, end), componentCount: result.sbom.components.length,
            nextCursor: end < result.sbom.components.length ? end : null, scannerVersion: archive.scannerVersion, checkedAt: new Date(archive.checkedAt).toISOString() };
        }
        const report = ledger.sbom(scanId, identity.subject, Number(cursor ?? 0), Number(limit ?? 50));
    if (!report) throw new NotFoundException();
    if (report.outcome === 'checked' && Number(cursor ?? 0) > report.componentCount)
      throw new BadRequestException({ errorCode: 'INVALID_PAGINATION' });
    return report;
  }

  vuln(identity: Identity, scanId: string, cursor: string | undefined, limit: string | undefined) {
    if (!/^[a-f0-9-]{36}$/.test(scanId)) throw new NotFoundException();
    if (cursor !== undefined && !/^(0|[1-9]\d{0,5})$/.test(cursor) ||
        limit !== undefined && !/^(?:[1-9]|[1-9]\d|100)$/.test(limit))
      throw new BadRequestException({ errorCode: 'INVALID_PAGINATION' });
    const ledger = this.ledgerStore.ledger;
    if (!ledger) throw unavailable();
    const archive = ledger.archiveResult(scanId, identity.subject);
        if (archive?.vuln) {
          const result = archive.vuln;
          if (result.outcome !== 'checked') return { outcome: result.outcome, reason: result.reason,
            ...(result.outcome === 'failed' ? { errorCode: result.reason === 'SCAN_TIMEOUT' ? 'SCAN_TIMEOUT' : 'SCAN_FAILED' } : {}),
            coverage: 'image', findings: [], nextCursor: null,
            ...(result.outcome === 'unsupported' ? { os: result.os, node: result.node, db: result.db } : {}) };
          const start = Number(cursor ?? 0), end = Math.min(start + Number(limit ?? 50), result.findings.length);
          if (start > result.findings.length) throw new BadRequestException({ errorCode: 'INVALID_PAGINATION' });
          return { outcome: 'checked', coverage: 'image', image: `${archive.receipt.registry}/${archive.receipt.repository}@${archive.receipt.digest}`,
            platform: archive.receipt.platform, findings: result.findings.slice(start, end), findingCount: result.findings.length,
            nextCursor: end < result.findings.length ? end : null, db: result.db, os: result.os, node: result.node,
            scannerVersion: archive.scannerVersion, checkedAt: new Date(archive.checkedAt).toISOString() };
        }
        const report = ledger.vuln(scanId, identity.subject, Number(cursor ?? 0), Number(limit ?? 50));
    if (!report) throw new NotFoundException();
    if (report.outcome === 'checked' && Number(cursor ?? 0) > report.findingCount)
      throw new BadRequestException({ errorCode: 'INVALID_PAGINATION' });
    return report;
  }

  private activeStreams = 0;
  private readonly streamsBySubject = new Map<string, number>();

  events(identity: Identity, scanId: string, lastId: string | string[] | undefined, response: ServerResponse): void {
    if (!/^[a-f0-9-]{36}$/.test(scanId)) throw new NotFoundException();
    if (lastId !== undefined && (typeof lastId !== 'string' || !/^(0|[1-9]\d{0,15})$/.test(lastId) ||
        !Number.isSafeInteger(Number(lastId)))) throw new BadRequestException({ errorCode: 'INVALID_EVENT_ID' });
    const ledger = this.ledgerStore.ledger;
    if (!ledger) throw unavailable();
    let cursor = lastId === undefined ? 0 : Number(lastId);
    // Validate ownership and the cursor before writing any SSE headers. Raw SQLite errors
    // must never escape as HTTP diagnostics, including from later polling callbacks.
    try {
      if (!ledger.events(scanId, identity.subject, cursor)) throw new NotFoundException();
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw unavailable();
    }
    const subject = identity.subject;
    const subjectStreams = this.streamsBySubject.get(subject) ?? 0;
    if (this.activeStreams >= 64 || subjectStreams >= 6)
      throw new HttpException({ errorCode: 'SCAN_STREAM_CAPACITY' }, HttpStatus.TOO_MANY_REQUESTS);
    this.activeStreams++;
    this.streamsBySubject.set(subject, subjectStreams + 1);
    let closed = false;
    let lastHeartbeat = Date.now();
    let timer: ReturnType<typeof setInterval> | undefined;
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const cleanup = () => {
      if (closed) return;
      closed = true;
      if (timer) clearInterval(timer);
      if (deadline) clearTimeout(deadline);
      response.off('close', cleanup);
      this.activeStreams--;
      const remaining = this.streamsBySubject.get(subject)! - 1;
      if (remaining === 0) this.streamsBySubject.delete(subject);
      else this.streamsBySubject.set(subject, remaining);
    };
    const end = () => { cleanup(); if (!response.destroyed) response.end(); };
    const write = (chunk: string): boolean => {
      if (closed || response.destroyed) { cleanup(); return false; }
      try {
        // Do not queue unbounded data for a slow reader. Reconnect will replay from ledger.
        if (!response.write(chunk)) { end(); return false; }
        return true;
      } catch { end(); return false; }
    };
    const poll = () => {
      if (closed) return;
      try {
        const events = ledger.events(scanId, identity.subject, cursor);
        if (!events) { end(); return; } // deleted/pruned or no longer visible
        for (const event of events) {
          if (!write(`id: ${event.id}\nevent: scan\ndata: ${JSON.stringify({ scanId, state: event.state, percent: null })}\n\n`)) return;
          cursor = event.id;
          if (['completed', 'partial', 'failed', 'cancelled'].includes(event.state)) { end(); return; }
        }
        // A terminal transition may have committed after the last event read. It is
        // already in the ledger, or the cursor is past it (reconnect after terminal).
        // Drain full pages before checking the snapshot, so the last event is not lost.
        if (events.length < 100 && ['completed', 'partial', 'failed', 'cancelled'].includes(ledger.state(scanId, identity.subject) ?? '') &&
            ledger.events(scanId, identity.subject, cursor)?.length === 0) {
          end(); return;
        }
        if (Date.now() - lastHeartbeat >= 15_000) {
          if (!write(': heartbeat\n\n')) return;
          lastHeartbeat = Date.now();
        }
      } catch {
        write('event: error\ndata: {"errorCode":"SCANNER_UNAVAILABLE"}\n\n');
        end();
      }
    };
    response.on('close', cleanup);
    try {
      response.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store',
        'Connection': 'keep-alive', 'X-Accel-Buffering': 'no' });
      if (!write('retry: 2000\n\n')) return;
      timer = setInterval(poll, 1000);
      deadline = setTimeout(end, 120_000);
      // Read again after attaching the disconnect listener and starting polling: any
      // transition between validation and attachment is replayed by this read.
      poll();
    } catch { end(); }
  }
}
