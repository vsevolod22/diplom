import { BadRequestException, ConflictException, ForbiddenException, Inject, Injectable, NotFoundException, ServiceUnavailableException, HttpException, HttpStatus } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { createHash, createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { isAbsolute } from 'node:path';

import { LedgerStore } from '../ledger/ledger-store.js';
import { AdmissionLimited, IdempotencyConflict, type ScanLedger } from '../ledger/ledger.js';
import { OciResolver } from '../oci/oci-resolver.js';
import { parseScanRequest } from './scan-request.js';
import { assertDbFreshness, preflightVulnDbBundle, type VerifiedDbIdentity } from '../worker/vuln-db-bundle.js';
import { CURRENT_DB_POLICY } from '../worker/cve-db-policy.mjs';
import { dbEvidenceMetadata, type CveDbEvidence } from '../worker/cve-db-evidence.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';
import { chainReady } from './scan-readiness.js';
import type { Identity } from '../security/identity.js';
import type { ImageReference } from './image-reference.js';
import type { ImageSuggestion } from './image-search.js';
import { localReceiptMatches, type LocalExecutionBinding } from '../oci/nginx-local-policy.js';
import { hasReportView, parseReportQuery, ReportViewError, type ReportKind } from './report-query.js';
import { pageVuln, pageSbom, pageSecrets } from './report-page.js';

const allowed = new Set(['registry-1.docker.io']);
const unavailable = () => new ServiceUnavailableException({ errorCode: 'SCANNER_UNAVAILABLE' });
function dbStillUsable(identity: Readonly<VerifiedDbIdentity> | boolean | undefined): boolean {
  if (!identity || typeof identity !== 'object') return false;
  try { assertDbFreshness(identity, Date.now(), CURRENT_DB_POLICY); return true; }
  catch { return false; }
}
function archivePolicyMetadata(report: ArchiveScanReport) {
  const vuln = report.vuln;
  if (!vuln || vuln.outcome === 'failed' || !vuln.db || !vuln.dbPolicy) return {};
  return policyMetadata({ db: vuln.db, checkedAt: report.checkedAt, dbPolicy: vuln.dbPolicy });
}
function policyMetadata(evidence: CveDbEvidence) {
  const { checkedAt, ...metadata } = dbEvidenceMetadata(evidence);
  return { ...metadata, workerCheckedAt: checkedAt };
}
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
  // eslint-disable-next-line @typescript-eslint/no-unused-vars -- Keep the proof subclass hook signature; production accepts any parsed check set.
  protected acceptsChecks(_reference: ImageReference, _checks: readonly string[]): boolean { return true; }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars -- Proof subclasses bind the reference; production has no archive binding.
  protected executionBinding(_reference: ImageReference): LocalExecutionBinding | undefined { return undefined; }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars -- Preserve the reference-aware proof subclass hook signature.
  protected allowedCheckSets(_reference: ImageReference): readonly (readonly string[])[] {
    return Array.from({ length: 15 }, (_, mask) => ['secret', 'sbom', 'vuln', 'config'].filter((_, bit) => (mask + 1) & (1 << bit)));
  }
  protected resolveTarget(reference: ImageReference) { return this.resolver.resolvePublicAlpine(reference); }
  protected acceptsPinned(pinned: { registry: string; repository: string; platform: string; digest: string }): boolean {
    return pinned.registry === 'registry-1.docker.io' && pinned.repository === 'library/alpine' && pinned.platform === 'linux/amd64';
  }
  imageSuggestion(suggestion: ImageSuggestion): ImageSuggestion { return suggestion; }

  // Historical subclasses may still return boolean; true is NOT authenticated v2 authority.
  protected async vulnDbReady(): Promise<Readonly<VerifiedDbIdentity> | boolean> {
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
      const verified = await preflightVulnDbBundle({ directory, trustedPublicKeyPem: key.toString('utf8'),
        expectedSigner: 'local-db-operator-v1', expectedSource: `ghcr.io/aquasecurity/trivy-db@${manifest}`,
        expectedSchemaVersion: 2, expectedManifestDigest: manifest!, expectedArtifactSha256: artifact!, policy: CURRENT_DB_POLICY });
      return verified.identity;
    } catch { return false; }
  }

  async create(identity: Identity, body: unknown): Promise<Receipt> {
    if (!identity.scope.includes('scan:create')) throw new ForbiddenException();
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
    if (!this.acceptsReference(request.reference) || !this.acceptsChecks(request.reference, request.checks)) {
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
      const db = request.checks.includes('vuln') ? await this.vulnDbReady() : undefined;
            if (request.checks.includes('vuln') && (!db || typeof db !== 'object')) { reject('UNSUPPORTED'); throw unavailable(); }
      if (!(await this.readiness())) { reject('EGRESS'); throw unavailable(); }
      const pinned = await this.resolveTarget(request.reference);
      if (!this.acceptsPinned(pinned)) { reject('UNSUPPORTED'); throw unavailable(); }
      // A worker/gateway outage during resolution must not enqueue a new task.
      if (!(await this.readiness())) { reject('EGRESS'); throw unavailable(); }
      // Hashing/readiness/resolution may cross the deadline: use only this request's authenticated identity.
            if (request.checks.includes('vuln') && !dbStillUsable(db)) { reject('UNSUPPORTED'); throw unavailable(); }
            const { scanId } = ledger.enqueue({ subject: identity.subject, idempotencyKey: request.idempotencyKey,
        registry: pinned.registry, repository: pinned.repository, digest: pinned.digest, platform: pinned.platform,
        fingerprint: request.fingerprint, checks: JSON.stringify(request.checks), scope: request.scope,
        executionProfile: this.executionBinding(request.reference),
                ...(request.checks.includes('vuln') ? { cvePolicy: CURRENT_DB_POLICY } : {}) });
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

  private readonly eligibilityRates = new Map<string, { until: number; count: number; active: number }>();
  private eligibilityActive = 0;
  protected eligibilityNow(): number { return Date.now(); }
  async eligibility(identity: Identity, body: unknown) {
    if (!identity.scope.includes('scan:create')) throw new ForbiddenException();
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => !['imageReference', 'checks'].includes(key)))
      throw new BadRequestException({ errorCode: 'INVALID_SCAN_REQUEST' });
    let request;
    try { request = parseScanRequest({ ...body, scope: 'image', idempotencyKey: 'eligibility-only' }, allowed); }
    catch { throw new BadRequestException({ errorCode: 'INVALID_SCAN_REQUEST' }); }
    const now = this.eligibilityNow();
    const limited = (limitReason: 'rate' | 'concurrency' | 'capacity', retryAfterSeconds: number) => new HttpException({
      errorCode: limitReason === 'capacity' ? 'IMAGE_SEARCH_CAPACITY' : 'IMAGE_SEARCH_RATE_LIMITED',
      limitReason, retryAfterSeconds,
    }, HttpStatus.TOO_MANY_REQUESTS);
    for (const [subject, rate] of this.eligibilityRates) if (!rate.active && rate.until <= now) this.eligibilityRates.delete(subject);
    let rate = this.eligibilityRates.get(identity.subject);
    if (!rate) {
      if (this.eligibilityRates.size >= 1024) throw limited('capacity', 60);
      rate = { until: now + 60_000, count: 0, active: 0 }; this.eligibilityRates.set(identity.subject, rate);
    }
    // Keep the same entry while old work finishes: replacing it would lose active
    // accounting. Rollover and admission are synchronous, before the first await.
    if (rate.until <= now) { rate.until = now + 60_000; rate.count = 0; }
    if (++rate.count > 30) throw limited('rate', Math.max(1, Math.min(60, Math.ceil((rate.until - now) / 1000))));
    if (rate.active >= 2 || this.eligibilityActive >= 8) throw limited('concurrency', 1);
    const allowedReference = this.acceptsReference(request.reference);
    const sets = allowedReference ? this.allowedCheckSets(request.reference) : [];
    const binding = allowedReference ? this.executionBinding(request.reference) : undefined;
    const result = (eligible: boolean, reason: string) => ({ imageReference: request.reference.canonical, eligible,
      eligibility: binding ? 'qualified-exact-profile' : allowedReference ? request.reference.repository === 'library/alpine' ? 'alpine-only' : 'isolated-exact-profile' : 'unsupported',
      allowedCheckSets: sets, ...(binding ? { qualificationId: binding.qualificationId } : {}), reason });
    if (!allowedReference || !this.acceptsChecks(request.reference, request.checks)) return result(false, 'UNSUPPORTED_SCAN');
    rate.active++; this.eligibilityActive++;
    try {
      if (!this.ledgerStore.ledger || !(await this.readiness())) return result(false, 'SCANNER_UNAVAILABLE');
      if (request.checks.includes('vuln') && process.env.SCAN_VULN_ENABLED !== 'true') return result(false, 'DB_UNAVAILABLE');
      const db = request.checks.includes('vuln') ? await this.vulnDbReady() : undefined;
      if (request.checks.includes('vuln') && (!db || typeof db !== 'object')) return result(false, 'DB_UNAVAILABLE');
      const pinned = await this.resolveTarget(request.reference);
      if (!this.acceptsPinned(pinned) || !(await this.readiness())) return result(false, 'SCANNER_UNAVAILABLE');
      if (request.checks.includes('vuln') && !dbStillUsable(db)) return result(false, 'DB_UNAVAILABLE');
      return result(true, 'READY');
    } catch { return result(false, 'SCANNER_UNAVAILABLE'); }
    finally { rate.active--; this.eligibilityActive--; }
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
    const config = ledger!.configResult(scanId, identity.subject);
    const configCoverage = config ? { check: 'config', coverage: 'image', ...config.config,
      checksVersion: config.checksVersion, resourcePolicyVersion: config.resourcePolicyVersion,
      supportedRuleIds: config.supportedRuleIds, completedRuleIds: config.completedRuleIds,
      findingCount: config.findings.length } : null;
    const archive = ledger?.archiveResult(scanId, identity.subject);
    if (archive) {
      const checks = ledger!.requestedChecks(scanId, identity.subject);
      const perCheck = Object.fromEntries(checks.map(check => {
        if (check === 'config') return [check, configCoverage];
        const result = archive[check as 'secret' | 'sbom' | 'vuln'];
        return [check, result ? { check, coverage: 'image', outcome: result.outcome,
          errorCode: result.outcome === 'failed' ? (result.reason === 'SCAN_TIMEOUT' ? 'SCAN_TIMEOUT' : 'SCAN_FAILED') : null,
          ...(result.outcome !== 'checked' ? { reason: result.reason } : {}),
          ...(check === 'secret' && archive.secret?.outcome === 'checked' ? { findingCount: archive.secret.findings.length } : {}),
          ...(check === 'sbom' && archive.sbom?.outcome === 'checked' ? { componentCount: archive.sbom.sbom.components.length } : {}),
          ...(check === 'vuln' && archive.vuln?.outcome === 'checked' ? { findingCount: archive.vuln.findings.length } : {}),
          ...(check === 'vuln' && archive.vuln && archive.vuln.outcome !== 'failed' ?
            { os: archive.vuln.os, node: archive.vuln.node, db: archive.vuln.db, ...archivePolicyMetadata(archive) } : {}),
          scannerVersion: archive.scannerVersion, checksVersion: archive.receipt.checksVersion, checkedAt: new Date(archive.checkedAt).toISOString() } : null];
      }));
      const executionProfile = ledger!.executionProfile(scanId);
      const qualified = !!executionProfile && localReceiptMatches(archive.receipt, archive.scannerVersion);
      return { scanId, ...snapshot, imageReference: `${archive.receipt.registry}/${archive.receipt.repository}@${archive.receipt.digest}`,
        checks, perCheck, ...(config ? { config } : {}), result: checks.length === 1 ? perCheck[checks[0]] : null,
        imageProfile: { version: archive.receipt.profileVersion, configDigest: archive.receipt.configDigest,
          resourcePolicyVersion: archive.receipt.resourcePolicyVersion, qualified },
        ...(qualified ? { executedQualification: executionProfile } : {}),
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
          scannerVersion: vuln.scannerVersion, checkedAt: vuln.checkedAt,
          ...(vuln.dbEvidence ? policyMetadata(vuln.dbEvidence) : {}) }
      : vuln?.outcome === 'failed'
        ? { check: 'vuln', coverage: vuln.coverage, outcome: vuln.outcome, errorCode: vuln.errorCode }
        : null;
    const perCheck = Object.fromEntries(checks.map(check => [check,
      check === 'secret' ? secret ?? null : check === 'sbom' ? sbomCoverage : check === 'vuln' ? vulnCoverage : configCoverage]));
    const check = checks.length === 1 ? checks[0] : undefined;
    return { scanId, ...snapshot, ...(config ? { config } : {}), ...(checks.length ? { checks, perCheck } : {}), ...(check ? { check } : {}),
      result: checks.length === 1 ? perCheck[checks[0]] : null };
  }

  report(identity: Identity, scanId: string, kind: ReportKind, rawQuery: unknown) {
    try {
      if (!hasReportView(rawQuery)) {
        parseReportQuery(kind, rawQuery);
        const { cursor, limit } = rawQuery as { cursor?: string; limit?: string };
        return kind === 'vuln' ? this.vuln(identity, scanId, cursor, limit) :
          kind === 'sbom' ? this.sbom(identity, scanId, cursor, limit) : this.results(identity, scanId, cursor, limit);
      }
      if (!/^[a-f0-9-]{36}$/.test(scanId)) throw new NotFoundException();
      const ledger = this.ledgerStore.ledger;
      if (!ledger) throw unavailable();
      // Keep ownership, metadata and all rows in one read snapshot. Hash/sort only
      // after releasing it; a cursor is consistency metadata, never authorization.
      const source = ledger.readReportSnapshot(() => {
        const scan = ledger.snapshot(scanId, identity.subject);
        if (!scan) throw new NotFoundException();
        const report = this.loadReportView(ledger, identity, scanId, kind);
        return { ...report, snapshot: { scan, report: report.snapshot } };
      });
      const context = { subject: identity.subject, scanId };
      if (source.kind === 'vuln') {
        const query = parseReportQuery('vuln', rawQuery);
        if (!query || query.kind !== 'vuln') throw new ReportViewError('INVALID_REPORT_QUERY');
        const { items, ...paging } = pageVuln(source.report.findings, query, context, source.snapshot, source.report.outcome === 'checked');
        return { ...source.report, findings: items, ...paging };
      }
      if (source.kind === 'sbom') {
        const query = parseReportQuery('sbom', rawQuery);
        if (!query || query.kind !== 'sbom') throw new ReportViewError('INVALID_REPORT_QUERY');
        const { items, ...paging } = pageSbom(source.report.components, query, context, source.snapshot, source.report.outcome === 'checked');
        return { ...source.report, components: items, ...paging };
      }
      const query = parseReportQuery('secret', rawQuery);
      if (!query || query.kind !== 'secret') throw new ReportViewError('INVALID_REPORT_QUERY');
      const { items, ...paging } = pageSecrets(source.report.findings, query, context, source.snapshot, source.report.coverage.outcome === 'checked');
      return { ...source.report, findings: items, ...paging };
    } catch (error) {
      if (!(error instanceof ReportViewError)) throw error;
      if (error.errorCode === 'REPORT_CURSOR_STALE') throw new ConflictException({ errorCode: error.errorCode });
      throw new BadRequestException({ errorCode: error.errorCode });
    }
  }

  private loadReportView(ledger: ScanLedger, identity: Identity, scanId: string, kind: ReportKind) {
    const archive = ledger.archiveResult(scanId, identity.subject);
    const archiveSnapshot = archive && { receipt: archive.receipt, scannerVersion: archive.scannerVersion,
      checkedAt: archive.checkedAt, [kind]: archive[kind] };
    if (kind === 'vuln') {
      const result = archive?.vuln;
      if (result && archive) {
        const report = result.outcome === 'checked'
          ? { outcome: result.outcome, coverage: 'image', image: `${archive.receipt.registry}/${archive.receipt.repository}@${archive.receipt.digest}`,
              platform: archive.receipt.platform, findings: result.findings, findingCount: result.findings.length,
              db: result.db, os: result.os, node: result.node, scannerVersion: archive.scannerVersion,
              checkedAt: new Date(archive.checkedAt).toISOString(), ...archivePolicyMetadata(archive) }
          : { outcome: result.outcome, reason: result.reason, coverage: 'image', findings: [],
              ...(result.outcome === 'failed' ? { errorCode: result.reason === 'SCAN_TIMEOUT' ? 'SCAN_TIMEOUT' : 'SCAN_FAILED' } : {}),
              ...(result.outcome === 'unsupported' ? { os: result.os, node: result.node, db: result.db,
                ...(result.dbPolicy ? { ...archivePolicyMetadata(archive), checkedAt: new Date(archive.checkedAt).toISOString() } : {}) } : {}) };
        return { kind, report, snapshot: archiveSnapshot };
      }
      const dataset = ledger.vulnDataset(scanId, identity.subject);
      if (!dataset) throw new NotFoundException();
      const { dbEvidence, ...report } = dataset.outcome === 'checked' ? dataset : { ...dataset, dbEvidence: undefined };
      return { kind, report: { ...report, ...(dbEvidence ? policyMetadata(dbEvidence) : {}) }, snapshot: dataset };
    }
    if (kind === 'sbom') {
      const result = archive?.sbom;
      if (result && archive) {
        const report = result.outcome === 'checked'
          ? { outcome: result.outcome, coverage: 'image', image: result.sbom.image, platform: result.sbom.platform,
              os: result.sbom.os, components: result.sbom.components, componentCount: result.sbom.components.length,
              scannerVersion: archive.scannerVersion, checkedAt: new Date(archive.checkedAt).toISOString() }
          : { outcome: result.outcome, reason: result.reason, errorCode: result.reason === 'SCAN_TIMEOUT' ? 'SCAN_TIMEOUT' : 'SCAN_FAILED',
              coverage: 'image', components: [] };
        return { kind, report, snapshot: archiveSnapshot };
      }
      const report = ledger.sbomDataset(scanId, identity.subject);
      if (!report) throw new NotFoundException();
      return { kind, report, snapshot: report };
    }
    const result = archive?.secret;
    if (result && archive) {
      const report = result.outcome === 'checked'
        ? { findings: result.findings, coverage: { check: 'secret', outcome: result.outcome, coverage: 'image',
            findingCount: result.findings.length, errorCode: null, scannerVersion: archive.scannerVersion,
            checkedAt: new Date(archive.checkedAt).toISOString() } }
        : { findings: [], coverage: { check: 'secret', outcome: result.outcome, coverage: 'image', reason: result.reason,
            findingCount: null, errorCode: result.reason === 'SCAN_TIMEOUT' ? 'SCAN_TIMEOUT' : 'SCAN_FAILED', scannerVersion: archive.scannerVersion } };
      return { kind, report, snapshot: archiveSnapshot };
    }
    const report = ledger.secretDataset(scanId, identity.subject);
    if (!report) throw new NotFoundException();
    return { kind, report, snapshot: report };
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
            check: 'secret', coverage: 'image', outcome: result.outcome, reason: result.reason, findingCount: null,
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
            ...(result.outcome === 'unsupported' ? { os: result.os, node: result.node, db: result.db, ...(result.dbPolicy ? { ...archivePolicyMetadata(archive), checkedAt: new Date(archive.checkedAt).toISOString() } : {}) } : {}) };
          const start = Number(cursor ?? 0), end = Math.min(start + Number(limit ?? 50), result.findings.length);
          if (start > result.findings.length) throw new BadRequestException({ errorCode: 'INVALID_PAGINATION' });
          return { outcome: 'checked', coverage: 'image', image: `${archive.receipt.registry}/${archive.receipt.repository}@${archive.receipt.digest}`,
            platform: archive.receipt.platform, findings: result.findings.slice(start, end), findingCount: result.findings.length,
            nextCursor: end < result.findings.length ? end : null, db: result.db, os: result.os, node: result.node,
            scannerVersion: archive.scannerVersion, checkedAt: new Date(archive.checkedAt).toISOString(), ...archivePolicyMetadata(archive) };
        }
        const report = ledger.vuln(scanId, identity.subject, Number(cursor ?? 0), Number(limit ?? 50));
    if (!report) throw new NotFoundException();
    if (report.outcome === 'checked' && Number(cursor ?? 0) > report.findingCount)
      throw new BadRequestException({ errorCode: 'INVALID_PAGINATION' });
    if (report.outcome === 'checked' && report.dbEvidence) {
      const { dbEvidence, ...result } = report;
      return { ...result, ...policyMetadata(dbEvidence) };
    }
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
