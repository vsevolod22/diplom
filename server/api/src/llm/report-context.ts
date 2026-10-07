import { ConflictException, ForbiddenException, HttpException, Inject, Injectable, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { createHash } from 'node:crypto';
import Database from 'better-sqlite3';
import { ScansService } from '../scans/scans.service.js';
import type { Identity } from '../security/identity.js';
import { validateConfigReport } from '../image-config/report-contract.js';
import { ADVISORY_SOURCES, validateAdvisory } from '../worker/vuln-advisory.js';
import { CEILINGS } from './policy.js';
import { object } from './response.js';

type Check = 'secret' | 'sbom' | 'vuln' | 'config';
const checks: Check[] = ['secret', 'sbom', 'vuln', 'config'];
const severities = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const reasons = ['SCAN_FAILED', 'SCAN_TIMEOUT', 'SCAN_UNAVAILABLE', 'DB_UNAVAILABLE', 'OS_EOL', 'OS_UNKNOWN',
  'NODE_INVENTORY_ABSENT', 'CHECK_DISABLED', 'INVALID_CHECK_FLAG', 'INVALID_RESOURCE_POLICY', 'OCI_IDENTITY_REJECTED',
  'CONFIG_LIMIT_EXCEEDED', 'INVALID_CONFIG', 'USER_NOT_RESOLVABLE', 'RULE_NOT_IMPLEMENTED', 'SOURCE_NOT_PROVIDED', 'SOURCE_ANALYZER_UNSUPPORTED'];
export type SafeFinding = { findingId: string; check: Check; severity: string; [key: string]: unknown };
export type ReportContext = { scanId: string; digest: string; platform: string; reportVersion: string;
  state: string; attempt: number; requestedChecks: Check[]; coverage: Record<Check, unknown>; findings: SafeFinding[];
  findingCount: number; checkedIsNotSafe: true; omittedEvidence: 'All free text, URLs, credentials, env, package strings and raw output excluded' };
const invalid = (): never => { throw new ConflictException({ errorCode: 'LLM_REPORT_UNAVAILABLE' }); };
const overflow = (): never => { throw new ConflictException({ errorCode: 'LLM_CONTEXT_LIMIT' }); };
const record = (v: unknown): Record<string, unknown> => object(v) ? v : invalid();
function match(v: unknown, pattern: RegExp): string { if (typeof v !== 'string' || !pattern.test(v)) return invalid(); return v; }
function count(v: unknown): number {
  if (!Number.isSafeInteger(v) || (v as number) < 0) return invalid();
  if ((v as number) > 1000) return overflow();
  return v as number;
}
function nullableEnum(v: unknown, values: readonly string[]): string | null {
  if (v === undefined || v === null) return null;
  if (typeof v !== 'string' || !values.includes(v)) return invalid();
  return v;
}
function hash(v: unknown): string {
  // Canonical authoritative projections are hashed locally, never sent to the provider.
  // Bound traversal before serialization, including optional metadata omitted from model context.
  let bytes = 0;
  const canonical = (x: unknown, depth = 0): unknown => {
    if (depth > 24 || (bytes += 8) > 4_000_000) return overflow();
    if (typeof x === 'string') { bytes += Buffer.byteLength(x); if (bytes > 4_000_000) return overflow(); return x; }
    if (x === null || typeof x === 'boolean' || typeof x === 'number' && Number.isFinite(x)) return x;
    if (Array.isArray(x)) return x.map(item => canonical(item, depth + 1));
    if (!object(x)) return invalid();
    return Object.fromEntries(Object.keys(x).sort().map(key => {
      bytes += Buffer.byteLength(key);
      return [key, canonical(x[key], depth + 1)];
    }));
  };
  return createHash('sha256').update(JSON.stringify(canonical(v))).digest('hex');
}
function basicCoverage(v: unknown): Record<string, unknown> {
  const item = record(v);
  const outcome = nullableEnum(item.outcome, ['checked', 'failed', 'unsupported', 'skipped']);
  if (!outcome || item.coverage !== undefined && item.coverage !== 'image') return invalid();
  const result: Record<string, unknown> = { outcome, scope: 'image', reason: nullableEnum(item.reason, reasons),
    errorCode: nullableEnum(item.errorCode, reasons) };
  if (item.findingCount !== undefined) result.findingCount = item.findingCount === null ? null : count(item.findingCount);
  if (item.componentCount !== undefined) result.componentCount = count(item.componentCount);
  if (item.scannerVersion !== undefined) result.scannerVersion = item.scannerVersion === null ? null : match(item.scannerVersion, /^\d+\.\d+\.\d+$/);
  if (item.checkedAt !== undefined) result.checkedAt = match(item.checkedAt, /^\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+Z)?$/);
  return result;
}
function coverage(v: unknown, sbomInventory = false): Record<string, unknown> {
  const item = record(v);
  const safe = basicCoverage(item);
  for (const key of ['os', 'node']) safe[key] = item[key] === undefined || sbomInventory && key === 'os'
    ? { outcome: 'unknown', reason: 'NOT_REPORTED' } : basicCoverage(item[key]);
  if (item.db === undefined || item.db === null) safe.db = { outcome: 'unknown', reason: 'NOT_REPORTED' };
  else {
    const db = record(item.db);
    if (db.envelopeVersion !== 1 || db.schemaVersion !== 2 || db.signer !== 'local-db-operator-v1') return invalid();
    const manifestDigest = match(db.manifestDigest, /^sha256:[a-f0-9]{64}$/);
    if (db.source !== `ghcr.io/aquasecurity/trivy-db@${manifestDigest}`) return invalid();
    safe.db = { envelopeVersion: 1, schemaVersion: 2, signer: 'local-db-operator-v1', manifestDigest,
      artifactSha256: match(db.artifactSha256, /^[a-f0-9]{64}$/), metadataSha256: match(db.metadataSha256, /^[a-f0-9]{64}$/),
      dbSha256: match(db.dbSha256, /^[a-f0-9]{64}$/), updatedAt: match(db.updatedAt, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z$/),
      downloadedAt: match(db.downloadedAt, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z$/),
      nextUpdate: match(db.nextUpdate, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z$/) };
  }
  return safe;
}
function finding(v: unknown, check: 'secret' | 'vuln'): SafeFinding {
  const f = record(v);
  if (check === 'secret') {
    if (f.line !== null && (!Number.isSafeInteger(f.line) || (f.line as number) < 0 || (f.line as number) > 10_000_000)) return invalid();
    return { check, findingId: match(f.findingId, /^secret-\d{1,6}-\d{1,6}$/), severity: 'UNKNOWN',
      ruleId: match(f.ruleId, /^rule-[a-f0-9]{16}$/), line: f.line, evidenceRef: match(f.evidenceRef, /^result-\d{1,6}-secret-\d{1,6}$/) };
  }
  const severity = nullableEnum(f.severity, severities);
  if (!severity || !['apk', 'npm'].includes(String(f.ecosystem)) || !Array.isArray(f.severitySources) || !f.severitySources.length ||
      f.severitySources.some(source => !ADVISORY_SOURCES.includes(source))) return invalid();
  const safe: SafeFinding = { check, findingId: match(f.findingId, /^vuln-[a-f0-9]{64}$/), severity,
    cveId: match(f.cveId, /^CVE-\d{4}-\d{4,12}$/), ecosystem: f.ecosystem, severitySources: [...f.severitySources],
    provenanceRef: match(f.provenanceRef, /^target-[a-f0-9]{64}$/), fixedVersionReported: f.fixedVersion !== null };
  if (f.advisory != null) {
    validateAdvisory(f.advisory, safe.cveId as string);
    const advisory = record(f.advisory);
    if (!Array.isArray(advisory.assessments)) return invalid();
    safe.assessments = advisory.assessments.map(a => {
      const assessment = record(a);
      const cvss = assessment.cvss === null ? null : record(assessment.cvss);
      return { source: nullableEnum(assessment.source, ADVISORY_SOURCES), severity: nullableEnum(assessment.severity, severities),
        fixedVersionReported: assessment.fixedVersion !== null,
        cvss: cvss ? { family: cvss.family, version: cvss.version, versionState: cvss.versionState,
          reportedScore: cvss.reportedScore, scoreState: cvss.scoreState, vectorState: cvss.vectorState } : null };
    });
    safe.advisoryState = advisory.state; safe.conflictState = advisory.conflictState;
    safe.conflicts = advisory.conflicts; safe.limitations = advisory.limitations;
  } else safe.advisoryState = 'unknown';
  return safe;
}

@Injectable()
export class ReportReader {
  constructor(@Inject(ScansService) private readonly scans: ScansService) {}
  read(identity: Identity, scanId: string): ReportContext {
    if (!identity.scope.includes('scan:read')) throw new ForbiddenException({ errorCode: 'SCAN_ACCESS_DENIED' });
    if (!/^[a-f0-9-]{36}$/.test(scanId)) throw new NotFoundException({ errorCode: 'SCAN_NOT_FOUND' });
    let db: Database.Database | undefined;
    try {
      const path = process.env.SCAN_LEDGER_PATH;
      if (!path || path === ':memory:') return invalid();
      db = new Database(path, { readonly: true, fileMustExist: true, timeout: 1000 });
      const before = db.pragma('data_version', { simple: true });
      const report = this.collect(identity, scanId, db);
      // Projections use the existing ledger connection. Reject any intervening commit,
      // including unrelated writes, rather than accepting a mixed-page snapshot.
      if (db.pragma('data_version', { simple: true }) !== before) return invalid();
      return report;
    }
    catch (error) {
      if (error instanceof HttpException && [403, 404, 409].includes(error.getStatus())) throw error;
      throw new ServiceUnavailableException({ errorCode: 'LLM_REPORT_UNAVAILABLE' });
    } finally { db?.close(); }
  }
  private collect(identity: Identity, scanId: string, db: Database.Database): ReportContext {
    const status = record(this.scans.status(identity, scanId)); // Ownership precedes config disclosure.
    const digest = match(status.digest, /^sha256:[a-f0-9]{64}$/);
    const platform = match(status.platform, /^linux\/amd64$/);
    if (!['completed', 'partial', 'failed', 'cancelled'].includes(String(status.state))) return invalid();
    if (!Array.isArray(status.checks) || !status.checks.length || status.checks.some(c => !checks.includes(c)) ||
        new Set(status.checks).size !== status.checks.length || status.scanId !== scanId) return invalid();
    const requestedChecks = status.checks as Check[];
    const perCheck = record(status.perCheck);
    if (Object.keys(perCheck).sort().join(',') !== [...requestedChecks].sort().join(',')) return invalid();
    // Additional owner-scoped read ONLY: projections omit attempt/scope/terminal fencing.
    const binding = record(db.prepare(`SELECT s.digest,s.platform,s.state,s.scope,s.checks,s.terminal_at AS terminalAt,
      o.attempts AS attempt,o.delivered_at AS deliveredAt FROM scans s JOIN outbox o ON o.scan_id=s.id
      WHERE s.id=? AND s.subject=?`).get(scanId, identity.subject));
    if (binding.digest !== digest || binding.platform !== platform || binding.state !== status.state || binding.scope !== 'image' ||
        binding.checks !== JSON.stringify(requestedChecks) || !binding.terminalAt || !Number.isSafeInteger(binding.attempt) ||
        (binding.attempt as number) < 0) return invalid();
    const allCoverage = {} as Record<Check, unknown>;
    const findings: SafeFinding[] = [];
    const raw: unknown[] = [binding, status];
    const ids = new Set<string>();
    const append = (f: SafeFinding) => {
      if (ids.has(f.findingId)) return invalid();
      if (findings.length >= CEILINGS.findings) return overflow();
      ids.add(f.findingId); findings.push(f);
    };
    for (const check of checks) {
      if (!requestedChecks.includes(check)) { allCoverage[check] = { outcome: 'unknown', reason: 'CHECK_NOT_REQUESTED' }; continue; }
      if (perCheck[check] === null) { allCoverage[check] = { outcome: 'unknown', reason: 'NO_RESULT' }; continue; }
      const expected = coverage(perCheck[check]);
      allCoverage[check] = expected;
      if (check === 'config') {
        const config = validateConfigReport(status.config, { digest, platform }, true);
        if (config.config.outcome !== expected.outcome || config.findings.length !== expected.findingCount) return invalid();
        allCoverage.config = { ...expected, history: config.history, dockerfile: config.dockerfile, iac: config.iac,
          rules: config.rules, checksVersion: config.checksVersion, resourcePolicyVersion: config.resourcePolicyVersion,
          supportedRuleIds: config.supportedRuleIds, completedRuleIds: config.completedRuleIds };
        for (const f of config.findings) append({ check, findingId: f.findingId, severity: f.severity, ruleId: f.ruleId,
          classification: f.classification, configDigest: f.configDigest, manifestDigest: f.manifestDigest, location: f.location });
        continue;
      }
      let cursor = 0, total = 0, firstCoverage: string | undefined;
      for (let pageIndex = 0; pageIndex <= 10; pageIndex++) {
        const page = record(check === 'secret' ? this.scans.results(identity, scanId, String(cursor), '100') :
          check === 'vuln' ? this.scans.vuln(identity, scanId, String(cursor), '100') : this.scans.sbom(identity, scanId, String(cursor), '100'));
        raw.push(page);
        const current = coverage(check === 'secret' ? page.coverage : page, check === 'sbom');
        // Nonchecked archive pages omit optional identity metadata that status
        // supplies authoritatively. Retain it without accepting supplied conflicts.
        if (current.outcome !== 'checked') {
          for (const key of ['scannerVersion', 'checkedAt'])
            if (current[key] === undefined && expected[key] !== undefined) current[key] = expected[key];
          // A null failed-page count is unknown, equivalent to an absent status
          // count, never a verified zero. Numeric counts still have to agree.
          if (current.findingCount === null && expected.findingCount === undefined) delete current.findingCount;
        }
        const projected = JSON.stringify(current);
        if (firstCoverage !== undefined && firstCoverage !== projected) return invalid();
        firstCoverage = projected;
        if (current.outcome !== expected.outcome || current.reason !== expected.reason ||
            current.errorCode !== expected.errorCode || current.scannerVersion !== expected.scannerVersion ||
            current.checkedAt !== expected.checkedAt ||
            JSON.stringify([current.os, current.node, current.db]) !== JSON.stringify([expected.os, expected.node, expected.db]) ||
            (check === 'sbom' ? current.componentCount !== expected.componentCount : current.findingCount !== expected.findingCount)) return invalid();
        if (check !== 'secret' && (page.image !== undefined && (typeof page.image !== 'string' || !page.image.endsWith(`@${digest}`) ||
            current.outcome === 'checked' && page.platform !== platform) || page.platform !== undefined && page.platform !== platform)) return invalid();
        const entries = check === 'sbom' ? page.components : page.findings;
        if (!Array.isArray(entries) || entries.length > 100 || current.outcome !== 'checked' && entries.length) return invalid();
        for (const f of entries) if (check !== 'sbom') append(finding(f, check));
        total += entries.length;
        if (total > 1000) return overflow();
        const next = page.nextCursor;
        if (next === null) {
          if (current.outcome === 'checked' && total !== (check === 'sbom' ? current.componentCount : current.findingCount)) return invalid();
          break;
        }
        if (!Number.isSafeInteger(next) || next !== cursor + entries.length || !entries.length || pageIndex === 10) return invalid();
        cursor = next as number;
      }
    }
    findings.sort((a, b) => a.findingId < b.findingId ? -1 : a.findingId > b.findingId ? 1 : 0);
    const reportVersion = hash({ subject: identity.subject, scanId, digest, platform, raw });
    const report: ReportContext = { scanId, digest, platform, reportVersion, state: status.state as string,
      attempt: binding.attempt as number, requestedChecks: [...requestedChecks], coverage: allCoverage,
      findings, findingCount: findings.length, checkedIsNotSafe: true,
      omittedEvidence: 'All free text, URLs, credentials, env, package strings and raw output excluded' };
    if (Buffer.byteLength(JSON.stringify(report)) > CEILINGS.requestBytes) return overflow();
    return freeze(report);
  }
}
function freeze<T>(value: T): T {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
