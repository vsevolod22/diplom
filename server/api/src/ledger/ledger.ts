import Database from 'better-sqlite3';
import { isDeepStrictEqual } from 'node:util';
import { createHash, randomUUID } from 'node:crypto';
import { and, eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { scans } from './schema.js';
import { MAX_FINDINGS, type SecretFinding } from '../worker/secret-findings.js';
import type { ImageSbom, SbomComponent } from '../worker/cyclonedx-components.js';
import { MAX_VULN_FINDINGS, type VulnFinding } from '../worker/vuln-findings.js';
import { omittedAdvisory, plainObject, validateAdvisoryBudget } from '../worker/vuln-advisory.js';
import { NGINX_ARCHIVE_CANDIDATES } from '../oci/bounded-image-archive.js';
import { assertArchiveDbFreshness, validateArchiveReport } from '../worker/archive-result-contract.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';
import type { ImageConfigResult } from '../image-config/contract.js';
import { validateConfigReport } from '../image-config/report-contract.js';
import { admittedConfigTarget, CONFIG_LOAD_MS } from '../oci/pinned-image-config.js';
import { exactLocalTarget, localChecksAllowed, localReceiptMatches, validLocalBinding, type LocalExecutionBinding } from '../oci/nginx-local-policy.js';

export type PinnedTarget = {
  subject: string;
  idempotencyKey: string;
  registry: string;
  repository: string;
  digest: `sha256:${string}`;
  platform: string;
  fingerprint?: string;
  checks?: string;
  scope?: string;
  executionProfile?: LocalExecutionBinding;
};
export type Job = { scanId: string; registry: string; repository: string; digest: string; platform: string; checks: string; scope: string; attempts: number; executionProfile?: LocalExecutionBinding };
export class IdempotencyConflict extends Error {}
export class AdmissionLimited extends Error {}
const SUBJECT_ACTIVE_LIMIT = 3;
const GLOBAL_ACTIVE_LIMIT = 30;
const SUBJECT_MINUTE_LIMIT = 6;
const MAX_SBOM_COMPONENTS = 1000;
const vulnSources = new Set(['unknown', 'alpine', 'nvd', 'ghsa', 'npm', 'nodejs-security-wg', 'osv', 'cve',
  'redhat', 'ubuntu', 'photon', 'amazon', 'oracle-oval', 'julia', 'alma', 'azure', 'rocky',
  'cbl-mariner', 'bitnami', 'ruby-advisory-db', 'bottlerocket']);
const sbomIdentifier = (value: unknown, max: number): value is string =>
  typeof value === 'string' && value.length > 0 && value.length <= max &&
  /^[A-Za-z0-9@][A-Za-z0-9@._+/-]*$/.test(value);
const sbomObject = (value: unknown, keys: string[]): value is Record<string, unknown> =>
  plainObject(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

type FailureCode = 'SCAN_FAILED' | 'SCAN_TIMEOUT' | 'SCAN_UNAVAILABLE';
type LegacyCheck = 'secret' | 'sbom' | 'vuln';
type CheckName = LegacyCheck | 'config';
type CheckedPayload =
  | { check: 'secret'; outcome: 'checked'; findings: SecretFinding[]; scannerVersion: '0.69.3' }
  | { check: 'sbom'; outcome: 'checked'; sbom: ImageSbom; scannerVersion: '0.69.3' }
  | { check: 'vuln'; outcome: 'checked'; image: string; findings: VulnFinding[]; scannerVersion: '0.69.3' };
export type CombinedOutcome = CheckedPayload | { check: LegacyCheck; outcome: 'failed'; errorCode: FailureCode };
const canonicalChecks = (value: string): CheckName[] | null => {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 4 ||
        parsed.some(check => !['secret', 'sbom', 'vuln', 'config'].includes(check)) ||
        JSON.stringify(parsed) !== value ||
        parsed.some((check, index) => index > 0 && ['secret', 'sbom', 'vuln', 'config'].indexOf(parsed[index - 1]) >=
          ['secret', 'sbom', 'vuln', 'config'].indexOf(check))) return null;
    return parsed as CheckName[];
  } catch { return null; }
};

function validateCombined(outcomes: CombinedOutcome[], archiveImage?: string): void {
  if (!Array.isArray(outcomes) || outcomes.length < 1 || outcomes.length > 3 ||
      outcomes.some(item => !sbomObject(item, item?.outcome === 'failed' ? ['check','outcome','errorCode'] :
        item?.check === 'sbom' ? ['check','outcome','sbom','scannerVersion'] :
        item?.check === 'vuln' ? ['check','outcome','image','findings','scannerVersion'] :
          ['check','outcome','findings','scannerVersion']))) throw new TypeError('Invalid combined result');
  for (const item of outcomes) {
    if (!['secret', 'sbom', 'vuln'].includes(item.check)) throw new TypeError('Invalid combined check');
    if (item.outcome === 'failed') {
      if (!['SCAN_FAILED', 'SCAN_TIMEOUT', 'SCAN_UNAVAILABLE'].includes(item.errorCode))
        throw new TypeError('Invalid failure code');
      continue;
    }
    if (item.outcome !== 'checked' || item.scannerVersion !== '0.69.3') throw new TypeError('Invalid scanner version');
    if (item.check === 'secret') {
      if (!Array.isArray(item.findings) || item.findings.length > MAX_FINDINGS) throw new TypeError('Invalid secret result');
      const ids = new Set<string>();
      for (const f of item.findings) {
        if (!sbomObject(f, ['findingId','ruleId','line','evidenceRef']) ||
            typeof f.findingId !== 'string' || !/^secret-\d+-\d+$/.test(f.findingId) ||
            typeof f.ruleId !== 'string' || !/^[A-Za-z0-9._-]{1,80}$/.test(f.ruleId) ||
            typeof f.evidenceRef !== 'string' || !/^result-\d+-secret-\d+$/.test(f.evidenceRef) ||
            f.line !== null && (!Number.isSafeInteger(f.line) || (f.line as number) < 0) || ids.has(f.findingId))
          throw new TypeError('Invalid secret finding');
        ids.add(f.findingId);
      }
    } else if (item.check === 'sbom') {
      const sbom = item.sbom;
      if (!sbomObject(sbom, ['image','platform','os','components']) ||
          typeof sbom.image !== 'string' ||
          !(archiveImage ? sbom.image === archiveImage : /^registry-1\.docker\.io\/library\/alpine@sha256:[a-f0-9]{64}$/.test(sbom.image)) ||
          sbom.platform !== 'linux/amd64' || !sbomObject(sbom.os, ['name','version']) ||
          sbom.os.name !== 'alpine' || !sbomIdentifier(sbom.os.version, 80) ||
          !Array.isArray(sbom.components) || sbom.components.length < 1 ||
          sbom.components.length > MAX_SBOM_COMPONENTS) throw new TypeError('Invalid SBOM');
      const seen = new Set<string>();
      for (const component of sbom.components) {
        if (!sbomObject(component, ['ecosystem','name','version']) ||
            component.ecosystem !== 'apk' && component.ecosystem !== 'npm' ||
            !sbomIdentifier(component.name, 128) ||
            !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._+-]*$/.test(component.name) ||
            !sbomIdentifier(component.version, 80)) throw new TypeError('Invalid SBOM component');
        const key = JSON.stringify([component.ecosystem, component.name, component.version]);
        if (seen.has(key)) throw new TypeError('Duplicate SBOM component');
        seen.add(key);
      }
    } else {
      if (typeof item.image !== 'string' ||
          !(archiveImage ? item.image === archiveImage : /^registry-1\.docker\.io\/library\/alpine@sha256:[a-f0-9]{64}$/.test(item.image)) ||
          !Array.isArray(item.findings) || item.findings.length > MAX_VULN_FINDINGS)
        throw new TypeError('Invalid vulnerability result');
      const seen = new Set<string>();
      for (const f of item.findings) {
        if (!sbomObject(f, ['findingId','cveId','ecosystem','packageName','installedVersion',
          'severity','severitySources','provenanceRef','fixedVersion', ...(Object.hasOwn(f, 'advisory') ? ['advisory'] : [])]) ||
            typeof f.cveId !== 'string' || !/^CVE-[0-9]{4}-[0-9]{4,12}$/.test(f.cveId) ||
            f.ecosystem !== 'apk' && f.ecosystem !== 'npm' ||
            typeof f.packageName !== 'string' || f.packageName.length > 128 ||
            !(f.ecosystem === 'apk' ? /^[a-z0-9][a-z0-9._+-]{0,127}$/ :
              /^(?:@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*|[a-z0-9][a-z0-9._-]*)$/).test(f.packageName) ||
            typeof f.installedVersion !== 'string' ||
            !/^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,79}$/.test(f.installedVersion) ||
            f.fixedVersion !== null && (typeof f.fixedVersion !== 'string' ||
              !/^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,79}$/.test(f.fixedVersion)) ||
            !['UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL'].includes(f.severity) ||
            typeof f.provenanceRef !== 'string' || !/^target-[a-f0-9]{64}$/.test(f.provenanceRef) ||
            !Array.isArray(f.severitySources) || f.severitySources.length < 1 ||
            f.severitySources.length > vulnSources.size ||
            f.severitySources.some((source, i) => typeof source !== 'string' || !vulnSources.has(source) ||
              i > 0 && f.severitySources[i - 1] >= source)) throw new TypeError('Invalid vulnerability finding');
        const key = JSON.stringify([...(archiveImage ? [archiveImage, 'linux/amd64', 'vuln'] : []), f.ecosystem, f.provenanceRef, f.cveId, f.packageName, f.installedVersion]);
        if (f.findingId !== `vuln-${createHash('sha256').update(key).digest('hex')}` || seen.has(key))
          throw new TypeError('Invalid or duplicate vulnerability finding');
        seen.add(key);
      }
      validateAdvisoryBudget(item.findings);
    }
  }
}

function validateStoredArchive(report: ArchiveScanReport): { requested: string[]; checked: CombinedOutcome[] } {
  const requested = ['secret', 'sbom', 'vuln'].filter(check => Object.hasOwn(report, check));
  validateArchiveReport(report, requested);
  assertArchiveDbFreshness(report, report.checkedAt);
  const image = `${report.receipt.registry}/${report.receipt.repository}@${report.receipt.digest}`;
  const checked: CombinedOutcome[] = [];
  if (report.secret?.outcome === 'checked') checked.push({ check: 'secret', ...report.secret, scannerVersion: report.scannerVersion });
  if (report.sbom?.outcome === 'checked') checked.push({ check: 'sbom', ...report.sbom, scannerVersion: report.scannerVersion });
  if (report.vuln?.outcome === 'checked') {
    if (!sbomObject(report.vuln, ['outcome', 'findings', 'db', 'os', 'node']) ||
      !sbomObject(report.vuln.os, ['outcome']) || report.vuln.os.outcome !== 'checked' ||
      !(sbomObject(report.vuln.node, ['outcome']) && report.vuln.node.outcome === 'checked' ||
      sbomObject(report.vuln.node, ['outcome','reason']) && report.vuln.node.outcome === 'unsupported' &&
      report.vuln.node.reason === 'NODE_INVENTORY_ABSENT')) throw new TypeError('Invalid archive coverage');
    checked.push({ check: 'vuln', outcome: 'checked', image, findings: report.vuln.findings, scannerVersion: report.scannerVersion });
  }
  if (checked.length) validateCombined(checked, image);
  return { requested, checked };
}

type ScanRow = { id: string; registry: string; repository: string; digest: string; platform: string; fingerprint: string | null };
type ClaimRow = { scanId: string; registry: string; repository: string; digest: string; platform: string; checks: string; scope: string; attempts: number };

export class ScanLedger {
  private readonly db: Database.Database;
  private readonly orm: ReturnType<typeof drizzle>;

  constructor(filename: string) {
    this.db = new Database(filename, { timeout: 5000 });
    try {
      this.db.pragma('journal_mode = WAL');
      this.db.pragma('foreign_keys = ON');
      this.db.pragma('busy_timeout = 5000');
      const version = Number(this.db.pragma('user_version', { simple: true }));
      if (version > 13 || version < 0) throw new Error('Unsupported ledger version');
      // FK enforcement must be toggled outside a transaction for SQLite's table rebuild.
      // Check the rebuilt references before commit, then restore enforcement afterward.
      if (version < 9) this.db.pragma('foreign_keys = OFF');
      // This is the sole migrator. v2 is an existing baseline; do not run drizzle-kit push.
      this.immediate(() => {
        if (version === 0) {
          const existing = this.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('scans','outbox')").all();
          if (existing.length) throw new Error('Unversioned ledger with existing tables');
          this.db.exec(`
            CREATE TABLE scans (
              id TEXT PRIMARY KEY, subject TEXT NOT NULL, idempotency_key TEXT NOT NULL,
              registry TEXT NOT NULL, repository TEXT NOT NULL, digest TEXT NOT NULL, platform TEXT NOT NULL,
              state TEXT NOT NULL CHECK (state IN ('queued','running','completed','failed','cancelled')),
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              UNIQUE (subject, idempotency_key)
            );
            CREATE TABLE outbox (scan_id TEXT PRIMARY KEY REFERENCES scans(id), delivered_at TEXT);
          `);
        }
        if (version < 2) {
          this.db.exec(`
            ALTER TABLE scans ADD COLUMN fingerprint TEXT;
            ALTER TABLE scans ADD COLUMN checks TEXT NOT NULL DEFAULT '[]';
            ALTER TABLE scans ADD COLUMN scope TEXT NOT NULL DEFAULT 'image';
            ALTER TABLE scans ADD COLUMN terminal_at TEXT;
            ALTER TABLE outbox ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE outbox ADD COLUMN lease_until INTEGER;
            ALTER TABLE outbox ADD COLUMN next_run_at INTEGER NOT NULL DEFAULT 0;
            PRAGMA user_version = 2;
          `);
        }
        if (version < 3) {
          this.db.exec(`CREATE TABLE scan_results (
            scan_id TEXT PRIMARY KEY REFERENCES scans(id),
            check_name TEXT NOT NULL CHECK (check_name = 'secret'),
            finding_count INTEGER NOT NULL CHECK (finding_count >= 0),
            coverage TEXT NOT NULL CHECK (coverage = 'image'),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
          ); PRAGMA user_version = 3;`);
        }
        if (version < 4) {
          this.db.exec(`CREATE TABLE admission_windows (
            subject TEXT NOT NULL, minute INTEGER NOT NULL, count INTEGER NOT NULL,
            PRIMARY KEY(subject, minute)
          ); PRAGMA user_version = 4;`);
        }
        if (version < 5) {
          this.db.exec(`ALTER TABLE scan_results ADD COLUMN scanner_version TEXT;
            ALTER TABLE scan_results ADD COLUMN outcome TEXT NOT NULL DEFAULT 'unsupported';
            ALTER TABLE scan_results ADD COLUMN error_code TEXT;
            CREATE TABLE scan_findings (
              scan_id TEXT NOT NULL REFERENCES scans(id), finding_id TEXT NOT NULL,
              rule_id TEXT NOT NULL, line INTEGER, evidence_ref TEXT NOT NULL,
              PRIMARY KEY(scan_id, finding_id)
            );
            CREATE TABLE scan_events (
              seq INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL REFERENCES scans(id),
              state TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX scan_events_by_scan ON scan_events(scan_id,seq);
            INSERT INTO scan_events(scan_id,state) SELECT id,state FROM scans;
            PRAGMA user_version = 5;`);
        }
        if (version < 6) {
          this.db.exec(`CREATE TABLE scan_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            subject TEXT NOT NULL, target TEXT NOT NULL, scope TEXT NOT NULL,
            decision TEXT NOT NULL, reason TEXT NOT NULL, scan_id TEXT
          ); PRAGMA user_version = 6;`);
        }
        if (version < 7) {
          this.db.exec(`CREATE TABLE scan_sbom_results (
            scan_id TEXT PRIMARY KEY REFERENCES scans(id), image TEXT,
            platform TEXT CHECK (platform = 'linux/amd64'),
            os_name TEXT CHECK (os_name = 'alpine'), os_version TEXT,
            component_count INTEGER CHECK (component_count BETWEEN 1 AND 1000),
            coverage TEXT NOT NULL CHECK (coverage = 'image'),
            outcome TEXT NOT NULL CHECK (outcome IN ('checked','failed')),
            scanner_version TEXT, error_code TEXT CHECK (error_code IN ('SCAN_FAILED','SCAN_TIMEOUT','SCAN_UNAVAILABLE')),
            checked_at TEXT,
            CHECK ((outcome = 'checked' AND image IS NOT NULL AND platform IS NOT NULL
              AND os_name IS NOT NULL AND os_version IS NOT NULL AND component_count IS NOT NULL
              AND scanner_version IS NOT NULL AND checked_at IS NOT NULL AND error_code IS NULL)
              OR (outcome = 'failed' AND image IS NULL AND platform IS NULL AND os_name IS NULL
              AND os_version IS NULL AND component_count IS NULL AND scanner_version IS NULL
              AND checked_at IS NULL AND error_code IS NOT NULL))
          );
          CREATE TABLE scan_sbom_components (
            scan_id TEXT NOT NULL REFERENCES scans(id), ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 999),
            ecosystem TEXT NOT NULL CHECK (ecosystem IN ('apk','npm')),
            name TEXT NOT NULL, version TEXT NOT NULL,
            PRIMARY KEY(scan_id,ordinal), UNIQUE(scan_id,ecosystem,name,version)
          );
          PRAGMA user_version = 7;`);
        }
        if (version < 8) {
          this.db.exec(`CREATE TABLE scan_vuln_results (
            scan_id TEXT PRIMARY KEY REFERENCES scans(id), image TEXT, platform TEXT CHECK (platform = 'linux/amd64'),
            finding_count INTEGER CHECK (finding_count BETWEEN 0 AND 1000),
            coverage TEXT NOT NULL CHECK (coverage = 'image'),
            outcome TEXT NOT NULL CHECK (outcome IN ('checked','failed')),
            scanner_version TEXT, error_code TEXT CHECK (error_code IN ('SCAN_FAILED','SCAN_TIMEOUT','SCAN_UNAVAILABLE')),
            checked_at TEXT,
            CHECK ((outcome = 'checked' AND image IS NOT NULL AND platform IS NOT NULL
              AND finding_count IS NOT NULL AND scanner_version IS NOT NULL AND checked_at IS NOT NULL AND error_code IS NULL)
              OR (outcome = 'failed' AND image IS NULL AND platform IS NULL AND finding_count IS NULL
              AND scanner_version IS NULL AND checked_at IS NULL AND error_code IS NOT NULL))
          );
          CREATE TABLE scan_vuln_findings (
            scan_id TEXT NOT NULL REFERENCES scans(id), ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 999),
            finding_id TEXT NOT NULL, cve_id TEXT NOT NULL, ecosystem TEXT NOT NULL CHECK (ecosystem IN ('apk','npm')),
            package_name TEXT NOT NULL, installed_version TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL')),
            severity_sources TEXT NOT NULL, provenance_ref TEXT NOT NULL, fixed_version TEXT,
            PRIMARY KEY(scan_id,ordinal), UNIQUE(scan_id,finding_id)
          );
          PRAGMA user_version = 8;`);
        }
        if (version < 9) {
          // SQLite cannot alter a CHECK in place; preserve every column, key and row.
          this.db.exec(`CREATE TABLE scans_v9 (
            id TEXT PRIMARY KEY, subject TEXT NOT NULL, idempotency_key TEXT NOT NULL,
            registry TEXT NOT NULL, repository TEXT NOT NULL, digest TEXT NOT NULL, platform TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('queued','running','completed','failed','cancelled','partial')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, fingerprint TEXT,
            checks TEXT NOT NULL DEFAULT '[]', scope TEXT NOT NULL DEFAULT 'image', terminal_at TEXT,
            UNIQUE(subject,idempotency_key)
          );
          INSERT INTO scans_v9(id,subject,idempotency_key,registry,repository,digest,platform,state,
            created_at,fingerprint,checks,scope,terminal_at)
            SELECT id,subject,idempotency_key,registry,repository,digest,platform,state,
              created_at,fingerprint,checks,scope,terminal_at FROM scans;
          DROP TABLE scans;
          ALTER TABLE scans_v9 RENAME TO scans;
          CREATE TABLE scan_results_v9 (
            scan_id TEXT PRIMARY KEY REFERENCES scans(id),
            check_name TEXT NOT NULL CHECK (check_name = 'secret'),
            finding_count INTEGER CHECK (finding_count >= 0),
            coverage TEXT NOT NULL CHECK (coverage = 'image'),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            scanner_version TEXT, outcome TEXT NOT NULL DEFAULT 'unsupported', error_code TEXT,
            CHECK ((outcome = 'failed' AND finding_count IS NULL) OR
              (outcome = 'checked' AND finding_count IS NOT NULL) OR outcome NOT IN ('failed','checked'))
          );
          INSERT INTO scan_results_v9(scan_id,check_name,finding_count,coverage,created_at,scanner_version,outcome,error_code)
            SELECT scan_id,check_name,CASE WHEN outcome = 'failed' THEN NULL ELSE finding_count END,
              coverage,created_at,scanner_version,outcome,error_code FROM scan_results;
          DROP TABLE scan_results;
          ALTER TABLE scan_results_v9 RENAME TO scan_results;
          PRAGMA user_version = 9;`);
        }
        if (version < 10) {
          this.db.exec(`CREATE TABLE IF NOT EXISTS scan_archive_results (
            scan_id TEXT PRIMARY KEY REFERENCES scans(id),
            attempt INTEGER NOT NULL CHECK (attempt > 0),
            report TEXT NOT NULL CHECK (length(report) <= 2000000)
          ); PRAGMA user_version = 10;`);
        }
        if (version < 11) {
          this.db.exec(`CREATE TABLE scan_check_results (
            scan_id TEXT NOT NULL REFERENCES scans(id), check_name TEXT NOT NULL CHECK (check_name = 'config'),
            attempt INTEGER NOT NULL CHECK (attempt > 0),
            outcome TEXT NOT NULL CHECK (outcome IN ('checked','unsupported','failed','skipped')),
            checks_version TEXT NOT NULL CHECK (checks_version = 'image-config-user-v1'),
            resource_policy_version TEXT NOT NULL CHECK (resource_policy_version = 'image-config-policy-v1'),
            report TEXT NOT NULL CHECK (length(CAST(report AS BLOB)) <= 16384),
            checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(scan_id,check_name)
          ); PRAGMA user_version = 11;`);
        }
        if (version < 12) this.db.exec(`CREATE TABLE scan_execution_profiles (
          scan_id TEXT PRIMARY KEY REFERENCES scans(id), binding TEXT NOT NULL CHECK(length(CAST(binding AS BLOB)) <= 1024)
        ); PRAGMA user_version = 12;`);
        if (version < 13) this.db.exec(`ALTER TABLE scan_vuln_findings ADD COLUMN advisory TEXT
          CHECK(advisory IS NULL OR length(CAST(advisory AS BLOB)) <= 16384);
          PRAGMA user_version = 13;`);
        if ((this.db.pragma('foreign_key_check') as unknown[]).length)
          throw new Error('Ledger migration foreign key mismatch');
      });
      this.db.pragma('foreign_keys = ON');
      this.orm = drizzle(this.db);
    } catch (error) {
      this.db.close();
      throw error;
    }
  }

  private immediate<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const value = fn();
      this.db.exec('COMMIT');
      return value;
    } catch (error) {
      if (this.db.inTransaction) this.db.exec('ROLLBACK');
      throw error;
    }
  }

  findByKey(subject: string, idempotencyKey: string): { scanId: string; digest: string; platform: string; fingerprint: string | null } | undefined {
    const [row] = this.orm.select({ id: scans.id, digest: scans.digest, platform: scans.platform, fingerprint: scans.fingerprint })
      .from(scans).where(and(eq(scans.subject, subject), eq(scans.idempotencyKey, idempotencyKey))).all();
    return row ? { scanId: row.id, digest: row.digest, platform: row.platform, fingerprint: row.fingerprint } : undefined;
  }

  // Cheap durable preflight avoids expensive registry requests during a burst.
  // The authoritative admission check is repeated in enqueue under BEGIN IMMEDIATE.
  checkAdmission(subject: string): void {
    if ((this.db.prepare(`SELECT count(*) AS n FROM scans WHERE subject = ? AND state IN ('queued','running')`)
      .get(subject) as { n: number }).n >= SUBJECT_ACTIVE_LIMIT) throw new AdmissionLimited();
    if ((this.db.prepare('SELECT count(*) AS n FROM scans WHERE state IN (\'queued\',\'running\')')
      .get() as { n: number }).n >= GLOBAL_ACTIVE_LIMIT) throw new AdmissionLimited();
  }

  reserveAttempt(subject: string, now = Date.now()): void {
    if (!/^[A-Za-z0-9:_-]{1,128}$/.test(subject)) throw new TypeError('Invalid subject');
    this.immediate(() => {
      const minute = Math.floor(now / 60000);
      const used = (this.db.prepare('SELECT count AS n FROM admission_windows WHERE subject = ? AND minute = ?')
        .get(subject, minute) as { n: number } | undefined)?.n ?? 0;
      if (used >= SUBJECT_MINUTE_LIMIT) throw new AdmissionLimited();
      this.db.prepare(`INSERT INTO admission_windows (subject,minute,count) VALUES (?,?,1)
        ON CONFLICT(subject,minute) DO UPDATE SET count = count + 1`).run(subject, minute);
    });
  }

  enqueue(target: PinnedTarget): { scanId: string; created: boolean } {
    if (!target.subject || !target.idempotencyKey || !target.registry || !target.repository ||
        !/^sha256:[a-f0-9]{64}$/.test(target.digest) ||
        !/^linux\/[a-z0-9]+(?:\/[a-z0-9]+)?$/.test(target.platform) ||
        (target.fingerprint !== undefined && !/^[a-f0-9]{64}$/.test(target.fingerprint))) throw new TypeError('Invalid pinned target');
    if (target.executionProfile !== undefined && (!validLocalBinding(target.executionProfile) || !exactLocalTarget(target) ||
        !localChecksAllowed(canonicalChecks(target.checks ?? '') ?? []) || target.scope !== 'image')) throw new TypeError('Invalid execution binding');
    return this.immediate(() => {
      const existing = this.db.prepare('SELECT * FROM scans WHERE subject = ? AND idempotency_key = ?')
        .get(target.subject, target.idempotencyKey) as ScanRow | undefined;
      if (existing) {
        if (target.fingerprint !== undefined && existing.fingerprint !== target.fingerprint ||
            target.fingerprint === undefined && (existing.registry !== target.registry || existing.repository !== target.repository ||
              existing.digest !== target.digest || existing.platform !== target.platform)) {
          throw new IdempotencyConflict('Idempotency key used for another request');
        }
        return { scanId: existing.id, created: false };
      }
      this.checkAdmission(target.subject);
      const scanId = randomUUID();
      this.db.prepare(`INSERT INTO scans (id, subject, idempotency_key, registry, repository, digest, platform, state, fingerprint, checks, scope)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)`).run(
        scanId, target.subject, target.idempotencyKey, target.registry, target.repository,
        target.digest, target.platform, target.fingerprint ?? null, target.checks ?? '[]', target.scope ?? 'image');
      if (target.executionProfile) this.db.prepare('INSERT INTO scan_execution_profiles(scan_id,binding) VALUES (?,?)')
        .run(scanId, JSON.stringify(target.executionProfile));
      this.db.prepare('INSERT INTO outbox (scan_id) VALUES (?)').run(scanId);
      this.event(scanId, 'queued');
      this.audit(target.subject, 'alpine', 'image', 'accepted', 'CREATED', scanId);
      return { scanId, created: true };
    });
  }

  pending(): Array<{ scanId: string; digest: string; platform: string }> {
    return this.db.prepare(`SELECT scans.id AS scanId, digest, platform FROM scans
      JOIN outbox ON outbox.scan_id = scans.id WHERE delivered_at IS NULL ORDER BY scans.created_at, scans.id`)
      .all() as Array<{ scanId: string; digest: string; platform: string }>;
  }

  claim(now = Date.now(), leaseMs = 60_000, archiveLeaseMs?: number): Job | undefined {
      if (archiveLeaseMs !== undefined && (!Number.isSafeInteger(archiveLeaseMs) || archiveLeaseMs < 1 || archiveLeaseMs > 627_000))
        throw new TypeError('Invalid archive lease');
    return this.immediate(() => {
      const row = this.db.prepare(`SELECT s.id AS scanId, s.registry, s.repository, s.digest, s.platform, s.checks, s.scope, o.attempts
        FROM outbox o JOIN scans s ON s.id = o.scan_id
        WHERE s.state IN ('queued','running') AND o.delivered_at IS NULL
          AND o.next_run_at <= ? AND (o.lease_until IS NULL OR o.lease_until <= ?)
        ORDER BY s.created_at, s.id LIMIT 1`).get(now, now) as ClaimRow | undefined;
      if (!row) return undefined;
      this.db.prepare('UPDATE outbox SET lease_until = ?, attempts = attempts + 1 WHERE scan_id = ?')
        .run(now + (row.repository === 'library/nginx' && archiveLeaseMs ? Math.max(leaseMs, archiveLeaseMs) : leaseMs) +
                  (canonicalChecks(row.checks)?.includes('config') ? CONFIG_LOAD_MS + 1000 : 0), row.scanId);
      this.db.prepare("UPDATE scans SET state = 'running' WHERE id = ?").run(row.scanId);
      this.event(row.scanId, 'running');
      const executionProfile = this.executionProfile(row.scanId);
      return { ...row, attempts: row.attempts + 1, ...(executionProfile ? { executionProfile } : {}) };
    });
  }

  cancel(scanId: string, subject: string): 'cancelled' | 'already_cancelled' | 'conflict' | 'not_found' {
    return this.immediate(() => {
      const changed = this.db.prepare(`UPDATE scans SET state = 'cancelled', terminal_at = CURRENT_TIMESTAMP
        WHERE id = ? AND subject = ? AND state IN ('queued','running')`).run(scanId, subject);
      if (changed.changes === 1) {
        this.db.prepare(`UPDATE outbox SET delivered_at = CURRENT_TIMESTAMP, lease_until = NULL
          WHERE scan_id = ? AND delivered_at IS NULL`).run(scanId);
        this.event(scanId, 'cancelled');
        return 'cancelled';
      }
      const row = this.db.prepare('SELECT state FROM scans WHERE id = ? AND subject = ?')
        .get(scanId, subject) as { state: string } | undefined;
      return !row ? 'not_found' : row.state === 'cancelled' ? 'already_cancelled' : 'conflict';
    });
  }

  // A worker may keep running after its lease expires. Only its current, live attempt
  // may continue; cancellation and a replacement claim both revoke that authority.
  attemptActive(scanId: string, attempts: number): boolean {
    return !!this.db.prepare(`SELECT 1 FROM outbox o JOIN scans s ON s.id = o.scan_id
      WHERE o.scan_id = ? AND o.attempts = ? AND o.delivered_at IS NULL AND s.state = 'running'`)
      .get(scanId, attempts);
  }

  configAttemptContext(scanId: string, attempts: number): { subject: string; job: Job } | undefined {
    const row = this.db.prepare(`SELECT s.subject,s.id AS scanId,s.registry,s.repository,s.digest,s.platform,s.checks,s.scope,o.attempts
      FROM scans s JOIN outbox o ON o.scan_id=s.id WHERE s.id=? AND s.state='running'
      AND o.attempts=? AND o.delivered_at IS NULL AND o.lease_until IS NOT NULL`)
      .get(scanId, attempts) as (Job & { subject: string }) | undefined;
    if (!row) return undefined;
    const { subject, ...job } = row;
    return { subject, job };
  }

  configResult(scanId: string, subject: string): ImageConfigResult | undefined {
    const row = this.db.prepare(`SELECT r.report,s.digest,s.platform,s.checks FROM scan_check_results r JOIN scans s ON s.id=r.scan_id
      WHERE s.id=? AND s.subject=? AND r.check_name='config'`).get(scanId, subject) as
      { report: string; digest: string; platform: string; checks: string } | undefined;
    return row ? validateConfigReport(JSON.parse(row.report), row, canonicalChecks(row.checks)?.includes('config') === true) : undefined;
  }

  private saveConfig(scanId: string, attempts: number, report: ImageConfigResult): void {
    this.db.prepare(`INSERT INTO scan_check_results(scan_id,check_name,attempt,outcome,checks_version,resource_policy_version,report)
      VALUES (?,'config',?,?,?,?,?)`).run(scanId, attempts, report.config.outcome, report.checksVersion,
        report.resourcePolicyVersion, JSON.stringify(report));
  }

  finish(scanId: string, attempts: number, state: 'failed', errorCode: 'SCAN_FAILED' | 'SCAN_TIMEOUT' | 'SCAN_UNAVAILABLE' = 'SCAN_FAILED'): boolean {
    return this.immediate(() => {
      const result = this.db.prepare(`UPDATE outbox SET delivered_at = CURRENT_TIMESTAMP, lease_until = NULL
        WHERE scan_id = ? AND attempts = ? AND delivered_at IS NULL
          AND EXISTS (SELECT 1 FROM scans WHERE id = ? AND state = 'running')`).run(scanId, attempts, scanId);
      if (result.changes) {
        const stateChange = this.db.prepare("UPDATE scans SET state = ?, terminal_at = CURRENT_TIMESTAMP WHERE id = ? AND state = 'running'").run(state, scanId);
        if (stateChange.changes !== 1) throw new Error('Scan failure contract mismatch');
        const job = this.db.prepare('SELECT checks, scope FROM scans WHERE id = ?')
          .get(scanId) as { checks: string; scope: string };
        if (job.scope !== 'image') throw new Error('Scan failure contract mismatch');
        if (job.checks === '["sbom"]') {
          this.db.prepare(`INSERT INTO scan_sbom_results(scan_id,coverage,outcome,error_code)
            VALUES (?,'image','failed',?)`).run(scanId, errorCode);
        } else if (job.checks === '["secret"]') {
          this.saveFailure(scanId, errorCode);
        } else if (job.checks === '["vuln"]') {
          this.db.prepare(`INSERT INTO scan_vuln_results(scan_id,coverage,outcome,error_code)
            VALUES (?,'image','failed',?)`).run(scanId, errorCode);
        }
        // Legacy/unsupported checks have no verified per-check coverage. Record only
        // the terminal failure; never attribute it to a secret or SBOM check.
        this.event(scanId, state);
      }
      return result.changes === 1;
    });
  }

  finishWithResult(scanId: string, attempts: number, findings: SecretFinding[], scannerVersion: string): boolean {
    if (!Array.isArray(findings) || findings.length > MAX_FINDINGS || scannerVersion !== '0.69.3' ||
      findings.some(f => !/^secret-\d+-\d+$/.test(f.findingId) || !/^[A-Za-z0-9._-]{1,80}$/.test(f.ruleId) ||
        !/^result-\d+-secret-\d+$/.test(f.evidenceRef) || f.line !== null && (!Number.isSafeInteger(f.line) || f.line < 0))) throw new TypeError('Invalid result');
    return this.immediate(() => {
      const delivered = this.db.prepare(`UPDATE outbox SET delivered_at = CURRENT_TIMESTAMP, lease_until = NULL
        WHERE scan_id = ? AND attempts = ? AND delivered_at IS NULL
          AND EXISTS (SELECT 1 FROM scans WHERE id = ? AND state = 'running')`).run(scanId, attempts, scanId);
      if (!delivered.changes) return false;
      this.db.prepare(`INSERT INTO scan_results (scan_id, check_name, finding_count, coverage, outcome, scanner_version)
        VALUES (?, 'secret', ?, 'image', 'checked', ?)`).run(scanId, findings.length, scannerVersion);
      const insert = this.db.prepare('INSERT INTO scan_findings(scan_id,finding_id,rule_id,line,evidence_ref) VALUES (?,?,?,?,?)');
      for (const finding of findings) insert.run(scanId, finding.findingId, finding.ruleId, finding.line, finding.evidenceRef);
      const state = this.db.prepare(`UPDATE scans SET state = 'completed', terminal_at = CURRENT_TIMESTAMP
        WHERE id = ? AND state = 'running' AND checks = '["secret"]' AND scope = 'image'`).run(scanId);
      if (state.changes !== 1) throw new Error('Scan result contract mismatch');
      this.event(scanId, 'completed');
      return true;
    });
  }

  finishWithSbom(scanId: string, attempts: number, sbom: ImageSbom, scannerVersion: string): boolean {
    if (!sbomObject(sbom, ['image', 'platform', 'os', 'components']) ||
        typeof sbom.image !== 'string' ||
        !/^registry-1\.docker\.io\/library\/alpine@sha256:[a-f0-9]{64}$/.test(sbom.image) ||
        sbom.platform !== 'linux/amd64' || !sbomObject(sbom.os, ['name', 'version']) ||
        sbom.os.name !== 'alpine' || !sbomIdentifier(sbom.os.version, 80) ||
        !Array.isArray(sbom.components) || sbom.components.length < 1 ||
        sbom.components.length > MAX_SBOM_COMPONENTS || scannerVersion !== '0.69.3') throw new TypeError('Invalid SBOM');
    const seen = new Set<string>();
    for (const component of sbom.components) {
      if (!sbomObject(component, ['ecosystem', 'name', 'version']) ||
          component.ecosystem !== 'apk' && component.ecosystem !== 'npm' ||
          !sbomIdentifier(component.name, 128) ||
          !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._+-]*$/.test(component.name) ||
          !sbomIdentifier(component.version, 80)) throw new TypeError('Invalid SBOM component');
      const key = JSON.stringify([component.ecosystem, component.name, component.version]);
      if (seen.has(key)) throw new TypeError('Duplicate SBOM component');
      seen.add(key);
    }
    return this.immediate(() => {
      const delivered = this.db.prepare(`UPDATE outbox SET delivered_at = CURRENT_TIMESTAMP, lease_until = NULL
        WHERE scan_id = ? AND attempts = ? AND delivered_at IS NULL
          AND EXISTS (SELECT 1 FROM scans WHERE id = ? AND state = 'running')`).run(scanId, attempts, scanId);
      if (!delivered.changes) return false;
      const row = this.db.prepare('SELECT registry, repository, digest, platform, checks, scope FROM scans WHERE id = ?')
        .get(scanId) as { registry: string; repository: string; digest: string; platform: string; checks: string; scope: string };
      if (row.checks !== '["sbom"]' || row.scope !== 'image' || row.platform !== sbom.platform ||
          `${row.registry}/${row.repository}@${row.digest}` !== sbom.image)
        throw new Error('Scan SBOM contract mismatch');
      this.db.prepare(`INSERT INTO scan_sbom_results
        (scan_id,image,platform,os_name,os_version,component_count,coverage,outcome,scanner_version,checked_at)
        VALUES (?,?,?,?,?,?,'image','checked',?,CURRENT_TIMESTAMP)`).run(scanId, sbom.image, sbom.platform,
          sbom.os.name, sbom.os.version, sbom.components.length, scannerVersion);
      const insert = this.db.prepare(`INSERT INTO scan_sbom_components(scan_id,ordinal,ecosystem,name,version)
        VALUES (?,?,?,?,?)`);
      sbom.components.forEach((component, ordinal) =>
        insert.run(scanId, ordinal, component.ecosystem, component.name, component.version));
      const state = this.db.prepare(`UPDATE scans SET state = 'completed', terminal_at = CURRENT_TIMESTAMP
        WHERE id = ? AND state = 'running' AND checks = '["sbom"]' AND scope = 'image'`).run(scanId);
      if (state.changes !== 1) throw new Error('Scan SBOM contract mismatch');
      this.event(scanId, 'completed');
      return true;
    });
  }

  // Quarantined exact-candidate attempt output. No public admission or generic profile switch.
  finishArchive(scanId: string, attempts: number, report: ArchiveScanReport, config?: ImageConfigResult): boolean {
    const context = config ? this.configAttemptContext(scanId, attempts) : undefined;
    if (config && !context) return false;
    const safeConfig = config ? validateConfigReport(config, context!.job, canonicalChecks(context!.job.checks)?.includes('config') === true) : undefined;
    const { requested, checked } = validateStoredArchive(report);
    // Optional report metadata is dropped deterministically before the fenced transaction.
    let body = JSON.stringify(report);
    if (Buffer.byteLength(body) > 2_000_000 && report.vuln?.outcome === 'checked') {
      report = { ...report, vuln: { ...report.vuln, findings: report.vuln.findings.map(f => ({ ...f })) } };
      if (report.vuln?.outcome === 'checked') {
        for (const finding of [...report.vuln.findings].sort((a, b) => a.findingId < b.findingId ? 1 : -1)) {
          if (!finding.advisory) continue;
          finding.advisory = omittedAdvisory('report_budget');
          body = JSON.stringify(report);
          if (Buffer.byteLength(body) <= 2_000_000) break;
        }
      }
    }
    if (Buffer.byteLength(body) > 2_000_000) throw new TypeError('Invalid archive result size');
    return this.immediate(() => {
      const row = this.db.prepare(`SELECT s.subject,s.registry,s.repository,s.digest,s.platform,s.checks,s.scope
        FROM scans s JOIN outbox o ON o.scan_id=s.id WHERE s.id=? AND s.state='running'
        AND o.attempts=? AND o.delivered_at IS NULL AND o.lease_until IS NOT NULL`).get(scanId, attempts) as Job | undefined;
      if (!row) return false;
      const target = NGINX_ARCHIVE_CANDIDATES.find(candidate => candidate.digest === report.receipt.digest);
      if (!target || Object.entries(target).some(([key, value]) => key !== 'configDigest' && row[key as keyof Job] !== value) ||
          row.scope !== 'image' || JSON.stringify(canonicalChecks(row.checks)?.filter(check => check !== 'config')) !== JSON.stringify(requested) ||
          canonicalChecks(row.checks)?.includes('config') && !safeConfig ||
          safeConfig && !isDeepStrictEqual(context, this.configAttemptContext(scanId, attempts))) throw new TypeError('Archive job mismatch');
      const binding = this.executionProfile(scanId);
      if (binding && (!validLocalBinding(binding) || !localChecksAllowed(requested) || !localReceiptMatches(report.receipt, report.scannerVersion)))
        throw new TypeError('Execution receipt mismatch');
      // Freshness is a clock check only; no hashing/network work inside the transaction.
      assertArchiveDbFreshness(report);
      const changed = this.db.prepare(`UPDATE outbox SET delivered_at=CURRENT_TIMESTAMP,lease_until=NULL
        WHERE scan_id=? AND attempts=? AND delivered_at IS NULL`).run(scanId, attempts);
      if (changed.changes !== 1) throw new Error('Archive attempt mismatch');
      this.db.prepare('INSERT INTO scan_archive_results(scan_id,attempt,report) VALUES (?,?,?)').run(scanId, attempts, body);
      if (safeConfig) this.saveConfig(scanId, attempts, safeConfig);
      const selectedConfig = canonicalChecks(row.checks)?.includes('config') === true;
      const count = checked.length + (selectedConfig && safeConfig?.config.outcome === 'checked' ? 1 : 0);
      const terminal = count === requested.length + (selectedConfig ? 1 : 0) ? 'completed' : count ? 'partial' : 'failed';
      this.db.prepare(`UPDATE scans SET state=?,terminal_at=CURRENT_TIMESTAMP WHERE id=? AND state='running'`).run(terminal, scanId);
      this.event(scanId, terminal);
      return true;
    });
  }

  executionProfile(scanId: string): LocalExecutionBinding | undefined {
    const row = this.db.prepare('SELECT binding FROM scan_execution_profiles WHERE scan_id=?').get(scanId) as { binding: string } | undefined;
    if (!row) return undefined;
    const value: unknown = JSON.parse(row.binding);
    if (!validLocalBinding(value)) throw new TypeError('Invalid stored execution binding');
    return value;
  }

  archiveResult(scanId: string, subject: string): ArchiveScanReport | undefined {
    const row = this.db.prepare(`SELECT r.report, s.registry, s.repository, s.digest, s.platform, s.checks FROM scan_archive_results r JOIN scans s ON s.id=r.scan_id
      WHERE s.id=? AND s.subject=?`).get(scanId, subject) as { report: string; registry: string; repository: string; digest: string; platform: string; checks: string } | undefined;
    if (!row) return undefined;
    if (Buffer.byteLength(row.report) > 2_000_000) throw new TypeError('Invalid stored archive size');
    const report: ArchiveScanReport = JSON.parse(row.report);
    const { requested } = validateStoredArchive(report);
    if (['registry', 'repository', 'digest', 'platform'].some(key => report.receipt[key as keyof typeof report.receipt] !== row[key as 'registry' | 'repository' | 'digest' | 'platform']) ||
        JSON.stringify(requested) !== JSON.stringify(canonicalChecks(row.checks)?.filter(check => check !== 'config')))
      throw new TypeError('Invalid stored archive binding');
    return report;
  }

  finishCombined(scanId: string, attempts: number, outcomes: CombinedOutcome[], config?: ImageConfigResult): boolean {
    if (outcomes.length || !config) validateCombined(outcomes);
    const context = config ? this.configAttemptContext(scanId, attempts) : undefined;
    if (config && !context) return false;
    const safeConfig = config ? validateConfigReport(config, context!.job, canonicalChecks(context!.job.checks)?.includes('config') === true) : undefined;
    return this.immediate(() => {
      const row = this.db.prepare(`SELECT s.registry,s.repository,s.digest,s.platform,s.checks,s.scope
        FROM scans s JOIN outbox o ON o.scan_id = s.id
        WHERE s.id = ? AND s.state = 'running' AND o.attempts = ? AND o.delivered_at IS NULL
          ${safeConfig ? 'AND o.lease_until IS NOT NULL' : ''}`)
        .get(scanId, attempts) as { registry: string; repository: string; digest: string;
          platform: string; checks: string; scope: string } | undefined;
      if (!row) return false;
      const requested = canonicalChecks(row.checks);
      if (!requested || row.scope !== 'image' || row.platform !== 'linux/amd64' ||
          !admittedConfigTarget(row) ||
          (row.repository !== 'library/alpine' && outcomes.some(item => item.outcome === 'checked')) ||
          !/^sha256:[a-f0-9]{64}$/.test(row.digest) ||
          JSON.stringify(outcomes.map(item => item.check)) !== JSON.stringify(requested.filter(check => check !== 'config')) ||
          requested.includes('config') && !safeConfig || safeConfig && !isDeepStrictEqual(context, this.configAttemptContext(scanId, attempts)))
        throw new Error('Scan combined contract mismatch');
      const image = `${row.registry}/${row.repository}@${row.digest}`;
      for (const item of outcomes) {
        if (item.outcome === 'checked' && item.check === 'sbom' &&
            (item.sbom.image !== image || item.sbom.platform !== row.platform) ||
            item.outcome === 'checked' && item.check === 'vuln' && item.image !== image)
          throw new Error('Scan combined image mismatch');
      }
      const delivered = this.db.prepare(`UPDATE outbox SET delivered_at = CURRENT_TIMESTAMP, lease_until = NULL
        WHERE scan_id = ? AND attempts = ? AND delivered_at IS NULL
          AND EXISTS (SELECT 1 FROM scans WHERE id = ? AND state = 'running')`).run(scanId, attempts, scanId);
      if (delivered.changes !== 1) throw new Error('Scan combined attempt mismatch');
      for (const item of outcomes) {
        if (item.outcome === 'failed') {
          if (item.check === 'secret') this.saveFailure(scanId, item.errorCode);
          else if (item.check === 'sbom') this.db.prepare(`INSERT INTO scan_sbom_results
            (scan_id,coverage,outcome,error_code) VALUES (?,'image','failed',?)`).run(scanId, item.errorCode);
          else this.db.prepare(`INSERT INTO scan_vuln_results
            (scan_id,coverage,outcome,error_code) VALUES (?,'image','failed',?)`).run(scanId, item.errorCode);
        } else if (item.check === 'secret') {
          this.db.prepare(`INSERT INTO scan_results
            (scan_id,check_name,finding_count,coverage,outcome,scanner_version)
            VALUES (?,'secret',?,'image','checked',?)`).run(scanId, item.findings.length, item.scannerVersion);
          const insert = this.db.prepare(`INSERT INTO scan_findings
            (scan_id,finding_id,rule_id,line,evidence_ref) VALUES (?,?,?,?,?)`);
          for (const f of item.findings) insert.run(scanId, f.findingId, f.ruleId, f.line, f.evidenceRef);
        } else if (item.check === 'sbom') {
          this.db.prepare(`INSERT INTO scan_sbom_results
            (scan_id,image,platform,os_name,os_version,component_count,coverage,outcome,scanner_version,checked_at)
            VALUES (?,?,?,?,?,?,'image','checked',?,CURRENT_TIMESTAMP)`).run(scanId,
              item.sbom.image, item.sbom.platform, item.sbom.os.name, item.sbom.os.version,
              item.sbom.components.length, item.scannerVersion);
          const insert = this.db.prepare(`INSERT INTO scan_sbom_components
            (scan_id,ordinal,ecosystem,name,version) VALUES (?,?,?,?,?)`);
          item.sbom.components.forEach((component, ordinal) =>
            insert.run(scanId, ordinal, component.ecosystem, component.name, component.version));
        } else {
          this.db.prepare(`INSERT INTO scan_vuln_results
            (scan_id,image,platform,finding_count,coverage,outcome,scanner_version,checked_at)
            VALUES (?,?,?,?,'image','checked',?,CURRENT_TIMESTAMP)`).run(scanId,
              item.image, row.platform, item.findings.length, item.scannerVersion);
          const insert = this.db.prepare(`INSERT INTO scan_vuln_findings
            (scan_id,ordinal,finding_id,cve_id,ecosystem,package_name,installed_version,severity,severity_sources,provenance_ref,fixed_version,advisory)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`);
          item.findings.forEach((f, ordinal) => insert.run(scanId, ordinal, f.findingId, f.cveId,
            f.ecosystem, f.packageName, f.installedVersion, f.severity, JSON.stringify(f.severitySources),
            f.provenanceRef, f.fixedVersion, f.advisory == null ? null : JSON.stringify(f.advisory)));
        }
      }
      if (safeConfig) this.saveConfig(scanId, attempts, safeConfig);
      const checked = outcomes.filter(item => item.outcome === 'checked').length +
        (requested.includes('config') && safeConfig?.config.outcome === 'checked' ? 1 : 0);
      const terminal = checked === requested.length ? 'completed' : checked === 0 ? 'failed' : 'partial';
      const changed = this.db.prepare(`UPDATE scans SET state = ?, terminal_at = CURRENT_TIMESTAMP
        WHERE id = ? AND state = 'running' AND checks = ? AND scope = 'image'`)
        .run(terminal, scanId, row.checks);
      if (changed.changes !== 1) throw new Error('Scan combined contract mismatch');
      this.event(scanId, terminal);
      return true;
    });
  }

  // The image is supplied by the pinned worker job, not reconstructed from untrusted findings.
  finishWithVuln(scanId: string, attempts: number, image: string, findings: VulnFinding[], scannerVersion: string): boolean {
    if (scannerVersion !== '0.69.3') throw new TypeError('Invalid vulnerability result');
    validateCombined([{ check: 'vuln', outcome: 'checked', image, findings, scannerVersion }]);
    return this.immediate(() => {
      const delivered = this.db.prepare(`UPDATE outbox SET delivered_at = CURRENT_TIMESTAMP, lease_until = NULL
        WHERE scan_id = ? AND attempts = ? AND delivered_at IS NULL
          AND EXISTS (SELECT 1 FROM scans WHERE id = ? AND state = 'running')`).run(scanId, attempts, scanId);
      if (!delivered.changes) return false;
      const row = this.db.prepare('SELECT registry, repository, digest, platform, checks, scope FROM scans WHERE id = ?')
        .get(scanId) as { registry: string; repository: string; digest: string; platform: string; checks: string; scope: string };
      if (row.checks !== '["vuln"]' || row.scope !== 'image' || row.platform !== 'linux/amd64' ||
          `${row.registry}/${row.repository}@${row.digest}` !== image)
        throw new Error('Scan vulnerability contract mismatch');
      this.db.prepare(`INSERT INTO scan_vuln_results
        (scan_id,image,platform,finding_count,coverage,outcome,scanner_version,checked_at)
        VALUES (?,?,?,?,'image','checked',?,CURRENT_TIMESTAMP)`)
        .run(scanId, image, row.platform, findings.length, scannerVersion);
      const insert = this.db.prepare(`INSERT INTO scan_vuln_findings
        (scan_id,ordinal,finding_id,cve_id,ecosystem,package_name,installed_version,severity,severity_sources,provenance_ref,fixed_version,advisory)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`);
      findings.forEach((finding, ordinal) => insert.run(scanId, ordinal, finding.findingId, finding.cveId,
        finding.ecosystem, finding.packageName, finding.installedVersion, finding.severity,
        JSON.stringify(finding.severitySources), finding.provenanceRef, finding.fixedVersion, finding.advisory == null ? null : JSON.stringify(finding.advisory)));
      const state = this.db.prepare(`UPDATE scans SET state = 'completed', terminal_at = CURRENT_TIMESTAMP
        WHERE id = ? AND state = 'running' AND checks = '["vuln"]' AND scope = 'image'`).run(scanId);
      if (state.changes !== 1) throw new Error('Scan vulnerability contract mismatch');
      this.event(scanId, 'completed');
      return true;
    });
  }

  vuln(scanId: string, subject: string, cursor = 0, limit = 50): ({
    image: string; platform: 'linux/amd64'; findingCount: number; coverage: 'image'; outcome: 'checked';
    scannerVersion: string; checkedAt: string; findings: VulnFinding[]; nextCursor: number | null;
  } | { coverage: 'image'; outcome: 'failed'; errorCode: 'SCAN_FAILED' | 'SCAN_TIMEOUT' | 'SCAN_UNAVAILABLE';
    findings: []; nextCursor: null }) | undefined {
    if (!Number.isSafeInteger(cursor) || cursor < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      throw new TypeError('Invalid pagination');
    const row = this.db.prepare(`SELECT r.image, r.platform, r.finding_count AS findingCount, r.coverage,
      r.outcome, r.scanner_version AS scannerVersion, r.checked_at AS checkedAt, r.error_code AS errorCode
      FROM scan_vuln_results r JOIN scans s ON s.id = r.scan_id WHERE s.id = ? AND s.subject = ?`)
      .get(scanId, subject) as { image: string | null; platform: 'linux/amd64' | null;
        findingCount: number | null; coverage: 'image'; outcome: 'checked' | 'failed';
        scannerVersion: string | null; checkedAt: string | null;
        errorCode: 'SCAN_FAILED' | 'SCAN_TIMEOUT' | 'SCAN_UNAVAILABLE' | null } | undefined;
    if (!row) return undefined;
    if (row.outcome === 'failed') return { coverage: 'image', outcome: 'failed', errorCode: row.errorCode!,
      findings: [], nextCursor: null };
    // Validate the complete bounded durable dataset before projecting a page.
    const stored = this.db.prepare(`SELECT finding_id AS findingId, cve_id AS cveId, ecosystem,
      package_name AS packageName, installed_version AS installedVersion, severity,
      severity_sources AS severitySources, provenance_ref AS provenanceRef, fixed_version AS fixedVersion, advisory
      FROM scan_vuln_findings WHERE scan_id = ? ORDER BY ordinal LIMIT 1001`)
      .all(scanId) as Array<Omit<VulnFinding, 'severitySources' | 'advisory'> & { severitySources: string; advisory: string | null }>;
    const all = stored.map(({ advisory, ...finding }) => {
      if (Buffer.byteLength(finding.severitySources) > 1024 || advisory !== null && Buffer.byteLength(advisory) > 16_384)
        throw new TypeError('Invalid stored vulnerability finding');
      return { ...finding, severitySources: JSON.parse(finding.severitySources) as string[],
        ...(advisory === null ? {} : { advisory: JSON.parse(advisory) }) };
    });
    if (row.platform !== 'linux/amd64' || row.scannerVersion !== '0.69.3' || row.findingCount !== all.length)
      throw new TypeError('Invalid stored vulnerability result');
    validateCombined([{ check: 'vuln', outcome: 'checked', image: row.image!, scannerVersion: row.scannerVersion, findings: all }]);
    const findings = all.slice(cursor, cursor + limit);
    return { image: row.image!, platform: row.platform, findingCount: row.findingCount, coverage: 'image',
      outcome: 'checked', scannerVersion: row.scannerVersion, checkedAt: row.checkedAt!, findings,
      nextCursor: cursor + findings.length < row.findingCount ? cursor + findings.length : null };
  }

  sbom(scanId: string, subject: string, cursor = 0, limit = 50): ({
    image: string; platform: 'linux/amd64'; os: ImageSbom['os']; componentCount: number;
    coverage: 'image'; outcome: 'checked'; scannerVersion: string; checkedAt: string;
    components: SbomComponent[]; nextCursor: number | null;
  } | { coverage: 'image'; outcome: 'failed'; errorCode: 'SCAN_FAILED' | 'SCAN_TIMEOUT' | 'SCAN_UNAVAILABLE';
    components: []; nextCursor: null }) | undefined {
    if (!Number.isSafeInteger(cursor) || cursor < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      throw new TypeError('Invalid pagination');
    const row = this.db.prepare(`SELECT r.image, r.platform, r.os_name AS osName, r.os_version AS osVersion,
      r.component_count AS componentCount, r.coverage, r.outcome, r.scanner_version AS scannerVersion,
      r.checked_at AS checkedAt, r.error_code AS errorCode FROM scan_sbom_results r JOIN scans s ON s.id = r.scan_id
      WHERE s.id = ? AND s.subject = ?`).get(scanId, subject) as {
      image: string | null; platform: 'linux/amd64' | null; osName: string | null; osVersion: string | null;
      componentCount: number | null; coverage: 'image'; outcome: 'checked' | 'failed';
      scannerVersion: string | null; checkedAt: string | null;
      errorCode: 'SCAN_FAILED' | 'SCAN_TIMEOUT' | 'SCAN_UNAVAILABLE' | null;
    } | undefined;
    if (!row) return undefined;
    if (row.outcome === 'failed') return { coverage: row.coverage, outcome: 'failed', errorCode: row.errorCode!,
      components: [], nextCursor: null };
    const components = this.db.prepare(`SELECT ecosystem,name,version FROM scan_sbom_components
      WHERE scan_id = ? AND ordinal >= ? ORDER BY ordinal LIMIT ?`)
      .all(scanId, cursor, limit) as SbomComponent[];
    return { image: row.image!, platform: row.platform!, os: { name: row.osName!, version: row.osVersion! },
      componentCount: row.componentCount!, coverage: row.coverage, outcome: 'checked',
      scannerVersion: row.scannerVersion!, checkedAt: row.checkedAt!, components,
      nextCursor: cursor + components.length < row.componentCount! ? cursor + components.length : null };
  }

  result(scanId: string, subject: string): { findingCount: number | null; check: string; coverage: string; outcome: string; errorCode: string | null; scannerVersion: string | null } | undefined {
    return this.db.prepare(`SELECT r.finding_count AS findingCount, r.check_name AS 'check', r.coverage,
      r.outcome, r.error_code AS errorCode, r.scanner_version AS scannerVersion
      FROM scan_results r JOIN scans s ON s.id = r.scan_id
      WHERE s.id = ? AND s.subject = ?`)
      .get(scanId, subject) as ReturnType<ScanLedger['result']>;
  }

  findings(scanId: string, subject: string, cursor = 0, limit = 50): { findings: SecretFinding[]; nextCursor: number | null } | undefined {
    if (!Number.isSafeInteger(cursor) || cursor < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new TypeError('Invalid pagination');
    if (!this.state(scanId, subject)) return undefined;
    const rows = this.db.prepare(`SELECT f.finding_id AS findingId, f.rule_id AS ruleId, f.line, f.evidence_ref AS evidenceRef
      FROM scan_findings f JOIN scans s ON s.id = f.scan_id WHERE s.id = ? AND s.subject = ?
      ORDER BY f.finding_id LIMIT ? OFFSET ?`).all(scanId, subject, limit + 1, cursor) as SecretFinding[];
    return { findings: rows.slice(0, limit), nextCursor: rows.length > limit ? cursor + limit : null };
  }

  audit(subject: string, target: 'alpine' | 'unknown', scope: 'image' | 'unknown',
    decision: 'accepted' | 'rejected', reason: 'CREATED' | 'INVALID_REQUEST' | 'UNSUPPORTED' | 'CAPACITY' | 'EGRESS' | 'UNAUTHORIZED', scanId: string | null = null): void {
    if (!/^[A-Za-z0-9:_-]{1,128}$/.test(subject) || scanId !== null && !/^[a-f0-9-]{36}$/.test(scanId)) throw new TypeError('Invalid audit');
    const write = () => {
      this.db.prepare(`DELETE FROM scan_audit WHERE id IN
        (SELECT id FROM scan_audit ORDER BY id DESC LIMIT -1 OFFSET 9999)`).run();
      this.db.prepare(`INSERT INTO scan_audit(subject,target,scope,decision,reason,scan_id) VALUES (?,?,?,?,?,?)`)
        .run(subject, target, scope, decision, reason, scanId);
    };
    if (this.db.inTransaction) write(); else this.immediate(write);
  }

  private event(scanId: string, state: string): void {
    this.db.prepare('INSERT INTO scan_events(scan_id,state) VALUES (?,?)').run(scanId, state);
  }

  private saveFailure(scanId: string, code: string): void {
    if (!['SCAN_FAILED','SCAN_TIMEOUT','SCAN_UNAVAILABLE'].includes(code)) throw new TypeError('Invalid failure code');
    this.db.prepare(`INSERT INTO scan_results(scan_id,check_name,finding_count,coverage,outcome,error_code)
      VALUES (?,'secret',NULL,'image','failed',?)`).run(scanId, code);
  }

  events(scanId: string, subject: string, after: number | null): Array<{ id: number; state: string }> | undefined {
    if (!this.state(scanId, subject)) return undefined;
    if (after !== null && (!Number.isSafeInteger(after) || after < 0)) throw new TypeError('Invalid event ID');
    const rows = this.db.prepare(`SELECT seq AS id,state FROM scan_events WHERE scan_id = ? AND seq > ? ORDER BY seq LIMIT 100`)
      .all(scanId, after ?? 0) as Array<{ id: number; state: string }>;
    // Last-Event-ID is exclusive. An exhausted stream stays empty: clients fetch GET status
    // for a snapshot instead of receiving the same terminal event again.
    return rows;
  }

  retry(scanId: string, attempts: number, nextRunAt: number): boolean {
    return this.immediate(() => {
      const result = this.db.prepare(`UPDATE outbox SET lease_until = NULL, next_run_at = ?
        WHERE scan_id = ? AND attempts = ? AND delivered_at IS NULL
          AND EXISTS (SELECT 1 FROM scans WHERE id = ? AND state = 'running')`).run(nextRunAt, scanId, attempts, scanId);
      return result.changes === 1;
    });
  }

  requestedCheck(scanId: string, subject: string): 'secret' | 'sbom' | null {
    const row = this.db.prepare('SELECT checks FROM scans WHERE id = ? AND subject = ?')
      .get(scanId, subject) as { checks: string } | undefined;
    return row?.checks === '["secret"]' ? 'secret' : row?.checks === '["sbom"]' ? 'sbom' : null;
  }

  requestedChecks(scanId: string, subject: string): readonly CheckName[] {
    const row = this.db.prepare('SELECT checks FROM scans WHERE id = ? AND subject = ?')
      .get(scanId, subject) as { checks: string } | undefined;
    return row ? canonicalChecks(row.checks) ?? [] : [];
  }

  snapshot(scanId: string, subject: string): { state: string; digest: string; platform: string } | undefined {
    const [row] = this.orm.select({ state: scans.state, digest: scans.digest, platform: scans.platform }).from(scans)
      .where(and(eq(scans.id, scanId), eq(scans.subject, subject))).all();
    return row;
  }

  list(subject: string, cursor: string | undefined = undefined, limit = 50): { scans: Array<{ scanId: string; state: string; digest: string; platform: string; targetLabel: string }>; nextCursor: string | null } {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
        cursor !== undefined && !/^[1-9]\d{0,14}:[1-9]\d{0,14}$/.test(cursor)) throw new TypeError('Invalid pagination');
    const bound = cursor ? Number(cursor.split(':')[0]) :
      (this.db.prepare('SELECT max(seq) AS bound FROM scan_events').get() as { bound: number | null }).bound ?? 0;
    const last = cursor ? Number(cursor.split(':')[1]) : bound + 1;
    if (!Number.isSafeInteger(bound) || !Number.isSafeInteger(last) || last > bound + 1) throw new TypeError('Invalid pagination');
    // The first event is an AUTOINCREMENT sequence, unlike SQLite's reusable rowid.
    // A scan accepted during pagination cannot enter a prior snapshot, even after prune.
    const rows = this.db.prepare(`SELECT e.seq AS createdSeq, s.id AS scanId, s.state, s.digest, s.platform,
      s.registry || '/' || s.repository || '@' || s.digest AS targetLabel
      FROM scans s JOIN scan_events e ON e.seq =
        (SELECT min(seq) FROM scan_events WHERE scan_id = s.id)
      WHERE s.subject = ? AND e.seq <= ? AND e.seq < ? ORDER BY e.seq DESC LIMIT ?`)
      .all(subject, bound, last, limit + 1) as Array<{ createdSeq: number; scanId: string; state: string; digest: string; platform: string; targetLabel: string }>;
    return { scans: rows.slice(0, limit).map(row => ({ scanId: row.scanId, state: row.state, digest: row.digest,
          platform: row.platform, targetLabel: row.targetLabel })),
      nextCursor: rows.length > limit ? `${bound}:${rows[limit - 1].createdSeq}` : null };
  }

  state(scanId: string, subject: string): string | undefined {
    return this.snapshot(scanId, subject)?.state;
  }

  prune(days = 30): number {
    if (!Number.isInteger(days) || days < 1) throw new TypeError('Invalid retention');
    return this.immediate(() => {
      this.db.prepare('DELETE FROM admission_windows WHERE minute < ?').run(Math.floor(Date.now() / 60000) - 1440);
      this.db.prepare(`DELETE FROM scan_audit WHERE created_at < datetime('now', ?)`).run(`-${days} days`);
      for (const table of ['scan_execution_profiles', 'scan_check_results', 'scan_archive_results', 'scan_findings', 'scan_sbom_components', 'scan_sbom_results', 'scan_vuln_findings', 'scan_vuln_results', 'scan_events']) this.db.prepare(`DELETE FROM ${table} WHERE scan_id IN (SELECT id FROM scans WHERE terminal_at < datetime('now', ?))`).run(`-${days} days`);
      this.db.prepare(`DELETE FROM scan_results WHERE scan_id IN (SELECT id FROM scans WHERE terminal_at < datetime('now', ?))`)
        .run(`-${days} days`);
      this.db.prepare(`DELETE FROM outbox WHERE scan_id IN (SELECT id FROM scans WHERE terminal_at < datetime('now', ?))`)
        .run(`-${days} days`);
      const result = this.db.prepare(`DELETE FROM scans WHERE terminal_at < datetime('now', ?)`).run(`-${days} days`);
      return result.changes;
    });
  }

  close(): void { this.db.close(); }
}
