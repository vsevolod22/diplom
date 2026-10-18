import Database from 'better-sqlite3';
import { isDeepStrictEqual } from 'node:util';
import { createHash, randomUUID } from 'node:crypto';
import { and, eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { scans } from './schema.js';
import { MAX_FINDINGS, type SecretFinding } from '../worker/secret-findings.js';
import type { ImageSbom, SbomComponent } from '../worker/cyclonedx-components.js';
import { MAX_VULN_FINDINGS, PUBLIC_VULN_SOURCES, type VulnFinding } from '../worker/vuln-findings.js';
import { PUBLIC_ECOSYSTEMS, publicOs, publicPackageName, publicPackageVersion, publicVulnerabilityId, type PackageEcosystem } from '../worker/public-image-evidence.js';
import { isPublicReceipt, validPublicTarget } from '../oci/public-image-policy.js';
import { omittedAdvisory, plainObject, validateAdvisoryBudget } from '../worker/vuln-advisory.js';
import { NGINX_ARCHIVE_CANDIDATES } from '../oci/bounded-image-archive.js';
import { assertArchiveDbFreshness, validateArchiveReport } from '../worker/archive-result-contract.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';
import { CURRENT_DB_POLICY, LEGACY_DB_POLICY, DbUsabilityError, DbPolicyContractError, type CveDbPolicy } from '../worker/cve-db-policy.mjs';
import { validatePolicyBinding, validateDbEvidence, finalizeDbEvidence, type CveDbEvidence } from '../worker/cve-db-evidence.js';
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
  cvePolicy?: CveDbPolicy;
};
export type Job = { scanId: string; registry: string; repository: string; digest: string; platform: string; checks: string; scope: string; attempts: number; leaseToken?: string; executionProfile?: LocalExecutionBinding; cvePolicy?: CveDbPolicy };
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
  | { check: 'vuln'; outcome: 'checked'; image: string; findings: VulnFinding[]; scannerVersion: '0.69.3'; dbEvidence?: CveDbEvidence };
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

function validateCombined(outcomes: CombinedOutcome[], archiveImage?: string, policy: CveDbPolicy = LEGACY_DB_POLICY,
  publicReceipt?: ArchiveScanReport['receipt']): void {
  // Only a complete validated receipt selects the expanded normalized contract.
  if (publicReceipt && (!isPublicReceipt(publicReceipt) ||
      archiveImage !== `${publicReceipt.registry}/${publicReceipt.repository}@${publicReceipt.digest}`))
    throw new TypeError('Invalid public archive context');
  const sources = publicReceipt ? new Set(PUBLIC_VULN_SOURCES) : vulnSources;
  if (!Array.isArray(outcomes) || outcomes.length < 1 || outcomes.length > 3 ||
      outcomes.some(item => !sbomObject(item, item?.outcome === 'failed' ? ['check','outcome','errorCode'] :
        item?.check === 'sbom' ? ['check','outcome','sbom','scannerVersion'] :
        item?.check === 'vuln' ? ['check','outcome','image','findings','scannerVersion', ...(policy === CURRENT_DB_POLICY ? ['dbEvidence'] : [])] :
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
          (publicReceipt ? !publicOs({ Family: sbom.os.name, Name: sbom.os.version }) :
            sbom.os.name !== 'alpine' || !sbomIdentifier(sbom.os.version, 80)) ||
          !Array.isArray(sbom.components) || sbom.components.length < 1 ||
          sbom.components.length > MAX_SBOM_COMPONENTS) throw new TypeError('Invalid SBOM');
      const seen = new Set<string>();
      for (const component of sbom.components) {
        if (!sbomObject(component, ['ecosystem','name','version']) ||
            (publicReceipt ?
              !(PUBLIC_ECOSYSTEMS as readonly unknown[]).includes(component.ecosystem) ||
              !publicPackageName(component.name, component.ecosystem as PackageEcosystem) || !publicPackageVersion(component.version) :
              component.ecosystem !== 'apk' && component.ecosystem !== 'npm' ||
              !sbomIdentifier(component.name, 128) ||
              !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._+-]*$/.test(component.name) ||
              !sbomIdentifier(component.version, 80))) throw new TypeError('Invalid SBOM component');
        const key = JSON.stringify([component.ecosystem, component.name, component.version]);
        if (seen.has(key)) throw new TypeError('Duplicate SBOM component');
        seen.add(key);
      }
    } else {
      if (policy === CURRENT_DB_POLICY) validateDbEvidence(item.dbEvidence, policy);
      if (typeof item.image !== 'string' ||
          !(archiveImage ? item.image === archiveImage : /^registry-1\.docker\.io\/library\/alpine@sha256:[a-f0-9]{64}$/.test(item.image)) ||
          !Array.isArray(item.findings) || item.findings.length > MAX_VULN_FINDINGS)
        throw new TypeError('Invalid vulnerability result');
      const seen = new Set<string>();
      for (const f of item.findings) {
        if (!sbomObject(f, ['findingId','cveId','ecosystem','packageName','installedVersion',
          'severity','severitySources','provenanceRef','fixedVersion', ...(Object.hasOwn(f, 'advisory') ? ['advisory'] : [])]) ||
            typeof f.cveId !== 'string' || (publicReceipt ? !publicVulnerabilityId(f.cveId, f.ecosystem) :
                          !/^CVE-[0-9]{4}-[0-9]{4,12}$/.test(f.cveId)) ||
            (publicReceipt ?
              !(PUBLIC_ECOSYSTEMS as readonly unknown[]).includes(f.ecosystem) ||
              !publicPackageName(f.packageName, f.ecosystem) || !publicPackageVersion(f.installedVersion) ||
              f.fixedVersion !== null && !publicPackageVersion(f.fixedVersion) :
              f.ecosystem !== 'apk' && f.ecosystem !== 'npm' ||
              typeof f.packageName !== 'string' || f.packageName.length > 128 ||
              !(f.ecosystem === 'apk' ? /^[a-z0-9][a-z0-9._+-]{0,127}$/ :
                /^(?:@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*|[a-z0-9][a-z0-9._-]*)$/).test(f.packageName) ||
              typeof f.installedVersion !== 'string' ||
              !/^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,79}$/.test(f.installedVersion) ||
              f.fixedVersion !== null && (typeof f.fixedVersion !== 'string' ||
                !/^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,79}$/.test(f.fixedVersion))) ||
            !['UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL'].includes(f.severity) ||
            typeof f.provenanceRef !== 'string' || !/^target-[a-f0-9]{64}$/.test(f.provenanceRef) ||
            !Array.isArray(f.severitySources) || f.severitySources.length < 1 ||
            f.severitySources.length > sources.size ||
            f.severitySources.some((source, i) => typeof source !== 'string' || !sources.has(source) ||
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

function validateStoredArchive(report: ArchiveScanReport, policy: CveDbPolicy = LEGACY_DB_POLICY): { requested: string[]; checked: CombinedOutcome[] } {
  const requested = ['secret', 'sbom', 'vuln'].filter(check => Object.hasOwn(report, check));
  validateArchiveReport(report, requested, policy);
  assertArchiveDbFreshness(report, report.checkedAt, policy);
  const image = `${report.receipt.registry}/${report.receipt.repository}@${report.receipt.digest}`;
  const checked: CombinedOutcome[] = [];
  if (report.secret?.outcome === 'checked') checked.push({ check: 'secret', outcome: 'checked', findings: report.secret.findings, scannerVersion: report.scannerVersion });
  if (report.sbom?.outcome === 'checked') checked.push({ check: 'sbom', outcome: 'checked', sbom: report.sbom.sbom, scannerVersion: report.scannerVersion });
  if (report.vuln?.outcome === 'checked') {
    if (!sbomObject(report.vuln, ['outcome', 'findings', 'db', 'os', 'node', ...(policy === CURRENT_DB_POLICY ? ['dbPolicy'] : [])]) ||
      !sbomObject(report.vuln.os, ['outcome']) || report.vuln.os.outcome !== 'checked' ||
      !(sbomObject(report.vuln.node, ['outcome']) && report.vuln.node.outcome === 'checked' ||
      sbomObject(report.vuln.node, ['outcome','reason']) && report.vuln.node.outcome === 'unsupported' &&
      report.vuln.node.reason === (isPublicReceipt(report.receipt) ? 'NODE_INVENTORY_UNKNOWN' : 'NODE_INVENTORY_ABSENT'))) throw new TypeError('Invalid archive coverage');
    checked.push({ check: 'vuln', outcome: 'checked', image, findings: report.vuln.findings, scannerVersion: report.scannerVersion });
  }
  if (checked.length) validateCombined(checked, image, LEGACY_DB_POLICY, isPublicReceipt(report.receipt) ? report.receipt : undefined);
  return { requested, checked };
}

export type VulnDataset = {
  image: string; platform: 'linux/amd64'; findingCount: number; coverage: 'image'; outcome: 'checked';
  scannerVersion: string; checkedAt: string; findings: VulnFinding[]; dbEvidence?: CveDbEvidence;
} | { coverage: 'image'; outcome: 'failed'; errorCode: FailureCode; findings: [] };

type ScanRow = { id: string; registry: string; repository: string; digest: string; platform: string; fingerprint: string | null };
type CheckpointRow = { check: CheckName; kind: 'combined' | 'archive' | 'config'; identity: string; body: string; hash: string; committedAt: number };
type ClaimRow = { scanId: string; registry: string; repository: string; digest: string; platform: string; checks: string; scope: string; attempts: number };

export class ScanLedger {
  private readonly db: Database.Database;
  private readonly orm: ReturnType<typeof drizzle>;

  constructor(filename: string, private readonly clock: () => number = () => Date.now()) {
    this.db = new Database(filename, { timeout: 5000 });
    try {
      this.db.pragma('journal_mode = WAL');
      this.db.pragma('foreign_keys = ON');
      this.db.pragma('busy_timeout = 5000');
      const version = Number(this.db.pragma('user_version', { simple: true }));
      if (version > 15 || version < 0) throw new Error('Unsupported ledger version');
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
        if (version < 14) {
          this.db.exec(`CREATE TABLE scan_cve_policy (
            scan_id TEXT PRIMARY KEY REFERENCES scans(id),
            policy TEXT NOT NULL CHECK(policy IN ('legacy-db-freshness-v1','cve-db-updated-at-14d-v2')),
            result_contract_version INTEGER NOT NULL,
            CHECK((policy='legacy-db-freshness-v1' AND result_contract_version=1) OR
              (policy='cve-db-updated-at-14d-v2' AND result_contract_version=2))
          ); CREATE TABLE scan_cve_evidence (
            scan_id TEXT PRIMARY KEY REFERENCES scans(id), attempt INTEGER NOT NULL CHECK(attempt>0),
            evidence TEXT NOT NULL CHECK(length(CAST(evidence AS BLOB))<=8192)
          );`);
          const insert = this.db.prepare('INSERT INTO scan_cve_policy(scan_id,policy,result_contract_version) VALUES (?, ?, 1)');
          for (const row of this.db.prepare('SELECT id,checks FROM scans').all() as Array<{id: string; checks: string}>) {
            if (canonicalChecks(row.checks)?.includes('vuln')) insert.run(row.id, LEGACY_DB_POLICY);
          }
          this.db.pragma('user_version = 14');
        }
        if (version < 15) this.db.exec(`
          ALTER TABLE outbox ADD COLUMN lease_token TEXT;
          CREATE TABLE scan_checkpoints (
            scan_id TEXT NOT NULL REFERENCES scans(id), attempt INTEGER NOT NULL CHECK(attempt > 0),
            lease_token TEXT NOT NULL, check_name TEXT NOT NULL CHECK(check_name IN ('secret','sbom','vuln','config')),
            kind TEXT NOT NULL CHECK(kind IN ('combined','archive','config')),
            identity TEXT NOT NULL CHECK(length(CAST(identity AS BLOB)) <= 4096),
            body TEXT NOT NULL CHECK(length(CAST(body AS BLOB)) <= 2000000),
            evidence_hash TEXT NOT NULL, committed_at INTEGER NOT NULL,
            PRIMARY KEY(scan_id,attempt,lease_token,check_name)
          ); PRAGMA user_version = 15;
        `);
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
    if (row) this.cvePolicy(row.id);
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
        this.cvePolicy(existing.id);
        return { scanId: existing.id, created: false };
      }
      this.checkAdmission(target.subject);
      const scanId = randomUUID();
      this.db.prepare(`INSERT INTO scans (id, subject, idempotency_key, registry, repository, digest, platform, state, fingerprint, checks, scope)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)`).run(
        scanId, target.subject, target.idempotencyKey, target.registry, target.repository,
        target.digest, target.platform, target.fingerprint ?? null, target.checks ?? '[]', target.scope ?? 'image');
      if (canonicalChecks(target.checks ?? '')?.includes('vuln')) {
        const binding = validatePolicyBinding({ policy: target.cvePolicy ?? LEGACY_DB_POLICY,
          resultContractVersion: target.cvePolicy === CURRENT_DB_POLICY ? 2 : 1 });
        this.db.prepare('INSERT INTO scan_cve_policy(scan_id,policy,result_contract_version) VALUES (?,?,?)')
          .run(scanId, binding.policy, binding.resultContractVersion);
      } else if (target.cvePolicy !== undefined) throw new DbPolicyContractError();
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
      const cvePolicy = this.cvePolicy(row.scanId);
      const leaseToken = randomUUID();
      // The explicit archive budget also covers generic public images. Alpine's
      // earlier legacy lease timing is unchanged; this never starts a retry sooner.
      // A replacement claim never inherits the previous attempt's partial coverage.
      this.db.prepare('DELETE FROM scan_checkpoints WHERE scan_id=?').run(row.scanId);
      this.db.prepare('UPDATE outbox SET lease_until = ?, lease_token = ?, attempts = attempts + 1 WHERE scan_id = ?')
        .run(now + (row.scope === 'image' && row.repository !== 'library/alpine' && archiveLeaseMs ? Math.max(leaseMs, archiveLeaseMs) : leaseMs) +
                  (canonicalChecks(row.checks)?.includes('config') ? CONFIG_LOAD_MS + 1000 : 0), leaseToken, row.scanId);
      this.db.prepare("UPDATE scans SET state = 'running' WHERE id = ?").run(row.scanId);
      this.event(row.scanId, 'running');
      const executionProfile = this.executionProfile(row.scanId);
      return { ...row, attempts: row.attempts + 1, leaseToken, ...(executionProfile ? { executionProfile } : {}), ...(cvePolicy ? { cvePolicy } : {}) };
    });
  }

  /** True only for the exact immutable claim, before revocation or wall-clock expiry. */
  checkpointActive(job: Job): boolean {
    const context = this.configAttemptContext(job.scanId, job.attempts);
    return !!job.leaseToken && !!context && isDeepStrictEqual(context.job, job) && this.liveLease(job.scanId, job.attempts, job.leaseToken);
  }

  private liveLease(scanId: string, attempts: number, leaseToken: string | undefined): boolean {
    return this.liveAttemptTime(scanId, attempts, leaseToken) !== undefined;
  }

  private liveAttemptTime(scanId: string, attempts: number, leaseToken: string | undefined): number | undefined {
    if (typeof leaseToken !== 'string' || !leaseToken) return undefined;
    const row = this.db.prepare(`SELECT o.lease_until AS leaseUntil FROM outbox o JOIN scans s ON s.id=o.scan_id
      WHERE s.id=? AND s.state='running' AND o.attempts=? AND o.delivered_at IS NULL
      AND o.lease_token=? AND o.lease_until IS NOT NULL`).get(scanId, attempts, leaseToken) as { leaseUntil: number } | undefined;
    if (!row) return undefined;
    const now = this.clock();
    return row.leaseUntil > now ? now : undefined;
  }

  private publicConfigTarget(job: Pick<Job, 'registry' | 'repository' | 'digest' | 'platform' | 'scope'> & { executionProfile?: LocalExecutionBinding }): boolean {
    // Explicit OCI public composition, not a widening of the default legacy guard.
        return !job.executionProfile && validPublicTarget(job) && admittedConfigTarget(job, true);
  }

  private validateArchiveJob(job: Pick<Job, 'registry' | 'repository' | 'digest' | 'platform' | 'scope'>,
    report: ArchiveScanReport, binding: LocalExecutionBinding | undefined): void {
    const publicImage = isPublicReceipt(report.receipt);
    const target = publicImage ? report.receipt : NGINX_ARCHIVE_CANDIDATES.find(candidate => candidate.digest === report.receipt.digest);
    if (!target || job.scope !== 'image' ||
        ['registry', 'repository', 'digest', 'platform'].some(key => job[key as keyof typeof job] !== target[key as keyof typeof target]))
      throw new TypeError('Archive job mismatch');
    if (binding && (publicImage || !validLocalBinding(binding) ||
        !localReceiptMatches(report.receipt, report.scannerVersion))) throw new TypeError('Execution receipt mismatch');
  }

  /** Accept only complete sanitized adapter outcomes, never scanner stdout or fragments. */
  checkpointCombined(job: Job, outcome: CombinedOutcome): boolean {
    return this.checkpoint(job, outcome.check, 'combined', outcome);
  }

  checkpointConfig(job: Job, report: ImageConfigResult): boolean {
    return this.checkpoint(job, 'config', 'config', report);
  }

  /** The envelope contains exactly one completed check and its verified archive receipt. */
  checkpointArchive(job: Job, check: LegacyCheck, report: ArchiveScanReport): boolean {
    return this.checkpoint(job, check, 'archive', report);
  }

  private validateCheckpoint(job: Job, check: CheckName, kind: CheckpointRow['kind'], payload: unknown): void {
    const requested = canonicalChecks(job.checks);
    if (!requested?.includes(check) || job.scope !== 'image')
      throw new TypeError('Checkpoint job mismatch');
    const policy = this.cvePolicy(job.scanId) ?? LEGACY_DB_POLICY;
    if (kind === 'config') {
      if (check !== 'config' || !(admittedConfigTarget(job) || this.publicConfigTarget(job)))
        throw new TypeError('Checkpoint config target mismatch');
      validateConfigReport(payload, job, true);
    } else if (kind === 'combined') {
      const item = payload as CombinedOutcome;
      validateCombined([item], undefined, policy);
      const image = `${job.registry}/${job.repository}@${job.digest}`;
      if (item.check !== check || !admittedConfigTarget(job) || job.repository !== 'library/alpine' || job.platform !== 'linux/amd64' ||
          item.outcome === 'checked' && (item.check === 'sbom' && (item.sbom.image !== image || item.sbom.platform !== job.platform) ||
            item.check === 'vuln' && item.image !== image)) throw new TypeError('Checkpoint image mismatch');
    } else {
      const report = payload as ArchiveScanReport;
      const { requested: included } = validateStoredArchive(report, policy);
      if (included.length !== 1 || included[0] !== check ||
          ['registry', 'repository', 'digest', 'platform'].some(key => report.receipt[key as keyof typeof report.receipt] !== job[key as keyof Job]))
        throw new TypeError('Checkpoint archive mismatch');
      const binding = this.executionProfile(job.scanId);
      this.validateArchiveJob(job, report, binding);
      if (binding && (!validLocalBinding(binding) || !localChecksAllowed(requested.filter(c => c !== 'config')) ||
          !localReceiptMatches(report.receipt, report.scannerVersion))) throw new TypeError('Execution receipt mismatch');
    }
  }

  private checkpoint(job: Job, check: CheckName, kind: CheckpointRow['kind'], payload: unknown): boolean {
    return this.immediate(() => {
      const context = this.configAttemptContext(job.scanId, job.attempts);
      if (!job.leaseToken || !context || !isDeepStrictEqual(context.job, job)) return false;
      const committedAt = this.liveAttemptTime(job.scanId, job.attempts, job.leaseToken);
      if (committedAt === undefined) return false;
      this.validateCheckpoint(job, check, kind, payload);
      const policy = this.cvePolicy(job.scanId) ?? LEGACY_DB_POLICY;
      // Freeze the authoritative DB evaluation now, not at cancellation/read time.
      if (kind === 'combined') {
        const item = payload as CombinedOutcome;
        if (item.check === 'vuln' && item.outcome === 'checked' && policy === CURRENT_DB_POLICY) {
          try { payload = { ...item, dbEvidence: finalizeDbEvidence(item.dbEvidence!, committedAt) }; }
          catch (error) {
            if (!(error instanceof DbUsabilityError)) throw error;
            payload = { check: 'vuln', outcome: 'failed', errorCode: 'SCAN_UNAVAILABLE' };
          }
        }
      } else if (kind === 'archive') {
        const report = payload as ArchiveScanReport;
        if (report.checkedAt > committedAt) throw new TypeError('Future archive checkpoint');
        try {
          if (policy === CURRENT_DB_POLICY && report.vuln && report.vuln.outcome !== 'failed' && report.vuln.db) {
            const evidence = finalizeDbEvidence({ db: report.vuln.db, checkedAt: report.checkedAt, dbPolicy: report.vuln.dbPolicy! }, committedAt);
            payload = { ...report, vuln: { ...report.vuln, dbPolicy: evidence.dbPolicy } };
          } else assertArchiveDbFreshness(report, committedAt, policy);
        } catch (error) {
          if (!(error instanceof DbUsabilityError)) throw error;
          payload = { ...report, vuln: { outcome: 'failed', reason: 'DB_UNAVAILABLE' } };
        }
      }
      const rows = this.checkpointRows(job.scanId);
      // First complete result wins; even a valid second result cannot rewrite evidence.
      if (rows.some(row => row.check === check)) return false;
      if (kind === 'archive') {
        const reports = rows.filter(row => row.kind === 'archive').map(row => JSON.parse(row.body) as ArchiveScanReport);
        let part = payload as ArchiveScanReport;
        const size = () => Buffer.byteLength(JSON.stringify(this.mergeArchiveCheckpoints([...reports, part], false)));
        // Same optional-advisory omission rule as final reports. Reserve the complete
        // cancellation envelope without ever rewriting an earlier checkpoint.
        if (size() > 2_000_000 && part.vuln?.outcome === 'checked') {
          part = { ...part, vuln: { ...part.vuln, findings: part.vuln.findings.map(f => ({ ...f })) } };
          if (part.vuln?.outcome === 'checked') {
            for (const finding of [...part.vuln.findings].sort((a, b) => a.findingId < b.findingId ? 1 : -1)) {
              if (!finding.advisory) continue;
              finding.advisory = omittedAdvisory('report_budget');
              if (size() <= 2_000_000) break;
            }
          }
        }
        this.mergeArchiveCheckpoints([...reports, part]);
        payload = part;
      }
      this.validateCheckpoint(job, check, kind, payload);
      const identity = JSON.stringify({ subject: context.subject, job }), body = JSON.stringify(payload);
      if (Buffer.byteLength(identity) > 4096 || Buffer.byteLength(body) > (kind === 'config' ? 16384 : 2_000_000))
        throw new TypeError('Checkpoint size exceeded');
      const hash = createHash('sha256').update(JSON.stringify([identity, check, kind, committedAt, body])).digest('hex');
      this.db.prepare(`INSERT INTO scan_checkpoints(scan_id,attempt,lease_token,check_name,kind,identity,body,evidence_hash,committed_at)
        VALUES (?,?,?,?,?,?,?,?,?)`).run(job.scanId, job.attempts, job.leaseToken, check, kind, identity, body, hash, committedAt);
      return true;
    });
  }

  private checkpointRows(scanId: string): CheckpointRow[] {
    return this.db.prepare(`SELECT c.check_name AS 'check',c.kind,c.identity,c.body,c.evidence_hash AS hash,c.committed_at AS committedAt
      FROM scan_checkpoints c JOIN outbox o ON o.scan_id=c.scan_id
      WHERE c.scan_id=? AND c.attempt=o.attempts AND c.lease_token=o.lease_token AND o.lease_until IS NOT NULL
      AND o.delivered_at IS NULL ORDER BY c.check_name`).all(scanId) as CheckpointRow[];
  }

  private mergeArchiveCheckpoints(reports: ArchiveScanReport[], enforceSize = true): ArchiveScanReport {
    const report = { ...reports[0], metrics: { ...reports[0].metrics } };
    for (const part of reports.slice(1)) {
      if (!isDeepStrictEqual(report.receipt, part.receipt) || report.scannerVersion !== part.scannerVersion)
        throw new TypeError('Mixed archive checkpoint identity');
      for (const check of ['secret', 'sbom', 'vuln'] as const) if (part[check]) Object.assign(report, { [check]: part[check] });
      for (const key of Object.keys(report.metrics) as Array<keyof typeof report.metrics>)
        report.metrics[key] = Math.max(report.metrics[key], part.metrics[key]);
    }
    // The single archive completion timestamp must remain the CVE evidence timestamp.
    report.checkedAt = (reports.find(part => part.vuln) ?? reports[reports.length - 1]).checkedAt;
    if (enforceSize && Buffer.byteLength(JSON.stringify(report)) > 2_000_000) throw new TypeError('Checkpoint archive size exceeded');
    return report;
  }

  private validatedCheckpoint(scanId: string, row: CheckpointRow): { job: Job; payload: unknown } {
    if (Buffer.byteLength(row.identity) > 4096 || Buffer.byteLength(row.body) > 2_000_000 ||
        row.hash !== createHash('sha256').update(JSON.stringify([row.identity, row.check, row.kind, row.committedAt, row.body])).digest('hex'))
      throw new TypeError('Invalid stored checkpoint');
    const identity: { subject: string; job: Job } = JSON.parse(row.identity);
    const { job } = identity;
    // Expiry prevents NEW writes, but does not erase a previously committed checkpoint.
    // Retry clears the token and replacement claim deletes the old attempt's rows.
    const context = this.configAttemptContext(scanId, job.attempts);
    if (!context || !isDeepStrictEqual(context, identity)) throw new TypeError('Invalid stored checkpoint identity');
    const payload: unknown = JSON.parse(row.body);
    this.validateCheckpoint(job, row.check, row.kind, payload);
    return { job, payload };
  }

  private assertArchiveCheckpointConsistency(scanId: string, report: ArchiveScanReport, config: ImageConfigResult | undefined,
    policy: CveDbPolicy, evaluatedAt: number): void {
    for (const row of this.checkpointRows(scanId)) {
      const { payload } = this.validatedCheckpoint(scanId, row);
      if (row.kind === 'config') {
        if (!isDeepStrictEqual(payload, config)) throw new TypeError('Archive config checkpoint mismatch');
        continue;
      }
      if (row.kind !== 'archive') throw new TypeError('Archive checkpoint kind mismatch');
      const accepted = payload as ArchiveScanReport;
      if (!isDeepStrictEqual(accepted.receipt, report.receipt) || accepted.scannerVersion !== report.scannerVersion)
        throw new TypeError('Archive checkpoint receipt mismatch');
      const check = row.check as LegacyCheck;
      if (check !== 'vuln') {
        if (!isDeepStrictEqual(accepted[check], report[check])) throw new TypeError('Archive checkpoint outcome mismatch');
        continue;
      }
      const previous = accepted.vuln, final = report.vuln;
      // A failed label alone is not expiry evidence. Independently reevaluate the
      // accepted DB, never a replacement supplied by the returned report.
      if (policy === CURRENT_DB_POLICY && previous && previous.outcome !== 'failed' && previous.db &&
          final?.outcome === 'failed' && final.reason === 'DB_UNAVAILABLE') {
        try { finalizeDbEvidence({ db: previous.db, checkedAt: accepted.checkedAt, dbPolicy: previous.dbPolicy! }, evaluatedAt); }
        catch (error) {
          if (!(error instanceof DbUsabilityError)) throw error;
          continue;
        }
      }
      const comparable = (value: typeof previous) => {
        if (!value || policy !== CURRENT_DB_POLICY) return value;
        const { dbPolicy, ...data } = value;
        void dbPolicy; // The ledger deliberately reevaluates this receipt at each write fence.
        return data;
      };
      let comparedFinal = final;
      if (previous?.outcome === 'checked' && final?.outcome === 'checked') {
        const omitted = omittedAdvisory('report_budget');
        comparedFinal = { ...final, findings: final.findings.map((finding, index) => {
          const prior = previous.findings[index];
          // Checkpoint aggregation and final serialization may independently omit
          // optional metadata, but no other advisory or core finding may change.
          return prior?.advisory && finding.advisory &&
            (isDeepStrictEqual(prior.advisory, omitted) || isDeepStrictEqual(finding.advisory, omitted))
            ? { ...finding, advisory: prior.advisory } : finding;
        }) };
      }
      if (!isDeepStrictEqual(comparable(previous), comparable(comparedFinal))) throw new TypeError('Archive checkpoint outcome mismatch');
    }
  }

  private publishCheckpoints(scanId: string): void {
    const rows = this.checkpointRows(scanId);
    const archives: ArchiveScanReport[] = [];
    for (const row of rows) {
      const { job, payload } = this.validatedCheckpoint(scanId, row);
      if (row.kind === 'config') {
        this.saveConfig(scanId, job.attempts, payload as ImageConfigResult);
        this.db.prepare("UPDATE scan_check_results SET checked_at=? WHERE scan_id=? AND check_name='config'")
          .run(new Date(row.committedAt).toISOString(), scanId);
      } else if (row.kind === 'combined') this.saveCombined(scanId, job.attempts, [payload as CombinedOutcome], job.platform,
        this.cvePolicy(scanId) ?? LEGACY_DB_POLICY, row.committedAt);
      else archives.push(payload as ArchiveScanReport);
    }
    if (archives.length) {
      const report = this.mergeArchiveCheckpoints(archives);
      validateStoredArchive(report, this.cvePolicy(scanId) ?? LEGACY_DB_POLICY);
      this.db.prepare(`INSERT INTO scan_archive_results(scan_id,attempt,report)
        SELECT scan_id,attempts,? FROM outbox WHERE scan_id=?`).run(JSON.stringify(report), scanId);
    }
  }

  cancel(scanId: string, subject: string): 'cancelled' | 'already_cancelled' | 'conflict' | 'not_found' {
    return this.immediate(() => {
      const owner = this.db.prepare(`SELECT 1 FROM scans WHERE id=? AND subject=? AND state IN ('queued','running')`).get(scanId, subject);
      if (owner) this.publishCheckpoints(scanId);
      const changed = this.db.prepare(`UPDATE scans SET state = 'cancelled', terminal_at = CURRENT_TIMESTAMP
        WHERE id = ? AND subject = ? AND state IN ('queued','running')`).run(scanId, subject);
      if (changed.changes === 1) {
        this.db.prepare(`UPDATE outbox SET delivered_at = CURRENT_TIMESTAMP, lease_until = NULL, lease_token = NULL
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
  attemptActive(scanId: string, attempts: number, leaseToken: string | undefined): boolean {
    return this.liveLease(scanId, attempts, leaseToken);
  }

  configAttemptContext(scanId: string, attempts: number): { subject: string; job: Job } | undefined {
    const row = this.db.prepare(`SELECT s.subject,s.id AS scanId,s.registry,s.repository,s.digest,s.platform,s.checks,s.scope,o.attempts,o.lease_token AS leaseToken
      FROM scans s JOIN outbox o ON o.scan_id=s.id WHERE s.id=? AND s.state='running'
      AND o.attempts=? AND o.delivered_at IS NULL AND o.lease_until IS NOT NULL`)
      .get(scanId, attempts) as (Job & { subject: string }) | undefined;
    if (!row) return undefined;
    const { subject, ...job } = row;
    const cvePolicy = this.cvePolicy(scanId);
    const executionProfile = this.executionProfile(scanId);
        return { subject, job: { ...job, ...(executionProfile ? { executionProfile } : {}), ...(cvePolicy ? { cvePolicy } : {}) } };
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

  finish(scanId: string, attempts: number, state: 'failed', errorCode: FailureCode = 'SCAN_FAILED', leaseToken: string | undefined): boolean {
    return this.immediate(() => {
      this.cvePolicy(scanId);
      if (!this.liveLease(scanId, attempts, leaseToken)) return false;
      const result = this.db.prepare(`UPDATE outbox SET delivered_at = CURRENT_TIMESTAMP, lease_until = NULL, lease_token = NULL
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

  finishWithResult(scanId: string, attempts: number, findings: SecretFinding[], scannerVersion: string, leaseToken: string | undefined): boolean {
    if (!Array.isArray(findings) || findings.length > MAX_FINDINGS || scannerVersion !== '0.69.3' ||
      findings.some(f => !/^secret-\d+-\d+$/.test(f.findingId) || !/^[A-Za-z0-9._-]{1,80}$/.test(f.ruleId) ||
        !/^result-\d+-secret-\d+$/.test(f.evidenceRef) || f.line !== null && (!Number.isSafeInteger(f.line) || f.line < 0))) throw new TypeError('Invalid result');
    return this.immediate(() => {
      if (!this.liveLease(scanId, attempts, leaseToken)) return false;
      const delivered = this.db.prepare(`UPDATE outbox SET delivered_at = CURRENT_TIMESTAMP, lease_until = NULL, lease_token = NULL
        WHERE scan_id = ? AND attempts = ? AND delivered_at IS NULL
          AND EXISTS (SELECT 1 FROM scans WHERE id = ? AND state = 'running')`).run(scanId, attempts, scanId);
      if (!delivered.changes) return false;
      this.db.prepare(`INSERT INTO scan_results (scan_id, check_name, finding_count, coverage, outcome, scanner_version)
        VALUES (?, 'secret', ?, 'image', 'checked', ?)`).run(scanId, findings.length, scannerVersion);
      const insert = this.db.prepare('INSERT INTO scan_findings(scan_id,finding_id,rule_id,line,evidence_ref) VALUES (?,?,?,?,?)');
      for (const finding of findings) insert.run(scanId, finding.findingId, finding.ruleId, finding.line, finding.evidenceRef);
      const state = this.db.prepare(`UPDATE scans SET state = 'completed', terminal_at = CURRENT_TIMESTAMP
        WHERE id = ? AND state = 'running' AND checks = '["secret"]' AND scope = 'image'
                  AND registry = 'registry-1.docker.io' AND repository = 'library/alpine' AND platform = 'linux/amd64'`).run(scanId);
      if (state.changes !== 1) throw new Error('Scan result contract mismatch');
      this.event(scanId, 'completed');
      return true;
    });
  }

  finishWithSbom(scanId: string, attempts: number, sbom: ImageSbom, scannerVersion: string, leaseToken: string | undefined): boolean {
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
      if (!this.liveLease(scanId, attempts, leaseToken)) return false;
      const delivered = this.db.prepare(`UPDATE outbox SET delivered_at = CURRENT_TIMESTAMP, lease_until = NULL, lease_token = NULL
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

  // Archive-only normalized output; a public receipt never grants an nginx execution profile.
  finishArchive(scanId: string, attempts: number, report: ArchiveScanReport, config: ImageConfigResult | undefined, leaseToken: string | undefined): boolean {
    const context = config ? this.configAttemptContext(scanId, attempts) : undefined;
    if (config && !context) return false;
    const safeConfig = config ? validateConfigReport(config, context!.job, canonicalChecks(context!.job.checks)?.includes('config') === true) : undefined;
    const policy = this.cvePolicy(scanId) ?? LEGACY_DB_POLICY;
    const { requested, checked } = validateStoredArchive(report, policy);
    // Optional report metadata is dropped deterministically before the fenced transaction.
    const precommitLimit = policy === CURRENT_DB_POLICY ? 1_999_488 : 2_000_000;
    let body = JSON.stringify(report);
    if (Buffer.byteLength(body) > precommitLimit && report.vuln?.outcome === 'checked') {
      report = { ...report, vuln: { ...report.vuln, findings: report.vuln.findings.map(f => ({ ...f })) } };
      if (report.vuln?.outcome === 'checked') {
        for (const finding of [...report.vuln.findings].sort((a, b) => a.findingId < b.findingId ? 1 : -1)) {
          if (!finding.advisory) continue;
          finding.advisory = omittedAdvisory('report_budget');
          body = JSON.stringify(report);
          if (Buffer.byteLength(body) <= precommitLimit) break;
        }
      }
    }
    if (Buffer.byteLength(body) > precommitLimit) throw new TypeError('Invalid archive result size');
    return this.immediate(() => {
      const evaluatedAt = this.liveAttemptTime(scanId, attempts, leaseToken);
      if (evaluatedAt === undefined) return false;
      const row = this.db.prepare(`SELECT s.subject,s.registry,s.repository,s.digest,s.platform,s.checks,s.scope
        FROM scans s JOIN outbox o ON o.scan_id=s.id WHERE s.id=? AND s.state='running'
        AND o.attempts=? AND o.delivered_at IS NULL AND o.lease_until IS NOT NULL`).get(scanId, attempts) as Job | undefined;
      if (!row) return false;
      const binding = this.executionProfile(scanId);
      this.validateArchiveJob(row, report, binding);
      if (JSON.stringify(canonicalChecks(row.checks)?.filter(check => check !== 'config')) !== JSON.stringify(requested) ||
          canonicalChecks(row.checks)?.includes('config') && !safeConfig ||
          safeConfig && !isDeepStrictEqual(context, this.configAttemptContext(scanId, attempts))) throw new TypeError('Archive job mismatch');
      if (binding && (!validLocalBinding(binding) || !localChecksAllowed(requested) || !localReceiptMatches(report.receipt, report.scannerVersion)))
        throw new TypeError('Execution receipt mismatch');
      if (this.cvePolicy(scanId) !== (requested.includes('vuln') ? policy : undefined)) throw new DbPolicyContractError();
      // Use the one clock capture from the current attempt/lease fence.
      if (policy === CURRENT_DB_POLICY && report.vuln && report.vuln.outcome !== 'failed' && report.vuln.db) {
        try {
          const evidence = finalizeDbEvidence({ db: report.vuln.db, checkedAt: report.checkedAt, dbPolicy: report.vuln.dbPolicy! }, evaluatedAt);
          report = { ...report, vuln: { ...report.vuln, dbPolicy: evidence.dbPolicy } };
        } catch (error) {
          if (!(error instanceof DbUsabilityError)) throw error;
          report = { ...report, vuln: { outcome: 'failed', reason: 'DB_UNAVAILABLE' } };
        }
      } else assertArchiveDbFreshness(report, evaluatedAt, policy);
      this.assertArchiveCheckpointConsistency(scanId, report, safeConfig, policy, evaluatedAt);
      const checkedCount = checked.length - (checked.some(item => item.check === 'vuln') && report.vuln?.outcome === 'failed' ? 1 : 0);
      body = JSON.stringify(report);
      if (Buffer.byteLength(body) > 2_000_000) throw new TypeError('Invalid archive result size');
      const changed = this.db.prepare(`UPDATE outbox SET delivered_at=CURRENT_TIMESTAMP,lease_until=NULL,lease_token=NULL
        WHERE scan_id=? AND attempts=? AND delivered_at IS NULL`).run(scanId, attempts);
      if (changed.changes !== 1) throw new Error('Archive attempt mismatch');
      this.db.prepare('INSERT INTO scan_archive_results(scan_id,attempt,report) VALUES (?,?,?)').run(scanId, attempts, body);
      if (safeConfig) this.saveConfig(scanId, attempts, safeConfig);
      const selectedConfig = canonicalChecks(row.checks)?.includes('config') === true;
      const count = checkedCount + (selectedConfig && safeConfig?.config.outcome === 'checked' ? 1 : 0);
      const terminal = count === requested.length + (selectedConfig ? 1 : 0) ? 'completed' : count ? 'partial' : 'failed';
      this.db.prepare(`UPDATE scans SET state=?,terminal_at=CURRENT_TIMESTAMP WHERE id=? AND state='running'`).run(terminal, scanId);
      this.event(scanId, terminal);
      return true;
    });
  }

  // Required independent authority: payload absence never identifies a legacy scan.
  cvePolicy(scanId: string): CveDbPolicy | undefined {
    const scan = this.db.prepare('SELECT checks FROM scans WHERE id=?').get(scanId) as { checks: string } | undefined;
    if (!scan) throw new DbPolicyContractError();
    const row = this.db.prepare('SELECT policy,result_contract_version AS resultContractVersion FROM scan_cve_policy WHERE scan_id=?')
      .get(scanId);
    if (!canonicalChecks(scan.checks)?.includes('vuln')) {
      if (row) throw new DbPolicyContractError();
      return undefined;
    }
    return validatePolicyBinding(row).policy;
  }

  executionProfile(scanId: string): LocalExecutionBinding | undefined {
    const row = this.db.prepare('SELECT binding FROM scan_execution_profiles WHERE scan_id=?').get(scanId) as { binding: string } | undefined;
    if (!row) return undefined;
    const value: unknown = JSON.parse(row.binding);
    if (!validLocalBinding(value)) throw new TypeError('Invalid stored execution binding');
    return value;
  }

  archiveResult(scanId: string, subject: string): ArchiveScanReport | undefined {
    if (!this.snapshot(scanId, subject)) return undefined;
    const row = this.db.prepare(`SELECT r.report, s.registry, s.repository, s.digest, s.platform, s.checks, s.scope, s.state FROM scan_archive_results r JOIN scans s ON s.id=r.scan_id
      WHERE s.id=? AND s.subject=?`).get(scanId, subject) as { report: string; registry: string; repository: string; digest: string; platform: string; checks: string; scope: string; state: string } | undefined;
    if (!row) return undefined;
    if (Buffer.byteLength(row.report) > 2_000_000) throw new TypeError('Invalid stored archive size');
    const report: ArchiveScanReport = JSON.parse(row.report);
    const { requested } = validateStoredArchive(report, this.cvePolicy(scanId) ?? LEGACY_DB_POLICY);
    const binding = this.executionProfile(scanId);
    this.validateArchiveJob(row, report, binding);
    if (binding && !localChecksAllowed(canonicalChecks(row.checks)?.filter(check => check !== 'config') ?? []))
          throw new TypeError('Execution receipt mismatch');
    if (['registry', 'repository', 'digest', 'platform'].some(key => report.receipt[key as keyof typeof report.receipt] !== row[key as 'registry' | 'repository' | 'digest' | 'platform']) ||
        (row.state === 'cancelled'
          ? requested.length === 0 || requested.some(check => !canonicalChecks(row.checks)?.includes(check as CheckName))
          : JSON.stringify(requested) !== JSON.stringify(canonicalChecks(row.checks)?.filter(check => check !== 'config'))))
      throw new TypeError('Invalid stored archive binding');
    return report;
  }

  finishCombined(scanId: string, attempts: number, outcomes: CombinedOutcome[], config: ImageConfigResult | undefined, leaseToken: string | undefined): boolean {
    const policy = this.cvePolicy(scanId) ?? LEGACY_DB_POLICY;
    if (outcomes.length || !config) validateCombined(outcomes, undefined, policy);
    for (const item of outcomes) {
      if (item.check === 'vuln' && item.outcome === 'checked' && item.dbEvidence &&
          Buffer.byteLength(JSON.stringify(item.dbEvidence)) > 7680) throw new DbPolicyContractError();
    }
    const context = config ? this.configAttemptContext(scanId, attempts) : undefined;
    if (config && !context) return false;
    const safeConfig = config ? validateConfigReport(config, context!.job, canonicalChecks(context!.job.checks)?.includes('config') === true) : undefined;
    return this.immediate(() => {
      const evaluatedAt = this.liveAttemptTime(scanId, attempts, leaseToken);
      if (evaluatedAt === undefined) return false;
      const row = this.db.prepare(`SELECT s.registry,s.repository,s.digest,s.platform,s.checks,s.scope
        FROM scans s JOIN outbox o ON o.scan_id = s.id
        WHERE s.id = ? AND s.state = 'running' AND o.attempts = ? AND o.delivered_at IS NULL
          ${safeConfig ? 'AND o.lease_until IS NOT NULL' : ''}`)
        .get(scanId, attempts) as { registry: string; repository: string; digest: string;
          platform: string; checks: string; scope: string } | undefined;
      if (!row) return false;
      const requested = canonicalChecks(row.checks);
      if (!requested || row.scope !== 'image' || row.platform !== 'linux/amd64' ||
          !(admittedConfigTarget(row) || safeConfig && this.publicConfigTarget({ ...row, executionProfile: this.executionProfile(scanId) })) ||
          (row.repository !== 'library/alpine' && outcomes.some(item => item.outcome === 'checked')) ||
          !/^sha256:[a-f0-9]{64}$/.test(row.digest) ||
          JSON.stringify(outcomes.map(item => item.check)) !== JSON.stringify(requested.filter(check => check !== 'config')) ||
          requested.includes('config') && !safeConfig || safeConfig && !isDeepStrictEqual(context, this.configAttemptContext(scanId, attempts)))
        throw new Error('Scan combined contract mismatch');
      if (this.cvePolicy(scanId) !== (requested.includes('vuln') ? policy : undefined)) throw new DbPolicyContractError();
      outcomes = outcomes.map(item => {
        if (policy !== CURRENT_DB_POLICY || item.check !== 'vuln' || item.outcome !== 'checked') return item;
        try { return { ...item, dbEvidence: finalizeDbEvidence(item.dbEvidence!, evaluatedAt) }; }
        catch (error) {
          if (!(error instanceof DbUsabilityError)) throw error;
          return { check: 'vuln', outcome: 'failed', errorCode: 'SCAN_UNAVAILABLE' };
        }
      });
      const image = `${row.registry}/${row.repository}@${row.digest}`;
      for (const item of outcomes) {
        if (item.outcome === 'checked' && item.check === 'sbom' &&
            (item.sbom.image !== image || item.sbom.platform !== row.platform) ||
            item.outcome === 'checked' && item.check === 'vuln' && item.image !== image)
          throw new Error('Scan combined image mismatch');
      }
      const delivered = this.db.prepare(`UPDATE outbox SET delivered_at = CURRENT_TIMESTAMP, lease_until = NULL, lease_token = NULL
        WHERE scan_id = ? AND attempts = ? AND delivered_at IS NULL
          AND EXISTS (SELECT 1 FROM scans WHERE id = ? AND state = 'running')`).run(scanId, attempts, scanId);
      if (delivered.changes !== 1) throw new Error('Scan combined attempt mismatch');
      this.saveCombined(scanId, attempts, outcomes, row.platform, policy);
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

  private saveCombined(scanId: string, attempts: number, outcomes: CombinedOutcome[], platform: string,
    policy: CveDbPolicy, checkedAt?: number): void {
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
              item.image, platform, item.findings.length, item.scannerVersion);
          if (policy === CURRENT_DB_POLICY) {
            const evidence = item.dbEvidence!;
            const serialized = JSON.stringify(evidence);
            if (Buffer.byteLength(serialized) > 8192) throw new DbPolicyContractError();
            this.db.prepare('INSERT INTO scan_cve_evidence(scan_id,attempt,evidence) VALUES (?,?,?)').run(scanId, attempts, serialized);
            this.db.prepare('UPDATE scan_vuln_results SET checked_at=? WHERE scan_id=?').run(new Date(evidence.checkedAt).toISOString(), scanId);
          }
          const insert = this.db.prepare(`INSERT INTO scan_vuln_findings
            (scan_id,ordinal,finding_id,cve_id,ecosystem,package_name,installed_version,severity,severity_sources,provenance_ref,fixed_version,advisory)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`);
          item.findings.forEach((f, ordinal) => insert.run(scanId, ordinal, f.findingId, f.cveId,
            f.ecosystem, f.packageName, f.installedVersion, f.severity, JSON.stringify(f.severitySources),
            f.provenanceRef, f.fixedVersion, f.advisory == null ? null : JSON.stringify(f.advisory)));
        }
      }
      if (checkedAt !== undefined) for (const item of outcomes) {
        if (item.outcome !== 'checked') continue;
        const date = new Date(checkedAt).toISOString();
        if (item.check === 'secret') this.db.prepare('UPDATE scan_results SET created_at=? WHERE scan_id=?').run(date, scanId);
        if (item.check === 'sbom') this.db.prepare('UPDATE scan_sbom_results SET checked_at=? WHERE scan_id=?').run(date, scanId);
        if (item.check === 'vuln' && policy !== CURRENT_DB_POLICY)
          this.db.prepare('UPDATE scan_vuln_results SET checked_at=? WHERE scan_id=?').run(date, scanId);
      }
  }

  // The image is supplied by the pinned worker job, not reconstructed from untrusted findings.
  finishWithVuln(scanId: string, attempts: number, image: string, findings: VulnFinding[], scannerVersion: string, leaseToken: string | undefined): boolean {
    if (this.cvePolicy(scanId) !== LEGACY_DB_POLICY) throw new DbPolicyContractError();
    if (scannerVersion !== '0.69.3') throw new TypeError('Invalid vulnerability result');
    validateCombined([{ check: 'vuln', outcome: 'checked', image, findings, scannerVersion }]);
    return this.immediate(() => {
      if (this.cvePolicy(scanId) !== LEGACY_DB_POLICY) throw new DbPolicyContractError();
      if (!this.liveLease(scanId, attempts, leaseToken)) return false;
      const delivered = this.db.prepare(`UPDATE outbox SET delivered_at = CURRENT_TIMESTAMP, lease_until = NULL, lease_token = NULL
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
    scannerVersion: string; checkedAt: string; findings: VulnFinding[]; nextCursor: number | null; dbEvidence?: CveDbEvidence;
  } | { coverage: 'image'; outcome: 'failed'; errorCode: 'SCAN_FAILED' | 'SCAN_TIMEOUT' | 'SCAN_UNAVAILABLE';
    findings: []; nextCursor: null }) | undefined {
    if (!Number.isSafeInteger(cursor) || cursor < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      throw new TypeError('Invalid pagination');
    const dataset = this.vulnDataset(scanId, subject);
    if (!dataset) return undefined;
    if (dataset.outcome === 'failed') return { ...dataset, nextCursor: null };
    const findings = dataset.findings.slice(cursor, cursor + limit);
    return { ...dataset, findings,
      nextCursor: cursor + findings.length < dataset.findingCount ? cursor + findings.length : null };
  }

  // DEFERRED read snapshots never acquire an IMMEDIATE writer transaction.
  readReportSnapshot<T>(read: () => T): T { return this.db.transaction(read).deferred(); }

  vulnDataset(scanId: string, subject: string): VulnDataset | undefined {
    return this.readReportSnapshot(() => this.loadVulnDataset(scanId, subject));
  }

  private loadVulnDataset(scanId: string, subject: string): VulnDataset | undefined {
    if (!this.snapshot(scanId, subject)) return undefined;
    const row = this.db.prepare(`SELECT r.image,r.platform,r.finding_count AS findingCount,
      r.outcome, r.scanner_version AS scannerVersion, r.checked_at AS checkedAt, r.error_code AS errorCode
      FROM scan_vuln_results r JOIN scans s ON s.id = r.scan_id WHERE s.id = ? AND s.subject = ?`)
      .get(scanId, subject) as { image: string | null; platform: 'linux/amd64' | null;
        findingCount: number | null; coverage: 'image'; outcome: 'checked' | 'failed';
        scannerVersion: string | null; checkedAt: string | null;
        errorCode: 'SCAN_FAILED' | 'SCAN_TIMEOUT' | 'SCAN_UNAVAILABLE' | null } | undefined;
    if (!row) return undefined;
    const policy = this.cvePolicy(scanId);
    if (row.outcome === 'failed') return { coverage: 'image', outcome: 'failed', errorCode: row.errorCode!, findings: [] };
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
    // A legacy marker cannot erase surviving v2 evidence, even if its attempt link is corrupt.
        if (policy === LEGACY_DB_POLICY && this.db.prepare('SELECT 1 FROM scan_cve_evidence WHERE scan_id=?').get(scanId))
          throw new DbPolicyContractError();
        const dbEvidence = policy === CURRENT_DB_POLICY ? this.standaloneDbEvidence(scanId) : undefined;
    if (dbEvidence && row.checkedAt !== new Date(dbEvidence.checkedAt).toISOString()) throw new DbPolicyContractError();
    validateCombined([{ check: 'vuln', outcome: 'checked', image: row.image!, scannerVersion: row.scannerVersion, findings: all,
      ...(dbEvidence ? { dbEvidence } : {}) }], undefined, policy);
    return { image: row.image!, platform: row.platform, findingCount: row.findingCount, coverage: 'image',
      outcome: 'checked', scannerVersion: row.scannerVersion, checkedAt: row.checkedAt!, findings: all,
      ...(dbEvidence ? { dbEvidence } : {}) };
  }

  private standaloneDbEvidence(scanId: string): CveDbEvidence {
    const row = this.db.prepare(`SELECT e.evidence FROM scan_cve_evidence e JOIN outbox o ON o.scan_id=e.scan_id
          WHERE e.scan_id=? AND e.attempt=o.attempts AND o.delivered_at IS NOT NULL`).get(scanId) as { evidence: string } | undefined;
    if (!row || Buffer.byteLength(row.evidence) > 8192) throw new DbPolicyContractError();
    const evidence: unknown = JSON.parse(row.evidence);
    validateDbEvidence(evidence, CURRENT_DB_POLICY);
    return evidence;
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

  sbomDataset(scanId: string, subject: string): ReturnType<ScanLedger['sbom']> {
    return this.readReportSnapshot(() => {
      const report = this.sbom(scanId, subject, 0, 1);
      if (!report || report.outcome !== 'checked') return report;
      const components = this.db.prepare(`SELECT ecosystem,name,version FROM scan_sbom_components
        WHERE scan_id = ? ORDER BY ordinal LIMIT 1001`).all(scanId) as SbomComponent[];
      if (components.length !== report.componentCount || report.coverage !== 'image' || report.scannerVersion !== '0.69.3')
        throw new TypeError('Invalid stored SBOM result');
      validateCombined([{ check: 'sbom', outcome: 'checked', scannerVersion: report.scannerVersion,
        sbom: { image: report.image, platform: report.platform, os: report.os, components } }]);
      return { ...report, components, nextCursor: null };
    });
  }

  secretDataset(scanId: string, subject: string): {
    findings: SecretFinding[]; coverage: NonNullable<ReturnType<ScanLedger['result']>>;
  } | undefined {
    return this.readReportSnapshot(() => {
      const coverage = this.result(scanId, subject);
      if (!coverage) return undefined;
      if (coverage.outcome !== 'checked') return { findings: [], coverage };
      const findings = this.db.prepare(`SELECT finding_id AS findingId, rule_id AS ruleId, line, evidence_ref AS evidenceRef
        FROM scan_findings WHERE scan_id = ? ORDER BY finding_id LIMIT 1001`).all(scanId) as SecretFinding[];
      if (findings.length !== coverage.findingCount || coverage.check !== 'secret' || coverage.coverage !== 'image' ||
          coverage.scannerVersion !== '0.69.3' || coverage.errorCode !== null)
        throw new TypeError('Invalid stored secret result');
      validateCombined([{ check: 'secret', outcome: 'checked', scannerVersion: coverage.scannerVersion, findings }]);
      return { findings, coverage };
    });
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

  retry(scanId: string, attempts: number, nextRunAt: number, leaseToken: string | undefined): boolean {
    return this.immediate(() => {
      if (!this.liveLease(scanId, attempts, leaseToken)) return false;
      const result = this.db.prepare(`UPDATE outbox SET lease_until = NULL, lease_token = NULL, next_run_at = ?
        WHERE scan_id = ? AND attempts = ? AND delivered_at IS NULL
          AND EXISTS (SELECT 1 FROM scans WHERE id = ? AND state = 'running')`).run(nextRunAt, scanId, attempts, scanId);
      if (result.changes === 1) this.db.prepare('DELETE FROM scan_checkpoints WHERE scan_id=?').run(scanId);
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
    if (row) this.cvePolicy(scanId);
    return row ? canonicalChecks(row.checks) ?? [] : [];
  }

  /** Direct pinned identity lookup; ownership is part of the query, including queued/config-only scans. */
  pinnedTarget(scanId: string, subject: string): Pick<Job, 'registry' | 'repository' | 'digest' | 'platform'> | undefined {
    return this.db.prepare('SELECT registry,repository,digest,platform FROM scans WHERE id=? AND subject=?')
      .get(scanId, subject) as ReturnType<ScanLedger['pinnedTarget']>;
  }

  snapshot(scanId: string, subject: string): { state: string; digest: string; platform: string } | undefined {
    const [row] = this.orm.select({ state: scans.state, digest: scans.digest, platform: scans.platform }).from(scans)
      .where(and(eq(scans.id, scanId), eq(scans.subject, subject))).all();
    if (row) this.cvePolicy(scanId);
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
    for (const row of rows.slice(0, limit)) this.cvePolicy(row.scanId);
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
      for (const table of ['scan_checkpoints', 'scan_cve_evidence', 'scan_cve_policy', 'scan_execution_profiles', 'scan_check_results', 'scan_archive_results', 'scan_findings', 'scan_sbom_components', 'scan_sbom_results', 'scan_vuln_findings', 'scan_vuln_results', 'scan_events']) this.db.prepare(`DELETE FROM ${table} WHERE scan_id IN (SELECT id FROM scans WHERE terminal_at < datetime('now', ?))`).run(`-${days} days`);
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
