import Database from 'better-sqlite3';
import { randomUUID } from 'node:crypto';
import { and, eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { scans } from './schema.js';
import { MAX_FINDINGS, type SecretFinding } from '../worker/secret-findings.js';

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
};
export type Job = { scanId: string; registry: string; repository: string; digest: string; platform: string; checks: string; scope: string; attempts: number };
export class IdempotencyConflict extends Error {}
export class AdmissionLimited extends Error {}
const SUBJECT_ACTIVE_LIMIT = 3;
const GLOBAL_ACTIVE_LIMIT = 30;
const SUBJECT_MINUTE_LIMIT = 6;

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
      if (version > 6 || version < 0) throw new Error('Unsupported ledger version');
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
      });
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

  claim(now = Date.now(), leaseMs = 60_000): Job | undefined {
    return this.immediate(() => {
      const row = this.db.prepare(`SELECT s.id AS scanId, s.registry, s.repository, s.digest, s.platform, s.checks, s.scope, o.attempts
        FROM outbox o JOIN scans s ON s.id = o.scan_id
        WHERE s.state IN ('queued','running') AND o.delivered_at IS NULL
          AND o.next_run_at <= ? AND (o.lease_until IS NULL OR o.lease_until <= ?)
        ORDER BY s.created_at, s.id LIMIT 1`).get(now, now) as ClaimRow | undefined;
      if (!row) return undefined;
      this.db.prepare('UPDATE outbox SET lease_until = ?, attempts = attempts + 1 WHERE scan_id = ?')
        .run(now + leaseMs, row.scanId);
      this.db.prepare("UPDATE scans SET state = 'running' WHERE id = ?").run(row.scanId);
      this.event(row.scanId, 'running');
      return { ...row, attempts: row.attempts + 1 };
    });
  }

  finish(scanId: string, attempts: number, state: 'failed', errorCode: 'SCAN_FAILED' | 'SCAN_TIMEOUT' | 'SCAN_UNAVAILABLE' = 'SCAN_FAILED'): boolean {
    return this.immediate(() => {
      const result = this.db.prepare(`UPDATE outbox SET delivered_at = CURRENT_TIMESTAMP, lease_until = NULL
        WHERE scan_id = ? AND attempts = ? AND delivered_at IS NULL`).run(scanId, attempts);
      if (result.changes) {
        const stateChange = this.db.prepare("UPDATE scans SET state = ?, terminal_at = CURRENT_TIMESTAMP WHERE id = ? AND state = 'running'").run(state, scanId);
        if (stateChange.changes !== 1) throw new Error('Scan failure contract mismatch');
        this.saveFailure(scanId, errorCode);
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
        WHERE scan_id = ? AND attempts = ? AND delivered_at IS NULL`).run(scanId, attempts);
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

  result(scanId: string, subject: string): { findingCount: number; check: string; coverage: string; outcome: string; errorCode: string | null; scannerVersion: string | null } | undefined {
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
      VALUES (?,'secret',0,'image','failed',?)`).run(scanId, code);
  }

  events(scanId: string, subject: string, after: number | null): Array<{ id: number; state: string }> | undefined {
    if (!this.state(scanId, subject)) return undefined;
    if (after !== null && (!Number.isSafeInteger(after) || after < 0)) throw new TypeError('Invalid event ID');
    const rows = this.db.prepare(`SELECT seq AS id,state FROM scan_events WHERE scan_id = ? AND seq > ? ORDER BY seq LIMIT 100`)
      .all(scanId, after ?? 0) as Array<{ id: number; state: string }>;
    if (rows.length || after === null) return rows;
    // A one-shot snapshot on reconnect is intentional; never reuse state as event ID.
    return this.db.prepare(`SELECT seq AS id,state FROM scan_events WHERE scan_id = ? ORDER BY seq DESC LIMIT 1`)
      .all(scanId) as Array<{ id: number; state: string }>;
  }

  retry(scanId: string, attempts: number, nextRunAt: number): boolean {
    const result = this.db.prepare(`UPDATE outbox SET lease_until = NULL, next_run_at = ?
      WHERE scan_id = ? AND attempts = ? AND delivered_at IS NULL`).run(nextRunAt, scanId, attempts);
    return result.changes === 1;
  }

  state(scanId: string, subject: string): string | undefined {
    const [row] = this.orm.select({ state: scans.state }).from(scans)
      .where(and(eq(scans.id, scanId), eq(scans.subject, subject))).all();
    return row?.state;
  }

  prune(days = 30): number {
    if (!Number.isInteger(days) || days < 1) throw new TypeError('Invalid retention');
    return this.immediate(() => {
      this.db.prepare('DELETE FROM admission_windows WHERE minute < ?').run(Math.floor(Date.now() / 60000) - 1440);
      this.db.prepare(`DELETE FROM scan_audit WHERE created_at < datetime('now', ?)`).run(`-${days} days`);
      for (const table of ['scan_findings', 'scan_events']) this.db.prepare(`DELETE FROM ${table} WHERE scan_id IN (SELECT id FROM scans WHERE terminal_at < datetime('now', ?))`).run(`-${days} days`);
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
