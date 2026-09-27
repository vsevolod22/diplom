import Database from 'better-sqlite3';
import { randomUUID } from 'node:crypto';
import { and, eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { scans } from './schema.js';

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
      if (version > 2 || version < 0) throw new Error('Unsupported ledger version');
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

  enqueue(target: PinnedTarget): { scanId: string; created: boolean } {
    if (!target.subject || !target.idempotencyKey || !target.registry || !target.repository ||
        !/^sha256:[a-f0-9]{64}$/.test(target.digest) ||
        !/^linux\/[a-z0-9]+(?:\/[a-z0-9]+)?$/.test(target.platform) ||
        (target.fingerprint !== undefined && !/^[a-f0-9]{64}$/.test(target.fingerprint))) throw new TypeError('Invalid pinned target');
    return this.immediate(() => {
      const existing = this.db.prepare('SELECT * FROM scans WHERE subject = ? AND idempotency_key = ?')
        .get(target.subject, target.idempotencyKey) as ScanRow | undefined;
      if (existing) {
        if (existing.registry !== target.registry || existing.repository !== target.repository ||
            existing.digest !== target.digest || existing.platform !== target.platform ||
            (target.fingerprint !== undefined && existing.fingerprint !== target.fingerprint)) {
          throw new IdempotencyConflict('Idempotency key used for another request');
        }
        return { scanId: existing.id, created: false };
      }
      const scanId = randomUUID();
      this.db.prepare(`INSERT INTO scans (id, subject, idempotency_key, registry, repository, digest, platform, state, fingerprint, checks, scope)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)`).run(
        scanId, target.subject, target.idempotencyKey, target.registry, target.repository,
        target.digest, target.platform, target.fingerprint ?? null, target.checks ?? '[]', target.scope ?? 'image');
      this.db.prepare('INSERT INTO outbox (scan_id) VALUES (?)').run(scanId);
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
      return { ...row, attempts: row.attempts + 1 };
    });
  }

  finish(scanId: string, attempts: number, state: 'completed' | 'failed'): boolean {
    return this.immediate(() => {
      const result = this.db.prepare(`UPDATE outbox SET delivered_at = CURRENT_TIMESTAMP, lease_until = NULL
        WHERE scan_id = ? AND attempts = ? AND delivered_at IS NULL`).run(scanId, attempts);
      if (result.changes) this.db.prepare("UPDATE scans SET state = ?, terminal_at = CURRENT_TIMESTAMP WHERE id = ? AND state = 'running'").run(state, scanId);
      return result.changes === 1;
    });
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
      this.db.prepare(`DELETE FROM outbox WHERE scan_id IN (SELECT id FROM scans WHERE terminal_at < datetime('now', ?))`)
        .run(`-${days} days`);
      const result = this.db.prepare(`DELETE FROM scans WHERE terminal_at < datetime('now', ?)`).run(`-${days} days`);
      return result.changes;
    });
  }

  close(): void { this.db.close(); }
}
