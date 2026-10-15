import { createHash, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { Injectable, OnModuleDestroy, ServiceUnavailableException } from '@nestjs/common';
import Database from 'better-sqlite3';

export type User = { id: string; email: string };
// Server-only authority, never serialized in User/API responses.
export type SessionSnapshot = Readonly<{ subject: string; sessionId: string; generation: number; expiresAt: number; accessIncarnation: string }>;
export function browserAccessFingerprint(): string {
  return digest(JSON.stringify(['AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP', 'SCAN_BROWSER_ALLOWED_USER_IDS',
    'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'].map(key => process.env[key] ?? null)));
}
const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
const WINDOW_MS = 15 * 60 * 1000;
const DUMMY_SALT = Buffer.alloc(16, 0).toString('hex');
const DUMMY_HASH = Buffer.alloc(64);
const digest = (token: string): string => createHash('sha256').update(token).digest('hex');
const hashPassword = (password: string, salt: string): Promise<Buffer> =>
  new Promise((resolve, reject) => scrypt(password, salt, 64, (error, key) => error ? reject(error) : resolve(key)));
const canonicalPath = (path: string): string => {
  try { return realpathSync(path); } catch { return resolve(path); }
};

@Injectable()
export class AuthStore implements OnModuleDestroy {
  private readonly db?: Database.Database;
  private readonly snapshots = new WeakMap<SessionSnapshot, string>();
  private readonly accessFingerprint = browserAccessFingerprint();

  constructor() {
    const path = process.env.AUTH_DB_PATH;
    if (!path || path === ':memory:' || path.startsWith('file:') ||
      (process.env.SCAN_LEDGER_PATH && canonicalPath(path) === canonicalPath(process.env.SCAN_LEDGER_PATH))) return;
    try {
      this.db = new Database(path);
      this.db.pragma('journal_mode = WAL');
      this.db.pragma('foreign_keys = ON');
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, salt TEXT NOT NULL, password_hash BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
          expires_at INTEGER NOT NULL, revoked_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id, expires_at);
        CREATE TABLE IF NOT EXISTS auth_attempts (
          bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL
        );
      `);
      this.db.transaction(() => {
        this.db!.exec(`CREATE TABLE IF NOT EXISTS trusted_sessions (
          token_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,
          session_id TEXT NOT NULL UNIQUE, generation INTEGER NOT NULL CHECK(generation>0)
        );
        CREATE TABLE IF NOT EXISTS browser_access (
          id INTEGER PRIMARY KEY CHECK(id=1), fingerprint TEXT NOT NULL, incarnation TEXT NOT NULL
        );
        INSERT OR IGNORE INTO trusted_sessions SELECT token_hash,lower(hex(randomblob(16))),1 FROM sessions;`);
        const previous = this.db!.prepare('SELECT fingerprint FROM browser_access WHERE id=1').get() as { fingerprint: string } | undefined;
        if (previous?.fingerprint !== this.accessFingerprint) this.db!.prepare(`INSERT INTO browser_access VALUES(1,?,?)
          ON CONFLICT(id) DO UPDATE SET fingerprint=excluded.fingerprint,incarnation=excluded.incarnation`)
          .run(this.accessFingerprint, randomBytes(16).toString('hex'));
      }).immediate();
    } catch {
      this.db?.close();
      // An unavailable configured volume must not fall back to ephemeral credentials.
    }
  }

  private database(): Database.Database {
    if (!this.db || !this.db.open) throw new ServiceUnavailableException({ errorCode: 'AUTH_UNAVAILABLE' });
    return this.db;
  }

  rateLimit(action: 'login' | 'register', email: string, ip: string): boolean {
    const db = this.database();
    const now = Date.now();
    const keys = [
      { key: digest(`${action}:email:${email}`), limit: 5 },
      { key: digest(`${action}:ip:${ip}`), limit: 20 },
    ];
    return db.transaction(() => {
      db.prepare('DELETE FROM auth_attempts WHERE expires_at <= ?').run(now);
      const read = db.prepare('SELECT count FROM auth_attempts WHERE bucket = ?');
      if (keys.some(({ key, limit }) => ((read.get(key) as { count: number } | undefined)?.count ?? 0) >= limit)) return false;
      const newKeys = keys.filter(({ key }) => !read.get(key)).length;
      const size = (db.prepare('SELECT count(*) AS total FROM auth_attempts').get() as { total: number }).total;
      if (size + newKeys > 10000) return false;
      for (const { key } of keys) {
        db.prepare(`INSERT INTO auth_attempts (bucket, count, expires_at) VALUES (?, 1, ?)
          ON CONFLICT(bucket) DO UPDATE SET count = count + 1`).run(key, now + WINDOW_MS);
      }
      return true;
    })();
  }

  async register(email: string, password: string): Promise<User | null> {
    const db = this.database();
    const id = randomBytes(16).toString('hex');
    const salt = randomBytes(16).toString('hex');
    const hash = await hashPassword(password, salt);
    try {
      db.prepare('INSERT INTO users (id, email, salt, password_hash) VALUES (?, ?, ?, ?)').run(id, email, salt, hash);
      return { id, email };
    } catch (error) {
      if (error instanceof Error && 'code' in error && error.code === 'SQLITE_CONSTRAINT_UNIQUE') return null;
      throw error;
    }
  }

  async login(email: string, password: string): Promise<User | null> {
    const row = this.database().prepare('SELECT id, email, salt, password_hash FROM users WHERE email = ?')
      .get(email) as (User & { salt: string; password_hash: Buffer }) | undefined;
    const actual = await hashPassword(password, row?.salt ?? DUMMY_SALT);
    const expected = row?.password_hash ?? DUMMY_HASH;
    if (!timingSafeEqual(actual, expected) || !row) return null;
    return { id: row.id, email: row.email };
  }

  createSession(userId: string, presentedToken?: string | null): string {
    const db = this.database();
    const now = Date.now();
    const token = randomBytes(32).toString('base64url');
    db.transaction(() => {
      if (presentedToken) db.prepare('UPDATE sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL')
        .run(now, digest(presentedToken));
      db.prepare('DELETE FROM sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL').run(now);
      db.prepare(`DELETE FROM sessions WHERE token_hash IN (
        SELECT token_hash FROM sessions WHERE user_id = ? ORDER BY expires_at DESC, rowid DESC LIMIT -1 OFFSET 4
      )`).run(userId);
      db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
        .run(digest(token), userId, now + SESSION_MS);
      db.prepare('INSERT INTO trusted_sessions VALUES(?,?,1)').run(digest(token), randomBytes(16).toString('hex'));
    }).immediate();
    return token;
  }

  userForToken(token: string): User | null {
    const row = this.database().prepare(`SELECT users.id, users.email FROM sessions
      JOIN users ON users.id = sessions.user_id
      WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?`)
      .get(digest(token), Date.now()) as User | undefined;
    return row ?? null;
  }

  sessionForToken(token: string): SessionSnapshot | null {
    const db = this.database();
    if (browserAccessFingerprint() !== this.accessFingerprint) throw new ServiceUnavailableException({ errorCode: 'AUTH_UNAVAILABLE' });
    const row = db.prepare(`SELECT s.user_id AS subject,t.session_id AS sessionId,t.generation,s.expires_at AS expiresAt,
      a.incarnation AS accessIncarnation FROM sessions s JOIN trusted_sessions t USING(token_hash)
      JOIN browser_access a ON a.id=1 WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>?
      AND a.fingerprint=?`).get(digest(token), Date.now(), this.accessFingerprint) as SessionSnapshot | undefined;
    if (!row) return null;
    const snapshot = Object.freeze({ ...row }); this.snapshots.set(snapshot, digest(token)); return snapshot;
  }

  guardSession<T>(snapshot: SessionSnapshot, action: () => T, busyMs = 100): T {
    const db = this.database(), tokenHash = this.snapshots.get(snapshot);
    if (!tokenHash || browserAccessFingerprint() !== this.accessFingerprint || !Number.isInteger(busyMs) || busyMs < 0 || busyMs > 100)
      throw new ServiceUnavailableException({ errorCode: 'AUTH_UNAVAILABLE' });
    const previous = db.pragma('busy_timeout', { simple: true }) as number;
    try {
      db.pragma(`busy_timeout = ${busyMs}`);
      return db.transaction(() => {
        const live = db.prepare(`SELECT 1 FROM sessions s JOIN trusted_sessions t USING(token_hash)
          JOIN browser_access a ON a.id=1 WHERE s.token_hash=? AND s.user_id=? AND s.revoked_at IS NULL
          AND s.expires_at>? AND s.expires_at=? AND t.session_id=? AND t.generation=?
          AND a.incarnation=? AND a.fingerprint=?`).get(tokenHash, snapshot.subject, Date.now(), snapshot.expiresAt,
          snapshot.sessionId, snapshot.generation, snapshot.accessIncarnation, this.accessFingerprint);
        if (!live) throw new ServiceUnavailableException({ errorCode: 'AUTH_UNAVAILABLE' });
        const result = action();
        if (result && typeof result === 'object' && 'then' in result) throw new ServiceUnavailableException({ errorCode: 'AUTH_UNAVAILABLE' });
        return result;
      }).immediate();
    } finally { db.pragma(`busy_timeout = ${previous}`); }
  }

  revoke(token: string): void {
    const db = this.database();
    db.transaction(() => db.prepare('UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL')
      .run(Date.now(), digest(token))).immediate();
  }

  onModuleDestroy(): void { this.db?.close(); }
}
