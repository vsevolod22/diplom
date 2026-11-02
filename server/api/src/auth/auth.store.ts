import { createHash, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { BadRequestException, Injectable, OnModuleDestroy, ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import Database from 'better-sqlite3';

export type User = { id: string; email: string };
type CredentialsRow = User & { salt: string; password_hash: Buffer; generation: number };
export type AuthAction = 'login' | 'register' | 'change-password' | 'revoke-all' | 'reset-request' | 'reset-confirm';
export const PASSWORD_RESET_TTL_MS = 15 * 60 * 1000;
export const validPassword = (value: unknown): value is string =>
  typeof value === 'string' && Buffer.byteLength(value) >= 12 && Buffer.byteLength(value) <= 128;
const validResetToken = (value: string): boolean => /^[A-Za-z0-9_-]{43}$/.test(value);
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
  private readonly authentications = new WeakMap<User, { subject: string; generation: number }>();
  private passwordWork = 0;

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
        INSERT OR IGNORE INTO trusted_sessions SELECT token_hash,lower(hex(randomblob(16))),1 FROM sessions;
        CREATE TABLE IF NOT EXISTS user_auth_state (
          user_id TEXT PRIMARY KEY REFERENCES users(id), generation INTEGER NOT NULL CHECK(generation>0)
        );
        INSERT OR IGNORE INTO user_auth_state SELECT id,1 FROM users;
        CREATE TABLE IF NOT EXISTS password_resets (
          token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE REFERENCES users(id),
          generation INTEGER NOT NULL, expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS password_resets_expiry ON password_resets(expires_at);`);
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

  assertAvailable(): void { this.database(); }

  private async passwordHash(password: string, salt: string): Promise<Buffer> {
    if (this.passwordWork >= 4) throw new ServiceUnavailableException({ errorCode: 'AUTH_BUSY' });
    this.passwordWork++;
    try { return await hashPassword(password, salt); }
    finally { this.passwordWork--; }
  }

  rateLimit(action: AuthAction, email: string, ip: string): boolean {
    const db = this.database();
    const now = Date.now();
    const keys = [
      { key: digest(`${action}:email:${email}`), limit: action === 'reset-request' ? 3 : 5 },
      { key: digest(`${action}:ip:${ip}`), limit: 20 },
    ];
    if (action === 'reset-request' || action === 'reset-confirm') keys.push({ key: digest(`${action}:global`), limit: 100 });
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
    }).immediate();
  }

  async register(email: string, password: string): Promise<User | null> {
    const db = this.database();
    const id = randomBytes(16).toString('hex');
    const salt = randomBytes(16).toString('hex');
    const hash = await this.passwordHash(password, salt);
    try {
      db.transaction(() => {
        db.prepare('INSERT INTO users (id, email, salt, password_hash) VALUES (?, ?, ?, ?)').run(id, email, salt, hash);
        db.prepare('INSERT INTO user_auth_state VALUES(?,1)').run(id);
      }).immediate();
      const user = { id, email };
      this.authentications.set(user, { subject: id, generation: 1 });
      return user;
    } catch (error) {
      if (error instanceof Error && 'code' in error && error.code === 'SQLITE_CONSTRAINT_UNIQUE') return null;
      throw error;
    }
  }

  async login(email: string, password: string): Promise<User | null> {
    const row = this.database().prepare(`SELECT id,email,salt,password_hash,generation FROM users
      JOIN user_auth_state ON user_id=id WHERE email=?`).get(email) as CredentialsRow | undefined;
    const actual = await this.passwordHash(password, row?.salt ?? DUMMY_SALT);
    const expected = row?.password_hash ?? DUMMY_HASH;
    if (!timingSafeEqual(actual, expected) || !row) return null;
    const user = { id: row.id, email: row.email };
    this.authentications.set(user, { subject: row.id, generation: row.generation });
    return user;
  }

  // HTTP login/register must use this one-use proof, not a bare account ID. A password
  // change or revoke-all during async scrypt must not mint a fresh session afterwards.
  createAuthenticatedSession(user: User, presentedToken?: string | null): string {
    const proof = this.authentications.get(user);
    this.authentications.delete(user);
    if (!proof || proof.subject !== user.id) throw new UnauthorizedException({ errorCode: 'INVALID_CREDENTIALS' });
    return this.mintSession(proof.subject, presentedToken, proof.generation);
  }

  // Trusted server-side compatibility API; never expose a caller-supplied ID through HTTP.
  createSession(userId: string, presentedToken?: string | null): string {
    return this.mintSession(userId, presentedToken);
  }

  private mintSession(userId: string, presentedToken?: string | null, generation?: number): string {
    const db = this.database();
    const now = Date.now();
    const token = randomBytes(32).toString('base64url');
    db.transaction(() => {
      if (generation !== undefined && !db.prepare('SELECT 1 FROM user_auth_state WHERE user_id=? AND generation=?').get(userId, generation))
        throw new UnauthorizedException({ errorCode: 'INVALID_CREDENTIALS' });
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

  private invalidateAccount(userId: string, now: number): void {
    const db = this.database();
    db.prepare('UPDATE user_auth_state SET generation=generation+1 WHERE user_id=?').run(userId);
    db.prepare('UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL').run(now, userId);
    db.prepare('DELETE FROM password_resets WHERE user_id=?').run(userId);
  }

  async changePassword(snapshot: SessionSnapshot, currentPassword: string, newPassword: string): Promise<boolean> {
    return this.changeAccount(snapshot, currentPassword, newPassword);
  }

  async revokeAll(snapshot: SessionSnapshot, currentPassword: string): Promise<boolean> {
    return this.changeAccount(snapshot, currentPassword);
  }

  private async changeAccount(snapshot: SessionSnapshot, currentPassword: string, newPassword?: string): Promise<boolean> {
    if (!validPassword(currentPassword) || (newPassword !== undefined && !validPassword(newPassword)))
      throw new BadRequestException({ errorCode: 'INVALID_INPUT' });
    const db = this.database();
    const row = this.guardSession(snapshot, () => db.prepare(`SELECT id,email,salt,password_hash,generation FROM users
      JOIN user_auth_state ON user_id=id WHERE id=?`).get(snapshot.subject) as CredentialsRow);
    const actual = await this.passwordHash(currentPassword, row.salt);
    if (!timingSafeEqual(actual, row.password_hash)) return false;
    const salt = newPassword === undefined ? undefined : randomBytes(16).toString('hex');
    const hash = salt === undefined ? undefined : await this.passwordHash(newPassword!, salt);
    // Revalidate authority after every asynchronous operation, holding the same DB write
    // fence used by protected actions. No promise or external work runs in this transaction.
    return this.guardSession(snapshot, () => {
      if (!db.prepare('SELECT 1 FROM user_auth_state WHERE user_id=? AND generation=?').get(row.id, row.generation))
        return false;
      if (hash && salt) db.prepare('UPDATE users SET salt=?,password_hash=? WHERE id=?').run(salt, hash, row.id);
      this.invalidateAccount(row.id, Date.now());
      return true;
    });
  }

  // Server-only handoff to the configured delivery adapter. Raw tokens are transient;
  // only their digest is persisted, and one outstanding token per account is allowed.
  issuePasswordReset(email: string): { token: string; expiresAt: number } | null {
    const db = this.database();
    return db.transaction(() => {
      const now = Date.now();
      db.prepare('DELETE FROM password_resets WHERE expires_at<=?').run(now);
      const row = db.prepare(`SELECT id,generation FROM users JOIN user_auth_state ON user_id=id WHERE email=?`)
        .get(email) as { id: string; generation: number } | undefined;
      if (!row) return null;
      const count = (db.prepare('SELECT count(*) AS total FROM password_resets').get() as { total: number }).total;
      if (count >= 1000 && !db.prepare('SELECT 1 FROM password_resets WHERE user_id=?').get(row.id)) return null;
      const token = randomBytes(32).toString('base64url'), expiresAt = now + PASSWORD_RESET_TTL_MS;
      db.prepare(`INSERT INTO password_resets VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET
        token_hash=excluded.token_hash,generation=excluded.generation,expires_at=excluded.expires_at`)
        .run(digest(token), row.id, row.generation, expiresAt);
      return { token, expiresAt };
    }).immediate();
  }

  cancelPasswordReset(token: string): void {
    this.database().prepare('DELETE FROM password_resets WHERE token_hash=?').run(digest(token));
  }

  async confirmPasswordReset(token: string, newPassword: string): Promise<boolean> {
    if (!validResetToken(token) || !validPassword(newPassword)) throw new BadRequestException({ errorCode: 'INVALID_INPUT' });
    const db = this.database(), tokenHash = digest(token);
    const salt = randomBytes(16).toString('hex');
    const hash = await this.passwordHash(newPassword, salt);
    return db.transaction(() => {
      const now = Date.now();
      const row = db.prepare(`SELECT r.user_id FROM password_resets r JOIN user_auth_state a USING(user_id)
        WHERE r.token_hash=? AND r.expires_at>? AND r.generation=a.generation`).get(tokenHash, now) as { user_id: string } | undefined;
      if (!row) return false;
      db.prepare('UPDATE users SET salt=?,password_hash=? WHERE id=?').run(salt, hash, row.user_id);
      this.invalidateAccount(row.user_id, now);
      return true;
    }).immediate();
  }

  onModuleDestroy(): void { if (this.db?.open) this.db.close(); }
}
