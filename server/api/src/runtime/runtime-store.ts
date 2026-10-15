import Database from 'better-sqlite3';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, realpathSync, unlinkSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import {
  canonical,
  EXCLUSIONS,
  exact,
  HEX,
  ID,
  integer,
  link,
  one,
  report,

  str,
  target,
  type Capture,
  type ImageLink,
  type Mode,
  type Report,
  type Target,
} from '../../../runtime/src/contract.js';
import { validateCaptureHash } from './runtime-evidence.js';
import type { Invalidation } from '../../../runtime/src/live-port.js';

const APPLICATION_ID = 0x52554e31;
const nowIso = (now: number) => new Date(now).toISOString();
const freshId = () => randomBytes(16).toString('hex');
export class RuntimeFault extends Error {
  constructor(
    readonly code: string,
    readonly status = 400,
  ) {
    super(code);
  }
}
export function fault(code: string, status = 400): never {
  throw new RuntimeFault(code, status);
}
export type Enrollment = {
  subject: string;
  target: Target;
  signerId: string;
  publicKey: string;
  fingerprint: string;
  sourceVersion: 'operator-runtime-v1';
};
export type Authority = {
  subject: string;
  target: Target;
  consentId: string;
  nonce: string;
  expiresAt: number;
  epoch: number;
  brokerSubject: string;
};
type CaptureRow = {
  id: string;
  subject: string;
  fingerprint: string;
  consent_id: string;
  epoch: number;
  attempt: number;
  state: string;
  report: string;
  created_at: number;
};
export function checkedPath(path: string, otherPaths: string[], exists: boolean): string {
  if (!isAbsolute(path) || resolve(path) !== path || path.startsWith('file:'))
    fault('RUNTIME_UNAVAILABLE', 503);
  const parent = dirname(path);
  const root = lstatSync(parent);
  if (
    realpathSync(parent) !== parent ||
    !root.isDirectory() ||
    root.uid !== process.getuid?.() ||
    (root.mode & 0o777) !== 0o700
  )
    fault('RUNTIME_UNAVAILABLE', 503);
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    if (exists) fault('RUNTIME_UNAVAILABLE', 503);
  }
  if (
    stat &&
    (!stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.uid !== root.uid ||
      (stat.mode & 0o777) !== 0o600 ||
      stat.nlink !== 1 ||
      realpathSync(path) !== path)
  )
    fault('RUNTIME_UNAVAILABLE', 503);
  for (const other of otherPaths.filter(Boolean)) {
    if (resolve(other) === path) fault('RUNTIME_UNAVAILABLE', 503);
    try {
      const s = lstatSync(other);
      if (stat && s.dev === stat.dev && s.ino === stat.ino) fault('RUNTIME_UNAVAILABLE', 503);
    } catch (e) {
      if (e instanceof RuntimeFault) throw e;
    }
  }
  return path;
}
const schema = `
CREATE TABLE runtime_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), epoch INTEGER NOT NULL);
INSERT INTO runtime_meta VALUES(1,1);
CREATE TABLE runtime_subjects(subject TEXT PRIMARY KEY, broker_subject TEXT NOT NULL UNIQUE);
CREATE TABLE runtime_enrollments(subject TEXT NOT NULL, target_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(subject,target_id));
CREATE TABLE runtime_consents(id TEXT PRIMARY KEY, subject TEXT NOT NULL, target_id TEXT NOT NULL, mode TEXT NOT NULL, target_version INTEGER NOT NULL, epoch INTEGER NOT NULL, nonce TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE runtime_captures(id TEXT PRIMARY KEY, subject TEXT NOT NULL, intent_key TEXT NOT NULL, fingerprint TEXT NOT NULL, consent_id TEXT NOT NULL, epoch INTEGER NOT NULL, attempt INTEGER NOT NULL, state TEXT NOT NULL, report TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(subject,intent_key));
CREATE TABLE runtime_events(id INTEGER PRIMARY KEY AUTOINCREMENT, capture_id TEXT NOT NULL REFERENCES runtime_captures(id), state TEXT NOT NULL);
CREATE TABLE runtime_links(capture_id TEXT NOT NULL REFERENCES runtime_captures(id), image_scan_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(capture_id,image_scan_id));
CREATE TABLE runtime_rate(subject TEXT PRIMARY KEY, start INTEGER NOT NULL, count INTEGER NOT NULL);
CREATE TRIGGER runtime_terminal_immutable BEFORE UPDATE ON runtime_captures WHEN OLD.state!='running' BEGIN SELECT RAISE(ABORT,'terminal immutable'); END;
CREATE TRIGGER runtime_links_immutable BEFORE UPDATE ON runtime_links BEGIN SELECT RAISE(ABORT,'link immutable'); END;
`;
// Explicit operator init; the request-serving constructor never creates or migrates a DB.
export function initializeRuntimeStore(path: string, otherPaths: string[] = []): void {
  checkedPath(path, otherPaths, false);
  const fd = openSync(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
    0o600,
  );
  closeSync(fd);
  const db = new Database(path);
  try {
    db.transaction(() => {
      db.exec(schema);
      db.pragma(`application_id=${APPLICATION_ID}`);
      db.pragma('user_version=1');
    })();
  } finally {
    db.close();
  }
}
export class RuntimeStore {
  private readonly db!: Database.Database;
  private readonly lock: { path: string; fd: number; inode: number };
  constructor(
    readonly path: string,
    readonly clock: () => number = Date.now,
    otherPaths: string[] = [],
  ) {
    checkedPath(path, otherPaths, true);
    const lockPath = `${path}.writer`;
    let fd: number;
    try {
      fd = openSync(
        lockPath,
        constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
        0o600,
      );
    } catch {
      throw new RuntimeFault('RUNTIME_UNAVAILABLE', 503);
    }
    this.lock = { path: lockPath, fd, inode: fstatSync(fd).ino };
    try {
      this.db = new Database(path, { fileMustExist: true, timeout: 1000 });
      if (
        this.db.pragma('application_id', { simple: true }) !== APPLICATION_ID ||
        this.db.pragma('user_version', { simple: true }) !== 1
      )
        fault('RUNTIME_UNAVAILABLE', 503);
      this.db.pragma('journal_mode=WAL');
      this.db.pragma('foreign_keys=ON');
      this.db.pragma('synchronous=FULL');
      // A read could have occurred before crash. No automatic recapture after recovery.
      this.atomic(() => {
        const rows = this.db
          .prepare("SELECT * FROM runtime_captures WHERE state='running'")
          .all() as CaptureRow[];
        for (const row of rows) this.failRow(row, 'INDETERMINATE');
      });
    } catch (e) {
      this.db?.close();
      this.releaseLock();
      throw e;
    }
  }
  private releaseLock(): void {
    closeSync(this.lock.fd);
    try {
      if (lstatSync(this.lock.path).ino === this.lock.inode) unlinkSync(this.lock.path);
    } catch {
      /* operator reconciliation owns replaced lock */
    }
  }
  close(): void {
    this.db.close();
    this.releaseLock();
  }
  private atomic<T>(fn: () => T): T {
    return this.db.transaction(fn).immediate();
  }
  private epoch(): number {
    return (this.db.prepare('SELECT epoch FROM runtime_meta WHERE singleton=1').get() as { epoch: number })
      .epoch;
  }
  private rate(subject: string): void {
    const now = this.clock();
    this.db.prepare('DELETE FROM runtime_rate WHERE start <= ?').run(now - 60000);
    const r = this.db.prepare('SELECT count FROM runtime_rate WHERE subject=?').get(subject) as
      | { count: number }
      | undefined;
    if (
      (r && r.count >= 12) ||
      (!r && (this.db.prepare('SELECT count(*) n FROM runtime_rate').get() as { n: number }).n >= 1000)
    )
      fault('RUNTIME_CAPACITY', 429);
    this.db
      .prepare('INSERT INTO runtime_rate VALUES(?,?,1) ON CONFLICT(subject) DO UPDATE SET count=count+1')
      .run(subject, now);
  }
  // Operator-local method only. No public route accepts enrollment or keys.
  enroll(input: Enrollment): void {
    exact(input, ['subject', 'target', 'signerId', 'publicKey', 'fingerprint', 'sourceVersion']);
    str(input.subject, /^[A-Za-z0-9:_-]{1,128}$/);
    target(input.target);
    str(input.signerId, ID);
    str(input.fingerprint, HEX);
    one(input.sourceVersion, ['operator-runtime-v1']);
    str(input.publicKey, /^[A-Za-z0-9+/]{40,128}={0,2}$/);
    const der = Buffer.from(input.publicKey, 'base64');
    const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (
      key.asymmetricKeyType !== 'ed25519' ||
      createHash('sha256').update(der).digest('hex') !== input.fingerprint ||
      der.toString('base64') !== input.publicKey
    )
      fault('INVALID_RUNTIME_INPUT');
    this.atomic(() => {
      if (
        (this.db.prepare('SELECT count(*) n FROM runtime_enrollments').get() as { n: number }).n >= 1000 &&
        !this.enrollment(input.subject, input.target.targetId)
      )
        fault('RUNTIME_CAPACITY', 429);
      const old = this.enrollment(input.subject, input.target.targetId);
      if (old && input.target.version <= old.target.version) fault('INVALID_RUNTIME_INPUT');
      this.db
        .prepare('INSERT OR IGNORE INTO runtime_subjects VALUES(?,?)')
        .run(input.subject, `s-${randomBytes(12).toString('hex')}`);
      this.db
        .prepare(
          'INSERT INTO runtime_enrollments VALUES(?,?,?) ON CONFLICT(subject,target_id) DO UPDATE SET record=excluded.record',
        )
        .run(input.subject, input.target.targetId, canonical(input));
      this.db.prepare('UPDATE runtime_meta SET epoch=epoch+1').run();
    });
  }
  enrollment(subject: string, targetId: string): Enrollment | undefined {
    const r = this.db
      .prepare('SELECT record FROM runtime_enrollments WHERE subject=? AND target_id=?')
      .get(subject, targetId) as { record: string } | undefined;
    return r ? (JSON.parse(r.record) as Enrollment) : undefined;
  }
  targets(subject: string): Target[] {
    return (
      this.db
        .prepare('SELECT record FROM runtime_enrollments WHERE subject=? ORDER BY target_id LIMIT 100')
        .all(subject) as { record: string }[]
    ).map((r) => target(JSON.parse(r.record).target));
  }
  consent(subject: string, targetId: string, mode: Mode): Authority {
    return this.atomic(() => {
      this.rate(subject);
      const e = this.enrollment(subject, targetId);
      if (!e || !(mode === 'imported-historical' ? e.target.importAllowed : e.target.liveAllowed))
        fault('NOT_AUTHORIZED', 403);
      this.db
        .prepare(
          'DELETE FROM runtime_consents WHERE expires_at < ? AND id NOT IN (SELECT consent_id FROM runtime_captures)',
        )
        .run(this.clock() - 300000);
      if ((this.db.prepare('SELECT count(*) n FROM runtime_consents').get() as { n: number }).n >= 10000)
        fault('RUNTIME_CAPACITY', 429);
      // Allocate an immutable consent identity, not a global validity/revocation epoch.
      this.db.prepare('UPDATE runtime_meta SET epoch=epoch+1').run();
      const id = freshId();
      const nonce = randomBytes(32).toString('hex');
      const expires = this.clock() + 300000;
      this.db
        .prepare(
          'INSERT INTO runtime_consents(id,subject,target_id,mode,target_version,epoch,nonce,expires_at) VALUES(?,?,?,?,?,?,?,?)',
        )
        .run(id, subject, targetId, mode, e.target.version, this.epoch(), nonce, expires);
      return this.authority(subject, id, mode);
    });
  }
  authority(subject: string, consentId: string, mode: Mode, allowConsumed = false): Authority {
    const c = this.db
      .prepare('SELECT * FROM runtime_consents WHERE id=? AND subject=?')
      .get(consentId, subject) as
      | {
          target_id: string;
          mode: string;
          target_version: number;
          epoch: number;
          nonce: string;
          expires_at: number;
          revoked: number;
          consumed: number;
        }
      | undefined;
    const e = c && this.enrollment(subject, c.target_id);
    if (
      !c ||
      !e ||
      c.mode !== mode ||
      c.revoked ||
      (!allowConsumed && c.consumed) ||
      c.expires_at <= this.clock() ||
      c.target_version !== e.target.version ||
      !(mode === 'imported-historical' ? e.target.importAllowed : e.target.liveAllowed)
    )
      fault('NOT_AUTHORIZED', 403);
    const s = this.db.prepare('SELECT broker_subject FROM runtime_subjects WHERE subject=?').get(subject) as {
      broker_subject: string;
    };
    return {
      subject,
      target: e.target,
      consentId,
      nonce: c.nonce,
      expiresAt: c.expires_at,
      epoch: c.epoch,
      brokerSubject: s.broker_subject,
    };
  }
  revoke(subject: string, id: string): { changed: boolean; fence: Invalidation } {
    return this.atomic(() => {
      str(id, ID);
      const c = this.db
        .prepare('SELECT epoch,revoked FROM runtime_consents WHERE subject=? AND id=?')
        .get(subject, id) as { epoch: number; revoked: number } | undefined;
      if (!c) fault('NOT_FOUND', 404);
      const fence = { subject, consentId: id, epoch: c.epoch };
      if (c.revoked) return { changed: false, fence };
      this.rate(subject);
      this.db.prepare('UPDATE runtime_consents SET revoked=1 WHERE id=? AND subject=?').run(id, subject);
      const rows = this.db
        .prepare("SELECT * FROM runtime_captures WHERE subject=? AND consent_id=? AND state='running'")
        .all(subject, id) as CaptureRow[];
      for (const row of rows) this.failRow(row, 'NOT_AUTHORIZED');
      return { changed: true, fence };
    });
  }
  replay(
    subject: string,
    key: string,
    fingerprint: string,
  ): { captureId: string; created: false; attempt: number } | undefined {
    str(key, ID);
    str(fingerprint, HEX);
    const prior = this.db
      .prepare('SELECT * FROM runtime_captures WHERE subject=? AND intent_key=?')
      .get(subject, key) as CaptureRow | undefined;
    if (!prior) return;
    if (prior.fingerprint !== fingerprint) fault('RUNTIME_CONFLICT', 409);
    return { captureId: prior.id, created: false, attempt: prior.attempt };
  }
  admit(subject: string): void {
    this.atomic(() => this.rate(subject));
  }
  begin(
    subject: string,
    key: string,
    fingerprint: string,
    consentId: string,
    mode: Mode,
  ): { captureId: string; created: boolean; attempt: number } {
    return this.atomic(() => {
      str(key, ID);
      str(fingerprint, HEX);
      const prior = this.db
        .prepare('SELECT * FROM runtime_captures WHERE subject=? AND intent_key=?')
        .get(subject, key) as CaptureRow | undefined;
      if (prior) {
        if (prior.fingerprint !== fingerprint) fault('RUNTIME_CONFLICT', 409);
        return { captureId: prior.id, created: false, attempt: prior.attempt };
      }
      const authority = this.authority(subject, consentId, mode);
      this.rate(subject);
      const count = (sql: string, ...params: string[]) =>
        (this.db.prepare(sql).get(...params) as { n: number }).n;
      if (
        count('SELECT count(*) n FROM runtime_captures') >= 10000 ||
        count('SELECT count(*) n FROM runtime_captures WHERE subject=?', subject) >= 1000 ||
        count("SELECT count(*) n FROM runtime_captures WHERE state='running'") >= 2
      )
        fault('RUNTIME_CAPACITY', 429);
      const captureId = freshId();
      const r: Report = {
        captureId,
        subject,
        target: authority.target,
        mode,
        state: 'running',
        reason: 'READY',
        createdAt: nowIso(this.clock()),
        receivedAt: null,
        consentId,
        checksVersion: 'runtime-config-v1',
        resourcePolicyVersion: 'runtime-host-policy-v1',
        evidence: null,
        provenance: null,
        links: [],
        exclusions: EXCLUSIONS,
      };
      this.db
        .prepare('INSERT INTO runtime_captures VALUES(?,?,?,?,?,?,1,?,?,?)')
        .run(
          captureId,
          subject,
          key,
          fingerprint,
          consentId,
          authority.epoch,
          'running',
          canonical(r),
          this.clock(),
        );
      this.db.prepare('INSERT INTO runtime_events(capture_id,state) VALUES(?,?)').run(captureId, 'running');
      return { captureId, created: true, attempt: 1 };
    });
  }
  private failRow(row: CaptureRow, reason: Report['reason'], cancelled = false): void {
    const r = report(JSON.parse(row.report));
    r.state = cancelled ? 'cancelled' : 'failed';
    r.reason = reason;
    this.db
      .prepare(
        "UPDATE runtime_captures SET state=?,report=?,attempt=attempt+1 WHERE id=? AND state='running'",
      )
      .run(r.state, canonical(r), row.id);
    this.db.prepare('INSERT INTO runtime_events(capture_id,state) VALUES(?,?)').run(row.id, r.state);
  }
  fail(subject: string, id: string, reason: Report['reason'], attempt: number): void {
    this.atomic(() => {
      const row = this.row(subject, id);
      if (row.state === 'running' && row.attempt === attempt) this.failRow(row, reason);
    });
  }
  cancel(
    subject: string,
    id: string,
  ): { changed: boolean; cancelled: boolean; state: Report['state']; fence: Invalidation | null } {
    return this.atomic(() => {
      const row = this.row(subject, id);
      if (row.state !== 'running')
        return {
          changed: false,
          cancelled: row.state === 'cancelled',
          state: row.state as Report['state'],
          fence: null,
        };
      this.rate(subject);
      this.failRow(row, 'CANCELLED', true);
      this.db
        .prepare('UPDATE runtime_consents SET revoked=1 WHERE id=? AND subject=?')
        .run(row.consent_id, subject);
      return {
        changed: true,
        cancelled: true,
        state: 'cancelled',
        fence: { subject, consentId: row.consent_id, epoch: row.epoch },
      };
    });
  }
  private row(subject: string, id: string): CaptureRow {
    str(id, ID);
    const row = this.db
      .prepare('SELECT * FROM runtime_captures WHERE id=? AND subject=?')
      .get(id, subject) as CaptureRow | undefined;
    if (!row) fault('NOT_FOUND', 404);
    return row;
  }
  active(subject: string, id: string, attempt: number): boolean {
    const row = this.row(subject, id);
    return row.state === 'running' && row.attempt === attempt;
  }
  commit(
    subject: string,
    id: string,
    attempt: number,
    evidence: Capture,
    provenance: Report['provenance'],
    nonce?: string,
  ): boolean {
    validateCaptureHash(evidence);
    return this.atomic(() => {
      const row = this.row(subject, id);
      if (row.state !== 'running' || row.attempt !== attempt) return false;
      const r = report(JSON.parse(row.report));
      const a = this.authority(subject, row.consent_id, r.mode);
      if (
        evidence.binding.nonce !== a.nonce ||
        evidence.binding.consentId !== a.consentId ||
        evidence.binding.authorityEpoch !== a.epoch ||
        a.epoch !== row.epoch ||
        evidence.snapshot.containerId !== a.target.containerId ||
        evidence.snapshot.context.id !== a.target.context ||
        evidence.snapshot.context.version !== a.target.contextVersion
      )
        fault('NOT_AUTHORIZED', 403);
      const age = this.clock() - Date.parse(evidence.endedAt);
      if (age > 300000 || age < -30000) fault('INVALID_RUNTIME_INPUT');
      if (r.mode === 'imported-historical') {
        const e = this.enrollment(subject, a.target.targetId)!;
        if (
          !provenance ||
          e.signerId !== provenance.signerId ||
          e.sourceVersion !== provenance.sourceVersion ||
          nonce !== a.nonce
        )
          fault('NOT_AUTHORIZED', 403);
      } else if (provenance || evidence.running !== true) fault('TARGET_NOT_RUNNING');
      this.db.prepare('UPDATE runtime_consents SET consumed=1 WHERE id=?').run(row.consent_id);
      r.state = 'completed';
      r.reason = 'READY';
      r.receivedAt = nowIso(this.clock());
      r.evidence = structuredClone(evidence);
      r.provenance = provenance;
      report(r);
      this.db
        .prepare(
          "UPDATE runtime_captures SET state='completed',report=? WHERE id=? AND state='running' AND attempt=?",
        )
        .run(canonical(r), id, attempt);
      this.db.prepare('INSERT INTO runtime_events(capture_id,state) VALUES(?,?)').run(id, 'completed');
      return true;
    });
  }
  read(subject: string, id: string): Report {
    const r = report(JSON.parse(this.row(subject, id).report));
    if (r.evidence) validateCaptureHash(r.evidence);
    r.links = (
      this.db
        .prepare('SELECT record FROM runtime_links WHERE capture_id=? ORDER BY image_scan_id LIMIT 8')
        .all(id) as { record: string }[]
    ).map((l) => JSON.parse(l.record));
    return report(r);
  }
  history(subject: string, cursor?: string): { captures: Report[]; nextCursor: string | null } {
    const anchor = cursor ? this.row(subject, str(cursor, ID)) : undefined;
    const rows = this.db
      .prepare(
        'SELECT id FROM runtime_captures WHERE subject=? AND (? IS NULL OR created_at<? OR (created_at=? AND id<?)) ORDER BY created_at DESC,id DESC LIMIT 21',
      )
      .all(
        subject,
        cursor ?? null,
        anchor?.created_at ?? null,
        anchor?.created_at ?? null,
        cursor ?? null,
      ) as { id: string }[];
    const captures: Report[] = [];
    let bytes = 64;
    for (const row of rows.slice(0, 20)) {
      const r = this.read(subject, row.id);
      const size = Buffer.byteLength(canonical(r)) + 1;
      if (bytes + size > 65536) break;
      captures.push(r);
      bytes += size;
    }
    return {
      captures,
      nextCursor: rows.length > captures.length ? (captures.at(-1)?.captureId ?? null) : null,
    };
  }
  events(subject: string, id: string, after: number): { id: number; state: string }[] {
    this.row(subject, id);
    integer(after);
    return this.db
      .prepare('SELECT id,state FROM runtime_events WHERE capture_id=? AND id>? ORDER BY id LIMIT 100')
      .all(id, after) as { id: number; state: string }[];
  }
  associate(subject: string, id: string, input: ImageLink): ImageLink {
    link(input);
    return this.atomic(() => {
      const r = this.read(subject, id);
      if (
        !r.evidence ||
        r.state !== 'completed' ||
        input.captureHash !== r.evidence.hash ||
        input.configDigest !== r.evidence.imageConfigDigest
      )
        fault('IMAGE_IDENTITY_MISMATCH');
      const prior = this.db
        .prepare('SELECT record FROM runtime_links WHERE capture_id=? AND image_scan_id=?')
        .get(id, input.imageScanId) as { record: string } | undefined;
      if (prior) return JSON.parse(prior.record) as ImageLink;
      if (r.links.length >= 8) fault('RUNTIME_CAPACITY', 429);
      this.db.prepare('INSERT INTO runtime_links VALUES(?,?,?)').run(id, input.imageScanId, canonical(input));
      return input;
    });
  }
}
