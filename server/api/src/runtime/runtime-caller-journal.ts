import Database from 'better-sqlite3';
import { constants, openSync, closeSync, lstatSync, fstatSync, unlinkSync } from 'node:fs';
import { str, HEX } from '../../../runtime/src/contract.js';
import { checkedPath } from './runtime-store.js';
import { digest } from './runtime-evidence.js';
import { fenceKey, type Invalidation, type LiveIntent } from '../../../runtime/src/live-port.js';
import {
  validateInvalidation,
  validateLiveIntent,
  validDispatchPermit,
} from '../../../runtime/src/dispatch-permit.js';
const APP = 0x52434a31;
// Independent private-caller database, never the API runtime DB or shared ledger. Explicit init only.
export function initializeCallerJournal(path: string, otherPaths: string[] = []): void {
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
      db.exec(
        `CREATE TABLE attempts(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, nonce TEXT NOT NULL UNIQUE, consent TEXT NOT NULL UNIQUE, state TEXT NOT NULL CHECK(state IN ('consumed','dispatched','settled','indeterminate'))); CREATE TABLE revoked(id TEXT PRIMARY KEY);`,
      );
      db.pragma(`application_id=${APP}`);
      db.pragma('user_version=1');
    })();
  } finally {
    db.close();
  }
}
export class CallerJournal {
  private readonly db!: Database.Database;
  private readonly lock: { path: string; fd: number; inode: number };
  constructor(
    path: string,
    private readonly key: string,
    otherPaths: string[] = [],
  ) {
    str(key, HEX);
    checkedPath(path, otherPaths, true);
    const lockPath = `${path}.writer`;
    const fd = openSync(
      lockPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
      0o600,
    );
    this.lock = { path: lockPath, fd, inode: fstatSync(fd).ino };
    try {
      this.db = new Database(path, { fileMustExist: true, timeout: 1000 });
      if (
        this.db.pragma('application_id', { simple: true }) !== APP ||
        this.db.pragma('user_version', { simple: true }) !== 1
      )
        throw new Error('RUNTIME_UNAVAILABLE');
      this.db.pragma('journal_mode=WAL');
      this.db.pragma('synchronous=FULL');
      this.db
        .prepare("UPDATE attempts SET state='indeterminate' WHERE state IN ('consumed','dispatched')")
        .run();
    } catch (error) {
      this.db?.close();
      this.releaseLock();
      throw error;
    }
  }
  private id(i: LiveIntent): string {
    return digest([i.subject, i.captureId, i.attempt], 'runtime-dispatch-attempt-v1');
  }
  revoked(f: Invalidation): boolean {
    return !!this.db.prepare('SELECT 1 FROM revoked WHERE id=?').get(fenceKey(f));
  }
  invalidate(f: Invalidation): void {
    validateInvalidation(f);
    this.db
      .transaction(() => {
        if (this.revoked(f)) return;
        if ((this.db.prepare('SELECT count(*) n FROM revoked').get() as { n: number }).n >= 10000)
          throw new Error('INDETERMINATE');
        this.db.prepare('INSERT INTO revoked VALUES(?)').run(fenceKey(f));
      })
      .immediate();
  }
  consume(i: LiveIntent, permit: unknown, now = Date.now()): void {
    validateLiveIntent(i);
    if (!validDispatchPermit(i, this.key, permit) || i.expiresAt <= now || i.expiresAt - now > 300000)
      throw new Error('NOT_AUTHORIZED');
    this.db
      .transaction(() => {
        if (this.revoked(i) || this.db.prepare('SELECT 1 FROM attempts WHERE id=?').get(this.id(i)))
          throw new Error('NOT_AUTHORIZED');
        if ((this.db.prepare('SELECT count(*) n FROM attempts').get() as { n: number }).n >= 10000)
          throw new Error('INDETERMINATE');
        try {
          this.db
            .prepare("INSERT INTO attempts VALUES(?,?,?,?,'consumed')")
            .run(
              this.id(i),
              digest(i, 'runtime-dispatch-intent-v1'),
              digest(i.nonce, 'runtime-dispatch-nonce-v1'),
              fenceKey(i),
            );
        } catch {
          throw new Error('NOT_AUTHORIZED');
        }
      })
      .immediate();
  }
  dispatched(i: LiveIntent): void {
    this.db.prepare("UPDATE attempts SET state='dispatched' WHERE id=? AND state='consumed'").run(this.id(i));
  }
  settle(i: LiveIntent, uncertain: boolean): void {
    this.db
      .prepare("UPDATE attempts SET state=? WHERE id=? AND state IN ('consumed','dispatched')")
      .run(uncertain ? 'indeterminate' : 'settled', this.id(i));
  }
  state(i: LiveIntent): string | undefined {
    return (
      this.db.prepare('SELECT state FROM attempts WHERE id=?').get(this.id(i)) as
        | { state: string }
        | undefined
    )?.state;
  }
  private releaseLock(): void {
    closeSync(this.lock.fd);
    try {
      if (lstatSync(this.lock.path).ino === this.lock.inode) unlinkSync(this.lock.path);
    } catch {
      // Best-effort inode-fenced cleanup; never unlink a replacement lock.
    }
  }
  close(): void {
    this.db.close();
    this.releaseLock();
  }
}
