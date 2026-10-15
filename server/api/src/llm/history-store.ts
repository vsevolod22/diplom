import { randomUUID } from 'node:crypto';
import { closeSync, existsSync, lstatSync, openSync, realpathSync, statfsSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import Database from 'better-sqlite3';
import { HttpException } from '@nestjs/common';
import { HISTORY, bytes, hashValue, historyCapacity, historyConflict, historyUnavailable, isId, historyProjection, validateHead,
  type Decision, type HistoryHead, type Pending, type Turn, type ChatReply } from './history-contract.js';

const APPLICATION = 1145655602;
type Row = { epoch: string; revision: number; content: string; content_hash: string };
// One bounded head per transaction; DELETE journal's entire source DB is <=8MiB,
// so even a full rollback journal plus record headers fits the 16MiB sidecar ceiling.
export class HistoryStore {
  private readonly db!: Database.Database;
  private readonly path: string;
  private readonly inode!: { ino: number; dev: number };
  readonly incarnation!: string;
  constructor(path: string, initialize = false) {
    this.path = resolve(path);
    if (basename(this.path) !== 'llm-history.sqlite' || realpathSync(dirname(this.path)) !== dirname(this.path)) return historyUnavailable();
    if (initialize) {
      if (existsSync(this.path)) return historyUnavailable();
      closeSync(openSync(this.path, 'wx', 0o600));
    }
    if (!existsSync(this.path)) return historyUnavailable();
    this.inode = lstatSync(this.path);
    this.fileSafety();
    this.db = new Database(this.path, { timeout: HISTORY.busyMs, fileMustExist: true });
    try {
      const application = this.db.pragma('application_id', { simple: true }), version = this.db.pragma('user_version', { simple: true });
      if (initialize ? application !== 0 || version !== 0 : application !== APPLICATION || version !== 3) return historyUnavailable();
      this.db.pragma('page_size = 4096');
      if (this.db.pragma('page_size', { simple: true }) !== 4096) return historyUnavailable();
      this.db.pragma('journal_mode = DELETE'); this.db.pragma('synchronous = FULL'); this.db.pragma('journal_size_limit = 0');
      this.db.pragma('temp_store = MEMORY'); this.db.pragma('cache_size = -1024'); this.db.pragma('foreign_keys = ON');
      this.db.pragma(`max_page_count = ${HISTORY.dbBytes / 4096}`);
      if (initialize) this.db.transaction(() => this.db.exec(`
        CREATE TABLE history_meta(id INTEGER PRIMARY KEY CHECK(id=1),incarnation TEXT NOT NULL) STRICT;
        INSERT INTO history_meta VALUES(1,'${randomUUID()}');
        CREATE TABLE history_head(scope TEXT PRIMARY KEY,epoch TEXT NOT NULL,revision INTEGER NOT NULL,
          content TEXT NOT NULL CHECK(length(CAST(content AS BLOB))<=524288),content_hash TEXT NOT NULL) STRICT;
        CREATE TABLE history_completion_space(scope TEXT PRIMARY KEY REFERENCES history_head(scope),
          padding BLOB NOT NULL CHECK(length(padding)=102400)) STRICT;
        PRAGMA application_id=${APPLICATION}; PRAGMA user_version=3;
      `)).immediate();
      const metadata = this.db.prepare('SELECT incarnation FROM history_meta WHERE id=1').get() as { incarnation: string } | undefined;
      if (!metadata || !isId(metadata.incarnation) || this.db.pragma('quick_check', { simple: true }) !== 'ok') return historyUnavailable();
      this.incarnation = metadata.incarnation;
      this.safety();
      for (const row of this.db.prepare('SELECT scope FROM history_head').all() as { scope: string }[]) this.read(row.scope);
            const spaces = (this.db.prepare('SELECT count(*) AS n FROM history_completion_space').get() as { n: number }).n;
            const pending = (this.db.prepare("SELECT count(*) AS n FROM history_head WHERE json_extract(content,'$.pending') IS NOT NULL").get() as { n: number }).n;
            if (spaces !== pending) return historyUnavailable();
    } catch (error) { this.db.close(); if (error instanceof HttpException) throw error; return historyUnavailable(); }
  }
  close() { this.db.close(); }
  private fileSafety() {
    const stat = lstatSync(this.path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) ||
      process.getuid && stat.uid !== process.getuid() || stat.ino !== this.inode.ino || stat.dev !== this.inode.dev || stat.size > HISTORY.dbBytes) return historyUnavailable();
    let sidecars = 0;
    for (const suffix of ['-journal', '-wal', '-shm']) {
      const path = this.path + suffix; if (!existsSync(path)) continue;
      const sidecar = lstatSync(path); sidecars += sidecar.size;
      if (suffix !== '-journal' || !sidecar.isFile() || sidecar.isSymbolicLink() || sidecar.nlink !== 1 ||
        (sidecar.mode & 0o077) || process.getuid && sidecar.uid !== process.getuid()) return historyUnavailable();
    }
    if (sidecars > HISTORY.sidecarBytes) return historyUnavailable();
    const fs = statfsSync(dirname(this.path), { bigint: true });
    if (fs.bavail * fs.bsize < BigInt(HISTORY.diskHeadroom)) return historyUnavailable();
  }
  private safety() {
    this.fileSafety();
    const pages = this.db.pragma('page_count', { simple: true }) as number;
    const heads = (this.db.prepare('SELECT count(*) AS n FROM history_head').get() as { n: number }).n;
    if (!Number.isSafeInteger(pages) || pages * 4096 > HISTORY.dbBytes || heads > HISTORY.heads) return historyCapacity();
    if (this.incarnation && (this.db.prepare('SELECT incarnation FROM history_meta WHERE id=1').get() as { incarnation: string } | undefined)?.incarnation !== this.incarnation) return historyUnavailable();
  }
  private transaction<T>(action: () => T): T {
    try {
      return this.db.transaction(() => { this.safety(); const result = action(); this.safety(); return result; }).immediate();
    } catch (error) {
      if (error instanceof HttpException) throw error;
      if (error instanceof Error && 'code' in error && error.code === 'SQLITE_FULL') return historyCapacity();
      return historyUnavailable();
    }
  }
  private key(owner: string, scanId: string) {
    if (!/^[a-f0-9]{32}$/.test(owner) || !isId(scanId)) return historyUnavailable();
    return hashValue([owner, scanId]);
  }
  private decode(row: Row): HistoryHead {
    if (typeof row.content !== 'string' || Buffer.byteLength(row.content) > HISTORY.scopeBytes) return historyUnavailable();
    const head: unknown = JSON.parse(row.content); validateHead(head);
    if (head.epoch !== row.epoch || head.revision !== row.revision || hashValue(head) !== row.content_hash) return historyUnavailable();
    return head;
  }
  private read(scope: string): HistoryHead {
    const row = this.db.prepare('SELECT epoch,revision,content,content_hash FROM history_head WHERE scope=?').get(scope) as Row | undefined;
    if (row) {
          const head = this.decode(row);
          const space = this.db.prepare('SELECT length(padding) AS n FROM history_completion_space WHERE scope=?').get(scope) as { n: number } | undefined;
          if (head.pending ? space?.n !== HISTORY.completionReserve : !!space) return historyUnavailable();
          return head;
        }
    if ((this.db.prepare('SELECT count(*) AS n FROM history_head').get() as { n: number }).n >= HISTORY.heads) return historyCapacity();
    const head: HistoryHead = { epoch: randomUUID(), revision: 0, turns: [], decisions: [], pending: null };
    this.db.prepare('INSERT INTO history_head VALUES(?,?,?,?,?)').run(scope, head.epoch, head.revision, JSON.stringify(head), hashValue(head));
    return head;
  }
  snapshot(owner: string, scanId: string): HistoryHead { return this.transaction(() => this.read(this.key(owner, scanId))); }
    guardHead<T>(owner: string, scanId: string, epoch: string, revision: number, action: () => T): T {
      return this.transaction(() => {
        this.expected(this.read(this.key(owner, scanId)), epoch, revision);
        const result = action();
        if (result && typeof result === 'object' && 'then' in result) return historyUnavailable();
        return result;
      });
    }
  private update(scope: string, head: HistoryHead, oldRevision: number) {
    validateHead(head);
    if (this.db.prepare('UPDATE history_head SET revision=?,content=?,content_hash=? WHERE scope=? AND epoch=? AND revision=?')
      .run(head.revision, JSON.stringify(head), hashValue(head), scope, head.epoch, oldRevision).changes !== 1) return historyConflict();
  }
  private advance(head: HistoryHead) {
    if (!Number.isSafeInteger(head.revision) || head.revision >= Number.MAX_SAFE_INTEGER) return historyCapacity();
    head.revision++;
  }
  private expected(head: HistoryHead, epoch: string, revision: number) {
    if (head.epoch !== epoch || head.revision !== revision) return historyConflict();
  }
  duplicate(owner: string, scanId: string, mutationId: string, matches?: (record: Turn | Decision, head: HistoryHead) => boolean) {
    return this.transaction(() => {
      const head = this.read(this.key(owner, scanId));
      const record = [...head.turns, ...head.decisions].find(t => t.mutationId === mutationId);
      if (record && matches && !matches(record, head)) return historyConflict();
      return record ? { duplicate: true as const, id: record.id, state: 'state' in record ? record.state : 'completed', epoch: head.epoch, revision: head.revision } : null;
    });
  }
  begin(owner: string, scanId: string, epoch: string, revision: number, turn: Turn, pending: Pending): HistoryHead {
    return this.transaction(() => {
      const scope = this.key(owner, scanId), head = this.read(scope); this.expected(head, epoch, revision);
      if (head.pending || [...head.turns, ...head.decisions].some(t => t.mutationId === turn.mutationId)) return historyConflict();
      const refs = head.turns.reduce((n, t) => n + (t.reply?.sources.length ?? 0), 0) + head.decisions.reduce((n, d) => n + d.sources.length, 0);
      if (head.turns.length >= HISTORY.turns || refs + HISTORY.citations > HISTORY.references) return historyCapacity();
      head.turns.push(turn); head.pending = pending; this.advance(head);
      // Include complete stored/private pending identity AND the actual public HTTP envelope.
      if (Math.max(bytes(head), bytes(historyProjection(head))) + HISTORY.completionReserve > HISTORY.scopeBytes) return historyCapacity();
      this.update(scope, head, revision);
      // Physically allocate completion headroom in the SAME bounded main DB before
      // quota/provider admission, not merely a process-local byte estimate.
      this.db.prepare('INSERT INTO history_completion_space VALUES(?,zeroblob(?))').run(scope, HISTORY.completionReserve);
      return head;
    });
  }
  decision(owner: string, scanId: string, epoch: string, revision: number, entry: Decision): HistoryHead {
    return this.transaction(() => {
      const scope = this.key(owner, scanId), head = this.read(scope); this.expected(head, epoch, revision);
      if (head.pending || [...head.turns, ...head.decisions].some(t => t.mutationId === entry.mutationId)) return historyConflict();
      if (head.decisions.length >= HISTORY.decisions) return historyCapacity();
      head.decisions.push(entry); this.advance(head); this.update(scope, head, revision); return head;
    });
  }
  guardPending<T>(owner: string, scanId: string, epoch: string, revision: number, pendingId: string, action: (head: HistoryHead) => T): T {
    return this.transaction(() => {
      const head = this.read(this.key(owner, scanId)); this.expected(head, epoch, revision);
      if (head.pending?.id !== pendingId || head.pending.deadline <= Date.now()) return historyConflict();
      const result = action(head);
      if (result && typeof result === 'object' && 'then' in result) return historyUnavailable();
      return result;
    });
  }
  associate(owner: string, scanId: string, epoch: string, revision: number, pendingId: string, reservation: string) {
    return this.guardPending(owner, scanId, epoch, revision, pendingId, head => {
      if (head.pending!.reservation) return historyConflict();
      head.pending!.reservation = reservation; this.update(this.key(owner, scanId), head, revision);
    });
  }
  finish(owner: string, scanId: string, epoch: string, revision: number, pendingId: string, reply: ChatReply) {
    return this.guardPending(owner, scanId, epoch, revision, pendingId, head => {
      const turn = head.turns.find(t => t.id === pendingId)!; turn.state = 'completed'; turn.reply = reply;
      head.pending = null; this.advance(head);
            const scope = this.key(owner, scanId); this.db.prepare('DELETE FROM history_completion_space WHERE scope=?').run(scope);
            this.update(scope, head, revision); return head;
    });
  }
  fail(owner: string, scanId: string, epoch: string, pendingId: string, state: 'failed' | 'cancelled' | 'interrupted') {
    return this.transaction(() => {
      const scope = this.key(owner, scanId), head = this.read(scope);
      if (head.epoch !== epoch || head.pending?.id !== pendingId) return false;
      const revision = head.revision; head.turns.find(t => t.id === pendingId)!.state = state; head.pending = null;
      this.advance(head); this.db.prepare('DELETE FROM history_completion_space WHERE scope=?').run(scope);
            this.update(scope, head, revision); return true;
    });
  }
  // Only expired pending operations are recovered online. A live second connection
  // must never terminalize a still-running operation during ordinary reads.
  recoverExpired() {
    return this.transaction(() => {
      for (const row of this.db.prepare('SELECT scope,epoch,revision,content,content_hash FROM history_head').all() as (Row & { scope: string })[]) {
        const head = this.decode(row);
        if (!head.pending || head.pending.deadline > Date.now()) continue;
        const revision = head.revision; head.turns.find(t => t.id === head.pending!.id)!.state = 'interrupted'; head.pending = null;
        this.advance(head); this.db.prepare('DELETE FROM history_completion_space WHERE scope=?').run(row.scope);
                this.update(row.scope, head, revision);
      }
    });
  }
  // Operator-only quiesced restore fencing; never called by GET/startup/generation.
  rotateRestoredLineage() {
    this.db.transaction(() => {
      this.safety();
      for (const row of this.db.prepare('SELECT scope,epoch,revision,content,content_hash FROM history_head').all() as (Row & { scope: string })[]) {
        const head = this.decode(row); head.epoch = randomUUID();
        if (head.pending) head.turns.find(t => t.id === head.pending!.id)!.state = 'interrupted'; head.pending = null;
        validateHead(head); this.db.prepare('DELETE FROM history_completion_space WHERE scope=?').run(row.scope);
        this.db.prepare('UPDATE history_head SET epoch=?,content=?,content_hash=? WHERE scope=?').run(head.epoch, JSON.stringify(head), hashValue(head), row.scope);
      }
      this.fileSafety();
      this.db.prepare('UPDATE history_meta SET incarnation=? WHERE id=1').run(randomUUID());
    }).immediate();
  }
}
