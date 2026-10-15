#!/usr/bin/env node
/**
 * Offline preservation helper with a SEPARATELY explicit consented additive
 * migration mode. Not a maintenance controller, account/quota initializer or
 * automatic recovery tool. ONLY explicit apply-migration may open original
 * existing auth/ledger SQLite handles RW; quota NEVER opens RW here.
 * Caller MUST close ingress, stop ALL writers, reconcile remote dispatches, hold
 * the refresh lock, and mount existing volumes read-only in ordinary mode. The
 * separately reviewed migration holder needs explicit RW auth/data mounts;
 * capture/plan/compare still use only O_RDONLY raw readers on those sources.
 * No application modules, env files, provider or daemon. Capture/plan/compare
 * NEVER open original SQLite handles; explicit apply is the only exception.
 *
 * Bounds (per capture, both volumes combined): raw/working/sealed each 256 MiB;
 * 2048 files, 256 directories, depth 8, 16 DBs, 512 tables/schema objects per DB,
 * 256 columns/table, 100000 rows/table, 250000 rows total, 1 MiB/cell,
 * 2 MiB encoded row, 64 MiB encoded cells total, 32 MiB manifest, 4 MiB schema.
 * SQLite cache 2 MiB/handle, no mmap, backup batches 64 pages/deadline 30s.
 * Row fingerprints are sorted (duplicates retained), not plaintext exports.
 * EACH capture needs >=800 MiB free, with pre retained during post. Two sets
 * can hold 2*(3*256 MiB +32 MiB manifests)=1600 MiB, plus bounded JS export
 * memory (64 MiB encoded cells), row fingerprints and SQLite/V8 overhead.
 * Explicit migration adds <=256 MiB dry-run DBs +32 MiB private plan +bounded
 * markers: <=1888 MiB retained, not a worst-case 2GiB memory-fit guarantee.
 * Transient SQLite journals, tmpfs accounting and JS/native overhead can exhaust
 * the unchanged parent limits; free-space/bounds failures MUST HOLD, not widen.
 * Parent's NEW backup-only proposed sandbox: UID/GID65532, /backup tmpfs2GiB,
 * memory2GiB/swap-total2GiB, CPU1/PIDs64, private bounded /tmp and holder lifetime.
 * These are supervision/review requirements, NOT grants or settings made here;
 * no native headroom/old-image/startup compatibility is asserted. This is NOT
 * a change to stopped history-proof resources. No CHOWN/DAC capability needed.
 * Unsuccessful captures remain private/incomplete; never retry over them.
 * Separate CURRENT-only compatibility /backup/pre reads <=16KiB private stdin
 * with exactly four raw null/string Auth settings (<=4096 UTF-8 bytes/value).
 * It revalidates private pre, opens only sealed RO DBs, creates no output, and
 * issues only {code,ok}. COMPATIBLE is conditional on CURRENT_PROFILE + parent
 * source/image/launch/optional-disabled guards, not an OLD-image or LIVE claim.
 * No extra holder/exec resource or time grant; parent supervises existing budget.
 */
import { createHash, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import * as fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const LIMITS = Object.freeze({
  bytes: 256 * 1024 ** 2, files: 2048, directories: 256, depth: 8, databases: 16,
  objects: 512, columns: 256, tableRows: 100000, rows: 250000,
  cellBytes: 1024 ** 2, rowBytes: 2 * 1024 ** 2, exportBytes: 64 * 1024 ** 2,
  manifestBytes: 32 * 1024 ** 2, schemaBytes: 4 * 1024 ** 2,
  freeBytes: 800 * 1024 ** 2, backupMs: 30000, recoveryMs: 30000,
});
const REQUIRED = ['auth/auth.sqlite', 'data/ledger.sqlite', 'auth/llm-usage.sqlite'];
const MAGIC = Buffer.from('SQLite format 3\0', 'binary');
// schema_version is a cache-invalidation cookie: SQLite backup legitimately
// changes it. Raw recovery preserves its bytes; logical equality compares the
// full schema objects and application/user versions, not this physical cookie.
const CODES = new Set(['CAPTURED', 'MATCH', 'MISMATCH', 'COMPATIBLE', 'INCOMPATIBLE',
  'PLANNED', 'MIGRATED', 'MIGRATION_MATCH', 'INVALID_ARGUMENTS',
  'UNSAFE_SOURCE', 'LIMIT', 'INVALID_STORE', 'INFLIGHT', 'IO_FAILURE']);
class Refusal extends Error {
  constructor(code) { super('Snapshot refused'); this.code = code; }
}
const requireThat = (ok, code = 'UNSAFE_SOURCE') => { if (!ok) throw new Refusal(code); };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const json = value => JSON.stringify(value);
const receipt = (ok, code) => Object.freeze({ code, ok });
const failure = error => receipt(false, error instanceof Refusal && CODES.has(error.code) ? error.code : 'IO_FAILURE');
const quote = name => '"' + name.replaceAll('"', '""') + '"';
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const meta = st => ({ mode: st.mode & 0o777, uid: st.uid, gid: st.gid });
const identity = st => [st.dev, st.ino, st.size, st.mode, st.uid, st.gid, st.nlink, st.mtimeMs, st.ctimeMs];
const same = (a, b) => json(a) === json(b);
const absent = p => { try { fs.lstatSync(p); return false; } catch (e) { if (e.code === 'ENOENT') return true; throw e; } };

function canonicalDirectory(p, privateDirectory = false) {
  requireThat(path.isAbsolute(p) && path.resolve(p) === p && fs.realpathSync(p) === p);
  const st = fs.lstatSync(p);
  requireThat(Number.isSafeInteger(st.dev) && Number.isSafeInteger(st.ino));
  requireThat(st.isDirectory() && !(st.mode & 0o7022));
  if (privateDirectory) requireThat((st.mode & 0o777) === 0o700 && st.uid === process.getuid());
  return st;
}

function inspectFile(p) {
  const st = fs.lstatSync(p);
  requireThat(Number.isSafeInteger(st.dev) && Number.isSafeInteger(st.ino));
  requireThat(st.isFile() && st.nlink === 1 && !(st.mode & 0o7022));
  requireThat(Number.isSafeInteger(st.size) && st.size <= LIMITS.bytes, 'LIMIT');
  return st;
}

function transfer(p, destination) {
  const before = inspectFile(p);
  const fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  let out;
  try {
    requireThat(same(identity(before), identity(fs.fstatSync(fd))));
    if (destination) out = fs.openSync(destination, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    const sha = createHash('sha256'), buffer = Buffer.alloc(1024 * 1024), header = Buffer.alloc(16);
    let bytes = 0;
    for (;;) {
      const n = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (!n) break;
      if (bytes < 16) buffer.copy(header, bytes, 0, Math.min(n, 16 - bytes));
      bytes += n;
      requireThat(bytes <= before.size && bytes <= LIMITS.bytes, 'LIMIT');
      sha.update(buffer.subarray(0, n));
      if (out !== undefined) {
        let offset = 0;
        while (offset < n) offset += fs.writeSync(out, buffer, offset, n - offset);
      }
    }
    requireThat(bytes === before.size && same(identity(before), identity(fs.fstatSync(fd))) && same(identity(before), identity(fs.lstatSync(p))));
    if (out !== undefined) fs.fsyncSync(out);
    return { bytes, sha256: sha.digest('hex'), sqlite: bytes >= 16 && header.equals(MAGIC) };
  } finally {
    if (out !== undefined) fs.closeSync(out);
    fs.closeSync(fd);
  }
}

function directoryNames(p) {
  const dir = fs.opendirSync(p), names = [];
  try {
    for (;;) {
      const entry = dir.readSync();
      if (!entry) break;
      requireThat(names.length < LIMITS.files + LIMITS.directories, 'LIMIT');
      names.push(entry.name);
    }
  } finally { dir.closeSync(); }
  return names.sort();
}

function inventory(roots, destination) {
  const entries = [], seen = new Set();
  let total = 0, files = 0, directories = 0;
  function visit(p, relative, depth) {
    requireThat(depth <= LIMITS.depth && Buffer.byteLength(relative) <= 4096, 'LIMIT');
    const st = fs.lstatSync(p), key = `${st.dev}:${st.ino}`;
    requireThat(!seen.has(key)); seen.add(key);
    if (st.isDirectory()) {
      canonicalDirectory(p);
      requireThat(++directories <= LIMITS.directories, 'LIMIT');
      entries.push({ path: relative, kind: 'directory', ...meta(st), sourceIdentity: identity(st) });
      if (destination) fs.mkdirSync(path.join(destination, relative), { mode: 0o700 });
      const names = directoryNames(p);
      requireThat(names.length <= LIMITS.files + LIMITS.directories, 'LIMIT');
      for (const name of names) {
        requireThat(name !== '.' && name !== '..' && !/[\u0000-\u001f\u007f]/.test(name) && Buffer.byteLength(name) <= 255);
        visit(path.join(p, name), relative + '/' + name, depth + 1);
      }
      requireThat(same(identity(st), identity(fs.lstatSync(p))));
    } else {
      requireThat(++files <= LIMITS.files, 'LIMIT');
      inspectFile(p); total += st.size;
      requireThat(total <= LIMITS.bytes, 'LIMIT');
      entries.push({ path: relative, kind: 'file', ...meta(st), sourceIdentity: identity(st), ...transfer(p, destination && path.join(destination, relative)) });
    }
  }
  for (const label of ['auth', 'data']) visit(roots[label], label, 0);
  return entries.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}

function classify(entries) {
  const files = new Map(entries.filter(e => e.kind === 'file').map(e => [e.path, e]));
  const databases = [...files.values()].filter(e => e.sqlite).map(e => e.path).sort();
  requireThat(databases.length <= LIMITS.databases, 'LIMIT');
  for (const required of REQUIRED) requireThat(files.get(required)?.sqlite, 'INVALID_STORE');
  const sides = new Set();
  for (const p of databases) {
    for (const suffix of ['-wal', '-shm', '-journal']) if (files.has(p + suffix)) sides.add(p + suffix);
  }
  for (const p of files.keys()) {
    if (/-wal$|-shm$|-journal$/.test(p)) requireThat(sides.has(p) && !files.get(p).sqlite, 'INVALID_STORE');
    if (/\.(?:sqlite|sqlite3|db)$/i.test(p)) requireThat(files.get(p).sqlite, 'INVALID_STORE');
  }
  return { databases, sides };
}

// Validate recovery inputs as bytes BEFORE any SQLite connection exists. SQLite
// may silently ignore a damaged WAL; integrity_check of that main-only view is
// therefore insufficient. Supported WALs have one complete checked generation,
// optionally with COMPLETE valid uncommitted frames after the last commit. No
// truncated/checksum-invalid/stale-salt tail is treated as harmless crash debris.
// Supported rollback journals have finite checksummed, sector-aligned hot
// segments only. Non-hot/zero-header, unbounded, partial or master-journal state
// refuses. Raw evidence is retained; no recovery input is repaired in place.
function byteFile(p, action) {
  const before = inspectFile(p), fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    requireThat(same(identity(before), identity(fs.fstatSync(fd))));
    const read = (offset, length) => {
      requireThat(Number.isSafeInteger(offset) && length >= 0 && offset >= 0 && offset + length <= before.size, 'INVALID_STORE');
      const buffer = Buffer.alloc(length);
      let n = 0;
      while (n < length) {
        const got = fs.readSync(fd, buffer, n, length - n, offset + n);
        requireThat(got > 0, 'INVALID_STORE'); n += got;
      }
      return buffer;
    };
    const result = action(read, before.size, before);
    requireThat(same(identity(before), identity(fs.fstatSync(fd))) && same(identity(before), identity(fs.lstatSync(p))));
    return result;
  } finally { fs.closeSync(fd); }
}
const powerOfTwo = n => Number.isInteger(n) && n >= 512 && n <= 65536 && (n & (n - 1)) === 0;
function mainHeader(p) {
  return byteFile(p, (read, bytes) => {
    requireThat(bytes >= 100, 'INVALID_STORE');
    const header = read(0, 100), encoded = header.readUInt16BE(16), pageSize = encoded === 1 ? 65536 : encoded;
    requireThat(header.subarray(0, 16).equals(MAGIC) && powerOfTwo(pageSize) && bytes % pageSize === 0 &&
      [1, 2].includes(header[18]) && header[18] === header[19], 'INVALID_STORE');
    return { pageSize, pages: bytes / pageSize, walFormat: header[18] === 2 };
  });
}
function walChecksum(buffer, state, bigEndian) {
  requireThat(buffer.length % 8 === 0, 'INVALID_STORE');
  let [a, b] = state;
  for (let i = 0; i < buffer.length; i += 8) {
    a = (a + (bigEndian ? buffer.readUInt32BE(i) : buffer.readUInt32LE(i)) + b) >>> 0;
    b = (b + (bigEndian ? buffer.readUInt32BE(i + 4) : buffer.readUInt32LE(i + 4)) + a) >>> 0;
  }
  return [a, b];
}
function validateWal(p, main, deadline) {
  return byteFile(p, (read, bytes) => {
    if (bytes === 0) return { kind: 'empty-wal', pageSize: main.pageSize, pages: main.pages, pageOffsets: new Map(), frames: 0, commits: 0, lastCommit: 0 };
    requireThat(main.walFormat && bytes >= 32, 'INVALID_STORE');
    const header = read(0, 32), magic = header.readUInt32BE(0), pageSize = header.readUInt32BE(8);
    requireThat([0x377f0682, 0x377f0683].includes(magic) && header.readUInt32BE(4) === 3007000 &&
      powerOfTwo(pageSize) && pageSize === main.pageSize && (bytes - 32) % (pageSize + 24) === 0, 'INVALID_STORE');
    const bigEndian = magic === 0x377f0683, salts = header.subarray(16, 24);
    let state = walChecksum(header.subarray(0, 24), [0, 0], bigEndian);
    requireThat(state[0] === header.readUInt32BE(24) && state[1] === header.readUInt32BE(28), 'INVALID_STORE');
    const frames = (bytes - 32) / (pageSize + 24), maxPage = Math.floor(LIMITS.bytes / pageSize);
    let lastCommit = 0, pages = main.pages, commits = 0;
    for (let i = 0; i < frames; i++) {
      requireThat(Date.now() <= deadline, 'LIMIT');
      const offset = 32 + i * (pageSize + 24), frame = read(offset, 24), page = read(offset + 24, pageSize);
      const number = frame.readUInt32BE(0), commitPages = frame.readUInt32BE(4);
      requireThat(number > 0 && number <= maxPage && commitPages <= maxPage && frame.subarray(8, 16).equals(salts), 'INVALID_STORE');
      state = walChecksum(frame.subarray(0, 8), state, bigEndian);
      state = walChecksum(page, state, bigEndian);
      requireThat(state[0] === frame.readUInt32BE(16) && state[1] === frame.readUInt32BE(20), 'INVALID_STORE');
      if (commitPages) { lastCommit = i + 1; pages = commitPages; commits++; }
    }
    // A second bounded pass chooses exactly the final committed page images;
    // complete uncommitted tails cannot overwrite the committed snapshot.
    const pageOffsets = new Map();
    for (let i = 0; i < lastCommit; i++) {
      requireThat(Date.now() <= deadline, 'LIMIT');
      const offset = 32 + i * (pageSize + 24), number = read(offset, 4).readUInt32BE(0);
      if (number <= pages) pageOffsets.set(number, offset + 24);
    }
    return { kind: 'wal', pageSize, pages, frames, commits, lastCommit, pageOffsets };
  });
}
const JOURNAL_MAGIC = Buffer.from([0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]);
function validateJournal(p, main, deadline) {
  return byteFile(p, (read, bytes) => {
    if (!bytes) return { kind: 'empty-journal', pageSize: main.pageSize, pages: main.pages, pageOffsets: new Map(), records: 0, segments: 0 };
    requireThat(!main.walFormat, 'INVALID_STORE');
    let offset = 0, records = 0, segments = 0, pages;
    const pageOffsets = new Map();
    while (offset < bytes) {
      requireThat(Date.now() <= deadline, 'LIMIT');
      const header = read(offset, 28), n = header.readUInt32BE(8), nonce = header.readUInt32BE(12);
      const originalPages = header.readUInt32BE(16), sector = header.readUInt32BE(20), pageSize = header.readUInt32BE(24);
      requireThat(header.subarray(0, 8).equals(JOURNAL_MAGIC) && n > 0 && n !== 0xffffffff &&
        originalPages > 0 && originalPages <= LIMITS.bytes / main.pageSize && powerOfTwo(sector) &&
        pageSize === main.pageSize && offset % sector === 0 && offset + sector + n * (pageSize + 8) <= bytes, 'INVALID_STORE');
      requireThat(read(offset + 28, sector - 28).every(b => b === 0), 'INVALID_STORE');
      requireThat(pages === undefined || pages === originalPages, 'INVALID_STORE'); pages = originalPages; segments++;
      offset += sector;
      for (let i = 0; i < n; i++) {
        requireThat(Date.now() <= deadline, 'LIMIT');
        const number = read(offset, 4).readUInt32BE(0), page = read(offset + 4, pageSize);
        requireThat(number > 0 && number <= pages && !pageOffsets.has(number), 'INVALID_STORE');
        let checksum = nonce;
        for (let j = pageSize - 200; j > 0; j -= 200) checksum = (checksum + page[j]) >>> 0;
        requireThat(checksum === read(offset + 4 + pageSize, 4).readUInt32BE(0), 'INVALID_STORE');
        pageOffsets.set(number, offset + 4); records++; offset += pageSize + 8;
      }
      if (offset < bytes) {
        const next = Math.ceil(offset / sector) * sector;
        requireThat(next <= bytes && read(offset, next - offset).every(b => b === 0), 'INVALID_STORE');
        offset = next;
      }
    }
    return { kind: 'journal', pageSize: main.pageSize, pages, records, segments, pageOffsets };
  });
}
function recoveryInputs(root, relative) {
  const mainPath = path.join(root, relative), main = mainHeader(mainPath), deadline = Date.now() + LIMITS.recoveryMs;
  const walPath = mainPath + '-wal', journalPath = mainPath + '-journal';
  const hasWal = !absent(walPath), hasJournal = !absent(journalPath);
  requireThat(!(hasWal && hasJournal), 'INVALID_STORE');
  let recovery = { kind: 'main', pageSize: main.pageSize, pages: main.pages, pageOffsets: new Map() };
  if (hasWal) recovery = validateWal(walPath, main, deadline);
  if (hasJournal) recovery = validateJournal(journalPath, main, deadline);
  requireThat(recovery.pages * recovery.pageSize <= LIMITS.bytes, 'LIMIT');
  const { pageOffsets, ...summary } = recovery;
  return { ...recovery, main, sidecar: hasWal ? walPath : hasJournal ? journalPath : null, summary: { format: 'checked-recovery-v1', ...summary } };
}
function checkRecoveredImage(root, relative, sealed, recovery) {
  const deadline = Date.now() + LIMITS.recoveryMs;
  // SQLite backup/DELETE normalization legitimately change these page-1 header
  // bookkeeping fields. No btree payload/user_version/application_id is masked.
  const normalize = page => {
    page.fill(0, 18, 20); page.fill(0, 24, 32); page.fill(0, 40, 44); page.fill(0, 92, 100); return page;
  };
  byteFile(path.join(root, relative), (mainRead, mainBytes) => byteFile(sealed, (sealedRead, bytes) => {
    const compare = sideRead => {
      requireThat(bytes === recovery.pages * recovery.pageSize, 'INVALID_STORE');
      for (let number = 1; number <= recovery.pages; number++) {
        requireThat(Date.now() <= deadline, 'LIMIT');
        const offset = (number - 1) * recovery.pageSize, sideOffset = recovery.pageOffsets.get(number);
        const expected = sideOffset !== undefined ? sideRead(sideOffset, recovery.pageSize) :
          offset + recovery.pageSize <= mainBytes ? mainRead(offset, recovery.pageSize) : Buffer.alloc(recovery.pageSize);
        const actual = sealedRead(offset, recovery.pageSize);
        requireThat((number === 1 ? normalize(expected).equals(normalize(actual)) : expected.equals(actual)), 'INVALID_STORE');
      }
    };
    if (recovery.sidecar) byteFile(recovery.sidecar, read => compare(read)); else compare(null);
  }));
}

function tune(db) {
  db.defaultSafeIntegers(true);
  db.pragma('busy_timeout = 1000');
  db.pragma('cache_size = -2048');
  db.pragma('mmap_size = 0');
  db.pragma('temp_store = FILE');
  // This read lets SQLite recover a hot journal ONLY in the private working copy.
  db.pragma('schema_version', { simple: true });
  db.pragma('query_only = ON');
}

function verify(db) {
  requireThat(db.prepare('PRAGMA integrity_check(1)').raw().get()?.[0] === 'ok', 'INVALID_STORE');
  requireThat(db.prepare('PRAGMA foreign_key_check').raw().get() === undefined, 'INVALID_STORE');
}

// Structural recognition of PUBLIC schemas, NOT old-image startup proof. The
// parent still needs hash/image-bound no-DDL/no-bootstrap compatibility BEFORE
// starting the original immutable API image; CAPTURED/MATCH never assert it.
function requiredTable(db, name, expected, strict = false) {
  const table = db.prepare('PRAGMA table_list').all().find(t => t.schema === 'main' && t.name === name);
  requireThat(table?.type === 'table' && table.wr === 0n && table.strict === (strict ? 1n : 0n), 'INVALID_STORE');
  const actual = db.prepare(`PRAGMA table_xinfo(${quote(name)})`).all();
  requireThat(actual.length === expected.length && expected.every(([column, type, notnull = 0, pk = 0, defaultValue = null], i) =>
    actual[i].name === column && actual[i].type.toUpperCase() === type && actual[i].notnull === BigInt(notnull) &&
    actual[i].pk === BigInt(pk) && actual[i].hidden === 0n && actual[i].dflt_value === defaultValue), 'INVALID_STORE');
}
function requiredForeignKey(db, table, from, target, to, onDelete = 'NO ACTION') {
  const keys = db.prepare(`PRAGMA foreign_key_list(${quote(table)})`).all();
  requireThat(keys.some(k => k.from === from && k.table === target && k.to === to && k.on_delete === onDelete && k.on_update === 'NO ACTION'), 'INVALID_STORE');
}
function requiredIndex(db, table, columns, unique, name) {
  const indexes = db.prepare(`PRAGMA index_list(${quote(table)})`).all();
  requireThat(indexes.some(i => (!name || i.name === name) && i.unique === (unique ? 1n : 0n) && i.partial === 0n &&
    same(db.prepare(`PRAGMA index_info(${quote(i.name)})`).all().map(c => c.name), columns)), 'INVALID_STORE');
}
const idColumn = ['id', 'TEXT', 0, 1];
const scanIdColumn = ['scan_id', 'TEXT', 0, 1];
const scanColumns = [idColumn, ['subject', 'TEXT', 1], ['idempotency_key', 'TEXT', 1], ['registry', 'TEXT', 1],
  ['repository', 'TEXT', 1], ['digest', 'TEXT', 1], ['platform', 'TEXT', 1], ['state', 'TEXT', 1],
  ['created_at', 'TEXT', 1, 0, 'CURRENT_TIMESTAMP'], ['fingerprint', 'TEXT'],
  ['checks', 'TEXT', 1, 0, "'[]'"], ['scope', 'TEXT', 1, 0, "'image'"], ['terminal_at', 'TEXT']];
function requiredSchemas(db, relative) {
  const application = db.pragma('application_id', { simple: true }), version = db.pragma('user_version', { simple: true });
  if (relative === 'auth/auth.sqlite') {
    requireThat(application === 0n && version === 0n, 'INVALID_STORE');
    requiredTable(db, 'users', [idColumn, ['email', 'TEXT', 1], ['salt', 'TEXT', 1], ['password_hash', 'BLOB', 1]]);
    requiredTable(db, 'sessions', [['token_hash', 'TEXT', 0, 1], ['user_id', 'TEXT', 1], ['expires_at', 'INTEGER', 1], ['revoked_at', 'INTEGER']]);
    requiredTable(db, 'auth_attempts', [['bucket', 'TEXT', 0, 1], ['count', 'INTEGER', 1], ['expires_at', 'INTEGER', 1]]);
    requiredTable(db, 'trusted_sessions', [['token_hash', 'TEXT', 0, 1], ['session_id', 'TEXT', 1], ['generation', 'INTEGER', 1]]);
    requiredTable(db, 'browser_access', [['id', 'INTEGER', 0, 1], ['fingerprint', 'TEXT', 1], ['incarnation', 'TEXT', 1]]);
    requiredForeignKey(db, 'sessions', 'user_id', 'users', 'id');
    requiredForeignKey(db, 'trusted_sessions', 'token_hash', 'sessions', 'token_hash', 'CASCADE');
    requiredIndex(db, 'users', ['email'], true);
    requiredIndex(db, 'trusted_sessions', ['session_id'], true);
    requiredIndex(db, 'sessions', ['user_id', 'expires_at'], false, 'sessions_user');
    const malformedHex = (c, n) => `typeof(${c})!='text' OR length(${c})!=${n} OR ${c} GLOB '*[^0-9a-f]*'`;
    requireThat(!db.prepare(`SELECT 1 FROM users WHERE ${malformedHex('id', 32)} OR ${malformedHex('salt', 32)} OR typeof(password_hash)!='blob' OR length(password_hash)!=64 LIMIT 1`).get(), 'INVALID_STORE');
    requireThat(!db.prepare(`SELECT 1 FROM sessions WHERE ${malformedHex('token_hash', 64)} OR ${malformedHex('user_id', 32)} OR typeof(expires_at)!='integer' OR expires_at<0 LIMIT 1`).get(), 'INVALID_STORE');
    requireThat(!db.prepare(`SELECT 1 FROM trusted_sessions WHERE ${malformedHex('token_hash', 64)} OR ${malformedHex('session_id', 32)} OR typeof(generation)!='integer' OR generation<1 LIMIT 1`).get(), 'INVALID_STORE');
    // Public startup INSERT OR IGNORE must have nothing to backfill. The actual
    // configuration fingerprint comparison belongs to the private controller.
    requireThat(!db.prepare('SELECT 1 FROM sessions s LEFT JOIN trusted_sessions t USING(token_hash) WHERE t.token_hash IS NULL LIMIT 1').get(), 'INVALID_STORE');
    requireThat(db.prepare('SELECT count(*) FROM browser_access').raw().get()[0] === 1n &&
      !db.prepare(`SELECT 1 FROM browser_access WHERE id!=1 OR ${malformedHex('fingerprint', 64)} OR ${malformedHex('incarnation', 32)} LIMIT 1`).get(), 'INVALID_STORE');
  } else if (relative === 'data/ledger.sqlite') {
    // Recognize the documented v8..v14 families without assuming the old image
    // is the CURRENT migrator. Recognition does not authorize v8->v14 startup.
    requireThat(application === 0n && version >= 8n && version <= 14n, 'INVALID_STORE');
    requiredTable(db, 'scans', scanColumns);
    requiredTable(db, 'outbox', [scanIdColumn, ['delivered_at', 'TEXT'], ['attempts', 'INTEGER', 1, 0, '0'], ['lease_until', 'INTEGER'], ['next_run_at', 'INTEGER', 1, 0, '0']]);
    requiredForeignKey(db, 'outbox', 'scan_id', 'scans', 'id'); requiredIndex(db, 'scans', ['subject', 'idempotency_key'], true);
    requiredTable(db, 'scan_results', [scanIdColumn, ['check_name', 'TEXT', 1], ['finding_count', 'INTEGER', version < 9n ? 1 : 0],
      ['coverage', 'TEXT', 1], ['created_at', 'TEXT', 1, 0, 'CURRENT_TIMESTAMP'], ['scanner_version', 'TEXT'], ['outcome', 'TEXT', 1, 0, "'unsupported'"], ['error_code', 'TEXT']]);
    requiredTable(db, 'admission_windows', [['subject', 'TEXT', 1, 1], ['minute', 'INTEGER', 1, 2], ['count', 'INTEGER', 1]]);
    requiredTable(db, 'scan_findings', [['scan_id', 'TEXT', 1, 1], ['finding_id', 'TEXT', 1, 2], ['rule_id', 'TEXT', 1], ['line', 'INTEGER'], ['evidence_ref', 'TEXT', 1]]);
    requiredTable(db, 'scan_events', [['seq', 'INTEGER', 0, 1], ['scan_id', 'TEXT', 1], ['state', 'TEXT', 1], ['created_at', 'TEXT', 1, 0, 'CURRENT_TIMESTAMP']]);
    requiredTable(db, 'scan_audit', [['id', 'INTEGER', 0, 1], ['created_at', 'TEXT', 1, 0, 'CURRENT_TIMESTAMP'], ['subject', 'TEXT', 1], ['target', 'TEXT', 1], ['scope', 'TEXT', 1], ['decision', 'TEXT', 1], ['reason', 'TEXT', 1], ['scan_id', 'TEXT']]);
    requiredTable(db, 'scan_sbom_results', [scanIdColumn, ['image', 'TEXT'], ['platform', 'TEXT'], ['os_name', 'TEXT'], ['os_version', 'TEXT'], ['component_count', 'INTEGER'], ['coverage', 'TEXT', 1], ['outcome', 'TEXT', 1], ['scanner_version', 'TEXT'], ['error_code', 'TEXT'], ['checked_at', 'TEXT']]);
    requiredTable(db, 'scan_sbom_components', [['scan_id', 'TEXT', 1, 1], ['ordinal', 'INTEGER', 1, 2], ['ecosystem', 'TEXT', 1], ['name', 'TEXT', 1], ['version', 'TEXT', 1]]);
    requiredTable(db, 'scan_vuln_results', [scanIdColumn, ['image', 'TEXT'], ['platform', 'TEXT'], ['finding_count', 'INTEGER'], ['coverage', 'TEXT', 1], ['outcome', 'TEXT', 1], ['scanner_version', 'TEXT'], ['error_code', 'TEXT'], ['checked_at', 'TEXT']]);
    requiredTable(db, 'scan_vuln_findings', [['scan_id', 'TEXT', 1, 1], ['ordinal', 'INTEGER', 1, 2], ['finding_id', 'TEXT', 1], ['cve_id', 'TEXT', 1], ['ecosystem', 'TEXT', 1], ['package_name', 'TEXT', 1], ['installed_version', 'TEXT', 1], ['severity', 'TEXT', 1], ['severity_sources', 'TEXT', 1], ['provenance_ref', 'TEXT', 1], ['fixed_version', 'TEXT'], ...(version >= 13n ? [['advisory', 'TEXT']] : [])]);
    if (version >= 10n) requiredTable(db, 'scan_archive_results', [scanIdColumn, ['attempt', 'INTEGER', 1], ['report', 'TEXT', 1]]);
    if (version >= 11n) requiredTable(db, 'scan_check_results', [['scan_id', 'TEXT', 1, 1], ['check_name', 'TEXT', 1, 2], ['attempt', 'INTEGER', 1], ['outcome', 'TEXT', 1], ['checks_version', 'TEXT', 1], ['resource_policy_version', 'TEXT', 1], ['report', 'TEXT', 1], ['checked_at', 'TEXT', 1, 0, 'CURRENT_TIMESTAMP']]);
    if (version >= 12n) requiredTable(db, 'scan_execution_profiles', [scanIdColumn, ['binding', 'TEXT', 1]]);
    if (version >= 14n) {
      requiredTable(db, 'scan_cve_policy', [scanIdColumn, ['policy', 'TEXT', 1], ['result_contract_version', 'INTEGER', 1]]);
      requiredTable(db, 'scan_cve_evidence', [scanIdColumn, ['attempt', 'INTEGER', 1], ['evidence', 'TEXT', 1]]);
    }
    const states = version >= 9n ? "'queued','running','completed','failed','cancelled','partial'" : "'queued','running','completed','failed','cancelled'";
    requireThat(!db.prepare(`SELECT 1 FROM scans WHERE state NOT IN (${states}) LIMIT 1`).get(), 'INVALID_STORE');
  } else if (relative === 'auth/llm-usage.sqlite') {
    requireThat(application === 1145655601n && version === 1n && db.pragma('page_size', { simple: true }) === 4096n, 'INVALID_STORE');
    requiredTable(db, 'quota_meta', [['id', 'INTEGER', 0, 1], ['clock', 'INTEGER', 1]], true);
    requiredTable(db, 'quota_attempt', [['id', 'TEXT', 1, 1], ['user_key', 'TEXT', 1], ['scan_key', 'TEXT', 1], ['report_hash', 'TEXT', 1], ['policy_hash', 'TEXT', 1], ['request_hash', 'TEXT', 1], ['quota_policy', 'TEXT', 1], ['window', 'INTEGER', 1], ['expires', 'INTEGER', 1], ['state', 'TEXT', 1], ['reserve_input', 'INTEGER', 1], ['reserve_output', 'INTEGER', 1], ['reserve_cost', 'INTEGER', 1], ['input', 'INTEGER', 1], ['output', 'INTEGER', 1], ['cost', 'INTEGER', 1], ['receipt', 'TEXT']], true);
    requiredIndex(db, 'quota_attempt', ['user_key', 'window', 'state'], false, 'quota_user');
    requiredIndex(db, 'quota_attempt', ['scan_key', 'window', 'state'], false, 'quota_scan');
    requiredIndex(db, 'quota_attempt', ['state', 'window'], false, 'quota_cleanup');
    requireThat(db.prepare('SELECT count(*) FROM quota_meta WHERE id=1 AND clock>=0').raw().get()[0] === 1n &&
      db.prepare('SELECT count(*) FROM quota_meta').raw().get()[0] === 1n, 'INVALID_STORE');
    requireThat(!db.prepare("SELECT 1 FROM quota_attempt WHERE state NOT IN ('reserved','dispatched','settled','released','fault') OR input<0 OR output<0 OR cost<0 OR reserve_input<0 OR reserve_output<0 OR reserve_cost<0 LIMIT 1").get(), 'INVALID_STORE');
  }
}

// CURRENT source-only overlay profile, NOT an OLD-image compatibility profile.
// Parent MUST independently bind the candidate API+worker/launch closure to this
// aggregate and guard history disabled, RUNTIME_DB_PATH absent/empty and no live
// runtime injection. No source/image/optional-consumer qualification is done here.
// These version pairs are predicates, never claims of observed original state.
export const CURRENT_PROFILE = Object.freeze({
  sourceAggregate: '29c3ca5bd186d625cc102e2f7e43b4f1e8e168ba3372cabd7840cc21b6676a37',
  auth: '0/0', ledger: '0/14', quota: '1145655601/1',
});
const AUTH_KEYS = Object.freeze(['AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP',
  'SCAN_BROWSER_ALLOWED_USER_IDS', 'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS']);
const AUTH_INPUT_BYTES = 16384, AUTH_VALUE_BYTES = 4096;

// A deliberately flat JSON grammar detects duplicate DECODED keys (including
// escape aliases) before JSON.parse could overwrite them. No defaults/trim or
// boolean coercion: absent environment values are explicit null, empty is ''.
function authoritySettings(bytes) {
  requireThat(Buffer.isBuffer(bytes) && bytes.length <= AUTH_INPUT_BYTES, 'LIMIT');
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { throw new Refusal('INVALID_ARGUMENTS'); }
  let offset = 0;
  const skip = () => { while (/[\t\n\r ]/.test(text[offset] ?? '') && offset < text.length) offset++; };
  const take = token => { skip(); requireThat(text[offset++] === token, 'INVALID_ARGUMENTS'); };
  const string = () => {
    skip();
    const match = /"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/y;
    match.lastIndex = offset;
    const found = match.exec(text);
    requireThat(found !== null, 'INVALID_ARGUMENTS'); offset = match.lastIndex;
    return JSON.parse(found[0]);
  };
  const values = new Map(); take('{'); skip();
  if (text[offset] !== '}') for (;;) {
    const key = string();
    requireThat(AUTH_KEYS.includes(key) && !values.has(key), 'INVALID_ARGUMENTS'); take(':'); skip();
    let value;
    if (text.slice(offset, offset + 4) === 'null') { value = null; offset += 4; }
    else {
      value = string();
      requireThat(Buffer.byteLength(value) <= AUTH_VALUE_BYTES, 'LIMIT');
      requireThat(!value.includes('\0') && !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value), 'INVALID_ARGUMENTS');
    }
    values.set(key, value); skip();
    if (text[offset] !== ',') break;
    offset++;
  }
  take('}'); skip();
  requireThat(offset === text.length && values.size === AUTH_KEYS.length, 'INVALID_ARGUMENTS');
  return AUTH_KEYS.map(key => values.get(key));
}
async function authorityInput(stream) {
  let timer;
  try {
    return await Promise.race([
      (async () => {
        const chunks = []; let size = 0;
        for await (const chunk of stream) {
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          size += bytes.length; requireThat(size <= AUTH_INPUT_BYTES, 'LIMIT'); chunks.push(bytes);
        }
        return Buffer.concat(chunks, size);
      })(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Refusal('LIMIT')), LIMITS.backupMs); }),
    ]);
  } finally { clearTimeout(timer); stream.destroy?.(); }
}

// Literal PUBLIC CURRENT DDL, pending independent profile review, never SQL
// executed by this helper or caller-provided profile input. Comparing the
// complete token stream retains CHECK/FK/conflict/collation/default expressions.
// Only whitespace, SQL-keyword/identifier case and ordinary identifier quoting
// are normalized. String literals, token order and operators stay exact.
function ddlTokens(sql) {
  requireThat(typeof sql === 'string' && Buffer.byteLength(sql) <= LIMITS.cellBytes, 'INCOMPATIBLE');
  const tokens = [];
  const lex = /[ \t\r\n\f]+|'(?:[^']|'')*'|"(?:[^"]|"")*"|`(?:[^`]|``)*`|\[[^\]]*\]|[A-Za-z_][A-Za-z_0-9]*|[0-9]+|<=|>=|!=|<>|[(),=<>+*-]/y;
  let offset = 0;
  while (offset < sql.length) {
    lex.lastIndex = offset; const found = lex.exec(sql);
    requireThat(found !== null, 'INCOMPATIBLE'); offset = lex.lastIndex;
    let token = found[0];
    if (/^\s/.test(token)) continue;
    if (token[0] === "'") tokens.push(['literal', token]);
    else {
      const quoted = ['"', '`', '['].includes(token[0]);
      if (token[0] === '"') token = token.slice(1, -1).replaceAll('""', '"');
      else if (token[0] === '`') token = token.slice(1, -1).replaceAll('``', '`');
      else if (token[0] === '[') token = token.slice(1, -1);
      // Do not equate DQS strings like "0"/"NULL" with numeric/SQL literals.
      if (quoted) requireThat(/^[A-Za-z_][A-Za-z_0-9]*$/.test(token) &&
        !/^(create|table|index|primary|key|not|null|unique|text|blob|integer|references|on|delete|cascade|check|default|current_timestamp|in|and|or|is|between|cast|as|autoincrement|strict)$/i.test(token), 'INCOMPATIBLE');
      tokens.push(['token', token.toLowerCase()]);
    }
  }
  return tokens;
}
const CURRENT_DDL = Object.freeze({
  'auth/auth.sqlite': [
    `CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT NOT NULL UNIQUE,salt TEXT NOT NULL,password_hash BLOB NOT NULL)`,
    `CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),expires_at INTEGER NOT NULL,revoked_at INTEGER)`,
    `CREATE INDEX sessions_user ON sessions(user_id,expires_at)`,
    `CREATE TABLE auth_attempts(bucket TEXT PRIMARY KEY,count INTEGER NOT NULL,expires_at INTEGER NOT NULL)`,
    `CREATE TABLE trusted_sessions(token_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,session_id TEXT NOT NULL UNIQUE,generation INTEGER NOT NULL CHECK(generation>0))`,
    `CREATE TABLE browser_access(id INTEGER PRIMARY KEY CHECK(id=1),fingerprint TEXT NOT NULL,incarnation TEXT NOT NULL)`,
  ],
  'data/ledger.sqlite': [
    `CREATE TABLE scans(id TEXT PRIMARY KEY,subject TEXT NOT NULL,idempotency_key TEXT NOT NULL,registry TEXT NOT NULL,repository TEXT NOT NULL,digest TEXT NOT NULL,platform TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('queued','running','completed','failed','cancelled','partial')),created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,fingerprint TEXT,checks TEXT NOT NULL DEFAULT '[]',scope TEXT NOT NULL DEFAULT 'image',terminal_at TEXT,UNIQUE(subject,idempotency_key))`,
    `CREATE TABLE outbox(scan_id TEXT PRIMARY KEY REFERENCES scans(id),delivered_at TEXT,attempts INTEGER NOT NULL DEFAULT 0,lease_until INTEGER,next_run_at INTEGER NOT NULL DEFAULT 0)`,
    `CREATE TABLE scan_results(scan_id TEXT PRIMARY KEY REFERENCES scans(id),check_name TEXT NOT NULL CHECK(check_name='secret'),finding_count INTEGER CHECK(finding_count>=0),coverage TEXT NOT NULL CHECK(coverage='image'),created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,scanner_version TEXT,outcome TEXT NOT NULL DEFAULT 'unsupported',error_code TEXT,CHECK((outcome='failed' AND finding_count IS NULL) OR (outcome='checked' AND finding_count IS NOT NULL) OR outcome NOT IN ('failed','checked')))`,
    `CREATE TABLE admission_windows(subject TEXT NOT NULL,minute INTEGER NOT NULL,count INTEGER NOT NULL,PRIMARY KEY(subject,minute))`,
    `CREATE TABLE scan_findings(scan_id TEXT NOT NULL REFERENCES scans(id),finding_id TEXT NOT NULL,rule_id TEXT NOT NULL,line INTEGER,evidence_ref TEXT NOT NULL,PRIMARY KEY(scan_id,finding_id))`,
    `CREATE TABLE scan_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,scan_id TEXT NOT NULL REFERENCES scans(id),state TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE INDEX scan_events_by_scan ON scan_events(scan_id,seq)`,
    `CREATE TABLE scan_audit(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,subject TEXT NOT NULL,target TEXT NOT NULL,scope TEXT NOT NULL,decision TEXT NOT NULL,reason TEXT NOT NULL,scan_id TEXT)`,
    `CREATE TABLE scan_sbom_results(scan_id TEXT PRIMARY KEY REFERENCES scans(id),image TEXT,platform TEXT CHECK(platform='linux/amd64'),os_name TEXT CHECK(os_name='alpine'),os_version TEXT,component_count INTEGER CHECK(component_count BETWEEN 1 AND 1000),coverage TEXT NOT NULL CHECK(coverage='image'),outcome TEXT NOT NULL CHECK(outcome IN ('checked','failed')),scanner_version TEXT,error_code TEXT CHECK(error_code IN ('SCAN_FAILED','SCAN_TIMEOUT','SCAN_UNAVAILABLE')),checked_at TEXT,CHECK((outcome='checked' AND image IS NOT NULL AND platform IS NOT NULL AND os_name IS NOT NULL AND os_version IS NOT NULL AND component_count IS NOT NULL AND scanner_version IS NOT NULL AND checked_at IS NOT NULL AND error_code IS NULL) OR (outcome='failed' AND image IS NULL AND platform IS NULL AND os_name IS NULL AND os_version IS NULL AND component_count IS NULL AND scanner_version IS NULL AND checked_at IS NULL AND error_code IS NOT NULL)))`,
    `CREATE TABLE scan_sbom_components(scan_id TEXT NOT NULL REFERENCES scans(id),ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 999),ecosystem TEXT NOT NULL CHECK(ecosystem IN ('apk','npm')),name TEXT NOT NULL,version TEXT NOT NULL,PRIMARY KEY(scan_id,ordinal),UNIQUE(scan_id,ecosystem,name,version))`,
    `CREATE TABLE scan_vuln_results(scan_id TEXT PRIMARY KEY REFERENCES scans(id),image TEXT,platform TEXT CHECK(platform='linux/amd64'),finding_count INTEGER CHECK(finding_count BETWEEN 0 AND 1000),coverage TEXT NOT NULL CHECK(coverage='image'),outcome TEXT NOT NULL CHECK(outcome IN ('checked','failed')),scanner_version TEXT,error_code TEXT CHECK(error_code IN ('SCAN_FAILED','SCAN_TIMEOUT','SCAN_UNAVAILABLE')),checked_at TEXT,CHECK((outcome='checked' AND image IS NOT NULL AND platform IS NOT NULL AND finding_count IS NOT NULL AND scanner_version IS NOT NULL AND checked_at IS NOT NULL AND error_code IS NULL) OR (outcome='failed' AND image IS NULL AND platform IS NULL AND finding_count IS NULL AND scanner_version IS NULL AND checked_at IS NULL AND error_code IS NOT NULL)))`,
    `CREATE TABLE scan_vuln_findings(scan_id TEXT NOT NULL REFERENCES scans(id),ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 999),finding_id TEXT NOT NULL,cve_id TEXT NOT NULL,ecosystem TEXT NOT NULL CHECK(ecosystem IN ('apk','npm')),package_name TEXT NOT NULL,installed_version TEXT NOT NULL,severity TEXT NOT NULL CHECK(severity IN ('UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL')),severity_sources TEXT NOT NULL,provenance_ref TEXT NOT NULL,fixed_version TEXT,advisory TEXT CHECK(advisory IS NULL OR length(CAST(advisory AS BLOB))<=16384),PRIMARY KEY(scan_id,ordinal),UNIQUE(scan_id,finding_id))`,
    `CREATE TABLE scan_archive_results(scan_id TEXT PRIMARY KEY REFERENCES scans(id),attempt INTEGER NOT NULL CHECK(attempt>0),report TEXT NOT NULL CHECK(length(report)<=2000000))`,
    `CREATE TABLE scan_check_results(scan_id TEXT NOT NULL REFERENCES scans(id),check_name TEXT NOT NULL CHECK(check_name='config'),attempt INTEGER NOT NULL CHECK(attempt>0),outcome TEXT NOT NULL CHECK(outcome IN ('checked','unsupported','failed','skipped')),checks_version TEXT NOT NULL CHECK(checks_version='image-config-user-v1'),resource_policy_version TEXT NOT NULL CHECK(resource_policy_version='image-config-policy-v1'),report TEXT NOT NULL CHECK(length(CAST(report AS BLOB))<=16384),checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(scan_id,check_name))`,
    `CREATE TABLE scan_execution_profiles(scan_id TEXT PRIMARY KEY REFERENCES scans(id),binding TEXT NOT NULL CHECK(length(CAST(binding AS BLOB))<=1024))`,
    `CREATE TABLE scan_cve_policy(scan_id TEXT PRIMARY KEY REFERENCES scans(id),policy TEXT NOT NULL CHECK(policy IN ('legacy-db-freshness-v1','cve-db-updated-at-14d-v2')),result_contract_version INTEGER NOT NULL,CHECK((policy='legacy-db-freshness-v1' AND result_contract_version=1) OR (policy='cve-db-updated-at-14d-v2' AND result_contract_version=2)))`,
    `CREATE TABLE scan_cve_evidence(scan_id TEXT PRIMARY KEY REFERENCES scans(id),attempt INTEGER NOT NULL CHECK(attempt>0),evidence TEXT NOT NULL CHECK(length(CAST(evidence AS BLOB))<=8192))`,
    `CREATE TABLE sqlite_sequence(name,seq)`,
  ],
  'auth/llm-usage.sqlite': [
    `CREATE TABLE quota_meta(id INTEGER PRIMARY KEY CHECK(id=1),clock INTEGER NOT NULL) STRICT`,
    `CREATE TABLE quota_attempt(id TEXT PRIMARY KEY,user_key TEXT NOT NULL,scan_key TEXT NOT NULL,report_hash TEXT NOT NULL,policy_hash TEXT NOT NULL,request_hash TEXT NOT NULL,quota_policy TEXT NOT NULL,window INTEGER NOT NULL,expires INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN ('reserved','dispatched','settled','released','fault')),reserve_input INTEGER NOT NULL,reserve_output INTEGER NOT NULL,reserve_cost INTEGER NOT NULL,input INTEGER NOT NULL CHECK(input>=0),output INTEGER NOT NULL CHECK(output>=0),cost INTEGER NOT NULL CHECK(cost>=0),receipt TEXT) STRICT`,
    `CREATE INDEX quota_user ON quota_attempt(user_key,window,state)`,
    `CREATE INDEX quota_scan ON quota_attempt(scan_key,window,state)`,
    `CREATE INDEX quota_cleanup ON quota_attempt(state,window)`,
  ],
});
const CURRENT_AUTOINDEXES = Object.freeze({
  'auth/auth.sqlite': { users: 2, sessions: 1, auth_attempts: 1, trusted_sessions: 2 },
  'data/ledger.sqlite': { scans: 2, outbox: 1, scan_results: 1, admission_windows: 1,
    scan_findings: 1, scan_sbom_results: 1, scan_sbom_components: 2, scan_vuln_results: 1,
    scan_vuln_findings: 2, scan_archive_results: 1, scan_check_results: 1,
    scan_execution_profiles: 1, scan_cve_policy: 1, scan_cve_evidence: 1 },
  'auth/llm-usage.sqlite': { quota_attempt: 1 },
});
function currentCompatibility(db, relative, settings, fingerprint = hash(json(settings))) {
  if (!REQUIRED.includes(relative)) return; // Optional consumers MUST be disabled upstream.
  const versions = { 'auth/auth.sqlite': CURRENT_PROFILE.auth,
    'data/ledger.sqlite': CURRENT_PROFILE.ledger, 'auth/llm-usage.sqlite': CURRENT_PROFILE.quota };
  requireThat(`${db.pragma('application_id', { simple: true })}/${db.pragma('user_version', { simple: true })}` === versions[relative], 'INCOMPATIBLE');
  exactSchema(db, CURRENT_DDL[relative], CURRENT_AUTOINDEXES[relative]);
  if (relative === 'auth/auth.sqlite') {
    const saved = db.prepare('SELECT fingerprint FROM browser_access WHERE id=1').raw().get()?.[0];
    requireThat(saved === fingerprint, 'INCOMPATIBLE');
  }
}
function exactSchema(db, ddl, autoindexes) {
  const expected = new Map(ddl.map(sql => {
    const tokens = ddlTokens(sql);
    return [tokens[2][1], tokens];
  }));
  const auto = new Map(Object.entries(autoindexes).flatMap(([table, count]) =>
    Array.from({ length: count }, (_, i) => [`sqlite_autoindex_${table}_${i + 1}`, table])));
  const objects = db.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema').all();
  requireThat(objects.length === expected.size + auto.size, 'INCOMPATIBLE');
  for (const object of objects) {
    if (object.sql === null) requireThat(object.type === 'index' && auto.get(object.name) === object.tbl_name && auto.delete(object.name), 'INCOMPATIBLE');
    else {
      const tokens = expected.get(object.name);
      requireThat(tokens && object.type === tokens[1][1] &&
        object.tbl_name === (object.type === 'table' ? object.name : tokens[4][1]) &&
        same(ddlTokens(object.sql), tokens), 'INCOMPATIBLE');
      expected.delete(object.name);
    }
  }
  requireThat(expected.size === 0 && auto.size === 0, 'INCOMPATIBLE');
}

// Separately consented source-only migration profile. No OLD serving claim.
export const MIGRATION_PROFILE = Object.freeze({
  name: 'preservation-migration-v1', current: CURRENT_PROFILE.sourceAggregate,
  oldAuthSource: 'b39f54808f63e07959ead476bf61a574cd3a4d288d96cbb5035b1bfecb24d4f0',
  oldLedgerSource: '9b0b3cce477da38aa91aeba2946a9b1ab334615f9b3f3a5d8273a45b36c14626',
});
const AUTH_STORE = 'auth/auth.sqlite', LEDGER_STORE = 'data/ledger.sqlite';
const TECH_AUTH = ['trusted_sessions', 'browser_access'];
const TECH_LEDGER = ['scan_cve_policy', 'scan_cve_evidence'];
const tableExists = (db, name) => !!db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?").get(name);
const namedDdl = (relative, name) => CURRENT_DDL[relative].find(sql => ddlTokens(sql)[2][1] === name);
function migrationSchemas(db, relative) {
  if (!REQUIRED.includes(relative)) return; // Captured unchanged; unknown optional DBs cannot be planned.
  if (relative !== AUTH_STORE) requiredSchemas(db, relative);
  let absentTables = [];
  if (relative === AUTH_STORE) {
    requireThat(db.pragma('application_id', { simple: true }) === 0n && db.pragma('user_version', { simple: true }) === 0n, 'INCOMPATIBLE');
    absentTables = TECH_AUTH.filter(name => !tableExists(db, name));

  } else if (relative === LEDGER_STORE) {
    const version = db.pragma('user_version', { simple: true });
    requireThat(version === 13n || version === 14n, 'INCOMPATIBLE');
    if (version === 13n) absentTables = TECH_LEDGER;
  }
  exactSchema(db, CURRENT_DDL[relative].filter(sql => !absentTables.includes(ddlTokens(sql)[2][1])),
    Object.fromEntries(Object.entries(CURRENT_AUTOINDEXES[relative]).filter(([table]) => !absentTables.includes(table))));
  if (relative === AUTH_STORE) {
    const malformedHex = (c, n) => `typeof(${c})!='text' OR length(${c})!=${n} OR ${c} GLOB '*[^0-9a-f]*'`;
    requireThat(!db.prepare(`SELECT 1 FROM users WHERE ${malformedHex('id', 32)} OR ${malformedHex('salt', 32)} OR typeof(password_hash)!='blob' OR length(password_hash)!=64 LIMIT 1`).get(), 'INVALID_STORE');
    requireThat(!db.prepare(`SELECT 1 FROM sessions WHERE ${malformedHex('token_hash', 64)} OR ${malformedHex('user_id', 32)} OR typeof(expires_at)!='integer' OR expires_at<0 LIMIT 1`).get(), 'INVALID_STORE');
    if (!absentTables.includes('browser_access')) requireThat(db.prepare('SELECT count(*) FROM browser_access').raw().get()[0] <= 1n &&
      !db.prepare("SELECT 1 FROM browser_access WHERE id!=1 OR typeof(fingerprint)!='text' OR length(fingerprint)!=64 OR fingerprint GLOB '*[^0-9a-f]*' OR typeof(incarnation)!='text' OR length(incarnation)!=32 OR incarnation GLOB '*[^0-9a-f]*' LIMIT 1").get(), 'INCOMPATIBLE');
    if (!absentTables.includes('trusted_sessions')) requireThat(!db.prepare("SELECT 1 FROM trusted_sessions WHERE typeof(token_hash)!='text' OR length(token_hash)!=64 OR token_hash GLOB '*[^0-9a-f]*' OR typeof(session_id)!='text' OR length(session_id)!=32 OR session_id GLOB '*[^0-9a-f]*' OR typeof(generation)!='integer' OR generation<1 LIMIT 1").get(), 'INCOMPATIBLE');
  }
}
const textCell = value => ['text', Buffer.from(value)];
const integerCell = value => ['integer', BigInt(value)];
function plannedRowHash(cells) {
  const sha = createHash('sha256').update('sqlite-row-v1\0');
  for (const [type, value] of cells) for (const part of cell(type, value)) sha.update(part);
  return sha.digest('hex');
}
function canonicalVulnChecks(value) {
  try {
    const parsed = JSON.parse(value), order = ['secret', 'sbom', 'vuln', 'config'];
    return typeof value === 'string' && Array.isArray(parsed) && parsed.length >= 1 && parsed.length <= 4 &&
      parsed.every(c => order.includes(c)) && json(parsed) === value &&
      parsed.every((c, i) => i === 0 || order.indexOf(parsed[i - 1]) < order.indexOf(c)) && parsed.includes('vuln');
  } catch { return false; }
}
function migrationFacts(db, relative, fingerprint) {
  migrationSchemas(db, relative); inflight(db, relative); verify(db);
  if (relative === AUTH_STORE) {
    const createTrusted = !tableExists(db, 'trusted_sessions'), createBrowser = !tableExists(db, 'browser_access');
    const browser = createBrowser ? undefined : db.prepare('SELECT fingerprint,incarnation FROM browser_access WHERE id=1').raw().get();
    requireThat(!browser || browser[0] === fingerprint, 'INCOMPATIBLE');
    const tokens = db.prepare(createTrusted ? 'SELECT token_hash FROM sessions ORDER BY token_hash' :
      'SELECT s.token_hash FROM sessions s LEFT JOIN trusted_sessions t USING(token_hash) WHERE t.token_hash IS NULL ORDER BY s.token_hash').raw().all().map(r => r[0]);
    requireThat(tokens.length <= LIMITS.tableRows && tokens.every(token => hex(token)), 'INCOMPATIBLE');
    const ids = createTrusted ? [] : db.prepare('SELECT session_id FROM trusted_sessions').raw().all().map(r => r[0]);
    const maximum = createTrusted ? 0n : db.prepare('SELECT coalesce(max(rowid),0) FROM trusted_sessions').raw().get()[0];
    return { createTrusted, createBrowser, addBrowser: !browser, tokens, ids, firstRowid: String(maximum < 0n ? 1n : maximum + 1n) };
  }
  if (relative === LEDGER_STORE) {
    const version = Number(db.pragma('user_version', { simple: true }));
    const policies = [];
    if (version === 13) for (const [id, checks] of db.prepare('SELECT id,checks FROM scans ORDER BY rowid').raw().iterate()) {
      if (!canonicalVulnChecks(checks)) continue;
      requireThat(policies.length < LIMITS.tableRows && typeof id === 'string' && id.length > 0 && Buffer.byteLength(id) <= 200, 'INCOMPATIBLE');
      policies.push(id);
    }
    return { version, policies };
  }
}
function migrationRecords(facts, fingerprint) {
  const occupied = new Set(facts.auth.ids);
  const mappings = facts.auth.tokens.map((token, index) => {
    let id = randomBytes(16).toString('hex');
    requireThat(!occupied.has(id), 'INCOMPATIBLE'); occupied.add(id);
    const rowid = BigInt(facts.auth.firstRowid) + BigInt(index);
    requireThat(rowid <= 9223372036854775807n, 'LIMIT');
    return [String(rowid), token, id, 1];
  });
  return { fingerprint, auth: { createTrusted: facts.auth.createTrusted, createBrowser: facts.auth.createBrowser,
    mappings, browser: facts.auth.addBrowser ? [1, fingerprint, randomBytes(16).toString('hex')] : null },
    ledger: { version: facts.ledger.version, policies: facts.ledger.policies } };
}
function validateRecords(plan, facts) {
  requireThat(hex(plan.fingerprint) && same(Object.keys(plan.auth).sort(), ['browser', 'createBrowser', 'createTrusted', 'mappings']) &&
    same(Object.keys(plan.ledger).sort(), ['policies', 'version']) &&
    plan.auth.createTrusted === facts.auth.createTrusted && plan.auth.createBrowser === facts.auth.createBrowser &&
    Array.isArray(plan.auth.mappings) && plan.auth.mappings.length === facts.auth.tokens.length &&
    plan.ledger.version === facts.ledger.version && same(plan.ledger.policies, facts.ledger.policies), 'INCOMPATIBLE');
  const ids = new Set(facts.auth.ids);
  for (let i = 0; i < plan.auth.mappings.length; i++) {
    const row = plan.auth.mappings[i];
    requireThat(Array.isArray(row) && row.length === 4 && row[0] === String(BigInt(facts.auth.firstRowid) + BigInt(i)) &&
      BigInt(row[0]) <= 9223372036854775807n && row[1] === facts.auth.tokens[i] && typeof row[2] === 'string' && /^[a-f0-9]{32}$/.test(row[2]) && row[3] === 1 && !ids.has(row[2]), 'INCOMPATIBLE'); ids.add(row[2]);
  }
  requireThat(facts.auth.addBrowser ? Array.isArray(plan.auth.browser) && plan.auth.browser.length === 3 &&
    plan.auth.browser[0] === 1 && plan.auth.browser[1] === plan.fingerprint && /^[a-f0-9]{32}$/.test(plan.auth.browser[2]) : plan.auth.browser === null, 'INCOMPATIBLE');
}
function executeAdditions(db, relative, plan) {
  if (relative === AUTH_STORE) {
    if (plan.auth.createTrusted) db.exec(namedDdl(AUTH_STORE, 'trusted_sessions'));
    if (plan.auth.createBrowser) db.exec(namedDdl(AUTH_STORE, 'browser_access'));
    const insert = db.prepare('INSERT INTO trusted_sessions(rowid,token_hash,session_id,generation) VALUES(?,?,?,?)');
    for (const [rowid, token, id, generation] of plan.auth.mappings) insert.run(BigInt(rowid), token, id, generation);
    if (plan.auth.browser) db.prepare('INSERT INTO browser_access(id,fingerprint,incarnation) VALUES(?,?,?)').run(...plan.auth.browser);
  } else if (relative === LEDGER_STORE && plan.ledger.version === 13) {
    for (const name of TECH_LEDGER) db.exec(namedDdl(LEDGER_STORE, name));
    const insert = db.prepare('INSERT INTO scan_cve_policy(rowid,scan_id,policy,result_contract_version) VALUES(?,?,?,1)');
    plan.ledger.policies.forEach((id, i) => insert.run(BigInt(i + 1), id, 'legacy-db-freshness-v1'));
    db.pragma('user_version = 14');
  }
}
function additionHashes(relative, plan) {
  if (relative === AUTH_STORE) return new Map([
    ['trusted_sessions', plan.auth.mappings.map(([rowid, token, id, generation]) => plannedRowHash([
      integerCell(rowid), textCell(token), textCell(id), integerCell(generation)]))],
    ['browser_access', plan.auth.browser ? [plannedRowHash([
      integerCell(1), integerCell(1), textCell(plan.fingerprint), textCell(plan.auth.browser[2])])] : []],
  ]);
  return new Map(plan.ledger.version === 13 ? [
    ['scan_cve_policy', plan.ledger.policies.map((id, i) => plannedRowHash([
      integerCell(i + 1), textCell(id), textCell('legacy-db-freshness-v1'), integerCell(1)]))],
    ['scan_cve_evidence', []],
  ] : []);
}
function migrationIdentity(before, after, relative, plan) {
  requireThat(before.schema.applicationId === after.schema.applicationId && before.schema.encoding === after.schema.encoding &&
    after.schema.userVersion === (relative === LEDGER_STORE ? '14' : before.schema.userVersion), 'MISMATCH');
  const objects = new Map(after.schema.objects.map((object, i) => [object[0] + '\0' + object[1], [object, after.schema.objectBytes[i]]]));
  before.schema.objects.forEach((object, i) => requireThat(same(objects.get(object[0] + '\0' + object[1]), [object, before.schema.objectBytes[i]]), 'MISMATCH'));
  const additions = additionHashes(relative, plan), originals = new Map(before.tables.map(table => [table.name, table]));
  const current = new Map(after.tables.map(table => [table.name, table]));
  for (const old of before.tables) {
    const next = current.get(old.name), extra = additions.get(old.name) ?? [];
    requireThat(next && same({ ...old, rows: 0, rowHashes: [], sha256: '' }, { ...next, rows: 0, rowHashes: [], sha256: '' }), 'MISMATCH');
    requireThat(same([...old.rowHashes, ...extra].sort(), next.rowHashes), 'MISMATCH');
  }
  for (const next of after.tables) if (!originals.has(next.name)) requireThat(additions.has(next.name) && same([...additions.get(next.name)].sort(), next.rowHashes), 'MISMATCH');
  requireThat(before.tables.every(table => current.has(table.name)), 'MISMATCH');
}
function privateJsonWrite(p, value) {
  const bytes = Buffer.from(json(value)); requireThat(bytes.length <= LIMITS.manifestBytes, 'LIMIT');
  const fd = fs.openSync(p, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  const parent = fs.openSync(path.dirname(p), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
}
function privateJsonRead(p, withHash = false, limit = LIMITS.manifestBytes) {
  return byteFile(p, (read, size, st) => {
    requireThat(size <= limit, 'LIMIT');
    requireThat(st.uid === process.getuid() && (st.mode & 0o7777) === 0o600);
    const bytes = read(0, size), value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    return withHash ? { value, sha256: hash(bytes) } : value;
  });
}
function tuneWriter(db) {
  db.defaultSafeIntegers(true); db.pragma('busy_timeout = 1000'); db.pragma('cache_size = -2048');
  db.pragma('mmap_size = 0'); db.pragma('foreign_keys = ON'); db.pragma('synchronous = FULL');
}

function inflight(db, relative) {
  if (relative === 'data/ledger.sqlite') {
    requireThat(!db.prepare("SELECT 1 FROM scans WHERE state IN ('queued','running') LIMIT 1").get(), 'INFLIGHT');
  }
  if (relative === 'auth/llm-usage.sqlite') {
    requireThat(db.pragma('application_id', { simple: true }) === 1145655601n &&
      db.pragma('user_version', { simple: true }) === 1n, 'INVALID_STORE');
    requireThat(!db.prepare("SELECT 1 FROM quota_attempt WHERE state IN ('reserved','dispatched') LIMIT 1").get(), 'INFLIGHT');
    // Fault, receipt, carried liability and clock rows are hashed, NEVER released.
  }
}

function cell(type, value) {
  let payload;
  switch (type) {
    case 'null': requireThat(value === null, 'INVALID_STORE'); payload = Buffer.alloc(0); break;
    case 'integer': requireThat(typeof value === 'bigint', 'INVALID_STORE'); payload = Buffer.alloc(8); payload.writeBigInt64BE(value); break;
    case 'real': requireThat(typeof value === 'number' && !Number.isNaN(value), 'INVALID_STORE'); payload = Buffer.alloc(8); payload.writeDoubleBE(value); break;
    case 'text': case 'blob': requireThat(Buffer.isBuffer(value), 'INVALID_STORE'); payload = value; break;
    default: throw new Refusal('INVALID_STORE');
  }
  requireThat(payload.length <= LIMITS.cellBytes, 'LIMIT');
  const length = Buffer.alloc(4); length.writeUInt32BE(payload.length);
  return [Buffer.from(type + '\0'), length, payload];
}

function logical(db, budget) {
  verify(db);
  const schemaRows = [], schemaBytes = [];
  let schemaExportBytes = 0;
  const fields = ['type', 'name', 'tbl_name', 'sql'];
  // Bound and retain exact schema TEXT bytes too, not just Node UTF-8 decoding.
  requireThat(!db.prepare(`SELECT 1 FROM sqlite_schema WHERE ${fields.map(c => `length(CAST(${c} AS BLOB))>${LIMITS.cellBytes}`).join(' OR ')} LIMIT 1`).get(), 'LIMIT');
  for (const row of db.prepare(`SELECT ${fields.join(',')},${fields.map(c => `CAST(${c} AS BLOB)`).join(',')} FROM sqlite_schema ORDER BY type COLLATE BINARY,name COLLATE BINARY`).raw().iterate()) {
    requireThat(schemaRows.length < LIMITS.objects, 'LIMIT');
    requireThat(row.slice(0, 4).every(x => x === null || typeof x === 'string'), 'INVALID_STORE');
    requireThat(row.slice(4).every(x => x === null || Buffer.isBuffer(x)), 'INVALID_STORE');
    schemaExportBytes += row.slice(4).reduce((n, b) => n + (b?.length ?? 0), 0);
    requireThat(schemaExportBytes <= LIMITS.schemaBytes, 'LIMIT');
    schemaRows.push(row.slice(0, 4)); schemaBytes.push(row.slice(4).map(b => b === null ? null : b.toString('hex')));
  }
  const schema = { applicationId: String(db.pragma('application_id', { simple: true })),
    userVersion: String(db.pragma('user_version', { simple: true })),

    encoding: db.pragma('encoding', { simple: true }), objects: schemaRows, objectBytes: schemaBytes };
  requireThat(Buffer.byteLength(json(schema)) <= LIMITS.schemaBytes, 'LIMIT');
  const tableList = db.prepare('PRAGMA table_list').all().filter(t => t.schema === 'main' && t.type !== 'view' && !['sqlite_schema', 'sqlite_temp_schema'].includes(t.name));
  requireThat(tableList.length <= LIMITS.objects, 'LIMIT');
  requireThat(tableList.every(t => t.type === 'table'), 'INVALID_STORE'); // virtual/shadow unsupported, not omitted
  const tables = [];
  for (const table of tableList.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
    const columns = db.prepare(`PRAGMA table_xinfo(${quote(table.name)})`).all();
    requireThat(columns.length > 0 && columns.length <= LIMITS.columns, 'LIMIT');
    requireThat(columns.every(c => [0n, 2n, 3n].includes(c.hidden)), 'INVALID_STORE');
    const names = columns.map(c => c.name), lower = names.map(n => n.toLowerCase());
    let rowid = null;
    if (table.wr === 0n) {
      rowid = ['rowid', '_rowid_', 'oid'].find(n => !lower.includes(n));
      requireThat(rowid !== undefined, 'INVALID_STORE'); // all implicit-rowid aliases shadowed
    }
    const selected = [...(rowid ? [rowid] : []), ...names];
    const tableSql = quote(table.name), refs = selected.map(quote);
    const count = db.prepare(`SELECT count(*) FROM (SELECT 1 FROM ${tableSql} LIMIT ${LIMITS.tableRows + 1})`).raw().get()[0];
    requireThat(count <= BigInt(LIMITS.tableRows) && budget.rows + Number(count) <= LIMITS.rows, 'LIMIT');
    // Bound values BEFORE exporting any TEXT/BLOB into Node memory.
    const lengths = refs.map(c => `coalesce(length(CAST(${c} AS BLOB)),0)`);
    requireThat(!db.prepare(`SELECT 1 FROM ${tableSql} WHERE ${lengths.map(n => `${n}>${LIMITS.cellBytes}`).join(' OR ')} OR (${lengths.join('+')})>${LIMITS.rowBytes - refs.length * 16} LIMIT 1`).get(), 'LIMIT');
    const expressions = refs.flatMap(c => [`typeof(${c})`, `CASE WHEN typeof(${c})='text' THEN CAST(${c} AS BLOB) ELSE ${c} END`]);
    const rowHashes = [];
    for (const row of db.prepare(`SELECT ${expressions.join(',')} FROM ${tableSql}`).raw().iterate()) {
      const sha = createHash('sha256'); sha.update('sqlite-row-v1\0');
      let bytes = 0;
      for (let i = 0; i < row.length; i += 2) for (const part of cell(row[i], row[i + 1])) { bytes += part.length; sha.update(part); }
      requireThat(bytes <= LIMITS.rowBytes && budget.bytes + bytes <= LIMITS.exportBytes && ++budget.rows <= LIMITS.rows, 'LIMIT');
      budget.bytes += bytes; rowHashes.push(sha.digest('hex'));
      requireThat(rowHashes.length <= LIMITS.tableRows, 'LIMIT');
    }
    requireThat(BigInt(rowHashes.length) === count, 'INVALID_STORE');
    rowHashes.sort();
    const columnMetadata = columns.map(c => Object.fromEntries(Object.entries(c).map(([k, v]) => [k, typeof v === 'bigint' ? String(v) : v])));
    tables.push({ name: table.name, withoutRowid: table.wr === 1n, strict: table.strict === 1n,
      rowid, columns: columnMetadata, rows: rowHashes.length, rowHashes, sha256: hash(json(rowHashes)) });
  }
  const result = { format: 'sqlite-all-state-v1', schema, tables };
  return { ...result, sha256: hash(json(result)) };
}

function privateTree(p, budget = { files: 0, directories: 0 }, depth = 0) {
  requireThat(depth <= LIMITS.depth + 2 && ++budget.directories <= LIMITS.directories * 2 + 4, 'LIMIT');
  canonicalDirectory(p, true);
  const names = directoryNames(p);
  requireThat(names.length <= LIMITS.files + LIMITS.directories, 'LIMIT');
  for (const name of names) {
    const child = path.join(p, name), st = fs.lstatSync(child);
    if (st.isDirectory()) privateTree(child, budget, depth + 1);
    else {
      requireThat(++budget.files <= LIMITS.files * 2 + LIMITS.databases + 1, 'LIMIT');
      requireThat(st.isFile() && st.nlink === 1 && (st.mode & 0o7777) === 0o600 && st.uid === process.getuid());
    }
  }
}

function syncDirectories(p) {
  for (const name of directoryNames(p)) if (fs.lstatSync(path.join(p, name)).isDirectory()) syncDirectories(path.join(p, name));
  const fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function restrictTree(p) {
  for (const name of directoryNames(p)) {
    const child = path.join(p, name), st = fs.lstatSync(child);
    requireThat(!st.isSymbolicLink());
    if (st.isDirectory()) restrictTree(child);
    else { inspectFile(child); fs.chmodSync(child, 0o600); }
  }
  fs.chmodSync(p, 0o700);
}

/** Test injection is an import-only interface, NEVER a production CLI argument. */
export function createSnapshotter({ Database, sourceRoots, backupRoot, preservationMigration = false }) {
  requireThat(typeof Database === 'function' && same(Object.keys(sourceRoots).sort(), ['auth', 'data']) && typeof preservationMigration === 'boolean');
  const checkSchema = preservationMigration ? migrationSchemas : requiredSchemas;
  const profile = preservationMigration ? MIGRATION_PROFILE.name : undefined;
  function destination(p) {
    const backup = canonicalDirectory(backupRoot, true);
    requireThat(path.dirname(p) === backupRoot && ['pre', 'post'].includes(path.basename(p)), 'INVALID_ARGUMENTS');
    for (const source of Object.values(sourceRoots)) {
      const st = canonicalDirectory(source);
      requireThat(!p.startsWith(source + '/') && !source.startsWith(backupRoot + '/') && source !== backupRoot &&
        !(backup.dev === st.dev && backup.ino === st.ino));
    }
  }
  async function seal(working, sealed, relative, budget, raw, recovery) {
    const db = new Database(working, { fileMustExist: true, timeout: 1000 });
    try {
      tune(db); checkSchema(db, relative); inflight(db, relative);
      const before = logical(db, budget), pageSize = Number(db.pragma('page_size', { simple: true }));
      requireThat(pageSize >= 512 && pageSize <= 65536, 'INVALID_STORE');
      const fd = fs.openSync(sealed, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      fs.closeSync(fd);
      const deadline = Date.now() + LIMITS.backupMs;
      await db.backup(sealed, { progress: ({ totalPages }) => {
        requireThat(totalPages * pageSize <= LIMITS.bytes && Date.now() <= deadline, 'LIMIT'); return 64;
      } });
      const target = new Database(sealed, { fileMustExist: true, timeout: 1000 });
      try { target.pragma('journal_mode = DELETE'); } finally { target.close(); }
      requireThat(['-wal', '-shm', '-journal'].every(s => absent(sealed + s)), 'INVALID_STORE');
      checkRecoveredImage(raw, relative, sealed, recovery);
      const ro = new Database(sealed, { readonly: true, fileMustExist: true, timeout: 1000 });
      try {
        tune(ro);
        const after = logical(ro, { rows: 0, bytes: 0 });
        requireThat(same(before, after), 'INVALID_STORE');
      } finally { ro.close(); }
      fs.chmodSync(sealed, 0o600);
      const out = fs.openSync(sealed, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      try { fs.fsyncSync(out); } finally { fs.closeSync(out); }
      return { path: relative, sealed: path.basename(sealed), recovery: recovery.summary, logical: before, ...transfer(sealed) };
    } finally { db.close(); }
  }
  async function captureInternal(p) {
    destination(p);
    canonicalDirectory(sourceRoots.auth); canonicalDirectory(sourceRoots.data);
    const available = fs.statfsSync(backupRoot, { bigint: true });
    requireThat(available.bavail * available.bsize >= BigInt(LIMITS.freeBytes), 'LIMIT');
    fs.mkdirSync(p, { mode: 0o700 }); // exclusive: existing/partial targets refuse
    for (const name of ['raw', 'working', 'sealed']) fs.mkdirSync(path.join(p, name), { mode: 0o700 });
    const raw = path.join(p, 'raw'), working = path.join(p, 'working');
    const entries = inventory(sourceRoots, raw), { databases } = classify(entries);
    requireThat(same(entries, inventory(sourceRoots)));
    const recoveries = new Map(databases.map(relative => [relative, recoveryInputs(raw, relative)]));
    const rawRoots = { auth: path.join(raw, 'auth'), data: path.join(raw, 'data') };
    inventory(rawRoots, working);
    // SHM is an advisory index, not committed evidence. Keep it RAW but force
    // SQLite to reconstruct it ONLY in the private working clone from checked WAL.
    for (const relative of databases) if (!absent(path.join(working, relative) + '-shm')) fs.unlinkSync(path.join(working, relative) + '-shm');
    const stores = [], budget = { rows: 0, bytes: 0 };
    for (const relative of databases) stores.push(await seal(path.join(working, relative), path.join(p, 'sealed', `${stores.length}.sqlite`), relative, budget, raw, recoveries.get(relative)));
    // Detect original drift during recovery/backup too. Never open originals.
    requireThat(same(entries, inventory(sourceRoots)));
    inventory({ auth: path.join(working, 'auth'), data: path.join(working, 'data') });
    requireThat(stores.reduce((n, s) => n + s.bytes, 0) <= LIMITS.bytes, 'LIMIT');
    restrictTree(working); restrictTree(path.join(p, 'sealed'));
    const manifest = { format: 'stand-state-snapshot-v2', limits: LIMITS, entries, stores, ...(profile ? { profile } : {}) };
    const bytes = Buffer.from(json(manifest));
    requireThat(bytes.length <= LIMITS.manifestBytes, 'LIMIT');
    privateTree(p);
    const fd = fs.openSync(path.join(p, 'manifest.json'), fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    syncDirectories(p);
    const parent = fs.openSync(backupRoot, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
    return manifest;
  }
  function load(p, validateCompatibility) {
    destination(p); privateTree(p);
    const manifestPath = path.join(p, 'manifest.json');
    const manifest = privateJsonRead(manifestPath);
    requireThat(manifest?.format === 'stand-state-snapshot-v2' && manifest.profile === profile && same(manifest.limits, LIMITS) && Array.isArray(manifest.entries) && Array.isArray(manifest.stores), 'INVALID_STORE');
    const raw = path.join(p, 'raw');
    const actual = inventory({ auth: path.join(raw, 'auth'), data: path.join(raw, 'data') });
    requireThat(actual.length === manifest.entries.length, 'INVALID_STORE');
    for (let i = 0; i < actual.length; i++) {
      const a = actual[i], e = manifest.entries[i];
      requireThat(a.path === e.path && a.kind === e.kind &&
        (a.kind === 'directory' || a.bytes === e.bytes && a.sha256 === e.sha256 && a.sqlite === e.sqlite), 'INVALID_STORE');
      requireThat(Number.isInteger(e.mode) && !(e.mode & ~0o777) && !(e.mode & 0o022) && Number.isSafeInteger(e.uid) && Number.isSafeInteger(e.gid), 'INVALID_STORE');
    }
    const { databases } = classify(manifest.entries);
    requireThat(same(manifest.stores.map(s => s.path), databases), 'INVALID_STORE');
    const recoveries = new Map(databases.map(relative => [relative, recoveryInputs(raw, relative)]));
    const budget = { rows: 0, bytes: 0 };
    for (let i = 0; i < manifest.stores.length; i++) {
      const s = manifest.stores[i];
      requireThat(s.sealed === `${i}.sqlite` && hex(s.sha256), 'INVALID_STORE');
      const sealed = path.join(p, 'sealed', s.sealed), info = transfer(sealed);
      requireThat(info.bytes === s.bytes && info.sha256 === s.sha256 && info.sqlite && ['-wal', '-shm', '-journal'].every(suffix => absent(sealed + suffix)), 'INVALID_STORE');
      const recovery = recoveries.get(s.path);
      requireThat(same(recovery.summary, s.recovery), 'INVALID_STORE');
      checkRecoveredImage(raw, s.path, sealed, recovery);
      const db = new Database(sealed, { readonly: true, fileMustExist: true, timeout: 1000 });
      try {
        tune(db); checkSchema(db, s.path); inflight(db, s.path);
        requireThat(same(logical(db, budget), s.logical), 'INVALID_STORE');
        validateCompatibility?.(db, s.path);
      } finally { db.close(); }
    }
    requireThat(same(directoryNames(p), ['manifest.json', 'raw', 'sealed', 'working']), 'INVALID_STORE');
    requireThat(same(directoryNames(path.join(p, 'sealed')), manifest.stores.map(s => s.sealed).sort()), 'INVALID_STORE');
    return manifest;
  }
  function comparison(m) {
    const { databases, sides } = classify(m.entries), dbSet = new Set(databases);
    return { entries: m.entries.filter(e => !sides.has(e.path)).map(e => {
      const base = { path: e.path, kind: e.kind, mode: e.mode, uid: e.uid, gid: e.gid };
      return e.kind === 'file' && !dbSet.has(e.path) ? { ...base, bytes: e.bytes, sha256: e.sha256 } : base;
    }), stores: m.stores.map(s => ({ path: s.path, logical: s.logical })) };
  }
  const migrationDir = path.join(backupRoot, 'migration');
  const baselineHash = pre => transfer(path.join(pre, 'manifest.json')).sha256;
  function factsFromPre(pre, fingerprint) {
    const facts = {};
    const manifest = load(pre, (db, relative) => {
      if (relative === AUTH_STORE) facts.auth = migrationFacts(db, relative, fingerprint);
      if (relative === LEDGER_STORE) facts.ledger = migrationFacts(db, relative, fingerprint);
    });
    requireThat(manifest.stores.length === REQUIRED.length && facts.auth && facts.ledger, 'INCOMPATIBLE');
    const quota = 'auth/llm-usage.sqlite';
    requireThat(manifest.entries.filter(e => [quota, quota + '-journal', quota + '-wal', quota + '-shm'].includes(e.path))
      .every(e => e.uid === process.getuid() && !(e.mode & 0o077) && (e.path === quota || e.path === quota + '-journal')), 'INCOMPATIBLE');
    return { facts, manifest };
  }
  function migrationPre(pre) {
    requireThat(preservationMigration && path.basename(pre) === 'pre', 'INVALID_ARGUMENTS'); destination(pre);
  }
  function readPlan(pre) {
    migrationPre(pre); privateTree(migrationDir);
    const names = directoryNames(migrationDir), base = ['auth.sqlite', 'ledger.sqlite', 'plan.json'];
    requireThat([base, [...base, 'apply-attempt.json'].sort(), [...base, 'apply-attempt.json', 'applied.json'].sort()]
      .some(allowed => same(names, allowed)), 'INCOMPATIBLE');
    const { value: plan, sha256: planHash } = privateJsonRead(path.join(migrationDir, 'plan.json'), true);
    requireThat(same(Object.keys(plan).sort(), ['auth', 'baseline', 'dryrun', 'fingerprint', 'format', 'ledger', 'profile']) &&
      plan.format === 'preservation-migration-plan-v1' && same(plan.profile, MIGRATION_PROFILE) &&
      plan.baseline === baselineHash(pre) && same(Object.keys(plan.dryrun).sort(), [AUTH_STORE, LEDGER_STORE].sort()) &&
      Object.values(plan.dryrun).every(hex), 'INCOMPATIBLE');
    const { facts, manifest } = factsFromPre(pre, plan.fingerprint); validateRecords(plan, facts);
    const marker = { baseline: plan.baseline, planHash };
    for (const name of ['apply-attempt.json', 'applied.json']) if (names.includes(name))
      requireThat(same(privateJsonRead(path.join(migrationDir, name), false, 256), marker), 'INCOMPATIBLE');
    const budget = { rows: 0, bytes: 0 }; let bytes = 0;
    for (const relative of [AUTH_STORE, LEDGER_STORE]) {
      const clone = path.join(migrationDir, relative === AUTH_STORE ? 'auth.sqlite' : 'ledger.sqlite');
      bytes += inspectFile(clone).size; requireThat(bytes <= LIMITS.bytes, 'LIMIT');
      const db = new Database(clone, { readonly: true, fileMustExist: true, timeout: 1000 });
      try {
        tune(db); requiredSchemas(db, relative); currentCompatibility(db, relative, [], plan.fingerprint);
        const after = logical(db, budget);
        migrationIdentity(manifest.stores.find(s => s.path === relative).logical, after, relative, plan);
        requireThat(after.sha256 === plan.dryrun[relative], 'MISMATCH');
      } finally { db.close(); }
    }
    return { plan, manifest, planHash };
  }
  function dryRun(pre, manifest, plan) {
    const hashes = {}, budget = { rows: 0, bytes: 0 }; let bytes = 0;
    for (const relative of [AUTH_STORE, LEDGER_STORE]) {
      const store = manifest.stores.find(s => s.path === relative), clone = path.join(migrationDir, relative === AUTH_STORE ? 'auth.sqlite' : 'ledger.sqlite');
      requireThat(bytes + store.bytes <= LIMITS.bytes, 'LIMIT');
      transfer(path.join(pre, 'sealed', store.sealed), clone);
      const db = new Database(clone, { fileMustExist: true, timeout: 1000 });
      try {
        tuneWriter(db);
        const pages = Math.floor((LIMITS.bytes - bytes) / Number(db.pragma('page_size', { simple: true })));
        requireThat(db.pragma(`max_page_count = ${pages}`, { simple: true }) <= BigInt(pages), 'LIMIT');
        db.exec('BEGIN IMMEDIATE'); executeAdditions(db, relative, plan);
        requiredSchemas(db, relative); currentCompatibility(db, relative, [], plan.fingerprint);
        const after = logical(db, budget); migrationIdentity(store.logical, after, relative, plan);
        hashes[relative] = after.sha256; db.exec('COMMIT');
      } finally { db.close(); }
      bytes += inspectFile(clone).size; requireThat(bytes <= LIMITS.bytes, 'LIMIT');
    }
    requireThat(['auth.sqlite', 'ledger.sqlite'].reduce((n, name) => n + inspectFile(path.join(migrationDir, name)).size, 0) <= LIMITS.bytes, 'LIMIT');
    requireThat(same(directoryNames(migrationDir), ['auth.sqlite', 'ledger.sqlite']), 'INVALID_STORE');
    return hashes;
  }
  function migrationComparison(baseline, current, plan) {
    const oldSides = classify(baseline.entries).sides, newSides = classify(current.entries).sides;
    const newEntries = new Map(current.entries.map(e => [e.path, e]));
    for (const e of baseline.entries.filter(e => oldSides.has(e.path) && newSides.has(e.path))) {
      const next = newEntries.get(e.path);
      requireThat(same({ mode: e.mode, uid: e.uid, gid: e.gid }, { mode: next.mode, uid: next.uid, gid: next.gid }), 'MISMATCH');
    }
    requireThat(same(comparison(baseline).entries, comparison(current).entries) && same(baseline.stores.map(s => s.path), current.stores.map(s => s.path)), 'MISMATCH');
    for (const old of baseline.stores) {
      const next = current.stores.find(s => s.path === old.path);
      if ([AUTH_STORE, LEDGER_STORE].includes(old.path)) {
        migrationIdentity(old.logical, next.logical, old.path, plan);
        requireThat(next.logical.sha256 === plan.dryrun[old.path], 'MISMATCH');
      } else requireThat(same(old.logical, next.logical), 'MISMATCH');
    }
  }
  return Object.freeze({
    async capture(p) { try { await captureInternal(p); return receipt(true, 'CAPTURED'); } catch (e) { return failure(e); } },
    async compatibility(pre, input) {
      try {
        requireThat(path.basename(pre) === 'pre' || preservationMigration && path.basename(pre) === 'post', 'INVALID_ARGUMENTS');
        const settings = authoritySettings(input);
        // Revalidate the SAME private pre without recapture, constructor writes,
        // new outputs or application imports. All connections in load are RO.
        const manifest = load(pre, (db, relative) => currentCompatibility(db, relative, settings));
        // Current non-initializing QuotaLedger.fileSafety forbids WAL/SHM and
        // requires private files owned by its UID. Parent binds API UID to holder
        // UID and checks the actual quota-policy capacity/free-space preconditions.
        const quota = 'auth/llm-usage.sqlite';
        requireThat(manifest.entries.filter(e => [quota, quota + '-journal', quota + '-wal', quota + '-shm'].includes(e.path))
          .every(e => e.kind === 'file' && e.uid === process.getuid() && !(e.mode & 0o077) &&
            (e.path === quota || e.path === quota + '-journal')), 'INCOMPATIBLE');
        return receipt(true, 'COMPATIBLE');
      } catch (e) { return failure(e); }
    },
    async planMigration(pre, input) {
      try {
        migrationPre(pre); const fingerprint = hash(json(authoritySettings(input)));
        const { facts, manifest } = factsFromPre(pre, fingerprint);
        const records = migrationRecords(facts, fingerprint); validateRecords(records, facts);
        requireThat(fs.statfsSync(backupRoot, { bigint: true }).bavail * fs.statfsSync(backupRoot, { bigint: true }).bsize >= BigInt(LIMITS.freeBytes), 'LIMIT');
        fs.mkdirSync(migrationDir, { mode: 0o700 }); // Exclusive, never replace/replan.
        const plan = { format: 'preservation-migration-plan-v1', profile: MIGRATION_PROFILE, baseline: baselineHash(pre),
          ...records, dryrun: dryRun(pre, manifest, records) };
        restrictTree(migrationDir); privateJsonWrite(path.join(migrationDir, 'plan.json'), plan);
        syncDirectories(migrationDir); syncDirectories(backupRoot);
        return receipt(true, 'PLANNED');
      } catch (e) { return failure(e); }
    },
    async applyMigration(pre) {
      const handles = [], pins = [];
      try {
        // Controller MUST already durably export PRE + reviewed plan, qualify
        // this exact RW holder, and retain continuous exclusion before this call.
        const { plan, manifest, planHash } = readPlan(pre);
        requireThat(absent(path.join(migrationDir, 'apply-attempt.json')) && absent(path.join(migrationDir, 'applied.json')), 'INCOMPATIBLE');
        requireThat(same(inventory(sourceRoots), manifest.entries), 'UNSAFE_SOURCE');
        privateJsonWrite(path.join(migrationDir, 'apply-attempt.json'), { baseline: plan.baseline, planHash });
        const sameFile = (a, b) => same([a.dev,a.ino,a.mode,a.uid,a.gid,a.nlink], [b.dev,b.ino,b.mode,b.uid,b.gid,b.nlink]);
        for (const relative of [AUTH_STORE, LEDGER_STORE]) {
          const label = relative.split('/')[0], original = path.join(sourceRoots[label], path.basename(relative));
          requireThat(fs.realpathSync(original) === original);
          const before = inspectFile(original), pin = fs.openSync(original, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
          pins.push({ fd: pin, original, before });
          requireThat(sameFile(before, fs.fstatSync(pin)));
          // Native SQLite opens by pathname, NOT this pinned fd. These checks
          // detect substitution but are not a kernel-atomic open guarantee;
          // controller-owned continuous exclusion is a necessary precondition.
          const db = new Database(original, { readonly: false, fileMustExist: true, timeout: 1000 });
          handles.push({ relative, db }); tuneWriter(db);
          requireThat(sameFile(before, fs.lstatSync(original)) && sameFile(before, fs.fstatSync(pin)));
          db.exec('BEGIN IMMEDIATE');
        }
        const facts = {}, budget = { rows: 0, bytes: 0 };
        for (const { relative, db } of handles) {
          requireThat(same(logical(db, budget), manifest.stores.find(s => s.path === relative).logical), 'MISMATCH');
          facts[relative === AUTH_STORE ? 'auth' : 'ledger'] = migrationFacts(db, relative, plan.fingerprint);
        }
        validateRecords(plan, facts);
        const afterBudget = { rows: 0, bytes: 0 };
        for (const { relative, db } of handles) {
          executeAdditions(db, relative, plan); requiredSchemas(db, relative);
          currentCompatibility(db, relative, [], plan.fingerprint);
          const after = logical(db, afterBudget);
          migrationIdentity(manifest.stores.find(s => s.path === relative).logical, after, relative, plan);
          requireThat(after.sha256 === plan.dryrun[relative], 'MISMATCH');
        }
        // Both candidates validate BEFORE the first commit. Separate SQLite files
        // cannot commit atomically: any failure retains attempted/HOLD, no retry,
        // compensating restore or rollback of an already committed store.
        for (const { db } of handles) db.exec('COMMIT');
        for (const { db } of handles) db.close(); handles.length = 0;
        for (const pin of pins) {
          requireThat(sameFile(pin.before, fs.fstatSync(pin.fd)) && sameFile(pin.before, fs.lstatSync(pin.original)));
          fs.fsyncSync(pin.fd);
          const dir = fs.openSync(path.dirname(pin.original), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
          try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
        }
        privateJsonWrite(path.join(migrationDir, 'applied.json'), { baseline: plan.baseline, planHash });
        return receipt(true, 'MIGRATED');
      } catch (e) { return failure(e); }
      finally {
        // SQLite closes/abandons any UNCOMMITTED transaction only. No attempt is
        // made to undo a successful commit or restart an application automatically.
        for (const { db } of handles) try { db.close(); } catch { /* keep closed refusal */ }
        for (const pin of pins) try { fs.closeSync(pin.fd); } catch { /* keep closed refusal */ }
      }
    },
    async compareMigrated(pre, post) {
      try {
        requireThat(preservationMigration && path.basename(post) === 'post' && pre !== post, 'INVALID_ARGUMENTS');
        const { plan, manifest, planHash } = readPlan(pre);
        requireThat(same(privateJsonRead(path.join(migrationDir, 'applied.json'), false, 256), { baseline: plan.baseline, planHash }), 'INCOMPATIBLE');
        const current = load(post, (db, relative) => {
          if (REQUIRED.includes(relative)) { requiredSchemas(db, relative); currentCompatibility(db, relative, [], plan.fingerprint); }
        });
        // Independently reconstruct exact allowed additive row hashes and compare
        // ALL old objects/columns/typed rows/rowids/multiplicity/files/quota.
        migrationComparison(manifest, current, plan);
        return receipt(true, 'MIGRATION_MATCH');
      } catch (e) { return failure(e); }
    },
    async compare(pre, post) {
      try {
        requireThat(path.basename(pre) === 'pre' && path.basename(post) === 'post' && pre !== post, 'INVALID_ARGUMENTS');
        const baseline = load(pre);
        await captureInternal(post);
        const current = load(post);
        const oldSides = classify(baseline.entries).sides, newSides = classify(current.entries).sides;
        const currentEntries = new Map(current.entries.map(e => [e.path, e]));
        // Sidecar creation/removal/checkpoint bytes may change; permissions and
        // ownership of a sidecar retained in both snapshots must not drift.
        const sideMetadataEqual = baseline.entries.filter(e => oldSides.has(e.path) && newSides.has(e.path))
          .every(e => same({ mode: e.mode, uid: e.uid, gid: e.gid },
            { mode: currentEntries.get(e.path).mode, uid: currentEntries.get(e.path).uid, gid: currentEntries.get(e.path).gid }));
        const equal = sideMetadataEqual && same(comparison(baseline), comparison(current));
        return receipt(equal, equal ? 'MATCH' : 'MISMATCH');
      } catch (e) { return failure(e); }
    },
  });
}

export async function runCli(args, testDependencies, testInput) {
  let result;
  try {
    const capture = same(args, ['capture', '/backup/pre']);
    const compare = same(args, ['compare', '/backup/pre', '/backup/post']);
    const compatibility = same(args, ['compatibility', '/backup/pre']);
    const migrationCapture = same(args, ['capture', '--preservation-migration', '/backup/pre']) ||
      same(args, ['capture', '--preservation-migration', '/backup/post']);
    const planMigration = same(args, ['plan-migration', '--preservation-migration', '/backup/pre']);
    const applyMigration = same(args, ['apply-migration', '--preservation-migration', '/backup/pre']);
    const compareMigrated = same(args, ['compare-migrated', '--preservation-migration', '/backup/pre', '/backup/post']);
    const migrationCompatibility = same(args, ['compatibility', '--preservation-migration', '/backup/post']);
    const migration = migrationCapture || planMigration || applyMigration || compareMigrated || migrationCompatibility;
    requireThat(capture || compare || compatibility || migration, 'INVALID_ARGUMENTS');
    const needsInput = compatibility || planMigration || migrationCompatibility;
    const input = needsInput ? await authorityInput(testInput ?? process.stdin) : undefined;
    if (needsInput) authoritySettings(input); // Refuse bad input before dependency/filesystem access.
    const dependencies = testDependencies ?? {
      Database: createRequire('/app/server/api/package.json')('better-sqlite3'),
      sourceRoots: { auth: '/source/auth', data: '/source/data' }, backupRoot: '/backup',
    };
    const snapshotter = createSnapshotter({ ...dependencies, preservationMigration: migration });
    const pre = path.join(dependencies.backupRoot, 'pre'), post = path.join(dependencies.backupRoot, 'post');
    if (capture) result = await snapshotter.capture('/backup/pre');
    else if (compare) result = await snapshotter.compare('/backup/pre', '/backup/post');
    else if (compatibility) result = await snapshotter.compatibility(pre, input);
    else if (migrationCapture) result = await snapshotter.capture(args[2] === '/backup/pre' ? pre : post);
    else if (planMigration) result = await snapshotter.planMigration(pre, input);
    else if (applyMigration) result = await snapshotter.applyMigration(pre);
    else if (compareMigrated) result = await snapshotter.compareMigrated(pre, post);
    else result = await snapshotter.compatibility(post, input);
  } catch (e) { result = failure(e); }
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  // Raw exception text, paths, counts, schema, row fingerprints and hashes NEVER
  // cross this interface. Diagnostic manifests remain under the private /backup.
  const result = await runCli(process.argv.slice(2));
  process.stdout.write(json(result) + '\n');
  process.exitCode = result.ok ? 0 : 1;
}
