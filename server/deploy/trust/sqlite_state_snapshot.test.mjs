import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import { createSnapshotter, CURRENT_PROFILE, MIGRATION_PROFILE, LIMITS, runCli } from './sqlite_state_snapshot.mjs';

// This file imports NO application modules or old tests. All opened DBs are
// new disposable files below one exclusive temporary directory per fixture.
const require = createRequire(new URL('../../api/package.json', import.meta.url));
let Database, nativeAvailable = false;
const probe = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'snapshot-native-'));
try {
  Database = require('better-sqlite3');
  const db = new Database(path.join(probe, 'disposable.sqlite'));
  db.exec('CREATE TABLE disposable (n INTEGER)'); db.close(); nativeAvailable = true;
} catch {
  // No rebuild, fallback binary, installation, application import or real store.
} finally { fs.rmSync(probe, { recursive: true, force: true }); }

function nativeTest(name, fn) {
  test(name, { skip: !nativeAvailable && 'Host native SQLite unavailable; pinned helper sandbox qualification required' }, fn);
}
function fixture(t, ledgerVersion = 14) {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'snapshot-fixture-'));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const auth = path.join(root, 'auth'), data = path.join(root, 'data'), backupRoot = path.join(root, 'backup');
  for (const p of [auth, data, backupRoot]) fs.mkdirSync(p, { mode: 0o700 });
  const stores = { auth: path.join(auth, 'auth.sqlite'), ledger: path.join(data, 'ledger.sqlite'), quota: path.join(auth, 'llm-usage.sqlite') };
  function make(p, sql) {
    const db = new Database(p);
    try { db.exec(sql); } finally { db.close(); }
    fs.chmodSync(p, 0o600);
  }
  make(stores.auth, `CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT NOT NULL UNIQUE,salt TEXT NOT NULL,password_hash BLOB NOT NULL);
    CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),expires_at INTEGER NOT NULL,revoked_at INTEGER);
    CREATE INDEX sessions_user ON sessions(user_id,expires_at);
    CREATE TABLE auth_attempts(bucket TEXT PRIMARY KEY,count INTEGER NOT NULL,expires_at INTEGER NOT NULL);
    CREATE TABLE trusted_sessions(token_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,session_id TEXT NOT NULL UNIQUE,generation INTEGER NOT NULL CHECK(generation>0));
    CREATE TABLE browser_access(id INTEGER PRIMARY KEY CHECK(id=1),fingerprint TEXT NOT NULL,incarnation TEXT NOT NULL);
    INSERT INTO users VALUES('${'a'.repeat(32)}','synthetic-owner@example.invalid','${'b'.repeat(32)}',zeroblob(64));
    INSERT INTO sessions VALUES('${'c'.repeat(64)}','${'a'.repeat(32)}',1234567890,NULL);
    INSERT INTO trusted_sessions VALUES('${'c'.repeat(64)}','${'d'.repeat(32)}',1);
    INSERT INTO browser_access VALUES(1,'${'e'.repeat(64)}','${'f'.repeat(32)}');`);
  make(stores.ledger, `CREATE TABLE scans(id TEXT PRIMARY KEY,subject TEXT NOT NULL,idempotency_key TEXT NOT NULL,
    registry TEXT NOT NULL,repository TEXT NOT NULL,digest TEXT NOT NULL,platform TEXT NOT NULL,state TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,fingerprint TEXT,checks TEXT NOT NULL DEFAULT '[]',scope TEXT NOT NULL DEFAULT 'image',terminal_at TEXT,UNIQUE(subject,idempotency_key));
    CREATE TABLE outbox(scan_id TEXT PRIMARY KEY REFERENCES scans(id),delivered_at TEXT,attempts INTEGER NOT NULL DEFAULT 0,lease_until INTEGER,next_run_at INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE scan_results(scan_id TEXT PRIMARY KEY REFERENCES scans(id),check_name TEXT NOT NULL,finding_count INTEGER ${ledgerVersion < 9 ? 'NOT NULL' : ''},coverage TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,scanner_version TEXT,outcome TEXT NOT NULL DEFAULT 'unsupported',error_code TEXT);
    CREATE TABLE admission_windows(subject TEXT NOT NULL,minute INTEGER NOT NULL,count INTEGER NOT NULL,PRIMARY KEY(subject,minute));
    CREATE TABLE scan_findings(scan_id TEXT NOT NULL REFERENCES scans(id),finding_id TEXT NOT NULL,rule_id TEXT NOT NULL,line INTEGER,evidence_ref TEXT NOT NULL,PRIMARY KEY(scan_id,finding_id));
    CREATE TABLE scan_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,scan_id TEXT NOT NULL REFERENCES scans(id),state TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE scan_audit(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,subject TEXT NOT NULL,target TEXT NOT NULL,scope TEXT NOT NULL,decision TEXT NOT NULL,reason TEXT NOT NULL,scan_id TEXT);
    CREATE TABLE scan_sbom_results(scan_id TEXT PRIMARY KEY REFERENCES scans(id),image TEXT,platform TEXT,os_name TEXT,os_version TEXT,component_count INTEGER,coverage TEXT NOT NULL,outcome TEXT NOT NULL,scanner_version TEXT,error_code TEXT,checked_at TEXT);
    CREATE TABLE scan_sbom_components(scan_id TEXT NOT NULL REFERENCES scans(id),ordinal INTEGER NOT NULL,ecosystem TEXT NOT NULL,name TEXT NOT NULL,version TEXT NOT NULL,PRIMARY KEY(scan_id,ordinal));
    CREATE TABLE scan_vuln_results(scan_id TEXT PRIMARY KEY REFERENCES scans(id),image TEXT,platform TEXT,finding_count INTEGER,coverage TEXT NOT NULL,outcome TEXT NOT NULL,scanner_version TEXT,error_code TEXT,checked_at TEXT);
    CREATE TABLE scan_vuln_findings(scan_id TEXT NOT NULL REFERENCES scans(id),ordinal INTEGER NOT NULL,finding_id TEXT NOT NULL,cve_id TEXT NOT NULL,ecosystem TEXT NOT NULL,package_name TEXT NOT NULL,installed_version TEXT NOT NULL,severity TEXT NOT NULL,severity_sources TEXT NOT NULL,provenance_ref TEXT NOT NULL,fixed_version TEXT${ledgerVersion >= 13 ? ',advisory TEXT' : ''},PRIMARY KEY(scan_id,ordinal));
    ${ledgerVersion >= 10 ? 'CREATE TABLE scan_archive_results(scan_id TEXT PRIMARY KEY REFERENCES scans(id),attempt INTEGER NOT NULL,report TEXT NOT NULL);' : ''}
    ${ledgerVersion >= 11 ? 'CREATE TABLE scan_check_results(scan_id TEXT NOT NULL REFERENCES scans(id),check_name TEXT NOT NULL,attempt INTEGER NOT NULL,outcome TEXT NOT NULL,checks_version TEXT NOT NULL,resource_policy_version TEXT NOT NULL,report TEXT NOT NULL,checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(scan_id,check_name));' : ''}
    ${ledgerVersion >= 12 ? 'CREATE TABLE scan_execution_profiles(scan_id TEXT PRIMARY KEY REFERENCES scans(id),binding TEXT NOT NULL);' : ''}
    ${ledgerVersion >= 14 ? 'CREATE TABLE scan_cve_policy(scan_id TEXT PRIMARY KEY REFERENCES scans(id),policy TEXT NOT NULL,result_contract_version INTEGER NOT NULL); CREATE TABLE scan_cve_evidence(scan_id TEXT PRIMARY KEY REFERENCES scans(id),attempt INTEGER NOT NULL,evidence TEXT NOT NULL);' : ''}
    CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,value TEXT);
    INSERT INTO scans(id,subject,idempotency_key,registry,repository,digest,platform,state) VALUES('scan-one','synthetic-subject','synthetic-key','synthetic-registry','synthetic-repository','synthetic-digest','linux/amd64','completed');
    INSERT INTO events(value) VALUES('synthetic-terminal'); PRAGMA user_version=${ledgerVersion};`);
  make(stores.quota, `CREATE TABLE quota_meta(id INTEGER PRIMARY KEY CHECK(id=1),clock INTEGER NOT NULL) STRICT;
    CREATE TABLE quota_attempt(id TEXT PRIMARY KEY,user_key TEXT NOT NULL,scan_key TEXT NOT NULL,report_hash TEXT NOT NULL,policy_hash TEXT NOT NULL,request_hash TEXT NOT NULL,quota_policy TEXT NOT NULL,window INTEGER NOT NULL,expires INTEGER NOT NULL,state TEXT NOT NULL,reserve_input INTEGER NOT NULL,reserve_output INTEGER NOT NULL,reserve_cost INTEGER NOT NULL,input INTEGER NOT NULL,output INTEGER NOT NULL,cost INTEGER NOT NULL,receipt TEXT) STRICT;
    CREATE INDEX quota_user ON quota_attempt(user_key,window,state); CREATE INDEX quota_scan ON quota_attempt(scan_key,window,state); CREATE INDEX quota_cleanup ON quota_attempt(state,window);
    INSERT INTO quota_meta VALUES(1,123456789);
    INSERT INTO quota_attempt VALUES('synthetic-attempt','${'a'.repeat(64)}','${'b'.repeat(64)}','${'c'.repeat(64)}','${'d'.repeat(64)}','${'e'.repeat(64)}','{}',0,1234567890,'fault',17,0,0,17,0,0,'synthetic-receipt');
    PRAGMA application_id=1145655601; PRAGMA user_version=1;`);
  const pre = path.join(backupRoot, 'pre'), post = path.join(backupRoot, 'post');
  const api = createSnapshotter({ Database, sourceRoots: { auth, data }, backupRoot });
  const manifest = p => JSON.parse(fs.readFileSync(path.join(p, 'manifest.json'), 'utf8'));
  const open = which => new Database(stores[which]);
  return { root, auth, data, backupRoot, stores, make, pre, post, api, manifest, open };
}
const okCapture = Object.freeze({ code: 'CAPTURED', ok: true });
const okMatch = Object.freeze({ code: 'MATCH', ok: true });

nativeTest('capture and compare preserve all state and fault liabilities', async t => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.data, 'worker.ready'), 'synthetic-marker', { mode: 0o600 });
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  assert.deepEqual(await f.api.compare(f.pre, f.post), okMatch);
  const m = f.manifest(f.pre), q = m.stores.find(s => s.path === 'auth/llm-usage.sqlite');
  assert.equal(q.logical.tables.find(table => table.name === 'quota_attempt').rows, 1);
  assert.equal(q.logical.tables.find(table => table.name === 'quota_meta').rows, 1);
  assert.equal(m.stores.find(s => s.path === 'data/ledger.sqlite').logical.tables.some(table => table.name === 'sqlite_sequence'), true);
  const sealed = new Database(path.join(f.pre, 'sealed', q.sealed), { readonly: true, fileMustExist: true });
  try { assert.equal(sealed.prepare('SELECT state FROM quota_attempt').get().state, 'fault'); assert.equal(sealed.prepare('SELECT clock FROM quota_meta').get().clock, 123456789); } finally { sealed.close(); }
  function privacy(p) {
    assert.equal(fs.statSync(p).mode & 0o777, 0o700);
    for (const name of fs.readdirSync(p)) {
      const child = path.join(p, name);
      if (fs.statSync(child).isDirectory()) privacy(child);
      else assert.equal(fs.statSync(child).mode & 0o777, 0o600);
    }
  }
  privacy(f.pre); privacy(f.post);
});

nativeTest('committed WAL-only rows survive private recovery and physical checkpoint changes', async t => {
  const f = fixture(t), db = f.open('auth');
  t.after(() => { if (db.open) db.close(); });
  db.pragma('journal_mode=WAL'); db.pragma('wal_autocheckpoint=0');
  db.prepare('INSERT INTO users VALUES(?,?,?,?)').run('1'.repeat(32), 'synthetic-WAL-only@example.invalid', '2'.repeat(32), Buffer.alloc(64, 1));
  assert.equal(fs.existsSync(f.stores.auth + '-wal'), true);
  const bytes = fs.readFileSync(f.stores.auth);
  assert.equal(bytes.includes(Buffer.from('synthetic-WAL-only')), false);
  const originalWal = fs.readFileSync(f.stores.auth + '-wal');
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  assert.deepEqual(fs.readFileSync(f.stores.auth), bytes);
  assert.deepEqual(fs.readFileSync(f.stores.auth + '-wal'), originalWal);
  db.pragma('wal_checkpoint(TRUNCATE)'); db.close();
  assert.deepEqual(await f.api.compare(f.pre, f.post), okMatch);
  const m = f.manifest(f.pre), s = m.stores.find(s => s.path === 'auth/auth.sqlite');
  assert.equal(s.logical.tables.find(table => table.name === 'users').rows, 2);
  assert.equal(fs.existsSync(path.join(f.pre, 'sealed', s.sealed) + '-wal'), false);
});

nativeTest('non-hot DELETE journal uncertainty refuses without altering originals', async t => {
  const f = fixture(t), db = f.open('auth');
  t.after(() => { if (db.open) { if (db.inTransaction) db.exec('ROLLBACK'); db.close(); } });
  db.pragma('journal_mode=DELETE'); db.exec("BEGIN IMMEDIATE; UPDATE users SET password_hash=randomblob(64);");
  assert.equal(fs.existsSync(f.stores.auth + '-journal'), true);
  const before = fs.readFileSync(f.stores.auth + '-journal');
  assert.deepEqual(await f.api.capture(f.pre), { code: 'INVALID_STORE', ok: false });
  assert.deepEqual(fs.readFileSync(f.stores.auth + '-journal'), before);
  assert.equal(fs.existsSync(path.join(f.pre, 'manifest.json')), false);
});

nativeTest('native uncertain journal tail refuses; finite hot segments recover privately', async t => {
  const f = fixture(t), db = f.open('auth');
  db.exec('CREATE TABLE bulk(id INTEGER PRIMARY KEY,v BLOB);');
  const insert = db.prepare('INSERT INTO bulk VALUES(?,zeroblob(65536))');
  db.transaction(() => { for (let i = 0; i < 16; i++) insert.run(i); })(); db.close();
  const script = `import {createRequire} from 'node:module'; const D=createRequire(process.argv[1])('better-sqlite3'); const db=new D(process.argv[2],{fileMustExist:true}); db.pragma('journal_mode=DELETE'); db.pragma('cache_size=4'); db.exec('BEGIN IMMEDIATE; UPDATE bulk SET v=randomblob(65536);'); process.kill(process.pid,'SIGKILL');`;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script, fileURLToPath(new URL('../../api/package.json', import.meta.url)), f.stores.auth], { timeout: 10000, maxBuffer: 2048 });
  assert.equal(child.signal, 'SIGKILL');
  // Build a supported finite hot fixture from the native journal. Its final
  // unsynced zero-header tail is deliberately NOT our supported recovery format;
  // that uncertainty is covered by separate refusal tests, not silently ignored.
  const nativeJournal = fs.readFileSync(f.stores.auth + '-journal');
  let end = 0;
  while (end + 28 <= nativeJournal.length && nativeJournal.subarray(end, end + 8).equals(Buffer.from([0xd9,0xd5,0x05,0xf9,0x20,0xa1,0x63,0xd7]))) {
    const n = nativeJournal.readUInt32BE(end + 8), sector = nativeJournal.readUInt32BE(end + 20), page = nativeJournal.readUInt32BE(end + 24);
    assert.ok(n > 0 && n < 0xffffffff);
    const recordsEnd = end + sector + n * (page + 8);
    assert.ok(recordsEnd <= nativeJournal.length);
    const next = Math.ceil(recordsEnd / sector) * sector;
    if (next + 28 > nativeJournal.length || !nativeJournal.subarray(next, next + 8).equals(nativeJournal.subarray(0, 8))) { end = recordsEnd; break; }
    end = next;
  }
  assert.ok(end > 0 && end < nativeJournal.length);
  const mainBefore = fs.readFileSync(f.stores.auth);
  assert.deepEqual(await f.api.capture(f.pre), { code: 'INVALID_STORE', ok: false });
  assert.equal(fs.existsSync(path.join(f.pre, 'manifest.json')), false);
  assert.deepEqual(fs.readFileSync(f.stores.auth), mainBefore);
  assert.deepEqual(fs.readFileSync(f.stores.auth + '-journal'), nativeJournal);
  // This truncates ONLY our disposable fixture to encode the finite control.
  // Never retry over the refused/incomplete pre destination.
  fs.truncateSync(f.stores.auth + '-journal', end);
  const journalBefore = fs.readFileSync(f.stores.auth + '-journal');
  assert.deepEqual(await f.api.capture(f.post), okCapture);
  assert.deepEqual(fs.readFileSync(f.stores.auth), mainBefore);
  assert.deepEqual(fs.readFileSync(f.stores.auth + '-journal'), journalBefore);
  const s = f.manifest(f.post).stores.find(s => s.path === 'auth/auth.sqlite');
  const ro = new Database(path.join(f.post, 'sealed', s.sealed), { readonly: true, fileMustExist: true });
  try { assert.equal(ro.prepare('SELECT count(*) AS n FROM bulk WHERE v=zeroblob(65536)').get().n, 16); } finally { ro.close(); }
});

function walFixture(t) {
  const f = fixture(t), db = f.open('auth');
  t.after(() => { if (db.open) db.close(); });
  db.pragma('journal_mode=WAL'); db.pragma('wal_autocheckpoint=0');
  db.prepare('INSERT INTO users VALUES(?,?,?,?)').run('1'.repeat(32), 'uncheckpointed-canary@example.invalid', '2'.repeat(32), Buffer.alloc(64, 1));
  assert.equal(db.prepare('SELECT count(*) AS n FROM users').get().n, 2);
  assert.equal(fs.readFileSync(f.stores.auth).includes(Buffer.from('uncheckpointed-canary')), false);
  return { ...f, db, wal: f.stores.auth + '-wal' };
}
// Independent fixture encoder, not an import of the production validator.
function checksumFixture(bytes, seed, big) {
  let a = seed[0], b = seed[1];
  for (let i = 0; i < bytes.length; i += 8) {
    const first = big ? bytes.readUInt32BE(i) : bytes.readUInt32LE(i);
    const second = big ? bytes.readUInt32BE(i + 4) : bytes.readUInt32LE(i + 4);
    a = (a + first + b) % 0x100000000; b = (b + second + a) % 0x100000000;
  }
  return [a, b];
}
function resignWal(bytes) {
  const big = bytes.readUInt32BE(0) === 0x377f0683, pageSize = bytes.readUInt32BE(8);
  let state = checksumFixture(bytes.subarray(0, 24), [0, 0], big);
  bytes.writeUInt32BE(state[0], 24); bytes.writeUInt32BE(state[1], 28);
  for (let offset = 32; offset < bytes.length; offset += pageSize + 24) {
    state = checksumFixture(bytes.subarray(offset, offset + 8), state, big);
    state = checksumFixture(bytes.subarray(offset + 24, offset + 24 + pageSize), state, big);
    bytes.writeUInt32BE(state[0], offset + 16); bytes.writeUInt32BE(state[1], offset + 20);
  }
  return bytes;
}

for (const defect of ['magic','version','page-size','header-checksum','salt','page-number','commit-size','frame-header-checksum','page-checksum','short-header','partial-frame','extra-byte','zeroed-header']) {
  nativeTest('invalid WAL refuses BEFORE SQLite: ' + defect, async t => {
    const f = walFixture(t); let bytes = fs.readFileSync(f.wal);
    if (defect === 'magic') bytes[0] ^= 1;
    if (defect === 'version') { bytes.writeUInt32BE(3007001, 4); resignWal(bytes); }
    if (defect === 'page-size') { bytes.writeUInt32BE(512, 8); }
    if (defect === 'header-checksum') bytes[24] ^= 1;
    if (defect === 'salt') bytes[40] ^= 1;
    if (defect === 'page-number') { bytes.writeUInt32BE(0, 32); resignWal(bytes); }
    if (defect === 'commit-size') { bytes.writeUInt32BE(LIMITS.bytes / bytes.readUInt32BE(8) + 1, 36); resignWal(bytes); }
    if (defect === 'frame-header-checksum') bytes[48] ^= 1;
    if (defect === 'page-checksum') bytes[56] ^= 1;
    if (defect === 'short-header') bytes = bytes.subarray(0, 31);
    if (defect === 'partial-frame') bytes = bytes.subarray(0, bytes.length - 1);
    if (defect === 'extra-byte') bytes = Buffer.concat([bytes, Buffer.from([1])]);
    if (defect === 'zeroed-header') bytes.fill(0, 0, 32);
    fs.writeFileSync(f.wal, bytes);
    const mainBefore = fs.readFileSync(f.stores.auth);
    let opened = 0;
    function GuardedDatabase(p, options) { opened++; return new Database(p, options); }
    const api = createSnapshotter({ Database: GuardedDatabase, sourceRoots: { auth: f.auth, data: f.data }, backupRoot: f.backupRoot });
    assert.deepEqual(await api.capture(f.pre), { code: 'INVALID_STORE', ok: false });
    assert.equal(opened, 0);
    assert.equal(fs.existsSync(path.join(f.pre, 'manifest.json')), false);
    assert.deepEqual(fs.readFileSync(f.wal), bytes); assert.deepEqual(fs.readFileSync(f.stores.auth), mainBefore);
    assert.equal((await api.compare(f.pre, f.post)).ok, false);
  });
}

nativeTest('a header-only checked WAL certifies no extra committed pages', async t => {
  const f = walFixture(t), header = fs.readFileSync(f.wal).subarray(0, 32);
  f.db.pragma('wal_checkpoint(PASSIVE)'); fs.writeFileSync(f.wal, header);
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  assert.equal(f.manifest(f.pre).stores.find(s => s.path === 'auth/auth.sqlite').logical.tables.find(s => s.name === 'users').rows, 2);
});

nativeTest('complete checked WAL with no commit recovers main, not uncommitted frames', async t => {
  const f = walFixture(t), bytes = fs.readFileSync(f.wal), page = bytes.readUInt32BE(8);
  for (let offset = 32; offset < bytes.length; offset += page + 24) bytes.writeUInt32BE(0, offset + 4);
  fs.writeFileSync(f.wal, resignWal(bytes));
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  assert.equal(f.manifest(f.pre).stores.find(s => s.path === 'auth/auth.sqlite').logical.tables.find(s => s.name === 'users').rows, 1);
});

nativeTest('post corruption cannot turn a valid pre into a degraded MATCH', async t => {
  const f = walFixture(t);
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  const bytes = fs.readFileSync(f.wal); bytes[0] ^= 1; fs.writeFileSync(f.wal, bytes);
  assert.deepEqual(await f.api.compare(f.pre, f.post), { code: 'INVALID_STORE', ok: false });
  assert.equal(fs.existsSync(path.join(f.post, 'manifest.json')), false);
});

nativeTest('validated WAL works with either checksum word order', async t => {
  const f = walFixture(t), bytes = fs.readFileSync(f.wal);
  bytes.writeUInt32BE(bytes.readUInt32BE(0) === 0x377f0682 ? 0x377f0683 : 0x377f0682, 0);
  fs.writeFileSync(f.wal, resignWal(bytes));
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  assert.deepEqual(await f.api.compare(f.pre, f.post), okMatch);
  assert.equal(f.manifest(f.pre).stores.find(s => s.path === 'auth/auth.sqlite').logical.tables.find(s => s.name === 'users').rows, 2);
});

nativeTest('complete valid uncommitted WAL tail cannot replace committed pages', async t => {
  const f = walFixture(t), original = fs.readFileSync(f.wal), pageSize = original.readUInt32BE(8);
  const tail = Buffer.alloc(24 + pageSize, 0x9e);
  tail.writeUInt32BE(original.readUInt32BE(32), 0); tail.writeUInt32BE(0, 4);
  original.copy(tail, 8, 16, 24);
  fs.writeFileSync(f.wal, resignWal(Buffer.concat([original, tail])));
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  assert.equal(f.manifest(f.pre).stores.find(s => s.path === 'auth/auth.sqlite').logical.tables.find(s => s.name === 'users').rows, 2);
});

nativeTest('rebuilt SHM cannot launder missing validated committed WAL data', async t => {
  const f = walFixture(t); fs.writeFileSync(f.stores.auth + '-shm', Buffer.alloc(32768));
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  assert.equal(f.manifest(f.pre).stores.find(s => s.path === 'auth/auth.sqlite').logical.tables.find(s => s.name === 'users').rows, 2);
});

nativeTest('ignoring a VALID WAL is caught by byte-image verification', async t => {
  const f = walFixture(t);
  function IgnoringWal(p, options) {
    if (p.includes(path.sep + 'working' + path.sep) && fs.existsSync(p + '-wal')) fs.unlinkSync(p + '-wal');
    return new Database(p, options);
  }
  const api = createSnapshotter({ Database: IgnoringWal, sourceRoots: { auth: f.auth, data: f.data }, backupRoot: f.backupRoot });
  assert.deepEqual(await api.capture(f.pre), { code: 'INVALID_STORE', ok: false });
  assert.equal(fs.existsSync(path.join(f.pre, 'manifest.json')), false);
});

function journalFixture(t) {
  const f = fixture(t), main = fs.readFileSync(f.stores.auth), pageSize = main.readUInt16BE(16);
  const header = Buffer.alloc(512), frame = Buffer.alloc(pageSize + 8), nonce = 0x12345678;
  Buffer.from([0xd9,0xd5,0x05,0xf9,0x20,0xa1,0x63,0xd7]).copy(header);
  header.writeUInt32BE(1, 8); header.writeUInt32BE(nonce, 12); header.writeUInt32BE(main.length / pageSize, 16);
  header.writeUInt32BE(512, 20); header.writeUInt32BE(pageSize, 24);
  frame.writeUInt32BE(1, 0); main.copy(frame, 4, 0, pageSize);
  let sum = nonce;
  for (let i = pageSize - 200; i > 0; i -= 200) sum = (sum + frame[4 + i]) % 0x100000000;
  frame.writeUInt32BE(sum, pageSize + 4);
  return { ...f, journal: f.stores.auth + '-journal', journalBytes: Buffer.concat([header, frame]), pageSize };
}
for (const defect of ['magic','zero-records','unbounded-records','sector','page-size','original-size','page-number','checksum','truncation','non-hot-tail','ambiguous-tail','duplicate-page']) {
  nativeTest('unsupported or corrupt journal refuses before recovery: ' + defect, async t => {
    const f = journalFixture(t); let bytes = f.journalBytes;
    if (defect === 'magic') bytes[0] ^= 1;
    if (defect === 'zero-records') bytes.writeUInt32BE(0, 8);
    if (defect === 'unbounded-records') bytes.writeUInt32BE(0xffffffff, 8);
    if (defect === 'sector') bytes.writeUInt32BE(3, 20);
    if (defect === 'page-size') bytes.writeUInt32BE(1024, 24);
    if (defect === 'original-size') bytes.writeUInt32BE(0, 16);
    if (defect === 'page-number') bytes.writeUInt32BE(0, 512);
    if (defect === 'checksum') bytes[bytes.length - 1] ^= 1;
    if (defect === 'truncation') bytes = bytes.subarray(0, bytes.length - 1);
    if (defect === 'non-hot-tail') bytes = Buffer.concat([bytes, Buffer.alloc(Math.ceil(bytes.length / 512) * 512 - bytes.length + 512)]);
    if (defect === 'ambiguous-tail') bytes = Buffer.concat([bytes, Buffer.from([1])]);
    if (defect === 'duplicate-page') { bytes = Buffer.concat([bytes, bytes.subarray(512)]); bytes.writeUInt32BE(2, 8); }
    fs.writeFileSync(f.journal, bytes, { mode: 0o600 });
    let opened = 0;
    function GuardedDatabase(p, options) { opened++; return new Database(p, options); }
    const api = createSnapshotter({ Database: GuardedDatabase, sourceRoots: { auth: f.auth, data: f.data }, backupRoot: f.backupRoot });
    assert.deepEqual(await api.capture(f.pre), { code: 'INVALID_STORE', ok: false });
    assert.equal(opened, 0); assert.equal(fs.existsSync(path.join(f.pre, 'manifest.json')), false);
    assert.deepEqual(fs.readFileSync(f.journal), bytes);
  });
}

nativeTest('WAL/journal simultaneous recovery input refuses', async t => {
  const f = walFixture(t); fs.writeFileSync(f.stores.auth + '-journal', '', { mode: 0o600 });
  assert.deepEqual(await f.api.capture(f.pre), { code: 'INVALID_STORE', ok: false });
});

for (const version of [8,9,10,11,12,13,14]) nativeTest('recognizes public ledger family without requiring current14: ' + version, async t => {
  const f = fixture(t, version);
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  assert.deepEqual(await f.api.compare(f.pre, f.post), okMatch);
  assert.equal(f.manifest(f.pre).stores.find(s => s.path === 'data/ledger.sqlite').logical.schema.userVersion, String(version));
  assert.deepEqual(Object.keys(await runCli(['invalid'])).sort(), ['code','ok']);
});

for (const defect of ['unrelated-auth','missing-sessions','missing-trusted','missing-access','auth-id','auth-version','user-id','session-backfill','access-bootstrap','ledger-minimal','ledger-outbox','ledger-v0','ledger-v7','ledger-v15','quota-minimal','quota-id','quota-version','quota-clock']) {
  nativeTest('required schema/identity gate refuses: ' + defect, async t => {
    const f = fixture(t);
    const edit = (store, sql) => { const db = f.open(store); db.pragma('foreign_keys=OFF'); db.exec(sql); db.close(); };
    if (defect === 'unrelated-auth') { fs.unlinkSync(f.stores.auth); f.make(f.stores.auth, 'CREATE TABLE unrelated(v)'); }
    if (defect === 'missing-sessions') edit('auth', 'DROP TABLE sessions');
    if (defect === 'missing-trusted') edit('auth', 'DROP TABLE trusted_sessions');
    if (defect === 'missing-access') edit('auth', 'DROP TABLE browser_access');
    if (defect === 'auth-id') edit('auth', 'PRAGMA application_id=1');
    if (defect === 'auth-version') edit('auth', 'PRAGMA user_version=1');
    if (defect === 'user-id') edit('auth', "UPDATE users SET id='unrecognized-id'");
    if (defect === 'session-backfill') edit('auth', 'DELETE FROM trusted_sessions');
    if (defect === 'access-bootstrap') edit('auth', 'DELETE FROM browser_access');
    if (defect === 'ledger-minimal') { fs.unlinkSync(f.stores.ledger); f.make(f.stores.ledger, 'CREATE TABLE scans(state TEXT); CREATE TABLE outbox(scan_id TEXT); PRAGMA user_version=8'); }
    if (defect === 'ledger-outbox') edit('ledger', 'ALTER TABLE outbox RENAME COLUMN attempts TO unexpected');
    if (defect === 'ledger-v0') edit('ledger', 'PRAGMA user_version=0');
    if (defect === 'ledger-v7') edit('ledger', 'PRAGMA user_version=7');
    if (defect === 'ledger-v15') edit('ledger', 'PRAGMA user_version=15');
    if (defect === 'quota-minimal') { fs.unlinkSync(f.stores.quota); f.make(f.stores.quota, 'CREATE TABLE quota_attempt(state TEXT); PRAGMA application_id=1145655601; PRAGMA user_version=1'); }
    if (defect === 'quota-id') edit('quota', 'PRAGMA application_id=1');
    if (defect === 'quota-version') edit('quota', 'PRAGMA user_version=2');
    if (defect === 'quota-clock') edit('quota', 'DELETE FROM quota_meta');
    const before = fs.readFileSync(f.stores.auth);
    assert.deepEqual(await f.api.capture(f.pre), { code: 'INVALID_STORE', ok: false });
    assert.equal(fs.existsSync(path.join(f.pre, 'manifest.json')), false);
    assert.deepEqual(fs.readFileSync(f.stores.auth), before);
  });
}

nativeTest('required schema corruption after a good pre refuses instead of MATCH', async t => {
  const f = fixture(t); assert.deepEqual(await f.api.capture(f.pre), okCapture);
  fs.unlinkSync(f.stores.auth); f.make(f.stores.auth, 'CREATE TABLE unrelated(v)');
  assert.deepEqual(await f.api.compare(f.pre, f.post), { code: 'INVALID_STORE', ok: false });
  assert.equal(fs.existsSync(path.join(f.post, 'manifest.json')), false);
});

nativeTest('optional header-classified SQLite and nested ordinary files are captured', async t => {
  const f = fixture(t);
  fs.mkdirSync(path.join(f.auth, 'nested'), { mode: 0o700 });
  f.make(path.join(f.auth, 'nested', 'history-without-extension'), 'CREATE TABLE turns(id INTEGER PRIMARY KEY, content TEXT); INSERT INTO turns VALUES(1,\'synthetic-private\');');
  fs.writeFileSync(path.join(f.auth, 'nested', 'auxiliary'), 'synthetic', { mode: 0o600 });
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  assert.equal(f.manifest(f.pre).stores.length, 4);
  assert.equal(fs.readFileSync(path.join(f.pre, 'raw', 'auth', 'nested', 'auxiliary'), 'utf8'), 'synthetic');
});

nativeTest('missing optional stores are not created', async t => {
  const f = fixture(t);
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  for (const name of ['llm-history.sqlite', 'runtime.sqlite', 'caller.sqlite']) assert.equal(fs.existsSync(path.join(f.auth, name)), false);
});

for (const required of ['auth', 'ledger', 'quota']) nativeTest('required existing store absence refuses without creation: ' + required, async t => {
  const f = fixture(t); fs.unlinkSync(f.stores[required]);
  assert.deepEqual(await f.api.capture(f.pre), { code: 'INVALID_STORE', ok: false });
  assert.equal(fs.existsSync(f.stores[required]), false);
});
for (const state of ['queued', 'running']) nativeTest('inflight scan gate: ' + state, async t => {
  const f = fixture(t), db = f.open('ledger'); db.prepare('UPDATE scans SET state=?').run(state); db.close();
  assert.deepEqual(await f.api.capture(f.pre), { code: 'INFLIGHT', ok: false });
});
for (const state of ['reserved', 'dispatched']) nativeTest('inflight quota gate: ' + state, async t => {
  const f = fixture(t), db = f.open('quota'); db.prepare('UPDATE quota_attempt SET state=?').run(state); db.close();
  assert.deepEqual(await f.api.capture(f.pre), { code: 'INFLIGHT', ok: false });
});

nativeTest('full-width integers, actual types, invalid UTF-8 text, blobs, NULL and duplicates are distinguished', async t => {
  const f = fixture(t), db = f.open('auth');
  db.exec(`CREATE TABLE values_all(v); INSERT INTO values_all VALUES(NULL),(9223372036854775807),(-9223372036854775808),(1),(1.0),('1'),(X'31'),(CAST(X'fffe' AS TEXT)),('duplicate'),('duplicate'),(1e999),(-1e999);`);
  db.close();
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  const table = f.manifest(f.pre).stores.find(s => s.path === 'auth/auth.sqlite').logical.tables.find(s => s.name === 'values_all');
  assert.equal(table.rows, 12); assert.equal(new Set(table.rowHashes).size, 12); // implicit rowid is preserved
  const edit = f.open('auth'); edit.exec('UPDATE values_all SET v=1.0 WHERE rowid=4'); edit.close();
  assert.deepEqual(await f.api.compare(f.pre, f.post), { code: 'MISMATCH', ok: false });
});

nativeTest('generated columns, WITHOUT ROWID, quoted names, views and triggers are retained', async t => {
  const f = fixture(t), db = f.open('auth');
  db.exec(`CREATE TABLE "odd\""" (id INTEGER PRIMARY KEY, n INTEGER, doubled INTEGER GENERATED ALWAYS AS(n*2) STORED, virtual_n INTEGER GENERATED ALWAYS AS(n+1) VIRTUAL);
    INSERT INTO "odd\""" (id,n) VALUES(1,3);
    CREATE TABLE no_rowid(id TEXT PRIMARY KEY,v BLOB) WITHOUT ROWID; INSERT INTO no_rowid VALUES('x',X'00');
    CREATE VIEW view_all AS SELECT * FROM no_rowid;
    CREATE TRIGGER trigger_all AFTER INSERT ON no_rowid BEGIN SELECT 1; END;`);
  db.close();
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  const logical = f.manifest(f.pre).stores.find(s => s.path === 'auth/auth.sqlite').logical;
  assert.equal(logical.tables.find(s => s.name === 'no_rowid').rowid, null);
  assert.equal(logical.tables.find(s => s.name === 'odd"').columns.length, 4);
  assert.equal(logical.schema.objects.some(s => s[0] === 'view'), true);
  assert.equal(logical.schema.objects.some(s => s[0] === 'trigger'), true);
  assert.deepEqual(await f.api.compare(f.pre, f.post), okMatch);
});

nativeTest('virtual/shadow tables refuse rather than omitting hidden state', async t => {
  const f = fixture(t), db = f.open('auth'); db.exec('CREATE VIRTUAL TABLE unsupported USING fts5(content)'); db.close();
  assert.deepEqual(await f.api.capture(f.pre), { code: 'INVALID_STORE', ok: false });
});

nativeTest('fully shadowed implicit rowid refuses', async t => {
  const f = fixture(t), db = f.open('auth'); db.exec('CREATE TABLE aliases(rowid, _rowid_, oid)'); db.close();
  assert.deepEqual(await f.api.capture(f.pre), { code: 'INVALID_STORE', ok: false });
});

for (const change of ['logical', 'schema', 'version', 'sequence', 'nonDB', 'mode']) nativeTest('comparison rejects preservation drift: ' + change, async t => {
  const f = fixture(t); const ordinary = path.join(f.data, 'marker'); fs.writeFileSync(ordinary, 'before', { mode: 0o600 });
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  if (change === 'nonDB') fs.writeFileSync(ordinary, 'after');
  else if (change === 'mode') fs.chmodSync(ordinary, 0o644);
  else {
    const db = f.open('ledger');
    db.exec({ logical: 'UPDATE scans SET id=2', schema: 'CREATE INDEX new_index ON scans(state)', version: 'PRAGMA user_version=13', sequence: "UPDATE sqlite_sequence SET seq=99 WHERE name='events'" }[change]);
    db.close();
  }
  assert.deepEqual(await f.api.compare(f.pre, f.post), { code: 'MISMATCH', ok: false });
});

for (const bad of ['symlink', 'hardlink', 'writable', 'orphan', 'corrupt']) nativeTest('unsafe or unsupported file refuses: ' + bad, async t => {
  const f = fixture(t), p = path.join(f.data, 'bad');
  if (bad === 'symlink') fs.symlinkSync(f.stores.auth, p);
  if (bad === 'hardlink') fs.linkSync(f.stores.auth, p);
  if (bad === 'writable') { fs.writeFileSync(p, 'synthetic', { mode: 0o600 }); fs.chmodSync(p, 0o666); }
  if (bad === 'orphan') fs.writeFileSync(p + '-wal', Buffer.alloc(32), { mode: 0o600 });
  if (bad === 'corrupt') fs.writeFileSync(f.stores.quota, 'not-a-database');
  assert.equal((await f.api.capture(f.pre)).ok, false);
});

nativeTest('SQLite foreign key violations refuse', async t => {
  const f = fixture(t), db = f.open('auth'); db.pragma('foreign_keys=OFF'); db.exec(`INSERT INTO sessions VALUES('${'1'.repeat(64)}','${'2'.repeat(32)}',1234567890,NULL)`); db.close();
  assert.deepEqual(await f.api.capture(f.pre), { code: 'INVALID_STORE', ok: false });
});

nativeTest('bounded rows and cells refuse before complete capture', async t => {
  const f = fixture(t), db = f.open('auth');
  db.exec(`CREATE TABLE large(v BLOB); INSERT INTO large VALUES(zeroblob(${LIMITS.cellBytes + 1}));`); db.close();
  assert.deepEqual(await f.api.capture(f.pre), { code: 'LIMIT', ok: false });
  assert.equal(fs.existsSync(path.join(f.pre, 'manifest.json')), false);
});

nativeTest('UTF-16 database encoding and exact text/schema bytes survive backup', async t => {
  const f = fixture(t), p = path.join(f.auth, 'utf16.db');
  f.make(p, `PRAGMA encoding='UTF-16le'; CREATE TABLE texts(v TEXT); INSERT INTO texts VALUES('synthetic-λ');`);
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  const s = f.manifest(f.pre).stores.find(s => s.path === 'auth/utf16.db');
  assert.equal(s.logical.schema.encoding, 'UTF-16le');
  assert.equal(s.logical.schema.objectBytes.length, s.logical.schema.objects.length);
  assert.deepEqual(await f.api.compare(f.pre, f.post), okMatch);
});

nativeTest('permissions on retained WAL sidecars cannot silently drift', async t => {
  const f = fixture(t), db = f.open('auth');
  t.after(() => { if (db.open) db.close(); });
  db.pragma('journal_mode=WAL'); db.exec(`INSERT INTO users VALUES('${'1'.repeat(32)}','synthetic-wal@example.invalid','${'2'.repeat(32)}',zeroblob(64))`);
  fs.chmodSync(f.stores.auth + '-wal', 0o600);
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  fs.chmodSync(f.stores.auth + '-wal', 0o644);
  assert.deepEqual(await f.api.compare(f.pre, f.post), { code: 'MISMATCH', ok: false });
});

nativeTest('bounded directory enumeration refuses excess files', async t => {
  const f = fixture(t);
  for (let i = 0; i < LIMITS.files - 2; i++) fs.writeFileSync(path.join(f.data, `entry-${i}`), '', { mode: 0o600 });
  assert.deepEqual(await f.api.capture(f.pre), { code: 'LIMIT', ok: false });
  assert.equal(fs.existsSync(path.join(f.pre, 'manifest.json')), false);
});

nativeTest('row cap refuses without unbounded export', async t => {
  const f = fixture(t), db = f.open('auth');
  db.exec(`CREATE TABLE many(v); WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<${LIMITS.tableRows + 1}) INSERT INTO many SELECT i FROM n;`);
  db.close();
  assert.deepEqual(await f.api.capture(f.pre), { code: 'LIMIT', ok: false });
  assert.equal(fs.existsSync(path.join(f.pre, 'manifest.json')), false);
});

nativeTest('aggregate volume byte cap applies across both sources', async t => {
  const f = fixture(t);
  for (const p of [path.join(f.auth, 'part'), path.join(f.data, 'part')]) {
    const fd = fs.openSync(p, 'wx', 0o600); fs.ftruncateSync(fd, LIMITS.bytes / 2 + 1); fs.closeSync(fd);
  }
  assert.deepEqual(await f.api.capture(f.pre), { code: 'LIMIT', ok: false });
});

nativeTest('backup progress oversize stops privately and never completes a manifest', async t => {
  const f = fixture(t);
  function OversizedBackup(p, options) {
    const db = new Database(p, options);
    db.backup = async (target, settings) => { settings.progress({ totalPages: LIMITS.bytes, remainingPages: LIMITS.bytes }); };
    return db;
  }
  const api = createSnapshotter({ Database: OversizedBackup, sourceRoots: { auth: f.auth, data: f.data }, backupRoot: f.backupRoot });
  assert.deepEqual(await api.capture(f.pre), { code: 'LIMIT', ok: false });
  assert.equal(fs.existsSync(path.join(f.pre, 'manifest.json')), false);
});

nativeTest('file byte cap and existing incomplete destination refuse without overwrite', async t => {
  const f = fixture(t), p = path.join(f.data, 'oversized');
  const fd = fs.openSync(p, 'wx', 0o600); fs.ftruncateSync(fd, LIMITS.bytes + 1); fs.closeSync(fd);
  assert.deepEqual(await f.api.capture(f.pre), { code: 'LIMIT', ok: false });
  fs.unlinkSync(p);
  assert.deepEqual(await f.api.capture(f.pre), { code: 'IO_FAILURE', ok: false });
  assert.equal(fs.existsSync(path.join(f.pre, 'manifest.json')), false);
});

nativeTest('pre raw or sealed tampering refuses and does not create post', async t => {
  const f = fixture(t); assert.deepEqual(await f.api.capture(f.pre), okCapture);
  fs.appendFileSync(path.join(f.pre, 'raw', 'auth', 'auth.sqlite'), 'synthetic-tamper');
  assert.deepEqual(await f.api.compare(f.pre, f.post), { code: 'INVALID_STORE', ok: false });
  assert.equal(fs.existsSync(f.post), false);
});

nativeTest('source drift during private recovery refuses completion', async t => {
  const f = fixture(t);
  function DriftDatabase(p, options) {
    fs.writeFileSync(path.join(f.data, 'unexpected-new-file'), 'synthetic', { mode: 0o600 });
    return new Database(p, options);
  }
  const api = createSnapshotter({ Database: DriftDatabase, sourceRoots: { auth: f.auth, data: f.data }, backupRoot: f.backupRoot });
  assert.deepEqual(await api.capture(f.pre), { code: 'UNSAFE_SOURCE', ok: false });
  assert.equal(fs.existsSync(path.join(f.pre, 'manifest.json')), false);
});

nativeTest('source aliases and destination aliases refuse', async t => {
  const f = fixture(t);
  const alias = createSnapshotter({ Database, sourceRoots: { auth: f.auth, data: f.auth }, backupRoot: f.backupRoot });
  assert.equal((await alias.capture(f.pre)).ok, false);
  fs.symlinkSync(f.backupRoot, path.join(f.root, 'backup-link'));
  const linked = createSnapshotter({ Database, sourceRoots: { auth: f.auth, data: f.data }, backupRoot: path.join(f.root, 'backup-link') });
  assert.equal((await linked.capture(path.join(f.root, 'backup-link', 'pre'))).ok, false);
});

test('CLI is closed and bounded, with no diagnostic reflection or dependency resolution on bad arguments', async () => {
  for (const args of [[], ['capture', '/canary-secret'], ['compare', '/backup/pre'], ['capture', '/backup/pre', '--dependency=canary-secret']]) {
    assert.deepEqual(await runCli(args), { code: 'INVALID_ARGUMENTS', ok: false });
  }
  const script = fileURLToPath(new URL('./sqlite_state_snapshot.mjs', import.meta.url));
  const child = spawnSync(process.execPath, [script, 'capture', '/canary-secret'], { encoding: 'utf8', timeout: 5000, maxBuffer: 2048 });
  assert.equal(child.status, 1); assert.equal(child.stderr, '');
  assert.equal(child.stdout, '{"code":"INVALID_ARGUMENTS","ok":false}\n');
  assert.equal(child.stdout.includes('canary-secret'), false);
});

test('invalid injected dependency produces a fixed receipt before any filesystem access', async () => {
  const result = await runCli(['capture', '/backup/pre'], { Database: undefined, sourceRoots: { auth: '/source/auth', data: '/source/data' }, backupRoot: '/backup' });
  assert.deepEqual(result, { code: 'UNSAFE_SOURCE', ok: false });
});

nativeTest('private dependency diagnostics do not escape a failed capture', async t => {
  const f = fixture(t);
  function BrokenDatabase() { throw Error('synthetic-private-canary'); }
  const api = createSnapshotter({ Database: BrokenDatabase, sourceRoots: { auth: f.auth, data: f.data }, backupRoot: f.backupRoot });
  assert.deepEqual(await api.capture(f.pre), { code: 'IO_FAILURE', ok: false });
  assert.equal(fs.existsSync(path.join(f.pre, 'manifest.json')), false);
});

// Focused NEW CURRENT-profile fixtures; not the old102/Q1 suite or an app import.
const authorityKeys = ['AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP',
  'SCAN_BROWSER_ALLOWED_USER_IDS', 'SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS'];
const nullAuthority = Object.fromEntries(authorityKeys.map(key => [key, null]));
const authorityBytes = settings => Buffer.from(JSON.stringify(settings));
const authorityDigest = settings => createHash('sha256').update(JSON.stringify(authorityKeys.map(key => settings[key]))).digest('hex');
const compatible = Object.freeze({ code: 'COMPATIBLE', ok: true });
function compatibilityFixture(t, settings = nullAuthority, change = sql => sql) {
  const f = fixture(t);
  // Replacement touches ONLY disposable DBs this fixture just created. Build
  // constraints independently from public DDL, including actual ALTER/RENAME
  // paths that change sqlite_schema formatting/column insertion positions.
  fs.unlinkSync(f.stores.ledger);
  f.make(f.stores.ledger, change(`
    CREATE TABLE scans_v9 (
      id TEXT PRIMARY KEY, subject TEXT NOT NULL, idempotency_key TEXT NOT NULL,
      registry TEXT NOT NULL, repository TEXT NOT NULL, digest TEXT NOT NULL, platform TEXT NOT NULL,
      state TEXT NOT NULL CHECK (state IN ('queued','running','completed','failed','cancelled','partial')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, fingerprint TEXT,
      checks TEXT NOT NULL DEFAULT '[]', scope TEXT NOT NULL DEFAULT 'image', terminal_at TEXT,
      UNIQUE(subject,idempotency_key)
    ); ALTER TABLE scans_v9 RENAME TO scans;
    CREATE TABLE outbox (scan_id TEXT PRIMARY KEY REFERENCES scans(id), delivered_at TEXT);
    ALTER TABLE outbox ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE outbox ADD COLUMN lease_until INTEGER;
    ALTER TABLE outbox ADD COLUMN next_run_at INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE scan_results_v9 (
      scan_id TEXT PRIMARY KEY REFERENCES scans(id), check_name TEXT NOT NULL CHECK (check_name = 'secret'),
      finding_count INTEGER CHECK (finding_count >= 0), coverage TEXT NOT NULL CHECK (coverage = 'image'),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, scanner_version TEXT,
      outcome TEXT NOT NULL DEFAULT 'unsupported', error_code TEXT,
      CHECK ((outcome = 'failed' AND finding_count IS NULL) OR
        (outcome = 'checked' AND finding_count IS NOT NULL) OR outcome NOT IN ('failed','checked'))
    ); ALTER TABLE scan_results_v9 RENAME TO scan_results;
    CREATE TABLE admission_windows (subject TEXT NOT NULL, minute INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(subject,minute));
    CREATE TABLE scan_findings (scan_id TEXT NOT NULL REFERENCES scans(id), finding_id TEXT NOT NULL,
      rule_id TEXT NOT NULL, line INTEGER, evidence_ref TEXT NOT NULL, PRIMARY KEY(scan_id,finding_id));
    CREATE TABLE scan_events (seq INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL REFERENCES scans(id),
      state TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE INDEX scan_events_by_scan ON scan_events(scan_id,seq);
    CREATE TABLE scan_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      subject TEXT NOT NULL, target TEXT NOT NULL, scope TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, scan_id TEXT);
    CREATE TABLE scan_sbom_results (
      scan_id TEXT PRIMARY KEY REFERENCES scans(id), image TEXT, platform TEXT CHECK (platform = 'linux/amd64'),
      os_name TEXT CHECK (os_name = 'alpine'), os_version TEXT, component_count INTEGER CHECK (component_count BETWEEN 1 AND 1000),
      coverage TEXT NOT NULL CHECK (coverage = 'image'), outcome TEXT NOT NULL CHECK (outcome IN ('checked','failed')),
      scanner_version TEXT, error_code TEXT CHECK (error_code IN ('SCAN_FAILED','SCAN_TIMEOUT','SCAN_UNAVAILABLE')), checked_at TEXT,
      CHECK ((outcome = 'checked' AND image IS NOT NULL AND platform IS NOT NULL AND os_name IS NOT NULL AND os_version IS NOT NULL
        AND component_count IS NOT NULL AND scanner_version IS NOT NULL AND checked_at IS NOT NULL AND error_code IS NULL)
        OR (outcome = 'failed' AND image IS NULL AND platform IS NULL AND os_name IS NULL AND os_version IS NULL
        AND component_count IS NULL AND scanner_version IS NULL AND checked_at IS NULL AND error_code IS NOT NULL))
    );
    CREATE TABLE scan_sbom_components (scan_id TEXT NOT NULL REFERENCES scans(id), ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 999),
      ecosystem TEXT NOT NULL CHECK (ecosystem IN ('apk','npm')), name TEXT NOT NULL, version TEXT NOT NULL,
      PRIMARY KEY(scan_id,ordinal), UNIQUE(scan_id,ecosystem,name,version));
    CREATE TABLE scan_vuln_results (
      scan_id TEXT PRIMARY KEY REFERENCES scans(id), image TEXT, platform TEXT CHECK (platform = 'linux/amd64'),
      finding_count INTEGER CHECK (finding_count BETWEEN 0 AND 1000), coverage TEXT NOT NULL CHECK (coverage = 'image'),
      outcome TEXT NOT NULL CHECK (outcome IN ('checked','failed')), scanner_version TEXT,
      error_code TEXT CHECK (error_code IN ('SCAN_FAILED','SCAN_TIMEOUT','SCAN_UNAVAILABLE')), checked_at TEXT,
      CHECK ((outcome = 'checked' AND image IS NOT NULL AND platform IS NOT NULL AND finding_count IS NOT NULL
        AND scanner_version IS NOT NULL AND checked_at IS NOT NULL AND error_code IS NULL)
        OR (outcome = 'failed' AND image IS NULL AND platform IS NULL AND finding_count IS NULL
        AND scanner_version IS NULL AND checked_at IS NULL AND error_code IS NOT NULL))
    );
    CREATE TABLE scan_vuln_findings (scan_id TEXT NOT NULL REFERENCES scans(id), ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 999),
      finding_id TEXT NOT NULL, cve_id TEXT NOT NULL, ecosystem TEXT NOT NULL CHECK (ecosystem IN ('apk','npm')),
      package_name TEXT NOT NULL, installed_version TEXT NOT NULL,
      severity TEXT NOT NULL CHECK (severity IN ('UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL')),
      severity_sources TEXT NOT NULL, provenance_ref TEXT NOT NULL, fixed_version TEXT,
      PRIMARY KEY(scan_id,ordinal), UNIQUE(scan_id,finding_id));
    ALTER TABLE scan_vuln_findings ADD COLUMN advisory TEXT CHECK(advisory IS NULL OR length(CAST(advisory AS BLOB)) <= 16384);
    CREATE TABLE scan_archive_results (scan_id TEXT PRIMARY KEY REFERENCES scans(id), attempt INTEGER NOT NULL CHECK (attempt > 0),
      report TEXT NOT NULL CHECK (length(report) <= 2000000));
    CREATE TABLE scan_check_results (scan_id TEXT NOT NULL REFERENCES scans(id), check_name TEXT NOT NULL CHECK (check_name = 'config'),
      attempt INTEGER NOT NULL CHECK (attempt > 0), outcome TEXT NOT NULL CHECK (outcome IN ('checked','unsupported','failed','skipped')),
      checks_version TEXT NOT NULL CHECK (checks_version = 'image-config-user-v1'),
      resource_policy_version TEXT NOT NULL CHECK (resource_policy_version = 'image-config-policy-v1'),
      report TEXT NOT NULL CHECK (length(CAST(report AS BLOB)) <= 16384), checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(scan_id,check_name));
    CREATE TABLE scan_execution_profiles (scan_id TEXT PRIMARY KEY REFERENCES scans(id), binding TEXT NOT NULL CHECK(length(CAST(binding AS BLOB)) <= 1024));
    CREATE TABLE scan_cve_policy (scan_id TEXT PRIMARY KEY REFERENCES scans(id),
      policy TEXT NOT NULL CHECK(policy IN ('legacy-db-freshness-v1','cve-db-updated-at-14d-v2')), result_contract_version INTEGER NOT NULL,
      CHECK((policy='legacy-db-freshness-v1' AND result_contract_version=1) OR (policy='cve-db-updated-at-14d-v2' AND result_contract_version=2)));
    CREATE TABLE scan_cve_evidence (scan_id TEXT PRIMARY KEY REFERENCES scans(id), attempt INTEGER NOT NULL CHECK(attempt>0),
      evidence TEXT NOT NULL CHECK(length(CAST(evidence AS BLOB))<=8192));
    PRAGMA user_version=14;`));
  fs.unlinkSync(f.stores.quota);
  f.make(f.stores.quota, `CREATE TABLE quota_meta(id INTEGER PRIMARY KEY CHECK(id=1),clock INTEGER NOT NULL) STRICT;
    CREATE TABLE quota_attempt(id TEXT PRIMARY KEY,user_key TEXT NOT NULL,scan_key TEXT NOT NULL,
      report_hash TEXT NOT NULL,policy_hash TEXT NOT NULL,request_hash TEXT NOT NULL,quota_policy TEXT NOT NULL,
      window INTEGER NOT NULL,expires INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN ('reserved','dispatched','settled','released','fault')),
      reserve_input INTEGER NOT NULL,reserve_output INTEGER NOT NULL,reserve_cost INTEGER NOT NULL,
      input INTEGER NOT NULL CHECK(input>=0),output INTEGER NOT NULL CHECK(output>=0),cost INTEGER NOT NULL CHECK(cost>=0),receipt TEXT) STRICT;
    CREATE INDEX quota_user ON quota_attempt(user_key,window,state); CREATE INDEX quota_scan ON quota_attempt(scan_key,window,state);
    CREATE INDEX quota_cleanup ON quota_attempt(state,window);
    INSERT INTO quota_meta VALUES(1,123456789);
    INSERT INTO quota_attempt VALUES('synthetic-attempt','${'a'.repeat(64)}','${'b'.repeat(64)}','${'c'.repeat(64)}','${'d'.repeat(64)}','${'e'.repeat(64)}','{}',0,1234567890,'fault',17,0,0,17,0,0,'private-compatibility-canary');
    PRAGMA application_id=1145655601; PRAGMA user_version=1;`);
  const auth = f.open('auth');
  try { auth.prepare('UPDATE browser_access SET fingerprint=? WHERE id=1').run(authorityDigest(settings)); }
  finally { auth.close(); }
  return f;
}
function privateFixtureHashes(root) {
  const result = [];
  function walk(p, relative) {
    const stat = fs.lstatSync(p);
    result.push([relative, stat.mode, stat.uid, stat.gid, stat.size]);
    if (stat.isDirectory()) for (const name of fs.readdirSync(p).sort()) walk(path.join(p, name), relative + '/' + name);
    else result.push([relative, createHash('sha256').update(fs.readFileSync(p)).digest('hex')]);
  }
  walk(root, 'fixture'); return result;
}

nativeTest('compatibility matches CURRENT source profile using sealed readonly pre without writes', async t => {
  const f = compatibilityFixture(t);
  assert.equal(CURRENT_PROFILE.sourceAggregate, '29c3ca5bd186d625cc102e2f7e43b4f1e8e168ba3372cabd7840cc21b6676a37');
  assert.deepEqual([CURRENT_PROFILE.auth, CURRENT_PROFILE.ledger, CURRENT_PROFILE.quota], ['0/0', '0/14', '1145655601/1']);
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  const before = privateFixtureHashes(f.root), opens = [];
  function ReadOnlyDatabase(p, options) {
    assert.equal(options.readonly, true); assert.equal(options.fileMustExist, true);
    assert.equal(p.startsWith(path.join(f.pre, 'sealed') + path.sep), true); opens.push(p);
    const db = new Database(p, options); db.exec = () => { throw Error('constructor-write-forbidden'); }; return db;
  }
  const api = createSnapshotter({ Database: ReadOnlyDatabase, sourceRoots: { auth: f.auth, data: f.data }, backupRoot: f.backupRoot });
  assert.deepEqual(await api.compatibility(f.pre, authorityBytes(nullAuthority)), compatible);
  assert.equal(opens.length, 3); assert.deepEqual(privateFixtureHashes(f.root), before);
  const receipt = JSON.stringify(await runCli(['compatibility', '/backup/pre'],
    { Database: ReadOnlyDatabase, sourceRoots: { auth: f.auth, data: f.data }, backupRoot: f.backupRoot }, Readable.from([authorityBytes(nullAuthority)])));
  assert.equal(receipt, '{"code":"COMPATIBLE","ok":true}'); assert.ok(receipt.length < 2048);
  assert.deepEqual(privateFixtureHashes(f.root), before); assert.equal(fs.existsSync(f.post), false);
});

for (const [label, settings] of [
  ['empty', Object.fromEntries(authorityKeys.map(key => [key, '']))],
  ['raw-booleans', { ...nullAuthority, AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true', SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: ' false ' }],
  ['unicode-escape', { ...nullAuthority, AUTH_ORIGIN: 'https://пример.invalid/😀', SCAN_BROWSER_ALLOWED_USER_IDS: 'literal\\quote"\nvalue' }],
]) nativeTest('compatibility preserves exact ordered raw authority: ' + label, async t => {
  const f = compatibilityFixture(t, settings);
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  const reversed = Object.fromEntries(Object.entries(settings).reverse());
  assert.deepEqual(await f.api.compatibility(f.pre, authorityBytes(reversed)), compatible);
  assert.deepEqual(await f.api.compatibility(f.pre, authorityBytes(nullAuthority)), { code: 'INCOMPATIBLE', ok: false });
});

nativeTest('compatibility distinguishes absent-null from empty and binds all four keys, not a key/JWT', async t => {
  const f = compatibilityFixture(t); assert.deepEqual(await f.api.capture(f.pre), okCapture);
  for (const key of authorityKeys) assert.deepEqual(await f.api.compatibility(f.pre, authorityBytes({ ...nullAuthority, [key]: '' })), { code: 'INCOMPATIBLE', ok: false });
  assert.deepEqual(await f.api.compatibility(f.pre, authorityBytes({ ...nullAuthority, OPENROUTER_API_KEY: 'private-canary' })), { code: 'INVALID_ARGUMENTS', ok: false });
  assert.deepEqual(await f.api.compatibility(f.pre, authorityBytes({ ...nullAuthority, SCAN_JWT_SECRET: 'private-canary' })), { code: 'INVALID_ARGUMENTS', ok: false });
});

for (const [label, mutation] of [
  ['fingerprint', f => { const db = f.open('auth'); db.prepare('UPDATE browser_access SET fingerprint=?').run('1'.repeat(64)); db.close(); }],

  ['ledger13', f => { const db = f.open('ledger'); db.pragma('user_version=13'); db.close(); }],
  ['auth-before-insert-trigger', f => { const db = f.open('auth'); db.exec('CREATE TABLE counter(n INTEGER); INSERT INTO counter VALUES(0); CREATE TRIGGER insert_side_effect BEFORE INSERT ON trusted_sessions BEGIN UPDATE counter SET n=n+1; END;'); db.close(); }],
  ['ledger-trigger', f => { const db = f.open('ledger'); db.exec('CREATE TRIGGER noop AFTER INSERT ON scans BEGIN SELECT 1; END;'); db.close(); }],
  ['quota-trigger', f => { const db = f.open('quota'); db.exec('CREATE TRIGGER noop AFTER INSERT ON quota_meta BEGIN SELECT 1; END;'); db.close(); }],
  ['view', f => { const db = f.open('auth'); db.exec('CREATE VIEW projection AS SELECT * FROM users'); db.close(); }],
  ['extra-table', f => { const db = f.open('ledger'); db.exec('CREATE TABLE unreviewed(v)'); db.close(); }],
  ['extra-index', f => { const db = f.open('ledger'); db.exec('CREATE INDEX extra ON scans(state)'); db.close(); }],
  ['missing-index', f => { const db = f.open('ledger'); db.exec('DROP INDEX scan_events_by_scan'); db.close(); }],
  ['wrong-index', f => { const db = f.open('ledger'); db.exec('DROP INDEX scan_events_by_scan; CREATE INDEX scan_events_by_scan ON scan_events(seq,scan_id)'); db.close(); }],
]) nativeTest('compatibility refuses before startup: ' + label, async t => {
  const f = compatibilityFixture(t); mutation(f);
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  const before = privateFixtureHashes(f.root);
  assert.deepEqual(await f.api.compatibility(f.pre, authorityBytes(nullAuthority)), { code: 'INCOMPATIBLE', ok: false });
  assert.deepEqual(privateFixtureHashes(f.root), before);
});

for (const [label, change] of [
  ['weaker-check', sql => sql.replace('CHECK (attempt > 0)', 'CHECK (attempt >= 0)')],
  ['string-enum', sql => sql.replace("'config'", "'CONFIG'")],
  ['missing-unique', sql => sql.replace(', UNIQUE(scan_id,ecosystem,name,version)', '')],
  ['fk-delete', sql => sql.replace('REFERENCES scans(id), delivered_at', 'REFERENCES scans(id) ON DELETE CASCADE, delivered_at')],
  ['conflict', sql => sql.replace('UNIQUE(subject,idempotency_key)', 'UNIQUE(subject,idempotency_key) ON CONFLICT IGNORE')],
  ['collation', sql => sql.replace('subject TEXT NOT NULL, idempotency_key', 'subject TEXT NOT NULL COLLATE NOCASE, idempotency_key')],
]) nativeTest('compatibility rejects exact-constraint drift: ' + label, async t => {
  const f = compatibilityFixture(t, nullAuthority, change);
  const captured = await f.api.capture(f.pre);
  if (label === 'fk-delete') {
    assert.deepEqual(captured, { code: 'INVALID_STORE', ok: false });
    assert.equal((await f.api.compatibility(f.pre, authorityBytes(nullAuthority))).ok, false);
  } else {
    assert.deepEqual(captured, okCapture);
    assert.deepEqual(await f.api.compatibility(f.pre, authorityBytes(nullAuthority)), { code: 'INCOMPATIBLE', ok: false });
  }
});

for (const [label, mutate] of [
  ['auth-id', f => { const db = f.open('auth'); db.pragma('application_id=1'); db.close(); }],
  ['auth-version', f => { const db = f.open('auth'); db.pragma('user_version=1'); db.close(); }],
  ['quota-id', f => { const db = f.open('quota'); db.pragma('application_id=1'); db.close(); }],
  ['ledger-id', f => { const db = f.open('ledger'); db.pragma('application_id=1'); db.close(); }],
  ['ledger15', f => { const db = f.open('ledger'); db.pragma('user_version=15'); db.close(); }],
  ['quota-version', f => { const db = f.open('quota'); db.pragma('user_version=2'); db.close(); }],
  ['backfill', f => { const db = f.open('auth'); db.exec('DELETE FROM trusted_sessions'); db.close(); }],
  ['missing-authority', f => { const db = f.open('auth'); db.exec('DELETE FROM browser_access'); db.close(); }],
  ['missing-table', f => { const db = f.open('auth'); db.exec('DROP TABLE auth_attempts'); db.close(); }],
  ['inflight', f => { const db = f.open('quota'); db.exec("UPDATE quota_attempt SET state='dispatched'"); db.close(); }],
]) nativeTest('compatibility cannot bypass baseline refusal: ' + label, async t => {
  const f = compatibilityFixture(t); mutate(f);
  const captured = await f.api.capture(f.pre); assert.equal(captured.ok, false);
  assert.equal((await f.api.compatibility(f.pre, authorityBytes(nullAuthority))).ok, false);
  assert.equal(fs.existsSync(path.join(f.pre, 'manifest.json')), false);
});

nativeTest('compatibility rejects unconstrained v14 shape despite baseline schema recognition', async t => {
  const f = fixture(t), auth = f.open('auth');
  auth.prepare('UPDATE browser_access SET fingerprint=?').run(authorityDigest(nullAuthority)); auth.close();
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  assert.deepEqual(await f.api.compatibility(f.pre, authorityBytes(nullAuthority)), { code: 'INCOMPATIBLE', ok: false });
});

nativeTest('compatibility rejects missing Auth CHECK without weakening snapshot recognition', async t => {
  const f = compatibilityFixture(t), auth = f.open('auth');
  auth.exec(`DROP TABLE trusted_sessions; CREATE TABLE trusted_sessions (
    token_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,
    session_id TEXT NOT NULL UNIQUE,generation INTEGER NOT NULL);
    INSERT INTO trusted_sessions VALUES('${'c'.repeat(64)}','${'d'.repeat(32)}',1);`); auth.close();
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  assert.deepEqual(await f.api.compatibility(f.pre, authorityBytes(nullAuthority)), { code: 'INCOMPATIBLE', ok: false });
});

nativeTest('compatibility rejects a genuinely recognizable lower-version ledger without migration', async t => {
  const f = fixture(t, 8), auth = f.open('auth');
  auth.prepare('UPDATE browser_access SET fingerprint=?').run(authorityDigest(nullAuthority)); auth.close();
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  assert.deepEqual(await f.api.compatibility(f.pre, authorityBytes(nullAuthority)), { code: 'INCOMPATIBLE', ok: false });
});

nativeTest('compatibility uses the sealed baseline rather than the current original fixture', async t => {
  const f = compatibilityFixture(t); assert.deepEqual(await f.api.capture(f.pre), okCapture);
  fs.writeFileSync(f.stores.auth, 'now-invalid-original-fixture');
  assert.deepEqual(await f.api.compatibility(f.pre, authorityBytes(nullAuthority)), compatible);
  const saved = f.manifest(f.pre).stores.find(s => s.path === 'auth/auth.sqlite');
  fs.appendFileSync(path.join(f.pre, 'sealed', saved.sealed), 'private-tamper');
  assert.equal((await f.api.compatibility(f.pre, authorityBytes(nullAuthority))).ok, false);
});

const flatNull = JSON.stringify(nullAuthority);
for (const [label, input, code = 'INVALID_ARGUMENTS'] of [
  ['empty', Buffer.alloc(0)], ['missing', Buffer.from('{}')], ['extra', authorityBytes({ ...nullAuthority, extra: null })],
  ['duplicate', Buffer.from(flatNull.replace('{', '{"AUTH_ORIGIN":"private-canary",'))],
  ['escaped-duplicate', Buffer.from(flatNull.replace('{', '{"\\u0041UTH_ORIGIN":null,'))],
  ['boolean', authorityBytes({ ...nullAuthority, AUTH_ORIGIN: true })],
  ['number', authorityBytes({ ...nullAuthority, AUTH_ORIGIN: 123 })],
  ['array', authorityBytes({ ...nullAuthority, AUTH_ORIGIN: [] })],
  ['nested', authorityBytes({ ...nullAuthority, AUTH_ORIGIN: {} })],
  ['trailing', Buffer.from(flatNull + '{}')], ['comma', Buffer.from(flatNull.slice(0, -1) + ',}')],
  ['nul', authorityBytes({ ...nullAuthority, AUTH_ORIGIN: '\0' })],
  ['surrogate', authorityBytes({ ...nullAuthority, AUTH_ORIGIN: '\ud800' })],
  ['utf8', Buffer.from([0xff])], ['bom', Buffer.concat([Buffer.from([0xef,0xbb,0xbf]), Buffer.from(flatNull)])],
  ['value-cap', authorityBytes({ ...nullAuthority, AUTH_ORIGIN: 'x'.repeat(4097) }), 'LIMIT'],
  ['unicode-byte-cap', authorityBytes({ ...nullAuthority, AUTH_ORIGIN: 'я'.repeat(2049) }), 'LIMIT'],
  ['wire-cap', Buffer.alloc(16385, 32), 'LIMIT'],
]) test('compatibility private input refuses without dependency resolution: ' + label, async () => {
  const result = await runCli(['compatibility', '/backup/pre'], undefined, Readable.from([input]));
  assert.deepEqual(result, { code, ok: false }); assert.equal(JSON.stringify(result).includes('private-canary'), false);
});

nativeTest('compatibility enforces private quota original mode from the captured inventory', async t => {
  const f = compatibilityFixture(t); fs.chmodSync(f.stores.quota, 0o644);
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  assert.deepEqual(await f.api.compatibility(f.pre, authorityBytes(nullAuthority)), { code: 'INCOMPATIBLE', ok: false });
});

nativeTest('compatibility refuses original quota WAL sidecars even when sealed schema matches', async t => {
  const f = compatibilityFixture(t), db = f.open('quota');
  t.after(() => { if (db.open) db.close(); });
  db.pragma('journal_mode=WAL'); db.pragma('wal_autocheckpoint=0');
  db.exec('UPDATE quota_attempt SET reserve_input=reserve_input+1');
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  assert.deepEqual(await f.api.compatibility(f.pre, authorityBytes(nullAuthority)), { code: 'INCOMPATIBLE', ok: false });
});

nativeTest('compatibility bounded stdin handles split UTF-8 bytes without value normalization', async t => {
  const settings = { ...nullAuthority, AUTH_ORIGIN: 'https://я.invalid/😀' }, f = compatibilityFixture(t, settings);
  assert.deepEqual(await f.api.capture(f.pre), okCapture);
  const bytes = authorityBytes(settings), input = Readable.from(Array.from(bytes, byte => Buffer.from([byte])));
  assert.deepEqual(await runCli(['compatibility', '/backup/pre'],
    { Database, sourceRoots: { auth: f.auth, data: f.data }, backupRoot: f.backupRoot }, input), compatible);
});

test('compatibility interrupted private stdin has a closed IO refusal', async () => {
  const input = Readable.from((async function* () { yield Buffer.from('{'); throw Error('private-input-canary'); })());
  assert.deepEqual(await runCli(['compatibility', '/backup/pre'], undefined, input), { code: 'IO_FAILURE', ok: false });
});

nativeTest('compatibility closed failure hides private dependency diagnostics', async t => {
  const f = compatibilityFixture(t); assert.deepEqual(await f.api.capture(f.pre), okCapture);
  function PrivateFailure() { throw Error('private-compatibility-canary'); }
  const result = await runCli(['compatibility', '/backup/pre'],
    { Database: PrivateFailure, sourceRoots: { auth: f.auth, data: f.data }, backupRoot: f.backupRoot }, Readable.from([Buffer.from(flatNull)]));
  assert.deepEqual(result, { code: 'IO_FAILURE', ok: false });
  assert.equal(JSON.stringify(result).includes('canary'), false);
});

test('compatibility CLI error receipt never reflects private stdin or diagnostics', async () => {
  const script = fileURLToPath(new URL('./sqlite_state_snapshot.mjs', import.meta.url));
  for (const args of [['compatibility', '/backup/pre'], ['compatibility', '/backup/post'], ['compatibility', '/backup/pre', '--profile=OLD']]) {
    const child = spawnSync(process.execPath, [script, ...args], { input: '{"private-canary":null}', encoding: 'utf8', timeout: 5000, maxBuffer: 2048 });
    assert.equal(child.status, 1); assert.equal(child.stderr, '');
    assert.equal(child.stdout, '{"code":"INVALID_ARGUMENTS","ok":false}\n');
  }
});

// NEW focused migration fixtures. These READ fixed PUBLIC source text only,
// never import an app constructor. Author verified all13 pre14 literal blocks
// byte-identical to ACTUAL acquired OLD ledger9b0b3cce... (also evidence458).
// Each fixture naturally builds OLD13 from an EMPTY disposable file, not a
// current14 DB with a fake version header/two tables removed.
function publicSource(relative, expected) {
  const p = fileURLToPath(new URL('../../api/src/' + relative, import.meta.url));
  const fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(fd); assert.ok(before.isFile() && before.size <= 100000);
    const bytes = fs.readFileSync(fd); assert.equal(createHash('sha256').update(bytes).digest('hex'), expected);
    assert.equal(fs.fstatSync(fd).mtimeMs, before.mtimeMs); return bytes.toString('utf8');
  } finally { fs.closeSync(fd); }
}
function migrationFixture(t, { authFamily = 'old', ledgerVersion = 13, native = Database } = {}) {
  const f = compatibilityFixture(t);
  fs.unlinkSync(f.stores.ledger);
  const ledgerSource = publicSource('ledger/ledger.ts', 'd2b6993b0de701a543315dfddd542c51cee3fbc6b18bb982eb972f0f3c5f33d4');
  const closure = ledgerSource.slice(ledgerSource.indexOf('constructor(filename'), ledgerSource.indexOf('if (version < 14)'));
  const sql = [...closure.matchAll(/this\.db\.exec\(`([^`]*)`\)/g)].map(match => match[1]);
  assert.equal(sql.length, 13); assert.ok(sql.every(text => !text.includes('${')));
  const ledger = new Database(f.stores.ledger); ledger.pragma('foreign_keys=OFF'); ledger.exec('BEGIN IMMEDIATE');
  for (const block of sql) ledger.exec(block);
  ledger.exec('COMMIT'); ledger.pragma('foreign_keys=ON'); assert.equal(ledger.pragma('user_version', { simple: true }), 13);
  const checks = ['["vuln"]','["secret","sbom","vuln","config"]','["secret"]','[]','[ "vuln" ]','["vuln","vuln"]','["vuln","secret"]','invalid'];
  const insertScan = ledger.prepare(`INSERT INTO scans(id,subject,idempotency_key,registry,repository,digest,platform,state,checks) VALUES(?,?,?,?,?,?,?,'completed',?)`);
  checks.forEach((check, i) => insertScan.run('scan-' + i, 'subject-' + i, 'key-' + i, 'registry', 'repository', 'digest', 'linux/amd64', check));
  ledger.exec(`INSERT INTO outbox VALUES('scan-0','delivered',3,123,456);
    INSERT INTO admission_windows VALUES('subject',1,2);
    INSERT INTO scan_results VALUES('scan-0','secret',0,'image','stored','scanner','checked',NULL);
    INSERT INTO scan_findings VALUES('scan-0','finding','rule',NULL,'opaque');
    INSERT INTO scan_events(scan_id,state) VALUES('scan-0','completed');
    INSERT INTO scan_audit(subject,target,scope,decision,reason,scan_id) VALUES('subject','target','image','allow','stored','scan-0');
    INSERT INTO scan_sbom_results(scan_id,coverage,outcome,error_code) VALUES('scan-0','image','failed','SCAN_FAILED');
    INSERT INTO scan_sbom_components VALUES('scan-0',0,'npm','package','1');
    INSERT INTO scan_vuln_results(scan_id,coverage,outcome,error_code) VALUES('scan-0','image','failed','SCAN_FAILED');
    INSERT INTO scan_vuln_findings VALUES('scan-0',0,'finding','CVE-synthetic','npm','package','1','HIGH','[]','opaque',NULL,'unicode-я');
    INSERT INTO scan_archive_results VALUES('scan-0',1,' exact text ');
    INSERT INTO scan_check_results VALUES('scan-0','config',1,'checked','image-config-user-v1','image-config-policy-v1','{}','stored');
    INSERT INTO scan_execution_profiles VALUES('scan-0','{}');`);
  if (ledgerVersion === 14) {
    const branch = ledgerSource.slice(ledgerSource.indexOf('if (version < 14)'), ledgerSource.indexOf('const insert =', ledgerSource.indexOf('if (version < 14)')));
    const added = /this\.db\.exec\(`([^`]*)`\)/.exec(branch)[1]; ledger.exec(added);
    ledger.prepare('INSERT INTO scan_cve_policy VALUES(?,?,1)').run('scan-0', 'legacy-db-freshness-v1');
    ledger.pragma('user_version=14');
  } else if (ledgerVersion !== 13) ledger.pragma('user_version=' + ledgerVersion);
  ledger.close(); fs.chmodSync(f.stores.ledger, 0o600);
  if (authFamily === 'old') {
    fs.unlinkSync(f.stores.auth);
    const authSource = publicSource('auth/auth.store.ts', '871b3fed4ecd3320ec19cc27cfa05fc083587efd96b5eb781f56cc29f17a3626');
    const base = /this\.db\.exec\(`([^`]*)`\)/.exec(authSource)[1];
    // Exact base constructor block verified against OLD b39f5480..., three tables.
    f.make(f.stores.auth, base + `INSERT INTO users VALUES('${'a'.repeat(32)}','private-account-canary','${'b'.repeat(32)}',zeroblob(64));
      INSERT INTO sessions VALUES('${'c'.repeat(64)}','${'a'.repeat(32)}',1234567890,NULL);
      INSERT INTO auth_attempts VALUES('opaque-bucket',2,1234567890);`);
  }
  const migrationApi = createSnapshotter({ Database: native, sourceRoots: { auth: f.auth, data: f.data }, backupRoot: f.backupRoot, preservationMigration: true });
  return { ...f, migrationApi };
}
const planned = { code: 'PLANNED', ok: true }, migrated = { code: 'MIGRATED', ok: true }, migrationMatch = { code: 'MIGRATION_MATCH', ok: true };
const readFixture = p => JSON.parse(fs.readFileSync(p, 'utf8'));
async function migrateFixture(f) {
  assert.deepEqual(await f.migrationApi.capture(f.pre), okCapture);
  assert.deepEqual(await f.migrationApi.planMigration(f.pre, authorityBytes(nullAuthority)), planned);
  assert.deepEqual(await f.migrationApi.applyMigration(f.pre), migrated);
}

nativeTest('migration OLD3/auth + actual OLD13 preserves ALL original logical state and quota', async t => {
  const f = migrationFixture(t), calls = [];
  function Guarded(p, options) {
    if (p === f.stores.quota) throw Error('quota-original-connection-forbidden');
    if ([f.stores.auth, f.stores.ledger].includes(p)) {
      assert.equal(options.readonly, false); assert.equal(options.fileMustExist, true);
      assert.ok(fs.existsSync(path.join(f.backupRoot, 'migration', 'apply-attempt.json'))); calls.push(p);
    }
    return new Database(p, options);
  }
  const api = createSnapshotter({ Database: Guarded, sourceRoots: { auth: f.auth, data: f.data }, backupRoot: f.backupRoot, preservationMigration: true });
  assert.deepEqual(await api.capture(f.pre), okCapture); assert.equal(calls.length, 0);
  const baseline = privateFixtureHashes(f.pre), originals = [fs.readFileSync(f.stores.auth), fs.readFileSync(f.stores.ledger), fs.readFileSync(f.stores.quota)];
  assert.deepEqual(await api.planMigration(f.pre, authorityBytes(nullAuthority)), planned); assert.equal(calls.length, 0);
  assert.deepEqual(privateFixtureHashes(f.pre), baseline);
  [f.stores.auth, f.stores.ledger, f.stores.quota].forEach((p, i) => assert.deepEqual(fs.readFileSync(p), originals[i]));
  assert.deepEqual(await api.applyMigration(f.pre), migrated); assert.equal(calls.length, 2);
  assert.deepEqual(privateFixtureHashes(f.pre), baseline); assert.deepEqual(fs.readFileSync(f.stores.quota), originals[2]);
  assert.deepEqual(await api.capture(f.post), okCapture);
  assert.deepEqual(await api.compareMigrated(f.pre, f.post), migrationMatch);
  assert.deepEqual(await api.compatibility(f.post, authorityBytes(nullAuthority)), compatible);
  const pre = f.manifest(f.pre), post = f.manifest(f.post);
  const beforeAuth = pre.stores.find(s => s.path === 'auth/auth.sqlite').logical;
  const afterAuth = post.stores.find(s => s.path === 'auth/auth.sqlite').logical;
  for (const old of beforeAuth.tables) assert.deepEqual(afterAuth.tables.find(table => table.name === old.name), old);
  const beforeLedger = pre.stores.find(s => s.path === 'data/ledger.sqlite').logical;
  const afterLedger = post.stores.find(s => s.path === 'data/ledger.sqlite').logical;
  assert.equal(beforeLedger.schema.userVersion, '13'); assert.equal(afterLedger.schema.userVersion, '14');
  for (const old of beforeLedger.tables) assert.deepEqual(afterLedger.tables.find(table => table.name === old.name), old);
  assert.equal(afterLedger.tables.find(table => table.name === 'scan_cve_policy').rows, 2);
  assert.equal(afterLedger.tables.find(table => table.name === 'scan_cve_evidence').rows, 0);
  assert.deepEqual(post.stores.find(s => s.path === 'auth/llm-usage.sqlite').logical, pre.stores.find(s => s.path === 'auth/llm-usage.sqlite').logical);
  assert.equal(JSON.stringify(migrationMatch).includes('private-account-canary'), false);
  assert.equal(MIGRATION_PROFILE.oldLedgerSource, '9b0b3cce477da38aa91aeba2946a9b1ab334615f9b3f3a5d8273a45b36c14626');
});

nativeTest('migration real committed WAL on OLD auth is captured and never dropped', async t => {
  const f = migrationFixture(t), auth = f.open('auth');
  t.after(() => { if (auth.open) auth.close(); });
  auth.pragma('journal_mode=WAL'); auth.pragma('wal_autocheckpoint=0');
  auth.prepare('INSERT INTO users VALUES(?,?,?,?)').run('1'.repeat(32), 'private-WAL-account', '2'.repeat(32), Buffer.alloc(64, 1));
  auth.prepare('INSERT INTO sessions VALUES(?,?,?,NULL)').run('3'.repeat(64), '1'.repeat(32), 2345678901);
  const main = fs.readFileSync(f.stores.auth), wal = fs.readFileSync(f.stores.auth + '-wal');
  assert.deepEqual(await f.migrationApi.capture(f.pre), okCapture);
  assert.deepEqual(fs.readFileSync(f.stores.auth), main); assert.deepEqual(fs.readFileSync(f.stores.auth + '-wal'), wal);
  assert.deepEqual(await f.migrationApi.planMigration(f.pre, authorityBytes(nullAuthority)), planned);
  assert.deepEqual(await f.migrationApi.applyMigration(f.pre), migrated);
  assert.deepEqual(await f.migrationApi.capture(f.post), okCapture);
  assert.deepEqual(await f.migrationApi.compareMigrated(f.pre, f.post), migrationMatch);
  assert.equal(f.manifest(f.post).stores.find(s => s.path === 'auth/auth.sqlite').logical.tables.find(table => table.name === 'users').rows, 2);
});

nativeTest('migration retains preexisting trusted generations/incarnation and adds only missing mappings', async t => {
  const f = migrationFixture(t, { authFamily: 'current' }), auth = f.open('auth');
  auth.exec('UPDATE trusted_sessions SET generation=7');
  auth.prepare('INSERT INTO sessions VALUES(?,?,?,NULL)').run('1'.repeat(64), 'a'.repeat(32), 2345678901); auth.close();
  const check = f.open('auth'), browser = check.prepare('SELECT * FROM browser_access').get(); check.close();
  await migrateFixture(f);
  const after = f.open('auth');
  assert.deepEqual(after.prepare('SELECT * FROM browser_access').get(), browser);
  assert.equal(after.prepare('SELECT generation FROM trusted_sessions WHERE token_hash=?').get('c'.repeat(64)).generation, 7);
  assert.equal(after.prepare('SELECT count(*) AS n FROM trusted_sessions').get().n, 2); after.close();
  assert.deepEqual(await f.migrationApi.capture(f.post), okCapture);
  assert.deepEqual(await f.migrationApi.compareMigrated(f.pre, f.post), migrationMatch);
});

nativeTest('migration exact existing current14 is a no-logical-change plan/apply', async t => {
  const f = migrationFixture(t, { authFamily: 'current', ledgerVersion: 14 }); await migrateFixture(f);
  assert.deepEqual(await f.migrationApi.capture(f.post), okCapture);
  assert.deepEqual(await f.migrationApi.compareMigrated(f.pre, f.post), migrationMatch);
  assert.deepEqual(f.manifest(f.pre).stores.map(s => s.logical), f.manifest(f.post).stores.map(s => s.logical));
});

nativeTest('migration legacy capture is EXPLICIT and cannot loosen normal CURRENT mode', async t => {
  const f = migrationFixture(t);
  assert.equal((await f.api.capture(f.pre)).ok, false);
  const separate = path.join(f.root, 'explicit-backup'); fs.mkdirSync(separate, { mode: 0o700 });
  const api = createSnapshotter({ Database, sourceRoots: { auth: f.auth, data: f.data }, backupRoot: separate, preservationMigration: true });
  const pre = path.join(separate, 'pre'); assert.deepEqual(await api.capture(pre), okCapture);
  const normal = createSnapshotter({ Database, sourceRoots: { auth: f.auth, data: f.data }, backupRoot: separate });
  assert.equal((await normal.compatibility(pre, authorityBytes(nullAuthority))).ok, false);
  assert.equal((await normal.planMigration(pre, authorityBytes(nullAuthority))).ok, false);
});

for (const [label, mutate] of [
  ['version12', f => { const db = f.open('ledger'); db.pragma('user_version=12'); db.close(); }],
  ['version15', f => { const db = f.open('ledger'); db.pragma('user_version=15'); db.close(); }],
  ['auth-trigger', f => { const db = f.open('auth'); db.exec('CREATE TRIGGER unsafe BEFORE INSERT ON sessions BEGIN SELECT 1; END;'); db.close(); }],
  ['ledger-extra-index', f => { const db = f.open('ledger'); db.exec('CREATE INDEX unsafe ON scans(state)'); db.close(); }],
  ['quota-clock', f => { const db = f.open('quota'); db.exec('UPDATE quota_meta SET clock=-1'); db.close(); }],
  ['queued', f => { const db = f.open('ledger'); db.exec("UPDATE scans SET state='queued' WHERE id='scan-0'"); db.close(); }],
  ['reserved', f => { const db = f.open('quota'); db.exec("UPDATE quota_attempt SET state='reserved'"); db.close(); }],
]) nativeTest('migration refuses unsupported baseline before a plan/write: ' + label, async t => {
  const f = migrationFixture(t); mutate(f);
  assert.equal((await f.migrationApi.capture(f.pre)).ok, false);
  assert.equal((await f.migrationApi.planMigration(f.pre, authorityBytes(nullAuthority))).ok, false);
  assert.equal(fs.existsSync(path.join(f.backupRoot, 'migration', 'apply-attempt.json')), false);
});

nativeTest('migration refuses existing browser fingerprint mismatch instead of rotating it', async t => {
  const f = migrationFixture(t, { authFamily: 'current' }), db = f.open('auth');
  db.prepare('UPDATE browser_access SET fingerprint=?').run('1'.repeat(64)); db.close();
  assert.deepEqual(await f.migrationApi.capture(f.pre), okCapture);
  const before = privateFixtureHashes(f.auth);
  assert.deepEqual(await f.migrationApi.planMigration(f.pre, authorityBytes(nullAuthority)), { code: 'INCOMPATIBLE', ok: false });
  assert.deepEqual(privateFixtureHashes(f.auth), before); assert.equal(fs.existsSync(path.join(f.backupRoot, 'migration')), false);
});

for (const [label, edit] of [
  ['quota', f => { const db = f.open('quota'); db.exec('UPDATE quota_meta SET clock=clock+1'); db.close(); }],
  ['users', f => { const db = f.open('auth'); db.exec("UPDATE users SET email='different'"); db.close(); }],
  ['session', f => { const db = f.open('auth'); db.exec('UPDATE sessions SET expires_at=expires_at+1'); db.close(); }],
  ['old-ledger', f => { const db = f.open('ledger'); db.exec("UPDATE scan_archive_results SET report='changed'"); db.close(); }],
  ['extra-policy', f => { const db = f.open('ledger'); db.prepare('INSERT INTO scan_cve_policy VALUES(?,?,1)').run('scan-2','legacy-db-freshness-v1'); db.close(); }],
  ['evidence', f => { const db = f.open('ledger'); db.prepare('INSERT INTO scan_cve_evidence VALUES(?,?,?)').run('scan-0',1,'fabricated'); db.close(); }],
  ['generation', f => { const db = f.open('auth'); db.exec('UPDATE trusted_sessions SET generation=2'); db.close(); }],
  ['mapping-id', f => { const db = f.open('auth'); db.prepare('UPDATE trusted_sessions SET session_id=?').run('1'.repeat(32)); db.close(); }],
  ['mode', f => fs.chmodSync(f.stores.auth, 0o644)],
  ['ordinary', f => fs.writeFileSync(path.join(f.data,'worker.ready'), 'changed', { mode: 0o600 })],
]) nativeTest('migration ALL-state comparator refuses non-allowlisted drift: ' + label, async t => {
  const f = migrationFixture(t); fs.writeFileSync(path.join(f.data,'worker.ready'), 'original', { mode: 0o600 });
  await migrateFixture(f); edit(f);
  assert.deepEqual(await f.migrationApi.capture(f.post), okCapture);
  assert.equal((await f.migrationApi.compareMigrated(f.pre, f.post)).ok, false);
});

nativeTest('migration stale originals and changed inode cannot reach writable constructors', async t => {
  const f = migrationFixture(t); assert.deepEqual(await f.migrationApi.capture(f.pre), okCapture);
  assert.deepEqual(await f.migrationApi.planMigration(f.pre, authorityBytes(nullAuthority)), planned);
  const bytes = fs.readFileSync(f.stores.auth); fs.unlinkSync(f.stores.auth); fs.writeFileSync(f.stores.auth, bytes, { mode: 0o600 });
  assert.equal((await f.migrationApi.applyMigration(f.pre)).ok, false);
  assert.equal(fs.existsSync(path.join(f.backupRoot, 'migration', 'apply-attempt.json')), false);
});

nativeTest('migration private plan tampering refuses without new original writes', async t => {
  const f = migrationFixture(t); assert.deepEqual(await f.migrationApi.capture(f.pre), okCapture);
  assert.deepEqual(await f.migrationApi.planMigration(f.pre, authorityBytes(nullAuthority)), planned);
  const p = path.join(f.backupRoot, 'migration', 'plan.json'), plan = readFixture(p);
  plan.auth.mappings[0][3] = 2; fs.writeFileSync(p, JSON.stringify(plan));
  assert.equal((await f.migrationApi.applyMigration(f.pre)).ok, false);
  const auth = f.open('auth'); assert.equal(auth.prepare("SELECT count(*) AS n FROM sqlite_schema WHERE name='trusted_sessions'").get().n, 0); auth.close();
});

nativeTest('migration partial commit retains attempted HOLD and forbids retries/compensating restore', async t => {
  const f = migrationFixture(t);
  assert.deepEqual(await f.migrationApi.capture(f.pre), okCapture);
  assert.deepEqual(await f.migrationApi.planMigration(f.pre, authorityBytes(nullAuthority)), planned);
  let originalOpens = 0;
  function Failing(p, options) {
    const db = new Database(p, options);
    if ([f.stores.auth, f.stores.ledger].includes(p)) originalOpens++;
    if (p === f.stores.ledger) { const exec = db.exec.bind(db); db.exec = sql => { if (sql === 'COMMIT') throw Error('private-partial-canary'); return exec(sql); }; }
    return db;
  }
  const api = createSnapshotter({ Database: Failing, sourceRoots: { auth: f.auth, data: f.data }, backupRoot: f.backupRoot, preservationMigration: true });
  const failed = await api.applyMigration(f.pre); assert.deepEqual(failed, { code: 'IO_FAILURE', ok: false });
  assert.equal(originalOpens, 2); assert.ok(fs.existsSync(path.join(f.backupRoot,'migration','apply-attempt.json')));
  assert.equal(fs.existsSync(path.join(f.backupRoot,'migration','applied.json')), false);
  assert.equal((await api.applyMigration(f.pre)).ok, false); assert.equal(originalOpens, 2);
  const auth = f.open('auth'), ledger = f.open('ledger');
  assert.equal(auth.prepare('SELECT count(*) AS n FROM trusted_sessions').get().n, 1);
  assert.equal(ledger.pragma('user_version', { simple: true }), 13); auth.close(); ledger.close();
});

for (const family of ['trusted-only', 'browser-only', 'empty-technical', 'empty-old'])
  nativeTest('migration exact known auth family supports additive-only records: ' + family, async t => {
    const f = migrationFixture(t, { authFamily: family === 'empty-old' ? 'old' : 'current' });
    const db = f.open('auth');
    if (family === 'trusted-only') db.exec('DROP TABLE browser_access');
    if (family === 'browser-only') db.exec('DROP TABLE trusted_sessions');
    if (family === 'empty-technical') db.exec('DELETE FROM trusted_sessions; DELETE FROM browser_access');
    if (family === 'empty-old') db.exec('DELETE FROM sessions; DELETE FROM users; DELETE FROM auth_attempts');
    db.close();
    assert.deepEqual(await f.migrationApi.capture(f.pre), okCapture);
    assert.deepEqual(await f.migrationApi.planMigration(f.pre, authorityBytes(nullAuthority)), planned);
    assert.deepEqual(await f.migrationApi.applyMigration(f.pre), migrated);
    assert.deepEqual(await f.migrationApi.capture(f.post), okCapture);
    assert.deepEqual(await f.migrationApi.compareMigrated(f.pre, f.post), migrationMatch);
    assert.deepEqual(await f.migrationApi.compatibility(f.post, authorityBytes(nullAuthority)), compatible);
  });

nativeTest('migration raw absent/empty/Unicode authority has exact CURRENT fingerprint and closed receipts', async t => {
  const f = migrationFixture(t), settings = { ...nullAuthority, AUTH_ORIGIN: '', SCAN_BROWSER_ALLOWED_USER_IDS: 'я🙂' };
  const results = [await f.migrationApi.capture(f.pre), await f.migrationApi.planMigration(f.pre, authorityBytes(settings)),
    await f.migrationApi.applyMigration(f.pre), await f.migrationApi.capture(f.post), await f.migrationApi.compareMigrated(f.pre, f.post),
    await f.migrationApi.compatibility(f.post, authorityBytes(settings))];
  assert.deepEqual(results, [okCapture, planned, migrated, okCapture, migrationMatch, compatible]);
  for (const result of results) assert.deepEqual(Object.keys(result).sort(), ['code','ok']);
  assert.equal((await f.migrationApi.compatibility(f.post, authorityBytes(nullAuthority))).ok, false);
});

for (const [label, mutate] of [
  ['old-invalid-id', f => { const db = f.open('auth'); db.exec("UPDATE users SET salt='invalid'"); db.close(); }],
  ['old-invalid-token', f => { const db = f.open('auth'); db.exec("UPDATE sessions SET token_hash='invalid'"); db.close(); }],
  ['technical-wrong-ddl', f => { const db = f.open('auth'); db.exec('CREATE TABLE browser_access(id INTEGER PRIMARY KEY,fingerprint TEXT NOT NULL,incarnation TEXT NOT NULL)'); db.close(); }],
  ['technical-orphan', f => { const db = f.open('auth'); db.pragma('foreign_keys=OFF'); db.exec(`CREATE TABLE trusted_sessions(token_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,session_id TEXT NOT NULL UNIQUE,generation INTEGER NOT NULL CHECK(generation>0));`);
    db.prepare('INSERT INTO trusted_sessions VALUES(?,?,1)').run('f'.repeat(64),'f'.repeat(32)); db.close(); }],
]) nativeTest('migration refuses invalid old/auth technical records before plan: ' + label, async t => {
  const f = migrationFixture(t); mutate(f);
  assert.equal((await f.migrationApi.capture(f.pre)).ok, false);
  assert.equal(fs.existsSync(path.join(f.backupRoot,'migration')), false);
});

for (const [label, mutate] of [
  ['unexpected-file', f => fs.writeFileSync(path.join(f.backupRoot,'migration','unreviewed'), 'private-canary', { mode:0o600 })],
  ['unexpected-directory', f => fs.mkdirSync(path.join(f.backupRoot,'migration','unreviewed'), { mode:0o700 })],
  ['clone-drift', f => { const db = new Database(path.join(f.backupRoot,'migration','auth.sqlite')); db.exec("UPDATE users SET email='private-clone-canary'"); db.close(); }],
  ['attempt-tamper', f => fs.writeFileSync(path.join(f.backupRoot,'migration','apply-attempt.json'), '{}', { mode:0o600 })],
  ['applied-without-attempt', f => fs.writeFileSync(path.join(f.backupRoot,'migration','applied.json'), '{}', { mode:0o600 })],
  ['plan-symlink', f => { const p = path.join(f.backupRoot,'migration','plan.json'); fs.renameSync(p, path.join(f.root,'plan-alias')); fs.symlinkSync(path.join(f.root,'plan-alias'),p); }],
  ['plan-hardlink', f => fs.linkSync(path.join(f.backupRoot,'migration','plan.json'), path.join(f.root,'plan-alias'))],
]) nativeTest('migration closed private plan tree refuses BEFORE original RW: ' + label, async t => {
  const f = migrationFixture(t); assert.deepEqual(await f.migrationApi.capture(f.pre), okCapture);
  assert.deepEqual(await f.migrationApi.planMigration(f.pre, authorityBytes(nullAuthority)), planned); mutate(f);
  let opens = 0;
  function Guarded(p, options) { if ([f.stores.auth,f.stores.ledger,f.stores.quota].includes(p)) opens++; return new Database(p, options); }
  const api = createSnapshotter({ Database:Guarded,sourceRoots:{ auth:f.auth,data:f.data },backupRoot:f.backupRoot,preservationMigration:true });
  assert.equal((await api.applyMigration(f.pre)).ok, false); assert.equal(opens,0);
});

nativeTest('migration captures optional SQLite untouched but refuses unqualified extra consumers at plan', async t => {
  const f = migrationFixture(t), optional = path.join(f.auth,'optional.sqlite');
  f.make(optional, 'CREATE TABLE opaque(value); INSERT INTO opaque VALUES(zeroblob(5))');
  const original = fs.readFileSync(optional);
  assert.deepEqual(await f.migrationApi.capture(f.pre), okCapture);
  assert.equal((await f.migrationApi.planMigration(f.pre, authorityBytes(nullAuthority))).ok, false);
  assert.deepEqual(fs.readFileSync(optional), original); assert.equal(fs.existsSync(path.join(f.backupRoot,'migration')),false);
});

nativeTest('migration checks aggregate final clone bytes and max_page_count without bound widening', async t => {
  const f = migrationFixture(t); assert.deepEqual(await f.migrationApi.capture(f.pre), okCapture);
  let limits = 0;
  function Guarded(p, options) {
    const db = new Database(p,options), pragma = db.pragma.bind(db);
    if (path.dirname(p) === path.join(f.backupRoot,'migration')) db.pragma = (sql, opts) => {
      if (sql.startsWith('max_page_count = ')) { limits++; assert.ok(Number(sql.split(' = ')[1]) * Number(pragma('page_size',{ simple:true })) <= LIMITS.bytes); }
      return pragma(sql,opts);
    };
    return db;
  }
  const api = createSnapshotter({ Database:Guarded,sourceRoots:{ auth:f.auth,data:f.data },backupRoot:f.backupRoot,preservationMigration:true });
  assert.deepEqual(await api.planMigration(f.pre, authorityBytes(nullAuthority)), planned); assert.equal(limits,2);
  assert.ok(['auth.sqlite','ledger.sqlite'].reduce((n,name) => n + fs.statSync(path.join(f.backupRoot,'migration',name)).size,0) <= LIMITS.bytes);
});

test('migration private-input CLI stdout remains closed and never reflects settings/errors', () => {
  const child = spawnSync(process.execPath, [fileURLToPath(new URL('./sqlite_state_snapshot.mjs', import.meta.url)),
    'plan-migration','--preservation-migration','/backup/pre'], {
    input: JSON.stringify({ ...nullAuthority, OPENROUTER_API_KEY:'private-migration-canary' }), encoding:'utf8',timeout:5000,maxBuffer:2048,
  });
  assert.equal(child.status,1); assert.equal(child.stderr,'');
  assert.equal(child.stdout,'{"code":"INVALID_ARGUMENTS","ok":false}\n');
});

test('migration closed CLI requires explicit flag and rejects private input extras', async () => {
  for (const args of [['plan-migration','/backup/pre'], ['apply-migration','/backup/pre'], ['compare-migrated','/backup/pre','/backup/post'],
    ['apply-migration','--preservation-migration','/backup/post']]) assert.deepEqual(await runCli(args), { code: 'INVALID_ARGUMENTS', ok: false });
  assert.deepEqual(await runCli(['plan-migration','--preservation-migration','/backup/pre'], undefined,
    Readable.from([authorityBytes({ ...nullAuthority, OPENROUTER_API_KEY:'private-canary' })])), { code:'INVALID_ARGUMENTS',ok:false });
});
