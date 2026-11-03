// Store-only extraction of legacy-empty-h7v3.test.ts; service orchestration is covered separately.
import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, readFileSync, statSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { HttpException } from '@nestjs/common';
import { HistoryStore } from '../history-store.js';
import { HISTORY, hashValue, reportBinding, validateHead, type HistoryHead, type Turn } from '../history-contract.js';
import { HISTORY_OWNER_CAPACITY, assertOwnerCapacity, historyOccupancy } from '../history-capacity.js';
import { openAiReport } from './openai-core.fixture.js';

const owner = 'a'.repeat(32), foreign = 'b'.repeat(32);
const capacity = (error: unknown) => error instanceof HttpException && error.getStatus() === 409 &&
  (error.getResponse() as { errorCode: string }).errorCode === 'LLM_HISTORY_CAPACITY';
const unavailable = (error: unknown) => error instanceof HttpException && error.getStatus() === 503 &&
  (error.getResponse() as { errorCode: string }).errorCode === 'LLM_HISTORY_UNAVAILABLE';
function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'legacy-empty-h7v3-'));
  const path = join(directory, 'llm-history.sqlite');
  const store = new HistoryStore(path, true), db = new Database(path);
  return { directory, path, store, db, close() { db.close(); store.close(); rmSync(directory, { recursive: true, force: true }); } };
}
function empty(): HistoryHead { return { epoch: randomUUID(), revision: 0, turns: [], decisions: [], pending: null }; }
function decision(scanId = randomUUID()) {
  return { id: randomUUID(), mutationId: randomUUID(), kind: 'user-decision' as const, text: 'Проверить вручную.',
    report: reportBinding({ ...openAiReport, scanId }), sources: [] };
}
function insert(db: Database.Database, scope: string, head: HistoryHead, padding = true) {
  validateHead(head);
  // Retain deliberately noncanonical allocation whitespace as a byte-preservation
  // oracle. Historical head checksums bind parsed values, not JSON formatting.
  const content = JSON.stringify(head) + ' \n';
  db.prepare('INSERT INTO history_head VALUES(?,?,?,?,?)').run(scope, head.epoch, head.revision, content, hashValue(head));
  if (head.pending && padding) db.prepare('INSERT INTO history_completion_space VALUES(?,zeroblob(?))').run(scope, HISTORY.completionReserve);
}
function legacy(db: Database.Database, count = 44) {
  return Array.from({ length: count }, () => {
    const scanId = randomUUID(), scope = hashValue([foreign, scanId]), head = empty();
    insert(db, scope, head); return { scope, scanId, head };
  });
}
function rows(db: Database.Database) {
  return ['history_meta', 'history_head', 'history_completion_space', 'llm_summary'].map(table =>
    db.prepare(`SELECT rowid,* FROM ${table} ORDER BY rowid`).all());
}
function fingerprint(path: string) {
  return ['', '-journal', '-wal', '-shm'].map(suffix => {
    const file = path + suffix;
    if (!existsSync(file)) return { suffix, exists: false };
    const stat = statSync(file, { bigint: true });
    return { suffix, size: stat.size, inode: stat.ino, mtime: stat.mtimeNs,
      hash: createHash('sha256').update(readFileSync(file)).digest('hex') };
  });
}
function begin(store: HistoryStore, subject = owner, scanId = randomUUID()) {
  const head = store.readSnapshot(subject, scanId), id = randomUUID();
  const turn: Turn = { id, mutationId: randomUUID(), state: 'pending', question: 'Что проверить вручную?',
    report: reportBinding({ ...openAiReport, scanId }), createdAt: Date.now(), inputHash: 'c'.repeat(64),
    consentPolicyVersion: 'd'.repeat(64), requestHash: 'e'.repeat(64) };
  return store.begin(subject, scanId, head.epoch, head.revision, turn, { id, sessionId: 'c'.repeat(32), generation: 1,
    accessIncarnation: 'd'.repeat(32), policyVersion: turn.consentPolicyVersion, deadline: Date.now() + 60000,
    requestHash: turn.requestHash });
}
function unknown(db: Database.Database, count: number, pending = false) {
  for (let i = 0; i < count; i++) {
    const head = empty(); head.revision = 2;
    head.decisions = [decision(), decision()]; // individually valid, mixed scan bindings: ownership is UNKNOWN.
    if (pending) {
      const id = randomUUID();
      head.turns = [{ id, mutationId: randomUUID(), state: 'pending', question: 'Проверить вручную.',
        report: reportBinding({ ...openAiReport, scanId: randomUUID() }), createdAt: Date.now(),
        inputHash: 'c'.repeat(64), consentPolicyVersion: 'd'.repeat(64), requestHash: 'e'.repeat(64) }];
      head.pending = { id, sessionId: 'c'.repeat(32), generation: 1, accessIncarnation: 'd'.repeat(32),
        policyVersion: 'd'.repeat(64), deadline: Date.now() + 60000, requestHash: 'e'.repeat(64) };
    }
    insert(db, hashValue(['unknown-historical-scope', randomUUID()]), head);
  }
}

test('legacy-empty-h7v3 fresh chat after44 legacy empties preserves every old row and GET is passive', () => {
  const f = fixture();
  try {
    const old = legacy(f.db), before = rows(f.db), files = fingerprint(f.path);
    for (const entry of old) assert.deepEqual(f.store.readSnapshot(foreign, entry.scanId), entry.head);
    f.store.assertHealthy();
    assert.deepEqual(rows(f.db), before); assert.deepEqual(fingerprint(f.path), files);
    const pending = begin(f.store);
    assert.equal(pending.turns.length, 1);
    const existing = f.db.prepare('SELECT rowid,* FROM history_head WHERE scope IN (SELECT value FROM json_each(?)) ORDER BY rowid')
      .all(JSON.stringify(old.map(row => row.scope)));
    assert.deepEqual(existing, before[1], 'admission cannot delete, rebind, normalize or rotate old empty rows');
    assert.equal((f.db.prepare('SELECT count(*) n FROM history_head').get() as { n: number }).n, 45);
    const reopened = new HistoryStore(f.path);
    try { for (const entry of old) assert.deepEqual(reopened.readSnapshot(foreign, entry.scanId), entry.head); }
    finally { reopened.close(); }
  } finally { f.close(); }
});

test('legacy-empty-h7v3 genuine owner16 head limit still rejects17th; known foreign occupancy is not charged', () => {
  const f = fixture();
  try {
    legacy(f.db);
    assert.equal(HISTORY_OWNER_CAPACITY.heads, 16);
    for (let i = 0; i < 16; i++) {
      const scanId = randomUUID(), head = f.store.readSnapshot(owner, scanId);
      f.store.decision(owner, scanId, head.epoch, head.revision, decision(scanId));
    }
    const before = rows(f.db);
    assert.throws(() => begin(f.store), capacity); assert.deepEqual(rows(f.db), before);
    assert.equal(begin(f.store, 'c'.repeat(32)).turns.length, 1);
  } finally { f.close(); }
});

for (const total of [127, 128]) test(`legacy-empty-h7v3 global head bound128 counts all legacy rows at${total}`, () => {
  const f = fixture();
  try {
    legacy(f.db);
    for (let i = 44; i < total; i++) {
      const scanId = randomUUID(), subject = (i + 1).toString(16).padStart(32, '0'), head = empty();
      head.revision = 1; head.decisions = [decision(scanId)]; insert(f.db, hashValue([subject, scanId]), head);
    }
    const before = rows(f.db);
    if (total === 127) { begin(f.store); assert.equal((f.db.prepare('SELECT count(*) n FROM history_head').get() as { n: number }).n, 128); }
    else { assert.throws(() => begin(f.store), capacity); assert.deepEqual(rows(f.db), before); }
    assert.ok((f.db.pragma('page_count', { simple: true }) as number) * 4096 < HISTORY.dbBytes, 'head cap, not disk-full, is decisive');
  } finally { f.close(); }
});

test('legacy-empty-h7v3 nonempty unknown bindings remain charged to every owner by entry and byte limits', () => {
  for (const [count, pending] of [[16, false], [2, true]] as const) {
    const f = fixture();
    try {
      legacy(f.db); unknown(f.db, count, pending);
      const before = rows(f.db);
      assert.throws(() => begin(f.store), capacity); assert.deepEqual(rows(f.db), before);
      assert.throws(() => begin(f.store, 'c'.repeat(32)), capacity); assert.deepEqual(rows(f.db), before);
    } finally { f.close(); }
  }
  const f = fixture();
  try { legacy(f.db); unknown(f.db, 15); assert.equal(begin(f.store).turns.length, 1); }
  finally { f.close(); }
});

test('legacy-empty-h7v3 real own pending byte limit is unchanged even with44 excluded empty heads', () => {
  const f = fixture();
  try {
    legacy(f.db); begin(f.store); begin(f.store);
    const before = rows(f.db);
    assert.throws(() => begin(f.store), capacity); assert.deepEqual(rows(f.db), before);
  } finally { f.close(); }
});

test('legacy-empty-h7v3 incomplete or inconsistent pending bindings fail closed, never receive empty exemption', () => {
  for (const kind of ['missing-scan', 'pending-without-turn']) {
    const f = fixture();
    try {
      legacy(f.db);
      const head = empty(); head.revision = 1; head.decisions = [decision()];
      const malformed = JSON.parse(JSON.stringify(head));
      if (kind === 'missing-scan') delete malformed.decisions[0].report.scanId;
      else { malformed.turns = []; malformed.decisions = []; malformed.pending = { id: randomUUID(), sessionId: 'c'.repeat(32),
        generation: 1, accessIncarnation: 'd'.repeat(32), policyVersion: 'd'.repeat(64), deadline: Date.now() + 60000,
        requestHash: 'e'.repeat(64) }; }
      const scope = hashValue(['malformed-retained-scope']);
      f.db.prepare('INSERT INTO history_head VALUES(?,?,?,?,?)')
        .run(scope, malformed.epoch, malformed.revision, JSON.stringify(malformed), hashValue(malformed));
      const before = rows(f.db);
      assert.throws(() => begin(f.store), unavailable); assert.deepEqual(rows(f.db), before);
      assert.throws(() => new HistoryStore(f.path), unavailable); assert.deepEqual(rows(f.db), before);
      assert.throws(() => historyOccupancy(scope, malformed), unavailable);
    } finally { f.close(); }
  }
});

test('legacy-empty-h7v3 empty exemption cannot be forged, copied or mutated into summary/unknown occupancy', () => {
  const target = hashValue([owner, randomUUID()]);
  const limits = { entries: HISTORY_OWNER_CAPACITY.heads, bytes: HISTORY_OWNER_CAPACITY.historyBytes };
  const branded = Array.from({ length: 44 }, () => historyOccupancy(hashValue([foreign, randomUUID()]), empty()));
  assert.doesNotThrow(() => assertOwnerCapacity(owner, target, 100, branded, limits));
  assert.equal(Object.isFrozen(branded[0]), true);
  assert.throws(() => { (branded[0] as { bytes: number }).bytes = HISTORY.scopeBytes; }, TypeError);
  assert.throws(() => assertOwnerCapacity(owner, target, 100, branded.map(row => ({ ...row })), limits), capacity);
  const forged = branded.map(row => ({ scope: row.scope, bytes: row.bytes, empty: true, legacyEmpty: true }));
  assert.throws(() => assertOwnerCapacity(owner, target, 100, forged, limits), capacity);
});

test('legacy-empty-h7v3 activating a retained empty scope still charges its new content and preserves lineage', () => {
  const f = fixture();
  try {
    legacy(f.db);
    for (let i = 0; i < 15; i++) {
      const scan = randomUUID(), head = f.store.readSnapshot(owner, scan);
      f.store.decision(owner, scan, head.epoch, head.revision, decision(scan));
    }
    const scanId = randomUUID(), old = { ...empty(), revision: 7 };
    insert(f.db, hashValue([owner, scanId]), old);
    const active = begin(f.store, owner, scanId);
    assert.equal(active.epoch, old.epoch); assert.equal(active.revision, 8);
    assert.equal(active.pending !== null, true);
    const before = rows(f.db);
    assert.throws(() => begin(f.store), capacity); assert.deepEqual(rows(f.db), before);
  } finally { f.close(); }
});

test('legacy-empty-h7v3 summary tenant cap and replacement remain enforced independently of empty history branding', async () => {
  const { makeOpenAiPolicy, openAiReply } = await import('./openai-core.fixture.js');
  const { validateReply } = await import('../response.js');
  const f = fixture();
  try {
    legacy(f.db);
    const provider = makeOpenAiPolicy();
    const policy: import('../provider-runtime-contract.js').OpenAiSummaryPolicy = { provider: 'OpenAI', version: provider.version,
      policy: provider, findings: provider.findings, requestBytes: provider.requestBytes, responseBytes: provider.responseBytes };
    const value = validateReply(openAiReply(), openAiReport, true);
    const reports = Array.from({ length: 8 }, () => ({ ...openAiReport, scanId: randomUUID() }));
    for (const report of reports) f.store.writeSummary(owner, report, policy, { ...value, scanId: report.scanId });
    const extra = { ...openAiReport, scanId: randomUUID() }, before = rows(f.db);
    assert.throws(() => f.store.writeSummary(owner, extra, policy, { ...value, scanId: extra.scanId }), capacity);
    assert.deepEqual(rows(f.db), before);
    f.store.writeSummary(owner, reports[0], policy, { ...value, scanId: reports[0].scanId });
    assert.deepEqual(rows(f.db), before);
  } finally { f.close(); }
});
