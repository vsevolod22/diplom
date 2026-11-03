import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { HttpException } from '@nestjs/common';
import Database from 'better-sqlite3';
import { HistoryStore } from '../history-store.js';
import { HISTORY, hashValue, reportBinding, type Decision, type HistoryHead, type Turn } from '../history-contract.js';
import { HISTORY_OWNER_CAPACITY, assertOwnerCapacity, historyOccupancy } from '../history-capacity.js';
import { fixtureReport } from './fixtures.js';

const owner = 'a'.repeat(32), other = 'b'.repeat(32);
const errorCode = (code: string) => (error: unknown) => error instanceof HttpException &&
  (error.getResponse() as { errorCode: string }).errorCode === code;
const capacity = errorCode('LLM_HISTORY_CAPACITY'), conflict = errorCode('LLM_HISTORY_CONFLICT');
function decision(scanId: string): Decision {
  return { id: randomUUID(), mutationId: randomUUID(), kind: 'user-decision', text: 'Keep this constraint.', report: reportBinding({ ...fixtureReport, scanId }), sources: [] };
}
function begin(store: HistoryStore, subject: string, scanId: string, head = store.readSnapshot(subject, scanId)) {
  const id = randomUUID();
  const turn: Turn = { id, mutationId: randomUUID(), state: 'pending', question: 'Keep this constraint.', report: reportBinding({ ...fixtureReport, scanId }),
    createdAt: Date.now(), inputHash: 'f'.repeat(64), consentPolicyVersion: 'd'.repeat(64), requestHash: 'e'.repeat(64) };
  return store.begin(subject, scanId, head.epoch, head.revision, turn, { id, sessionId: 'b'.repeat(32), generation: 1,
    accessIncarnation: 'c'.repeat(32), policyVersion: turn.consentPolicyVersion, deadline: Date.now() + 600000, requestHash: turn.requestHash });
}
function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'history-a4-')), path = join(dir, 'llm-history.sqlite');
  const a = new HistoryStore(path, true), b = new HistoryStore(path), db = new Database(path);
  const rows = () => ['history_meta', 'history_head', 'history_completion_space', 'llm_summary'].map(table => db.prepare(`SELECT * FROM ${table} ORDER BY 1`).all());
  return { path, a, b, db, rows, close() { db.close(); a.close(); b.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test('A4 repeated missing snapshot/alias/dedup/guards/fail allocate nothing; virtual epoch is detached, scoped and durable', () => {
  const f = fixture();
  try {
    const scan = randomUUID(), before = f.rows(), empty = f.a.readSnapshot(owner, scan);
    assert.equal(empty.revision, 0); assert.match(empty.epoch, /^[a-f0-9-]{36}$/);
    for (let n = 0; n < 256; n++) {
      assert.deepEqual(f.a.readSnapshot(owner, scan), empty);
      assert.deepEqual(f.b.snapshot(owner, scan), empty);
      assert.equal(f.a.snapshot(owner, randomUUID()).revision, 0);
    }
    assert.notEqual(f.a.snapshot(other, scan).epoch, empty.epoch);
    assert.equal(f.a.duplicate(owner, scan, randomUUID()), null);
    assert.equal(f.a.fail(owner, scan, empty.epoch, randomUUID(), 'failed'), false);
    assert.equal(f.a.guardHead(owner, scan, empty.epoch, 0, () => 'read-only'), 'read-only');
    assert.deepEqual(f.rows(), before, 'no scope/padding/meta/summary writes on missing reads');
    const detached = f.a.snapshot(owner, scan); detached.decisions.push(decision(scan));
    assert.deepEqual(f.a.snapshot(owner, scan), empty);
    const reopened = new HistoryStore(f.path);
    try { assert.deepEqual(reopened.snapshot(owner, scan), empty); } finally { reopened.close(); }
    const isolatedDir = mkdtempSync(join(tmpdir(), 'history-a4-incarnation-'));
    const isolated = new HistoryStore(join(isolatedDir, 'llm-history.sqlite'), true);
    try { assert.notEqual(isolated.snapshot(owner, scan).epoch, empty.epoch); }
    finally { isolated.close(); rmSync(isolatedDir, { recursive: true, force: true }); }
    f.b.close(); f.a.rotateRestoredLineage(); f.a.close();
    const restored = new HistoryStore(f.path);
    try {
      assert.notEqual(restored.snapshot(owner, scan).epoch, empty.epoch);
      assert.throws(() => restored.decision(owner, scan, empty.epoch, 0, decision(scan)), conflict);
    } finally { restored.close(); }
    assert.equal((f.db.prepare('SELECT count(*) n FROM history_head').get() as { n: number }).n, 0);
  } finally { f.close(); }
});

test('A4 first begin/decision materializes revision1 exactly once across SQLite connections; failed admission rolls back', () => {
  const f = fixture();
  try {
    for (const kind of ['begin', 'decision'] as const) {
      const scan = randomUUID(), empty = f.a.snapshot(owner, scan), stale = f.b.snapshot(owner, scan);
      if (kind === 'begin') {
        const saved = begin(f.a, owner, scan, empty); assert.equal(saved.revision, 1);
        assert.throws(() => begin(f.b, owner, scan, stale), conflict);
        assert.equal(f.a.fail(owner, scan, saved.epoch, saved.pending!.id, 'cancelled'), true);
      } else {
        const saved = f.a.decision(owner, scan, empty.epoch, 0, decision(scan)); assert.equal(saved.revision, 1);
        assert.throws(() => f.b.decision(owner, scan, stale.epoch, 0, decision(scan)), conflict);
      }
    }
    const scan = randomUUID(), empty = f.a.snapshot(owner, scan), before = f.rows();
    assert.throws(() => f.a.decision(owner, scan, empty.epoch, 0, decision(randomUUID())), conflict);
    assert.deepEqual(f.rows(), before);
    f.db.exec("CREATE TRIGGER refuse_padding BEFORE INSERT ON history_completion_space BEGIN SELECT RAISE(ABORT,'synthetic allocation failure'); END");
    assert.throws(() => begin(f.a, owner, scan));
    assert.deepEqual(f.rows(), before, 'first head insertion rolls back with physical allocation');
    f.db.exec('DROP TRIGGER refuse_padding');
    assert.equal(f.a.snapshot(owner, scan).epoch, empty.epoch);
  } finally { f.close(); }
});

test('A4 owner16-head cap refuses before simulated provider, preserves other owner and existing legacy over-share reads', () => {
  const f = fixture();
  try {
    assert.deepEqual(HISTORY_OWNER_CAPACITY, { version: 'history-owner-capacity-v1', heads: 16, historyBytes: 1048576, summaries: 8, summaryBytes: 262144 });
    const scans: string[] = [];
    for (let n = 0; n < 16; n++) {
      const scan = randomUUID(), head = f.a.snapshot(owner, scan); scans.push(scan);
      f.a.decision(owner, scan, head.epoch, 0, decision(scan));
    }
    const before = f.rows(); let providerCalls = 0;
    const scan = randomUUID(), head = f.a.snapshot(owner, scan);
    assert.throws(() => { f.a.decision(owner, scan, head.epoch, 0, decision(scan)); providerCalls++; }, capacity);
    assert.equal(providerCalls, 0); assert.deepEqual(f.rows(), before);
    const foreign = f.a.snapshot(other, scan); f.a.decision(other, scan, foreign.epoch, 0, decision(scan));
    // Preserve a synthetically seeded, checksum-valid pre-cap seventeenth head.
    const legacyScan = randomUUID(), legacyHead = f.a.snapshot(owner, legacyScan);
    const legacy: HistoryHead = { ...legacyHead, revision: 1, decisions: [decision(legacyScan)] };
    f.db.prepare('INSERT INTO history_head VALUES(?,?,?,?,?)').run(hashValue([owner, legacyScan]), legacy.epoch, 1, JSON.stringify(legacy), hashValue(legacy));
    assert.deepEqual(f.a.snapshot(owner, legacyScan), legacy);
    const reopened = new HistoryStore(f.path);
    try { assert.deepEqual(reopened.snapshot(owner, legacyScan), legacy); } finally { reopened.close(); }
    assert.equal(f.a.snapshot(owner, scans[0]).decisions.length, 1, 'no eviction');
  } finally { f.close(); }
});

test('A4 pending charges full512KiB: two fit1MiB, third refuses, admitted completion remains possible over new shares', () => {
  const f = fixture();
  try {
    const scan1 = randomUUID(), scan2 = randomUUID();
    const one = begin(f.a, owner, scan1), two = begin(f.b, owner, scan2);
    assert.equal(historyOccupancy(hashValue([owner, scan1]), one).bytes, HISTORY.scopeBytes);
    const before = f.rows(); let providerCalls = 0;
    assert.throws(() => { begin(f.a, owner, randomUUID()); providerCalls++; }, capacity);
    assert.equal(providerCalls, 0); assert.deepEqual(f.rows(), before);
    const legacyScan = randomUUID(), empty = f.a.snapshot(owner, legacyScan);
    const legacy = { ...empty, revision: 1, decisions: [decision(legacyScan)] };
    f.db.prepare('INSERT INTO history_head VALUES(?,?,?,?,?)').run(hashValue([owner, legacyScan]), legacy.epoch, 1, JSON.stringify(legacy), hashValue(legacy));
    f.a.associate(owner, scan1, one.epoch, one.revision, one.pending!.id, randomUUID());
    const completed = f.a.finish(owner, scan1, one.epoch, one.revision, one.pending!.id,
      { ...reportBinding({ ...fixtureReport, scanId: scan1 }), kind: 'hypothesis', text: 'Check this manually.', sources: [{
              ...reportBinding({ ...fixtureReport, scanId: scan1 }), finding: { check: 'secret', findingId: 'secret-0-1', severity: 'UNKNOWN',
                ruleId: 'rule-0123456789abcdef', line: 1, evidenceRef: 'result-0-secret-1' },
            }] });
    assert.equal(completed.turns[0].state, 'completed');
    assert.equal(f.b.fail(owner, scan2, two.epoch, two.pending!.id, 'failed'), true);
    assert.deepEqual(f.db.prepare('SELECT * FROM history_completion_space').all(), []);
    assert.equal(f.a.snapshot(owner, legacyScan).decisions.length, 1);
  } finally { f.close(); }
});

test('A4 unchanged global128-head cap: read at capacity stays empty, admission refuses without eviction', () => {
  const f = fixture();
  try {
    for (let n = 0; n < HISTORY.heads; n++) {
      const subject = (n + 1).toString(16).padStart(32, '0'), scan = randomUUID(), head = f.a.snapshot(subject, scan);
      f.a.decision(subject, scan, head.epoch, 0, decision(scan));
    }
    const before = f.rows(), scan = randomUUID(), empty = f.a.snapshot(owner, scan);
    assert.equal(empty.revision, 0); assert.deepEqual(f.rows(), before);
    assert.throws(() => f.a.decision(owner, scan, empty.epoch, 0, decision(scan)), capacity);
    assert.deepEqual(f.rows(), before);
  } finally { f.close(); }
});

test('A4 legacy materialized empty head retains exact epoch/revision; unknown debt is conservative', () => {
  const f = fixture();
  try {
    const scan = randomUUID(), legacy: HistoryHead = { epoch: randomUUID(), revision: 0, turns: [], decisions: [], pending: null };
    f.db.prepare('INSERT INTO history_head VALUES(?,?,?,?,?)').run(hashValue([owner, scan]), legacy.epoch, 0, JSON.stringify(legacy), hashValue(legacy));
    assert.deepEqual(f.a.snapshot(owner, scan), legacy);
    const reopened = new HistoryStore(f.path);
    try { assert.deepEqual(reopened.snapshot(owner, scan), legacy); } finally { reopened.close(); }
    const next = f.a.decision(owner, scan, legacy.epoch, 0, decision(scan));
    assert.equal(next.epoch, legacy.epoch); assert.equal(next.revision, 1);
  } finally { f.close(); }
});

test('A4 exact owner byte/count accounting, replacement exclusion and conservative unknown/mixed legacy debt', () => {
  const scope = hashValue([owner, fixtureReport.scanId]);
  const rows = [{ scope, scanId: fixtureReport.scanId, bytes: 262144 }];
  assert.doesNotThrow(() => assertOwnerCapacity(owner, scope, 1048576, rows, { entries: 16, bytes: 1048576 }));
  assert.throws(() => assertOwnerCapacity(owner, scope, 1048577, rows, { entries: 16, bytes: 1048576 }), capacity);
  const unknown = Array.from({ length: 16 }, () => ({ scope: hashValue(randomUUID()), bytes: 1 }));
  assert.throws(() => assertOwnerCapacity(other, scope, 1, unknown, { entries: 16, bytes: 1048576 }), capacity);
  const head: HistoryHead = { epoch: randomUUID(), revision: 0, turns: [], decisions: [decision(randomUUID()), decision(randomUUID())], pending: null };
  assert.equal(historyOccupancy(scope, head).scanId, undefined);
  assert.equal(historyOccupancy(scope, { ...head, decisions: [] }).scanId, undefined);
});
