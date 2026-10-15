import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync, renameSync, linkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { HistoryStore } from '../history-store.js';
import { HISTORY, bytes, cleanText, hashValue, historyProjection, mutationInputHash, reportBinding, validateHead, type HistoryHead, type Pending, type Turn } from '../history-contract.js';
import { PreparedContextCache, selectHistoryContext } from '../history-context.js';
import { policyFromEnvironment } from '../policy.js';
import { fixtureEnv, fixtureReport } from './fixtures.js';
import { FixtureQuotaLedger, quotaPolicy } from './quota-fixtures.js';

const owner = 'a'.repeat(32), scan = fixtureReport.scanId;
export const historyFreePolicy = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'apodex/apodex-1.1-mini:free',
  LLM_PROVIDER_ALLOWLIST: 'novita/bf16', LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0', LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' })!;
const turn = (): Turn => ({ id: randomUUID(), mutationId: randomUUID(), state: 'pending', question: 'Keep the first important constraint.', report: reportBinding(fixtureReport), createdAt: Date.now(), inputHash: 'f'.repeat(64), consentPolicyVersion: 'd'.repeat(64), requestHash: 'e'.repeat(64) });
const pending = (id: string): Pending => ({ id, sessionId: 'b'.repeat(32), generation: 1, accessIncarnation: 'c'.repeat(32), policyVersion: 'd'.repeat(64), deadline: Date.now() + 40000, requestHash: 'e'.repeat(64) });

test('durable owner+scan head: shared SQLite CAS, dedup, reopen, capacity, missing/corrupt and restore lineage', () => {
  const dir = mkdtempSync(join(tmpdir(), 'history-store-')), path = join(dir, 'llm-history.sqlite');
  let a: HistoryStore | undefined, b: HistoryStore | undefined;
  try {
    assert.throws(() => new HistoryStore(path));
    a = new HistoryStore(path, true); b = new HistoryStore(path);
    assert.throws(() => new HistoryStore(path, true), 'initializer refuses existing memory');
    const h = a.snapshot(owner, scan), original = b.snapshot(owner, scan); assert.deepEqual(h, original);
    const t = turn(), p = a.begin(owner, scan, h.epoch, h.revision, t, pending(t.id));
    assert.equal(p.revision, 1);
    const physical = new Database(path, { readonly: true });
    assert.deepEqual(physical.prepare('SELECT length(padding) AS bytes FROM history_completion_space').get(), { bytes: HISTORY.completionReserve });
    const other = turn(); assert.throws(() => b!.begin(owner, scan, h.epoch, h.revision, other, pending(other.id)));
    const reply = { ...reportBinding(fixtureReport), kind: 'hypothesis' as const, text: 'This is only a hypothesis.', sources: [{ ...reportBinding(fixtureReport), finding:
          { check: 'secret' as const, findingId: 'secret-0-1', severity: 'UNKNOWN', ruleId: 'rule-0123456789abcdef', line: 1, evidenceRef: 'result-0-secret-1' } }] };
    const done = a.finish(owner, scan, p.epoch, p.revision, t.id, reply); assert.equal(done.revision, 2);
        assert.deepEqual(physical.prepare('SELECT count(*) AS n FROM history_completion_space').get(), { n: 0 }); physical.close();
    assert.equal(b.duplicate(owner, scan, t.mutationId)?.id, t.id);
    assert.throws(() => b!.finish(owner, scan, p.epoch, p.revision, t.id, reply));
    assert.equal(a.snapshot('f'.repeat(32), scan).turns.length, 0);
    assert.equal(a.snapshot(owner, randomUUID()).turns.length, 0);
    a.close(); a = new HistoryStore(path); assert.deepEqual(a.snapshot(owner, scan), done);
    b.close(); b = undefined;
    a.rotateRestoredLineage(); a.close(); a = new HistoryStore(path);
    const restored = a.snapshot(owner, scan); assert.notEqual(restored.epoch, done.epoch); assert.deepEqual(restored.turns, done.turns);
    assert.throws(() => a!.decision(owner, scan, done.epoch, done.revision, { id: randomUUID(), mutationId: randomUUID(), kind: 'user-decision', text: 'Keep this decision.', report: reportBinding(fixtureReport), sources: [] }));
    linkSync(path, join(dir, 'hardlink')); assert.throws(() => a!.snapshot(owner, scan));
    rmSync(join(dir, 'hardlink'));
    a.close(); a = undefined;
    const db = new Database(path); db.prepare('UPDATE history_head SET content_hash=? WHERE scope=?').run('f'.repeat(64), hashValue([owner, scan])); db.close();
    assert.throws(() => new HistoryStore(path), 'corrupt hash cannot become empty history');
    renameSync(path, join(dir, 'lost.sqlite')); assert.throws(() => new HistoryStore(path));
  } finally { a?.close(); b?.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('public turn allowlist excludes internal identity without mutating persisted history', () => {
  const report = reportBinding(fixtureReport), reply = { ...report, kind: 'hypothesis' as const, text: 'A retained hypothesis.',
    sources: [{ ...report, finding: { check: 'secret' as const, findingId: 'secret-0-1', severity: 'UNKNOWN',
          ruleId: 'rule-0123456789abcdef', line: 1, evidenceRef: 'result-0-secret-1' } }] };
  const turns = (['completed', 'failed', 'cancelled', 'interrupted', 'pending'] as const).map(state => ({ ...turn(), state,
    ...(state === 'completed' ? { reply } : {}) }));
  const head: HistoryHead = { epoch: randomUUID(), revision: 9, turns, decisions: [], pending: pending(turns.at(-1)!.id) };
  validateHead(head);
  const before = structuredClone(head), projection = historyProjection(head);
  assert.equal(projection.turns.length, 5);
  for (let n = 0; n < turns.length; n++) {
    const saved = turns[n], visible = projection.turns[n];
    const expected = { id: saved.id, mutationId: saved.mutationId, state: saved.state, question: saved.question,
      report: saved.report, createdAt: saved.createdAt, ...(saved.state === 'completed' ? { reply } : {}) };
    assert.deepEqual(visible, expected);
  }
  assert.deepEqual(projection.pending, { turnId: turns.at(-1)!.id, state: 'pending' });
  assert.doesNotMatch(JSON.stringify(projection), /inputHash|consentPolicyVersion|requestHash|sessionId|generation|accessIncarnation|reservation/);
  assert.deepEqual(head, before, 'projection must not delete or rewrite durable replay fingerprints');
  const futureMetadata = { ...head, turns: head.turns.map(t => ({ ...t, futureInternalMetadata: 'private bookkeeping' })) };
  assert.deepEqual(historyProjection(futureMetadata), projection, 'runtime allowlist does not depend on a blacklist or static type erasure');
});

test('mandatory old user constraints, historical sources, all critical/unknown/coverage survive optional reduction; cache is context-only', () => {
  const head: HistoryHead = { epoch: randomUUID(), revision: 80, turns: [], decisions: [], pending: null };
  for (let n = 0; n < 40; n++) head.turns.push({ ...turn(), state: 'failed', question: n ? `Optional later request ${n}.` : 'Never apply a destructive action without approval.' });
  head.decisions.push({ id: randomUUID(), mutationId: randomUUID(), kind: 'user-decision', text: 'The earliest accepted constraint remains mandatory.',
    report: { ...reportBinding(fixtureReport), reportVersion: 'e'.repeat(64) }, sources: [] });
  const report = { ...fixtureReport, findings: Array.from({ length: 40 }, (_, n) => ({ ...fixtureReport.findings[0], findingId: `finding-${n}`, severity: n === 39 ? 'CRITICAL' : n === 38 ? 'UNKNOWN' : 'LOW' })) };
  const selected = selectHistoryContext(report, head, 'Unrelated question about finding-1.', historyFreePolicy, 65536);
  assert.deepEqual(selected.context.report.coverage, fixtureReport.coverage);
  assert.ok(selected.context.report.findings.some(f => f.findingId === 'finding-39'));
  assert.ok(selected.context.report.findings.some(f => f.findingId === 'finding-38'));
  assert.equal(selected.context.history.userTurns.length, 40);
  assert.match(JSON.stringify(selected.context), /Never apply a destructive/);
  assert.match(JSON.stringify(selected.context), /historical-unresolved/);
  assert.ok(selected.context.omission.findings > 0);
  assert.equal(selected.prepared.reserve.input, Buffer.byteLength(selected.prepared.body) + 1024);
  assert.equal(selected.prepared.reserve.output, 256); assert.equal(JSON.parse(selected.prepared.body).stream, false);
  const cache = new PreparedContextCache();
  const first = cache.get('bound-key', selected.context), hit = cache.get('bound-key', selected.context);
  assert.equal(first, hit); assert.ok(Object.isFrozen(hit.history));
  const poisoned = { ...selected.context, question: 'Foreign question.' };
  const map = (cache as unknown as { entries: Map<string, unknown> }).entries;
  map.set('bound-key', { context: poisoned, bytes: 10, expires: Date.now() + 60000, hash: hashValue(poisoned) });
  assert.equal(cache.get('bound-key', selected.context).question, selected.context.question);
  assert.throws(() => selectHistoryContext(report, { ...head, turns: head.turns.map(t => ({ ...t, question: 'x '.repeat(1000) })) }, 'Small question.', historyFreePolicy, 65536));
  assert.equal(HISTORY.dbBytes, 8 * 1024 * 1024, 'stricter physical main bound caps whole DELETE journal');
});

test('physical completion reservations exhaust bounded main capacity atomically without losing prior heads', () => {
  const dir = mkdtempSync(join(tmpdir(), 'history-physical-')), path = join(dir, 'llm-history.sqlite');
  let store = new HistoryStore(path, true);
  try {
    let admitted = 0, refused = false, first: HistoryHead | undefined;
    for (let n = 0; n < HISTORY.heads; n++) {
      const id = randomUUID(), head = store.snapshot(owner, id), t = { ...turn(), report: { ...reportBinding(fixtureReport), scanId: id } };
      try {
        const started = store.begin(owner, id, head.epoch, head.revision, t, pending(t.id));
        admitted++; first ??= started;
      } catch (error) {
        assert.equal((error as { getStatus(): number }).getStatus(), 409);
        const unchanged = store.snapshot(owner, id);
        assert.equal(unchanged.revision, 0); assert.equal(unchanged.pending, null); assert.equal(unchanged.turns.length, 0);
        refused = true; break;
      }
    }
    assert.ok(refused); assert.ok(admitted > 0 && admitted < HISTORY.heads);
    const db = new Database(path, { readonly: true });
    assert.ok((db.pragma('page_count', { simple: true }) as number) * 4096 <= HISTORY.dbBytes);
    assert.deepEqual(db.prepare('SELECT count(*) AS n FROM history_completion_space').get(), { n: admitted }); db.close();
    store.close(); store = new HistoryStore(path);
    assert.deepEqual(store.snapshot(owner, first!.turns[0].report.scanId), first);
  } finally { store.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('nested historical schema, expired pending recovery, finite heads and short guarded quota contention fail closed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'history-guards-')), path = join(dir, 'llm-history.sqlite');
  const store = new HistoryStore(path, true), quota = new FixtureQuotaLedger(join(dir, 'llm-usage.sqlite'), quotaPolicy);
  const qdb = new Database(join(dir, 'llm-usage.sqlite'));
  try {
    assert.equal(cleanText('Объясни находку 🙂.'), 'Объясни находку 🙂.');
    assert.throws(() => cleanText('\ud800'));
    const h = store.snapshot(owner, scan), t = turn();
    const p = store.begin(owner, scan, h.epoch, h.revision, t, { ...pending(t.id), deadline: Date.now() - 1 });
    assert.throws(() => store.guardPending(owner, scan, p.epoch, p.revision, t.id, () => assert.fail('expired guard invoked')));
    store.recoverExpired(); const recovered = store.snapshot(owner, scan);
    assert.equal(recovered.pending, null); assert.equal(recovered.turns[0].state, 'interrupted');
    for (const key of ['inputHash', 'consentPolicyVersion', 'requestHash'] as const) assert.equal(recovered.turns[0][key], t[key]);
    assert.equal(recovered.revision, 2); store.recoverExpired(); assert.equal(store.snapshot(owner, scan).revision, 2);
    for (const corrupt of [
      { ...recovered, turns: [{ ...recovered.turns[0], rawEvidence: 'private' }] },
      { ...recovered, decisions: [{ id: randomUUID(), mutationId: randomUUID(), kind: 'user-decision', text: 'Retain this.', report: reportBinding(fixtureReport), sources: [
        { ...reportBinding(fixtureReport), finding: { check: 'secret', findingId: 'secret-0-1', severity: 'UNKNOWN', ruleId: 'rule-0123456789abcdef', line: 1, evidenceRef: 'result-0-secret-1', rawEvidence: 'private' } }] }] },
      { ...p, pending: { ...p.pending!, generation: 0 } },
      { ...p, pending: { ...p.pending!, extraAuthority: true } },
      { ...p, pending: { ...p.pending!, policyVersion: '0'.repeat(64) } },
      { ...p, pending: { ...p.pending!, requestHash: '0'.repeat(64) } },
      { ...recovered, turns: [{ ...recovered.turns[0], inputHash: undefined }] },
    ]) assert.throws(() => validateHead(corrupt));
    store.guardHead(owner, scan, recovered.epoch, recovered.revision, () => assert.equal(qdb.pragma('journal_mode', { simple: true }), 'delete'));
    assert.throws(() => store.guardHead(owner, scan, recovered.epoch, 0, () => assert.fail('stale write invoked')));
    assert.throws(() => store.duplicate(owner, scan, t.mutationId, () => false), 'changed replay cannot reuse a mutation');
    qdb.exec('BEGIN IMMEDIATE');
    const started = Date.now();
    assert.throws(() => quota.withBusyTimeout(10, () => quota.reserve({ subject: owner, scanId: scan, reportVersion: 'a'.repeat(64), policyVersion: 'b'.repeat(64), requestHash: 'c'.repeat(64) }, { input: 1000, output: 256, costMicros: 0 })));
    assert.ok(Date.now() - started < 500, 'new guard does not inherit the ordinary 1000ms quota wait');
    qdb.exec('ROLLBACK');
    const privateDb = (quota as unknown as { db: Database.Database }).db;
    assert.equal(privateDb.pragma('busy_timeout', { simple: true }), quotaPolicy.busyMs, 'connection default restored');
    assert.throws(() => quota.withBusyTimeout(10, () => Promise.resolve()));
    for (let n = 1; n < HISTORY.heads; n++) store.snapshot(owner, randomUUID());
    assert.throws(() => store.snapshot(owner, randomUUID()), 'persistent scope capacity refuses rather than evicts');
    assert.equal(store.snapshot(owner, scan).turns[0].state, 'interrupted');
  } finally { qdb.close(); quota.close(); store.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('completion reserve covers escaped full projection growth; original identities persist and old schema is refused without reset', t => {
  // cleanText rejects control escapes/surrogates; accepted UTF8 expands at most 2x for quote/backslash.
  // Bound every copied source at its full serialized limit, not the smaller synthetic test citations.
  const replyWrapper = bytes({ ...reportBinding(fixtureReport), kind: 'hypothesis', text: '', sources: [] });
  const reservationField = bytes({ reservation: randomUUID() }) - 2 + 1;
  const worstGrowth = 2 * HISTORY.replyBytes + HISTORY.citations * HISTORY.citationBytes + (HISTORY.citations - 1) +
    replyWrapper + Buffer.byteLength(',"reply":') + ('completed'.length - 'pending'.length) + 16 + reservationField;
  assert.ok(worstGrowth <= HISTORY.completionReserve, `full-envelope worst-case growth ${worstGrowth} <= ${HISTORY.completionReserve}`);
  t.diagnostic(`worst valid full-projection/storage growth <=${worstGrowth} bytes, unchanged reserve=${HISTORY.completionReserve}`);
  const expected = { epoch: randomUUID(), revision: 123, mutationId: randomUUID(), reportVersion: fixtureReport.reportVersion };
  const inputHash = mutationInputHash(scan, expected, 'Keep the original consent.', 'a'.repeat(64));
  assert.equal(inputHash, mutationInputHash(scan, { reportVersion: expected.reportVersion, mutationId: expected.mutationId,
    revision: expected.revision, epoch: expected.epoch }, 'Keep the original consent.', 'a'.repeat(64)), 'explicit tuple is independent of object key order');
  assert.notEqual(inputHash, mutationInputHash(scan, { ...expected, revision: 124 }, 'Keep the original consent.', 'a'.repeat(64)));
  assert.notEqual(inputHash, mutationInputHash(scan, expected, 'Keep the original consent.', 'b'.repeat(64)));
  const dir = mkdtempSync(join(tmpdir(), 'history-identity-')), path = join(dir, 'llm-history.sqlite');
  let store: HistoryStore | undefined = new HistoryStore(path, true);
  try {
    for (const state of ['failed', 'cancelled', 'interrupted'] as const) {
      const h = store.snapshot(owner, scan), t = { ...turn(), inputHash };
      store.begin(owner, scan, h.epoch, h.revision, t, pending(t.id));
      assert.equal(store.fail(owner, scan, h.epoch, t.id, state), true);
      const saved: Turn = store.snapshot(owner, scan).turns.at(-1)!;
      assert.deepEqual(saved, { ...t, state });
    }
    const saved = store.snapshot(owner, scan);
    assert.equal(bytes(historyProjection(saved)), bytes(historyProjection(saved, reportBinding(fixtureReport))));
    store.close(); store = new HistoryStore(path); assert.deepEqual(store.snapshot(owner, scan), saved);
    store.rotateRestoredLineage(); store.close(); store = new HistoryStore(path);
    assert.deepEqual(store.snapshot(owner, scan).turns, saved.turns, 'restore retains ORIGINAL identity, never infers it from current context');
    store.close(); store = undefined;
    const db = new Database(path); db.pragma('user_version = 2');
    const before = db.prepare('SELECT epoch,revision,content,content_hash FROM history_head').all(); db.close();
    assert.throws(() => new HistoryStore(path), 'unsupported identity-less schema must fail closed');
    assert.throws(() => new HistoryStore(path, true), 'existing old store must not be reinitialized');
    const after = new Database(path, { readonly: true });
    try { assert.equal(after.pragma('user_version', { simple: true }), 2); assert.deepEqual(after.prepare('SELECT epoch,revision,content,content_hash FROM history_head').all(), before); }
    finally { after.close(); }
  } finally { store?.close(); rmSync(dir, { recursive: true, force: true }); }
});
