import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ScanLedger, type CombinedOutcome } from './ledger.js';
import { runImageConfig } from '../worker/image-config-runner.js';
import { configBytes, fixtureLoader } from '../worker/config-test-fixtures.js';
import { sanitizeConfigReport, validateConfigReport } from '../image-config/report-contract.js';

const bytes = configBytes();
const target = { subject: 'alice', idempotencyKey: 'config-ledger', registry: 'registry-1.docker.io', repository: 'library/alpine',
  digest: bytes.digest, platform: 'linux/amd64', checks: '["secret","config"]' };
const secret: CombinedOutcome = { check: 'secret', outcome: 'checked', scannerVersion: '0.69.3',
  findings: [{ findingId: 'secret-0-0', ruleId: 'test-rule', evidenceRef: 'result-0-secret-0', line: 1 }] };
async function fixture(run: (ledger: ScanLedger, file: string, directory: string) => Promise<void>) {
  const directory = mkdtempSync(join(tmpdir(), 'ledger-config-')); const file = join(directory, 'ledger.sqlite');
  const ledger = new ScanLedger(file);
  try { await run(ledger, file, directory); } finally { ledger.close(); rmSync(directory, { recursive: true, force: true }); }
}
for (const [table, action] of [['outbox', 'UPDATE'], ['scans', 'UPDATE'], ['scan_events', 'INSERT'],
  ['scan_check_results', 'INSERT'], ['scan_results', 'INSERT'], ['scan_findings', 'INSERT']] as const) {
  test(`config + siblings + ack + terminal event roll back together on ${table} write failure`, async () => fixture(async (ledger, file) => {
    const id = ledger.enqueue(target).scanId, job = ledger.claim()!;
    const report = await runImageConfig(ledger, job, new AbortController().signal, fixtureLoader(bytes));
    const db = new Database(file);
    try {
      db.exec(`CREATE TRIGGER reject_write BEFORE ${action} ON ${table} BEGIN SELECT RAISE(ABORT,'controlled write failure'); END`);
      assert.throws(() => ledger.finishCombined(id, job.attempts, [secret], report), /controlled write failure/);
      assert.equal(ledger.state(id, 'alice'), 'running'); assert.equal(ledger.result(id, 'alice'), undefined);
      assert.equal(ledger.configResult(id, 'alice'), undefined); assert.ok(ledger.configAttemptContext(id, job.attempts));
      assert.deepEqual(ledger.events(id, 'alice', null)?.map(event => event.state), ['queued','running']);
      db.exec('DROP TRIGGER reject_write');
      assert.equal(ledger.finishCombined(id, job.attempts, [secret], report), true);
      assert.equal(ledger.finishCombined(id, job.attempts, [secret], report), false);
      assert.deepEqual(ledger.events(id, 'alice', null)?.map(event => event.state), ['queued','running','completed']);
    } finally { db.close(); }
  }));
}

test('retry clears lease without incrementing attempt and rejects precomputed report before finalization', async () => fixture(async (ledger) => {
  const id = ledger.enqueue(target).scanId, job = ledger.claim(1000, 100)!;
  const report = await runImageConfig(ledger, job, new AbortController().signal, fixtureLoader(bytes));
  ledger.retry(id, job.attempts, 99_000);
  assert.equal(ledger.attemptActive(id, job.attempts), true); assert.equal(ledger.configAttemptContext(id, job.attempts), undefined);
  assert.equal(ledger.finishCombined(id, job.attempts, [secret], report), false);
  assert.equal(ledger.result(id, 'alice'), undefined); assert.equal(ledger.configResult(id, 'alice'), undefined);
  assert.equal(ledger.claim(98_999), undefined); const next = ledger.claim(99_000)!; assert.equal(next.attempts, 2);
  assert.equal(ledger.finishCombined(id, job.attempts, [secret], report), false);
  assert.equal(ledger.finishCombined(id, next.attempts, [secret], await runImageConfig(ledger, next, new AbortController().signal, fixtureLoader(bytes))), true);
}));

test('closed report rejects extra/raw fields, mismatched findings, versions and counts; sanitization preserves siblings', async () => fixture(async (ledger) => {
  const id = ledger.enqueue(target).scanId, job = ledger.claim()!;
  const report = await runImageConfig(ledger, job, new AbortController().signal, fixtureLoader(bytes));
  for (const unsafe of [{ ...report, raw: 'CANARY_RAW' }, { ...report, checksVersion: 'future' },
    { ...report, findings: [{ ...report.findings[0], findingId: `sha256:${'a'.repeat(64)}` }] },
    { ...report, findings: [{ ...report.findings[0], manifestDigest: `sha256:${'a'.repeat(64)}` }] },
    { ...report, completedRuleIds: [] }, { ...report, dockerfile: { outcome: 'checked' } }]) {
    assert.throws(() => validateConfigReport(unsafe, job, true), /Invalid config report/);
    assert.throws(() => ledger.finishCombined(id, job.attempts, [secret], unsafe as typeof report));
  }
  const safe = sanitizeConfigReport({ ...report, raw: 'CANARY_RAW' }, job, true);
  assert.equal(ledger.finishCombined(id, job.attempts, [secret], safe), true);
  assert.equal(ledger.result(id, 'alice')?.outcome, 'checked'); assert.equal(ledger.configResult(id, 'alice')?.config.outcome, 'failed');
  assert.equal(ledger.state(id, 'alice'), 'partial');
}));

test('populated v10 forward migration preserves all legacy tables/states/keys/provenance and does not backfill config', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'config-v10-')); const file = join(directory, 'ledger.sqlite');
  try {
    const original = new ScanLedger(file);
    for (const [index, state] of ['completed', 'failed', 'cancelled', 'running', 'queued', 'partial'].entries()) {
      const owner = `owner-${index}`; const id = original.enqueue({ ...target, subject: owner, checks: '["secret"]', idempotencyKey: `old-${index}` }).scanId;
      if (state === 'queued') continue;
      if (state === 'cancelled') { original.cancel(id, owner); continue; }
      const job = original.claim(1000 + index)!;
      if (state === 'completed') original.finishWithResult(id, job.attempts, secret.outcome === 'checked' ? secret.findings : [], '0.69.3');
      if (state === 'failed') original.finish(id, job.attempts, 'failed');
    }
    original.close();
    const raw = new Database(file);
    raw.exec("UPDATE scans SET state='partial', terminal_at=CURRENT_TIMESTAMP WHERE subject='owner-5'; DROP TABLE scan_check_results; PRAGMA user_version=10;");
    const tables = raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all() as { name: string }[];
    const before = Object.fromEntries(tables.map(({ name }) => [name, raw.prepare(`SELECT * FROM ${name} ORDER BY rowid`).all()]));
    raw.close();
    const upgraded = new ScanLedger(file), second = new ScanLedger(file);
    const reader = new Database(file);
    try {
      assert.equal(reader.pragma('user_version', { simple: true }), 11);
      for (const { name } of tables) assert.deepEqual(reader.prepare(`SELECT * FROM ${name} ORDER BY rowid`).all(), before[name]);
      assert.deepEqual(reader.prepare('SELECT * FROM scan_check_results').all(), []);
      assert.deepEqual(reader.pragma('foreign_key_check'), []); assert.equal(reader.pragma('integrity_check', { simple: true }), 'ok');
      assert.equal(second.configResult((before.scans as { id: string }[])[0].id, 'owner-0'), undefined);
      await reader.backup(join(directory, 'backup.sqlite'));
    } finally { reader.close(); second.close(); upgraded.close(); }
    const restored = new ScanLedger(join(directory, 'backup.sqlite')); restored.close();
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('v11 migration failure leaves v10 version and rows untouched', async () => fixture(async (ledger, file) => {
  ledger.enqueue(target);
  const raw = new Database(file);
  raw.exec('DROP TABLE scan_check_results; CREATE TABLE scan_check_results(sentinel TEXT); PRAGMA user_version=10;');
  const before = raw.prepare('SELECT * FROM scans').all(); raw.close();
  assert.throws(() => new ScanLedger(file), /already exists/);
  const after = new Database(file);
  try { assert.equal(after.pragma('user_version', { simple: true }), 10); assert.deepEqual(after.prepare('SELECT * FROM scans').all(), before); }
  finally { after.close(); }
}));

test('SQL constraints: FK, uniqueness, attempt, versions, UTF-8 byte bound; reopen/backup/prune retain honest evidence', async () => fixture(async (ledger, file, directory) => {
  const id = ledger.enqueue(target).scanId, job = ledger.claim()!;
  const report = await runImageConfig(ledger, job, new AbortController().signal, fixtureLoader(bytes));
  const raw = new Database(file); raw.pragma('foreign_keys=ON');
  try {
    const insert = raw.prepare('INSERT INTO scan_check_results(scan_id,check_name,attempt,outcome,checks_version,resource_policy_version,report) VALUES (?,?,?,?,?,?,?)');
    const valid = [id, 'config', 1, 'checked', report.checksVersion, report.resourcePolicyVersion, JSON.stringify(report)];
    for (const [field, value] of [[0, 'missing'], [1, 'secret'], [2, 0], [3, 'safe'], [4, 'future'], [5, 'future'], [6, 'é'.repeat(8193)]]) {
      const invalid = [...valid]; invalid[field as number] = value; assert.throws(() => insert.run(...invalid));
    }
    assert.equal(ledger.finishCombined(id, job.attempts, [secret], report), true);
    assert.throws(() => insert.run(...valid));
    const reopened = new ScanLedger(file);
    try { assert.deepEqual(reopened.configResult(id, 'alice'), report); assert.equal(reopened.configResult(id, 'bob'), undefined); }
    finally { reopened.close(); }
    const backup = join(directory, 'backup.sqlite'); await raw.backup(backup);
    const restored = new ScanLedger(backup); try { assert.deepEqual(restored.configResult(id, 'alice'), report); } finally { restored.close(); }
    raw.prepare("UPDATE scans SET terminal_at=datetime('now','-40 days') WHERE id=?").run(id);
    assert.equal(ledger.prune(), 1); assert.deepEqual(raw.prepare('SELECT * FROM scan_check_results').all(), []);
    assert.deepEqual(raw.pragma('foreign_key_check'), []);
  } finally { raw.close(); }
}));
