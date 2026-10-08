import assert from 'node:assert/strict';
import test from 'node:test';
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { QuotaLedger as ExistingQuotaLedger } from '../quota-ledger.js';
import { FixtureQuotaLedger as QuotaLedger } from './quota-fixtures.js';
import { DAY } from '../quota-policy.js';
import { quotaPolicy } from './quota-fixtures.js';
const binding = { subject: 'owner', scanId: 'scan', reportVersion: 'a'.repeat(64), policyVersion: 'b'.repeat(64), requestHash: 'c'.repeat(64) };
const reserve = { input: 2000, output: 256, costMicros: 0 };

test('production opens only an initialized existing ledger; missing/empty/schema-loss never reset capacity', () => {
  const dir = mkdtempSync(join(tmpdir(), 'quota-missing-')), path = join(dir, 'llm-usage.sqlite');
  try {
    assert.throws(() => new ExistingQuotaLedger(path, quotaPolicy)); assert.equal(existsSync(path), false);
    writeFileSync(path, '', { mode: 0o600 }); assert.throws(() => new ExistingQuotaLedger(path, quotaPolicy)); rmSync(path);
    const initialized = new QuotaLedger(path, quotaPolicy); initialized.close();
    const opened = new ExistingQuotaLedger(path, quotaPolicy); opened.close();
    const broken = new Database(path); broken.exec('DROP TABLE quota_attempt'); broken.close();
    assert.throws(() => new ExistingQuotaLedger(path, quotaPolicy));
    const inspect = new Database(path); assert.equal((inspect.prepare("SELECT count(*) n FROM sqlite_master WHERE name='quota_attempt'").get() as { n: number }).n, 0); inspect.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('clock is sampled under real write lock; bounded busy failures cannot admit or partially mutate', () => {
  const dir = mkdtempSync(join(tmpdir(), 'quota-lock-')), path = join(dir, 'llm-usage.sqlite');
  let blocker: Database.Database | undefined;
  const ledger = new QuotaLedger(path, { ...quotaPolicy, busyMs: 5 }, () => {
    assert.throws(() => blocker!.exec('BEGIN IMMEDIATE'), /locked/);
    return Date.UTC(2026, 9, 8);
  });
  blocker = new Database(path); blocker.pragma('busy_timeout=1');
  try {
    const id = ledger.reserve(binding, reserve); assert.ok(id);
    blocker.exec('BEGIN IMMEDIATE');
    assert.throws(() => ledger.reserve(binding, reserve));
    blocker.exec('ROLLBACK');
    assert.equal((blocker.prepare('SELECT count(*) n FROM quota_attempt').get() as { n: number }).n, 1);
  } finally { blocker.close(); ledger.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('finite row cap and bounded cleanup preserve unknown indefinitely, terminal replay horizon expires safely', () => {
  const dir = mkdtempSync(join(tmpdir(), 'quota-retention-')), path = join(dir, 'llm-usage.sqlite');
  let time = Date.UTC(2026, 9, 8);
  const policy = { ...quotaPolicy, maxRows: 3, cleanupBatch: 1 };
  const ledger = new QuotaLedger(path, policy, () => time);
  try {
    const unknown = ledger.reserve(binding, reserve); ledger.dispatch(unknown);
    const released = ledger.reserve(binding, reserve); ledger.release(released);
    assert.throws(() => ledger.reserve(binding, reserve));
    time += 9 * DAY;
    const id = ledger.reserve(binding, reserve); ledger.release(id);
    assert.equal(ledger.observe(released, { normal: true, input: 0, output: 0, costMicros: 0 }), false);
    assert.equal(ledger.snapshot('owner', 'scan').user.carried.input, 2000);
    assert.equal(ledger.release(unknown), false);
    assert.equal(ledger.observe(unknown, { normal: true, input: 0, output: 0, costMicros: 0 }), false);
  } finally { ledger.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('wrong basename/schema/version/corruption and unsafe file permissions fail closed without migrating another DB', () => {
  const dir = mkdtempSync(join(tmpdir(), 'quota-invalid-')), path = join(dir, 'llm-usage.sqlite');
  try {
    assert.throws(() => new QuotaLedger(join(dir, 'auth.sqlite'), quotaPolicy));
    writeFileSync(path, 'not a SQLite database', { mode: 0o600 });
    assert.throws(() => new QuotaLedger(path, quotaPolicy));
    rmSync(path);
    const foreign = new Database(path); foreign.exec('CREATE TABLE current_auth (id TEXT)'); foreign.close(); chmodSync(path, 0o600);
    assert.throws(() => new QuotaLedger(path, quotaPolicy));
    const inspect = new Database(path); assert.equal(inspect.pragma('application_id', { simple: true }), 0);
    assert.equal((inspect.prepare('SELECT count(*) n FROM sqlite_master WHERE name=?').get('quota_attempt') as { n: number }).n, 0); inspect.close();
    rmSync(path);
    const ledger = new QuotaLedger(path, quotaPolicy); ledger.close(); chmodSync(path, 0o644);
    assert.throws(() => new QuotaLedger(path, quotaPolicy));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('logical page budget/DELETE journal/FULL durability, unusable headroom and corrupt clock refuse admission', () => {
  const dir = mkdtempSync(join(tmpdir(), 'quota-bounds-')), path = join(dir, 'llm-usage.sqlite');
  const ledger = new QuotaLedger(path, quotaPolicy);
  const inspect = new Database(path);
  try {
    assert.equal(inspect.pragma('journal_mode', { simple: true }), 'delete');
    assert.equal(inspect.pragma('page_size', { simple: true }), 4096);
    // max_page_count is connection-local: verify enforcement through the ledger,
    // not a new connection's default. Inspect durable rows, no secret payloads.
    inspect.prepare('UPDATE quota_meta SET clock=? WHERE id=1').run(8640000000000000);
    assert.throws(() => ledger.reserve(binding, reserve));
    assert.equal((inspect.prepare('SELECT count(*) n FROM quota_attempt').get() as { n: number }).n, 0);
    assert.throws(() => new QuotaLedger(path, { ...quotaPolicy, diskHeadroomBytes: Number.MAX_SAFE_INTEGER }));
  } finally { inspect.close(); ledger.close(); rmSync(dir, { recursive: true, force: true }); }
});
