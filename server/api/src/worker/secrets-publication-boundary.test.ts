import assert from 'node:assert/strict';
import type { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import Database from 'better-sqlite3';
import { ScanLedger, type Job } from '../ledger/ledger.js';
import { consumeOne } from './outbox-consumer.js';
import { scanPinned, type ScanResult } from './scan-worker.js';
import { parseSecretFindings } from './secret-findings.js';
import type { SbomScanResult } from './sbom-worker.js';

const canary = 'SYNTHETIC_SECRET_CANARY_20261016';
const rule = 'SYNTHETIC_RULE_CANARY_20261016';
const raw = JSON.stringify({ Metadata: { Env: [canary] }, Results: [{ Target: `/synthetic/${canary}`,
  Secrets: [{ RuleID: rule, StartLine: 12, Match: canary, Title: canary,
    Code: { Lines: [{ Content: canary }] } }, { RuleID: rule, StartLine: canary, Match: canary }] }] });
const expected = [0, 1].map(index => ({ findingId: `secret-0-${index}`,
  ruleId: `rule-${createHash('sha256').update(rule).digest('hex').slice(0, 16)}`,
  line: index === 0 ? 12 : null, evidenceRef: `result-0-secret-${index}` }));
const success: ScanResult = { ok: true, findings: expected, scannerVersion: '0.69.3' };

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

function fakeScanner() {
  const child = Object.assign(new EventEmitter(), { stdout: new PassThrough(),
    kill: (signal: string) => { signals.push(signal); return true; } });
  const signals: string[] = [];
  let stops = 0;
  const lifecycle = {
    spawn: (() => child) as unknown as typeof spawn,
    stopWorker: () => { stops++; },
  };
  return { child, signals, lifecycle, get stops() { return stops; } };
}

async function fixture(checks: string, run: (context: {
  ledger: ScanLedger; id: string; directory: string; options: { timeoutMs: number; dbDir: string };
  reopen: () => ScanLedger;
}) => Promise<void>) {
  const directory = mkdtempSync(join(tmpdir(), 'secrets-publication-'));
  const filename = join(directory, 'ledger.sqlite');
  let ledger = new ScanLedger(filename);
  try {
    const { scanId: id } = ledger.enqueue({ subject: 'alice', idempotencyKey: 'synthetic',
      registry: 'registry-1.docker.io', repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`,
      platform: 'linux/amd64', scope: 'image', checks });
    await run({ ledger, id, directory, options: { timeoutMs: 1000, dbDir: join(directory, 'unused-cache') },
      reopen: () => { ledger.close(); ledger = new ScanLedger(filename); return ledger; } });
  } finally { ledger.close(); rmSync(directory, { recursive: true, force: true }); }
}

function assertNoRawPersistence(directory: string) {
  // Inspect only this test's disposable DB, including audit/events and active WAL bytes.
  const observer = new Database(join(directory, 'ledger.sqlite'), { readonly: true, fileMustExist: true });
  try {
    const tables = observer.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as { name: string }[];
    for (const { name } of tables) {
      assert.match(name, /^[a-zA-Z0-9_]+$/);
      const rows = JSON.stringify(observer.prepare(`SELECT * FROM "${name}"`).all());
      for (const value of [canary, rule]) assert.equal(rows.includes(value), false, `raw value in ${name}`);
    }
  } finally { observer.close(); }
  for (const name of readdirSync(directory).filter(name => /^ledger\.sqlite(?:-wal|-shm)?$/.test(name))) {
    const bytes = readFileSync(join(directory, name));
    for (const value of [canary, rule]) assert.equal(bytes.includes(Buffer.from(value)), false, `raw bytes in ${name}`);
  }
}

function assertCancelled(ledger: ScanLedger, id: string, preserved = false) {
  assert.equal(ledger.state(id, 'alice'), 'cancelled');
  if (preserved) {
    assert.equal(ledger.result(id, 'alice')?.outcome, 'checked');
    assert.deepEqual(ledger.secretDataset(id, 'alice')?.findings, expected);
    assert.equal(ledger.secretDataset(id, 'bob'), undefined);
  } else {
    assert.equal(ledger.result(id, 'alice'), undefined);
    assert.equal(ledger.secretDataset(id, 'alice'), undefined);
  }
  assert.deepEqual(ledger.findings(id, 'alice'), { findings: preserved ? expected : [], nextCursor: null });
  assert.equal(ledger.sbom(id, 'alice'), undefined);
  assert.equal(ledger.configResult(id, 'alice'), undefined);
  assert.deepEqual(ledger.pending(), []);
  assert.deepEqual(ledger.events(id, 'alice', null)?.map(event => event.state), ['queued', 'running', 'cancelled']);
}

test('positive raw Secrets traverse adapter -> consumer -> SQLite/reopen with only safe findings retained', { timeout: 5000 }, async () =>
  fixture('["secret"]', async ({ ledger, id, directory, options, reopen }) => {
    const fake = fakeScanner();
    try {
      assert.equal(await consumeOne(ledger, options, async (job, settings) => {
        const result = scanPinned(job, settings, fake.lifecycle);
        fake.child.stdout.write(raw.slice(0, 31));
        fake.child.stdout.write(raw.slice(31));
        fake.child.emit('close', 0);
        assert.deepEqual(await result, success);
        return result;
      }), true);
      const verify = (db: ScanLedger) => {
        assert.equal(db.state(id, 'alice'), 'completed');
        assert.deepEqual(db.secretDataset(id, 'alice'), { findings: expected, coverage: {
          findingCount: 2, check: 'secret', coverage: 'image', outcome: 'checked', errorCode: null, scannerVersion: '0.69.3' } });
        assert.equal(db.secretDataset(id, 'bob'), undefined);
        assert.equal(db.findings(id, 'bob'), undefined);
        assert.equal(db.events(id, 'bob', null), undefined);
        assert.deepEqual(db.events(id, 'alice', null)?.map(event => event.state), ['queued', 'running', 'completed']);
        assert.deepEqual(db.pending(), []);
      };
      verify(ledger);
      assertNoRawPersistence(directory);
      verify(reopen());
      assertNoRawPersistence(directory);
      assert.deepEqual(fake.signals, []);
      assert.equal(fake.stops, 0);
    } finally { fake.child.emit('close', null); fake.child.stdout.destroy(); }
  }));

for (const mode of ['truncated', 'nonzero'] as const) {
  test(`positive Secrets in ${mode} scanner output never become checked coverage or retained fragments`, { timeout: 5000 }, async () =>
    fixture('["secret"]', async ({ ledger, id, directory, options, reopen }) => {
      const fake = fakeScanner();
      try {
        assert.equal(await consumeOne(ledger, options, async (job, settings) => {
          const result = scanPinned(job, settings, fake.lifecycle);
          fake.child.stdout.write(mode === 'truncated' ? raw.slice(0, -1) : raw);
          fake.child.emit('close', mode === 'nonzero' ? 1 : 0);
          return result;
        }), true);
        const verify = (db: ScanLedger) => {
          assert.equal(db.state(id, 'alice'), 'failed');
          assert.deepEqual(db.result(id, 'alice'), { findingCount: null, check: 'secret', coverage: 'image',
            outcome: 'failed', errorCode: mode === 'nonzero' ? 'SCAN_FAILED' : 'SCAN_UNAVAILABLE', scannerVersion: null });
          assert.deepEqual(db.findings(id, 'alice'), { findings: [], nextCursor: null });
          assert.deepEqual(db.events(id, 'alice', null)?.map(event => event.state), ['queued', 'running', 'failed']);
        };
        verify(ledger);
        assertNoRawPersistence(directory);
        verify(reopen());
      } finally { fake.child.emit('close', null); fake.child.stdout.destroy(); }
    }));
}

test('cancel after buffered positive stdout refuses a successful late close and stops the fake worker', { timeout: 5000 }, async () =>
  fixture('["secret"]', async ({ ledger, id, directory, options, reopen }) => {
    const fake = fakeScanner();
    const ready = deferred<void>();
    let scanning: Promise<ScanResult> | undefined;
    const controller = new AbortController();
    const work = consumeOne(ledger, { ...options, signal: controller.signal }, (job, settings) => {
      scanning = scanPinned(job, settings, fake.lifecycle);
      fake.child.stdout.write(raw);
      ready.resolve();
      return scanning;
    });
    try {
      await ready.promise;
      assert.equal(ledger.cancel(id, 'alice'), 'cancelled');
      assert.equal(await work, true, 'consumer must finish while scanner close is still absent');
      assert.deepEqual(fake.signals, ['SIGKILL']);
      assert.equal(fake.stops, 1);
      fake.child.emit('close', 0);
      assert.equal((await scanning!).ok, false);
      assertCancelled(ledger, id);
      assertNoRawPersistence(directory);
      assertCancelled(reopen(), id);
    } finally {
      controller.abort();
      fake.child.emit('close', null);
      fake.child.stdout.destroy();
      await work;
    }
  }));

test('uncooperative positive runner resolves only after consumer cancellation; no late publication or terminal rewrite', { timeout: 5000 }, async () =>
  fixture('["secret"]', async ({ ledger, id, directory, options, reopen }) => {
    const ready = deferred<void>();
    const late = deferred<ScanResult>();
    let attempt: Job | undefined;
    let signal: AbortSignal | undefined;
    const work = consumeOne(ledger, options, (job, settings) => {
      attempt = job;
      signal = settings.signal;
      ready.resolve();
      return late.promise;
    });
    try {
      await ready.promise;
      assert.equal(ledger.cancel(id, 'bob'), 'not_found');
      assert.equal(ledger.state(id, 'alice'), 'running');
      assert.equal(ledger.cancel(id, 'alice'), 'cancelled');
      assert.equal(await work, true, 'must not depend on the uncooperative runner settling');
      assert.equal(signal?.aborted, true);
      const before = ledger.events(id, 'alice', null);
      late.resolve({ ok: true, findings: parseSecretFindings(JSON.parse(raw)), scannerVersion: '0.69.3' });
      await late.promise;
      await new Promise<void>(resolve => setImmediate(resolve));
      assert.equal(ledger.finishCombined(id, attempt!.attempts, [{ check: 'secret', outcome: 'checked',
        findings: expected, scannerVersion: '0.69.3' }], undefined, attempt!.leaseToken), false);
      assert.equal(ledger.cancel(id, 'alice'), 'already_cancelled');
      assert.deepEqual(ledger.events(id, 'alice', null), before);
      assertCancelled(ledger, id);
      assertNoRawPersistence(directory);
      assertCancelled(reopen(), id);
    } finally { late.resolve(success); await work; }
  }));

test('completed positive Secrets checkpoint survives cancellation during the next check with no raw persistence', { timeout: 5000 }, async () =>
  fixture('["secret","sbom","vuln"]', async ({ ledger, id, directory, options, reopen }) => {
    const ready = deferred<void>();
    const late = deferred<SbomScanResult>();
    const calls: string[] = [];
    const work = consumeOne(ledger, { ...options, vuln: { cacheDir: options.dbDir,
      releaseDir: join(directory, 'unused-release'), trust: { trustedPublicKeyPem: '',
        expectedSigner: 'synthetic', expectedSource: 'synthetic', expectedSchemaVersion: 2,
        expectedManifestDigest: `sha256:${'b'.repeat(64)}`, expectedArtifactSha256: 'c'.repeat(64) } } }, async () => {
      calls.push('secret');
      return { ok: true, findings: parseSecretFindings(JSON.parse(raw)), scannerVersion: '0.69.3' };
    }, Date.now(), () => { calls.push('sbom'); ready.resolve(); return late.promise; }, async () => {
      calls.push('vuln');
      assert.fail('cancelled scan must not start another check');
    });
    try {
      await ready.promise;
      assert.equal(ledger.result(id, 'alice'), undefined, 'checkpoint is durable but not yet a published terminal report');
      assert.equal(ledger.cancel(id, 'alice'), 'cancelled');
      assert.equal(await work, true);
      late.resolve({ ok: false, errorCode: 'SCAN_FAILED' });
      await late.promise;
      await new Promise<void>(resolve => setImmediate(resolve));
      assert.deepEqual(calls, ['secret', 'sbom']);
      assertCancelled(ledger, id, true);
      assertNoRawPersistence(directory);
      assertCancelled(reopen(), id, true);
    } finally { late.resolve({ ok: false, errorCode: 'SCAN_FAILED' }); await work; }
  }));
