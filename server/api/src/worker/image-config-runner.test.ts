import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ScanLedger } from '../ledger/ledger.js';
import { runImageConfig } from './image-config-runner.js';
import { configBytes, fixtureLoader } from './config-test-fixtures.js';
import { consumeOne } from './outbox-consumer.js';

for (const revocation of ['retry', 'cancel', 'replacement', 'subject', 'digest', 'checks'] as const) {
  test(`authority revoked across async byte load: ${revocation}`, async () => {
    const dir = mkdtempSync(join(tmpdir(), 'config-authority-'));
    const file = join(dir, 'ledger.sqlite');
    const ledger = new ScanLedger(file);
    const bytes = configBytes();
    try {
      const id = ledger.enqueue({ subject: 'alice', idempotencyKey: 'config-attempt', registry: 'registry-1.docker.io',
        repository: 'library/alpine', digest: bytes.digest, platform: 'linux/amd64', checks: '["config"]' }).scanId;
      const job = ledger.claim(1000, 100)!;
      let release!: () => void, started!: () => void;
      const ready = new Promise<void>(resolve => { started = resolve; });
      const waiting = new Promise<void>(resolve => { release = resolve; });
      const work = runImageConfig(ledger, job, new AbortController().signal, async (...args) => { started(); await waiting; return fixtureLoader(bytes)(...args); });
      await ready;
      if (revocation === 'retry') { assert.equal(ledger.retry(id, job.attempts, 99_000), true); assert.equal(ledger.attemptActive(id, job.attempts), true); }
      else if (revocation === 'cancel') ledger.cancel(id, 'alice');
      else if (revocation === 'replacement') assert.equal(ledger.claim(32_101, 100)?.attempts, 2);
      else {
        const { default: Database } = await import('better-sqlite3'); const raw = new Database(file);
        if (revocation === 'subject') raw.prepare('UPDATE scans SET subject=? WHERE id=?').run('bob', id);
        if (revocation === 'digest') raw.prepare('UPDATE scans SET digest=? WHERE id=?').run(`sha256:${'a'.repeat(64)}`, id);
        if (revocation === 'checks') raw.prepare('UPDATE scans SET checks=? WHERE id=?').run('["secret","config"]', id);
        raw.close();
      }
      release();
      assert.deepEqual((await work).config, { outcome: 'failed', reason: 'OCI_IDENTITY_REJECTED' });
      assert.equal(ledger.configResult(id, 'alice'), undefined);
    } finally { ledger.close(); rmSync(dir, { recursive: true, force: true }); }
  });
}
for (const field of ['scanId', 'attempts', 'registry', 'repository', 'digest', 'platform', 'checks', 'scope'] as const) {
  test(`forged job field ${field} never receives bytes`, async () => {
    const dir = mkdtempSync(join(tmpdir(), 'config-forged-')); const ledger = new ScanLedger(join(dir, 'db.sqlite'));
    try {
      ledger.enqueue({ subject: 'alice', idempotencyKey: 'config-forged', registry: 'registry-1.docker.io', repository: 'library/alpine',
        digest: configBytes().digest, platform: 'linux/amd64', checks: '["config"]' });
      const job = ledger.claim()!; let calls = 0;
      const forged = { ...job, [field]: field === 'attempts' ? job.attempts + 1 : field === 'checks' ? '["secret","config"]' : 'forged' };
      const result = await runImageConfig(ledger, forged, new AbortController().signal, async () => { calls++; throw Error(); });
      assert.equal(result.config.outcome, 'failed'); assert.equal(calls, 0);
    } finally { ledger.close(); rmSync(dir, { recursive: true, force: true }); }
  });
}
for (const action of ['retry', 'cancel', 'abort', 'replacement'] as const) {
  test(`consumer ${action} during uncooperative load commits no staged sibling/config outcomes`, async () => {
    const dir = mkdtempSync(join(tmpdir(), 'config-consumer-revoke-')); const ledger = new ScanLedger(join(dir, 'db.sqlite'));
    try {
      const bytes = configBytes(); const id = ledger.enqueue({ subject: 'alice', idempotencyKey: 'config-revoke', registry: 'registry-1.docker.io',
        repository: 'library/alpine', digest: bytes.digest, platform: 'linux/amd64', checks: '["secret","config"]' }).scanId;
      let started!: () => void; const ready = new Promise<void>(resolve => { started = resolve; });
      const controller = new AbortController(); let sibling = false;
      const work = consumeOne(ledger, { timeoutMs: 1000, dbDir: '/unused', signal: controller.signal,
        configLoader: async () => { started(); return new Promise(() => {}); } }, async () => { sibling = true; return { ok: true, findings: [], scannerVersion: '0.69.3' }; }, 1000);
      await ready;
      if (action === 'retry') ledger.retry(id, 1, 99_000);
      if (action === 'cancel') ledger.cancel(id, 'alice');
      if (action === 'abort') controller.abort();
      if (action === 'replacement') assert.equal(ledger.claim(65_001)?.attempts, 2);
      await work;
      assert.equal(sibling, false); assert.equal(ledger.configResult(id, 'alice'), undefined); assert.equal(ledger.result(id, 'alice'), undefined);
    } finally { ledger.close(); rmSync(dir, { recursive: true, force: true }); }
  });
}
