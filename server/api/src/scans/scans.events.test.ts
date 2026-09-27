import 'reflect-metadata';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { ScanLedger } from '../ledger/ledger.js';
import type { LedgerStore } from '../ledger/ledger-store.js';
import type { OciResolver } from '../oci/oci-resolver.js';
import { ScansService } from './scans.service.js';

const identity = { subject: 'alice', scope: ['scan:create'] };
test('durable ordered events and subject-scoped reconnect snapshot after terminal', () => {
  const dir = mkdtempSync(join(tmpdir(), 'scan-events-'));
  try {
    const ledger = new ScanLedger(join(dir, 'db.sqlite'));
    const { scanId } = ledger.enqueue({ subject: 'alice', idempotencyKey: 'key', registry: 'registry-1.docker.io',
      repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', checks: '["secret"]' });
    const service = new ScansService({ ledger } as LedgerStore, {} as OciResolver);
    const queued = ledger.events(scanId, 'alice', null)![0];
    const job = ledger.claim()!;
    assert.equal(ledger.finishWithResult(scanId, job.attempts, [], '0.69.3'), true);
    const later = ledger.events(scanId, 'alice', queued.id)!;
    assert.deepEqual(later.map(e => e.state), ['running', 'completed']);
    assert.ok(later[0].id > queued.id && later[1].id > later[0].id);
    assert.deepEqual(ledger.events(scanId, 'alice', later[1].id), [later[1]]);
    assert.equal(ledger.events(scanId, 'bob', null), undefined);
    assert.match(service.events(identity, scanId, String(queued.id)), /event: scan/);
    assert.throws(() => service.events({ subject: 'bob', scope: ['scan:create'] }, scanId, undefined));
    ledger.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
