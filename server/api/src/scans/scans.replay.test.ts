import 'reflect-metadata';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { ConflictException, ServiceUnavailableException } from '@nestjs/common';
import { ScanLedger } from '../ledger/ledger.js';
import type { LedgerStore } from '../ledger/ledger-store.js';
import type { OciResolver } from '../oci/oci-resolver.js';
import { parseScanRequest } from './scan-request.js';
import { ScansService } from './scans.service.js';

const body = { imageReference: 'registry-1.docker.io/library/alpine:3.20', checks: ['secret'], scope: 'image', idempotencyKey: 'replay-key-123' };
const identity = { subject: 'alice', scope: ['scan:create'] };

test('two POSTs resolving a mutable tag to different digests still commit one original pinned job', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scan-race-'));
  try {
    const ledger = new ScanLedger(join(dir, 'db.sqlite'));
    let resolves = 0;
    const resolver = { async resolvePublicAlpine() {
      resolves++;
      return { registry: 'registry-1.docker.io', repository: 'library/alpine',
        digest: `sha256:${(resolves === 1 ? 'a' : 'b').repeat(64)}`, platform: 'linux/amd64' };
    } } as unknown as OciResolver;
    class ReadyService extends ScansService {
      protected override async readiness() { return true; }
    }
    const service = new ReadyService({ ledger } as LedgerStore, resolver);
    const receipts = await Promise.all([service.create(identity, body), service.create(identity, body)]);
    assert.equal(receipts[0].scanId, receipts[1].scanId);
    assert.equal(ledger.pending().length, 1);
    assert.equal(ledger.findByKey('alice', body.idempotencyKey)?.digest, `sha256:${'a'.repeat(64)}`);
    assert.equal((await service.create(identity, body)).scanId, receipts[0].scanId);
    ledger.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('committed replay precedes readiness and tag resolution, even across restart', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scan-replay-'));
  try {
    const file = join(dir, 'db.sqlite');
    let ledger = new ScanLedger(file);
    const fingerprint = parseScanRequest(body, new Set(['registry-1.docker.io'])).fingerprint;
    const original = ledger.enqueue({ subject: identity.subject, idempotencyKey: body.idempotencyKey,
      fingerprint, registry: 'registry-1.docker.io', repository: 'library/alpine',
      digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', checks: '["secret"]' });
    ledger.close();
    ledger = new ScanLedger(file);
    const resolver = { resolvePublicAlpine() { throw new Error('Mutable tag changed; resolver must not run'); } } as unknown as OciResolver;
    const service = new ScansService({ ledger } as LedgerStore, resolver);
    assert.equal((await service.create(identity, body)).scanId, original.scanId);
    assert.equal(ledger.findByKey('alice', body.idempotencyKey)?.digest, `sha256:${'a'.repeat(64)}`);
    await assert.rejects(service.create(identity, { ...body, imageReference: 'registry-1.docker.io/library/alpine:latest' }), ConflictException);
    await assert.rejects(service.create(identity, { ...body, idempotencyKey: 'other-key-123' }), ServiceUnavailableException);
    ledger.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
