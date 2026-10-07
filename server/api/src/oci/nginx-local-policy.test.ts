import 'reflect-metadata';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { BadRequestException, ForbiddenException, ServiceUnavailableException } from '@nestjs/common';
import { ScanLedger } from '../ledger/ledger.js';
import type { LedgerStore } from '../ledger/ledger-store.js';
import type { OciResolver } from './oci-resolver.js';
import { ScansService } from '../scans/scans.service.js';
import { NginxLocalScansService, localWorkerReady } from './nginx-local-profile.js';
import { NGINX_LOCAL_POLICY as p, NGINX_LOCAL_BINDING as binding, exactLocalTarget, localChecksAllowed, localReceiptMatches, validLocalBinding } from './nginx-local-policy.js';
import { consumeOne } from '../worker/outbox-consumer.js';
import { localResourceEnvelope } from '../worker/worker-runtime.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';
import { normalizeImageSuggestions } from '../scans/image-search.js';

const reference = `${p.registry}/${p.repository}@${p.digest}`;
const owner = { subject: 'owner', scope: ['scan:create'] };
class FixtureService extends NginxLocalScansService {
  available = true; dbAvailable = true; resolutions = 0;
  protected override async readiness() { return this.available; }
  protected override async vulnDbReady() { return this.dbAvailable; }
  protected override async resolveTarget() { this.resolutions++; return p; }
}
function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'local-policy-')), file = join(directory, 'db.sqlite');
  const ledger = new ScanLedger(file), store = { ledger } as LedgerStore;
  const resolver = {} as OciResolver;
  return { directory, file, ledger, service: new FixtureService(store, resolver), defaultService: new ScansService(store, resolver),
    close: () => { ledger.close(); rmSync(directory, { recursive: true, force: true }); } };
}
const report = (): ArchiveScanReport => ({ receipt: { registry: p.registry, repository: p.repository, digest: p.digest, configDigest: p.configDigest,
  platform: p.platform, layerDigests: [`sha256:${'a'.repeat(64)}`], diffIds: [`sha256:${'b'.repeat(64)}`], archiveSha256: `sha256:${'c'.repeat(64)}`,
  profileVersion: p.profileVersion, resourcePolicyVersion: p.resourcePolicyVersion, checksVersion: p.checksVersion }, scannerVersion: '0.69.3',
  checkedAt: Date.now(), metrics: { wireBytes: 100, requests: 5, compressedBytes: 50, expandedBytes: 2048, entries: 1,
    archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 }, secret: { outcome: 'checked', findings: [] } });

test('compiled identity is deeply frozen, only four canonical sets/receipt/binding can match', () => {
  assert.ok(Object.isFrozen(p) && Object.isFrozen(p.allowedCheckSets) && p.allowedCheckSets.every(Object.isFrozen));
  for (const set of p.allowedCheckSets) assert.ok(localChecksAllowed(set));
  for (const set of [[], ['config'], ['secret','config'], ['secret','sbom'], ['sbom','vuln'], ['vuln','secret'], ['secret','secret']]) assert.equal(localChecksAllowed(set), false);
  assert.ok(exactLocalTarget(p)); assert.ok(validLocalBinding(binding)); assert.ok(localReceiptMatches(report().receipt, '0.69.3'));
  for (const key of Object.keys(binding)) assert.equal(validLocalBinding({ ...binding, [key]: 'wrong' }), false);
  assert.equal(validLocalBinding({ ...binding, extra: true }), false);
  assert.equal(exactLocalTarget({ ...p, digest: `sha256:${'a'.repeat(64)}` }), false);
  assert.equal(localReceiptMatches({ ...report().receipt, digest: 'sha256:b17b00f7ef0038aeb11362157f49006a130628ee711cefcced871405d046f114', configDigest: 'sha256:42ce3d3585d47518cb0c1ef4bd3d8a65c1edfcbbfd423eda86990a83f378b111' }, '0.69.3'), false);
  assert.equal(localReceiptMatches(report().receipt, '0.69.2'), false);
});

test('LOCAL policy before replay; exact replay before DB/readiness; eligibility is readonly/current and default closed', async () => {
  const f = fixture(), previous = process.env.SCAN_VULN_ENABLED; process.env.SCAN_VULN_ENABLED = 'true';
  try {
    const body = { imageReference: reference, checks: ['secret'], scope: 'image', idempotencyKey: 'local-intent-0001' };
    await assert.rejects(f.service.create({ ...owner, scope: [] }, body), ForbiddenException);
    for (const imageReference of [reference.replace(p.digest, `sha256:${'a'.repeat(64)}`), reference.replace('nginx','node'),
      reference.replace(p.digest, 'sha256:b17b00f7ef0038aeb11362157f49006a130628ee711cefcced871405d046f114'),
      'registry-1.docker.io/library/nginx:latest', reference.replace('library/nginx','evil/nginx')])
      await assert.rejects(f.service.create(owner, { ...body, imageReference }), BadRequestException);
    for (const checks of [['config'], ['secret','sbom'], ['secret','config']])
      await assert.rejects(f.service.create(owner, { ...body, checks }), BadRequestException);
    assert.equal(f.ledger.pending().length, 0);
    const receipt = await f.service.create(owner, body);
    assert.deepEqual(f.ledger.executionProfile(receipt.scanId), binding);
    f.service.available = false; f.service.dbAvailable = false;
    assert.deepEqual(await f.service.create(owner, body), receipt); assert.equal(f.service.resolutions, 1);
    await assert.rejects(f.defaultService.create(owner, body), BadRequestException);
    const unavailable = await f.service.eligibility(owner, { imageReference: reference, checks: ['secret'] });
    assert.equal(unavailable.eligible, false); assert.equal(unavailable.reason, 'SCANNER_UNAVAILABLE');
    f.service.available = true;
    const ready = await f.service.eligibility(owner, { imageReference: reference, checks: ['secret'] });
    assert.equal(ready.eligible, true); assert.deepEqual(ready.allowedCheckSets, p.allowedCheckSets);
    assert.equal((await f.service.eligibility(owner, { imageReference: reference, checks: ['vuln'] })).reason, 'DB_UNAVAILABLE');
    assert.equal((await f.service.eligibility(owner, { imageReference: reference, checks: ['config'] })).eligible, false);
    assert.equal((await f.defaultService.eligibility(owner, { imageReference: reference, checks: ['secret'] })).eligible, false);
    await assert.rejects(f.service.eligibility(owner, { imageReference: reference, checks: ['secret'], scannable: true }), BadRequestException);
    await assert.rejects(f.service.create(owner, { ...body, idempotencyKey: 'local-intent-0002', checks: ['vuln'] }), ServiceUnavailableException);
    assert.equal(f.ledger.pending().length, 1);
    const [suggestion] = normalizeImageSuggestions({ results: [{ repo_name: 'nginx' }], count: 1, next: null }, false);
    assert.equal(f.defaultService.imageSuggestion(suggestion).scannable, false);
    assert.deepEqual(f.service.imageSuggestion(suggestion).allowedCheckSets, p.allowedCheckSets);
    // Rate limit is charged before the expensive readiness/DB/resolution seam.
    for (let index = 0; index < 31; index++) await f.service.eligibility(owner, { imageReference: reference, checks: ['secret'] }).catch(() => undefined);
    await assert.rejects(f.service.eligibility(owner, { imageReference: reference, checks: ['secret'] }), error => (error as { status: number }).status === 429);
  } finally { if (previous === undefined) delete process.env.SCAN_VULN_ENABLED; else process.env.SCAN_VULN_ENABLED = previous; f.close(); }
});

test('default/prequeued/missing-binding worker rejects BEFORE config/archive/scanner; LOCAL binds actual receipt', async () => {
  for (const mode of ['default', 'missing', 'unsupported', 'wrong-context', 'wrong-repository', 'local', 'wrong-receipt'] as const) {
    const f = fixture();
    try {
      const id = f.ledger.enqueue({ ...p, subject: 'owner', scope: 'image', idempotencyKey: 'worker-policy', checks: '["secret"]',
        ...(mode === 'missing' ? {} : { executionProfile: binding }) }).scanId;
      if (mode === 'unsupported' || mode === 'wrong-context' || mode === 'wrong-repository') {
        const raw = new Database(f.file);
        if (mode === 'unsupported') raw.prepare('UPDATE scans SET checks=? WHERE id=?').run('["secret","config"]', id);
        else if (mode === 'wrong-context') raw.prepare('UPDATE scans SET platform=? WHERE id=?').run('linux/arm64', id);
                else raw.prepare('UPDATE scans SET repository=? WHERE id=?').run('library/alpine', id);
        raw.close();
      }
      let calls = 0;
      await consumeOne(f.ledger, { timeoutMs: 1000, dbDir: '/unused', ...(mode !== 'default' ? { archivePolicy: 'local' as const } : {}),
        configLoader: async () => { assert.fail('no config selected'); } }, async () => { assert.fail('remote runner'); }, Date.now(), undefined, undefined,
        async () => { calls++; const value = report(); if (mode === 'wrong-receipt') value.receipt.profileVersion = 'nginx-alpine-amd64-v1'; return value; });
      assert.equal(calls, mode === 'local' || mode === 'wrong-receipt' ? 1 : 0);
      assert.equal(f.ledger.state(id, 'owner'), mode === 'local' ? 'completed' : 'failed');
      assert.equal(!!f.ledger.archiveResult(id, 'owner'), mode === 'local');
      if (mode === 'local') assert.equal((f.service.status(owner, id) as { imageProfile: { qualified: boolean } }).imageProfile.qualified, true);
    } finally { f.close(); }
  }
});

test('v12 binding is atomic, legacy remains unqualified, reopen/fences/retention/rollback preserve rows', () => {
  const f = fixture();
  try {
    const input = { ...p, subject: 'owner', scope: 'image', idempotencyKey: 'binding-atomic', checks: '["secret"]', executionProfile: binding };
    const raw = new Database(f.file);
    raw.exec("CREATE TRIGGER reject_profile BEFORE INSERT ON scan_execution_profiles BEGIN SELECT RAISE(ABORT, 'profile rejected'); END");
    assert.throws(() => f.ledger.enqueue(input)); assert.equal(f.ledger.pending().length, 0);
    raw.exec('DROP TRIGGER reject_profile');
    const id = f.ledger.enqueue(input).scanId;
    const first = f.ledger.claim(1000, 1000, 627000)!;
    const second = f.ledger.claim(628000, 1000, 627000)!;
    assert.equal(f.ledger.finishArchive(id, first.attempts, report()), false);
    const mismatched = report(); mismatched.receipt.resourcePolicyVersion = 'other';
    assert.throws(() => f.ledger.finishArchive(id, second.attempts, mismatched));
    assert.equal(f.ledger.state(id, 'owner'), 'running');
    assert.equal(f.ledger.finishArchive(id, second.attempts, report()), true);
    const reopened = new ScanLedger(f.file); assert.deepEqual(reopened.executionProfile(id), binding); reopened.close();
    raw.prepare("UPDATE scans SET terminal_at=datetime('now','-40 days') WHERE id=?").run(id);
    assert.equal(f.ledger.prune(30), 1); assert.equal(f.ledger.executionProfile(id), undefined);
    assert.deepEqual(raw.pragma('foreign_key_check'), []); raw.close();
  } finally { f.close(); }
});

test('v11 forward upgrade never promotes legacy rows and conflicting v12 DDL rolls back', () => {
  for (const corrupt of [false, true]) {
    const f = fixture();
    try {
      const id = f.ledger.enqueue({ ...p, subject: 'owner', scope: 'image', idempotencyKey: 'legacy-v11', checks: '["secret"]' }).scanId;
      const raw = new Database(f.file);
      raw.exec('DROP TABLE scan_execution_profiles; PRAGMA user_version=11;');
      if (corrupt) raw.exec('CREATE TABLE scan_execution_profiles(sentinel TEXT);');
      const before = raw.prepare('SELECT * FROM scans').all();
      if (corrupt) {
        assert.throws(() => new ScanLedger(f.file), /already exists/);
        assert.equal(raw.pragma('user_version', { simple: true }), 11);
      } else {
        const upgraded = new ScanLedger(f.file);
        assert.equal(upgraded.executionProfile(id), undefined);
        assert.equal(raw.pragma('user_version', { simple: true }), 12);
        upgraded.close();
      }
      assert.deepEqual(raw.prepare('SELECT * FROM scans').all(), before);
      assert.deepEqual(raw.pragma('foreign_key_check'), []); raw.close();
    } finally { f.close(); }
  }
});

test('marker version/freshness/symlink and actual cgroup contract mismatch fail closed', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'local-marker-')), path = join(directory, 'ready');
  try {
    const marker = { qualificationId: p.qualificationId, version: p.version, at: Date.now() };
    writeFileSync(path, JSON.stringify(marker)); assert.equal(await localWorkerReady(path), true);
    for (const value of [{ ...marker, version: 2 }, { ...marker, at: Date.now() - 6000 }, { ...marker, at: Date.now() + 6000 }, { ...marker, other: true }]) {
      writeFileSync(path, JSON.stringify(value)); assert.equal(await localWorkerReady(path), false);
    }
    symlinkSync(path, join(directory, 'link')); assert.equal(await localWorkerReady(join(directory, 'link')), false);
    const envelope: Record<string, string> = { 'memory.max': '1073741824', 'memory.swap.max': '0', 'cpu.max': '100000 100000', 'pids.max': '128' };
    assert.equal(localResourceEnvelope(name => envelope[name]), true);
    for (const key of Object.keys(envelope)) assert.equal(localResourceEnvelope(name => name === key ? 'bad' : envelope[name]), false);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
