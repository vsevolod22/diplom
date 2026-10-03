import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import type { spawn } from 'node:child_process';
import type { Job } from '../ledger/ledger.js';
import { scanSbomPinned } from './sbom-worker.js';

const job: Job = { scanId: 'scan', attempts: 1, registry: 'registry-1.docker.io',
  repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64',
  checks: '["sbom"]', scope: 'image' };
const image = `${job.registry}/${job.repository}@${job.digest}`;
const report = () => JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6',
  metadata: { component: { type: 'container', name: image } }, components: [
    { type: 'operating-system', name: 'alpine', version: '3.21.3' },
    { type: 'library', name: 'apk-tools', version: '2.14.6-r0', purl: 'pkg:apk/alpine/apk-tools@2.14.6-r0',
      properties: [{ value: 'CANARY_SECRET' }] },
  ] });
function scanner() {
  const child = new EventEmitter() as EventEmitter & { stdout: PassThrough; kill: (signal: string) => boolean };
  child.stdout = new PassThrough();
  const signals: string[] = [];
  child.kill = signal => { signals.push(signal); return true; };
  const calls: { args: string[]; options: Parameters<typeof spawn>[2] }[] = [];
  let stops = 0;
  const lifecycle = { spawn: ((_binary: string, args: string[], options: Parameters<typeof spawn>[2]) => {
    calls.push({ args, options }); return child;
  }) as unknown as typeof spawn, stopWorker: () => { stops++; } };
  return { child, signals, calls, lifecycle, get stops() { return stops; } };
}
const options = { timeoutMs: 1000, cacheDir: '/tmp/trivy' };

test('fixed CycloneDX argv, no inherited proxy or DB fetch; returns only safe parsed fields', async () => {
  const fake = scanner();
  process.env.SENSITIVE_TRIVY_TOKEN = 'CANARY_SECRET';
  try {
    const pending = scanSbomPinned(job, options, fake.lifecycle);
    assert.deepEqual(fake.calls[0].args, [ 'image', '--image-src', 'remote', '--skip-db-update',
      '--skip-java-db-update', '--offline-scan', '--cache-dir', '/tmp/trivy', '--platform', 'linux/amd64',
      '--format', 'cyclonedx', image ]);
    assert.equal(fake.calls[0].options?.shell, false);
    assert.equal(fake.calls[0].options?.env?.SENSITIVE_TRIVY_TOKEN, undefined);
    fake.child.stdout.write(report()); fake.child.emit('close', 0);
    const result = await pending;
    assert.equal(result.ok, true);
    assert.ok(!JSON.stringify(result).includes('CANARY_SECRET'));
    if (result.ok) assert.deepEqual(result.sbom.components, [{ ecosystem: 'apk', name: 'apk-tools', version: '2.14.6-r0' }]);
  } finally { delete process.env.SENSITIVE_TRIVY_TOKEN; }
});

test('rejects wrong repository/platform/check before invoking scanner', async () => {
  const fake = scanner();
  for (const invalid of [{ ...job, checks: '["vuln"]' }, { ...job, repository: 'other' },
    { ...job, platform: 'linux/arm64' }, { ...job, digest: 'sha256:broken' }])
    assert.deepEqual(await scanSbomPinned(invalid, options, fake.lifecycle), { ok: false, errorCode: 'SCAN_FAILED' });
  assert.equal(fake.calls.length, 0);
});

test('rejects malformed, invalid utf8, mismatched image, empty and truncated output on exit zero', async () => {
  for (const output of [Buffer.from('{'), Buffer.from([0xff]), Buffer.from('{}'), Buffer.from(report().replace(image, 'attacker')),
    Buffer.alloc(0)]) {
    const fake = scanner(); const pending = scanSbomPinned(job, options, fake.lifecycle);
    fake.child.stdout.write(output); fake.child.emit('close', 0);
    assert.deepEqual(await pending, { ok: false, errorCode: 'SCAN_FAILED' });
  }
});

test('stdout overflow kills scanner and waits for close even if exit is zero', async () => {
  const fake = scanner(); let resolved = false;
  const pending = scanSbomPinned(job, options, fake.lifecycle).then(result => { resolved = true; return result; });
  fake.child.stdout.write(Buffer.alloc(2_000_001));
  assert.deepEqual(fake.signals, ['SIGKILL']);
  assert.equal(resolved, false);
  fake.child.emit('close', 0);
  assert.deepEqual(await pending, { ok: false, errorCode: 'SCAN_FAILED' });
});

test('abort kills isolated process/container and refuses successful late close', async () => {
  const fake = scanner(); const controller = new AbortController();
  const pending = scanSbomPinned(job, { ...options, signal: controller.signal }, fake.lifecycle);
  controller.abort();
  assert.deepEqual(fake.signals, ['SIGKILL']); assert.equal(fake.stops, 1);
  fake.child.stdout.write(report()); fake.child.emit('close', 0);
  assert.deepEqual(await pending, { ok: false, errorCode: 'SCAN_FAILED' });
});

test('timeout kills scanner and does not accept a late successful close', async () => {
  const fake = scanner(); const pending = scanSbomPinned(job, options, fake.lifecycle);
  await new Promise(resolve => setTimeout(resolve, 1100));
  assert.deepEqual(fake.signals, ['SIGKILL']);
  fake.child.emit('close', 0);
  assert.deepEqual(await pending, { ok: false, errorCode: 'SCAN_TIMEOUT' });
});
