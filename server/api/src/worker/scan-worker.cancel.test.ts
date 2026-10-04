import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import type { spawn } from 'node:child_process';
import type { Job } from '../ledger/ledger.js';
import { scanPinned } from './scan-worker.js';

const job: Job = { scanId: 'scan', attempts: 1, registry: 'registry-1.docker.io',
  repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`,
  platform: 'linux/amd64', checks: '["secret"]', scope: 'image' };

function scanner() {
  const child = new EventEmitter() as EventEmitter & { stdout: PassThrough; kill: (signal: string) => boolean };
  child.stdout = new PassThrough();
  const signals: string[] = [];
  child.kill = signal => { signals.push(signal); return true; };
  let stops = 0;
  const lifecycle = {
    spawn: (() => child) as unknown as typeof spawn,
    stopWorker: () => { stops++; },
  };
  return { child, signals, lifecycle, get stops() { return stops; } };
}

const wait = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

test('abort stops the worker synchronously before the consumer can take another job', async () => {
  const fake = scanner();
  const controller = new AbortController();
  const result = scanPinned(job, { timeoutMs: 1000, dbDir: '/tmp/cache', signal: controller.signal }, fake.lifecycle);
  controller.abort();
  assert.deepEqual(fake.signals, ['SIGKILL']);
  assert.equal(fake.stops, 1);
  fake.child.emit('close', null);
  assert.equal((await result).ok, false);
});

test('exit with stdout still open never resolves; unreaped pipe stops worker after grace period', async () => {
  const fake = scanner();
  let resolved = false;
  const result = scanPinned(job, { timeoutMs: 1000, dbDir: '/tmp/cache' }, fake.lifecycle)
    .then(value => { resolved = true; return value; });
  fake.child.emit('exit', null);
  await wait(3200);
  assert.deepEqual(fake.signals, ['SIGKILL']);
  assert.equal(fake.stops, 1);
  assert.equal(resolved, false);
  fake.child.emit('close', null);
  const scan = await result;
  assert.equal(scan.ok, false);
  if (!scan.ok) assert.equal(scan.failure.errorCode, 'SCAN_TIMEOUT');
});

test('stdout byte limit kills scanner and only close allows failure to resolve', async () => {
  const fake = scanner();
  let resolved = false;
  const result = scanPinned(job, { timeoutMs: 1000, dbDir: '/tmp/cache' }, fake.lifecycle)
    .then(value => { resolved = true; return value; });
  for (let i = 0; i < 9; i++) fake.child.stdout.write(Buffer.alloc(1_000_000));
  assert.deepEqual(fake.signals, ['SIGKILL']);
  assert.equal(resolved, false);
  fake.child.emit('close', null);
  assert.equal((await result).ok, false);
  assert.equal(fake.stops, 0);
});
