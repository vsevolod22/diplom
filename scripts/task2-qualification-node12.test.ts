// New targeted compatibility/evidence tests; no discovery runner or old proof execution.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { ScanLedger } from '../server/api/src/ledger/ledger.ts';

const read = (path: string) => readFileSync(new URL('../' + path, import.meta.url), 'utf8');
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const proof = 'server/deploy/proof/';
const previous = JSON.parse(read(proof + 'task2-qualification-validation.json'));

test('historical runner behavior changed only in its two mandatory final lease arguments', () => {
  const source = read('scripts/task2-qualification-run.ts');
  const current = 'ledger.finishCombined(id, job.attempts, outcomes, undefined, job.leaseToken)';
  assert.equal(source.split(current).length - 1, 2);
  const original = source.replace(/^\/\* eslint-disable[^\n]+\*\/\n/, '')
      .replaceAll(current, 'ledger.finishCombined(id, job.attempts, outcomes)');
  assert.equal(hash(original), previous.hashes['scripts/task2-qualification-run.ts']);
});

test('actual TEMP ledger rejects missing/wrong lease, accepts final lease and refuses duplicate', { timeout: 5000 }, () => {
  const directory = mkdtempSync(join(tmpdir(), 'task2-qualification-lease-'));
  let ledger: ScanLedger | undefined;
  try {
    ledger = new ScanLedger(join(directory, 'ledger.sqlite'));
    const id = ledger.enqueue({ subject: 'task2-lease-owner', idempotencyKey: 'task2-lease-compatibility',
      registry: 'registry-1.docker.io', repository: 'library/alpine', digest: `sha256:${'1'.repeat(64)}`,
      platform: 'linux/amd64', checks: '["secret"]', scope: 'image' }).scanId;
    const job = ledger.claim()!;
    assert.equal(job.scanId, id);
    assert.ok(job.leaseToken);
    // A normalized synthetic unit fixture, not scanner or remote acquisition evidence.
    const outcomes = [{ check: 'secret' as const, outcome: 'checked' as const, scannerVersion: '0.69.3' as const,
      findings: [{ findingId: 'secret-0-0', ruleId: 'rule-22550b936ddce0b0', line: 1, evidenceRef: 'result-0-secret-0' }] }];
    assert.equal(ledger.finishCombined(id, job.attempts, outcomes, undefined, undefined), false);
    assert.equal(ledger.finishCombined(id, job.attempts, outcomes, undefined, 'not-the-claimed-lease'), false);
    assert.equal(ledger.state(id, 'task2-lease-owner'), 'running');
    assert.equal(ledger.finishCombined(id, job.attempts, outcomes, undefined, job.leaseToken), true);
    assert.equal(ledger.finishCombined(id, job.attempts, outcomes, undefined, job.leaseToken), false);
    assert.equal(ledger.state(id, 'task2-lease-owner'), 'completed');
    assert.equal(ledger.result(id, 'task2-other'), undefined);
  } finally { ledger?.close(); rmSync(directory, { recursive: true }); }
});

test('single Node12 observation fits compressed caps only, without claiming inflated or remote qualification', () => {
  const text = read(proof + 'task2-node12-metadata.json');
  const e = JSON.parse(text);
  assert.equal(e.candidate, 'registry-1.docker.io/library/node:12.22.12-alpine3.15');
  assert.equal(e.candidateInvestigations, 1);
  assert.equal(e.requests, 3);
  assert.equal(e.discoveryCompleted, true);
  assert.equal(e.compressedEnvelopeFits, true);
  assert.equal(e.compressedTotal, 30_083_968);
  assert.equal(e.largestCompressedLayer, 24_910_721);
  assert.equal(e.layers.length, 4);
  assert.ok(e.layers.every((l: { size: number }) => l.size <= 32 * 1024 ** 2));
  assert.ok(e.compressedTotal <= 96 * 1024 ** 2);
  assert.equal(e.manifestDigest, 'sha256:4517380049fc3c9aacceae7764fcf3500354b0ac8a47e4afb35b5bbeb75b9498');
  assert.equal(e.allCapsVerified, false);
  assert.equal(e.layerAcquisitionAttempted, false);
  assert.equal(e.scannerAttempted, false);
  assert.ok(e.unverifiedCaps.includes('256MiB-inflated-total'));
  assert.ok(!/Bearer |ghp_[A-Za-z0-9]{36}|"(?:Env|Secrets|Match|token)"\s*:/.test(text));
});

test('earlier native and Node14/16 observations remain byte-for-byte unchanged', () => {
  for (const name of ['task2-qualification-results.json', 'task2-npm-remote-candidate.json'])
    assert.equal(hash(read(proof + name)), previous.hashes[proof + name]);
  const smaller = JSON.parse(read(proof + 'task2-small-node-validation.json'));
  for (const name of ['task2-small-node-metadata.json', 'task2-small-node-tests.tap'])
    assert.equal(hash(read(proof + name)), smaller.hashes[proof + name]);
});
