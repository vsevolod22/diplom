import assert from 'node:assert/strict';
import test from 'node:test';
import type { Job, ScanLedger } from '../ledger/ledger.js';
import { NGINX_SUPPORTED_CANDIDATE } from '../oci/bounded-image-archive.js';
import { consumeOne } from './outbox-consumer.js';
import { scannerFailure } from './scanner-errors.js';
import { validateArchiveReport } from './archive-result-contract.js';
import type { scanPublicImageArchive } from './archive-scan-worker.js';
import { publicReport, publicTarget } from './public-image-test-fixtures.js';

// In-memory protocol spy, not a native SQLite, DB, OCI or Trivy integration claim.
function fixture(change: Partial<Job> = {}) {
  const job: Job = { ...publicTarget, scanId: 'fixture-scan', attempts: 1, checks: '["secret"]', scope: 'image',
    leaseToken: 'original-lease-token', ...change };
  let active = true, claimed = false, final = 0, failed = 0, combined = 0;
  const checkpoints: string[] = [];
  const ledger = {
    claim() { if (claimed) return undefined; claimed = true; return job; },
    checkpointActive(supplied: Job) { assert.equal(supplied, job); return active; },
    checkpointArchive(supplied: Job, check: string, report: ReturnType<typeof publicReport>) {
      assert.equal(supplied, job); assert.equal(supplied.leaseToken, 'original-lease-token');
      validateArchiveReport(report, [check]); checkpoints.push(check); return active;
    },
    finishArchive(scanId: string, attempts: number, report: ReturnType<typeof publicReport>, _config: unknown, token: string) {
      assert.equal(scanId, job.scanId); assert.equal(attempts, job.attempts); assert.equal(token, job.leaseToken);
      validateArchiveReport(report, JSON.parse(job.checks)); final++; return active;
    },
    finish(scanId: string, attempts: number, state: string, _result: unknown, token: string) {
      assert.equal(scanId, job.scanId); assert.equal(attempts, job.attempts); assert.equal(state, 'failed');
      assert.equal(token, job.leaseToken); failed++; return true;
    },
    checkpointCombined() { return active; },
    finishCombined() { combined++; return true; },
  };
  return { job, ledger: ledger as unknown as ScanLedger, protocol: ledger,
    cancel() { active = false; }, state: () => ({ final, failed, combined, checkpoints }) };
}
const options = { timeoutMs: 1000, dbDir: '/unused' };
const noLegacy = async (): Promise<never> => { throw new TypeError('Legacy scanner must not run'); };
const consume = (f: ReturnType<typeof fixture>, publicImagePolicy: boolean, runner: typeof scanPublicImageArchive) =>
  consumeOne(f.ledger, { ...options, publicImagePolicy }, noLegacy, Date.now(), undefined, undefined, undefined, runner);

test('only explicit public consumer composition reaches generic archives, preserving original job/token', async () => {
  const f = fixture(); let calls = 0;
  await consume(f, true, async (checks, opts) => {
    calls++; assert.deepEqual(checks, ['secret']); assert.deepEqual(opts.target,
      { registry: f.job.registry, repository: f.job.repository, digest: f.job.digest, platform: f.job.platform });
    const report = publicReport(); assert.equal(opts.onCheckpoint?.('secret', report), true); return report;
  });
  assert.equal(calls, 1); assert.deepEqual(f.state(), { final: 1, failed: 0, combined: 0, checkpoints: ['secret'] });
  const legacy = fixture(); let legacyCalls = 0;
  await consumeOne(legacy.ledger, options, async () => { legacyCalls++; return { ok: false, failure: scannerFailure(null) }; },
    Date.now(), undefined, undefined, undefined, async () => { assert.fail('Default must not invoke public archives'); });
  assert.equal(legacyCalls, 1); assert.equal(legacy.state().final, 0);
});

test('public composition never treats arbitrary executionProfile as authority or redirects Alpine', async () => {
  for (const change of [
    { executionProfile: { version: 'public-hub-amd64-v1' } as unknown as Job['executionProfile'] },
    { registry: 'evil.example' }, { platform: 'linux/arm64' }, { checks: '["vuln","secret"]' },
  ]) {
    const f = fixture(change);
    await consume(f, true, async () => { assert.fail('Invalid generic job reached public scanner'); });
    assert.equal(f.state().failed, 1);
  }
  const alpine = fixture({ repository: 'library/alpine' }); let pinned = 0;
  await consumeOne(alpine.ledger, { ...options, publicImagePolicy: true }, async () => {
    pinned++; return { ok: false, failure: scannerFailure(null) };
  }, Date.now(), undefined, undefined, undefined, async () => { assert.fail('Alpine must stay legacy'); });
  assert.equal(pinned, 1);
});

test('explicit exact-nginx proof composition remains selected over public composition', async () => {
  const f = fixture(NGINX_SUPPORTED_CANDIDATE); let exact = 0;
  await consumeOne(f.ledger, { ...options, archivePolicy: 'proof', publicImagePolicy: true }, noLegacy, Date.now(), undefined, undefined,
    async (_checks, opts) => { exact++; assert.deepEqual(opts.target, NGINX_SUPPORTED_CANDIDATE); throw Error('synthetic acquisition failure'); },
    async () => { assert.fail('Exact legacy composition must remain legacy'); });
  assert.equal(exact, 1); assert.equal(f.state().combined, 1);
});

test('public consumer preserves checkpoint storage exceptions even when abort wins or runner swallows', async () => {
  for (const swallow of [false, true]) {
    const f = fixture(); const original = new Error('original storage error');
    f.protocol.checkpointArchive = () => { throw original; };
    await assert.rejects(consume(f, true, async (_checks, opts) => {
      if (swallow) { try { opts.onCheckpoint?.('secret', publicReport()); } catch { /* hostile test seam */ } }
      else opts.onCheckpoint?.('secret', publicReport());
      return publicReport();
    }), error => error === original);
    assert.equal(f.state().final, 0); assert.equal(f.state().combined, 0);
  }
});

test('public cleanup failure after checkpoint never overwrites completed siblings with fallback failures', async () => {
  const f = fixture(); const original = new Error('cleanup failure');
  await assert.rejects(consume(f, true, async (_checks, opts) => {
    opts.onCheckpoint?.('secret', publicReport()); throw original;
  }), error => error === original);
  assert.deepEqual(f.state(), { final: 0, failed: 0, combined: 0, checkpoints: ['secret'] });
});

test('public cancellation keeps checkpoint but never publishes uncooperative late output', { timeout: 3000 }, async () => {
  const f = fixture(); let ready!: () => void, release!: () => void;
  const started = new Promise<void>(resolve => { ready = resolve; });
  const late = new Promise<void>(resolve => { release = resolve; });
  let runnerWork: Promise<ReturnType<typeof publicReport>> | undefined;
  const consuming = consume(f, true, (_checks, opts) => {
    runnerWork = (async () => { opts.onCheckpoint?.('secret', publicReport()); ready(); await late; return publicReport(); })();
    return runnerWork;
  });
  await started; f.cancel(); assert.equal(await consuming, true);
  assert.deepEqual(f.state(), { final: 0, failed: 0, combined: 0, checkpoints: ['secret'] });
  release(); await runnerWork;
  assert.equal(f.state().final, 0);
});
