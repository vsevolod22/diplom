import assert from 'node:assert/strict';
import test from 'node:test';
import type Database from 'better-sqlite3';
import { ScanLedger, type Job, type CombinedOutcome } from './ledger.js';
import { NGINX_ARCHIVE_TARGET } from '../oci/bounded-image-archive.js';
import type { ArchiveScanReport } from '../worker/archive-scan-worker.js';
import { consumeOne } from '../worker/outbox-consumer.js';

const target = { subject: 'review', idempotencyKey: 'review', registry: 'registry-1.docker.io', repository: 'library/alpine',
  digest: `sha256:${'a'.repeat(64)}` as const, platform: 'linux/amd64' };
const secret: CombinedOutcome = { check: 'secret', outcome: 'checked', findings: [], scannerVersion: '0.69.3' };
const image = (job: Pick<Job, 'registry' | 'repository' | 'digest'>) => `${job.registry}/${job.repository}@${job.digest}`;
const sbom = (job: Pick<Job, 'registry' | 'repository' | 'digest'>) => ({ image: image(job), platform: 'linux/amd64' as const,
  os: { name: 'alpine' as const, version: '3.20.6' }, components: [{ ecosystem: 'apk' as const, name: 'busybox', version: '1.0' }] });
function envelope(at: number): Omit<ArchiveScanReport, 'secret' | 'sbom' | 'vuln'> {
  return { receipt: { ...NGINX_ARCHIVE_TARGET, layerDigests: [`sha256:${'a'.repeat(64)}`], diffIds: [`sha256:${'b'.repeat(64)}`],
    archiveSha256: `sha256:${'c'.repeat(64)}`, profileVersion: 'nginx-alpine-amd64-v1',
    resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' }, scannerVersion: '0.69.3', checkedAt: at,
    metrics: { wireBytes: 100, requests: 5, compressedBytes: 50, expandedBytes: 2048, entries: 1, archiveBytes: 4096,
      reservationPeak: 4096, scratchPeak: 4096 } };
}
const raw = (ledger: ScanLedger) => (ledger as unknown as { db: Database.Database }).db;
const methods = ['finish', 'finishWithResult', 'finishWithSbom', 'finishWithVuln', 'finishCombined', 'finishArchive', 'retry'] as const;
type Method = typeof methods[number];
// Explicit token is passed to the tested API, including wrong/undefined tokens.
// Reflect.apply also reproduces the pre-fix API's ignoring of this extra argument.
function invoke(ledger: ScanLedger, method: Method, job: Job, token: string | undefined, at: number): boolean {
  const args: Record<Method, unknown[]> = {
    finish: [job.scanId, job.attempts, 'failed', 'SCAN_FAILED'],
    finishWithResult: [job.scanId, job.attempts, [], '0.69.3'],
    finishWithSbom: [job.scanId, job.attempts, sbom(job), '0.69.3'],
    finishWithVuln: [job.scanId, job.attempts, image(job), [], '0.69.3'],
    finishCombined: [job.scanId, job.attempts, [secret], undefined],
    finishArchive: [job.scanId, job.attempts, { ...envelope(at), secret: { outcome: 'checked', findings: [] } }, undefined],
    retry: [job.scanId, job.attempts, at + 1000],
  };
  return Reflect.apply(ledger[method], ledger, [...args[method], token]);
}
for (const method of methods) for (const mode of ['valid', 'wrong', 'missing', 'expired', 'retry', 'null-token', 'replacement', 'cancelled'] as const) {
  test(`R1/R3 ${method}: ${mode} authority`, () => {
    let now = Date.now(); const ledger = new ScanLedger(':memory:', () => now);
    try {
      const check = method === 'finishWithVuln' ? 'vuln' : method === 'finishWithSbom' ? 'sbom' : 'secret';
      const id = ledger.enqueue({ ...target, ...(method === 'finishArchive' ? { ...NGINX_ARCHIVE_TARGET, digest: NGINX_ARCHIVE_TARGET.digest as `sha256:${string}` } : {}), checks: JSON.stringify([check]) }).scanId;
      const job = ledger.claim(now, 100)!;
      if (mode === 'expired' || mode === 'replacement') now += 100;
      if (mode === 'replacement') ledger.claim(now, 100);
      if (mode === 'retry') assert.equal(invoke(ledger, 'retry', job, job.leaseToken, now), true);
      if (mode === 'cancelled') ledger.cancel(id, 'review');
      if (mode === 'null-token') raw(ledger).prepare('UPDATE outbox SET lease_token=NULL WHERE scan_id=?').run(id);
      const before = raw(ledger).prepare('SELECT * FROM outbox').all();
      const events = ledger.events(id, 'review', null);
      const token = mode === 'wrong' ? 'wrong-token' : mode === 'missing' ? undefined : job.leaseToken;
      assert.equal(invoke(ledger, method, job, token, now), mode === 'valid');
      if (mode !== 'valid') {
        assert.deepEqual(raw(ledger).prepare('SELECT * FROM outbox').all(), before);
        assert.deepEqual(ledger.events(id, 'review', null), events);
        for (const table of ['scan_results', 'scan_findings', 'scan_sbom_results', 'scan_sbom_components', 'scan_vuln_results', 'scan_vuln_findings', 'scan_archive_results'])
          assert.deepEqual(raw(ledger).prepare(`SELECT * FROM ${table}`).all(), []);
      }
    } finally { ledger.close(); }
  });
}

const malformed: Array<[string, 'secret' | 'sbom', (at: number) => unknown]> = [
  ['secret shadowed version', 'secret', at => ({ ...envelope(at), secret: { outcome: 'checked', findings: [], scannerVersion: { Match: 'RAW_CANARY', Code: 'CODE_CANARY' } } })],
  ['SBOM shadowed version', 'sbom', at => ({ ...envelope(at), sbom: { outcome: 'checked', sbom: sbom(NGINX_ARCHIVE_TARGET), scannerVersion: { Match: 'RAW_CANARY' } } })],
  ['secret discriminator override', 'secret', at => ({ ...envelope(at), secret: { outcome: 'checked', check: 'sbom', sbom: sbom(NGINX_ARCHIVE_TARGET) } })],
  ['SBOM discriminator override', 'sbom', at => ({ ...envelope(at), sbom: { outcome: 'checked', check: 'secret', findings: [] } })],
  ['nested secret finding', 'secret', at => ({ ...envelope(at), secret: { outcome: 'checked', findings: [{ findingId: 'secret-0-0', ruleId: 'rule', line: 1, evidenceRef: 'result-0-secret-0', Code: { Match: 'RAW_CANARY' } }] } })],
  ['nested SBOM component', 'sbom', at => { const value = sbom(NGINX_ARCHIVE_TARGET); return { ...envelope(at), sbom: { outcome: 'checked', sbom: { ...value, components: [{ ...value.components[0], raw: { Match: 'RAW_CANARY' } }] } } }; }],
];
malformed.push(['nested SBOM OS', 'sbom', at => {
  const value = sbom(NGINX_ARCHIVE_TARGET);
  return { ...envelope(at), sbom: { outcome: 'checked', sbom: { ...value, os: { ...value.os, Match: { raw: 'RAW_CANARY' } } } } };
}]);
for (const [name, check, build] of malformed) for (const path of ['checkpoint', 'finalize', 'stored-read'] as const) {
  test(`R2 ${name}: ${path}`, () => {
    const now = Date.now(), ledger = new ScanLedger(':memory:', () => now);
    try {
      const id = ledger.enqueue({ ...target, ...NGINX_ARCHIVE_TARGET, digest: NGINX_ARCHIVE_TARGET.digest as `sha256:${string}`, checks: JSON.stringify([check]) }).scanId;
      const job = ledger.claim(now)!, report = build(now) as ArchiveScanReport;
      if (path === 'checkpoint') assert.throws(() => ledger.checkpointArchive(job, check, report), TypeError);
      if (path === 'finalize') assert.throws(() => Reflect.apply(ledger.finishArchive, ledger, [id, job.attempts, report, undefined, job.leaseToken]), TypeError);
      if (path === 'stored-read') {
        raw(ledger).prepare('INSERT INTO scan_archive_results(scan_id,attempt,report) VALUES (?,?,?)').run(id, job.attempts, JSON.stringify(report));
        assert.equal(ledger.archiveResult(id, 'other'), undefined);
        assert.throws(() => ledger.archiveResult(id, 'review'), TypeError);
      } else {
        assert.deepEqual(raw(ledger).prepare('SELECT * FROM scan_checkpoints').all(), []);
        assert.deepEqual(raw(ledger).prepare('SELECT * FROM scan_archive_results').all(), []);
        assert.equal(ledger.state(id, 'review'), 'running'); assert.equal(ledger.checkpointActive(job), true);
      }
    } finally { ledger.close(); }
  });
}

for (const behavior of ['swallow-callback', 'replace-with-cleanup-error', 'cleanup-after-commit'] as const) {
  test(`R4 ${behavior}: abort race cannot hide storage error or discard committed evidence`, { timeout: 5000 }, async () => {
    const ledger = new ScanLedger(':memory:');
    try {
      const id = ledger.enqueue({ ...target, ...NGINX_ARCHIVE_TARGET, digest: NGINX_ARCHIVE_TARGET.digest as `sha256:${string}`, checks: '["secret","sbom"]' }).scanId;
      raw(ledger).exec("CREATE TRIGGER reject_sbom BEFORE INSERT ON scan_checkpoints WHEN NEW.check_name='sbom' BEGIN SELECT RAISE(ABORT,'storage error'); END");
      const cleanup = new Error('cleanup error');
      let storageError: unknown;
      const work = consumeOne(ledger, { timeoutMs: 1000, dbDir: '/unused', archivePolicy: 'proof' }, undefined, Date.now(), undefined, undefined,
        async (_checks, options) => {
          const base = envelope(Date.now());
          options.onCheckpoint!('secret', { ...base, secret: { outcome: 'checked', findings: [] } });
          if (behavior === 'cleanup-after-commit') throw cleanup;
          try { options.onCheckpoint!('sbom', { ...base, sbom: { outcome: 'failed', reason: 'SCAN_FAILED' } }); }
          catch (error) { storageError = error; }
          if (behavior === 'replace-with-cleanup-error') throw cleanup;
          return new Promise(() => {}); // Consumer must reject without waiting for an uncooperative adapter.
        });
      await assert.rejects(work, (error: unknown) => {
        assert.equal(error, behavior === 'cleanup-after-commit' ? cleanup : storageError);
        return true;
      });
      assert.equal(ledger.state(id, 'review'), 'running');
      assert.equal(ledger.cancel(id, 'review'), 'cancelled');
      assert.equal(ledger.archiveResult(id, 'review')?.secret?.outcome, 'checked');
      assert.equal(ledger.archiveResult(id, 'review')?.sbom, undefined);
    } finally { ledger.close(); }
  });
}

for (const phase of ['checkpoint', 'finalize'] as const) {
  test(`R4 archive ${phase} storage error propagates and leaves committed sibling cancellable`, { timeout: 5000 }, async () => {
    const ledger = new ScanLedger(':memory:');
    try {
      const id = ledger.enqueue({ ...target, ...NGINX_ARCHIVE_TARGET, digest: NGINX_ARCHIVE_TARGET.digest as `sha256:${string}`, checks: '["secret","sbom"]' }).scanId;
      raw(ledger).exec(phase === 'checkpoint'
        ? "CREATE TRIGGER reject_write BEFORE INSERT ON scan_checkpoints WHEN NEW.check_name='sbom' BEGIN SELECT RAISE(ABORT,'checkpoint storage failure'); END"
        : "CREATE TRIGGER reject_write BEFORE INSERT ON scan_archive_results BEGIN SELECT RAISE(ABORT,'finalization storage failure'); END");
      let thrown: unknown;
      const work = consumeOne(ledger, { timeoutMs: 1000, dbDir: '/unused', archivePolicy: 'proof' }, undefined, Date.now(), undefined, undefined,
        async (_checks, options) => {
          const base = envelope(Date.now());
          assert.equal(options.onCheckpoint!('secret', { ...base, secret: { outcome: 'checked', findings: [] } }), true);
          if (phase === 'checkpoint') {
            try { options.onCheckpoint!('sbom', { ...base, sbom: { outcome: 'failed', reason: 'SCAN_FAILED' } }); }
            catch (error) { thrown = error; throw error; }
          }
          return { ...base, secret: { outcome: 'checked', findings: [] }, sbom: { outcome: 'failed', reason: 'SCAN_FAILED' } };
        });
      await assert.rejects(work, (error: unknown) => {
        assert.equal((error as { code: string }).code, 'SQLITE_CONSTRAINT_TRIGGER');
        if (phase === 'checkpoint') assert.equal(error, thrown);
        return true;
      });
      assert.equal(ledger.state(id, 'review'), 'running');
      assert.equal(ledger.result(id, 'review'), undefined); assert.equal(ledger.archiveResult(id, 'review'), undefined);
      assert.deepEqual(ledger.events(id, 'review', null)?.map(e => e.state), ['queued', 'running']);
      assert.equal((raw(ledger).prepare('SELECT count(*) AS n FROM scan_checkpoints').get() as { n: number }).n, 1);
      raw(ledger).exec('DROP TRIGGER reject_write');
      assert.equal(ledger.cancel(id, 'review'), 'cancelled');
      assert.equal(ledger.archiveResult(id, 'review')?.secret?.outcome, 'checked');
      assert.equal(ledger.archiveResult(id, 'review')?.sbom, undefined);
    } finally { ledger.close(); }
  });
}
