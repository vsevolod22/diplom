import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import Database from 'better-sqlite3';
import { ScanLedger, type Job } from '../ledger/ledger.js';
import { consumeOne } from './outbox-consumer.js';
import { scanPublicImageArchive, type ArchiveScanReport } from './archive-scan-worker.js';
import { publicBom, publicLifecycle, publicRaw, publicTarget } from './public-image-test-fixtures.js';

const rawMatch = 'R1_RAW_MATCH_CANARY';
const interruption = /Archive interrupted after accepted checkpoint/;
const positiveSecrets = () => ({ ...publicRaw(), Results: [{ Target: '/R1_PRIVATE_PATH_CANARY', Secrets: [{
  RuleID: 'synthetic-rule', StartLine: 7, Match: rawMatch, Code: { Lines: [{ Content: 'R1_CODE_CANARY' }] },
}] }] });
const assertSanitized = (value: unknown) => {
  const json = JSON.stringify(value);
  for (const raw of [rawMatch, 'R1_PRIVATE_PATH_CANARY', 'R1_CODE_CANARY', '"Match"']) assert.equal(json.includes(raw), false);
};

// Real disposable SQLite and consumer/checkpoint publication. Only acquisition,
// scanner responses, and the selected audit/deadline fault are fixture dependencies.
for (const fault of ['sbom-audit', 'final-audit', 'deadline'] as const) {
  test(`R1 positive Secrets checkpoint survives ${fault} through real ledger, consumer and public lifecycle`, { timeout: 5000 }, async () => {
    const storage = await mkdtemp(`${tmpdir()}/public-checkpoint-ledger-`);
    const path = `${storage}/ledger.sqlite`;
    const ledger = new ScanLedger(path);
    const deadline = new AbortController();
    const invoked: string[] = [], accepted: string[] = [];
    let stage = '', sbomAccepted = false, finalCalls = 0;
    let claimed: Job | undefined;
    let attemptDirectory: string | undefined;
    try {
      // A third check verifies that neither later invocations nor future unaudited
      // outputs can escape the failed SBOM stage. Final-audit is after both checks.
      const checks = fault === 'final-audit' ? ['secret', 'sbom'] : ['secret', 'sbom', 'vuln'];
      const id = ledger.enqueue({ ...publicTarget, subject: 'alice', idempotencyKey: `r1-${fault}`,
        scope: 'image', checks: JSON.stringify(checks) }).scanId;
      const claim = ledger.claim.bind(ledger);
      ledger.claim = (...args) => { claimed = claim(...args); return claimed; };
      const checkpoint = ledger.checkpointArchive.bind(ledger);
      ledger.checkpointArchive = (job, check, report) => {
        assert.equal(job, claimed); assert.equal(job.leaseToken, claimed?.leaseToken);
        const result = checkpoint(job, check, report);
        if (result) {
          accepted.push(check); assertSanitized(report);
          if (check === 'secret') {
            assert.equal(report.secret?.outcome, 'checked');
            if (report.secret?.outcome !== 'checked') assert.fail('Positive Secrets must be checked');
            assert.equal(report.secret.findings.length, 1);
          }
          if (check === 'sbom') sbomAccepted = true;
        }
        return result;
      };
      const finish = ledger.finishArchive.bind(ledger);
      ledger.finishArchive = (...args) => { finalCalls++; return finish(...args); };
      const fixture = await publicLifecycle(async (check, _binding, _directory, signal) => {
        invoked.push(check); stage = check;
        if (check === 'secret') return positiveSecrets();
        assert.equal(check, 'sbom', 'No future scanner may run after an interrupted check');
        if (fault === 'deadline') {
          // Start the shortened internal deadline only after the positive durable
          // checkpoint. The production 600s deadline remains independently active.
          const timeout = AbortSignal.timeout(10);
          timeout.addEventListener('abort', () => deadline.abort(timeout.reason), { once: true });
          await new Promise<void>(resolve => {
            if (signal.aborted) resolve();
            else signal.addEventListener('abort', () => resolve(), { once: true });
          });
          // Even an uncooperative scanner returning valid-looking bytes after its
          // deadline must not grant a checked SBOM or an additional checkpoint.
        }
        return publicBom();
      });
      attemptDirectory = fixture.directory;
      if (fault === 'deadline') fixture.lifecycle.deadlineSignal = deadline.signal;
      const audit = fixture.lifecycle.audit;
      fixture.lifecycle.audit = async (...args) => {
        if (fault === 'sbom-audit' && stage === 'sbom' || fault === 'final-audit' && sbomAccepted)
          throw new Error('synthetic scratch audit failure');
        return audit(...args);
      };
      let returned: ArchiveScanReport | undefined;
      await assert.rejects(consumeOne(ledger, { timeoutMs: 1000, dbDir: '/unused', publicImagePolicy: true },
        undefined, Date.now(), undefined, undefined, undefined, async (selected, options) => {
          returned = await scanPublicImageArchive(selected, options, fixture.lifecycle);
          return returned;
        }), interruption);
      assert.equal(returned, undefined, 'No contradictory or unaudited final report may return normally');
      assert.equal(finalCalls, 0, 'Consumer must not attempt final delivery after an accepted checkpoint interruption');
      assert.deepEqual(invoked, ['secret', 'sbom']);
      assert.deepEqual(accepted, fault === 'final-audit' ? ['secret', 'sbom'] : ['secret']);
      assert.ok(claimed?.leaseToken); assert.equal(ledger.checkpointActive(claimed!), true);
      assert.equal(ledger.state(id, 'alice'), 'running');
      assert.equal(ledger.archiveResult(id, 'alice'), undefined);
      await assert.rejects(access(fixture.directory));

      const sql = new Database(path);
      try {
        const rows = sql.prepare('SELECT body FROM scan_checkpoints WHERE scan_id=?').all(id) as Array<{ body: string }>;
        assert.equal(rows.length, accepted.length); assertSanitized(rows);
        const secret = rows.map(row => JSON.parse(row.body) as ArchiveScanReport).find(report => report.secret)?.secret;
        assert.equal(secret?.outcome, 'checked');
        if (secret?.outcome !== 'checked') assert.fail('Positive checkpoint must remain durable');
        assert.equal(secret.findings.length, 1);
        assert.equal((sql.prepare('SELECT count(*) AS n FROM scan_archive_results WHERE scan_id=?').get(id) as { n: number }).n, 0);
      } finally { sql.close(); }

      const reopened = new ScanLedger(path);
      try {
        assert.equal(reopened.state(id, 'alice'), 'running');
        assert.equal(reopened.cancel(id, 'bob'), 'not_found');
        assert.equal(reopened.cancel(id, 'alice'), 'cancelled');
        const saved = reopened.archiveResult(id, 'alice')!;
        assert.equal(saved.secret?.outcome, 'checked');
        if (saved.secret?.outcome !== 'checked') assert.fail('Accepted Secrets must remain owner-visible after recovery');
        assert.equal(saved.secret.findings.length, 1);
        assert.equal(saved.sbom?.outcome, fault === 'final-audit' ? 'checked' : undefined);
        assert.equal(saved.vuln, undefined, 'No unaudited future check may be published');
        assertSanitized(saved);
        assert.equal(reopened.archiveResult(id, 'bob'), undefined);
        assert.deepEqual(ledger.archiveResult(id, 'alice'), saved);
        assert.equal(ledger.checkpointActive(claimed!), false);
        assert.deepEqual(reopened.events(id, 'alice', null)?.map(event => event.state), ['queued', 'running', 'cancelled']);
      } finally { reopened.close(); }
    } finally {
      ledger.close();
      if (attemptDirectory) await rm(attemptDirectory, { recursive: true, force: true });
      await rm(storage, { recursive: true, force: true });
    }
  });
}
