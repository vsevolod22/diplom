import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, realpathSync, chmodSync, rmSync, existsSync, statSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { runtimeCallerInit } from './runtime-caller-init.js';
import { CallerJournal } from './runtime-caller-journal.js';
import { createQualifiedRuntimePort } from './runtime-live-bootstrap.js';
import { dispatchPermit } from '../../../runtime/src/dispatch-permit.js';
import type { LiveIntent, Qualification } from '../../../runtime/src/live-port.js';

test(
  'explicit caller init creates only a separate journal; whole-intent one-use permit survives reopen',
  { timeout: 10000 },
  () => {
    const dir = mkdtempSync(join(realpathSync(tmpdir()), 'runtime-caller-continuation-'));
    chmodSync(dir, 0o700);
    const path = join(dir, 'caller.sqlite');
    const forbidden = ['runtime.sqlite', 'auth.sqlite', 'images.sqlite'].map((p) => join(dir, p));
    const args = ['init', path, '--authorize-runtime-caller-journal', ...forbidden];
    const key = randomBytes(32).toString('hex');
    const intent: LiveIntent = {
      subject: 'synthetic-owner',
      brokerSubject: 'broker-owner',
      target: {
        targetId: 'a'.repeat(32),
        containerId: 'b'.repeat(64),
        context: 'isolated-linux',
        contextVersion: 1,
        version: 1,
        importAllowed: true,
        liveAllowed: true,
      },
      consentId: 'c'.repeat(32),
      nonce: 'd'.repeat(64),
      epoch: 1,
      captureId: 'e'.repeat(32),
      attempt: 1,
      expiresAt: Date.now() + 60000,
    };
    let journal: CallerJournal | undefined;
    try {
      assert.throws(() => runtimeCallerInit(args.slice(0, 3)), /AUTHORIZATION_REQUIRED/);
      assert.throws(() => runtimeCallerInit(['init', path, 'yes', ...forbidden]), /AUTHORIZATION_REQUIRED/);
      assert.throws(
        () => runtimeCallerInit(['init', forbidden[0], args[2], ...forbidden]),
        /RUNTIME_UNAVAILABLE/,
      );
      assert.equal(existsSync(path), false);
      // Exercise the actual executable entrypoint with only public arguments, not a real key or config.
      const result = spawnSync(
        process.execPath,
        ['--import', 'tsx', 'src/runtime/runtime-caller-init.ts', ...args],
        { encoding: 'utf8', timeout: 5000, maxBuffer: 4096 },
      );
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, 'runtime_caller_journal_initialized\n');
      assert.equal(statSync(path).mode & 0o777, 0o600);
      assert.ok(forbidden.every((p) => !existsSync(p)));
      const before = readFileSync(path);
      assert.throws(() => runtimeCallerInit(args));
      assert.deepEqual(readFileSync(path), before);
      journal = new CallerJournal(path, key, forbidden);
      assert.throws(() => new CallerJournal(path, key, forbidden));
      const permit = dispatchPermit(intent, key);
      assert.throws(() => journal!.consume({ ...intent, subject: 'other-owner' }, permit), /NOT_AUTHORIZED/);
      assert.equal(journal.state(intent), undefined);
      journal.consume(intent, permit);
      journal.dispatched(intent);
      journal.close();
      journal = undefined;
      journal = new CallerJournal(path, key, forbidden);
      assert.equal(journal.state(intent), 'indeterminate');
      assert.throws(() => journal!.consume(intent, permit), /NOT_AUTHORIZED/);
      const changed = { ...intent, captureId: 'f'.repeat(32), attempt: 2 };
      assert.throws(() => journal!.consume(changed, dispatchPermit(changed, key)), /NOT_AUTHORIZED/);
      const next = { ...changed, consentId: '1'.repeat(32), nonce: '2'.repeat(64) };
      journal.invalidate({ subject: next.subject, consentId: next.consentId, epoch: next.epoch });
      journal.close();
      journal = undefined;
      journal = new CallerJournal(path, key, forbidden);
      assert.throws(() => journal!.consume(next, dispatchPermit(next, key)), /NOT_AUTHORIZED/);
      // A CLI failure never prints the supplied path or underlying SQLite/OS error.
      const denied = spawnSync(
        process.execPath,
        ['--import', 'tsx', 'src/runtime/runtime-caller-init.ts', ...args],
        { encoding: 'utf8', timeout: 5000, maxBuffer: 4096 },
      );
      assert.equal(denied.status, 1);
      assert.equal(denied.stdout, '');
      assert.equal(denied.stderr, 'runtime_caller_journal_initialization_failed\n');
    } finally {
      journal?.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test('API live bootstrap refuses unreviewed or expired qualification before touching any socket', () => {
  // Deliberately unaccepted synthetic record. No platform spoofing or permissive review callback.
  const qualification: Qualification = {
    schema: 'runtime-qualification-v1',
    fixtureAccepted: true,
    applicationAccepted: true,
    protocolAccepted: true,
    platform: 'linux',
    context: 'isolated-linux',
    contextVersion: 1,
    sourceHash: 'a'.repeat(64),
    topologyHash: 'b'.repeat(64),
    epoch: 1,
    expiresAt: Date.now() + 60000,
  };
  const input = {
    qualification,
    independentReview: () => false,
    applicationSocket: '/not-provisioned-runtime-continuation/application.sock',
    applicationCredential: 'c'.repeat(64),
    dispatchKey: 'd'.repeat(64),
  };
  assert.throws(() => createQualifiedRuntimePort(input), /^Error: QUALIFICATION_MISSING$/);
  assert.throws(
    () => createQualifiedRuntimePort({ ...input, qualification: { ...qualification, expiresAt: 0 } }),
    /^Error: QUALIFICATION_MISSING$/,
  );
});
