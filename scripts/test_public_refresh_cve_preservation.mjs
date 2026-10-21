import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { ROOT, fixture } from './public-refresh-cve-fixtures.mjs';
import { createPublicPreservationCapture } from './public-refresh-cve-preservation.mjs';
const Database = createRequire(join(ROOT, 'server/api/package.json'))('better-sqlite3');
function snapshots(t) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'public-cve-preserve-')));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const paths = { auth: join(root, 'auth.sqlite'), ledger: join(root, 'ledger.sqlite') };
  for (const [name, path] of Object.entries(paths)) {
    const db = new Database(path);
    db.exec(
      name === 'ledger'
        ? "CREATE TABLE reports(id INTEGER, body TEXT); INSERT INTO reports VALUES(1,'synthetic report'); PRAGMA user_version=15;"
        : "CREATE TABLE accounts(id TEXT, password_hash TEXT); INSERT INTO accounts VALUES('synthetic','not-real-credentials');",
    );
    db.close();
  }
  const context = { root, endpoint: 'unix:///fixture/socket', lock: { verify() {} } };
  let closes = 0;
  const capture = createPublicPreservationCapture({
    snapshot: async () => {
      const auth = new Database(paths.auth, { readonly: true, fileMustExist: true }),
        ledger = new Database(paths.ledger, { readonly: true, fileMustExist: true });
      return {
        auth,
        ledger,
        close() {
          auth.close();
          ledger.close();
          closes++;
        },
      };
    },
  });
  const change = (role, sql) => {
    const db = new Database(paths[role]);
    db.exec(sql);
    db.close();
  };
  return { capture, context, change, paths, closes: () => closes };
}

test('real sealed readonly auth+ledger snapshots compare at both acceptance fences, with no schema or data writes', async (t) => {
  const f = snapshots(t),
    before = Object.values(f.paths).map((p) => fs.readFileSync(p));
  const guard = await f.capture(f.context);
  await guard.verify({ ...f.context, phase: 'before-api' });
  await guard.verify({ ...f.context, phase: 'after-api' });
  assert.deepEqual(
    Object.values(f.paths).map((p) => fs.readFileSync(p)),
    before,
  );
  assert.equal(f.closes(), 3);
  assert.deepEqual(Object.keys(guard), ['verify']);
});
for (const [role, sql] of [
  ['auth', "UPDATE accounts SET password_hash='changed'"],
  ['ledger', "UPDATE reports SET body='changed'"],
  ['ledger', 'ALTER TABLE reports ADD COLUMN drift TEXT'],
  ['ledger', 'PRAGMA user_version=14'],
  ['ledger', "INSERT INTO reports VALUES(1,'synthetic report')"],
]) {
  test(`preservation rejects ${role} ${sql.split(' ')[0]} and closes snapshots without leaking data`, async (t) => {
    const f = snapshots(t),
      guard = await f.capture(f.context);
    f.change(role, sql);
    await assert.rejects(guard.verify({ ...f.context, phase: 'before-api' }), (error) => {
      assert.equal(error.message, 'PUBLIC CVE preservation refused; details withheld.');
      assert.equal(error.cause, undefined);
      return true;
    });
    assert.equal(f.closes(), 2);
  });
}

test('typed value change and integer precision are not silently normalized', async (t) => {
  const f = snapshots(t);
  f.change('ledger', 'CREATE TABLE typed(v);INSERT INTO typed VALUES(9007199254740993);');
  const guard = await f.capture(f.context);
  f.change('ledger', "UPDATE typed SET v='9007199254740993'");
  await assert.rejects(guard.verify({ ...f.context, phase: 'before-api' }));
});
test('capture refuses writable live DB handles and never queries/migrates them', async () => {
  let closed = false;
  const capture = createPublicPreservationCapture({
    snapshot: async () => ({
      auth: { readonly: false },
      close() {
        closed = true;
      },
    }),
  });
  await assert.rejects(capture({ lock: { verify() {} } }));
  assert.equal(closed, true);
});
test('out-of-order/foreign endpoint preservation comparison refuses before a new snapshot', async (t) => {
  const f = snapshots(t),
    guard = await f.capture(f.context);
  await assert.rejects(guard.verify({ ...f.context, phase: 'after-api' }));
  await assert.rejects(guard.verify({ ...f.context, endpoint: 'unix:///other/socket', phase: 'before-api' }));
  assert.equal(f.closes(), 1);
});
test('concrete data comparator integrates into offline public workflow, not a truthy success callback', async (t) => {
  const f = fixture(t),
    data = snapshots(t);
  f.integration.capturePreservation = createPublicPreservationCapture({
    snapshot: async () => {
      const auth = new Database(data.paths.auth, { readonly: true }),
        ledger = new Database(data.paths.ledger, { readonly: true });
      return {
        auth,
        ledger,
        close() {
          auth.close();
          ledger.close();
        },
      };
    },
  });
  assert.equal((await f.refresh()).outcome, 'activated');
});
