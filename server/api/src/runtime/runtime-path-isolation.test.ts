import assert from 'node:assert/strict';
import { test, type TestContext } from 'node:test';
import { createHash } from 'node:crypto';
import {
  mkdtempSync,
  realpathSync,
  chmodSync,
  rmSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  readdirSync,
  lstatSync,
  readlinkSync,
  symlinkSync,
  linkSync,
  existsSync,
  copyFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { runtimeCallerInit } from './runtime-caller-init.js';
import { CallerJournal, initializeCallerJournal } from './runtime-caller-journal.js';
import { RuntimeStore, initializeRuntimeStore } from './runtime-store.js';

const suffixes = ['-journal', '-wal', '-shm', '.writer'] as const;
const key = 'a'.repeat(64); // synthetic journal key, never an operator credential
function fixture(t: TestContext) {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'runtime-path-review-'));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}
function snapshot(root: string): unknown[] {
  const entries: unknown[] = [];
  const walk = (path: string) => {
    const s = lstatSync(path);
    entries.push({
      path: path.slice(root.length),
      dev: s.dev,
      ino: s.ino,
      mode: s.mode,
      nlink: s.nlink,
      content: s.isSymbolicLink()
        ? readlinkSync(path)
        : s.isFile()
          ? createHash('sha256').update(readFileSync(path)).digest('hex')
          : null,
    });
    if (s.isDirectory()) for (const name of readdirSync(path).sort()) walk(join(path, name));
  };
  walk(root);
  return entries;
}
function rejectedUnchanged(root: string, action: () => void) {
  const before = snapshot(root);
  let error: unknown;
  try {
    action();
  } catch (caught) {
    error = caught;
  }
  // Check identity/bytes/link targets before the error assertion: even an error after SQLite damage fails.
  assert.deepEqual(
    snapshot(root),
    before,
    'rejection must not create, overwrite or delete any fixture member',
  );
  assert.ok(error instanceof Error, 'unsafe path must be rejected');
}
const cli = (path: string, excluded: string[]) =>
  runtimeCallerInit(['init', path, '--authorize-runtime-caller-journal', ...excluded]);
const excludedFor = (root: string, first: string) => [
  first,
  join(root, 'auth.sqlite'),
  join(root, 'images.sqlite'),
];
const canary = (path: string) => writeFileSync(path, 'synthetic protected bytes\n', { mode: 0o600 });
const stores = [
  {
    name: 'caller',
    init: initializeCallerJournal,
    open: (path: string, excluded: string[]) => new CallerJournal(path, key, excluded).close(),
  },
  {
    name: 'runtime',
    init: initializeRuntimeStore,
    open: (path: string, excluded: string[]) => new RuntimeStore(path, Date.now, excluded).close(),
  },
];

test('R1 exact reviewer reproduction: excluded real SQLite rollback-journal name is preserved', (t) => {
  const root = fixture(t),
    path = join(root, 'caller.sqlite'),
    protectedPath = `${path}-journal`;
  const db = new Database(protectedPath);
  db.exec("CREATE TABLE sentinel(value TEXT); INSERT INTO sentinel VALUES('synthetic-only');");
  db.close();
  chmodSync(protectedPath, 0o600);
  rejectedUnchanged(root, () => cli(path, excludedFor(root, protectedPath)));
});

for (const suffix of suffixes) {
  for (const reverse of [false, true]) {
    for (const present of [false, true]) {
      test(`R1 CLI ${suffix}, reverse=${reverse}, protected-present=${present}`, (t) => {
        const root = fixture(t),
          base = join(root, 'caller.sqlite');
        const path = reverse ? `${base}${suffix}` : base;
        const protectedPath = reverse ? base : `${base}${suffix}`;
        if (present) canary(protectedPath);
        rejectedUnchanged(root, () => cli(path, excludedFor(root, protectedPath)));
      });
    }
  }
  for (const store of stores) {
    test(`R1 ${store.name} init rejects unexpected existing ${suffix} even without exclusions`, (t) => {
      const root = fixture(t),
        path = join(root, 'own.sqlite');
      canary(`${path}${suffix}`);
      rejectedUnchanged(root, () => store.init(path));
    });
    for (const reverse of [false, true]) {
      test(`R1 direct ${store.name} init/open namespace collision ${suffix}, reverse=${reverse}`, (t) => {
        const root = fixture(t),
          base = join(root, 'own.sqlite');
        const path = reverse ? `${base}${suffix}` : base;
        const excluded = [reverse ? base : `${base}${suffix}`];
        rejectedUnchanged(root, () => store.init(path, excluded));
        store.init(path);
        rejectedUnchanged(root, () => store.open(path, excluded));
      });
    }
  }
}

for (const store of stores) {
  for (const suffix of suffixes) {
    test(`R1 ${store.name} open preserves existing excluded bytes at ${suffix}`, (t) => {
      const root = fixture(t),
        path = join(root, 'own.sqlite');
      store.init(path);
      const protectedPath = `${path}${suffix}`;
      canary(protectedPath);
      rejectedUnchanged(root, () => store.open(path, [protectedPath]));
    });
  }
  test(`${store.name} rejects collisions and inode aliases between protected families too`, (t) => {
    const root = fixture(t),
      path = join(root, 'own.sqlite'),
      protectedPath = join(root, 'protected.sqlite');
    rejectedUnchanged(root, () => store.init(path, [protectedPath, `${protectedPath}-wal`]));
    canary(protectedPath);
    const alias = join(root, 'other-protected.sqlite');
    linkSync(protectedPath, alias);
    rejectedUnchanged(root, () => store.init(path, [protectedPath, alias]));
  });
  test(`${store.name} reopens a genuine private WAL snapshot without relaxing family checks`, (t) => {
    const root = fixture(t),
      source = join(root, 'source.sqlite'),
      path = join(root, 'restored.sqlite');
    store.init(source);
    const db = new Database(source);
    try {
      db.pragma('journal_mode=WAL');
      db.pragma('wal_autocheckpoint=0');
      db.exec(
        store.name === 'runtime'
          ? 'UPDATE runtime_meta SET epoch=epoch+1'
          : "INSERT INTO revoked VALUES('synthetic-fence')",
      );
      // The source connection is quiescent. Copy its real SQLite files, not fabricated WAL headers.
      for (const suffix of ['', '-wal', '-shm']) copyFileSync(source + suffix, path + suffix);
    } finally {
      db.close();
    }
    store.open(path, [source, join(root, 'absent.sqlite')]);
    const reader = new Database(path, { readonly: true, fileMustExist: true });
    try {
      assert.equal(reader.pragma('integrity_check', { simple: true }), 'ok');
      const row = reader
        .prepare(
          store.name === 'runtime'
            ? 'SELECT epoch AS value FROM runtime_meta'
            : 'SELECT count(*) AS value FROM revoked',
        )
        .get() as { value: number };
      assert.equal(row.value, store.name === 'runtime' ? 2 : 1);
    } finally {
      reader.close();
    }
  });
  for (const kind of [
    'dangling-leaf',
    'symlink-parent',
    'existing-leaf',
    'missing-parent',
    'relative',
    'dotdot',
  ] as const) {
    for (const opening of [false, true]) {
      test(`R2 ${store.name} ${opening ? 'open' : 'init'} rejects exclusion ${kind}`, (t) => {
        const root = fixture(t),
          path = join(root, 'own.sqlite');
        if (opening) store.init(path);
        let excluded: string;
        if (kind === 'dangling-leaf') {
          excluded = join(root, 'alias.sqlite');
          symlinkSync(opening ? join(root, 'absent.sqlite') : path, excluded);
        } else if (kind === 'symlink-parent') {
          const alias = join(root, 'alias-dir');
          symlinkSync(root, alias);
          excluded = join(alias, 'own.sqlite');
        } else if (kind === 'existing-leaf') {
          const protectedPath = join(root, 'protected.sqlite');
          canary(protectedPath);
          excluded = join(root, 'alias.sqlite');
          symlinkSync(protectedPath, excluded);
        } else if (kind === 'missing-parent') {
          excluded = join(root, 'not-provisioned', 'protected.sqlite');
        } else if (kind === 'relative') {
          excluded = 'relative-protected.sqlite';
        } else {
          excluded = `${root}/unused/../protected.sqlite`;
        }
        rejectedUnchanged(root, () =>
          opening ? store.open(path, [excluded]) : store.init(path, [excluded]),
        );
      });
    }
  }
  for (const suffix of ['', ...suffixes]) {
    test(`R2 ${store.name} open preserves protected hardlink at own family member ${suffix || 'base'}`, (t) => {
      const root = fixture(t),
        path = join(root, 'own.sqlite'),
        protectedPath = join(root, 'protected.sqlite');
      store.init(path);
      if (!suffix) linkSync(path, protectedPath);
      else {
        canary(protectedPath);
        linkSync(protectedPath, `${path}${suffix}`);
      }
      rejectedUnchanged(root, () => store.open(path, [protectedPath]));
    });
    if (suffix) {
      test(`R2 ${store.name} open rejects dangling protected sidecar ${suffix}`, (t) => {
        const root = fixture(t),
          path = join(root, 'own.sqlite'),
          protectedPath = join(root, 'protected.sqlite');
        store.init(path);
        symlinkSync(`${path}${suffix}`, `${protectedPath}${suffix}`);
        rejectedUnchanged(root, () => store.open(path, [protectedPath]));
      });
    }
  }
  test(`${store.name}: distinct absent/existing exclusions and exact sibling names remain usable`, (t) => {
    const root = fixture(t),
      directory = join(root, 'protected');
    mkdirSync(directory, { mode: 0o700 });
    const path = join(root, 'own.sqlite');
    const excluded = [
      join(directory, 'existing.sqlite'),
      join(directory, 'absent.sqlite'),
      `${path}-wal.backup`,
    ];
    canary(excluded[0]);
    canary(excluded[2]);
    const before = excluded.filter(existsSync).map((p) => [p, readFileSync(p)] as const);
    store.init(path, excluded);
    store.open(path, excluded);
    store.open(path, excluded);
    for (const [p, bytes] of before) assert.deepEqual(readFileSync(p), bytes);
    assert.equal(existsSync(excluded[1]), false);
    assert.equal(existsSync(`${path}.writer`), false);
  });
}

for (const kind of ['dangling-leaf', 'symlink-parent'] as const) {
  test(`R2 CLI exact reviewer alias reproduction: ${kind}`, (t) => {
    const root = fixture(t),
      path = join(root, 'next.sqlite');
    let excluded: string;
    if (kind === 'dangling-leaf') {
      excluded = join(root, 'runtime-alias.sqlite');
      symlinkSync(path, excluded);
    } else {
      const alias = join(root, 'alias-dir');
      symlinkSync(root, alias);
      excluded = join(alias, 'next.sqlite');
    }
    rejectedUnchanged(root, () => cli(path, excludedFor(root, excluded)));
  });
}
