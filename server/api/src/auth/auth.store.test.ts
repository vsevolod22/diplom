import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import Database from 'better-sqlite3';
import { AuthStore } from './auth.store.js';

test('rate limits by email and socket IP; stores only hashes and bounds live sessions', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'auth-store-'));
  const path = join(dir, 'auth.sqlite');
  const previous = process.env.AUTH_DB_PATH;
  process.env.AUTH_DB_PATH = path;
  const store = new AuthStore();
  try {
    for (let n = 0; n < 5; n++) assert.equal(store.rateLimit('login', 'a@example.com', `ip${n}`), true);
    assert.equal(store.rateLimit('login', 'a@example.com', 'other'), false);
    for (let n = 0; n < 20; n++) assert.equal(store.rateLimit('register', `user${n}@example.com`, 'same-ip'), true);
    assert.equal(store.rateLimit('register', 'another@example.com', 'same-ip'), false);
    const registration = store.register('a@example.com', 'long-secret-1234');
    assert.equal(await Promise.race([registration.then(() => 'hash'), new Promise<string>(resolve => setTimeout(() => resolve('timer'), 0))]), 'timer',
      'password hashing must not block the event loop');
    const user = await registration;
    assert.ok(user);
    assert.equal(await store.login('a@example.com', 'wrong-secret-1'), null);
    assert.equal(await store.login('unknown@example.com', 'long-secret-1234'), null);
    assert.deepEqual(await store.login('a@example.com', 'long-secret-1234'), user);
    const login = store.login('a@example.com', 'long-secret-1234');
    assert.equal(await Promise.race([login.then(() => 'hash'), new Promise<string>(resolve => setTimeout(() => resolve('timer'), 0))]), 'timer',
      'password verification must not block the event loop');
    assert.deepEqual(await login, user);
    const tokens = Array.from({ length: 6 }, () => store.createSession(user.id));
    assert.equal(store.userForToken(tokens[0]), null);
    assert.equal(store.userForToken(tokens[5])?.id, user.id);
    store.revoke(tokens[5]);
    assert.equal(store.userForToken(tokens[5]), null);
    const db = new Database(path, { readonly: true });
    try {
      assert.equal((db.prepare('SELECT token_hash FROM sessions WHERE user_id = ? ORDER BY rowid DESC LIMIT 1').get(user.id) as { token_hash: string }).token_hash.length, 64);
      assert.equal((db.prepare('SELECT count(*) AS n FROM sessions WHERE user_id = ?').get(user.id) as { n: number }).n, 5);
      assert.equal((db.prepare('SELECT password_hash FROM users WHERE id = ?').get(user.id) as { password_hash: Buffer }).password_hash.length, 64);
    } finally { db.close(); }
    const other = await store.register('b@example.com', 'another-long-secret');
    assert.ok(other);
    const otherToken = store.createSession(other.id);
    assert.equal(store.userForToken(otherToken)?.id, other.id);
    assert.equal(store.userForToken(tokens[4])?.id, user.id);
    const writable = new Database(path);
    try {
      writable.prepare('UPDATE sessions SET expires_at = ? WHERE token_hash = ?')
        .run(Date.now() - 1, createHash('sha256').update(otherToken).digest('hex'));
    } finally { writable.close(); }
    assert.equal(store.userForToken(otherToken), null, 'expired session must not authenticate');
    assert.equal(store.userForToken(tokens[4])?.id, user.id, 'expiry of another user must not affect this user');
  } finally {
    store.onModuleDestroy();
    if (previous === undefined) delete process.env.AUTH_DB_PATH; else process.env.AUTH_DB_PATH = previous;
    rmSync(dir, { recursive: true, force: true });
  }
});
