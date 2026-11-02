import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHash, scryptSync } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { HttpException } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import Database from 'better-sqlite3';
import { AuthStore, PASSWORD_RESET_TTL_MS, validPassword } from './auth.store.js';
import { AuthModule } from './auth.module.js';
import { AuthController, originForRequest } from './auth.controller.js';
import { PasswordResetService, type PasswordResetDelivery } from './password-reset.service.js';

const password = 'synthetic-password-1234', nextPassword = 'synthetic-next-password-5678';
const origin = 'https://auth.example';
const digest = (text: string) => createHash('sha256').update(text).digest('hex');
const code = (expected: string) => (error: unknown) => error instanceof HttpException &&
  (error.getResponse() as { errorCode: string }).errorCode === expected;
function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'auth-a3-'));
  const keys = ['AUTH_DB_PATH', 'AUTH_ORIGIN', 'AUTH_ALLOW_INSECURE_LOCAL_HTTP', 'SCAN_LEDGER_PATH'] as const;
  const previous = keys.map(key => process.env[key]);
  const path = join(dir, 'auth.sqlite');
  process.env.AUTH_DB_PATH = path; process.env.AUTH_ORIGIN = origin;
  delete process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP; delete process.env.SCAN_LEDGER_PATH;
  const stores: AuthStore[] = [];
  return { path, open() { const store = new AuthStore(); stores.push(store); return store; }, close() {
    stores.forEach(store => store.onModuleDestroy());
    keys.forEach((key, i) => { if (previous[i] === undefined) delete process.env[key]; else process.env[key] = previous[i]; });
    rmSync(dir, { recursive: true, force: true });
  } };
}

test('A3 additive actual legacy SQLite migration twice preserves credentials, sessions and unrelated owner history', async () => {
  const f = fixture(), db = new Database(f.path);
  const id = 'a'.repeat(32), token = 'b'.repeat(43), salt = 'c'.repeat(32);
  try {
    db.exec(`CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT NOT NULL UNIQUE,salt TEXT NOT NULL,password_hash BLOB NOT NULL);
      CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),expires_at INTEGER NOT NULL,revoked_at INTEGER);
      CREATE TABLE owner_history(owner TEXT PRIMARY KEY,content BLOB NOT NULL);`);
    db.prepare('INSERT INTO users VALUES(?,?,?,?)').run(id, 'legacy@example.com', salt, scryptSync(password, salt, 64));
    db.prepare('INSERT INTO sessions VALUES(?,?,?,NULL)').run(digest(token), id, Date.now() + 60000);
    db.prepare('INSERT INTO owner_history VALUES(?,?)').run(id, Buffer.from('unchanged synthetic history'));
    const before = ['users', 'sessions', 'owner_history'].map(table => db.prepare(`SELECT * FROM ${table}`).all());
    const first = f.open(); assert.equal(first.sessionForToken(token)?.subject, id);
    const trusted = db.prepare('SELECT * FROM trusted_sessions').all();
    const access = db.prepare('SELECT * FROM browser_access').all();
    first.onModuleDestroy(); const second = f.open();
    assert.deepEqual(await second.login('legacy@example.com', password), { id, email: 'legacy@example.com' });
    assert.equal(second.sessionForToken(token)?.subject, id);
    assert.deepEqual(['users', 'sessions', 'owner_history'].map(table => db.prepare(`SELECT * FROM ${table}`).all()), before);
    assert.deepEqual(db.prepare('SELECT * FROM trusted_sessions').all(), trusted);
    assert.deepEqual(db.prepare('SELECT * FROM browser_access').all(), access);
    assert.deepEqual(db.prepare('SELECT * FROM user_auth_state').all(), [{ user_id: id, generation: 1 }]);
    assert.deepEqual(db.prepare('SELECT * FROM password_resets').all(), []);
  } finally { db.close(); f.close(); }
});

for (const invalidator of ['change', 'revoke', 'reset'] as const) {
  test(`A3 ${invalidator} fences captured sessions and old/hash-in-flight login proofs across connections/reopen`, async () => {
    const f = fixture();
    try {
      const a = f.open(), b = f.open();
      const user = (await a.register('subject@example.com', password))!;
      const other = (await a.register('other@example.com', password))!;
      const tokens = [a.createSession(user.id), a.createSession(user.id)];
      const otherToken = a.createSession(other.id);
      const snapshots = tokens.map(token => a.sessionForToken(token)!);
      const proof = (await b.login(user.email, password))!;
      assert.equal(await a.changePassword(snapshots[0], 'wrong-password-1234', nextPassword), false);
      tokens.forEach(token => assert.ok(a.userForToken(token)));
      const reset = a.issuePasswordReset(user.email)!;
      const inFlight = b.login(user.email, password);
      if (invalidator === 'change') assert.equal(await a.changePassword(snapshots[0], password, nextPassword), true);
      else if (invalidator === 'revoke') assert.equal(await a.revokeAll(snapshots[0], password), true);
      else assert.equal(await a.confirmPasswordReset(reset.token, nextPassword), true);
      assert.throws(() => b.createAuthenticatedSession(proof), code('INVALID_CREDENTIALS'));
      const late = await inFlight;
      assert.ok(late, 'verification started before mutation may finish with a stale proof');
      assert.throws(() => b.createAuthenticatedSession(late), code('INVALID_CREDENTIALS'));
      for (const snapshot of snapshots) assert.throws(() => a.guardSession(snapshot, () => assert.fail('revoked callback executed')), code('AUTH_UNAVAILABLE'));
      tokens.forEach(token => assert.equal(b.userForToken(token), null));
      assert.equal(b.userForToken(otherToken)?.id, other.id);
      assert.equal(await b.confirmPasswordReset(reset.token, nextPassword), false);
      const reopened = f.open(); tokens.forEach(token => assert.equal(reopened.sessionForToken(token), null));
      assert.ok(await reopened.login(user.email, invalidator === 'revoke' ? password : nextPassword));
      const fresh = (await b.login(other.email, password))!;
      assert.throws(() => b.createAuthenticatedSession({ ...fresh }), code('INVALID_CREDENTIALS'));
      fresh.id = user.id;
      assert.throws(() => b.createAuthenticatedSession(fresh), code('INVALID_CREDENTIALS'));
      const once = (await b.login(other.email, password))!;
      b.createAuthenticatedSession(once);
      assert.throws(() => b.createAuthenticatedSession(once), code('INVALID_CREDENTIALS'));
    } finally { f.close(); }
  });
}

test('A3 concurrent account mutations have one winner; reset hash-only TTL/reissue/replay and rollback are atomic', async () => {
  const f = fixture();
  try {
    const a = f.open(), b = f.open(), user = (await a.register('reset@example.com', password))!;
    const db = new Database(f.path);
    try {
      const token = a.createSession(user.id), snapshot = a.sessionForToken(token)!;
      const races = await Promise.allSettled([a.changePassword(snapshot, password, nextPassword), b.revokeAll(b.sessionForToken(token)!, password)]);
      assert.equal(races.filter(result => result.status === 'fulfilled' && result.value).length, 1);
      const first = a.issuePasswordReset(user.email)!, replacement = a.issuePasswordReset(user.email)!;
      assert.match(replacement.token, /^[A-Za-z0-9_-]{43}$/);
      assert.notEqual(first.token, replacement.token);
      const rows = db.prepare('SELECT * FROM password_resets').all() as { token_hash: string; expires_at: number }[];
      assert.equal(rows.length, 1); assert.equal(rows[0].token_hash, digest(replacement.token));
      assert.ok(rows[0].expires_at <= Date.now() + PASSWORD_RESET_TTL_MS);
      assert.doesNotMatch(JSON.stringify(rows), new RegExp(replacement.token));
      assert.equal(await a.confirmPasswordReset(first.token, password), false);
      db.prepare('UPDATE password_resets SET expires_at=?').run(Date.now());
      assert.equal(await a.confirmPasswordReset(replacement.token, password), false, 'expiry equality is invalid');
      const atomic = a.issuePasswordReset(user.email)!;
      a.createSession(user.id); // Ensure the synthetic revoke trigger has a live row to reject.
      const before = ['users', 'sessions', 'user_auth_state', 'password_resets'].map(table => db.prepare(`SELECT * FROM ${table} ORDER BY 1`).all());
      db.exec("CREATE TRIGGER refuse_revoke BEFORE UPDATE ON sessions BEGIN SELECT RAISE(ABORT,'synthetic failure'); END");
      await assert.rejects(a.confirmPasswordReset(atomic.token, password));
      assert.deepEqual(['users', 'sessions', 'user_auth_state', 'password_resets'].map(table => db.prepare(`SELECT * FROM ${table} ORDER BY 1`).all()), before);
      db.exec('DROP TRIGGER refuse_revoke');
      assert.deepEqual((await Promise.all([a.confirmPasswordReset(atomic.token, password), b.confirmPasswordReset(atomic.token, nextPassword)])).sort(), [false, true]);
      assert.equal(await a.confirmPasswordReset(atomic.token, password), false);
      const same = a.issuePasswordReset(user.email)!;
      assert.deepEqual((await Promise.all([a.confirmPasswordReset(same.token, password), a.confirmPasswordReset(same.token, password)])).sort(), [false, true]);
    } finally { db.close(); }
  } finally { f.close(); }
});

test('A3 durable reset identity/socket/global/bucket limits, expiry and four concurrent KDFs', async () => {
  const f = fixture();
  try {
    const a = f.open();
    for (let n = 0; n < 3; n++) assert.equal(a.rateLimit('reset-request', 'same@example.com', `ip-${n}`), true);
    assert.equal(f.open().rateLimit('reset-request', 'same@example.com', 'different'), false);
    for (let n = 0; n < 20; n++) assert.equal(a.rateLimit('revoke-all', `owner-${n}`, 'socket'), true);
    assert.equal(a.rateLimit('revoke-all', 'new-owner', 'socket'), false);
    for (let n = 0; n < 100; n++) assert.equal(a.rateLimit('reset-confirm', `synthetic-token-${n}`, `ip-${n}`), true);
    assert.equal(a.rateLimit('reset-confirm', 'new-token', 'new-ip'), false);
    const db = new Database(f.path);
    try {
      const buckets = db.prepare('SELECT bucket FROM auth_attempts').all() as { bucket: string }[];
      assert.ok(buckets.every(row => /^[a-f0-9]{64}$/.test(row.bucket)));
      db.prepare('UPDATE auth_attempts SET expires_at=?').run(Date.now());
      assert.equal(a.rateLimit('reset-request', 'same@example.com', 'different'), true);
      db.exec('DELETE FROM auth_attempts');
      const insert = db.prepare('INSERT INTO auth_attempts VALUES(?,1,?)');
      db.transaction(() => { for (let n = 0; n < 10000; n++) insert.run(digest(`bucket-${n}`), Date.now() + 60000); })();
      assert.equal(a.rateLimit('change-password', 'new', 'new'), false);
    } finally { db.close(); }
    const work = Array.from({ length: 4 }, (_, n) => a.register(`kdf-${n}@example.com`, password));
    await assert.rejects(a.register('kdf-overflow@example.com', password), code('AUTH_BUSY'));
    assert.ok((await Promise.all(work)).every(Boolean));
  } finally { f.close(); }
});

test('A3 reset adapters: disabled/misconfigured/drift, equal slots, rejection cancellation, timeout and hung permit', async t => {
  const f = fixture();
  try {
    const logs: unknown[][] = [];
    for (const method of ['log', 'info', 'warn', 'error', 'debug'] as const) t.mock.method(console, method, (...args: unknown[]) => { logs.push(args); });
    const store = f.open(); await store.register('known@example.com', password);
    assert.deepEqual(new PasswordResetService(store).status(), { available: false, reason: 'DELIVERY_NOT_CONFIGURED', action: 'CONTACT_OPERATOR' });
    for (const resetPageUrl of ['http://auth.example/reset', 'https://evil.example/reset', 'https://auth.example/reset?q=x', 'https://auth.example/reset#x', 'https://user:pass@auth.example/reset']) {
      const service = new PasswordResetService(store, { resetPageUrl, send: async () => { assert.fail('invalid adapter called'); } });
      assert.equal(service.status().available, false); assert.throws(() => service.request('known@example.com'), code('PASSWORD_RESET_UNAVAILABLE'));
    }
    t.mock.timers.enable({ apis: ['setTimeout'] });
    let captured: Parameters<PasswordResetDelivery['send']>[0] | undefined;
    const service = new PasswordResetService(store, { resetPageUrl: `${origin}/reset`, send: async message => { captured = message; throw new Error('synthetic private provider failure'); } });
    service.request('known@example.com'); service.request('unknown@example.com');
    await new Promise<void>(resolve => setImmediate(resolve));
    assert.equal(service.diagnostics().pending, 2); assert.equal(service.diagnostics().failures, 1);
    const url = new URL(captured!.resetUrl); assert.equal(url.origin, origin); assert.equal(url.search, '');
    const raw = url.hash.slice('#token='.length); assert.match(raw, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(await store.confirmPasswordReset(raw, nextPassword), false);
    assert.doesNotMatch(JSON.stringify(logs), /known@example|synthetic private provider|token=|synthetic-next-password/);
    assert.equal(logs.length, 0, 'adapter errors and request arguments are not logged');
    t.mock.timers.tick(10000); await new Promise<void>(resolve => setImmediate(resolve));
    assert.equal(service.diagnostics().pending, 0); service.onModuleDestroy();
    const rejected = new PasswordResetService(store, { resetPageUrl: `${origin}/reset`, send: async message => {
      captured = message; return { accepted: false } as unknown as { accepted: true };
    } });
    rejected.request('known@example.com'); await new Promise<void>(resolve => setImmediate(resolve));
    assert.equal(rejected.diagnostics().failures, 1);
    assert.equal(await store.confirmPasswordReset(new URL(captured!.resetUrl).hash.slice(7), nextPassword), false);
    t.mock.timers.tick(10000); await new Promise<void>(resolve => setImmediate(resolve)); rejected.onModuleDestroy();
    let settle!: (value: { accepted: true }) => void;
    const hung = new PasswordResetService(store, { resetPageUrl: `${origin}/reset`, send: message => {
      captured = message; return new Promise(resolve => { settle = resolve; });
    } });
    hung.request('known@example.com');
    for (let n = 0; n < 3; n++) hung.request(`unknown-${n}@example.com`);
    assert.throws(() => hung.request('overflow@example.com'), code('PASSWORD_RESET_BUSY'));
    t.mock.timers.tick(10000); await new Promise<void>(resolve => setImmediate(resolve));
    assert.equal(captured!.signal.aborted, true); assert.equal(hung.diagnostics().pending, 1, 'unsettled adapter retains its permit');
    assert.equal(await store.confirmPasswordReset(new URL(captured!.resetUrl).hash.slice(7), nextPassword), false);
    settle({ accepted: true }); await new Promise<void>(resolve => setImmediate(resolve));
    assert.equal(hung.diagnostics().pending, 0);
    process.env.AUTH_ORIGIN = 'https://changed.example'; assert.equal(hung.status().available, false);
    hung.onModuleDestroy();
  } finally { t.mock.timers.reset(); f.close(); }
});

test('A3 HTTP password byte boundaries and revoke-all expire every subject cookie, never another owner', async () => {
  const f = fixture();
  const app = await NestFactory.create(AuthModule, { logger: false });
  try {
    await app.listen(0, '127.0.0.1');
    const url = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}/api/v1/auth`;
    const post = (route: string, body: unknown, cookie = '') => fetch(`${url}/${route}`, { method: 'POST',
      headers: { origin, cookie, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const store = app.get(AuthStore), user = (await store.register('bounds@example.com', password))!;
    const other = (await store.register('unrelated@example.com', password))!, otherToken = store.createSession(other.id);
    let currentPassword = password;
    for (const newPassword of ['é'.repeat(6), 'é'.repeat(64)]) {
      const tokens = [store.createSession(user.id), store.createSession(user.id)];
      const changed = await post('change-password', { currentPassword, newPassword }, `demo_session=${tokens[0]}`);
      assert.equal(changed.status, 204); assert.equal(await changed.text(), '');
      assert.match(changed.headers.get('set-cookie')!, /Max-Age=0; Secure$/);
      tokens.forEach(token => assert.equal(store.userForToken(token), null));
      assert.equal(store.userForToken(otherToken)?.id, other.id);
      assert.ok(await store.login(user.email, newPassword)); currentPassword = newPassword;
    }
    const tokens = [store.createSession(user.id), store.createSession(user.id)];
    const revoked = await post('revoke-all', { currentPassword }, `demo_session=${tokens[0]}`);
    assert.equal(revoked.status, 204); assert.equal(await revoked.text(), '');
    assert.match(revoked.headers.get('set-cookie')!, /HttpOnly; SameSite=Lax; Path=\/; Max-Age=0; Secure$/);
    tokens.forEach(token => assert.equal(store.userForToken(token), null));
    assert.equal(store.userForToken(otherToken)?.id, other.id);
    const absent = await post('revoke-all', { currentPassword });
    assert.equal(absent.status, 401); assert.deepEqual(await absent.json(), { errorCode: 'UNAUTHORIZED' });
  } finally { await app.close(); f.close(); }
});

test('A3 isolated real HTTP: exact origin/DTO/UTF8/envelope, disabled reset, nondisclosure, secure invalidation and untrusted forwarding', async () => {
  const f = fixture();
  let app: Awaited<ReturnType<typeof NestFactory.create>> | undefined;
  try {
    const start = async (delivery?: PasswordResetDelivery) => {
      const instance = await NestFactory.create(delivery ? AuthModule.withPasswordReset(delivery) : AuthModule, { logger: false });
      await instance.listen(0, '127.0.0.1'); app = instance;
      return `http://127.0.0.1:${(instance.getHttpServer().address() as { port: number }).port}/api/v1/auth`;
    };
    let url = await start();
    const post = (route: string, body: unknown, headers: Record<string, string> = {}) => fetch(`${url}/${route}`, {
      method: 'POST', headers: { origin, 'content-type': 'application/json', ...headers }, body: JSON.stringify(body),
    });
    const status = await fetch(`${url}/password-reset/status`);
    assert.equal(status.headers.get('cache-control'), 'no-store');
    assert.deepEqual(await status.json(), { available: false, reason: 'DELIVERY_NOT_CONFIGURED', action: 'CONTACT_OPERATOR' });
    for (const route of ['password-reset/request', 'password-reset/confirm']) {
      const response = await post(route, {}); assert.equal(response.status, 503);
      assert.deepEqual(await response.json(), { errorCode: 'PASSWORD_RESET_UNAVAILABLE' });
    }
    await app!.close();
    let message: Parameters<PasswordResetDelivery['send']>[0] | undefined;
    url = await start({ resetPageUrl: `${origin}/reset`, send: async value => { message = value; return { accepted: true }; } });
    for (const candidate of ['', `${origin}/`, 'https://AUTH.example', `${origin}:443`, 'https://evil.example']) {
      const response = await post('password-reset/request', { email: 'known@example.com' }, { origin: candidate });
      assert.equal(response.status, 403); assert.deepEqual(await response.json(), { errorCode: 'INVALID_ORIGIN' });
    }
    assert.throws(() => originForRequest({ headers: { origin: [origin, origin] }, socket: {} }), code('INVALID_ORIGIN'));
    assert.equal(validPassword('é'.repeat(6)), true); assert.equal(validPassword('é'.repeat(64)), true);
    assert.equal(validPassword('é'.repeat(65)), false); assert.equal(validPassword('é'.repeat(5)), false);
    const registered = await post('register', { email: 'known@example.com', password }); assert.equal(registered.status, 201);
    const cookie = registered.headers.get('set-cookie')!.split(';')[0];
    for (const body of [{ currentPassword: password, newPassword: 'é'.repeat(65) }, { currentPassword: password, newPassword: nextPassword, extra: true }]) {
      const response = await post('change-password', body, { cookie }); assert.equal(response.status, 400);
      assert.deepEqual(await response.json(), { errorCode: 'INVALID_INPUT' });
    }
    const oversized = await post('change-password', { padding: 'x'.repeat(2048) }, { cookie }); assert.equal(oversized.status, 415);
    const wrongType = await post('revoke-all', {}, { cookie, 'content-type': 'text/plain' }); assert.equal(wrongType.status, 415);
    const wrong = await post('change-password', { currentPassword: 'wrong-password-1234', newPassword: nextPassword }, { cookie });
    assert.equal(wrong.status, 401); assert.deepEqual(await wrong.json(), { errorCode: 'INVALID_CREDENTIALS' });
    for (const email of ['known@example.com', 'missing@example.com']) {
      const response = await post('password-reset/request', { email }, { host: 'evil.example', 'x-forwarded-host': 'evil.example' });
      assert.equal(response.status, 202); assert.deepEqual(await response.json(), { status: 'accepted' });
      assert.equal(response.headers.get('cache-control'), 'no-store');
    }
    assert.equal(new URL(message!.resetUrl).origin, origin);
    const confirmed = await post('password-reset/confirm', { token: new URL(message!.resetUrl).hash.slice(7), newPassword: nextPassword });
    assert.equal(confirmed.status, 204); assert.equal(await confirmed.text(), '');
    assert.match(confirmed.headers.get('set-cookie')!, /HttpOnly; SameSite=Lax; Path=\/; Max-Age=0; Secure$/);
    assert.equal((await fetch(`${url}/me`, { headers: { cookie } })).status, 401);
    const replay = await post('password-reset/confirm', { token: new URL(message!.resetUrl).hash.slice(7), newPassword: password });
    assert.equal(replay.status, 400); assert.deepEqual(await replay.json(), { errorCode: 'INVALID_RESET_TOKEN' });
    // Use the actual controller with synthetic request headers to exercise envelopes not expressible by fetch.
    const controller = app!.get(AuthController);
    for (const length of [undefined, '01', '-1', '2049']) await assert.rejects(controller.requestPasswordReset({ headers: {
      origin, 'content-type': 'application/json', 'content-length': length,
    }, socket: {} }, { email: 'known@example.com' }), code('INVALID_CONTENT_TYPE'));
    for (let n = 0; n < 20; n++) {
      const response = await post('login', { email: `missing-${n}@example.com`, password }, { 'x-forwarded-for': `192.0.2.${n}` });
      assert.equal(response.status, 401);
    }
    const limited = await post('login', { email: 'last@example.com', password }, { 'x-forwarded-for': '198.51.100.1' });
    assert.equal(limited.status, 429); assert.deepEqual(await limited.json(), { errorCode: 'RATE_LIMITED' });
  } finally { await app?.close(); f.close(); }
});
