import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { runInNewContext } from 'node:vm';
import {
  AccountGate,
  assertNoCaptureEnvironment,
  ORIGIN,
  LIMITS,
  CHECKS,
  REVIEW_SOURCE,
  aggregate,
  browserIo,
  classify,
  fingerprint,
  freshAccount,
  installRoutes,
  journey,
  parseArgs,
  runOnce,
} from './batch34-account-native.mjs';

const user = (account) => ({ id: 'synthetic-disposable-subject', email: account.email });
const parsed = (review) =>
  parseArgs([
    '--run-once',
    '--ack-coordinator-account-go',
    '--ack-disposable-account-retained',
    '--review-sha256',
    review,
  ]);
function route(kind = 'register', body, options = {}) {
  const url = options.url ?? `${ORIGIN}/api/v1/auth/${kind}`;
  const method = options.method ?? (kind === 'me' ? 'GET' : 'POST');
  const trace = [],
    fetchOptions = [];
  const reply = options.reply ?? '';
  const result = {
    url: () => options.responseUrl ?? url,
    status: () => options.status ?? 201,
    headers: () => ({ 'content-type': options.responseType ?? 'application/json' }),
    body: async () => {
      if (options.bodyFailure) throw Error('PRIVATE-body');
      return Buffer.from(typeof reply === 'string' ? reply : JSON.stringify(reply));
    },
    dispose: async () => {
      trace.push('dispose');
      if (options.disposeFailure) throw Error('PRIVATE-dispose');
    },
  };
  return {
    trace,
    fetchOptions,
    result,
    request: () => ({
      url: () => url,
      method: () => method,
      redirectedFrom: () => (options.redirected ? {} : null),
      postData: () =>
        options.raw !== undefined ? options.raw : body === undefined ? null : JSON.stringify(body),
      headerValue: async (name) =>
        name === 'origin' ? (options.origin ?? ORIGIN) : (options.contentType ?? 'application/json'),
    }),
    fetch: async (value) => {
      trace.push('fetch');
      fetchOptions.push(value);
      if (options.fetchFailure) throw Error('PRIVATE-reset');
      await options.duringFetch?.();
      return result;
    },
    fulfill: async (value) => {
      assert.deepEqual(value, { response: result });
      trace.push('fulfill');
      if (options.fulfillFailure) throw Error('PRIVATE-fulfill');
      await options.duringFulfill?.();
    },
    abort: async () => {
      trace.push('abort');
    },
    continue: async () => {
      throw Error('CONTINUE_MUST_NEVER_BE_USED');
    },
  };
}
async function setup(account = freshAccount(), clock) {
  const gate = new AccountGate(account, clock);
  const handlers = {},
    sockets = {};
  for (const label of ['first', 'second'])
    await installRoutes(
      {
        route: async (_, fn) => {
          handlers[label] = fn;
        },
        routeWebSocket: async (_, fn) => {
          sockets[label] = fn;
        },
      },
      gate,
      label,
    );
  return { account, gate, handlers, sockets };
}
const registration = (a) => ({ email: a.email, password: a.old });
async function register(f) {
  f.gate.arm('register');
  const r = route('register', registration(f.account), { reply: user(f.account) });
  await f.handlers.first(r);
  return r;
}
async function syntheticJourney(f, failAt) {
  const order = [];
  async function send(label, kind, body, status = 204) {
    const reply =
      status === 200 || status === 201
        ? user(f.account)
        : status === 401
          ? { errorCode: kind === 'me' ? 'UNAUTHORIZED' : 'INVALID_CREDENTIALS' }
          : '';
    const r = route(kind, body, { status, reply });
    await f.handlers[label](r);
    f.gate.live();
    assert.equal(r.trace.includes('fulfill'), true);
    order.push(`${label}:${kind}:${status}`);
  }
  let secondEstablishedBeforeChange = false,
    secondEstablishedAfterChange = false,
    changed = false,
    revoked = false;
  const io = {
    anonymous: (label) => send(label, 'me', undefined, 401),
    register: () => send('first', 'register', registration(f.account), 201),
    logout: () => send('first', 'logout', {}),
    async login(label, password, status) {
      if (label === 'second') {
        if (!changed) secondEstablishedBeforeChange = true;
        else secondEstablishedAfterChange = true;
      }
      await send(label, 'login', { email: f.account.email, password: f.account[password] }, status);
    },
    async changePassword() {
      assert.equal(secondEstablishedBeforeChange, true);
      if (failAt === 'change') throw Error('PRIVATE-password-current');
      await send('first', 'change-password', { currentPassword: f.account.old, newPassword: f.account.new });
      changed = true;
    },
    async revoked(label) {
      assert.equal(changed || revoked, true);
      await send(label, 'me', undefined, 401);
    },
    async revokeAll() {
      assert.equal(secondEstablishedAfterChange, true);
      await send('first', 'revoke-all', { currentPassword: f.account.new });
      revoked = true;
    },
  };
  await journey(io, f.gate);
  return order;
}

test('default and import are inert; exact new GO, retention acknowledgment and reviewed bytes required', async () => {
  assert.deepEqual(parseArgs([]), { mode: 'inert' });
  assert.deepEqual(parseArgs(['--fingerprint']), { mode: 'fingerprint' });
  const review = await fingerprint();
  assert.match(review, /^[a-f0-9]{64}$/);
  assert.equal(REVIEW_SOURCE.includes('tests-e2e/batch34-account-native.test.mjs'), true);
  assert.deepEqual(parsed(review), { mode: 'run', review, coordinatorGo: true, retainAccount: true });
  for (const args of [
    ['--help'],
    ['--run-once'],
    ['--run'],
    ['--origin', ORIGIN],
    ['--credentials', 'old.json'],
    ['--run-once', '--ack-coordinator-account-go', '--review-sha256', review],
    [
      '--run-once',
      '--ack-coordinator-account-go',
      '--ack-disposable-account-retained',
      '--review-sha256',
      review,
      '--retry',
    ],
  ])
    assert.throws(() => parseArgs(args), /CLI/);
  const process = spawnSync('node', ['tests-e2e/batch34-account-native.mjs'], {
    encoding: 'utf8',
    timeout: 10000,
  });
  assert.equal(process.status, 0);
  assert.deepEqual(JSON.parse(process.stdout), { status: 'INERT', browserStarted: false });
  assert.equal(process.stderr, '');
});
test('runOnce rejects missing GO, serialized credentials/factory/path override and stale review before browser import', async () => {
  for (const value of [
    { mode: 'run', review: 'a'.repeat(64) },
    { ...parsed('a'.repeat(64)), coordinatorGo: false },
    { ...parsed('a'.repeat(64)), credentials: {} },
    { ...parsed('a'.repeat(64)), factory: () => {} },
    { ...parsed('a'.repeat(64)), origin: ORIGIN },
  ])
    await assert.rejects(runOnce(value), /CLI/);
  await assert.rejects(runOnce(parsed('a'.repeat(64))), /REVIEW/);
});
test('capture environment preflight matches the existing shared policy without importing its Playwright graph', async () => {
  const source = await readFile(new URL('./batch26-native-chat.mjs', import.meta.url), 'utf8');
  const match = source.match(/^export function assertNoCaptureEnvironment\(environment\) \{\n[\s\S]*?^\}/m);
  assert.ok(match, 'the reviewed shared policy must still exist as a standalone function');
  const shared = runInNewContext(`(${match[0].replace(/^export /, '')})`, {
    need(value, code) {
      if (!value) throw Error(code);
    },
  });
  const marker = 'SYNTHETIC_CREDENTIAL_MARKER_34';
  const outcome = (check, environment) => {
    try {
      check(environment);
      return 'allowed';
    } catch (cause) {
      return cause.message;
    }
  };
  for (const key of ['DEBUG', 'PWDEBUG', 'NODE_DEBUG', 'NODE_DEBUG_NATIVE']) {
    for (const value of [undefined, '', '0', '1', 'http', 'pw:api', ' ', marker]) {
      const environment = value === undefined ? {} : { [key]: value };
      assert.equal(outcome(assertNoCaptureEnvironment, environment), outcome(shared, environment));
      if (value && value !== '0')
        assert.equal(outcome(assertNoCaptureEnvironment, environment), 'CAPTURE_DEBUG_ENABLED');
      assert.equal(environment[key], value, 'preflight must not delete or rewrite diagnostic settings');
    }
  }
  assert.equal(REVIEW_SOURCE.includes('tests-e2e/batch26-native-chat.mjs'), true);
});

for (const [key, value] of [
  ['NODE_DEBUG', 'http'],
  ['NODE_DEBUG_NATIVE', 'http'],
  ['DEBUG', 'pw:api'],
  ['PWDEBUG', '1'],
]) {
  test(`actual CLI refuses ${key} BEFORE credentials or Playwright import; no credential marker on stdout/stderr`, async () => {
    const review = await fingerprint();
    const marker = 'SYNTHETIC_CREDENTIAL_MARKER_34';
    // Memory-only preload: even a regression cannot import/launch Playwright or send HTTP.
    const preload = `
      import crypto from 'node:crypto';
      import { registerHooks, syncBuiltinESMExports } from 'node:module';
      let credentialCalls = 0, playwrightImports = 0;
      crypto.randomUUID = () => ++credentialCalls === 1
        ? '00000000-0000-4000-8000-000000000034'
        : ${JSON.stringify(marker)} + credentialCalls;
      syncBuiltinESMExports();
      registerHooks({ resolve(specifier, context, next) {
        if (specifier === '@playwright/test' || /playwright(?:-core)?(?:\\/|$)/.test(specifier)) {
          playwrightImports++; throw Error('PLAYWRIGHT_IMPORT_FORBIDDEN');
        }
        if (['http', 'https', 'net', 'tls', 'node:http', 'node:https', 'node:net', 'node:tls'].includes(specifier))
          throw Error('NETWORK_IMPORT_FORBIDDEN');
        return next(specifier, context);
      } });
      process.on('exit', () => console.log(JSON.stringify({ credentialCalls, playwrightImports,
        diagnosticSettingPreserved: process.env[${JSON.stringify(key)}] === ${JSON.stringify(value)} })));
    `;
    const result = spawnSync(
      process.execPath,
      [
        '--import',
        'data:text/javascript;base64,' + Buffer.from(preload).toString('base64'),
        'tests-e2e/batch34-account-native.mjs',
        '--run-once',
        '--ack-coordinator-account-go',
        '--ack-disposable-account-retained',
        '--review-sha256',
        review,
      ],
      { encoding: 'utf8', timeout: 10000, env: { [key]: value } },
    );
    assert.equal(result.status, 1);
    assert.equal(result.signal, null);
    assert.deepEqual(
      result.stdout
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line)),
      [
        { status: 'REFUSED', failure: 'CAPTURE_DEBUG_ENABLED' },
        { credentialCalls: 0, playwrightImports: 0, diagnosticSettingPreserved: true },
      ],
    );
    assert.equal(result.stdout.includes(marker), false);
    assert.equal(result.stderr.includes(marker), false);
    assert.equal(result.stderr, '');
  });
}

test('fresh credentials are independent memory-only random inputs, not historical user credentials', () => {
  const a = freshAccount(),
    b = freshAccount();
  assert.match(a.email, /^batch34-[a-f0-9-]{36}@example\.invalid$/);
  assert.notEqual(a.email, b.email);
  assert.notEqual(a.old, a.new);
  assert.notEqual(a.new, b.new);
  assert.deepEqual(Object.keys(a).sort(), ['email', 'new', 'old']);
});
for (const [url, method] of [
  ['http://127.0.0.1:8080/account', 'GET'],
  ['http://localhost:8081/account', 'GET'],
  ['https://example.invalid/account', 'GET'],
  [`${ORIGIN}/api/v1/auth/me?x=1`, 'GET'],
  [`${ORIGIN}/api/v1/auth/me#x`, 'GET'],
  [`${ORIGIN}/api/v1/auth/%6de`, 'GET'],
  [`${ORIGIN}/api/v1/auth/../auth/me`, 'GET'],
  [`${ORIGIN}/api/v1/auth/login`, 'PUT'],
  [`${ORIGIN}/api/v1/auth/password-reset/request`, 'POST'],
  [`${ORIGIN}/api/v1/browser/scans`, 'POST'],
  [`${ORIGIN}/api/v1/scans/id/llm/chat`, 'POST'],
  [`${ORIGIN}/api/v1/auth/me`, 'HEAD'],
])
  test(`closed route classification refuses ${method} ${url.replace(ORIGIN, '')}`, () => {
    assert.equal(classify(url, method), null);
  });
test('closed classification admits only exact auth methods and public built assets; rejects redirects', () => {
  assert.equal(classify(`${ORIGIN}/account`, 'GET'), 'document');
  assert.equal(classify(`${ORIGIN}/assets/index-a1.js`, 'GET'), 'asset');
  assert.equal(classify(`${ORIGIN}/api/v1/auth/me`, 'GET'), 'me');
  assert.equal(classify(`${ORIGIN}/api/v1/auth/login`, 'POST'), 'login');
  assert.equal(classify(`${ORIGIN}/api/v1/auth/login`, 'POST', true), null);
});
test('actual installed handler consumes before exact original no-follow/no-retry fetch then fulfill/dispose', async () => {
  const f = await setup();
  const r = await register(f);
  assert.deepEqual(r.trace, ['fetch', 'fulfill', 'dispose']);
  assert.equal(r.fetchOptions.length, 1);
  assert.equal(r.fetchOptions[0].maxRedirects, 0);
  assert.equal(r.fetchOptions[0].maxRetries, 0);
  assert.ok(r.fetchOptions[0].timeout > 0 && r.fetchOptions[0].timeout <= 8000);
  assert.equal(f.gate.log.completedPosts, 1);
  assert.equal(f.gate.log.denied, 0);
  await f.handlers.first(r);
  assert.deepEqual(r.trace, ['fetch', 'fulfill', 'dispose', 'abort']);
  assert.equal(f.gate.log.dispatched.register, 1);
  assert.equal(f.gate.log.failure, 'UNARMED');
});
for (const options of [
  { status: 300 },
  { status: 301 },
  { status: 302 },
  { status: 303 },
  { status: 304 },
  { status: 305 },
  { status: 306 },
  { status: 307 },
  { status: 308 },
  { status: 399 },
  { status: 429 },
  { status: 503 },
  { status: NaN },
  { responseUrl: 'http://127.0.0.1:8081/login' },
  { fetchFailure: true },
  { bodyFailure: true },
  { reply: 'not-json' },
  { reply: { id: 'x', email: 'foreign@example.invalid' } },
  { reply: { id: 'x', email: 'foreign@example.invalid', secret: 'PRIVATE' } },
  { responseType: 'text/html' },
  { fulfillFailure: true },
  { disposeFailure: true },
]) {
  test(`installed route fails closed on ${Object.keys(options).join('/')} ${String(options.status ?? '')}`, async () => {
    const f = await setup();
    f.gate.arm('register');
    const r = route('register', registration(f.account), { reply: user(f.account), ...options });
    await f.handlers.first(r);
    assert.equal(r.fetchOptions.length, 1);
    assert.ok(f.gate.log.failure);
    const previous = r.fetchOptions.length;
    await f.handlers.first(r);
    assert.equal(r.fetchOptions.length, previous);
    assert.equal(f.gate.log.dispatched.register, 1);
    assert.doesNotMatch(JSON.stringify(aggregate(f.gate)), /PRIVATE|foreign@example/);
  });
}
for (const mutate of [
  (b) => ({ ...b, extra: true }),
  (b) => ({ email: b.email, password: 'not-the-created-password' }),
  () => [],
  () => null,
]) {
  test('request shape, own credentials and unknown fields refuse BEFORE transport', async () => {
    const f = await setup();
    f.gate.arm('register');
    const r = route('register', mutate(registration(f.account)));
    await f.handlers.first(r);
    assert.deepEqual(r.trace, ['abort']);
    assert.equal(f.gate.log.dispatched.register, 0);
    assert.equal(f.gate.log.failure, 'BODY');
  });
}
test('wrong origin, content-type, duplicate JSON fields, oversized body and wrong context all refuse without transport', async () => {
  for (const options of [
    { origin: 'http://127.0.0.1:8080' },
    { contentType: 'text/plain' },
    { raw: '{"email":"x","email":"y","password":"z"}' },
    { raw: 'x'.repeat(1025) },
  ]) {
    const f = await setup();
    f.gate.arm('register');
    const r = route('register', registration(f.account), options);
    await f.handlers.first(r);
    assert.deepEqual(r.trace, ['abort']);
  }
  const f = await setup();
  f.gate.arm('register');
  const r = route('register', registration(f.account));
  await f.handlers.second(r);
  assert.deepEqual(r.trace, ['abort']);
});
test('concurrent duplicate and deadline during fetch cannot fulfill or authorize a retry', async () => {
  let now = 0;
  const f = await setup(freshAccount(), { now: () => now, durationMs: 20 });
  f.gate.arm('register');
  const second = route('register', registration(f.account));
  const first = route('register', registration(f.account), {
    reply: user(f.account),
    duringFetch: async () => {
      await f.handlers.first(second);
      now = 21;
    },
  });
  await f.handlers.first(first);
  assert.equal(first.trace.includes('fulfill'), false);
  assert.deepEqual(second.trace, ['abort']);
  assert.equal(f.gate.log.dispatched.register, 1);
});
test('expired before transport cannot consume a POST; remaining time includes whole journey', async () => {
  let now = 0;
  const f = await setup(freshAccount(), { now: () => now, durationMs: 10 });
  f.gate.arm('register');
  now = 10;
  const r = route('register', registration(f.account));
  await f.handlers.first(r);
  assert.deepEqual(r.trace, ['abort']);
  assert.equal(f.gate.log.failure, 'DEADLINE');
  assert.equal(f.gate.log.dispatched.register, 0);
  assert.equal(LIMITS.journeyMs + LIMITS.closeMs <= LIMITS.wholeMs, true);
  assert.equal(LIMITS.wholeMs, 120000);
});
test('auth GET and asset request budgets are independent of mutation allowances', async () => {
  const f = await setup();
  for (let n = 0; n <= LIMITS.me; n++)
    await f.handlers.first(route('me', undefined, { status: 401, reply: { errorCode: 'UNAUTHORIZED' } }));
  assert.equal(f.gate.log.failure, 'BUDGET');
  assert.equal(f.gate.log.budgetFailure, 'AUTH_ME');
  assert.equal(f.gate.log.me, 41);
  assert.equal(f.gate.log.transportCounts.authMe, 40);
  assert.deepEqual(f.gate.log.dispatched, {
    register: 0,
    login: 0,
    logout: 0,
    'change-password': 0,
    'revoke-all': 0,
  });
  const g = await setup();
  for (let n = 0; n <= LIMITS.assets; n++)
    await g.handlers.first(
      route('asset', undefined, { url: `${ORIGIN}/assets/index-a1.js`, method: 'GET', status: 200 }),
    );
  assert.equal(g.gate.log.failure, 'BUDGET');
  assert.equal(g.gate.log.budgetFailure, 'ASSETS');
  assert.equal(g.gate.log.requestCounts.asset, 351);
  assert.equal(g.gate.log.transportCounts.asset, 350);
});

test('400 total ceiling and document cap stay independent, with the rejected request counted but not sent', async () => {
  const f = await setup();
  for (let n = 0; n < LIMITS.assets; n++)
    await f.handlers.first(
      route('asset', undefined, { url: `${ORIGIN}/assets/chunk-${n}.js`, method: 'GET', status: 200 }),
    );
  for (let n = 0; n < LIMITS.documents; n++)
    await f.handlers.second(
      route('document', undefined, { url: `${ORIGIN}/account`, method: 'GET', status: 200 }),
    );
  for (let n = 0; n < 10; n++)
    await f.handlers.first(route('me', undefined, { status: 401, reply: { errorCode: 'UNAUTHORIZED' } }));
  assert.equal(f.gate.log.requests, 400);
  assert.equal(f.gate.log.failure, null);
  const overflow = route('me', undefined, { status: 401, reply: { errorCode: 'UNAUTHORIZED' } });
  await f.handlers.first(overflow);
  assert.deepEqual(overflow.trace, ['abort']);
  assert.equal(f.gate.log.budgetFailure, 'TOTAL');
  assert.equal(f.gate.log.requests, 401);
  assert.equal(f.gate.log.me, 11);
  assert.equal(
    Object.values(f.gate.log.transportCounts).reduce((a, b) => a + b, 0),
    400,
  );
  const g = await setup();
  for (let n = 0; n <= LIMITS.documents; n++)
    await g.handlers.second(
      route('document', undefined, { url: `${ORIGIN}/login`, method: 'GET', status: 200 }),
    );
  assert.equal(g.gate.log.budgetFailure, 'DOCUMENTS');
  assert.equal(g.gate.log.transportCounts.document, 40);
});

test('finite classification separates assets/API/contexts and never emits denied URL or private values', async () => {
  const f = await setup();
  await f.handlers.first(
    route('asset', undefined, { url: `${ORIGIN}/assets/chunk-a.js`, method: 'GET', status: 200 }),
  );
  await f.handlers.second(
    route('document', undefined, { url: `${ORIGIN}/account`, method: 'GET', status: 200 }),
  );
  await f.handlers.second(route('me', undefined, { status: 401, reply: { errorCode: 'UNAUTHORIZED' } }));
  await register(f);
  await f.handlers.first(
    route('asset', undefined, {
      url: `${ORIGIN}/PRIVATE_CREDENTIAL_MARKER?secret=value`,
      method: 'GET',
      status: 200,
    }),
  );
  const result = aggregate(f.gate);
  assert.equal(result.requests, 5);
  assert.equal(result.apiRequests, 2);
  assert.deepEqual(result.requestCounts, { asset: 1, document: 1, authMe: 1, authPost: 1, refused: 1 });
  assert.deepEqual(result.transportCounts, { asset: 1, document: 1, authMe: 1, authPost: 1, refused: 0 });
  assert.equal(result.requestCountsByContext.first.asset, 1);
  assert.equal(result.requestCountsByContext.second.authMe, 1);
  assert.equal(
    Object.values(result.requestCounts).reduce((a, b) => a + b, 0),
    result.requests,
  );
  assert.doesNotMatch(
    JSON.stringify(result),
    /PRIVATE_CREDENTIAL_MARKER|secret=value|http:|example\.invalid/,
  );
});

test('websocket and page-error finite failures cannot be hidden behind passing checks', async () => {
  const f = await setup();
  let closed = 0;
  f.sockets.first({
    close() {
      closed++;
    },
  });
  assert.equal(closed, 1);
  assert.equal(f.gate.log.failure, 'WEBSOCKET');
  f.gate.fail('PRIVATE-unknown-error');
  assert.equal(f.gate.log.failure, 'WEBSOCKET');
  assert.equal(aggregate(f.gate).status, 'FAILED_OR_PARTIAL');
});
test('full actual orchestrator + installed guards qualifies both PRE-change and POST-change second sessions offline', async () => {
  const f = await setup();
  const order = await syntheticJourney(f);
  assert.ok(order.indexOf('second:login:200') < order.indexOf('first:change-password:204'));
  assert.equal(order.filter((x) => x === 'second:login:200').length, 2);
  assert.equal(f.gate.log.completedPosts, 9);
  assert.deepEqual(f.gate.log.dispatched, {
    register: 1,
    login: 5,
    logout: 1,
    'change-password': 1,
    'revoke-all': 1,
  });
  assert.ok(CHECKS.every((key) => f.gate.log.checks[key]));
  assert.equal(aggregate(f.gate).status, 'FAILED_OR_PARTIAL'); // Cleanup must be confirmed separately.
  f.gate.log.cleanup = true;
  assert.equal(aggregate(f.gate).status, 'NATIVE_AUTH_PASS');
  const serialized = JSON.stringify(aggregate(f.gate));
  for (const secret of [f.account.email, f.account.old, f.account.new, user(f.account).id])
    assert.equal(serialized.includes(secret), false);
  assert.equal(aggregate(f.gate).accountRetained, true);
  assert.equal(aggregate(f.gate).deletionAttempted, false);
});
test('any failed journey step stops immediately; never continues to old-password test/new login/revoke', async () => {
  const f = await setup();
  await assert.rejects(syntheticJourney(f, 'change'), /PRIVATE/);
  f.gate.fail('UI');
  assert.equal(f.gate.log.dispatched['change-password'], 0);
  assert.equal(f.gate.log.dispatched['revoke-all'], 0);
  assert.equal(f.gate.log.dispatched.login, 2);
  assert.equal(f.gate.log.checks.passwordChanged, false);
  assert.equal(aggregate(f.gate).status, 'FAILED_OR_PARTIAL');
});
for (const [coldChunks, failPrivateHeading] of [
  [0, false],
  [12, false],
  [12, true],
])
  test(`actual browser adapter with ${coldChunks} cold chunks and private-heading fault=${failPrivateHeading}`, async () => {
    const account = freshAccount(),
      gate = new AccountGate(account),
      contexts = [],
      actions = [];
    let password = account.old;
    const fakeBrowser = {
      async newContext(options) {
        assert.equal(options.serviceWorkers, 'block');
        assert.equal(options.acceptDownloads, false);
        const label = contexts.length === 0 ? 'first' : 'second';
        let handler;
        const state = { valid: false, label };
        contexts.push(state);
        const fields = new Map();
        let url = `${ORIGIN}/account`,
          waiting,
          alert = false;
        async function transport(kind, body) {
          let status = 204,
            reply = '';
          const r = route(kind, body);
          r.fetch = async (options) => {
            assert.equal(options.maxRedirects, 0);
            assert.equal(options.maxRetries, 0);
            if (kind === 'me') {
              status = state.valid ? 200 : 401;
              reply = state.valid ? user(account) : { errorCode: 'UNAUTHORIZED' };
            }
            if (kind === 'register') {
              status = 201;
              state.valid = true;
              reply = user(account);
            }
            if (kind === 'login') {
              status = body.password === password ? 200 : 401;
              state.valid = status === 200;
              reply = state.valid ? user(account) : { errorCode: 'INVALID_CREDENTIALS' };
            }
            if (kind === 'logout') state.valid = false;
            if (kind === 'change-password') {
              assert.equal(contexts[1].valid, true, 'second OLD session must exist before mutation');
              assert.equal(fields.get('#account-change-confirmation'), true);
              assert.equal(body.currentPassword, password);
              password = body.newPassword;
              contexts.forEach((context) => {
                context.valid = false;
              });
            }
            if (kind === 'revoke-all') {
              assert.equal(contexts[1].valid, true, 'second NEW session must exist before mutation');
              assert.equal(fields.get('#account-revoke-confirmation'), true);
              assert.equal(body.currentPassword, password);
              contexts.forEach((context) => {
                context.valid = false;
              });
            }
            return {
              status: () => status,
              url: () => `${ORIGIN}/api/v1/auth/${kind}`,
              headers: () => ({ 'content-type': 'application/json' }),
              body: async () => Buffer.from(typeof reply === 'string' ? reply : JSON.stringify(reply)),
              dispose: async () => {},
            };
          };
          r.fulfill = async () => {
            if (kind !== 'me') {
              actions.push(`${label}:${kind}:${status}`);
              alert = kind === 'login' && status === 401;
              if (status === 204) url = `${ORIGIN}/login`;
              const response = {
                url: () => `${ORIGIN}/api/v1/auth/${kind}`,
                status: () => status,
                request: () => ({ method: () => 'POST' }),
              };
              if (waiting?.predicate(response)) {
                waiting.resolve(response);
                waiting = null;
              }
            }
          };
          await handler(r);
          gate.live();
        }
        const node = (selector) => ({
          selector,
          state,
          async fill(value) {
            fields.set(selector, value);
            fields.delete('#account-change-confirmation');
            fields.delete('#account-revoke-confirmation');
          },
          async check() {
            fields.set(selector, true);
          },
          async click() {
            if (selector === '#account-password-section' || selector === '#account-revoke-section') return;
            if (selector === 'Создать аккаунт')
              return transport('register', {
                email: fields.get('#demo-auth-email'),
                password: fields.get('#demo-auth-password'),
              });
            if (selector === 'Войти')
              return transport('login', {
                email: fields.get('#demo-auth-email'),
                password: fields.get('#demo-auth-password'),
              });
            if (selector === 'Выйти из аккаунта') return transport('logout', {});
            if (selector === '#account-change-submit')
              return transport('change-password', {
                currentPassword: fields.get('#account-current-password'),
                newPassword: fields.get('#account-new-password'),
              });
            if (selector === '#account-revoke-submit')
              return transport('revoke-all', { currentPassword: fields.get('#account-revoke-password') });
            throw Error('unexpected UI action');
          },
        });
        async function navigate(value) {
          url = value;
          const document = route('document', undefined, { url: value, method: 'GET', status: 200 });
          await handler(document);
          gate.live();
          for (let n = 0; n < coldChunks; n++) {
            const asset = route('asset', undefined, {
              url: `${ORIGIN}/assets/cold-chunk-${n}.js`,
              method: 'GET',
              status: 200,
            });
            await handler(asset);
            gate.live();
          }
          await transport('me', undefined);
        }
        const page = {
          state,
          url: () => url,
          setDefaultTimeout() {},
          setDefaultNavigationTimeout() {},
          on() {},
          locator: node,
          getByRole: (role, options) => ({ ...node(options?.name ?? role), role, alert: () => alert }),
          async goto(value) {
            await navigate(value);
          },
          async reload() {
            await navigate(url);
          },
          waitForResponse(predicate) {
            return new Promise((resolve) => {
              assert.equal(waiting == null, true);
              waiting = { predicate, resolve };
            });
          },
        };
        return {
          route: async (_, fn) => {
            handler = fn;
          },
          routeWebSocket: async () => {},
          newPage: async () => page,
        };
      },
    };
    const expect = (target) => ({
      async toHaveText(value) {
        assert.equal(target.state.valid, true);
        assert.equal(value, account.email);
      },
      async toHaveCount(value) {
        assert.equal(value, 0);
        assert.equal(target.state.valid, false);
      },
      async toBeVisible() {
        if (failPrivateHeading && gate.log.phase === 'changeRevokedFirst' && target.role === 'heading')
          throw Error('PRIVATE_SYNTHETIC_HEADING_FAILURE');
        if (target.role === 'alert') assert.equal(target.alert(), true);
        else assert.equal(target.state.valid, false);
      },
      async toHaveURL(value) {
        assert.equal(target.url(), value);
      },
    });
    const operation = journey(browserIo(fakeBrowser, expect, gate, account), gate);
    if (failPrivateHeading) {
      await assert.rejects(operation, /PRIVATE_SYNTHETIC_HEADING_FAILURE/);
      gate.fail('UI');
      const result = aggregate(gate);
      assert.equal(result.failurePhase, 'changeRevokedFirst');
      assert.equal(result.failureProbe, 'private-heading');
      assert.equal(result.status, 'FAILED_OR_PARTIAL');
      assert.equal(result.requests, 159);
      assert.deepEqual(result.authPosts, {
        register: 1,
        login: 2,
        logout: 1,
        'change-password': 1,
        'revoke-all': 0,
      });
      assert.equal(result.completedPosts, 5);
      assert.ok(
        ['anonymous', 'registered', 'loggedOut', 'oldLogin', 'secondBeforeChange', 'passwordChanged'].every(
          (key) => result.checks[key],
        ),
      );
      assert.equal(result.checks.changeRevokedFirst, false);
      assert.equal(result.checks.changeRevokedSecond, false);
      assert.equal(result.checks.allRevoked, false);
      assert.doesNotMatch(JSON.stringify(result), /PRIVATE_SYNTHETIC_HEADING_FAILURE/);
      return;
    }
    await operation;
    assert.deepEqual(actions, [
      'first:register:201',
      'first:logout:204',
      'first:login:200',
      'second:login:200',
      'first:change-password:204',
      'first:login:401',
      'first:login:200',
      'second:login:200',
      'first:revoke-all:204',
    ]);
    assert.equal(contexts.length, 2);
    assert.equal(
      contexts.every((context) => !context.valid),
      true,
    );
    assert.ok(gate.log.anonymous.first >= 2 && gate.log.anonymous.second >= 2);
    assert.equal(gate.log.denied, 0);
    assert.deepEqual(gate.log.dispatched, {
      register: 1,
      login: 5,
      logout: 1,
      'change-password': 1,
      'revoke-all': 1,
    });
    assert.equal(gate.log.requestCounts.document, 23);
    assert.equal(gate.log.me, 23);
    assert.equal(gate.log.requestCounts.asset, coldChunks * 23);
    assert.equal(gate.log.requests, coldChunks * 23 + 55);
    assert.equal(gate.log.requestCountsByContext.first.asset, coldChunks * 15);
    assert.equal(gate.log.requestCountsByContext.second.asset, coldChunks * 8);
    if (coldChunks) {
      assert.ok(gate.log.requests > 150);
      assert.equal(gate.log.requests, 331);
    }
    assert.equal(LIMITS.me, 40);
    assert.equal(LIMITS.wholeMs, 120000);
    gate.finish();
  });

test('runner source has no persistence/capture/private-credential imports; normal UI selectors and hard watchdog remain wired', async () => {
  const source = await readFile(new URL('./batch34-account-native.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(
    source,
    /writeFile|mkdir|storageState|screenshot|tracing\.|recordHar|credentials\.json|\.request\.post|route\.continue|console\.(?:error|warn)/,
  );
  for (const selector of [
    '#demo-auth-email',
    '#demo-auth-password',
    '#account-change-confirmation',
    '#account-change-submit',
    '#account-revoke-confirmation',
    '#account-revoke-submit',
  ])
    assert.ok(source.includes(selector));
  assert.doesNotMatch(source, /delete process\.env|process\.env\.(?:DEBUG|PWDEBUG)\s*=/);
  assert.ok(
    source.indexOf('assertNoCaptureEnvironment(process.env)') <
      source.indexOf('const account = freshAccount()'),
  );
  assert.match(source, /serviceWorkers: 'block'/);
  assert.match(source, /process\.exit\(1\)/);
  assert.match(source, /maxRedirects: 0, maxRetries: 0/);
  assert.equal(typeof browserIo, 'function');
});
