import { randomUUID, createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

export const ORIGIN = 'http://127.0.0.1:8081';
export const LIMITS = Object.freeze({
  wholeMs: 120000,
  journeyMs: 110000,
  closeMs: 4500,
  requestMs: 8000,
  requests: 400,
  assets: 350,
  documents: 40,
  me: 40,
  bodyBytes: 4096,
  assetBytes: 2097152,
});
export const REVIEW_SOURCE = Object.freeze([
  'tests-e2e/batch34-account-native.mjs',
  'tests-e2e/batch34-account-native.test.mjs',
  'tests-e2e/batch26-native-chat.mjs',
  'src/pages/auth/DemoAuthPage.tsx',
  'src/pages/auth/AccountSecurityForm.tsx',
  'src/shared/api/auth/demoAuth.ts',
  'src/shared/api/auth/accountSecurity.ts',
  'src/shared/api/auth/authReturnTo.ts',
]);
const ROOT = new URL('../', import.meta.url);
const REQUEST_KINDS = ['asset', 'document', 'authMe', 'authPost', 'refused'];
const counts = () => Object.fromEntries(REQUEST_KINDS.map((kind) => [kind, 0]));
const UI_PROBES = [
  'none',
  'private-heading',
  'identity-absent',
  'password-absent',
  'revoke-password-absent',
  'fresh-auth-401',
];
const CODES = new Set([
  'CLI',
  'CAPTURE_DEBUG_ENABLED',
  'REVIEW',
  'DEADLINE',
  'ROUTE',
  'BUDGET',
  'BODY',
  'UNARMED',
  'ORDER',
  'STATUS',
  'RESPONSE',
  'TRANSPORT',
  'DISPOSE',
  'PAGE_ERROR',
  'WEBSOCKET',
  'UI',
  'INCOMPLETE',
  'CLEANUP',
]);
const error = (code) =>
  Object.assign(new Error(CODES.has(code) ? code : 'UI'), { finiteCode: CODES.has(code) ? code : 'UI' });
const need = (ok, code) => {
  if (!ok) throw error(code);
};
const exact = (value, keys) =>
  value !== null &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  Object.keys(value).sort().join('|') === [...keys].sort().join('|');
const STEPS = Object.freeze(
  [
    ['register', 'first', 'register', 201, 'old'],
    ['logout', 'first', 'logout', 204],
    ['loginFirst', 'first', 'login', 200, 'old'],
    ['loginBeforeChange', 'second', 'login', 200, 'old'],
    ['changePassword', 'first', 'change-password', 204],
    ['rejectOld', 'first', 'login', 401, 'old'],
    ['loginNewFirst', 'first', 'login', 200, 'new'],
    ['loginAfterChange', 'second', 'login', 200, 'new'],
    ['revokeAll', 'first', 'revoke-all', 204],
  ].map((row) => Object.freeze(row)),
);
export const CHECKS = Object.freeze([
  'anonymous',
  'registered',
  'loggedOut',
  'oldLogin',
  'secondBeforeChange',
  'passwordChanged',
  'changeRevokedFirst',
  'changeRevokedSecond',
  'oldRejected',
  'newLogin',
  'secondAfterChange',
  'allRevoked',
  'revokeFirst',
  'revokeSecond',
]);

export function parseArgs(args) {
  if (!args.length) return { mode: 'inert' };
  if (args.length === 1 && args[0] === '--fingerprint') return { mode: 'fingerprint' };
  need(
    args.length === 5 &&
      args[0] === '--run-once' &&
      args[1] === '--ack-coordinator-account-go' &&
      args[2] === '--ack-disposable-account-retained' &&
      args[3] === '--review-sha256' &&
      /^[a-f0-9]{64}$/.test(args[4]),
    'CLI',
  );
  return { mode: 'run', review: args[4], coordinatorGo: true, retainAccount: true };
}
// Same assertNoCaptureEnvironment policy as batch26-native-chat.mjs (parity-tested).
// Do not import its module here: its dependency graph imports Playwright eagerly.
export function assertNoCaptureEnvironment(environment) {
  need(
    ['DEBUG', 'PWDEBUG', 'NODE_DEBUG', 'NODE_DEBUG_NATIVE'].every(
      (key) => !environment[key] || environment[key] === '0',
    ),
    'CAPTURE_DEBUG_ENABLED',
  );
}
export async function fingerprint() {
  const rows = [];
  for (const path of REVIEW_SOURCE) {
    const bytes = await readFile(new URL(path, ROOT));
    need(bytes.length <= LIMITS.assetBytes, 'REVIEW');
    rows.push({ path, sha256: createHash('sha256').update(bytes).digest('hex') });
  }
  return createHash('sha256').update(JSON.stringify(rows)).digest('hex');
}
export function freshAccount() {
  assertNoCaptureEnvironment(process.env);
  return {
    email: `batch34-${randomUUID()}@example.invalid`,
    old: `Old-${randomUUID()}-a!`,
    new: `New-${randomUUID()}-b!`,
  };
}
export function classify(url, method, redirected = false) {
  try {
    const u = new URL(url);
    if (
      redirected ||
      u.origin !== ORIGIN ||
      u.href !== url ||
      u.username ||
      u.password ||
      u.search ||
      u.hash ||
      /%|\\|\/\./.test(url)
    )
      return null;
    if (method === 'GET' && u.pathname === '/api/v1/auth/me') return 'me';
    if (
      method === 'POST' &&
      ['register', 'login', 'logout', 'change-password', 'revoke-all'].some(
        (x) => u.pathname === `/api/v1/auth/${x}`,
      )
    )
      return u.pathname.slice('/api/v1/auth/'.length);
    if (method === 'GET' && ['/', '/account', '/login', '/register'].includes(u.pathname)) return 'document';
    if (
      method === 'GET' &&
      (['/favicon.ico', '/favicon.svg'].includes(u.pathname) ||
        /^\/assets\/[A-Za-z0-9_/-]+\.[A-Za-z0-9.]+$/.test(u.pathname))
    )
      return 'asset';
  } catch {
    /* Fixed refusal only. */
  }
  return null;
}

export class AccountGate {
  #account;
  #identity;
  #pending;
  #index = 0;
  #now;
  #expires;
  #reject;
  #closed = false;
  constructor(account, { now = () => performance.now(), durationMs = LIMITS.journeyMs } = {}) {
    need(
      exact(account, ['email', 'old', 'new']) &&
        /^batch34-[a-f0-9-]{36}@example\.invalid$/.test(account.email) &&
        ['old', 'new'].every(
          (k) =>
            typeof account[k] === 'string' &&
            Buffer.byteLength(account[k]) >= 12 &&
            Buffer.byteLength(account[k]) <= 128,
        ) &&
        account.old !== account.new,
      'BODY',
    );
    need(Number.isFinite(durationMs) && durationMs > 0 && durationMs <= LIMITS.journeyMs, 'DEADLINE');
    this.#account = { ...account };
    this.#now = now;
    this.#expires = now() + durationMs;
    this.failure = new Promise((_, reject) => {
      this.#reject = reject;
    });
    void this.failure.catch(() => {});
    this.log = {
      failure: null,
      requests: 0,
      requestCounts: counts(),
      requestCountsByContext: { first: counts(), second: counts() },
      transportCounts: counts(),
      budgetFailure: 'NONE',
      phase: 'setup',
      uiProbe: 'none',
      failurePhase: 'setup',
      failureProbe: 'none',
      denied: 0,
      dispatched: { register: 0, login: 0, logout: 0, 'change-password': 0, 'revoke-all': 0 },
      me: 0,
      inFlight: 0,
      completedPosts: 0,
      anonymous: { first: 0, second: 0 },
      checks: Object.fromEntries(CHECKS.map((key) => [key, false])),
      cleanup: false,
    };
  }
  fail(code) {
    if (!this.log.failure) {
      this.log.failure = CODES.has(code) ? code : 'UI';
      this.log.failurePhase = CHECKS.includes(this.log.phase) ? this.log.phase : 'setup';
      this.log.failureProbe = UI_PROBES.includes(this.log.uiProbe) ? this.log.uiProbe : 'none';
      this.#reject(error(this.log.failure));
    }
    return error(this.log.failure);
  }
  live() {
    if (this.#now() >= this.#expires) throw this.fail('DEADLINE');
    if (this.log.failure) throw error(this.log.failure);
    need(!this.#closed, 'INCOMPLETE');
  }
  remaining() {
    this.live();
    return Math.max(1, Math.min(LIMITS.requestMs, Math.floor(this.#expires - this.#now())));
  }
  arm(name) {
    this.live();
    need(!this.#pending && this.log.inFlight === 0 && STEPS[this.#index]?.[0] === name, 'ORDER');
    this.#pending = STEPS[this.#index];
  }
  expectedBody(step) {
    const a = this.#account,
      kind = step[2];
    if (kind === 'register' || kind === 'login') return { email: a.email, password: a[step[4]] };
    if (kind === 'change-password') return { currentPassword: a.old, newPassword: a.new };
    if (kind === 'revoke-all') return { currentPassword: a.new };
    return {};
  }
  requestKind(kind) {
    return kind === 'me'
      ? 'authMe'
      : kind === 'asset' || kind === 'document'
        ? kind
        : ['register', 'login', 'logout', 'change-password', 'revoke-all'].includes(kind)
          ? 'authPost'
          : 'refused';
  }
  recordRequest(label, kind) {
    this.live();
    need(label === 'first' || label === 'second', 'ROUTE');
    const bucket = this.requestKind(kind);
    this.log.requests++;
    this.log.requestCounts[bucket]++;
    this.log.requestCountsByContext[label][bucket]++;
    if (kind === 'me') this.log.me++;
    // Count the rejected boundary too. Unknown URLs/values never enter telemetry.
    const limit =
      this.log.requests > LIMITS.requests
        ? 'TOTAL'
        : this.log.requestCounts.asset > LIMITS.assets
          ? 'ASSETS'
          : this.log.requestCounts.document > LIMITS.documents
            ? 'DOCUMENTS'
            : this.log.me > LIMITS.me
              ? 'AUTH_ME'
              : null;
    if (limit) {
      this.log.budgetFailure = limit;
      throw error('BUDGET');
    }
  }
  admit(label, kind, body) {
    this.live();
    need(label === 'first' || label === 'second', 'ROUTE');
    if (kind === 'me' || kind === 'asset' || kind === 'document') {
      need(body === null, 'BODY');
      return null;
    }
    const step = this.#pending;
    need(step && step[1] === label && step[2] === kind, 'UNARMED');
    const expected = this.expectedBody(step);
    need(
      exact(body, Object.keys(expected)) && Object.keys(expected).every((key) => body[key] === expected[key]),
      'BODY',
    );
    // Consume BEFORE the first possible transport. An uncertain dispatch can never rearm this step.
    this.#pending = null;
    this.#index++;
    return step;
  }
  validate(label, kind, step, status, value) {
    this.live();
    need(
      kind === 'asset' || kind === 'document'
        ? status === 200
        : kind === 'me'
          ? [200, 401].includes(status)
          : status === step[3],
      'STATUS',
    );
    if (kind === 'asset' || kind === 'document') return;
    if (status === 204) {
      need(value === '', 'RESPONSE');
      return;
    }
    if (status === 401) {
      need(
        exact(value, ['errorCode']) &&
          value.errorCode === (kind === 'login' ? 'INVALID_CREDENTIALS' : 'UNAUTHORIZED'),
        'RESPONSE',
      );
      if (kind === 'me') this.log.anonymous[label]++;
      return;
    }
    need(
      exact(value, ['id', 'email']) &&
        typeof value.id === 'string' &&
        value.id.length > 0 &&
        value.id.length <= 128 &&
        value.email === this.#account.email,
      'RESPONSE',
    );
    if (kind === 'register') {
      need(!this.#identity, 'RESPONSE');
      this.#identity = value.id;
    } else need(this.#identity === value.id, 'RESPONSE');
  }
  check(name) {
    this.live();
    need(CHECKS.includes(name) && !this.log.checks[name], 'ORDER');
    this.log.checks[name] = true;
  }
  finish() {
    this.live();
    need(
      this.#index === STEPS.length &&
        !this.#pending &&
        this.log.completedPosts === STEPS.length &&
        this.log.inFlight === 0 &&
        Object.values(this.log.checks).every(Boolean),
      'INCOMPLETE',
    );
  }
  close() {
    this.#closed = true;
    this.#account = null;
    this.#identity = null;
    this.#pending = null;
  }
}

export async function installRoutes(context, gate, label) {
  await context.route('**/*', async (route) => {
    let response,
      active = false;
    try {
      const req = route.request(),
        kind = classify(req.url(), req.method(), !!req.redirectedFrom());
      gate.recordRequest(label, kind);
      need(kind, 'ROUTE');
      const raw = req.postData();
      let body = null;
      if (req.method() === 'POST') {
        need(
          typeof raw === 'string' &&
            Buffer.byteLength(raw) <= 1024 &&
            (await req.headerValue('content-type')) === 'application/json' &&
            (await req.headerValue('origin')) === ORIGIN,
          'BODY',
        );
        try {
          body = JSON.parse(raw);
        } catch {
          throw error('BODY');
        }
        need(raw === JSON.stringify(body), 'BODY');
      } else need(raw === null, 'BODY');
      const step = gate.admit(label, kind, body);
      gate.log.inFlight++;
      active = true;
      const timeout = gate.remaining();
      if (step) gate.log.dispatched[kind]++;
      gate.log.transportCounts[gate.requestKind(kind)]++;
      response = await route.fetch({ maxRedirects: 0, maxRetries: 0, timeout });
      gate.live();
      const status = response.status();
      need(
        Number.isInteger(status) && response.url() === req.url() && !(status >= 300 && status < 400),
        'STATUS',
      );
      const bytes = await response.body();
      const isStatic = kind === 'asset' || kind === 'document';
      need(bytes.length <= (isStatic ? LIMITS.assetBytes : LIMITS.bodyBytes), 'RESPONSE');
      let value = bytes.toString('utf8');
      if (!isStatic && status !== 204) {
        need(/^application\/json(?:;|$)/i.test(response.headers()['content-type'] ?? ''), 'RESPONSE');
        try {
          value = JSON.parse(value);
        } catch {
          throw error('RESPONSE');
        }
      }
      gate.validate(label, kind, step, status, value);
      await route.fulfill({ response });
      gate.live();
      if (step) gate.log.completedPosts++;
    } catch (cause) {
      gate.log.denied++;
      gate.fail(cause?.finiteCode ?? 'TRANSPORT');
      await route.abort().catch(() => {
        gate.fail('TRANSPORT');
      });
    } finally {
      if (response)
        await response.dispose().catch(() => {
          gate.fail('DISPOSE');
        });
      if (active) gate.log.inFlight--;
    }
  });
  await context.routeWebSocket('**/*', (socket) => {
    gate.log.denied++;
    gate.fail('WEBSOCKET');
    socket.close();
  });
}

export async function journey(io, gate) {
  const check = async (name, action) => {
    gate.live();
    gate.log.phase = name;
    gate.log.uiProbe = 'none';
    await action();
    await settle(gate);
    gate.check(name);
  };
  const mutate = async (step, action) => {
    await settle(gate);
    gate.arm(step);
    await action();
    gate.live();
  };
  await check('anonymous', () => io.anonymous('first'));
  await check('registered', () => mutate('register', () => io.register()));
  await check('loggedOut', () => mutate('logout', () => io.logout()));
  await check('oldLogin', () => mutate('loginFirst', () => io.login('first', 'old', 200)));
  await check('secondBeforeChange', () => mutate('loginBeforeChange', () => io.login('second', 'old', 200)));
  await check('passwordChanged', () => mutate('changePassword', () => io.changePassword()));
  await check('changeRevokedFirst', () => io.revoked('first'));
  await check('changeRevokedSecond', () => io.revoked('second'));
  await check('oldRejected', () => mutate('rejectOld', () => io.login('first', 'old', 401)));
  await check('newLogin', () => mutate('loginNewFirst', () => io.login('first', 'new', 200)));
  await check('secondAfterChange', () => mutate('loginAfterChange', () => io.login('second', 'new', 200)));
  await check('allRevoked', () => mutate('revokeAll', () => io.revokeAll()));
  await check('revokeFirst', () => io.revoked('first'));
  await check('revokeSecond', () => io.revoked('second'));
  gate.finish();
}

export function browserIo(browser, expect, gate, account) {
  const pages = new Map();
  async function page(label) {
    if (pages.has(label)) return pages.get(label);
    const context = await browser.newContext({
      viewport: { width: 1280, height: 900 },
      serviceWorkers: 'block',
      acceptDownloads: false,
    });
    await installRoutes(context, gate, label);
    const p = await context.newPage();
    p.setDefaultTimeout(6000);
    p.setDefaultNavigationTimeout(8000);
    p.on('pageerror', () => gate.fail('PAGE_ERROR'));
    pages.set(label, p);
    return p;
  }
  const go = async (p, path) => {
    gate.live();
    await p.goto(ORIGIN + path, { waitUntil: 'domcontentloaded', timeout: gate.remaining() });
  };
  const identity = async (p) => {
    await expect(p.locator('.demo-auth__email')).toHaveText(account.email);
  };
  const privateGate = async (p) => {
    gate.log.uiProbe = 'private-heading';
    await expect(p.getByRole('heading', { name: 'Войдите в свой аккаунт', exact: true })).toBeVisible();
    gate.log.uiProbe = 'identity-absent';
    await expect(p.locator('.demo-auth__email')).toHaveCount(0);
    gate.log.uiProbe = 'password-absent';
    await expect(p.locator('#account-current-password')).toHaveCount(0);
    gate.log.uiProbe = 'revoke-password-absent';
    await expect(p.locator('#account-revoke-password')).toHaveCount(0);
  };
  const submit = async (p, kind, status, click) => {
    const response = p.waitForResponse(
      (r) => r.url() === `${ORIGIN}/api/v1/auth/${kind}` && r.request().method() === 'POST',
      { timeout: gate.remaining() },
    );
    await Promise.all([response.then((r) => need(r.status() === status, 'STATUS')), click()]);
    // Fulfillment can reach the browser before the route's final dispose microtask.
    await settle(gate);
  };
  const login = async (label, password, status) => {
    const p = await page(label);
    await go(p, '/login');
    await p.locator('#demo-auth-email').fill(account.email);
    await p.locator('#demo-auth-password').fill(account[password]);
    await submit(p, 'login', status, () => p.getByRole('button', { name: 'Войти', exact: true }).click());
    if (status === 200) {
      await go(p, '/account');
      await identity(p);
    } else await expect(p.getByRole('alert')).toBeVisible();
  };
  return {
    async anonymous(label) {
      const p = await page(label);
      await go(p, '/account');
      await privateGate(p);
    },
    async register() {
      const p = await page('first');
      await go(p, '/register');
      await p.locator('#demo-auth-email').fill(account.email);
      await p.locator('#demo-auth-password').fill(account.old);
      await submit(p, 'register', 201, () =>
        p.getByRole('button', { name: 'Создать аккаунт', exact: true }).click(),
      );
      await go(p, '/account');
      await identity(p);
    },
    async logout() {
      const p = await page('first');
      await submit(p, 'logout', 204, () =>
        p.getByRole('button', { name: 'Выйти из аккаунта', exact: true }).click(),
      );
      await go(p, '/account');
      await privateGate(p);
    },
    login,
    async changePassword() {
      const p = await page('first');
      await go(p, '/account');
      await identity(p);
      await p.locator('#account-password-section').click();
      await p.locator('#account-current-password').fill(account.old);
      await p.locator('#account-new-password').fill(account.new);
      await p.locator('#account-confirm-password').fill(account.new);
      await p.locator('#account-change-confirmation').check();
      await submit(p, 'change-password', 204, () => p.locator('#account-change-submit').click());
      await expect(p).toHaveURL(ORIGIN + '/login');
    },
    async revokeAll() {
      const p = await page('first');
      await go(p, '/account');
      await identity(p);
      await p.locator('#account-revoke-section').click();
      await p.locator('#account-revoke-password').fill(account.new);
      await p.locator('#account-revoke-confirmation').check();
      await submit(p, 'revoke-all', 204, () => p.locator('#account-revoke-submit').click());
      await expect(p).toHaveURL(ORIGIN + '/login');
    },
    async revoked(label) {
      const p = await page(label),
        before = gate.log.anonymous[label];
      await go(p, '/account');
      await p.reload({ waitUntil: 'domcontentloaded', timeout: gate.remaining() });
      await privateGate(p);
      await settle(gate);
      gate.log.uiProbe = 'fresh-auth-401';
      need(gate.log.anonymous[label] > before, 'RESPONSE');
    },
  };
}
async function settle(gate) {
  const until = performance.now() + 1000;
  while (gate.log.inFlight) {
    gate.live();
    need(performance.now() < until, 'TRANSPORT');
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  gate.live();
}
export function aggregate(gate) {
  const l = gate.log;
  return {
    status:
      !l.failure && l.cleanup && Object.values(l.checks).every(Boolean)
        ? 'NATIVE_AUTH_PASS'
        : 'FAILED_OR_PARTIAL',
    failure: l.failure,
    checks: { ...l.checks },
    requests: l.requests,
    requestCounts: { ...l.requestCounts },
    requestCountsByContext: {
      first: { ...l.requestCountsByContext.first },
      second: { ...l.requestCountsByContext.second },
    },
    transportCounts: { ...l.transportCounts },
    apiRequests: l.requestCounts.authMe + l.requestCounts.authPost,
    budgetFailure: ['NONE', 'TOTAL', 'ASSETS', 'DOCUMENTS', 'AUTH_ME'].includes(l.budgetFailure)
      ? l.budgetFailure
      : 'NONE',
    failurePhase: CHECKS.includes(l.failurePhase) ? l.failurePhase : 'setup',
    failureProbe: UI_PROBES.includes(l.failureProbe) ? l.failureProbe : 'none',
    denied: l.denied,
    authPosts: { ...l.dispatched },
    completedPosts: l.completedPosts,
    cleanup: l.cleanup,
    providerPosts: 0,
    scanPosts: 0,
    credentialsPersisted: false,
    existingCredentialsRead: false,
    accountRetained: l.checks.registered,
    accountCreationMayHaveCommitted: l.dispatched.register > 0,
    deletionAttempted: false,
  };
}
export async function runOnce(options) {
  need(
    exact(options, ['mode', 'review', 'coordinatorGo', 'retainAccount']) &&
      options.mode === 'run' &&
      options.coordinatorGo === true &&
      options.retainAccount === true &&
      /^[a-f0-9]{64}$/.test(options.review),
    'CLI',
  );
  assertNoCaptureEnvironment(process.env);
  need((await fingerprint()) === options.review, 'REVIEW');
  assertNoCaptureEnvironment(process.env);
  const account = freshAccount(),
    gate = new AccountGate(account);
  let browser;
  const timeout = setTimeout(() => gate.fail('DEADLINE'), LIMITS.journeyMs);
  try {
    const operation = async () => {
      assertNoCaptureEnvironment(process.env);
      const { chromium, expect } = await import('@playwright/test');
      gate.live();
      browser = await chromium.launch({
        headless: true,
        timeout: 10000,
        args: [
          '--disable-background-networking',
          '--disable-component-update',
          '--no-first-run',
          '--proxy-server=http://native-denied.invalid:1',
          '--proxy-bypass-list=<-loopback>;127.0.0.1:8081',
          '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1',
        ],
      });
      gate.live();
      await journey(browserIo(browser, expect, gate, account), gate);
    };
    await Promise.race([operation(), gate.failure]);
  } catch (cause) {
    gate.fail(cause?.finiteCode ?? 'UI');
  } finally {
    clearTimeout(timeout);
    gate.close();
    if (browser) {
      let closeTimer;
      try {
        await Promise.race([
          browser.close(),
          new Promise((_, reject) => {
            closeTimer = setTimeout(() => reject(error('CLEANUP')), LIMITS.closeMs);
          }),
        ]);
        gate.log.cleanup = true;
      } catch {
        gate.fail('CLEANUP');
      } finally {
        clearTimeout(closeTimer);
      }
    }
    account.email = '';
    account.old = '';
    account.new = '';
  }
  return aggregate(gate);
}
async function main() {
  let watchdog;
  try {
    const options = parseArgs(process.argv.slice(2));
    if (options.mode === 'inert') {
      console.log(JSON.stringify({ status: 'INERT', browserStarted: false }));
      return;
    }
    if (options.mode === 'fingerprint') {
      console.log(await fingerprint());
      return;
    }
    watchdog = setTimeout(() => {
      console.log(
        JSON.stringify({
          status: 'FAILED_OR_PARTIAL',
          failure: 'DEADLINE',
          cleanup: false,
          paidRetryAuthorized: false,
        }),
      );
      process.exit(1);
    }, LIMITS.wholeMs);
    const result = await runOnce(options);
    console.log(JSON.stringify(result));
    process.exitCode = result.status === 'NATIVE_AUTH_PASS' ? 0 : 1;
  } catch (cause) {
    console.log(
      JSON.stringify({ status: 'REFUSED', failure: CODES.has(cause?.finiteCode) ? cause.finiteCode : 'UI' }),
    );
    process.exitCode = 1;
  } finally {
    // Keep the hard stop available if failed cleanup leaves Playwright handles alive,
    // but do not keep an otherwise clean process running just for this timer.
    watchdog?.unref();
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
