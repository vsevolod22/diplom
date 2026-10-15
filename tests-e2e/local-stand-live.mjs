// Run: node tests-e2e/local-stand-live.mjs
// Existing projectdip-local-full only: no server/process/container lifecycle or config reads.
// Creates one retained synthetic account and at most one retained, real worker scan.
// Credentials exist only in memory. No screenshots, traces, storage state or raw reports are saved.
// Sanitized receipt: test-results/local-stand-live.json (gitignored).
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { chromium, expect as baseExpect } from '@playwright/test';

const origin = 'http://127.0.0.1:8080';
const scansPath = '/api/v1/browser/scans';
const receiptPath = new URL('../test-results/local-stand-live.json', import.meta.url);
const expect = baseExpect.configure({ timeout: 8000 });
const started = Date.now();
const email = `live-smoke-${randomUUID()}@example.invalid`;
const password = randomBytes(36).toString('base64url');
const receipt = {
  origin,
  stand: 'projectdip-local-full',
  startedAt: new Date().toISOString(),
  passed: false,
  checks: [],
  layout: [],
  blockedExternalRequests: 0,
  blockedMutations: [],
  pageErrorCount: 0,
  scanLaunchRequests: 0,
};
let browser;
let phase = 'browser launch';
let permittedIntent;
let stopping = false;
const pageErrors = [];
const contexts = [];
const terminal = ['completed', 'partial', 'failed', 'cancelled'];
const sanitize = (value) =>
  String(value)
    .split(password)
    .join('[redacted]')
    .split(email)
    .join('[synthetic-account]')
    .replace(/(?:Bearer\s+)[^\s"']+/gi, 'Bearer [redacted]')
    .replace(/demo_session=[^\s;"']+/g, 'demo_session=[redacted]');
const check = (name) => receipt.checks.push(name);
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function newPage() {
  const context = await browser.newContext({
    viewport: { width: 1280, height: 1000 },
    reducedMotion: 'reduce',
    serviceWorkers: 'block',
  });
  contexts.push(context);
  await context.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.origin !== origin) {
      receipt.blockedExternalRequests++;
      return route.abort('blockedbyclient');
    }
    const method = request.method();
    if (['GET', 'HEAD'].includes(method)) return route.continue();
    // Permit real auth + read-only eligibility; forbid every LLM/runtime/other mutation.
    if (
      method === 'POST' &&
      [
        '/api/v1/auth/register',
        '/api/v1/auth/login',
        '/api/v1/auth/logout',
        `${scansPath}/images/eligibility`,
      ].includes(url.pathname)
    )
      return route.continue();
    if (method === 'POST' && url.pathname === scansPath) {
      const intent = request.postDataJSON();
      if (
        permittedIntent &&
        receipt.scanLaunchRequests === 0 &&
        intent.scope === 'image' &&
        intent.imageReference === permittedIntent.imageReference &&
        JSON.stringify(intent.checks) === JSON.stringify(permittedIntent.checks)
      ) {
        receipt.scanLaunchRequests++;
        return route.continue();
      }
    }
    receipt.blockedMutations.push(`${method} ${url.pathname}`);
    return route.abort('blockedbyclient');
  });
  await context.routeWebSocket('**/*', (socket) => {
    // This UI uses HTTP/SSE, not WebSockets; don't allow a separate egress channel.
    socket.close();
  });
  context.on('page', (page) => {
    page.setDefaultTimeout(8000);
    page.setDefaultNavigationTimeout(15000);
    page.on('pageerror', (error) => pageErrors.push(error));
  });
  return { context, page: await context.newPage() };
}

// Runs HTTP in the actual isolated browser, with its own HttpOnly session and routing guard.
async function http(page, path, body, timeoutMs = 10000) {
  assert.ok(path.startsWith('/api/v1/') && !path.startsWith('//'), 'HTTP path must stay on this origin');
  return page.evaluate(
    async ({ path, body, timeoutMs }) => {
      const response = await fetch(path, {
        method: body === undefined ? 'GET' : 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        signal: AbortSignal.timeout(timeoutMs),
        ...(body === undefined
          ? {}
          : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
      });
      const value = await response.json().catch(() => null);
      return { status: response.status, value };
    },
    { path, body, timeoutMs },
  );
}

function statusIs(response, expected, operation) {
  const code = response.value?.errorCode;
  assert.equal(
    response.status,
    expected,
    `${operation}: HTTP ${response.status}${typeof code === 'string' && /^[A-Z_]{1,64}$/.test(code) ? ` (${code})` : ''}; expected ${expected}`,
  );
}

async function auth(page, mode) {
  await page.goto(`${origin}/${mode}`);
  await page.getByLabel('Email', { exact: true }).fill(email);
  await page.getByLabel('Пароль', { exact: true }).fill(password);
  const response = page.waitForResponse(
    (r) => r.url() === `${origin}/api/v1/auth/${mode}` && r.request().method() === 'POST',
  );
  const [wire] = await Promise.all([
    response,
    page
      .getByRole('button', { name: mode === 'register' ? 'Создать аккаунт' : 'Войти', exact: true })
      .click(),
  ]);
  assert.equal(wire.status(), mode === 'register' ? 201 : 200, `${mode}: HTTP ${wire.status()}`);
  await expect(page).toHaveURL(`${origin}/account`);
  await expect(page.getByRole('heading', { name: 'Вы вошли', exact: true })).toBeVisible();
  // Avoid assertion diffs containing identity/credential payloads.
  const me = await http(page, '/api/v1/auth/me');
  statusIs(me, 200, 'session');
  assert.ok(
    me.value?.email === email && typeof me.value?.id === 'string',
    'Session belongs to the synthetic account',
  );
  const cookie = (await page.context().cookies(origin)).find((item) => item.name === 'demo_session');
  assert.ok(cookie?.httpOnly && cookie.sameSite === 'Lax', 'Session cookie must be HttpOnly + SameSite=Lax');
}

async function verifyLayout(page, form) {
  const archive = form.getByRole('button', { name: /Alpine · 3.16 \(архивный/ });
  await archive.click();
  await expect(archive).toHaveAttribute('aria-pressed', 'true');
  const reference = await form.locator('input[type="hidden"]').inputValue();
  assert.match(reference, /\/alpine@sha256:[a-f0-9]{64}$/);
  const selected = form.locator('p').filter({ hasText: 'Выбранная цель (сохраняется отдельно от поиска):' });
  await expect(selected).toContainText(reference);
  const consent = form.getByRole('checkbox', { name: /Подтверждаю выбранную цель и область/ });
  await consent.check();
  for (const width of [320, 375, 1280]) {
    await page.setViewportSize({ width, height: 1000 });
    await page.evaluate(() => document.fonts.ready);
    const geometry = await form.evaluate((root) => {
      const failures = [];
      const bounds = root.getBoundingClientRect();
      const css = getComputedStyle(root);
      const left = bounds.left + parseFloat(css.paddingLeft);
      const right = bounds.right - parseFloat(css.paddingRight);
      const fits = (rect, min, max) => rect.left >= min - 1 && rect.right <= max + 1;
      if (!fits(bounds, 0, innerWidth)) failures.push('form exceeds viewport');
      for (let ancestor = root.parentElement; ancestor; ancestor = ancestor.parentElement) {
        if (['hidden', 'clip'].includes(getComputedStyle(ancestor).overflowX))
          failures.push('ancestor masks overflow');
      }
      for (const element of root.querySelectorAll('*')) {
        if (!element.getClientRects().length) continue;
        const style = getComputedStyle(element);
        if (!fits(element.getBoundingClientRect(), left, right)) failures.push('element exceeds form');
        if (
          element.textContent?.trim() &&
          (['hidden', 'clip'].includes(style.overflowX) ||
            style.textOverflow === 'ellipsis' ||
            !['', 'none'].includes(style.getPropertyValue('-webkit-line-clamp')))
        )
          failures.push('clipped text');
      }
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      while (walker.nextNode()) {
        const node = walker.currentNode;
        if (!node.textContent?.trim() || !node.parentElement.getClientRects().length) continue;
        const range = document.createRange();
        range.selectNodeContents(node);
        const parent = node.parentElement.getBoundingClientRect();
        for (const rect of range.getClientRects()) {
          if (!fits(rect, left, right) || !fits(rect, parent.left, parent.right))
            failures.push('text exceeds cell/form');
        }
      }
      return {
        width: innerWidth,
        documentWidth: document.documentElement.scrollWidth,
        formWidth: bounds.width,
        failures: [...new Set(failures)],
      };
    });
    receipt.layout.push(geometry);
    assert.deepEqual(geometry.failures, [], `Archive form layout at ${width}px`);
    assert.ok(geometry.documentWidth <= width, `Document overflow at ${width}px`);
    await expect(archive).toHaveAttribute('aria-pressed', 'true');
    await expect(selected).toContainText(reference);
    await expect(consent).toBeChecked();
  }
  assert.equal(receipt.scanLaunchRequests, 0, 'Archive layout must not launch any scan');
  check('built CSS: selected archive reference + consent fit at 320/375/1280, no clipping/overflow');
}

async function verifyReport(page, scanId, snapshot) {
  const path = `${scansPath}/${scanId}`;
  const secret = await http(page, `${path}/results?limit=50`);
  statusIs(secret, 200, 'persisted Secrets');
  assert.equal(secret.value?.coverage?.outcome, 'checked', 'Secrets report coverage');
  assert.equal(
    secret.value.coverage.findingCount,
    snapshot.perCheck.secret.findingCount,
    'Secrets count identity',
  );
  const sbom = await http(page, `${path}/sbom?limit=50`);
  statusIs(sbom, 200, 'persisted SBOM');
  assert.equal(sbom.value?.outcome, 'checked', 'SBOM report coverage');
  assert.equal(sbom.value.componentCount, snapshot.perCheck.sbom.componentCount, 'SBOM count identity');
  assert.ok(sbom.value.components?.length > 0, 'Actual worker package inventory must be present');
  assert.equal(sbom.value.image, snapshot.imageReference, 'SBOM image identity');
  assert.equal(sbom.value.platform, snapshot.platform, 'SBOM platform identity');
  const secretsSection = page.getByRole('region', { name: 'Результаты Secrets', exact: true });
  const sbomSection = page.getByRole('region', { name: 'Пакеты SBOM', exact: true });
  await expect(secretsSection).toBeVisible();
  await expect(sbomSection).toContainText(`Подтверждённый инвентарь: ${sbom.value.componentCount} пакетов`);
  await expect(sbomSection.locator('ul.scan-report-inventory > li')).toHaveCount(
    Math.min(25, sbom.value.componentCount),
  );
  if (snapshot.perCheck.secret.findingCount === 0)
    await expect(secretsSection).toContainText('0 находок в выполненной проверенной области Secrets');
  else
    await expect(secretsSection.locator('ul.scan-report-inventory > li')).toHaveCount(
      Math.min(25, snapshot.perCheck.secret.findingCount),
    );
  await expect(page.getByRole('alert')).toHaveCount(0);
  if (snapshot.checks.includes('config')) {
    await expect(page.locator('[aria-label="Image config coverage"]')).toContainText(
      'Выполнено (не гарантия безопасности)',
    );
    await expect(page.locator('[aria-label="Image config coverage"]')).toContainText('IMGCFG_USER_ROOT');
  }
}

async function smoke() {
  browser = await chromium.launch({ headless: true, timeout: 15000 });
  if (stopping) {
    await browser.close();
    return;
  }
  const { context, page } = await newPage();
  phase = 'UI registration and session';
  await auth(page, 'register');
  check('UI register → account → real HttpOnly session');
  phase = 'UI logout and login';
  const logout = page.waitForResponse(
    (r) => r.url() === `${origin}/api/v1/auth/logout` && r.request().method() === 'POST',
  );
  const [loggedOut] = await Promise.all([
    logout,
    page.getByRole('button', { name: 'Выйти из аккаунта' }).click(),
  ]);
  assert.equal(loggedOut.status(), 204, 'UI logout HTTP');
  await expect(page).toHaveURL(`${origin}/login`);
  statusIs(await http(page, '/api/v1/auth/me'), 401, 'logged-out session');
  await auth(page, 'login');
  check('UI logout revokes session; UI login restores own session');

  phase = 'built UI archive layout';
  await page.goto(`${origin}/scans/new`);
  const form = page.getByRole('form', { name: 'Параметры скана' });
  await expect(form).toBeVisible();
  await verifyLayout(page, form);

  phase = 'safe target eligibility and UI consent';
  // Prefer 3.20, otherwise the currently rendered, enabled 3.21 button; no heavy retries.
  const target320 = form.getByRole('button', { name: /Alpine · 3\.20\s/ });
  const target =
    (await target320.count()) && (await target320.isEnabled())
      ? target320
      : form.getByRole('button', { name: /Alpine · 3\.21\s/ });
  await expect(target).toBeEnabled();
  await target.click();
  const imageReference = await form.locator('input[type="hidden"]').inputValue();
  assert.match(imageReference, /^registry-1\.docker\.io\/library\/alpine:3\.(20|21)$/);
  const eligibility = await http(page, `${scansPath}/images/eligibility`, {
    imageReference,
    checks: ['secret', 'sbom', 'config'],
  });
  statusIs(eligibility, 200, 'safe image eligibility');
  const allowed = eligibility.value?.allowedCheckSets;
  assert.ok(Array.isArray(allowed), 'Eligibility must expose allowed check sets');
  let checks = ['secret', 'sbom', 'config'];
  if (!eligibility.value.eligible || !allowed.some((set) => JSON.stringify(set) === JSON.stringify(checks))) {
    checks = ['secret', 'sbom'];
    const fallback = await http(page, `${scansPath}/images/eligibility`, { imageReference, checks });
    statusIs(fallback, 200, 'Secrets + SBOM eligibility');
    assert.ok(
      fallback.value?.eligible &&
        fallback.value.allowedCheckSets.some((set) => JSON.stringify(set) === JSON.stringify(checks)),
      'No eligible Secrets + SBOM check set; no scan launched',
    );
    receipt.configSkipped = true;
  }
  await form.getByRole('checkbox', { name: 'Secrets · проверка образа', exact: true }).check();
  await form.getByRole('checkbox', { name: /SBOM · перечень пакетов/ }).check();
  await form
    .getByRole('checkbox', { name: /Image config · OCI User metadata/ })
    .setChecked(checks.includes('config'));
  await expect(form.getByRole('checkbox', { name: /CVE · доступно только/ })).not.toBeChecked();
  const consent = form.getByRole('checkbox', { name: /Подтверждаю выбранную цель и область/ });
  const submit = form.getByRole('button', { name: 'Запустить скан', exact: true });
  await expect(consent).not.toBeChecked();
  await expect(submit).toBeDisabled();
  await consent.check();
  await expect(submit).toBeEnabled();
  permittedIntent = { imageReference, checks };
  receipt.requested = permittedIntent;
  check('server eligibility + safe Alpine selection + explicit check set and consent; CVE excluded');

  phase = 'single UI scan launch';
  const response = page.waitForResponse(
    (r) => r.url() === `${origin}${scansPath}` && r.request().method() === 'POST',
    { timeout: 30000 },
  );
  const [wire] = await Promise.all([response, submit.click()]);
  const value = await wire.json();
  statusIs({ status: wire.status(), value }, 202, 'scan launch (not retried)');
  assert.match(value.scanId ?? '', /^[a-f0-9-]{36}$/);
  receipt.scanId = value.scanId;
  receipt.url = `${origin}/scans/${value.scanId}`;
  const path = `${scansPath}/${value.scanId}`;
  await expect(page).toHaveURL(receipt.url);
  check('UI POST 202 receipt → own detail route');

  phase = 'real worker terminal status (maximum 180s, no relaunch)';
  const deadline = Date.now() + 180000;
  let snapshot;
  do {
    const result = await http(page, path, undefined, Math.max(1, Math.min(10000, deadline - Date.now())));
    statusIs(result, 200, 'worker status');
    snapshot = result.value;
    receipt.state = snapshot.state;
    receipt.perCheck = Object.fromEntries(
      Object.entries(snapshot.perCheck ?? {}).map(([name, item]) => [
        name,
        item &&
          Object.fromEntries(
            [
              'outcome',
              'findingCount',
              'componentCount',
              'scannerVersion',
              'checkedAt',
              'reason',
              'errorCode',
            ]
              .filter((key) => item[key] !== undefined)
              .map((key) => [key, item[key]]),
          ),
      ]),
    );
    if (terminal.includes(snapshot.state)) break;
    await pause(Math.min(2000, Math.max(0, deadline - Date.now())));
  } while (Date.now() < deadline);
  assert.ok(terminal.includes(snapshot.state), 'Worker did not reach terminal status within 180s');
  assert.equal(
    snapshot.state,
    'completed',
    `Worker terminal ${snapshot.state}: ${JSON.stringify(receipt.perCheck)}`,
  );
  assert.equal(snapshot.scanId, value.scanId, 'Worker scan identity');
  assert.deepEqual(snapshot.checks, checks, 'Worker requested check set');
  assert.match(snapshot.digest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(snapshot.platform, 'linux/amd64');
  for (const name of checks)
    assert.equal(snapshot.perCheck?.[name]?.outcome, 'checked', `${name}: worker outcome`);
  assert.ok(
    Number.isInteger(snapshot.perCheck.secret.findingCount) && snapshot.perCheck.secret.findingCount >= 0,
    'Confirmed Secrets count, including zero',
  );
  assert.ok(snapshot.perCheck.sbom.componentCount > 0, 'Confirmed positive SBOM inventory');
  // Legacy Secrets status has scannerVersion but no required checkedAt; SBOM has both.
  for (const name of ['secret', 'sbom']) {
    assert.ok(snapshot.perCheck[name].scannerVersion, `${name}: real worker scanner version`);
  }
  assert.ok(snapshot.perCheck.sbom.checkedAt, 'SBOM: real worker completion timestamp');
  if (checks.includes('config')) {
    assert.equal(snapshot.config?.config?.outcome, 'checked', 'Image config evidence checked');
    assert.ok(snapshot.config.completedRuleIds.includes('IMGCFG_USER_ROOT'), 'Config rule actually executed');
    receipt.configChecked = true;
    receipt.configFindingCount = snapshot.config.findings.length;
  }
  check(
    'real worker completed; Secrets checked with confirmed count; SBOM checked with inventory; optional config evidence',
  );

  phase = 'persisted report reload';
  await page.reload();
  await verifyReport(page, value.scanId, snapshot);
  const llm = await http(page, `${path}/llm/context`);
  statusIs(llm, 200, 'read-only LLM context');
  assert.equal(llm.value?.enabled, false, 'LLM must remain disabled on this stand');
  check('report survives reload, real Secrets/SBOM endpoints and rendered rows match; LLM disabled');
  phase = 'persisted list and fresh browser session';
  await page.getByRole('link', { name: 'К списку', exact: true }).click();
  await expect(page.locator(`a[href="/scans/${value.scanId}"]`)).toBeVisible();
  await context.close();
  const fresh = await newPage();
  await fresh.page.goto(`${origin}/login`);
  statusIs(await http(fresh.page, path), 401, 'anonymous scan isolation');
  // Public proxy must not expose the internal JWT route, with or without browser cookies.
  statusIs(await http(fresh.page, `/api/v1/scans/${value.scanId}`), 404, 'hidden internal JWT route');
  await auth(fresh.page, 'login');
  await fresh.page.goto(`${origin}/scans`);
  const detailLink = fresh.page.locator(`a[href="/scans/${value.scanId}"]`);
  await expect(detailLink).toBeVisible();
  await detailLink.click();
  await verifyReport(fresh.page, value.scanId, snapshot);
  const persisted = await http(fresh.page, path);
  statusIs(persisted, 200, 'fresh-session persisted scan');
  assert.deepEqual(
    persisted.value,
    snapshot,
    'Persisted worker evidence is unchanged after new-context login',
  );
  check(
    'list persistence + fresh context UI login + same persisted report; anonymous 401/internal JWT route 404',
  );
  assert.equal(receipt.scanLaunchRequests, 1, 'Exactly one real scan launch');
  assert.deepEqual(receipt.blockedMutations, [], 'No unwanted LLM/runtime/other mutation attempted');
  assert.equal(pageErrors.length, 0, 'No browser pageerrors in either isolated context');
  check('no pageerrors; no LLM generation; browser egress limited to the stand origin');
  receipt.passed = true;
}

let interrupt;
const interrupted = new Promise((_, reject) => {
  interrupt = (reason) => reject(new Error(reason));
});
const timeout = setTimeout(() => interrupt('Global smoke deadline: 290s'), 290000);
const hardStop = setTimeout(() => process.exit(1), 299000);
const onSignal = () => interrupt('Smoke interrupted; stand left untouched');
process.once('SIGINT', onSignal);
process.once('SIGTERM', onSignal);
try {
  await Promise.race([smoke(), interrupted]);
} catch (error) {
  receipt.error = { phase, message: sanitize(error instanceof Error ? error.message : error).slice(0, 4000) };
  process.exitCode = 1;
} finally {
  stopping = true;
  clearTimeout(timeout);
  await Promise.allSettled(contexts.map((context) => context.close()));
  await browser?.close();
  receipt.pageErrorCount = pageErrors.length;
  receipt.elapsedMs = Date.now() - started;
  receipt.finishedAt = new Date().toISOString();
  // Allowlist-only receipt; never serialize auth payloads, cookies, credentials or full report bodies.
  await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
  console.log(JSON.stringify(receipt, null, 2));
  clearTimeout(hardStop);
  process.off('SIGINT', onSignal);
  process.off('SIGTERM', onSignal);
}
