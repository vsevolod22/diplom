import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { chromium, expect } from '@playwright/test';

const origin = 'http://127.0.0.1:18080';
const [owner, other, unlisted] = JSON.parse(await readFile(process.argv[2], 'utf8'));
const digest = 'sha256:0dcc88822d45581e65ae329f8be769762bf628d3b2bb7d2a077d4aa5c98b30e3';
const image = `registry-1.docker.io/library/nginx@${digest}`;
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext();
const foreign = await browser.newContext();
let phase = 'dom-login';
let createdScanId;
try {
  const page = await context.newPage();
  await page.goto(`${origin}/login`);
  await page.getByLabel('Email', { exact: true }).fill(owner.email);
  await page.getByLabel('Пароль', { exact: true }).fill(owner.password);
  await page.getByRole('button', { name: 'Войти', exact: true }).click();
  await page.waitForURL('**/account');
  phase = 'standalone-http-create';
  const standaloneIntent = { imageReference: image, scope: 'image', checks: ['vuln'], idempotencyKey: randomUUID() };
  const standalonePost = await context.request.post(`${origin}/api/v1/browser/scans`, { headers: { Origin: origin }, data: standaloneIntent });
  assert.equal(standalonePost.status(), 202);
  const standaloneId = (await standalonePost.json()).scanId;
  let standaloneStatus;
  const deadline = Date.now() + 600_000;
  do {
    const response = await context.request.get(`${origin}/api/v1/browser/scans/${standaloneId}`);
    assert.equal(response.status(), 200);
    standaloneStatus = await response.json();
    if (['completed', 'partial', 'failed', 'cancelled'].includes(standaloneStatus.state)) break;
    await new Promise(resolve => setTimeout(resolve, 500));
  } while (Date.now() < deadline);
  assert.equal(standaloneStatus.state, 'completed');
  assert.equal(standaloneStatus.digest, digest);
  assert.equal(standaloneStatus.perCheck.vuln.outcome, 'checked');
  const standaloneResponse = await context.request.get(`${origin}/api/v1/browser/scans/${standaloneId}/vuln`);
  assert.equal(standaloneResponse.status(), 200);
  const standaloneVuln = await standaloneResponse.json();
  assert.ok(standaloneVuln.findingCount > 0);
  assert.equal(standaloneVuln.os.outcome, 'checked');
  assert.equal(standaloneVuln.node.reason, 'NODE_INVENTORY_ABSENT');
  assert.equal(standaloneVuln.scannerVersion, '0.69.3');
  const standaloneReplay = await context.request.post(`${origin}/api/v1/browser/scans`, { headers: { Origin: origin }, data: standaloneIntent });
  assert.equal(standaloneReplay.status(), 202);
  assert.equal((await standaloneReplay.json()).scanId, standaloneId);
  phase = 'readonly-eligibility';
  const eligibility = async (data, headers = { Origin: origin }) => context.request.post(`${origin}/api/v1/browser/scans/images/eligibility`, { headers, data });
  const before = await (await context.request.get(`${origin}/api/v1/browser/scans`)).json();
  for (const checks of [['secret'], ['sbom'], ['vuln'], ['secret','sbom','vuln']]) {
    const response = await eligibility({ imageReference: image, checks }); assert.equal(response.status(), 200);
    const value = await response.json(); assert.equal(value.eligible, true); assert.equal(value.qualificationId, 'nginx-local-0dcc-v1');
  }
  for (const checks of [['config'], ['secret','sbom'], ['sbom','vuln'], ['secret','config']]) {
    const response = await eligibility({ imageReference: image, checks }); assert.equal(response.status(), 200); assert.equal((await response.json()).eligible, false);
    const rejected = await context.request.post(`${origin}/api/v1/browser/scans`, { headers: { Origin: origin }, data: { ...standaloneIntent, checks } });
    assert.equal(rejected.status(), 400); // policy BEFORE even a known replay key
  }
  assert.equal((await eligibility({ imageReference: image, checks: ['secret'], scannable: true })).status(), 400);
  assert.equal((await eligibility({ imageReference: image, checks: ['secret'] }, { Origin: 'https://foreign.invalid' })).status(), 403);
  const after = await (await context.request.get(`${origin}/api/v1/browser/scans`)).json(); assert.equal(after.scans.length, before.scans.length);
  phase = 'dom-search';
    await page.goto(`${origin}/scans/new`);
  await page.getByLabel('Поиск по доступным образам').fill('nginx');
  const selected = page.getByRole('group', { name: 'Выбор образа' }).getByRole('button').filter({ hasText: image });
  await expect(selected).toBeEnabled({ timeout: 30_000 });
  phase = 'dom-select';
    await selected.click();
  await page.getByRole('radio', { name: 'Secrets + SBOM + CVE', exact: true }).check();
  await expect(page.getByText('Image config и недоказанные сочетания для этого профиля недоступны.')).toBeVisible();
  await page.reload();
  await expect(selected).toHaveAttribute('aria-pressed', 'true');
  await expect(selected).toBeEnabled({ timeout: 30_000 });
  await page.getByRole('radio', { name: 'Secrets + SBOM + CVE', exact: true }).check();
  await page.getByLabel('Подтверждаю выбранную цель и область:', { exact: false }).check();
  phase = 'dom-create';
    const posted = page.waitForResponse(response => response.url() === `${origin}/api/v1/browser/scans` && response.request().method() === 'POST', { timeout: 60_000 });
  await page.getByRole('button', { name: 'Запустить скан', exact: true }).click();
  const receipt = await posted;
  assert.equal(receipt.status(), 202);
  const intent = receipt.request().postDataJSON();
  assert.equal(intent.imageReference, image);
  assert.deepEqual(intent.checks, ['secret', 'sbom', 'vuln']);
  const { scanId } = await receipt.json();
    createdScanId = scanId;
  await page.waitForURL(`**/scans/${scanId}`);
  phase = 'dom-report';
    const cves = page.getByRole('region', { name: 'Результаты CVE' });
  await expect(cves).toContainText('Находок в проверенной области:', { timeout: 300_000 });
  const get = async (suffix = '') => {
    const response = await context.request.get(`${origin}/api/v1/browser/scans/${scanId}${suffix}`);
    assert.equal(response.status(), 200); assert.ok(response.headers()['cache-control']?.split(',').map(value => value.trim()).includes('no-store'));
    return response.json();
  };
  phase = 'http-evidence';
    const status = await get(), vuln = await get('/vuln'), sbom = await get('/sbom');
  phase = 'evidence-status';
    assert.equal(status.state, 'completed'); assert.equal(status.digest, digest); assert.equal(status.imageReference, image);
  assert.equal(status.imageProfile.qualified, true);
    assert.equal(status.executedQualification.qualificationId, 'nginx-local-0dcc-v1');
    assert.equal(status.executedQualification.scannerVersion, '0.69.3');
  phase = 'evidence-checks';
    for (const check of ['secret', 'sbom', 'vuln']) assert.equal(status.perCheck[check].outcome, 'checked');
  phase = 'evidence-vuln';
    assert.equal(vuln.image, image); assert.equal(vuln.os.outcome, 'checked');
  assert.equal(vuln.node.outcome, 'unsupported'); assert.equal(vuln.node.reason, 'NODE_INVENTORY_ABSENT');
  assert.ok(vuln.findingCount > 0); assert.ok(vuln.findings.length > 0);
  phase = 'evidence-sbom';
    assert.equal(sbom.image, image); assert.equal(sbom.componentCount, 72); assert.equal(sbom.os.version, '3.23.3');
  phase = 'dom-cve-evidence';
    await expect(cves).toContainText(vuln.findings[0].cveId);
  await expect(cves).toContainText('NODE_INVENTORY_ABSENT');
  await expect(cves).toContainText(vuln.db.manifestDigest);
  phase = 'dom-sbom-evidence';
  await expect(page.getByRole('region', { name: 'Пакеты SBOM' })).toContainText('72 пакетов');
  await expect(page.locator('.scan-a1__facts')).toContainText(digest);
  phase = 'dom-reload';
    await page.reload();
  await expect(page.getByRole('region', { name: 'Результаты CVE' })).toContainText(vuln.findings[0].cveId, { timeout: 30_000 });
  await expect(page.getByRole('region', { name: 'Пакеты SBOM' })).toContainText('72 пакетов');
  phase = 'http-replay';
    const replay = await context.request.post(`${origin}/api/v1/browser/scans`, { headers: { Origin: origin }, data: intent });
  assert.equal(replay.status(), 202); assert.equal((await replay.json()).scanId, scanId);
    const conflict = await context.request.post(`${origin}/api/v1/browser/scans`, { headers: { Origin: origin }, data: { ...intent, checks: ['vuln'] } });
    assert.equal(conflict.status(), 409);
    const wrongOrigin = await context.request.post(`${origin}/api/v1/browser/scans`, { headers: { Origin: 'https://foreign.invalid' }, data: intent });
    assert.equal(wrongOrigin.status(), 403);
  for (const badImage of [image.replace(digest, `sha256:${'a'.repeat(64)}`), 'registry-1.docker.io/library/nginx:latest', image.replace('nginx', 'node')]) {
    const response = await context.request.post(`${origin}/api/v1/browser/scans`, { headers: { Origin: origin }, data: { ...intent, imageReference: badImage, idempotencyKey: randomUUID() } });
    assert.equal(response.status(), 400);
  }
  phase = 'foreign-login';
    const login = await foreign.request.post(`${origin}/api/v1/auth/login`, { headers: { Origin: origin }, data: other });
  assert.equal(login.status(), 200);
  phase = 'http-ownership';
    for (const suffix of ['', '/results', '/sbom', '/vuln']) assert.equal((await foreign.request.get(`${origin}/api/v1/browser/scans/${scanId}${suffix}`)).status(), 404);
  for (const suffix of ['', '/vuln']) assert.equal((await foreign.request.get(`${origin}/api/v1/browser/scans/${standaloneId}${suffix}`)).status(), 404);
  const foreignReplay = await foreign.request.post(`${origin}/api/v1/browser/scans`, { headers: { Origin: origin }, data: { ...intent, imageReference: image.replace(digest, `sha256:${'b'.repeat(64)}`) } });
  assert.equal(foreignReplay.status(), 400);
  const anonymous = await browser.newContext();
  try {
    assert.equal((await anonymous.request.get(`${origin}/api/v1/browser/scans/${scanId}`)).status(), 401);
    assert.equal((await anonymous.request.post(`${origin}/api/v1/browser/scans/images/eligibility`, { headers: { Origin: origin }, data: { imageReference: image, checks: ['secret'] } })).status(), 401);
    assert.equal((await anonymous.request.post(`${origin}/api/v1/auth/login`, { headers: { Origin: origin }, data: unlisted })).status(), 200);
    assert.equal((await anonymous.request.post(`${origin}/api/v1/browser/scans/images/eligibility`, { headers: { Origin: origin }, data: { imageReference: image, checks: ['secret'] } })).status(), 403);
  } finally { await anonymous.close(); }
  const scans = await context.request.get(`${origin}/api/v1/browser/scans`);
  assert.equal((await scans.json()).scans.length, 2);
  assert.equal(standaloneVuln.db.manifestDigest, vuln.db.manifestDigest);
  phase = 'logout';
  assert.equal((await context.request.post(`${origin}/api/v1/auth/logout`, { headers: { Origin: origin }, data: {} })).status(), 204);
  assert.equal((await context.request.get(`${origin}/api/v1/browser/scans`)).status(), 401);
  console.log(JSON.stringify({ scanIds: [standaloneId, scanId], readonlyEligibility: true, unsupportedSetsBeforeReplay: true, logout: true, actualChromium: true, domLoginSearchSelectionCreateReportReload: true, isolated: true,
    digest, configDigest: status.imageProfile.configDigest, archiveQualified: true, savedCardReload: true, qualification: status.executedQualification, findings: vuln.findingCount, components: sbom.componentCount,
    os: sbom.os, node: vuln.node, dbManifest: vuln.db.manifestDigest, scannerVersion: vuln.scannerVersion,
    standaloneHttpCreated: true, standaloneFindings: standaloneVuln.findingCount,
    replay: true, ownership: true, rejectedOtherPins: true, noSeededScan: true }));
} catch (error) {
  // Deliberately no error message/stack/Playwright trace: those may contain form data.
  let snapshot;
    if (createdScanId) {
      const response = await context.request.get(`${origin}/api/v1/browser/scans/${createdScanId}`).catch(() => null);
      if (response?.ok()) {
        const status = await response.json();
        snapshot = { state: status.state, checks: status.perCheck };
      }
    }
    console.log(JSON.stringify({ failedPhase: phase, snapshot,
    ...(Number.isSafeInteger(error.actual) ? { actualStatus: error.actual } : {}),
    ...(Number.isSafeInteger(error.expected) ? { expectedStatus: error.expected } : {}) }));
  process.exitCode = 1;
} finally { await context.close(); await foreign.close(); await browser.close(); }
