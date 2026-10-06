import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { chromium, expect } from '@playwright/test';
import { parseCurrentStatus, parseCurrentResults, parseCurrentSbom, parseCurrentVuln } from '../../../src/shared/api/scans/scanTransport.ts';

const origin = 'http://127.0.0.1:18080';
const [owner, other] = JSON.parse(await readFile(process.argv[2], 'utf8'));
const mode = process.argv[3], set = process.argv[4];
assert.ok(['positive', 'admission', 'expired', 'malformed-content', 'independent'].includes(mode));
const image = 'registry-1.docker.io/library/nginx@sha256:0dcc88822d45581e65ae329f8be769762bf628d3b2bb7d2a077d4aa5c98b30e3';
const digest = image.split('@')[1];
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext(), foreign = await browser.newContext(), anonymous = await browser.newContext();
let phase = 'login'; let lastStatus; const accepted = []; const evidence = [];
const states = ['queued', 'running', 'completed', 'partial', 'failed', 'cancelled'];
const outcomes = ['checked', 'failed', 'unsupported', 'skipped', 'not_authorized'];
const reasons = ['DB_UNAVAILABLE', 'SCAN_FAILED', 'SCAN_TIMEOUT', 'OS_EOL', 'NODE_INVENTORY_ABSENT'];
const enumValue = (value, allowed) => allowed.includes(value) ? value : 'unclassified';
const statusSnapshot = status => status && ({ state: enumValue(status.state, states),
  perCheck: Object.fromEntries(['secret', 'sbom', 'vuln'].filter(check => status.perCheck?.[check]).map(check =>
    [check, { outcome: enumValue(status.perCheck[check].outcome, outcomes),
      ...(status.perCheck[check].reason ? { reason: enumValue(status.perCheck[check].reason, reasons) } : {}) }])) });
const safe = value => { const text = JSON.stringify(value); for (const canary of [owner.password, other.password,
  'MALFORMED_DB_SECRET_CANARY', 'NOT_A_BOLT_DB_SECRET_CANARY', 'PRIVATE_DB_CANARY']) assert.equal(text.includes(canary), false); return value; };
try {
  const page = await context.newPage();
  if (mode === 'positive') {
    await page.goto(`${origin}/login`); await page.getByLabel('Email', { exact: true }).fill(owner.email);
    await page.getByLabel('Пароль', { exact: true }).fill(owner.password);
    await page.getByRole('button', { name: 'Войти', exact: true }).click(); await page.waitForURL('**/account');
  } else assert.equal((await context.request.post(`${origin}/api/v1/auth/login`, { headers: { Origin: origin }, data: owner })).status(), 200);
  assert.equal((await foreign.request.post(`${origin}/api/v1/auth/login`, { headers: { Origin: origin }, data: other })).status(), 200);
  const make = checks => ({ imageReference: image, scope: 'image', checks, idempotencyKey: randomUUID() });
  const post = intent => context.request.post(`${origin}/api/v1/browser/scans`, { headers: { Origin: origin }, data: intent });
  async function rejectedDom() {
    phase = 'rejected-dom-search'; await page.goto(`${origin}/scans/new`);
    await page.getByLabel('Поиск по доступным образам').fill('nginx');
    const selected = page.getByRole('group', { name: 'Выбор образа' }).getByRole('button').filter({ hasText: image });
    await expect(selected).toBeEnabled({ timeout: 30_000 }); await selected.click();
    await page.getByLabel('SBOM · перечень пакетов, не проверка уязвимостей', { exact: true }).check();
    await page.getByLabel('CVE · доступно только при настроенной сервером базе уязвимостей', { exact: true }).check();
    await page.getByLabel('Подтверждаю выбранную цель и область:', { exact: false }).check();
    phase = 'rejected-dom-post';
    const response = page.waitForResponse(r => r.url() === `${origin}/api/v1/browser/scans` && r.request().method() === 'POST', { timeout: 60_000 });
    await page.getByRole('button', { name: 'Запустить скан', exact: true }).click();
    const r = await response; assert.equal(r.status(), 503); safe(await r.json());
    await expect(page).toHaveURL(`${origin}/scans/new`);
    await expect(page.getByRole('button', { name: 'Запустить скан', exact: true })).toBeEnabled();
    safe(await page.locator('body').innerText());
  }
  if (mode === 'admission') {
    for (const checks of [['vuln'], ['secret', 'sbom', 'vuln']]) {
      phase = 'admission-http'; const r = await post(make(checks)); assert.equal(r.status(), 503);
      assert.equal(safe(await r.json()).errorCode, 'SCANNER_UNAVAILABLE');
    }
    await rejectedDom();
    assert.equal((await context.request.get(`${origin}/api/v1/browser/scans`).then(r => r.json())).scans.length, 0);
    console.log(JSON.stringify({ admission503: true, domRejected: true, noOwnerScans: true, noSeededScan: true }));
  } else {
    const checkSets = mode === 'positive' ? [['secret'], ['sbom'], ['vuln'], ['secret', 'sbom', 'vuln']] :
      mode === 'independent' ? [['secret'], ['sbom']] : [set === 'combined' ? ['secret', 'sbom', 'vuln'] : ['vuln']];
    for (const checks of checkSets) {
      phase = 'http-create'; const intent = make(checks), response = await post(intent); assert.equal(response.status(), 202);
      const { scanId } = safe(await response.json()); accepted.push(scanId);
      const admittedAt = Date.now(); console.log(JSON.stringify({ created: scanId, admittedAt, checks }));
      phase = 'terminal'; let status; const deadline = Date.now() + 600_000;
      do {
        const r = await context.request.get(`${origin}/api/v1/browser/scans/${scanId}`); assert.equal(r.status(), 200);
        status = safe(await r.json()); lastStatus = status; parseCurrentStatus(status);
        if (['completed', 'partial', 'failed', 'cancelled'].includes(status.state)) break;
        await new Promise(resolve => setTimeout(resolve, 500));
      } while (Date.now() < deadline);
      const combined = checks.length === 3;
      const failure = mode === 'expired' ? 'DB_UNAVAILABLE' : mode === 'malformed-content' ? 'SCAN_FAILED' : null;
      phase = 'terminal-state'; assert.equal(status.state, failure ? combined ? 'partial' : 'failed' : 'completed');
      phase = 'terminal-identity';
      assert.equal(status.digest, digest); assert.equal(status.platform, 'linux/amd64'); assert.equal(status.imageProfile.qualified, false);
      phase = 'terminal-checks';
      for (const check of checks) assert.equal(status.perCheck[check].outcome, check === 'vuln' && failure ? 'failed' : 'checked');
      for (const check of ['secret', 'sbom', 'vuln'].filter(c => !checks.includes(c))) assert.equal(status.perCheck[check], undefined);
      const result = {};
      phase = 'owner-report-http';
      for (const [suffix, parser, check] of [['/results', parseCurrentResults, 'secret'], ['/sbom', parseCurrentSbom, 'sbom'], ['/vuln', parseCurrentVuln, 'vuln']]) {
        assert.equal((await foreign.request.get(`${origin}/api/v1/browser/scans/${scanId}${suffix}`)).status(), 404);
        assert.equal((await anonymous.request.get(`${origin}/api/v1/browser/scans/${scanId}${suffix}`)).status(), 401);
        if (!checks.includes(check)) { result[suffix] = {}; continue; }
        const r = await context.request.get(`${origin}/api/v1/browser/scans/${scanId}${suffix}`); assert.equal(r.status(), 200);
        assert.ok(r.headers()['cache-control']?.includes('no-store')); const value = safe(await r.json()); parser(value); result[suffix] = value;
        assert.equal((await foreign.request.get(`${origin}/api/v1/browser/scans/${scanId}${suffix}`)).status(), 404);
        assert.equal((await anonymous.request.get(`${origin}/api/v1/browser/scans/${scanId}${suffix}`)).status(), 401);
      }
      assert.equal((await foreign.request.get(`${origin}/api/v1/browser/scans/${scanId}`)).status(), 404);
      assert.equal((await anonymous.request.get(`${origin}/api/v1/browser/scans/${scanId}`)).status(), 401);
      if (checks.includes('sbom')) { assert.equal(result['/sbom'].componentCount, 72); assert.equal(result['/sbom'].os.version, '3.23.3'); }
      if (checks.includes('vuln')) {
        if (failure) { assert.equal(result['/vuln'].errorCode, 'SCAN_FAILED'); assert.equal(result['/vuln'].reason, failure); assert.equal(result['/vuln'].findingCount, undefined); assert.deepEqual(result['/vuln'].findings, []); }
        else { assert.ok(result['/vuln'].findingCount > 0); assert.equal(result['/vuln'].scannerVersion, '0.69.3');
          assert.equal(result['/vuln'].os.outcome, 'checked'); assert.equal(result['/vuln'].node.reason, 'NODE_INVENTORY_ABSENT'); }
      }
      phase = 'owner-dom-reload'; await page.goto(`${origin}/scans/${scanId}`);
      for (let visit = 0; visit < 2; visit++) {
        await expect(page.locator('.scan-a1__facts')).toContainText(digest, { timeout: 30_000 });
        if (checks.includes('sbom')) await expect(page.getByRole('region', { name: 'Пакеты SBOM' })).toContainText('72 пакетов', { timeout: 30_000 });
        if (checks.includes('vuln')) {
          const cves = page.getByRole('region', { name: 'Результаты CVE' });
          await expect(cves).toContainText(failure ?? result['/vuln'].findings[0].cveId, { timeout: 30_000 });
          if (failure) await expect(cves).toContainText('Число уязвимостей неизвестно.');
        }
        safe(await page.locator('body').innerText()); if (!visit) await page.reload();
      }
      phase = 'replay'; const replay = await post(intent); assert.equal(replay.status(), 202); assert.equal((await replay.json()).scanId, scanId);
      const conflict = await post({ ...intent, checks: checks.length === 1 ? ['secret', 'sbom'] : ['vuln'] }); assert.equal(conflict.status(), 409);
      assert.equal((await context.request.post(`${origin}/api/v1/browser/scans`, { headers: { Origin: 'https://foreign.invalid' }, data: intent })).status(), 403);
      const foreignReplay = await foreign.request.post(`${origin}/api/v1/browser/scans`, { headers: { Origin: origin },
        data: failure === 'DB_UNAVAILABLE' ? intent : { ...intent, imageReference: image.replace(digest, `sha256:${'b'.repeat(64)}`) } });
      assert.equal(foreignReplay.status(), failure === 'DB_UNAVAILABLE' ? 503 : 400);
      evidence.push({ scanId, checks, state: status.state, failure, admittedAt, checkedAt: status.perCheck[checks[0]].checkedAt,
        findings: result['/vuln'].findingCount ?? null, components: result['/sbom'].componentCount ?? null,
        configDigest: status.imageProfile.configDigest, scannerVersion: result['/vuln'].scannerVersion ?? null, db: result['/vuln'].db ?? null,
        domReload: true, strictParsers: true, ownership: true, replay: true });
    }
    console.log(JSON.stringify({ mode, evidence, accepted, noSeededScan: true, actualChromium: true }));
  }
} catch (error) {
  console.log(JSON.stringify({ failedPhase: phase, accepted, status: statusSnapshot(lastStatus),
      ...(typeof error.actual === 'string' && [...states, ...outcomes, ...reasons].includes(error.actual) ? { actual: error.actual } : {}),
      ...(typeof error.expected === 'string' && [...states, ...outcomes, ...reasons].includes(error.expected) ? { expected: error.expected } : {}),
      ...(Number.isSafeInteger(error.actual) ? { actualStatus: error.actual } : {}),
    ...(Number.isSafeInteger(error.expected) ? { expectedStatus: error.expected } : {}) })); process.exitCode = 1;
} finally { await context.close(); await foreign.close(); await anonymous.close(); await browser.close(); }
