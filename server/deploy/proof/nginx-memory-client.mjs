import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { chromium, expect } from '@playwright/test';

const origin = 'http://127.0.0.1:18080';
const [owner] = JSON.parse(await readFile(process.argv[2], 'utf8'));
const mode = process.argv[3];
assert.ok(['kill', 'restart'].includes(mode));
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext();
let phase = 'login';
try {
  assert.equal((await context.request.post(`${origin}/api/v1/auth/login`, { headers: { Origin: origin }, data: owner })).status(), 200);
  phase = 'create';
  const response = await context.request.post(`${origin}/api/v1/browser/scans`, { headers: { Origin: origin }, data: {
    imageReference: 'registry-1.docker.io/library/nginx@sha256:0dcc88822d45581e65ae329f8be769762bf628d3b2bb7d2a077d4aa5c98b30e3',
    scope: 'image', checks: ['secret', 'sbom', 'vuln'], idempotencyKey: randomUUID(),
  } });
  assert.equal(response.status(), 202);
  const { scanId } = await response.json();
  console.log(JSON.stringify({ created: scanId }));
  phase = 'terminal';
  const deadline = Date.now() + 900_000;
  let status;
  do {
    const current = await context.request.get(`${origin}/api/v1/browser/scans/${scanId}`);
    assert.equal(current.status(), 200); status = await current.json();
    if (['completed', 'partial', 'failed', 'cancelled'].includes(status.state)) break;
    await new Promise(resolve => setTimeout(resolve, 500));
  } while (Date.now() < deadline);
  assert.equal(status.state, mode === 'kill' ? 'partial' : 'completed');
  assert.equal(status.perCheck.secret.outcome, 'checked');
  assert.equal(status.perCheck.sbom.outcome, 'checked');
  assert.equal(status.perCheck.vuln.outcome, mode === 'kill' ? 'failed' : 'checked');
  const vuln = await (await context.request.get(`${origin}/api/v1/browser/scans/${scanId}/vuln`)).json();
  if (mode === 'kill') assert.equal(vuln.errorCode, 'SCAN_FAILED');
  else assert.ok(vuln.findingCount > 0);
  phase = 'dom-reload';
  const page = await context.newPage();
  await page.goto(`${origin}/scans/${scanId}`);
  await expect(page.getByRole('region', { name: 'Пакеты SBOM' })).toContainText('72 пакетов', { timeout: 30_000 });
  if (mode === 'kill') {
    await expect(page.getByRole('region', { name: 'Результаты CVE' })).toContainText('SCAN_FAILED', { timeout: 30_000 });
    await expect(page.getByRole('region', { name: 'Результаты CVE' })).toContainText('Число уязвимостей неизвестно.');
  }
  await page.reload();
  await expect(page.getByRole('region', { name: 'Пакеты SBOM' })).toContainText('72 пакетов');
  if (mode === 'restart') await expect(page.getByRole('region', { name: 'Результаты CVE' })).toContainText(vuln.findings[0].cveId);
  else await expect(page.getByRole('region', { name: 'Результаты CVE' })).toContainText('SCAN_FAILED');
  console.log(JSON.stringify({ mode, scanId, state: status.state, independentOutcomes: true, domReload: true }));
} catch {
  console.log(JSON.stringify({ failedPhase: phase, mode })); process.exitCode = 1;
} finally { await context.close(); await browser.close(); }
