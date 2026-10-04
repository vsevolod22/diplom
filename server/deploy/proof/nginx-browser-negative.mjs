import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { chromium } from '@playwright/test';

// Existing local stand: negative admission/UI proof only, NOT positive nginx
// qualification. Session/cookie/password values remain transient and unlogged.
const origin = 'http://127.0.0.1:8080';
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext();
try {
  const registration = await context.request.post(`${origin}/api/v1/auth/register`, {
    headers: { Origin: origin }, data: { email: `nginx-negative-${randomUUID()}@qualification.invalid`, password: `Proof-${randomUUID()}` },
  });
  assert.equal(registration.status(), 201);
  const key = randomUUID();
  const data = { imageReference: 'registry-1.docker.io/library/nginx@sha256:b17b00f7ef0038aeb11362157f49006a130628ee711cefcced871405d046f114',
    checks: ['secret', 'sbom', 'vuln'], scope: 'image', idempotencyKey: key };
  for (let attempt = 0; attempt < 2; attempt++) {
    const result = await context.request.post(`${origin}/api/v1/browser/scans`, { headers: { Origin: origin }, data });
    assert.equal(result.status(), 400); assert.equal((await result.json()).errorCode, 'UNSUPPORTED_SCAN');
  }
  const page = await context.newPage();
  await page.goto(`${origin}/scans/new`);
  await page.getByLabel('Поиск по доступным образам').fill('nginx');
  const suggestion = page.getByRole('group', { name: 'Выбор образа' }).getByRole('button').filter({ hasText: 'registry-1.docker.io/library/nginx:latest' }).first();
  await suggestion.waitFor({ state: 'visible', timeout: 30_000 });
  assert.equal(await suggestion.isDisabled(), true);
  assert.equal(await page.locator('input[name="imageReference"]').inputValue(), '');
  await page.reload();
  assert.equal(await page.locator('input[name="imageReference"]').inputValue(), '');
  console.log(JSON.stringify({ actualChromium: true, authenticated: true, nginxAdmission: '400-no-receipt',
    repeatedRequest: '400-no-receipt', serverDerivedSuggestionDisabled: true, reloadNoSelection: true,
    positiveQualification: false }));
} finally {
  await context.request.post(`${origin}/api/v1/auth/logout`, { headers: { Origin: origin } }).catch(() => {});
  await context.close(); await browser.close();
}
