import 'reflect-metadata';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module.js';
import { ScansService } from './scans.service.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { OciResolver } from '../oci/oci-resolver.js';
import { consumeOne } from '../worker/outbox-consumer.js';
import { configBytes, fixtureLoader } from '../worker/config-test-fixtures.js';

// Explicit optional browser proof, not part of server-only production test dependencies.
// Browser networking is not intercepted: Vite proxies actual HTTP to disposable Nest.
const vitePackage = 'vite', playwrightPackage = '@playwright/test';
const { createServer } = await import(vitePackage);
const { chromium } = await import(playwrightPackage);
const directory = mkdtempSync(join(tmpdir(), 'config-browser-'));
const env = { AUTH_DB_PATH: join(directory, 'auth.sqlite'), SCAN_LEDGER_PATH: join(directory, 'ledger.sqlite'),
  AUTH_ORIGIN: 'http://127.0.0.1:8080', AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true',
  SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'false', SCAN_BROWSER_ALLOWED_USER_IDS: '' };
const previous = Object.keys(env).map(key => process.env[key]); Object.assign(process.env, env);
const app = await NestFactory.create(AppModule, { logger: false });
let ui: Awaited<ReturnType<typeof createServer>> | undefined;
let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
let bytes = configBytes();
try {
  Object.defineProperty(app.get(ScansService), 'readiness', { value: async () => true });
  Object.defineProperty(app.get(OciResolver), 'resolvePublicAlpine', { value: async () => ({ registry: 'registry-1.docker.io', repository: 'library/alpine', digest: bytes.digest, platform: 'linux/amd64' }) });
  await app.listen(0, '127.0.0.1');
  const api = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}`;
  ui = await createServer({ root: fileURLToPath(new URL('../../../../', import.meta.url)),
    server: { host: '127.0.0.1', port: 0, proxy: { '/api/': { target: api, changeOrigin: false } } } });
  await ui.listen();
  const origin = `http://127.0.0.1:${ui.httpServer.address().port}`;
  process.env.AUTH_ORIGIN = origin;
  browser = await chromium.launch({ headless: true });
  for (const [width, user, expected] of [[320, '0', 'checked'], [375, '1000', 'checked'], [1280, 'CANARY_USER', 'unsupported']] as const) {
    bytes = configBytes(user);
    const context = await browser.newContext({ viewport: { width, height: 900 }, reducedMotion: 'reduce' });
    const page = await context.newPage();
    const errors: string[] = [];
    page.on('pageerror', (error: Error) => errors.push(error.message));
    try {
      const registration = await context.request.post(`${origin}/api/v1/auth/register`, { headers: { origin },
        data: { email: `config-${width}@example.com`, password: 'disposable-browser-1234' } });
      assert.equal(registration.status(), 201);
      process.env.SCAN_BROWSER_ALLOWED_USER_IDS = (await registration.json()).id;
      await page.goto(`${origin}/scans/new`);
      const checkbox = page.getByRole('checkbox', { name: /Image config/ }); await checkbox.waitFor();
      assert.equal(await checkbox.isChecked(), false);
      await page.getByRole('button', { name: /Alpine · latest/ }).click();
      await page.getByRole('checkbox', { name: /Secrets ·/ }).uncheck();
      await checkbox.focus(); await page.keyboard.press('Space'); assert.equal(await checkbox.isChecked(), true);
      await page.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }).check();
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth), false);
      const responsePromise = page.waitForResponse((response: { url(): string; request(): { method(): string } }) => response.url() === `${origin}/api/v1/browser/scans` && response.request().method() === 'POST');
      await page.getByRole('button', { name: 'Запустить скан' }).click();
      const response = await responsePromise; assert.equal(response.status(), 202);
      const { scanId } = await response.json();
      const post = JSON.parse(response.request().postData()); assert.deepEqual(post.checks, ['config']);
      await consumeOne(app.get(LedgerStore).ledger!, { timeoutMs: 1000, dbDir: '/unused', configLoader: fixtureLoader(bytes) });
      await page.getByRole('heading', { name: 'Image config · только метаданные образа' }).waitFor();
      await page.getByText(/History: RULE_NOT_IMPLEMENTED/).waitFor();
      const report = await context.request.get(`${origin}/api/v1/browser/scans/${scanId}`);
      assert.equal((await report.json()).config.config.outcome, expected);
      const text = await page.locator('body').innerText();
      assert.ok(text.includes('image-config-user-v1')); assert.ok(text.includes('image-config-policy-v1'));
      assert.ok(text.includes('SOURCE_NOT_PROVIDED')); assert.ok(text.includes('Numeric UID без находки'));
      assert.equal(text.includes('CANARY'), false);
      if (user === '0') assert.ok(text.includes('NUMERIC_ROOT'));
      if (user === '1000') assert.ok(text.includes('Root metadata finding отсутствует'));
      if (expected === 'unsupported') assert.ok(text.includes('USER_NOT_RESOLVABLE'));
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth), false);
      assert.deepEqual(errors, []);
      console.log(`Real Nest/worker/SQLite/browser config: ${width}px ${expected}, keyboard/coverage/no-overflow passed`);
    } finally { await context.close(); }
  }
} finally {
  await browser?.close(); await ui?.close(); await app.close();
  Object.keys(env).forEach((key, index) => { if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index]; });
  rmSync(directory, { recursive: true, force: true });
}
