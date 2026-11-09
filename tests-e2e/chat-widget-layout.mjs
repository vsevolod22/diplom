import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';
import tailwindcss from '@tailwindcss/vite';
import { chromium, expect } from '@playwright/test';

const root = fileURLToPath(new URL('../', import.meta.url));
const server = await createServer({
  configFile: false,
  root,
  plugins: [tailwindcss()],
  resolve: { alias: { '@': fileURLToPath(new URL('../src', import.meta.url)) } },
  server: { host: '127.0.0.1', port: 0, strictPort: false, open: false },
});
let browser;
try {
  await server.listen();
  const address = server.httpServer.address();
  assert(address && typeof address !== 'string');
  assert(![8080, 8081].includes(address.port));
  const origin = `http://127.0.0.1:${address.port}`;
  browser = await chromium.launch({ headless: true });
  const results = [];
  const failures = [];
  for (const width of [375, 1280]) {
    const context = await browser.newContext({ viewport: { width, height: 900 }, reducedMotion: 'reduce' });
    const blocked = [];
    await context.route('**/*', (route) => {
      const url = new URL(route.request().url());
      if (url.origin === origin && !url.pathname.startsWith('/api/')) return route.continue();
      blocked.push(url.origin + url.pathname);
      return route.abort();
    });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', (error) => {
      errors.push(error.message);
      console.error('Browser error:', error.message);
    });
    page.setDefaultTimeout(15000);
    await page.goto(`${origin}/tests-e2e/chat-widget-layout.renderer.html`);
    const launcher = page.getByRole('button', { name: 'Открыть чат по отчёту' });
    await expect(launcher).toBeVisible();
    await expect(page.getByLabel('Вопрос чату')).toHaveCount(0);
    await launcher.click();
    const dialog = page.getByRole('dialog', { name: 'Ассистент отчёта' });
    await expect(dialog).toBeVisible();
    await expect(page.getByRole('button', { name: 'Обновить историю' })).toBeEnabled();
    await expect(page.getByLabel('Вопрос чату')).toBeFocused();
    await expect(dialog.locator('.cs-message--incoming table')).toBeVisible();
    await expect(dialog.locator('.cs-message--incoming pre code')).toContainText('пример_команды');

    const contrast = await dialog.evaluate((element) => {
      const parse = (color) => (color.match(/[\d.]+/g) ?? []).map(Number);
      const over = (foreground, background) => {
        const alpha = foreground[3] ?? 1;
        return foreground
          .slice(0, 3)
          .map((channel, index) => channel * alpha + background[index] * (1 - alpha));
      };
      function background(node) {
        return node
          ? over(parse(getComputedStyle(node).backgroundColor), background(node.parentElement))
          : [255, 255, 255];
      }
      const luminance = (rgb) =>
        rgb
          .map((channel) => {
            const value = channel / 255;
            return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
          })
          .reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0);
      const selectors = [
        '.scan-chat-widget__header h2',
        '.cs-message--outgoing p',
        '.cs-message--incoming p',
        '.cs-message--incoming code',
        '.cs-message--incoming th',
        '.cs-message--incoming td',
        'textarea',
        '#scan-chat-input-count',
      ];
      return selectors.map((selector) => {
        const node = element.querySelector(selector);
        if (!node) throw new Error(`Missing contrast sample: ${selector}`);
        const bg = background(node);
        const color = getComputedStyle(node).color;
        const a = luminance(over(parse(color), bg)),
          b = luminance(bg);
        return { selector, color, background: bg, ratio: (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05) };
      });
    });
    for (const sample of contrast)
      assert(sample.ratio >= 4.5, `${width}px ${sample.selector}: contrast ${sample.ratio}`);
    const bounds = await dialog.boundingBox();
    assert(
      bounds &&
        bounds.x >= 0 &&
        bounds.x + bounds.width <= width + 1 &&
        bounds.y >= 0 &&
        bounds.y + bounds.height <= 901,
      `widget outside viewport: ${JSON.stringify(bounds)}`,
    );
    const overflow = await page.evaluate(() => ({
      page: document.documentElement.scrollWidth - innerWidth,
      widget:
        document.querySelector('.scan-chat-widget').scrollWidth -
        document.querySelector('.scan-chat-widget').clientWidth,
      content:
        document.querySelector('.scan-chat-content').scrollWidth -
        document.querySelector('.scan-chat-content').clientWidth,
    }));
    for (const [name, pixels] of Object.entries(overflow))
      assert(pixels <= 1, `${width}px ${name} horizontal overflow: ${pixels}`);
    for (const selector of ['.cs-message--incoming table', '.cs-message--incoming pre code']) {
      const sample = dialog.locator(selector);
      await sample.scrollIntoViewIfNeeded();
      await expect(sample).toBeInViewport();
    }
    const draft =
      '**Предпросмотр**\n\n| Имя | Итог |\n| --- | --- |\n| образ | проверен |\n\n```text\nкод\n```';
    await page.getByLabel('Вопрос чату').fill(draft);
    await page.getByRole('button', { name: 'Предпросмотр Markdown' }).click();
    const preview = page.getByRole('region', { name: 'Предпросмотр Markdown', exact: true });
    await expect(preview.getByRole('table')).toBeVisible();
    await expect(preview.locator('pre code')).toHaveText('код\n');
    await expect(preview.getByRole('button')).toHaveCount(0);
    await dialog.screenshot({ path: `${root}/test-results/chat-widget-ux-20261109/layout-${width}.png` });
    await page.getByRole('button', { name: 'Редактировать Markdown' }).click();
    await expect(page.getByLabel('Вопрос чату')).toHaveValue(draft);
    await page.getByRole('button', { name: 'Свернуть чат' }).click();
    await expect(dialog).toBeHidden();
    try {
      await expect(launcher).toBeFocused({ timeout: 1000 });
    } catch {
      failures.push(`${width}px: minimize does not restore launcher focus`);
    }
    await launcher.focus();
    await page.keyboard.press('Enter');
    await expect(page.getByLabel('Вопрос чату')).toBeFocused();
    await expect(page.getByLabel('Вопрос чату')).toHaveValue(draft);
    await page.keyboard.press('Escape');
    try {
      await expect(launcher).toBeFocused({ timeout: 1000 });
    } catch {
      failures.push(`${width}px: Escape does not restore launcher focus`);
    }
    const closedEscapeConsumed = await page.evaluate(() => {
      const event = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true });
      document.body.dispatchEvent(event);
      return event.defaultPrevented;
    });
    assert.equal(closedEscapeConsumed, false, 'minimized widget must not consume report Escape');
    assert.deepEqual(errors, []);
    assert.deepEqual(blocked, []);
    results.push({ width, bounds, overflow, contrast });
    await context.close();
  }
  console.log(
    JSON.stringify(
      {
        passed: failures.length === 0,
        mode: 'ephemeral loopback / synthetic only',
        results: results.map(({ contrast, ...result }) => ({
          ...result,
          contrast: Object.fromEntries(
            contrast.map((sample) => [sample.selector, Number(sample.ratio.toFixed(2))]),
          ),
        })),
        failures,
      },
      null,
      2,
    ),
  );
  assert.deepEqual(failures, [], 'Browser focus regressions');
} finally {
  await browser?.close();
  await server.close();
}
