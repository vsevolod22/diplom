import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createServer as createNetServer } from 'node:net';
import { createServer } from 'vite';
import tailwindcss from '@tailwindcss/vite';
import { chromium, expect as playwrightExpect } from '@playwright/test';

const expect = playwrightExpect.configure({ timeout: 3000 });

// Run with node tests-e2e/blocknote-chat-layout.mjs. Never attaches to a live app.
const root = fileURLToPath(new URL('../', import.meta.url));
// Vite treats port: 0 as its default 5173, so ask the OS for a port first.
const reservation = createNetServer();
await new Promise((resolve, reject) => {
  reservation.once('error', reject);
  reservation.listen(0, '127.0.0.1', resolve);
});
const ephemeralPort = reservation.address().port;
await new Promise((resolve, reject) => reservation.close((error) => (error ? reject(error) : resolve())));
const server = await createServer({
  configFile: false,
  root,
  plugins: [tailwindcss()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('../src', import.meta.url)) },
    dedupe: ['react', 'react-dom'],
  },
  optimizeDeps: {
    entries: ['tests-e2e/blocknote-chat-layout.renderer.html'],
    include: ['react', 'react-dom/client', '@blocknote/core', '@blocknote/react'],
  },
  server: { host: '127.0.0.1', port: ephemeralPort, strictPort: true, open: false, hmr: false },
});
let browser;
const results = [];
const failures = [];
try {
  await server.listen();
  const address = server.httpServer.address();
  assert(address && typeof address !== 'string');
  assert(![8080, 8081].includes(address.port));
  const origin = `http://127.0.0.1:${address.port}`;
  browser = await chromium.launch({ headless: true });
  for (const width of [375, 1280]) {
    const context = await browser.newContext({
      viewport: { width, height: 900 },
      reducedMotion: 'reduce',
      serviceWorkers: 'block',
    });
    const blocked = [];
    const errors = [];
    await context.route('**/*', (route) => {
      const url = new URL(route.request().url());
      if (url.origin === origin && !url.pathname.startsWith('/api/')) return route.continue();
      blocked.push(url.origin + url.pathname);
      return route.abort();
    });
    const page = await context.newPage();
    page.setDefaultTimeout(7000);
    page.on('pageerror', (error) => errors.push(error.message));
    const fixture = `${origin}/tests-e2e/blocknote-chat-layout.renderer.html`;
    const textbox = () => page.getByRole('textbox', { name: 'Вопрос чату', exact: true });
    const draft = () => page.getByTestId('draft');
    async function check(name, run) {
      try {
        await run();
        results.push({ width, name, passed: true });
      } catch (error) {
        failures.push({
          width,
          name,
          error: String(error.message)
            .replace(/\u001b\[[0-9;]*m/g, '')
            .slice(0, 1400),
          blocks: await textbox()
            .locator('[data-content-type]')
            .evaluateAll((elements) =>
              elements.map((element) => ({
                type: element.getAttribute('data-content-type'),
                level: element.getAttribute('data-level'),
                text: element.textContent,
              })),
            )
            .catch(() => null),
          active: await page.evaluate(() => document.activeElement?.outerHTML.slice(0, 600)),
        });
      }
    }
    await page.goto(`${fixture}?composer`);
    await check('real editor: heading input, live bold/list, controlled Markdown; no preview', async () => {
      await expect(textbox()).toHaveAttribute('contenteditable', 'true');
      await expect(textbox()).toHaveClass(/bn-editor/);
      await expect(page.locator('textarea')).toHaveCount(0);
      await expect(
        page.getByRole('button', { name: /Предпросмотр Markdown|Редактировать Markdown/ }),
      ).toHaveCount(0);
      await textbox().click();
      await page.keyboard.type('# heading');
      await expect(textbox().locator('h1')).toHaveText('heading');
      await expect(draft()).toContainText('# heading');
      await page.keyboard.press('Enter');
      await page.keyboard.press('ControlOrMeta+b');
      await page.keyboard.type('bold');
      await page.keyboard.press('ControlOrMeta+b');
      await expect(textbox().locator('strong')).toHaveText('bold');
      await expect(draft()).toContainText('**bold**');
      await page.keyboard.press('Enter');
      await page.keyboard.type('- item');
      await expect(textbox().locator('[data-content-type="bulletListItem"]')).toContainText('item');
      await expect(draft()).toContainText('item');
      await expect(page.getByTestId('submitted')).toHaveText('[]');
      const before = await draft().textContent();
      await page.getByRole('button', { name: 'Отправить тестовый вопрос' }).click();
      await expect(page.getByTestId('submitted')).toHaveText(JSON.stringify([before]));
    });
    await check('external retry/reset, disabled contenteditable and validation accessibility', async () => {
      await page.getByRole('button', { name: 'Внешний повтор' }).click();
      await expect(textbox().locator('h2')).toHaveText('Повторная проверка');
      await expect(textbox().locator('strong')).toHaveText('Сохранённый');
      await expect(textbox().locator('[data-content-type="bulletListItem"]')).toContainText('Первый пункт');
      await expect(textbox()).toHaveAttribute('aria-describedby', 'fixture-feedback');
      await page.getByRole('button', { name: 'Переключить блокировку' }).click();
      await expect(textbox()).toHaveAttribute('contenteditable', 'false');
      await expect(textbox()).toHaveAttribute('aria-disabled', 'true');
      await expect(page.getByRole('button', { name: 'Отправить тестовый вопрос' })).toBeDisabled();
      await page.getByRole('button', { name: 'Переключить блокировку' }).click();
      await expect(textbox()).toHaveAttribute('contenteditable', 'true');
      await page.getByRole('button', { name: 'Внешний сброс' }).click();
      await expect(textbox()).toHaveText('');
      await expect(draft()).toHaveText('');
    });
    await check('UTF-8 boundary and over-limit draft retained without truncation', async () => {
      await page.getByRole('button', { name: 'Граница UTF-8', exact: true }).click();
      await expect(page.getByTestId('bytes')).toHaveText('2048');
      await expect(page.getByRole('button', { name: 'Отправить тестовый вопрос' })).toBeEnabled();
      await expect(textbox()).toHaveAttribute('aria-invalid', 'false');
      await page.getByRole('button', { name: 'Сверх лимита UTF-8' }).click();
      await expect(page.getByTestId('bytes')).toHaveText('2049');
      await expect(textbox()).toHaveAttribute('aria-invalid', 'true');
      await expect(page.getByRole('button', { name: 'Отправить тестовый вопрос' })).toBeDisabled();
      assert.equal(await draft().textContent(), 'я '.repeat(683));
      await expect(textbox()).toContainText('я я я');
    });
    await check(
      'malicious HTML paste inert; narrowed schema has no images, links, tables or requests',
      async () => {
        await page.getByRole('button', { name: 'Внешний сброс' }).click();
        await expect(textbox()).toHaveText('');
        await textbox().click();
        await textbox().evaluate((element) => {
          const clipboardData = new DataTransfer();
          clipboardData.setData(
            'text/html',
            '<p><a href="javascript:alert(1)">опасно</a><a href="https://example.test/track">адрес</a><img src="https://example.test/pixel.png" onerror="window.__pasteExecuted=true"><script>window.__pasteExecuted=true</script></p><table><tr><td>ячейка</td></tr></table>',
          );
          clipboardData.setData('text/plain', 'опасно https://example.test/track ячейка');
          element.dispatchEvent(
            new ClipboardEvent('paste', { clipboardData, bubbles: true, cancelable: true }),
          );
        });
        await expect(textbox()).toContainText('опасно');
        await expect(textbox().locator('img, a[href], script, iframe, table, [onerror]')).toHaveCount(0);
        assert.equal(await page.evaluate(() => Boolean(window.__pasteExecuted)), false);
        // Let queued resource requests and serialization finish before testing the boundary.
        await expect(draft()).toContainText('опасно');
        await expect(page.getByRole('button', { name: 'Отправить тестовый вопрос' })).toBeDisabled();
        assert.deepEqual(blocked, []);
      },
    );
    // Every regression starts from a fresh controlled editor; a failure cannot contaminate the next.
    async function seed(button, text) {
      await page.goto(`${fixture}?composer`);
      await page.getByRole('button', { name: button, exact: true }).click();
      await expect(textbox()).toContainText(text);
    }
    async function selectText(startText, startOffset, endText = startText, endOffset = startText.length) {
      await textbox().focus();
      await textbox().evaluate(
        (element, range) => {
          const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
          const nodes = [];
          while (walker.nextNode()) nodes.push(walker.currentNode);
          const start = nodes.find((node) => node.textContent === range.startText);
          const end = nodes.find((node) => node.textContent === range.endText);
          if (!start || !end) throw new Error('Selection text nodes not found');
          const selection = window.getSelection();
          selection.setBaseAndExtent(start, range.startOffset, end, range.endOffset);
          document.dispatchEvent(new Event('selectionchange'));
        },
        { startText, startOffset, endText, endOffset },
      );
      await expect.poll(() => page.evaluate(() => window.getSelection()?.toString())).not.toBe('');
    }
    const heading = () => page.getByRole('button', { name: 'Заголовок', exact: true });
    const selectionText = () => page.evaluate(() => window.getSelection()?.toString());
    await check('regression: H2 applies to every selected paragraph, not only cursor block', async () => {
      await seed('Три абзаца', 'Gamma paragraph');
      await selectText('Alpha paragraph', 0, 'Gamma paragraph', 15);
      await heading().click();
      await expect(textbox().locator('h2')).toHaveText([
        'Alpha paragraph',
        'Beta paragraph',
        'Gamma paragraph',
      ]);
      await expect(draft()).toHaveText('## Alpha paragraph\n\n## Beta paragraph\n\n## Gamma paragraph');
      await expect(page.getByTestId('submitted')).toHaveText('[]');
    });
    await check('regression: H1 selection becomes H2, never toggles to paragraph', async () => {
      await seed('Исходный H1', 'Existing H1');
      await selectText('Existing H1', 0);
      await heading().click();
      await expect(textbox().locator('h2')).toHaveText('Existing H1');
      await expect(textbox().locator('h1')).toHaveCount(0);
      await expect(draft()).toHaveText('## Existing H1');
    });
    await check('regression: selected actual H2 blocks toggle together to paragraphs', async () => {
      await seed('Исходные H2', 'Second H2');
      await selectText('Existing H2', 0, 'Second H2', 9);
      await heading().click();
      await expect(textbox().locator('h2')).toHaveCount(0);
      await expect(
        textbox()
          .locator('[data-content-type="paragraph"]')
          .filter({ hasText: /Existing H2|Second H2/ }),
      ).toHaveText(['Existing H2', 'Second H2']);
      await expect(draft()).toHaveText('Existing H2\n\nSecond H2');
    });
    await check(
      'regression: substring text/selection survive H2 and typing replaces intended range',
      async () => {
        await seed('Подстрока', 'Before selected after');
        await selectText('Before selected after', 7, 'Before selected after', 15);
        assert.equal(await selectionText(), 'selected');
        await heading().click();
        await expect(textbox().locator('h2')).toHaveText('Before selected after');
        assert.equal(await selectionText(), 'selected', 'toolbar must retain the exact substring selection');
        await expect(textbox()).toBeFocused();
        await page.keyboard.type('REPLACED');
        await expect(textbox().locator('h2')).toHaveText('Before REPLACED after');
        // Typing again must continue at the replacement caret, not jump to a block edge.
        await page.keyboard.type('!');
        await expect(draft()).toHaveText('## Before REPLACED! after');
        assert.equal(await selectionText(), '');
        await expect(page.getByTestId('submitted')).toHaveText('[]');
      },
    );
    await check('regression: editor blank-area click focuses input and accepts typing', async () => {
      await page.goto(`${fixture}?composer`);
      const editor = page.locator('.scan-chat-editor');
      const bounds = await editor.boundingBox();
      assert(bounds);
      // Bottom-right padding belongs to the editor surface, not its contenteditable child.
      await page.mouse.click(bounds.x + bounds.width - 3, bounds.y + bounds.height - 3);
      await expect(textbox()).toBeFocused();
      await page.keyboard.type('Blank area question');
      await expect(draft()).toHaveText('Blank area question');
    });
    await check(
      'regression: external reset clears heading/selection; new typing is plain at fresh caret',
      async () => {
        await seed('Исходные H2', 'Second H2');
        await selectText('Existing H2', 2, 'Existing H2', 8);
        await page.getByRole('button', { name: 'Внешний сброс', exact: true }).click();
        await expect(textbox()).toHaveText('');
        await expect(draft()).toHaveText('');
        await textbox().click();
        await page.keyboard.type('Fresh question');
        await expect(textbox().locator('h1, h2, h3, strong, em, code')).toHaveCount(0);
        await expect(draft()).toHaveText('Fresh question');
        assert.equal(await selectionText(), '');
        await expect(heading()).toHaveAttribute('aria-pressed', 'false');
      },
    );
    await check(
      'regression: panel-style external retry ref focus places typing in replacement draft',
      async () => {
        await seed('Подстрока', 'Before selected after');
        await selectText('Before selected after', 7, 'Before selected after', 15);
        await page.getByRole('button', { name: 'Повтор с фокусом как в панели', exact: true }).click();
        await expect(textbox()).toBeFocused();
        await expect(textbox().locator('h2')).toHaveText('Retry heading');
        await page.keyboard.type('!');
        // The intended external-replacement caret is the end of the restored question.
        await expect(draft()).toHaveText('## Retry heading\n\nRetry paragraph!');
        await expect(page.getByTestId('submitted')).toHaveText('[]');
      },
    );
    await page.goto(fixture);
    await check('widget: lazy mount, minimize/reopen draft and focus retention, mobile bounds', async () => {
      const launcher = page.getByRole('button', { name: 'Открыть чат по отчёту' });
      await expect(launcher).toBeVisible();
      await expect(textbox()).toHaveCount(0);
      await launcher.click();
      const dialog = page.getByRole('dialog', { name: 'Ассистент отчёта' });
      await expect(textbox()).toHaveAttribute('contenteditable', 'true');
      await check('widget: first-open editor focus', async () => {
        await expect(textbox()).toBeFocused();
      });
      await textbox().click();
      await page.keyboard.type('# draft');
      await expect(textbox().locator('h1')).toHaveText('draft');
      const original = await textbox().innerHTML();
      await page.getByRole('button', { name: 'Свернуть чат' }).click();
      await expect(dialog).toBeHidden();
      await expect(launcher).toBeFocused();
      await page.keyboard.press('Enter');
      await expect(textbox()).toBeFocused();
      assert.equal(await textbox().innerHTML(), original);
      const bounds = await dialog.boundingBox();
      assert(
        bounds &&
          bounds.x >= 0 &&
          bounds.y >= 0 &&
          bounds.x + bounds.width <= width + 1 &&
          bounds.y + bounds.height <= 901,
        JSON.stringify(bounds),
      );
      assert(
        await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1),
        'page horizontal overflow',
      );
      const overflow = await dialog.evaluate((element) => element.scrollWidth - element.clientWidth);
      assert(overflow <= 1, `widget horizontal overflow ${overflow}`);
      await check('widget: Escape from focused editor restores launcher focus', async () => {
        await page.keyboard.press('Escape');
        await expect(launcher).toBeFocused();
      });
    });
    await check('no browser exceptions or API/external requests', async () => {
      assert.deepEqual(errors, []);
      assert.deepEqual(blocked, []);
    });
    await context.close();
  }
  console.log(
    JSON.stringify(
      {
        mode: 'real Chromium / ephemeral loopback / synthetic fixture only',
        summary: { passed: results.length, failed: failures.length },
        results,
        failures,
      },
      null,
      2,
    ),
  );
  assert.equal(
    failures.length,
    0,
    `${failures.length} BlockNote browser qualification failures (details above)`,
  );
} finally {
  await browser?.close();
  await server.close();
}
