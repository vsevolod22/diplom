import { chromium } from '@playwright/test';
import { createServer } from 'vite';

const server = await createServer({ server: { host: '127.0.0.1', port: 0 } });
async function assertNoOverflow(page, screen) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  if (overflow) throw Error(`${screen}: horizontal overflow at ${page.viewportSize().width}px`);
}
let browser;
try {
  await server.listen();
  browser = await chromium.launch({ headless: true });
  const port = server.httpServer.address().port;
  let checks = 0;
  for (const width of [320, 375, 1280])
    for (const reducedMotion of ['reduce', 'no-preference']) {
      const page = await browser.newPage({ viewport: { width, height: 800 }, reducedMotion });
      const errors = [];
      page.on('pageerror', (error) => errors.push(error.message));
      await page.goto(`http://127.0.0.1:${port}/demo/scans`);
      await page.getByText('library/alpine:latest (демо)', { exact: true }).waitFor();
      await assertNoOverflow(page, 'demo/list');
      await page
        .getByRole('link', { name: /Новый скан/ })
        .last()
        .click();
      if (!(await page.getByRole('button', { name: 'Запуск недоступен' }).isDisabled()))
        throw Error('Launch enabled');
      await assertNoOverflow(page, 'demo/create');
      await page.getByRole('link', { name: /отдельный образец отчёта/ }).click();
      await page.getByText('База уязвимостей недоступна').waitFor();
      await assertNoOverflow(page, 'demo/detail');
      if (!(await page.getByRole('button', { name: 'Чат недоступен' }).isDisabled()))
        throw Error('Chat enabled');
      if (width < 640) {
        await page.getByRole('button', { name: 'Фильтры' }).click();
        await page.getByRole('dialog', { name: 'Фильтры находок' }).waitFor();
        await page.keyboard.press('Escape');
      } else {
        await page.getByLabel('Категория').selectOption('vulnerability');
        await page.getByText(/Нет совпадений фильтра/).waitFor();
        await page.getByRole('button', { name: 'Сбросить фильтр' }).click();
      }
      await page.getByRole('link', { name: 'К списку' }).click();
      await page.getByText('library/alpine:latest (демо)', { exact: true }).waitFor();
      await page.goto(`http://127.0.0.1:${port}/scans`);
      await page.getByText(/Список недоступен: GET/).waitFor();
      await assertNoOverflow(page, 'live/list');
      if (errors.length) throw Error(`${width}/${reducedMotion}: ${errors.join('; ')}`);
      checks++;
      await page.close();
    }
  console.log(`A1 production routes: ${checks} viewport/motion scenarios passed`);
} finally {
  await browser?.close();
  await server.close();
}
