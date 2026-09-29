import { createServer } from 'vite';
import { chromium } from '@playwright/test';

const server = await createServer({ server: { port: 0, host: '127.0.0.1' } });
let browser;
try {
  await server.listen();
  const port = server.httpServer.address().port;
  browser = await chromium.launch({ headless: true });
  let checks = 0;
  for (const width of [320, 375, 1280])
    for (const reducedMotion of ['reduce', 'no-preference'])
      for (const concept of ['a1', 'a2', 'a3']) {
        const page = await browser.newPage({ viewport: { width, height: 800 }, reducedMotion });
        const errors = [];
        page.on('pageerror', (error) => errors.push(error.message));
        await page.goto(`http://127.0.0.1:${port}/docs/ui-concepts/task-27-react.html`);
        await page.getByRole('tab', { name: new RegExp(concept.toUpperCase()) }).click();
        await page.getByRole('button', { name: /Новый скан/ }).click();
        await page.waitForFunction(() => document.activeElement?.getAttribute('aria-label') === '02 Создать');
        await page.getByRole('button', { name: /Посмотреть независимый образец отчёта/ }).click();
        await page.getByRole('heading', { name: /Спросить об отчёте/ }).waitFor();
        await page.getByRole('button', { name: '02 Создать' }).click();
        if (!(await page.getByRole('button', { name: 'Запуск недоступен' }).isDisabled()))
          throw Error('Launch enabled');
        await page.getByRole('button', { name: '01 Список' }).click();
        await page.getByRole('button', { name: /Открыть деталь/ }).click();
        await page.getByRole('heading', { name: /Спросить об отчёте/ }).waitFor();
        if (!(await page.getByRole('button', { name: 'Чат недоступен в прототипе' }).isDisabled()))
          throw Error('Chat enabled');
        await page.getByRole('combobox', { name: 'Фильтр категорий' }).selectOption('cve');
        await page.getByText('Нет совпадений фильтра').waitFor();
        await page.getByRole('button', { name: 'Сбросить фильтр' }).click();
        await page.getByRole('button', { name: /Что означает неполный отчёт/ }).click();
        await page.getByText(/Нельзя считать непроверенные категории безопасными/).waitFor();
        await page.getByRole('button', { name: '04 Реальный режим' }).click();
        await page.getByText(/нет защищённого browser ingress/).waitFor();
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
        if (overflow || errors.length)
          throw Error(
            `${concept} ${width} ${reducedMotion}: overflow=${overflow}, errors=${errors.join(';')}`,
          );
        checks++;
        await page.close();
      }
  console.log(
    `Chromium: ${checks} variants × widths × motion states passed; create/detail/filter/accordion/live and no overflow/page errors.`,
  );
} finally {
  await browser?.close();
  await server.close();
}
