import { expect, test } from '@playwright/test';

const baseline = process.env.SCENE_BASELINE === '1';
const routes = [
  { variant: 'list', path: '/demo/scans', heading: /Каждая проверка/ },
  { variant: 'create', path: '/demo/scans/new', heading: /Задайте границы/ },
  { variant: 'detail', path: '/demo/scans/partial-demo', heading: /Частичный/ },
] as const;

test('320px long fact geometry survives disabled decoration and has no live requests', async ({ page }) => {
  test.skip(baseline, 'New contract only');
  const apiRequests: string[] = [];
  page.on('request', (request) => {
    if (request.url().includes('/api/v1/')) apiRequests.push(request.url());
  });
  await page.route('**/api/v1/**', (request) => request.abort());
  await page.setViewportSize({ width: 320, height: 900 });
  await page.goto('/demo/scans/new');
  await page.addStyleTag({
    content:
      '.scan-a1__scene { display:none !important; } *, *::before, *::after { animation:none !important; transition:none !important; }',
  });
  await expect(page.getByRole('button', { name: 'Запуск недоступен' })).toBeDisabled();
  await page.evaluate(async () => {
    const { demoScans } = await import('/src/shared/api/scans/fixtureScanTransport.ts');
    demoScans[0].stage = 'unbroken-' + 's'.repeat(280);
  });
  await page.getByRole('link', { name: /К списку/ }).click();
  const facts = page.locator('.scan-a1__record-facts').first();
  await expect(facts).toContainText('unbroken-');
  const fragments = await facts.evaluate((element) => {
    const bounds = element.getBoundingClientRect();
    const range = document.createRange();
    range.selectNodeContents(element.querySelector('p')!);
    return [...range.getClientRects()].map((rect) => ({
      fits: rect.left >= bounds.left - 1 && rect.right <= bounds.right + 1,
    }));
  });
  expect(fragments.length).toBeGreaterThan(2);
  expect(fragments.every((fragment) => fragment.fits)).toBe(true);
  await page
    .getByRole('link', { name: /Открыть деталь/ })
    .first()
    .click();
  await expect(page.getByText('Прогресс: неизвестен', { exact: true })).toBeVisible();
  await expect(page.getByText('База уязвимостей недоступна', { exact: false })).toBeVisible();
  expect(apiRequests).toEqual([]);
});

for (const width of [320, 375, 1280]) {
  for (const reducedMotion of ['no-preference', 'reduce'] as const) {
    for (const route of routes) {
      test(`${route.variant} ${width} ${reducedMotion}: static geometry, immediate facts, keyboard`, async ({
        page,
      }) => {
        test.skip(
          baseline && reducedMotion === 'reduce',
          'Baseline needs one visual reference per size/route',
        );
        await page.setViewportSize({ width, height: 900 });
        await page.emulateMedia({ reducedMotion });
        await page.route('**/api/v1/**', (request) => request.abort());
        await page.goto(route.path);
        const scene = page.locator(`.scan-a1__scene--${route.variant}`);
        await expect(scene).toBeVisible();
        await scene.scrollIntoViewIfNeeded();
        if (baseline) {
          await scene.screenshot({
            path: `docs/scan-scene-task-28-screens/before-${route.variant}-${width}.png`,
          });
          return;
        }
        await expect(scene).toHaveAttribute('aria-hidden', 'true');
        await expect(scene.locator('[data-scan-scene-art]')).toHaveCSS('opacity', '1');
        await expect(scene.locator('[data-scan-scene-art]')).toHaveCSS('transform', 'none');
        expect(await scene.locator('canvas, button, a, input, [tabindex]').count()).toBe(0);
        expect(await scene.locator('[data-scan-glow]').count()).toBe(0);
        // Check every actual text fragment, not just document scrollWidth.
        const geometry = await scene.evaluate((root) => {
          const bounds = root.getBoundingClientRect();
          const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
          const failures: string[] = [];
          while (walker.nextNode()) {
            const node = walker.currentNode;
            if (!node.textContent?.trim()) continue;
            const range = document.createRange();
            range.selectNodeContents(node);
            for (const rect of range.getClientRects()) {
              if (
                rect.left < bounds.left - 1 ||
                rect.right > bounds.right + 1 ||
                rect.top < bounds.top - 1 ||
                rect.bottom > bounds.bottom + 1
              )
                failures.push(node.textContent);
            }
          }
          return { failures, height: bounds.height };
        });
        expect(geometry.failures).toEqual([]);
        if (route.variant === 'detail') expect(geometry.height).toBe(170);
        const rectBefore = await scene.locator('[data-scan-scene-art]').boundingBox();
        await page.waitForTimeout(200);
        expect(await scene.locator('[data-scan-scene-art]').boundingBox()).toEqual(rectBefore);
        expect(await scene.evaluate((root) => root.getAnimations({ subtree: true }).length)).toBe(0);
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);

        if (route.variant === 'list') {
          await expect(page.getByRole('heading', { name: route.heading, level: 2 })).toBeVisible();
          const footer = await scene.locator('.scan-a1__passport-footer').boundingBox();
          const cta = await page.locator('.scan-a1__intro-cta').boundingBox();
          if (!footer || !cta) throw new Error('Missing scene footer / CTA');
          expect(footer.y + footer.height).toBeLessThanOrEqual(cta.y);
          const firstCard = page.locator('.scan-a1__record .scan-a1__magic').first();
          await expect(firstCard.getByText(/Прогресс:/)).toBeVisible();
          const link = firstCard.getByRole('link');
          await link.focus();
          await expect(link).toHaveCSS('outline-style', 'solid');
          const box = await firstCard.boundingBox();
          if (!box) throw new Error('Missing MagicCard geometry');
          await page.mouse.move(box.x + 15, box.y + 15);
          await page.waitForTimeout(80);
          const gradient = await firstCard.evaluate((element) => getComputedStyle(element).backgroundImage);
          await page.mouse.move(box.x + box.width - 15, box.y + box.height - 15);
          if (reducedMotion === 'reduce') {
            await page.waitForTimeout(80);
            expect(await firstCard.evaluate((element) => getComputedStyle(element).backgroundImage)).toBe(
              gradient,
            );
            await expect(firstCard.locator('.scan-a1__spotlight')).toHaveCSS('display', 'none');
          } else {
            await expect
              .poll(() => firstCard.evaluate((element) => getComputedStyle(element).backgroundImage))
              .not.toBe(gradient);
          }
          await firstCard.dispatchEvent('pointerleave');
          await page.waitForTimeout(80);
          const resetGradient = await firstCard.evaluate(
            (element) => getComputedStyle(element).backgroundImage,
          );
          await firstCard.dispatchEvent('pointermove', {
            pointerType: 'touch',
            clientX: box.x + 40,
            clientY: box.y + 40,
          });
          await page.waitForTimeout(80);
          expect(await firstCard.evaluate((element) => getComputedStyle(element).backgroundImage)).toBe(
            resetGradient,
          );
        } else if (route.variant === 'create') {
          await expect(page.getByRole('button', { name: 'Запуск недоступен' })).toBeDisabled();
          const tabs = page.getByRole('tablist', { name: 'Памятка о подготовке скана' });
          await tabs.getByRole('tab', { name: '01 / Цель' }).focus();
          await page.keyboard.press('ArrowRight');
          await expect(tabs.getByRole('tab', { name: '02 / Границы' })).toBeFocused();
          await expect(page.getByRole('tabpanel')).toContainText('авторизованный GET status');
        } else {
          await expect(page.getByText('Прогресс: неизвестен')).toBeVisible();
          await expect(page.getByText('База уязвимостей недоступна', { exact: false })).toBeVisible();
          const trigger = page.getByRole('button', { name: 'Что означает неполный отчёт?' });
          await trigger.focus();
          await page.keyboard.press('Enter');
          await expect(trigger).toHaveAttribute('aria-expanded', 'true');
          await expect(page.getByText('Сбой проверки не означает', { exact: false })).toBeVisible();
          if (width < 640) {
            const filter = page.getByRole('button', { name: 'Фильтры' });
            await filter.focus();
            await page.keyboard.press('Enter');
            await expect(page.getByRole('dialog', { name: 'Фильтры находок' })).toBeVisible();
            await page.keyboard.press('Escape');
            await expect(filter).toBeFocused();
          }
        }
        await scene.scrollIntoViewIfNeeded();
        await scene.screenshot({
          path: `docs/scan-scene-task-28-screens/after-${route.variant}-${width}-${reducedMotion}.png`,
        });
        if (reducedMotion === 'reduce')
          await page.screenshot({
            path: `docs/scan-scene-task-28-screens/page-${route.variant}-${width}.png`,
            fullPage: true,
          });
      });
    }
  }
}
