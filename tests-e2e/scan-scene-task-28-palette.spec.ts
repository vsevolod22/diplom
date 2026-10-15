import { expect, test } from '@playwright/test';

const routes = [
  { variant: 'list', path: '/demo/scans' },
  { variant: 'create', path: '/demo/scans/new' },
  { variant: 'detail', path: '/demo/scans/partial-demo' },
] as const;
const cases = [
  ...[320, 1024, 1280, 1440].map((width) => ({ width, reducedMotion: 'no-preference' as const })),
  { width: 320, reducedMotion: 'reduce' as const },
];

for (const { width, reducedMotion } of cases) {
  for (const { variant, path } of routes) {
    test(`${variant} ${width} ${reducedMotion}: A1 palette, unchanged static passport and controls`, async ({
      page,
    }, testInfo) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ reducedMotion });
      const apiRequests: string[] = [];
      page.on('request', (request) => {
        if (request.url().includes('/api/v1/')) apiRequests.push(request.url());
      });
      await page.route('**/*', (route) => {
        const url = new URL(route.request().url());
        return url.origin === 'http://127.0.0.1:4187' && !url.pathname.startsWith('/api/')
          ? route.continue()
          : route.abort();
      });
      await page.goto(path);
      const scene = page.locator(`.scan-a1__scene--${variant}`);
      await expect(scene).toBeVisible();
      await expect(scene).toHaveAttribute('aria-hidden', 'true');
      await expect(scene).toHaveCSS('background-color', 'rgb(20, 19, 36)');
      await expect(scene).toHaveCSS('color', 'rgb(250, 248, 255)');
      await expect(scene.locator('.scan-a1__passport-scope')).toHaveCSS(
        'background-color',
        'rgb(33, 31, 52)',
      );
      await expect(scene.locator('.scan-a1__passport-scope')).toHaveCSS(
        'border-top-color',
        'rgb(96, 91, 116)',
      );
      await expect(scene.locator('.scan-a1__passport-title strong')).toHaveCSS(
        'background-color',
        'rgb(209, 255, 94)',
      );
      await expect(scene.locator('.scan-a1__passport-title strong')).toHaveCSS('color', 'rgb(20, 19, 36)');
      await expect(scene.locator('.scan-a1__passport-label').first()).toHaveCSS('color', 'rgb(209, 255, 94)');
      await expect(scene.locator('.scan-a1__passport-footer')).toHaveCSS('color', 'rgb(198, 192, 214)');
      await expect(scene.locator('[data-scan-scene-art]')).toHaveCSS('opacity', '1');
      await expect(scene.locator('[data-scan-scene-art]')).toHaveCSS('transform', 'none');
      expect(await scene.locator('canvas, button, a, input, [tabindex], [role]').count()).toBe(0);
      expect(await scene.evaluate((root) => root.getAnimations({ subtree: true }).length)).toBe(0);
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
      if (variant === 'detail') expect(geometry.height).toBe(170);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
      const clippedButtons = await page.getByRole('button').evaluateAll((buttons) =>
        buttons
          .filter((button) => {
            const rect = button.getBoundingClientRect();
            if (!rect.width || !rect.height) return false;
            return (
              rect.left < -1 ||
              rect.right > window.innerWidth + 1 ||
              button.scrollWidth > button.clientWidth + 1
            );
          })
          .map((button) => button.textContent),
      );
      expect(clippedButtons).toEqual([]);
      if (variant === 'list') {
        const footer = await scene.locator('.scan-a1__passport-footer').boundingBox();
        const cta = await page.locator('.scan-a1__intro-cta').boundingBox();
        if (!footer || !cta) throw new Error('Missing footer / CTA');
        expect(footer.y + footer.height).toBeLessThanOrEqual(cta.y);
        const link = page.getByRole('link', { name: /Открыть деталь/ }).first();
        await link.focus();
        await expect(link).toHaveCSS('outline-style', 'solid');
        await expect(page.locator('.scan-a1__record-facts').first()).toContainText('Прогресс:');
      } else if (variant === 'create') {
        await expect(page.getByRole('button', { name: 'Запуск недоступен' })).toBeDisabled();
      } else {
        await expect(page.getByText('Прогресс: неизвестен', { exact: true })).toBeVisible();
        await expect(page.getByText('База уязвимостей недоступна', { exact: false })).toBeVisible();
      }
      await scene.scrollIntoViewIfNeeded();
      await scene.screenshot({
        path: `test-results/scan-scene-task-28-palette/${variant}-${width}-${reducedMotion}.png`,
      });
      await page.screenshot({
        path: `test-results/scan-scene-task-28-palette/page-${variant}-${width}-${reducedMotion}.png`,
        fullPage: true,
      });
      await testInfo.attach('geometry', { body: JSON.stringify(geometry), contentType: 'application/json' });
      expect(apiRequests).toEqual([]);
      // The detail tokens are inherited; list/create use identical fallback values.
      await scene.evaluate((root) => (root as HTMLElement).style.setProperty('--a1-accent', '#e0ff80'));
      await expect(scene.locator('.scan-a1__passport-title strong')).toHaveCSS(
        'background-color',
        'rgb(224, 255, 128)',
      );
    });
  }
}

test('320px: semantic facts and disabled launch survive absent decoration', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 900 });
  const apiRequests: string[] = [];
  page.on('request', (request) => {
    if (request.url().includes('/api/v1/')) apiRequests.push(request.url());
  });
  await page.route('**/*', (route) => {
    const url = new URL(route.request().url());
    return url.origin === 'http://127.0.0.1:4187' && !url.pathname.startsWith('/api/')
      ? route.continue()
      : route.abort();
  });
  await page.goto('/demo/scans/new');
  await page.addStyleTag({ content: '.scan-a1__scene { display: none !important; }' });
  await expect(page.getByRole('button', { name: 'Запуск недоступен' })).toBeDisabled();
  await page.goto('/demo/scans/partial-demo');
  await page.addStyleTag({ content: '.scan-a1__scene { display: none !important; }' });
  await expect(page.getByText('Прогресс: неизвестен', { exact: true })).toBeVisible();
  await expect(page.getByText('База уязвимостей недоступна', { exact: false })).toBeVisible();
  expect(apiRequests).toEqual([]);
});
