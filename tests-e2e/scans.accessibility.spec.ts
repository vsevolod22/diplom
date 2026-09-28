import { expect, test } from '@playwright/test';

function contrast(foreground: number[], background: number[]) {
  const channel = (value: number) => {
    const normalized = value / 255;
    return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
  };
  const luminance = (values: number[]) =>
    0.2126 * channel(values[0]) + 0.7152 * channel(values[1]) + 0.0722 * channel(values[2]);
  const lighter = Math.max(luminance(foreground), luminance(background));
  const darker = Math.min(luminance(foreground), luminance(background));
  return (lighter + 0.05) / (darker + 0.05);
}

for (const width of [320, 375, 1280]) {
  test(`fixture scan at ${width}px: keyboard, text status, no horizontal overflow or canvas dependency`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 740 });
    await page.goto('/demo/scans/partial-demo');
    await expect(page.getByText('ДЕМО · вымышленные данные', { exact: false })).toBeVisible();
    await expect(page.getByText('Состояние из локальной фикстуры', { exact: false })).toBeVisible();
    await expect(page.locator('main nav [aria-current="page"]')).toHaveCount(0);
    await expect(page.getByText('Статус: Частичный результат')).toBeVisible();
    await expect(page.getByText('Прогресс: неизвестен')).toBeVisible();
    await expect(page.getByText('База уязвимостей недоступна', { exact: false })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Отмена недоступна' })).toBeDisabled();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    const columns = await page
      .locator('section[aria-labelledby="scan-detail"] > .grid')
      .evaluate((element) => getComputedStyle(element).gridTemplateColumns.split(' ').length);
    expect(columns).toBe(width < 640 ? 1 : 2);
    expect(await page.locator('canvas').count()).toBe(0);
    if (width < 640) {
      const trigger = page.getByRole('button', { name: 'Фильтры' });
      await trigger.focus();
      await page.keyboard.press('Enter');
      const dialog = page.getByRole('dialog', { name: 'Фильтры находок' });
      await expect(dialog).toBeVisible();
      const select = dialog.getByLabel('Категория');
      await expect(select).toBeFocused();
      await select.selectOption('vulnerability');
      await expect(page.getByText('Нет совпадений фильтра', { exact: false })).toBeVisible();
      await page.keyboard.press('Tab');
      await expect(dialog.getByRole('button', { name: 'Сбросить фильтр' })).toBeFocused();
      await page.keyboard.press('Shift+Tab');
      await expect(select).toBeFocused();
      await page.keyboard.press('Escape');
      await expect(trigger).toBeFocused();
      await expect(dialog).toHaveCount(0);
      await page.keyboard.press('Enter');
      await expect(dialog.getByLabel('Категория')).toHaveValue('vulnerability');
    } else {
      await expect(page.getByLabel('Категория')).toBeVisible();
      await expect(page.getByRole('button', { name: 'Фильтры' })).toBeHidden();
    }
  });
}

test('navigation marks only the actual list or create page as current', async ({ page }) => {
  await page.goto('/demo/scans');
  await expect(page.getByRole('link', { name: 'Демо', exact: true })).toHaveAttribute('aria-current', 'page');
  await page.goto('/demo/scans/new');
  await expect(page.getByRole('link', { name: /Новый скан/ })).toHaveAttribute('aria-current', 'page');
  await expect(page.getByRole('link', { name: 'Демо', exact: true })).not.toHaveAttribute(
    'aria-current',
    'page',
  );
});

for (const colorScheme of ['light', 'dark'] as const) {
  test(`fixture: text contrast and keyboard focus in ${colorScheme} system scheme`, async ({ page }) => {
    await page.emulateMedia({ colorScheme, reducedMotion: 'reduce' });
    await page.setViewportSize({ width: 375, height: 740 });
    await page.goto('/demo/scans/partial-demo');
    await expect(page.getByText('Статус: Частичный результат')).toBeVisible();
    const pairs = await page.evaluate(() => {
      const canvas = document.createElement('canvas');
      const context = canvas.getContext('2d');
      if (!context) throw new Error('Cannot sample browser-computed colors');
      const rgb = (color: string) => {
        context.fillStyle = color;
        context.fillRect(0, 0, 1, 1);
        return Array.from(context.getImageData(0, 0, 1, 1).data).slice(0, 3);
      };
      const css = (selector: string, property: 'color' | 'backgroundColor') => {
        const element = document.querySelector(selector);
        if (!element) throw new Error(`Missing element: ${selector}`);
        return getComputedStyle(element)[property];
      };
      return [
        [rgb(css('main h1', 'color')), rgb(css('main', 'backgroundColor'))],
        [rgb(css('main nav a', 'color')), rgb(css('main', 'backgroundColor'))],
        [rgb(css('main [role="note"]', 'color')), rgb(css('main [role="note"]', 'backgroundColor'))],
      ];
    });
    for (const [text, surface] of pairs) expect(contrast(text, surface)).toBeGreaterThanOrEqual(4.5);
    const trigger = page.getByRole('button', { name: 'Фильтры' });
    await trigger.focus();
    await page.keyboard.press('Enter');
    const dialog = page.getByRole('dialog', { name: 'Фильтры находок' });
    await expect(dialog.getByLabel('Категория')).toBeFocused();
    const dialogColors = await page.evaluate(() => {
      const content = document.querySelector('[role="dialog"]');
      if (!content) throw new Error('Dialog missing');
      const style = getComputedStyle(content);
      const canvas = document.createElement('canvas');
      const context = canvas.getContext('2d');
      if (!context) throw new Error('Cannot sample dialog colors');
      const rgb = (color: string) => {
        context.fillStyle = color;
        context.fillRect(0, 0, 1, 1);
        return Array.from(context.getImageData(0, 0, 1, 1).data).slice(0, 3);
      };
      return [rgb(style.color), rgb(style.backgroundColor)];
    });
    expect(contrast(dialogColors[0], dialogColors[1])).toBeGreaterThanOrEqual(4.5);
    await page.keyboard.press('Escape');
    await expect(trigger).toBeFocused();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
  });
}
