import { expect, test } from '@playwright/test';

for (const width of [320, 375, 1280]) {
  test(`fixture scan at ${width}px: keyboard, text status, no horizontal overflow or canvas dependency`, async ({ page }) => {
    await page.setViewportSize({ width, height: 740 });
    await page.goto('/demo/scans/partial-demo');
    await expect(page.getByText('ДЕМО · вымышленные данные', { exact: false })).toBeVisible();
    await expect(page.getByText('Статус: Частичный результат')).toBeVisible();
    await expect(page.getByText('Прогресс: неизвестен')).toBeVisible();
    await expect(page.getByText('База уязвимостей недоступна', { exact: false })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Отмена недоступна' })).toBeDisabled();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    const columns = await page.locator('section[aria-labelledby="scan-detail"] > .grid').evaluate((element) => getComputedStyle(element).gridTemplateColumns.split(' ').length);
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
