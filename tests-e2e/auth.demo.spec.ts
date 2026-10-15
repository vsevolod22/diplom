import { expect, test } from '@playwright/test';

test('optional account and guest demo at 320px with auth backend offline', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 740 });
  const scanRequests: string[] = [];
  page.on('request', request => { if (/\/api\/v1\/(?:browser\/)?scans/.test(request.url())) scanRequests.push(request.url()); });
  await page.goto('/register');
  await expect(page.getByRole('heading', { name: /Создайте аккаунт/ })).toBeVisible();
  await expect(page.getByRole('link', { name: /Смотреть демо без регистрации/ })).toBeVisible();
  await page.getByLabel('Email').fill('visitor@example.org');
  await page.getByLabel('Пароль').fill('unique-strong-passphrase');
  await page.getByRole('button', { name: 'Создать аккаунт' }).click();
  await expect(page.getByRole('alert')).toContainText('Регистрация и вход сейчас недоступны');
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByRole('link', { name: /Смотреть демо без регистрации/ }).click();
  await expect(page.getByText('ДЕМО · вымышленные данные')).toBeVisible();
  expect(scanRequests).toEqual([]);
});
