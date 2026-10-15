import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page, baseURL }) => {
  await page.route('**/*', route => {
    const url = new URL(route.request().url());
    if (url.origin !== baseURL) return route.abort();
    if (url.pathname.startsWith('/api/')) return route.fulfill({ status: 503, contentType: 'application/json', body: '{"errorCode":"TEST_BACKEND_OFFLINE"}' });
    return route.continue();
  });
});

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

test('landing: Radix tabs switch by keyboard without inventing live scan data', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 740 });
  await page.goto('/');
  const tabs = page.getByRole('tablist', { name: 'Ракурсы исследования образа' });
  const image = tabs.getByRole('tab', { name: /Образ/ });
  await image.focus();
  await expect(image).toHaveAttribute('aria-selected', 'true');
  const focusColors = await image.evaluate((element) => {
    const style = getComputedStyle(element);
    const context = document.createElement('canvas').getContext('2d');
    if (!context) throw new Error('Cannot sample focus colors');
    const rgb = (color: string) => {
      context.fillStyle = color;
      context.fillRect(0, 0, 1, 1);
      return Array.from(context.getImageData(0, 0, 1, 1).data).slice(0, 3);
    };
    return [rgb(style.outlineColor), rgb(style.backgroundColor)];
  });
  expect(contrast(focusColors[0], focusColors[1])).toBeGreaterThanOrEqual(3);
  await page.keyboard.press('ArrowRight');
  const secrets = tabs.getByRole('tab', { name: /Secrets/ });
  await expect(secrets).toBeFocused();
  await expect(secrets).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('tabpanel')).toContainText(
    'Внутренний Secrets-only сценарий разрабатывается и ожидает приёмки',
  );
  await page.keyboard.press('ArrowRight');
  await expect(tabs.getByRole('tab', { name: /Покрытие/ })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('tabpanel')).toContainText('не SBOM и не скан');
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
  const panelFits = await page.locator('.home__explore-tabs').evaluate((tabsElement) => {
    const container = tabsElement.getBoundingClientRect();
    const panelText = tabsElement.querySelector('[data-state="active"] .home__explore-copy');
    if (!panelText) throw new Error('Active panel copy missing');
    const text = panelText.getBoundingClientRect();
    return text.left >= container.left && text.right <= container.right;
  });
  expect(panelFits).toBe(true);
});

for (const width of [320, 375, 1280]) {
  test(`demo list and launch at ${width}px stay clearly fictional and readable`, async ({ page }) => {
    await page.setViewportSize({ width, height: 800 });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/demo/scans');
    await expect(page.getByRole('heading', { name: /Каждая проверка/, level: 2 })).toBeVisible();
    await expect(page.getByText('Вымышленные данные · не результат реальной проверки').first()).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    if (width === 375 || width === 1280)
      await page.screenshot({ path: `tests-e2e/test-results/frontend-review/scan-list-${width}.png`, fullPage: true });
    await page.goto('/demo/scans/new');
    await expect(page.getByRole('button', { name: 'Запуск недоступен' })).toBeDisabled();
    await expect(page.getByText('Область доверия', { exact: true })).toBeVisible();
    await expect(page.getByText('Secrets · проверка образа', { exact: false }).first()).toBeVisible();
    await expect(page.locator('fieldset input:checked')).toHaveCount(1);
    await expect(page.getByText('host и running container не поддерживаются', { exact: false }).first()).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    if (width === 375 || width === 1280)
      await page.screenshot({ path: `tests-e2e/test-results/frontend-review/scan-create-${width}.png`, fullPage: true });
  });
  test(`landing at ${width}px: clear demo boundary and no horizontal overflow`, async ({ page }) => {
    await page.setViewportSize({ width, height: 800 });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/');
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await expect(page.getByText('Демо — вымышленные данные.', { exact: false })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Смотреть демо' })).toHaveAttribute('href', '/demo/scans');
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    const titleLines = await page.locator('.home__title-line').evaluateAll((lines) =>
      lines.map((line) => {
        const { left, top, right, bottom } = line.getBoundingClientRect();
        return { left, top, right, bottom };
      }),
    );
    expect(titleLines).toHaveLength(3);
    for (const line of titleLines) {
      expect(line.left).toBeGreaterThanOrEqual(0);
      expect(line.right).toBeLessThanOrEqual(width);
    }
    for (let i = 1; i < titleLines.length; i++)
      expect(titleLines[i].top).toBeGreaterThanOrEqual(titleLines[i - 1].bottom);
    await page.screenshot({ path: `tests-e2e/test-results/frontend-review/landing-${width}.png`, fullPage: true });
  });
  test(`fixture scan at ${width}px: keyboard, text status, no horizontal overflow or canvas dependency`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 740 });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/demo/scans/partial-demo');
    await expect(page.getByText('ДЕМО · вымышленные данные', { exact: false })).toBeVisible();
    await expect(page.getByText('Состояние из локальной фикстуры', { exact: false })).toBeVisible();
    await expect(page.locator('main nav [aria-current="page"]')).toHaveCount(0);
    await expect(
      page.locator('.scan-a1__facts').getByText('Частичный результат', { exact: true }),
    ).toBeVisible();
    await expect(page.getByText('Прогресс: неизвестен')).toBeVisible();
    await expect(page.getByText('База уязвимостей недоступна', { exact: false })).toBeVisible();
    await expect(page.getByText('Демо не отправляет серверную отмену.')).toBeVisible();
        await expect(page.getByRole('button', { name: 'Отменить скан' })).toHaveCount(0);
    if (width === 375 || width === 1280)
      await page.screenshot({ path: `tests-e2e/test-results/frontend-review/scan-detail-${width}.png`, fullPage: true });
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    const columns = await page
      .locator('.scan-a1__grid')
      .evaluate((element) => getComputedStyle(element).gridTemplateColumns.split(' ').length);
    expect(columns).toBe(1);
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

for (const width of [320, 375, 1280]) {
  for (const reducedMotion of ['reduce', 'no-preference'] as const) {
    test(`21st.dev tabs and accordion: ${width}px ${reducedMotion}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 800 });
      await page.emulateMedia({ reducedMotion });
      await page.goto('/demo/scans/new');
      const tabs = page.getByRole('tablist', { name: 'Памятка о подготовке скана' });
      const target = tabs.getByRole('tab', { name: '01 / Цель' });
      await target.focus();
      await expect(target).toHaveCSS('outline-style', 'solid');
      await page.keyboard.press('ArrowRight');
      await expect(tabs.getByRole('tab', { name: '02 / Границы' })).toBeFocused();
      await expect(page.getByRole('tabpanel')).toContainText('авторизованный GET status');
      await expect(page.getByRole('button', { name: 'Запуск недоступен' })).toBeDisabled();
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
      if (reducedMotion === 'reduce')
        await page.screenshot({ path: `tests-e2e/test-results/frontend-review/21st-create-${width}.png`, fullPage: true });
      await page.goto('/demo/scans/partial-demo');
      await expect(page.getByText('База уязвимостей недоступна', { exact: false })).toBeVisible();
      await expect(page.getByText('Прогресс: неизвестен')).toBeVisible();
      const trigger = page.getByRole('button', { name: 'Что означает неполный отчёт?' });
      await trigger.focus();
      await expect(trigger).toHaveCSS('outline-style', 'solid');
      await page.keyboard.press('Enter');
      await expect(trigger).toHaveAttribute('aria-expanded', 'true');
      await expect(page.getByText('Сбой проверки не означает', { exact: false })).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
      if (reducedMotion === 'reduce')
        await page.screenshot({ path: `tests-e2e/test-results/frontend-review/21st-detail-${width}.png`, fullPage: true });
    });
  }
}

test('ordinary motion: MagicCard spotlight and mobile filter preserve keyboard focus', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 740 });
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.goto('/demo/scans');
  const firstCard = page.locator('.scan-a1__record .scan-a1__magic').first();
  await expect(firstCard).toBeVisible();
  await firstCard.scrollIntoViewIfNeeded();
  const box = await firstCard.boundingBox();
  if (!box) throw new Error('Missing MagicCard bounds');
  await page.mouse.move(box.x + 20, box.y + 20);
  const firstGradient = await firstCard.evaluate((element) => getComputedStyle(element).backgroundImage);
  await page.mouse.move(box.x + box.width - 20, box.y + box.height - 20);
  await expect
    .poll(() => firstCard.evaluate((element) => getComputedStyle(element).backgroundImage))
    .not.toBe(firstGradient);
  await expect
    .poll(() =>
      firstCard
        .locator('.scan-a1__spotlight')
        .evaluate((element) => Number(getComputedStyle(element).opacity)),
    )
    .toBeGreaterThan(0);
  const link = firstCard.getByRole('link');
  await link.focus();
  await expect(link).toBeFocused();
  await expect(link).toHaveCSS('outline-style', 'solid');

  await page.goto('/demo/scans/partial-demo');
  const trigger = page.getByRole('button', { name: 'Фильтры' });
  await trigger.focus();
  await page.keyboard.press('Enter');
  const dialog = page.getByRole('dialog', { name: 'Фильтры находок' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByLabel('Категория')).toBeVisible();
  const select = dialog.getByLabel('Категория');
  await expect(select).toBeFocused();
  await select.selectOption('vulnerability');
  await page.keyboard.press('Tab');
  await expect(dialog.getByRole('button', { name: 'Сбросить фильтр' })).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  await expect(select).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  await expect(trigger).toBeFocused();
});

test('21st.dev navigation card keeps real destinations, keyboard focus and reduced motion', async ({
  page,
}) => {
  await page.setViewportSize({ width: 320, height: 740 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/demo/scans/partial-demo');
  const nav = page.getByRole('navigation', { name: 'Разделы сканирования' });
  await expect(nav.locator('.scan-nav-card__items > li')).toHaveCount(3);
    // Tap animations must not introduce a second Tab stop inside a link.
    await expect(nav.locator('a [tabindex="0"]')).toHaveCount(0);
  await expect(nav.locator('[aria-current="page"]')).toHaveCount(0);
  await expect(nav.getByRole('link', { name: 'Реальные сканы' })).toHaveAttribute('href', '/scans');
  await expect(nav.getByRole('link', { name: 'Новый скан' })).toHaveAttribute('href', '/demo/scans/new');
  const demo = nav.getByRole('link', { name: 'Демо' });
  for (let i = 0; i < 6; i++) {
    await page.keyboard.press('Tab');
    if (await demo.evaluate((element) => document.activeElement === element)) break;
  }
  await expect(demo).toBeFocused();
  await expect(demo).toHaveCSS('outline-style', 'solid');
  const item = demo.locator('.scan-nav-card__item');
  const before = await item.evaluate((element) => getComputedStyle(element).transform);
  await demo.hover();
  await page.waitForTimeout(350);
  expect(await item.evaluate((element) => getComputedStyle(element).transform)).toBe(before);
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/\/demo\/scans$/);
  await expect(nav.getByRole('link', { name: 'Демо' })).toHaveAttribute('aria-current', 'page');
  const liveLink = nav.getByRole('link', { name: 'Реальные сканы' });
  const description = await liveLink.getAttribute('aria-describedby');
  expect(description).toBeTruthy();
  await expect(page.locator(`[id="${description}"]`)).toHaveText('По защищённой сессии');
  await liveLink.click();
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByText(/Доступ закрыт/)).toBeVisible();
  await page.goto('/demo/scans');
  await nav.getByRole('link', { name: 'Новый скан' }).click();
  await expect(page).toHaveURL(/\/demo\/scans\/new$/);
  await expect(page.getByRole('button', { name: 'Запуск недоступен' })).toBeDisabled();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.reload();
  await expect(nav.locator('a [tabindex="0"]')).toHaveCount(0);
    const first = nav.getByRole('link', { name: 'Реальные сканы' });
    await first.focus();
    await page.keyboard.press('Tab');
    await expect(nav.getByRole('link', { name: 'Демо', exact: true })).toBeFocused();
    const moving = nav.getByRole('link', { name: 'Демо' }).locator('.scan-nav-card__item');
  await moving.hover();
  await expect.poll(() => moving.evaluate((element) => getComputedStyle(element).transform)).not.toBe('none');
});

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
    await expect(
      page.locator('.scan-a1__facts').getByText('Частичный результат', { exact: true }),
    ).toBeVisible();
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
        [rgb(css('main h1', 'color')), rgb(css('.scan-shell__hero', 'backgroundColor'))],
        [rgb(css('main nav a', 'color')), rgb(css('.scan-shell__hero', 'backgroundColor'))],
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

test('long untrusted scan ID wraps without claiming a report or overflowing', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 740 });
  await page.goto(`/demo/scans/${'sha256:' + 'a'.repeat(128)}`);
  await expect(page.getByText(/Не удалось получить данные скана/)).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
});

for (const width of [320, 375, 1280]) {
  for (const motion of ['reduce', 'no-preference'] as const) {
    test(`A1 contract: list/create/detail/live at ${width}px ${motion}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 740 });
      await page.emulateMedia({ reducedMotion: motion });
      await page.goto('/demo/scans');
      await page.addStyleTag({
        content:
          '.scan-a1 *, .scan-a1 *::before, .scan-a1 *::after { animation: none !important; transition: none !important; }',
      });
      const records = page.locator('.scan-a1__records > li');
      await expect(records.first()).toBeVisible();
      expect(await records.count()).toBeGreaterThan(1);
      await expect(records.first().getByText('Прогресс: неизвестен', { exact: false })).toBeVisible();
      await expect(records.first().getByRole('link', { name: /Открыть деталь/ })).toHaveAttribute(
        'href',
        /\/demo\/scans\//,
      );
      const card = records.first().locator('.scan-a1__magic');
      await expect(card).toBeVisible();
      await expect(card.locator('.scan-a1__spotlight')).toHaveAttribute('aria-hidden', 'true');
      if (motion === 'reduce') await expect(card.locator('.scan-a1__spotlight')).toHaveCSS('display', 'none');
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);

      await page.goto('/demo/scans/new');
      await expect(page.getByText('Область доверия', { exact: true })).toBeVisible();
      await expect(page.getByRole('searchbox', { name: 'Поиск по доступным образам' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Запуск недоступен' })).toBeDisabled();
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);

      await page.goto('/demo/scans/partial-demo');
      await expect(page.getByText('База уязвимостей недоступна', { exact: false })).toBeVisible();
      await expect(page.getByText('Прогресс: неизвестен')).toBeVisible();
      await expect(page.getByText(/Порядок чтения/)).toBeVisible();
      await expect(page.getByText(/Демо не отправляет данные модели/)).toBeVisible();
            await expect(page.getByText(/Чат доступен только для авторизованного отчёта при разрешении сервера/)).toBeVisible();
            await expect(page.getByText('Чат пока не реализован.', { exact: false })).toHaveCount(0);
            await expect(page.getByRole('textbox', { name: 'Вопрос чату', exact: true })).toHaveCount(0);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);

      await page.goto('/scans');
      await expect(page).toHaveURL(/\/login$/);
      await expect(page.getByText(/Доступ закрыт/)).toBeVisible();
      await expect(page.locator('.scan-a1__records > li')).toHaveCount(0);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    });
  }
}

test('long unbroken stage fits the actual card text cell at 320px', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 740 });
  await page.goto('/demo/scans/new');
  await page.evaluate(async () => {
    const { demoScans } = await import('/src/shared/api/scans/fixtureScanTransport.ts');
    demoScans[0].stage = 'unbroken-' + 's'.repeat(280);
  });
  await page.getByRole('link', { name: /К списку/ }).click();
  const facts = page.locator('.scan-a1__record-facts').first();
  await expect(facts).toContainText('unbroken-');
  const bounds = await facts.evaluate((element) => {
    const card = element.closest('.scan-a1__magic')!.getBoundingClientRect();
    const cell = element.getBoundingClientRect();
    const line = element.querySelector('p')!;
    const range = document.createRange();
    range.selectNodeContents(line);
    return {
      card: { left: card.left, right: card.right },
      cell: { left: cell.left, right: cell.right },
      fragments: [...range.getClientRects()].map((rect) => ({ left: rect.left, right: rect.right })),
    };
  });
  expect(bounds.fragments.length).toBeGreaterThan(2);
  for (const fragment of bounds.fragments) {
    expect(fragment.left).toBeGreaterThanOrEqual(bounds.cell.left - 1);
    expect(fragment.right).toBeLessThanOrEqual(bounds.cell.right + 1);
    expect(fragment.right).toBeLessThanOrEqual(bounds.card.right - 1);
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
});

for (const width of [320, 375, 1280]) {
  for (const motion of ['reduce', 'no-preference'] as const) {
    test(`upstream artwork is decorative and responsive across three screens ${width}px ${motion}`, async ({
      page,
    }) => {
      await page.setViewportSize({ width, height: 740 });
      await page.emulateMedia({ reducedMotion: motion });
      for (const path of ['/demo/scans', '/demo/scans/new', '/demo/scans/partial-demo']) {
        await page.goto(path);
        const scene = page.locator('.scan-a1__scene:visible').first();
        await expect(scene).toHaveAttribute('aria-hidden', 'true');
        await scene.scrollIntoViewIfNeeded();
        await expect(scene.locator('[data-scan-glow]')).toHaveCount(0);
        expect(await scene.evaluate(element => element.getAnimations({ subtree: true }).length)).toBe(0);
        await expect(scene.locator('[data-scan-scene-art]')).toBeAttached();
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
      }
      await page.goto('/demo/scans/new');
      await page.addStyleTag({ content: '.scan-a1__scene { display: none !important; }' });
      await expect(page.getByRole('button', { name: 'Запуск недоступен' })).toBeDisabled();
      await page.goto('/demo/scans/partial-demo');
      await page.addStyleTag({ content: '.scan-a1__scene { display: none !important; }' });
      await page
        .getByRole('navigation', { name: 'Разделы отчёта' })
        .getByRole('link', { name: /Покрытие/ })
        .click();
      await expect(page.getByRole('heading', { name: 'Покрытие проверок' })).toBeVisible();
      await expect(page.getByText('База уязвимостей недоступна', { exact: false })).toBeVisible();
    });
  }
}
