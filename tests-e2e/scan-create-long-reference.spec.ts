import { expect, test } from '@playwright/test';

const policy = {
  pageSize: 12,
  maxPages: 5,
  maxCandidates: 60,
  maxActivePerProcess: 8,
  maxActivePerSubject: 2,
  maxRequestsPerSubject: 30,
  rateWindowMs: 60000,
  maxSessions: 1024,
  maxRateEntries: 1024,
  scope: 'process-local',
};

for (const { width, zoom } of [
  { width: 320, zoom: 1 },
  { width: 375, zoom: 1 },
  { width: 768, zoom: 1 },
  { width: 1280, zoom: 1 },
  { width: 1440, zoom: 1 },
  // CSS zoom exercises enlarged text/layout, not deviceScaleFactor (which only changes rasterization).
  { width: 1280, zoom: 2 },
]) {
  test(`live create: archived digest fits at ${width}px, ${zoom * 100}% CSS zoom`, async ({
    page,
    baseURL,
  }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 });
    const unexpected: string[] = [];
    const launches: unknown[] = [];
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    // Browser-only API: no credentials, backend, private env, or external registry/font requests.
    await page.route('**/*', (route) => {
      const request = route.request();
      const url = new URL(request.url());
      if (url.origin !== baseURL) return route.abort();
      if (!url.pathname.startsWith('/api/')) return route.continue();
      const json = (body: unknown, status = 200, headers = {}) =>
        route.fulfill({
          status,
          headers,
          contentType: 'application/json',
          body: JSON.stringify(body),
        });
      if (url.pathname === '/api/v1/auth/me' && request.method() === 'GET') {
        return json({ id: 'long-reference-browser-test', email: 'layout@example.invalid' });
      }
      if (url.pathname === '/api/v1/browser/scans/images/eligibility' && request.method() === 'POST') {
        return json({
          imageReference: request.postDataJSON().imageReference,
          eligible: false,
          eligibility: 'unsupported',
          allowedCheckSets: [],
          reason: 'UNSUPPORTED_SCAN',
        });
      }
      if (url.pathname === '/api/v1/browser/scans/images' && request.method() === 'GET') {
        return json({ items: [], loaded: 0, pages: 1, nextCursor: null, state: 'terminal', policy });
      }
      if (url.pathname.startsWith('/api/v1/browser/runtime/') && request.method() === 'GET') {
        return json({ errorCode: 'RUNTIME_UNAVAILABLE' }, 503);
      }
      if (url.pathname === '/api/v1/browser/scans' && request.method() === 'POST') {
        launches.push(request.postDataJSON());
        return json({ errorCode: 'SCAN_CAPACITY' }, 429, { 'retry-after': '60' });
      }
      unexpected.push(`${request.method()} ${url.pathname}`);
      return route.abort();
    });

    await page.goto('/scans/new');
    if (zoom !== 1)
      await page.evaluate((value) => {
        document.documentElement.style.zoom = String(value);
      }, zoom);
    const form = page.getByRole('form', { name: 'Параметры скана' });
    await expect(form).toBeVisible();
    const submit = form.getByRole('button', { name: 'Запустить скан', exact: true });
    const consent = form.getByRole('checkbox', { name: /Подтверждаю выбранную цель и область/ });
    await expect(submit).toBeDisabled();
    await expect(consent).not.toBeChecked();
    await expect(form.getByRole('button', { name: /nginx · закреплённый пример/ })).toBeDisabled();

    // Read the real alpineTargets rendered by ScanCreatePage; don't maintain a shorter test-only copy.
    const references = await form.locator('.scan-a1__target').evaluateAll((buttons) =>
      buttons
        .filter((button) => button.querySelector('strong')?.textContent?.startsWith('Alpine'))
        .map(
          (button) =>
            button.textContent?.match(
              /registry-1\.docker\.io\/library\/alpine(?:@sha256:[a-f0-9]{64}|:[a-z0-9.]+)/,
            )?.[0] ?? '',
        )
        .sort((a, b) => b.length - a.length),
    );
    const reference = references[0];
    expect(reference).toMatch(/@sha256:[a-f0-9]{64}$/);
    const target = form
      .getByRole('button', { name: /Alpine · 3.16 \(архивный/ })
      .filter({ hasText: reference });
    await target.click();
    await expect(target).toHaveAttribute('aria-pressed', 'true');
    await expect(submit).toBeDisabled();
    const selected = form
      .locator('p')
      .filter({ hasText: 'Выбранная цель (сохраняется отдельно от поиска):' });
    await expect(selected).toContainText(reference);
    await expect(consent).toHaveAccessibleName(new RegExp(reference.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    await expect(form.locator('input[type="hidden"]')).toHaveValue(reference);

    // Preserve checkbox and confirmation guards while exercising their actual flex labels.
    const secret = form.getByRole('checkbox', { name: 'Secrets · проверка образа', exact: true });
    const sbom = form.getByRole('checkbox', { name: /SBOM · перечень пакетов/ });
    await expect(secret).toBeChecked();
    await expect(sbom).not.toBeChecked();
    await expect(form.getByRole('checkbox', { name: /Image config · OCI User metadata/ })).not.toBeChecked();
    await expect(form.getByRole('checkbox', { name: /Host · отдельный opt-in/ })).toBeDisabled();
    await consent.check();
    await expect(submit).toBeEnabled();
    await sbom.check();
    await expect(consent).not.toBeChecked();
    await expect(submit).toBeDisabled();
    await sbom.uncheck();
    await secret.uncheck();
    await consent.check();
    await expect(submit).toBeDisabled();
    await secret.check();
    await expect(consent).not.toBeChecked();
    await consent.check();
    await expect(submit).toBeEnabled();

    // Search may hide all catalogue cards, but must retain the full selected reference and consent.
    await page.getByRole('searchbox', { name: 'Поиск по доступным образам' }).fill('no-matching-image');
    await expect(page.getByRole('status', { name: 'Состояние поиска Docker Hub' })).toHaveText(
      'Ничего не найдено в Docker Hub.',
    );
    await expect(selected).toContainText(reference);
    await expect(consent).toBeChecked();
    await page.getByRole('searchbox').clear();
    await expect(target).toHaveAttribute('aria-pressed', 'true');
    await page.evaluate(() => document.fonts.ready);

    const geometry = await form.evaluate((root) => {
      const bounds = root.getBoundingClientRect();
      const style = getComputedStyle(root);
      const scale = bounds.width / (root as HTMLElement).offsetWidth;
      const left = bounds.left + parseFloat(style.paddingLeft) * scale;
      const right = bounds.right - parseFloat(style.paddingRight) * scale;
      const failures: string[] = [];
      const fits = (rect: DOMRect, min: number, max: number) => rect.left >= min - 1 && rect.right <= max + 1;
      const grid = root.parentElement!;
      const gridBounds = grid.getBoundingClientRect();
      if (!fits(bounds, gridBounds.left, gridBounds.right)) failures.push('form exceeds grid');
      if (!fits(bounds, 0, window.innerWidth)) failures.push('form exceeds viewport');
      for (let ancestor: Element | null = grid; ancestor; ancestor = ancestor.parentElement) {
        if (['hidden', 'clip'].includes(getComputedStyle(ancestor).overflowX)) {
          failures.push(`ancestor masks overflow: ${ancestor.tagName}.${ancestor.className}`);
        }
      }
      for (const element of [grid, root, ...root.querySelectorAll('*')]) {
        if (!element.getClientRects().length) continue;
        const css = getComputedStyle(element);
        const lineClamp = css.getPropertyValue('line-clamp') || css.getPropertyValue('-webkit-line-clamp');
        if (
          element.textContent?.trim() &&
          (['hidden', 'clip'].includes(css.overflowX) ||
            css.textOverflow === 'ellipsis' ||
            (lineClamp && lineClamp !== 'none'))
        ) {
          failures.push(`clipped content: ${element.tagName}.${element.className}`);
        }
        if (element !== grid && element !== root && !fits(element.getBoundingClientRect(), left, right)) {
          failures.push(`element exceeds form content: ${element.tagName}.${element.className}`);
        }
      }
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      while (walker.nextNode()) {
        const node = walker.currentNode;
        if (!node.textContent?.trim()) continue;
        const parent = node.parentElement!;
        const parentBounds = parent.getBoundingClientRect();
        const range = document.createRange();
        range.selectNodeContents(node);
        for (const rect of range.getClientRects()) {
          if (!fits(rect, left, right) || !fits(rect, parentBounds.left, parentBounds.right)) {
            failures.push(`text exceeds cell/form: ${node.textContent}`);
          }
        }
      }
      return {
        failures,
        formWidth: bounds.width,
        gridWidth: gridBounds.width,
        buttonWidth: root.querySelector('button[type="submit"]')!.getBoundingClientRect().width,
        contentWidth: right - left,
        documentWidth: document.documentElement.scrollWidth,
        viewportWidth: window.innerWidth,
        confirmationLines: (() => {
          const range = document.createRange();
          range.selectNodeContents(root.querySelector('label strong')!);
          return new Set([...range.getClientRects()].map((rect) => rect.top)).size;
        })(),
        pageOverflow: [...document.querySelectorAll('body *')]
          .filter((element) => {
            if (!element.textContent?.trim() || element.closest('.scan-a1__scene')) return false;
            const rect = element.getBoundingClientRect();
            return rect.width && (rect.left < -1 || rect.right > window.innerWidth + 1);
          })
          .map((element) => ({
            tag: element.tagName,
            className: element.getAttribute('class'),
            text: element.textContent?.slice(0, 100),
            width: element.getBoundingClientRect().width,
            minWidth: getComputedStyle(element).minWidth,
          })),
      };
    });
    await testInfo.attach('geometry', {
      body: JSON.stringify(geometry, null, 2),
      contentType: 'application/json',
    });
    await form.screenshot({ path: testInfo.outputPath('form.png') });
    expect(geometry.failures, JSON.stringify(geometry)).toEqual([]);
    expect(geometry.documentWidth, JSON.stringify(geometry)).toBeLessThanOrEqual(geometry.viewportWidth);
    expect(geometry.buttonWidth).toBeLessThanOrEqual(geometry.contentWidth + 1);
    expect(geometry.confirmationLines).toBeGreaterThan(1);
    await testInfo.attach('form', { path: testInfo.outputPath('form.png'), contentType: 'image/png' });
    await submit.focus();
    await expect(submit).toBeFocused();
    await expect(submit).toHaveCSS('outline-style', 'solid');
    expect(launches).toEqual([]);

    if (width === 375) {
      await submit.click();
      await expect(page.getByRole('status', { name: 'Ожидание сервера' })).toContainText(
        'Ожидание допуска запуска',
      );
      await expect(submit).toBeDisabled();
      expect(launches).toEqual([
        { imageReference: reference, scope: 'image', checks: ['secret'], idempotencyKey: expect.any(String) },
      ]);
    }
    expect(unexpected).toEqual([]);
    expect(errors).toEqual([]);
  });
}
