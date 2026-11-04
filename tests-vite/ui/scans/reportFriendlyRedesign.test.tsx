import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ScanReportOverview } from '@/pages/scans/ScanReportOverview';
import { VulnAdvisoryCard } from '@/pages/scans/VulnAdvisoryCard';
import type { ScanStatus, VulnFinding } from '@/shared/api/scans/scanTransport';

const finding: VulnFinding = {
  findingId: 'friendly-synthetic-finding',
  cveId: 'CVE-2026-1000',
  ecosystem: 'apk',
  packageName: 'synthetic-library',
  installedVersion: '1.0',
  fixedVersion: '2.0',
  severity: 'HIGH',
};
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
function visibleText(element: HTMLElement) {
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
  const values: string[] = [];
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const parent = node.parentElement;
    if (!parent || parent.closest('[hidden]')) continue;
    const collapsed = parent.closest('details:not([open])');
    if (collapsed && !parent.closest('summary')) continue;
    values.push(node.textContent ?? '');
  }
  return values.join(' ');
}

describe('friendly report: actionable before technical disclosure', () => {
  it('high-risk finding explains significance and a next action without opening raw technical details', () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => {
        throw new Error('Unexpected network in friendly report test');
      }),
    );
    const { container } = render(
      <ul>
        <VulnAdvisoryCard finding={finding} />
      </ul>,
    );
    const row = container.querySelector('li')!;
    const text = visibleText(row);
    expect(text).toContain(finding.packageName);
    expect(text).toContain(finding.cveId);
    expect(text).toContain('Высокая оценка');
    expect(text).toContain('Следующий шаг.');
    expect(text).toContain('Сверьте исправление с поставщиком: данные источников неполны или расходятся.');
    expect(text).not.toContain(finding.findingId);
    expect(row.querySelectorAll('details[open]')).toHaveLength(0);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('missing source/fix cannot become a made-up assured fix or safety claim', () => {
    const { container } = render(
      <ul>
        <VulnAdvisoryCard finding={{ ...finding, fixedVersion: null, severity: 'UNKNOWN' }} />
      </ul>,
    );
    const text = visibleText(container.querySelector('li')!);
    expect(text).toMatch(/неизвест|не указан|не предостав|не подтвержд|недостаточно|источник не указал/i);
    expect(text).not.toMatch(/образ безопасен|угроз нет|гарантированно устран|обновите до 2\.0/i);
  });
});

const published: ScanStatus = {
  scanId: 'synthetic-friendly-overview',
  state: 'completed',
  percent: null,
  checks: ['secret', 'sbom', 'vuln'],
  perCheck: {
    secret: { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 2 },
    sbom: { check: 'sbom', coverage: 'image', outcome: 'checked', componentCount: 500 },
    vuln: {
      check: 'vuln',
      coverage: 'image',
      outcome: 'checked',
      findingCount: 41,
      os: { outcome: 'checked' },
      node: { outcome: 'checked' },
    },
  },
};
function countCell(label: string) {
  return screen.getByText(label, { selector: 'dt', exact: true }).parentElement!;
}
function mountOverview(status: ScanStatus = published) {
  const onShowFindings = vi.fn(),
    onShowCoverage = vi.fn();
  return {
    ...render(
      <ScanReportOverview status={status} onShowFindings={onShowFindings} onShowCoverage={onShowCoverage} />,
    ),
    onShowFindings,
    onShowCoverage,
  };
}

describe('friendly whole-report overview: published evidence, not loaded-page counts', () => {
  it('shows exact published whole-report totals and fact-bound priority actions without raw identity', () => {
    mountOverview();
    expect(countCell('Уязвимости пакетов')).toHaveTextContent('41 находка');
    expect(countCell('Возможные секреты')).toHaveTextContent('2 находки');
    expect(countCell('Состав образа')).toHaveTextContent('500 пакетов');
    expect(countCell('Настройки образа')).toHaveTextContent('Не запрашивалось');
    expect(screen.getByText(/Числа по всему отчёту выбранных проверок/)).toBeVisible();
    const actions = screen.getByRole('region', { name: 'Что требует внимания' });
    const items = within(actions).getAllByRole('listitem');
    expect(items[0]).toHaveTextContent('Проверьте ключи и пароли');
    expect(items[1]).toHaveTextContent('Обновите уязвимые зависимости');
    expect(items[0]).toHaveTextContent('Действующий ключ может дать посторонним доступ.');
    expect(items[1]).toHaveTextContent('Начните с высоких и критических оценок.');
    expect(actions).not.toHaveTextContent('срочно');
    expect(document.body).not.toHaveTextContent(published.scanId);
  });

  it('action links route to the exact source category and coverage callback, not unrelated raw sections', () => {
    const { onShowFindings, onShowCoverage, rerender } = mountOverview();
    fireEvent.click(screen.getByRole('link', { name: 'Посмотреть возможные секреты' }));
    expect(onShowFindings).toHaveBeenLastCalledWith('secret');
    expect(screen.getByRole('link', { name: 'Посмотреть возможные секреты' })).toHaveAttribute(
      'href',
      '#scan-report-secrets',
    );
    fireEvent.click(screen.getByRole('link', { name: 'Открыть пакеты и исправления' }));
    expect(onShowFindings).toHaveBeenLastCalledWith('vuln');
    expect(screen.getByRole('link', { name: 'Открыть пакеты и исправления' })).toHaveAttribute(
      'href',
      '#scan-report-vulnerabilities',
    );
    const partial: ScanStatus = {
      ...published,
      state: 'partial',
      perCheck: { ...published.perCheck, sbom: null },
    };
    rerender(
      <ScanReportOverview status={partial} onShowFindings={onShowFindings} onShowCoverage={onShowCoverage} />,
    );
    fireEvent.click(screen.getByRole('link', { name: 'Что осталось непроверенным' }));
    expect(onShowCoverage).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/Результаты неполны\./)).toBeVisible();
  });

  it.each(['failed', 'unsupported', 'skipped', 'not_authorized'] as const)(
    '%s legacy zero cannot become zero confirmed findings or invented priority work',
    (outcome) => {
      mountOverview({
        ...published,
        state: 'partial',
        checks: ['vuln'],
        perCheck: {
          vuln: { check: 'vuln', coverage: 'image', outcome, findingCount: 0 },
        },
      });
      expect(countCell('Уязвимости пакетов')).not.toHaveTextContent('0 находок');
      expect(countCell('Возможные секреты')).toHaveTextContent('Не запрашивалось');
      expect(screen.queryByRole('link', { name: 'Открыть пакеты и исправления' })).not.toBeInTheDocument();
      expect(screen.getByRole('heading', { name: 'Данных недостаточно для полного вывода' })).toBeVisible();
      expect(screen.getByText(/отсутствие находок не гарантирует безопасность/)).toBeVisible();
    },
  );

  it('checked without a published count remains unknown; checked zero is explicit and never means whole-application safety', () => {
    const { rerender } = mountOverview({
      ...published,
      checks: ['secret'],
      perCheck: {
        secret: { check: 'secret', coverage: 'image', outcome: 'checked' },
      },
    });
    expect(countCell('Возможные секреты')).toHaveTextContent('Количество пока неизвестно');
    expect(screen.getByText(/Результаты неполны\./)).toBeVisible();
    rerender(
      <ScanReportOverview
        status={{
          ...published,
          checks: ['secret'],
          perCheck: {
            secret: { check: 'secret', coverage: 'image', outcome: 'checked', findingCount: 0 },
          },
        }}
        onShowFindings={vi.fn()}
        onShowCoverage={vi.fn()}
      />,
    );
    expect(countCell('Возможные секреты')).toHaveTextContent('0 находок');
    expect(screen.getByRole('heading', { name: 'В выполненных проверках находок нет' })).toBeVisible();
    expect(screen.getByText(/отсутствие находок не гарантирует безопасность/)).toBeVisible();
  });

  it('active durable outcomes never publish counts or static terminal recommendations before report publication', () => {
    mountOverview({
      ...published,
      state: 'running',
      perCheck: { secret: null, sbom: null, vuln: null },
      progress: {
        basis: 'durable-outcomes-v1',
        requestedChecks: ['secret', 'sbom', 'vuln'],
        outcomes: { secret: 'checked', sbom: null, vuln: null },
        resolvedChecks: 1,
        checkedChecks: 1,
      },
    });
    expect(countCell('Возможные секреты')).toHaveTextContent('Количество пока неизвестно');
    expect(screen.queryByRole('region', { name: 'Что требует внимания' })).not.toBeInTheDocument();
    expect(screen.getByText(/Итоговые количества пока неизвестны/)).toBeVisible();
  });
});
