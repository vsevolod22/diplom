import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { CursorReportPager, type PageDescription } from '@/pages/scans/CursorReportPager';
afterEach(cleanup);
const token = (offset: number) => btoa(JSON.stringify({ v: 1, q: 'a'.repeat(64), r: 'b'.repeat(64), o: offset })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
it('jumps directly among numbered seven-row pages and preserves verified revisits', async () => {
  const load = vi.fn(async (cursor: string | undefined) => {
    const start = cursor ? JSON.parse(atob(cursor.replace(/-/g, '+').replace(/_/g, '/'))).o : 0;
    return { start, rows: Array.from({ length: Math.min(7, 35 - start) }, (_, i) => `CVE-${start + i}`) };
  });
  const describe = (page: Awaited<ReturnType<typeof load>>): PageDescription => ({ checked: true, identity: 'fixed-report',
    rowIds: page.rows, rowFingerprint: JSON.stringify(page.rows), total: 35, offset: page.start,
    nextCursor: page.start + 7 < 35 ? token(page.start + 7) : null });
  render(<CursorReportPager reportKey="cve7" label="Уязвимости" enabled waiting="Ожидание" load={load} describe={describe} numberedPageSize={7}>
    {page => <ul>{page.rows.map(row => <li key={row}>{row}</li>)}</ul>}
  </CursorReportPager>);
  await screen.findByText('CVE-0');
  expect(screen.getAllByRole('listitem')).toHaveLength(7);
  const top = screen.getByRole('navigation', { name: 'Пагинация Уязвимости · сверху' });
  fireEvent.click(within(top).getByRole('button', { name: 'Страница 5' }));
  await screen.findByText('CVE-28');
  expect(load).toHaveBeenCalledTimes(2);
  expect(within(top).getByRole('button', { name: 'Страница 5' })).toHaveAttribute('aria-current', 'page');
  fireEvent.click(within(top).getByRole('button', { name: 'Страница 1' }));
  await screen.findByText('CVE-0');
  expect(load).toHaveBeenCalledTimes(3);
  expect(screen.queryByRole('alert')).toBeNull();
});
