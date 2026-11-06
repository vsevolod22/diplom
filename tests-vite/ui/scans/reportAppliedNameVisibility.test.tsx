import '@testing-library/jest-dom/vitest';
import { useState } from 'react';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { SbomReportControls } from '@/pages/scans/ReportViewControls';
import type { SbomReportQuery } from '@/shared/api/scans/reportView';

function Controls({ onQuery }: { onQuery: (query: SbomReportQuery) => void }) {
  const [query, setQuery] = useState<SbomReportQuery>({
    view: 'report-v1', limit: 10, sort: 'name:desc', ecosystem: 'npm', name: null,
  });
  return <SbomReportControls query={query} disabled={false} onChange={next => {
    onQuery(next);
    setQuery(next);
  }} />;
}

afterEach(cleanup);

it('keeps the applied package name visible with collapsed filters, distinct from an unsubmitted draft', async () => {
  const user = userEvent.setup();
  const onQuery = vi.fn();
  render(<Controls onQuery={onQuery} />);
  const toggle = screen.getByText('Фильтры и сортировка · Пакеты');
  await user.click(toggle);
  const input = screen.getByRole('textbox', { name: 'Название пакета' });
  await user.type(input, 'openssl{Enter}');
  expect(onQuery).toHaveBeenCalledExactlyOnceWith({
    view: 'report-v1', limit: 10, sort: 'name:desc', ecosystem: 'npm', name: 'openssl',
  });

  await user.clear(input);
  await user.type(input, 'curl');
  await user.click(toggle);
  expect(toggle.closest('details')).not.toHaveAttribute('open');
  expect(screen.getByText('Применённое название пакета: openssl')).toBeVisible();
  expect(screen.queryByText('Применённое название пакета: curl')).not.toBeInTheDocument();
  expect(onQuery).toHaveBeenCalledTimes(1);

  await user.click(toggle);
  expect(input).toHaveValue('curl');
  await user.click(screen.getByRole('button', { name: 'Сбросить название' }));
  expect(input).toHaveValue('');
  expect(screen.queryByText(/Применённое название пакета:/)).not.toBeInTheDocument();
  expect(onQuery).toHaveBeenLastCalledWith({
    view: 'report-v1', limit: 10, sort: 'name:desc', ecosystem: 'npm', name: null,
  });
});
