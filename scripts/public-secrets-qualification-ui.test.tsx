import React from 'react';
import { readFileSync, writeFileSync } from 'node:fs';
import { afterAll, afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { ScanReportSections } from '../src/pages/scans/ScanReportSections';
import { createAuthorizedScanTransport } from '../src/shared/api/scans/httpScanTransport';
import { parseCurrentStatus, parseCurrentResults } from '../src/shared/api/scans/scanTransport';
import type { QualificationSnapshot } from './public-secrets-qualification-native';

// Required fresh native handoff. No fabricated fallback and no live HTTP requests.
if (!process.env.PUBLIC_SECRETS_HANDOFF || !process.env.PUBLIC_SECRETS_UI_RESULT) throw new Error('Fresh native handoff required');
const handoff = JSON.parse(readFileSync(process.env.PUBLIC_SECRETS_HANDOFF, 'utf8')) as {
  cases: Record<string, QualificationSnapshot>;
};
let completed = 0;
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
afterAll(() => writeFileSync(process.env.PUBLIC_SECRETS_UI_RESULT!, JSON.stringify({ passed: completed === 4, tests: completed,
  nativeHttpSnapshotReplay: true, jsdom: true, browserEndToEnd: false }), { mode: 0o600 }));

function mount(name: string) {
  const saved = handoff.cases[name];
  let subject: string | null = 'disposable-owner';
  let requests = 0;
  vi.stubGlobal('fetch', vi.fn(async (input: string, init: RequestInit) => {
    const url = new URL(input, 'http://localhost');
    expect(url.pathname === `/api/v1/browser/scans/${saved.status.scanId}/results`).toBe(true);
    expect(url.searchParams.get('view') === 'report-v1' && url.searchParams.get('sort') === 'ruleId:asc').toBe(true);
    expect(init.credentials === 'same-origin' && init.cache === 'no-store').toBe(true);
    requests++;
    return new Response(JSON.stringify(saved.report), { status: 200, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  }));
  const transport = createAuthorizedScanTransport({ subject: 'disposable-owner', currentSubject: () => subject });
  const status = parseCurrentStatus(saved.status);
  const view = (): React.ReactElement => <ScanReportSections status={status} transport={transport} scope={['public-secrets-qualification', name]}
    demo={false} filter="all" onResetFilter={() => {}} />;
  const rendered = render(view());
  return { saved, view, rendered, requests: () => requests, loseAccess: () => { subject = null; } };
}
function safeDom() {
  const html = document.body.innerHTML;
  expect(/ghp_[A-Za-z0-9]{36}|qualification_[a-f0-9]{24}|TOKEN_A=|TOKEN_B=|"Match"|"Code"/.test(html)).toBe(false);
  expect(html.includes('result-0-secret-')).toBe(false); // UI deliberately drops internal evidenceRef.
  expect(document.body.textContent?.includes('0 находок в выполненной')).toBe(false);
}
async function positiveRows(saved: QualificationSnapshot) {
  const section = screen.getByRole('region', { name: 'Результаты Secrets' });
  for (const finding of saved.results.findings) await within(section).findByText(`ID: ${finding.findingId}`);
  expect(within(section).getAllByRole('listitem').length === 2).toBe(true);
  expect(section.textContent?.includes('не гарантия безопасности')).toBe(true);
  const decoded = parseCurrentResults(saved.report, { view: 'report-v1', limit: 25, sort: 'ruleId:asc', ruleId: null, linePresence: null });
  expect(decoded.findings.every(item => item.evidenceRef === undefined)).toBe(true);
  safeDom();
}

it('native positive HTTP bytes decode into real UI, reload exactly, and clear on access loss', async () => {
  const context = mount('positive');
  await positiveRows(context.saved);
  context.rendered.unmount();
  const reloaded = render(context.view());
  await positiveRows(context.saved);
  expect(context.requests() === 2).toBe(true);
  context.loseAccess(); reloaded.unmount(); render(context.view());
  await screen.findByRole('alert');
  await waitFor(() => expect(screen.queryByText(`ID: ${context.saved.results.findings[0].findingId}`) === null).toBe(true));
  safeDom(); completed++;
});
it('explicit duplicate-native-row derivative reaches UI as two original findings, not four', async () => {
  const context = mount('duplicate-derived');
  expect(context.saved.status.state === 'completed').toBe(true);
  expect(JSON.stringify(context.saved.results.findings) === JSON.stringify(handoff.cases.positive.results.findings)).toBe(true);
  await positiveRows(context.saved);
  expect(context.requests() === 1).toBe(true);
  completed++;
});
it('cancel before audited publication is unknown, never checked zero or late positive rows', async () => {
  const context = mount('buffered-cancel');
  expect(context.saved.status.state === 'cancelled').toBe(true);
  await screen.findByText('Secrets: завершённый результат не сохранён. Число находок неизвестно.');
  expect(context.requests() === 0).toBe(true);
  expect(screen.queryAllByRole('listitem').length === 0).toBe(true);
  safeDom(); completed++;
});
it('cancelled scan retains actual positive audited Secrets, but does not invent SBOM zero', async () => {
  const context = mount('checkpoint-cancel');
  expect(context.saved.status.state === 'cancelled').toBe(true);
  await positiveRows(context.saved);
  await screen.findByText('SBOM: завершённый результат не сохранён. Число пакетов неизвестно.');
  expect(context.requests() === 1).toBe(true);
  safeDom(); completed++;
});
