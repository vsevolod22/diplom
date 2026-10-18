import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor, act } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { LiveScanSession } from '@/features/scans/LiveScanSession';
import { ScanCreatePage } from '@/pages/scans/ScanCreatePage';
import { SbomReportControls } from '@/pages/scans/ReportViewControls';
import { parseCurrentSbom, parseCurrentStatus, parseCurrentVuln } from '@/shared/api/scans/scanTransport';
import { REPORT_ECOSYSTEMS, PUBLIC_IMAGE_PROFILE, publicImageReference } from '@/shared/api/scans/publicImageProfile';
import { reportViewSearch } from '@/shared/api/scans/reportView';

const id = '00000000-0000-4000-8000-000000000001';
const digest = `sha256:${'a'.repeat(64)}`;
const image = `registry-1.docker.io/example/application@${digest}`;
const reference = 'registry-1.docker.io/example/application:stable';
const sets = Array.from({ length: 15 }, (_, mask) => ['secret', 'sbom', 'vuln', 'config'].filter((_, bit) => (mask + 1) & (1 << bit)));
const eligible = (imageReference: string, checks: string[], ready = true) => ({ imageReference, eligible: ready && checks.length > 0,
  eligibility: 'public-hub-profile', allowedCheckSets: sets, reason: ready ? 'READY' : 'SCANNER_UNAVAILABLE' });
const json = (body: unknown) => ({ ok: true, status: 200, json: async () => body });
class Observer { observe() {} unobserve() {} disconnect() {} }
beforeEach(() => { vi.stubGlobal('IntersectionObserver', Observer); sessionStorage.clear(); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); sessionStorage.clear(); });
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/scans/new']}><Routes>
    <Route path="/scans/new" element={<LiveScanSession><ScanCreatePage /></LiveScanSession>} />
    <Route path="/scans/:scanId" element={<p>created public scan</p>} />
  </Routes></MemoryRouter></QueryClientProvider>);
  return client;
}

it('keeps public syntax canonical and explicit rather than enabling arbitrary registries/platforms', () => {
  for (const valid of [reference, image, 'registry-1.docker.io/library/node:22']) expect(publicImageReference.safeParse(valid).success).toBe(true);
  for (const invalid of ['node:22', 'docker.io/library/node:22', 'https://registry-1.docker.io/library/node:22',
    'registry-1.docker.io/node:22', 'registry-1.docker.io/team/nested/app:tag', 'registry-1.docker.io/team/../app:tag',
    'registry-1.docker.io/team/app', 'registry-1.docker.io:443/library/node:22', 'ghcr.io/team/app:tag', `${reference} `]) expect(publicImageReference.safeParse(invalid).success).toBe(false);
});

it('strict public checked reports need the named profile and retain only closed ecosystems/sources and bounded target identity', () => {
  const sbom = { profile: PUBLIC_IMAGE_PROFILE, outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64',
    os: { name: 'debian', version: '12.12' }, componentCount: REPORT_ECOSYSTEMS.length, scannerVersion: '0.69.3', checkedAt: '2026-10-18T00:00:00.000Z',
    components: REPORT_ECOSYSTEMS.map(ecosystem => ({ ecosystem, name: 'package', version: '1' })), nextCursor: null };
  expect(parseCurrentSbom(sbom).components.map(row => row.ecosystem)).toEqual(REPORT_ECOSYSTEMS);
    const legacyAlpine = { ...sbom, profile: undefined, image: `registry-1.docker.io/library/alpine@${digest}`, os: { name: 'alpine', version: 'edge' }, componentCount: 1, components: [{ ecosystem: 'apk', name: 'package', version: '1' }] };
    expect(parseCurrentSbom(legacyAlpine)).toMatchObject({ os: { name: 'alpine', version: 'edge' } });
    expect(() => parseCurrentSbom({ ...legacyAlpine, profile: PUBLIC_IMAGE_PROFILE })).toThrow();
  const finding = { findingId: `vuln-${'b'.repeat(64)}`, cveId: 'CVE-2026-1234', ecosystem: 'deb', packageName: 'libc6', installedVersion: '2.36-1',
    severity: 'HIGH', fixedVersion: null, severitySources: ['debian'], provenanceRef: `target-${'c'.repeat(64)}` };
  const vuln = { identifierCounts: { cve: 1, debianTemp: 0 }, profile: PUBLIC_IMAGE_PROFILE, outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64', findingCount: 1,
    scannerVersion: '0.69.3', checkedAt: sbom.checkedAt, findings: [finding], nextCursor: null,
    node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_UNKNOWN' } };
  expect(parseCurrentVuln(vuln).findings[0]).toMatchObject(finding);
    expect(parseCurrentVuln(vuln)).toMatchObject({ node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_UNKNOWN' } });
    expect(parseCurrentVuln({ profile: PUBLIC_IMAGE_PROFILE, outcome: 'unsupported', coverage: 'image', reason: 'OS_UNKNOWN',
      node: vuln.node, findings: [], nextCursor: null })).toMatchObject({ outcome: 'unsupported', node: vuln.node });
  for (const change of [{ profile: undefined }, { profile: 'any-platform' }, { image: image.replace('registry-1.docker.io', 'ghcr.io') },
    { image: reference }, { platform: 'linux/arm64' }, { raw: 'PRIVATE_CANARY' }]) {
    expect(() => parseCurrentSbom({ ...sbom, ...change })).toThrow();
    expect(() => parseCurrentVuln({ ...vuln, ...change })).toThrow();
  }
  for (const row of [{ ecosystem: 'arbitrary', name: 'package', version: '1' }, { ecosystem: 'deb', name: 'package', version: '1', raw: 'PRIVATE_CANARY' }]) {
    expect(() => parseCurrentSbom({ ...sbom, components: [row] })).toThrow();
  }
  expect(() => parseCurrentVuln({ ...vuln, findings: [{ ...finding, severitySources: ['unreviewed-source'] }] })).toThrow();
  const status = { profile: PUBLIC_IMAGE_PROFILE, scanId: id, state: 'queued', digest, platform: 'linux/amd64', imageReference: image, checks: ['config'], perCheck: { config: null }, result: null };
  expect(parseCurrentStatus(status)).toMatchObject({ profile: PUBLIC_IMAGE_PROFILE, imageReference: image });
  for (const change of [{ digest: `sha256:${'c'.repeat(64)}` }, { platform: 'linux/arm64' }, { profile: undefined }, { imageReference: undefined }, { digest: undefined }]) expect(() => parseCurrentStatus({ ...status, ...change })).toThrow();
});

it('public config responses bind allowlisted metadata findings to the pinned manifest/platform', () => {
  const finding = { findingId: `sha256:${'f'.repeat(64)}`, ruleId: 'IMGCFG_USER_ROOT', category: 'image-config', severity: 'MEDIUM',
    severitySource: 'image-config-user-v1', classification: 'NUMERIC_ROOT', message: 'Image metadata declares numeric UID 0.',
    recommendation: 'Set an explicit non-zero numeric image user; verify runtime identity separately.', location: '/config/User',
    manifestDigest: digest, configDigest: `sha256:${'c'.repeat(64)}`, platform: { os: 'linux', architecture: 'amd64' } };
  const config = { checksVersion: 'image-config-user-v1', resourcePolicyVersion: 'image-config-policy-v1', supportedRuleIds: ['IMGCFG_USER_ROOT'],
    completedRuleIds: ['IMGCFG_USER_ROOT'], config: { outcome: 'checked' }, rules: [{ ruleId: 'IMGCFG_USER_ROOT', outcome: 'checked' }],
    history: { outcome: 'unsupported', reason: 'RULE_NOT_IMPLEMENTED' }, dockerfile: { outcome: 'unsupported', reason: 'SOURCE_NOT_PROVIDED' },
    iac: { outcome: 'unsupported', reason: 'SOURCE_NOT_PROVIDED' }, findings: [finding] };
  const coverage = { check: 'config', coverage: 'image', outcome: 'checked', checksVersion: config.checksVersion, resourcePolicyVersion: config.resourcePolicyVersion,
    supportedRuleIds: config.supportedRuleIds, completedRuleIds: config.completedRuleIds, findingCount: 1 };
  const status = { profile: PUBLIC_IMAGE_PROFILE, scanId: id, state: 'completed', imageReference: image, digest, platform: 'linux/amd64',
    checks: ['config'], perCheck: { config: coverage }, result: coverage, config };
  expect(parseCurrentStatus(status).config?.findings[0].manifestDigest).toBe(digest);
  expect(() => parseCurrentStatus({ ...status, config: { ...config, rawEnv: 'PRIVATE_CANARY' } })).toThrow();
  expect(() => parseCurrentStatus({ ...status, config: { ...config, findings: [{ ...finding, manifestDigest: `sha256:${'d'.repeat(64)}` }] } })).toThrow();
});

it('all reviewed ecosystems have explicit SBOM filter options and use report-v1 lexical sort/query keys', () => {
  const onChange = vi.fn();
  render(<SbomReportControls query={{ view: 'report-v1' }} onChange={onChange} disabled={false} />);
  const select = screen.getByLabelText('Экосистема · SBOM');
  for (const ecosystem of REPORT_ECOSYSTEMS) {
    fireEvent.change(select, { target: { value: ecosystem } });
    expect(onChange).toHaveBeenLastCalledWith({ view: 'report-v1', ecosystem });
    expect(reportViewSearch('sbom', { view: 'report-v1', ecosystem, sort: 'ecosystem:desc', name: 'org.example:lib' })).toContain(`ecosystem=${ecosystem}`);
  }
  expect(() => reportViewSearch('sbom', { view: 'report-v1', ecosystem: 'raw' } as never)).toThrow();
  expect(() => reportViewSearch('sbom', { view: 'report-v1', raw: 'no' } as never)).toThrow();
});

it('manual canonical entry works without discovery, needs current server eligibility and a fresh public preflight before POST', async () => {
  let available = false;
  const posts: Record<string, unknown>[] = [], preflights: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
    if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
    if (path.includes('/images/eligibility')) {
      const request = JSON.parse(String(init?.body)); preflights.push(request.imageReference);
      return json(eligible(request.imageReference, request.checks, available));
    }
    if (path === '/api/v1/browser/scans' && init?.method === 'POST') { posts.push(JSON.parse(String(init.body))); return json({ scanId: id }); }
    return { ok: false, status: 503, json: async () => ({ errorCode: 'UNAVAILABLE' }) };
  }));
  const client = mount();
  await screen.findByRole('button', { name: 'Запустить скан' });
  const input = screen.getByRole('textbox', { name: 'Canonical reference Docker Hub' });
  fireEvent.change(input, { target: { value: reference } });
  await waitFor(() => expect(preflights).toContain(reference));
  fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
  expect(screen.getByRole('button', { name: 'Запустить скан' }).hasAttribute('disabled')).toBe(true); expect(posts).toHaveLength(0);
  available = true;
  fireEvent.click(screen.getByRole('button', { name: 'Проверить допуск снова' }));
  const submit = screen.getByRole('button', { name: 'Запустить скан' });
  await waitFor(() => expect(submit.hasAttribute('disabled')).toBe(false));
  const before = preflights.length;
  fireEvent.click(submit);
  await screen.findByText('created public scan');
  expect(preflights.length).toBe(before + 1);
  expect(posts).toHaveLength(1); expect(posts[0]).toMatchObject({ imageReference: reference, checks: ['secret'], scope: 'image' });
  expect(Object.keys(posts[0]).sort()).toEqual(['checks', 'idempotencyKey', 'imageReference', 'scope']);
  client.clear();
});

it('revoked fresh public preflight does not POST even after an earlier eligible response and consent', async () => {
  let targetReads = 0;
  const posts: unknown[] = [];
  vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
    if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
    if (path.includes('/images/eligibility')) {
      const body = JSON.parse(String(init?.body));
      const ready = body.imageReference === reference && ++targetReads === 1;
      return json(eligible(body.imageReference, body.checks, ready));
    }
    if (path === '/api/v1/browser/scans' && init?.method === 'POST') posts.push(init.body);
    return { ok: false, status: 503, json: async () => ({ errorCode: 'UNAVAILABLE' }) };
  }));
  const client = mount();
  await screen.findByRole('button', { name: 'Запустить скан' });
  fireEvent.change(screen.getByRole('textbox', { name: 'Canonical reference Docker Hub' }), { target: { value: reference } });
  await waitFor(() => expect(targetReads).toBe(1));
  fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
  const submit = screen.getByRole('button', { name: 'Запустить скан' });
  await waitFor(() => expect(submit.hasAttribute('disabled')).toBe(false)); fireEvent.click(submit);
  await screen.findByText('Актуальный серверный допуск недоступен. Скан не создан.');
  expect(posts).toHaveLength(0); expect(targetReads).toBe(2); client.clear();
});

it('public search candidates are selectable but never claim scannability or authorize a launch without inspection', async () => {
  let inspected = false;
  const posts: unknown[] = [];
  vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
    if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
    if (path.includes('/images/eligibility')) {
      const body = JSON.parse(String(init?.body));
      if (body.imageReference === reference) inspected = true;
      return json(eligible(body.imageReference, body.checks, false));
    }
    if (path.includes('/images?')) return json({ items: [{ label: 'example/application', reference, scannable: false, eligibility: 'public-hub-profile', allowedCheckSets: sets,
      reason: 'Кандидат; требуется проверка', kind: 'repository', tagConfirmed: false, checks: { secret: true, sbom: true, vuln: 'conditional' } }],
      nextCursor: null, state: 'terminal', loaded: 1, pages: 1, policy: { pageSize: 12, maxPages: 5, maxCandidates: 60, maxActivePerProcess: 8, maxActivePerSubject: 2, maxRequestsPerSubject: 30, rateWindowMs: 60000, maxSessions: 1024, maxRateEntries: 1024, scope: 'process-local' } });
    if (path === '/api/v1/browser/scans' && init?.method === 'POST') posts.push(init.body);
    return { ok: false, status: 503, json: async () => ({ errorCode: 'UNAVAILABLE' }) };
  }));
  const client = mount();
  await screen.findByRole('button', { name: 'Запустить скан' });
  fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'example' } });
  const candidate = await screen.findByRole('button', { name: /example\/application.*Кандидат/ });
  expect(candidate.hasAttribute('disabled')).toBe(false); expect(inspected).toBe(false);
  fireEvent.click(candidate);
  await waitFor(() => expect(inspected).toBe(true));
  fireEvent.click(screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }));
  expect(screen.getByRole('button', { name: 'Запустить скан' }).hasAttribute('disabled')).toBe(true);
  expect(screen.getByText(/public-hub-resources-v1/)).toBeTruthy();
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 180)); });
  expect(posts).toHaveLength(0); client.clear();
});
