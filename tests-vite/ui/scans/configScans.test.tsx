import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor, act } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { LiveScanSession } from '@/features/scans/LiveScanSession';
import { ScanCreatePage } from '@/pages/scans/ScanCreatePage';
import { ScanDetailPage } from '@/pages/scans/ScanDetailPage';
import { parseCurrentStatus, parseScanStatus } from '@/shared/api/scans/scanTransport';
import { transitionScanSession } from '@/shared/api/auth/scanSession';

const id = '00000000-0000-4000-8000-000000000007';
const digest = `sha256:${'a'.repeat(64)}`;
const json = (value: unknown) => ({ ok: true, status: 200, json: async () => value });
function configReport(outcome = 'checked', reason?: string) {
  const coverage = { outcome, ...(reason ? { reason } : {}) };
  return { checksVersion: 'image-config-user-v1', resourcePolicyVersion: 'image-config-policy-v1', supportedRuleIds: ['IMGCFG_USER_ROOT'],
    completedRuleIds: outcome === 'checked' ? ['IMGCFG_USER_ROOT'] : [], config: coverage, rules: [{ ruleId: 'IMGCFG_USER_ROOT', ...coverage }],
    history: { outcome: 'unsupported', reason: 'RULE_NOT_IMPLEMENTED' }, dockerfile: { outcome: 'unsupported', reason: 'SOURCE_NOT_PROVIDED' },
    iac: { outcome: 'unsupported', reason: 'SOURCE_NOT_PROVIDED' }, findings: [] };
}
function wire(report = configReport(), selected = true) {
  const coverage = { check: 'config', coverage: 'image', ...report.config, checksVersion: report.checksVersion,
    resourcePolicyVersion: report.resourcePolicyVersion, supportedRuleIds: report.supportedRuleIds,
    completedRuleIds: report.completedRuleIds, findingCount: report.findings.length };
  return { scanId: id, digest, platform: 'linux/amd64', state: 'completed', checks: selected ? ['config'] : ['secret'], config: report,
    perCheck: selected ? { config: coverage } : { secret: null }, result: selected ? coverage : null };
}
class Observer { observe() {} unobserve() {} disconnect() {} }
beforeEach(() => vi.stubGlobal('IntersectionObserver', Observer));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
function mount(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Routes>
    <Route path="/scans/new" element={<LiveScanSession><ScanCreatePage /></LiveScanSession>} />
    <Route path="/scans/:scanId" element={<LiveScanSession><ScanDetailPage /></LiveScanSession>} />
  </Routes></MemoryRouter></QueryClientProvider>);
  return client;
}

it('strict check discriminator does not misattribute config versions to Trivy; rejects extra fields and conflicting rule/outcome evidence', () => {
  expect(parseCurrentStatus(wire()).perCheck?.config?.checksVersion).toBe('image-config-user-v1');
  expect(parseCurrentStatus(wire(configReport('skipped', 'CHECK_DISABLED'), false)).config?.config.outcome).toBe('skipped');
  const valid = wire();
  for (const bad of [
    { ...valid, config: { ...valid.config, rawEnv: 'CANARY' } },
    { ...valid, config: { ...valid.config, checksVersion: 'future' } },
    { ...valid, config: { ...valid.config, completedRuleIds: [] } },
    { ...valid, config: { ...valid.config, rules: [{ ruleId: 'IMGCFG_USER_ROOT', outcome: 'failed', reason: 'INVALID_CONFIG' }] } },
    { ...valid, perCheck: { config: { ...valid.perCheck.config, scannerVersion: '0.69.3' } } },
    { ...valid, config: undefined },
    { ...valid, config: configReport('skipped', 'CHECK_DISABLED') },
  ]) expect(() => parseCurrentStatus(bad)).toThrow();
  expect(parseCurrentStatus({ scanId: id, state: 'completed', result: null }).config).toBeUndefined();
});

it('generic status parser keeps legacy reason guards and validates config coverage separately', () => {
  expect(parseScanStatus(wire()).perCheck?.config?.checksVersion).toBe('image-config-user-v1');
  const legacy = { scanId: id, state: 'partial', perCheck: { vuln: {
    check: 'vuln', coverage: 'image', outcome: 'unsupported', reason: 'OS_EOL',
  } } };
  expect(parseScanStatus(legacy).perCheck?.vuln?.reason).toBe('OS_EOL');
  expect(() => parseScanStatus({ ...legacy, perCheck: { vuln: { ...legacy.perCheck.vuln, reason: 'USER_NOT_RESOLVABLE' } } })).toThrow();
  const config = wire();
  expect(() => parseScanStatus({ ...config, perCheck: { config: { ...config.perCheck.config, reason: 'OS_EOL' } } })).toThrow();
});

it('checkbox is default-off and a toggle resets confirmation; canonical four-check POST is explicit', async () => {
  const requests: Array<{ path: string; init?: RequestInit }> = [];
  vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
    requests.push({ path, init });
    if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
    if (init?.method === 'POST') return { ok: false, status: 503, json: async () => ({ errorCode: 'SCANNER_UNAVAILABLE' }) };
    throw Error('Unexpected fetch');
  }));
  mount('/scans/new');
  const config = await screen.findByRole('checkbox', { name: /Image config/ });
  expect((config as HTMLInputElement).checked).toBe(false);
  fireEvent.click(screen.getByRole('button', { name: /Alpine · latest/ }));
  const confirmation = screen.getByRole('checkbox', { name: /Подтверждаю выбранную цель/ }); fireEvent.click(confirmation);
  fireEvent.click(config); expect((confirmation as HTMLInputElement).checked).toBe(false);
  fireEvent.click(screen.getByRole('checkbox', { name: /SBOM ·/ }));
  fireEvent.click(screen.getByRole('checkbox', { name: /CVE ·/ })); fireEvent.click(confirmation);
  fireEvent.click(screen.getByRole('button', { name: /Запустить скан/ }));
  await waitFor(() => expect(requests.some(request => request.init?.method === 'POST')).toBe(true));
  const request = requests.find(request => request.init?.method === 'POST')!;
  expect(JSON.parse(String(request.init!.body)).checks).toEqual(['secret','sbom','vuln','config']);
  expect(request.path).toBe('/api/v1/browser/scans');
});

for (const [outcome, reason] of [['checked', undefined], ['failed', 'INVALID_CONFIG'], ['unsupported', 'USER_NOT_RESOLVABLE'], ['skipped', 'CHECK_DISABLED']] as const) {
  it(`renders visible ${outcome} config/version/rule/source limits without fetching secret/SBOM/vuln for config-only`, async () => {
    const requests: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      requests.push(path); if (path === '/api/v1/auth/me') return json({ id: 'alice', email: 'alice@example.com' });
      return json(wire(configReport(outcome, reason), outcome !== 'skipped'));
    }));
    const client = mount(`/scans/${id}`);
    await screen.findByRole('heading', { name: /Image config · только/ });
    expect(screen.getByText(/Правила: выполнено/).textContent).toContain(outcome === 'checked' ? '1 /' : '0 /');
    expect(screen.getAllByText(/image-config-user-v1/).length).toBeGreaterThan(0);
    expect(screen.getByText(/History: RULE_NOT_IMPLEMENTED/).textContent).toContain('Dockerfile: SOURCE_NOT_PROVIDED');
    expect(screen.getByText(/Numeric UID без находки/)).toBeTruthy();
    expect(document.body.textContent).not.toContain('CANARY');
    if (outcome !== 'skipped') expect(requests).not.toContain(`/api/v1/browser/scans/${id}/results?limit=50`);
    act(() => transitionScanSession('bob', client));
    expect(client.getQueryCache().findAll({ queryKey: ['live-scans'] }).every(query => query.queryKey.includes('bob') || query.state.data === undefined)).toBe(true);
  });
}
