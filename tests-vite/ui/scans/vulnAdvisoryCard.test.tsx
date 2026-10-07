import { afterEach, expect, it } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { VulnAdvisoryCard } from '@/pages/scans/VulnAdvisoryCard';
import { parseCurrentVuln } from '@/shared/api/scans/scanTransport';
import { parseVulnFindings } from '../../../server/api/src/worker/vuln-findings';
import { ADVISORY_SOURCES } from '../../../server/api/src/worker/vuln-advisory';

const image = `registry-1.docker.io/library/alpine@sha256:${'a'.repeat(64)}`;
const raw = (change: Record<string, unknown> = {}) => ({
  VulnerabilityID: 'CVE-2026-1234', PkgName: 'busybox', InstalledVersion: '1.2',
  Severity: 'LOW', SeveritySource: 'alpine', DataSource: { ID: 'alpine' }, FixedVersion: '1.3',
  VendorSeverity: { alpine: 1, nvd: 4 }, ...change,
});
function normalized(items = [raw()]) {
  const findings = parseVulnFindings({ SchemaVersion: 2, ArtifactType: 'container_image', ArtifactName: image,
    Metadata: { RepoDigests: [image], ImageConfig: { os: 'linux', architecture: 'amd64' },
      OS: { Family: 'alpine', Name: '3.21.3' } },
    Results: [{ Class: 'os-pkgs', Type: 'alpine', Target: 'alpine', Vulnerabilities: items }],
  }, image, 'linux/amd64');
  return parseCurrentVuln({ outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64',
    findingCount: findings.length, scannerVersion: '0.69.3', checkedAt: '2026-10-07T08:00:00.000Z',
    findings, nextCursor: null });
}
afterEach(cleanup);

it('labels the source union as contributors, not origins of LOW, and preserves separate source assessments', () => {
  const page = normalized();
  expect(page.findings).toHaveLength(1);
  const finding = page.findings[0];
  expect(finding.severity).toBe('LOW');
  expect(finding.severitySources).toEqual(['alpine', 'nvd']);
  render(<VulnAdvisoryCard finding={finding} />);
  expect(screen.getByText(/Источники отдельных оценок: alpine, nvd/)).toBeTruthy();
  expect(screen.queryByText(/Источник severity: alpine, nvd/)).toBeNull();
  expect(screen.getByText(/Совместимое значение severity, не авторитетная оценка источника/)).toBeTruthy();
  const nvd = screen.getAllByLabelText('Источник nvd');
  expect(nvd.some(row => within(row).queryByText(/Severity источника: CRITICAL/))).toBe(true);
  expect(nvd.some(row => within(row).queryByText(/Severity источника: LOW/))).toBe(false);
  expect(finding.findingId).toBe(normalized([raw({ VendorSeverity: undefined })]).findings[0].findingId);
});

it('marks merged conflicting severity and fix as non-authoritative compatibility representatives without changing IDs', () => {
  const first = raw({ VendorSeverity: undefined });
  const second = raw({ Severity: 'HIGH', SeveritySource: 'nvd', DataSource: { ID: 'nvd' },
    FixedVersion: '1.4', VendorSeverity: undefined });
  const page = normalized([first, second]);
  expect(page).toEqual(normalized([second, first]));
  expect(page.findings).toHaveLength(1);
  const finding = page.findings[0];
  expect(finding.findingId).toBe(normalized([first]).findings[0].findingId);
  expect(finding.severity).toBe('HIGH');
  expect(finding.fixedVersion).toBe('1.3');
  render(<VulnAdvisoryCard finding={finding} />);
  expect(screen.getByText(/Совместимое значение severity, не авторитетная оценка источника/)).toBeTruthy();
  expect(screen.getByText(/Совместимое значение исправления, не авторитетная оценка источника/)).toBeTruthy();
  expect(screen.getByText(/Источники расходятся: severity, fixedVersion/)).toBeTruthy();
  expect(screen.getAllByText(/исправление источника: 1\.[34]/)).toHaveLength(2);
});

it('shows known conflicts as well as incomplete assessment warning at the real cap of sixteen', () => {
  const vendors = Object.fromEntries(ADVISORY_SOURCES.filter(source => source !== 'unknown')
    .map((source, index) => [source, index % 4 + 1]));
  const page = normalized([raw({ VendorSeverity: vendors })]);
  const finding = page.findings[0];
  expect(page.findings).toHaveLength(1);
  expect(finding.advisory?.assessments).toHaveLength(16);
  expect(finding.advisory?.conflicts).toContain('severity');
  expect(finding.advisory?.conflictState).toBe('unknown');
  expect(finding.advisory?.limitations).toContain('assessment_limit');
  render(<VulnAdvisoryCard finding={finding} />);
  expect(screen.getByText(/Источники расходятся: severity/)).toBeTruthy();
  expect(screen.getByText(/Согласованность источников неизвестна/)).toBeTruthy();
  expect(screen.getByText(/Совместимое значение severity, не авторитетная оценка источника/)).toBeTruthy();
});

it('renders normalized optional text without Basic payloads or residual nested Markdown', () => {
  const encoded = btoa('synthetic-user:PRIVATE_BASIC_PASSWORD');
  const page = normalized([raw({ Title: `Authorization: Basic ${encoded}`, Description: '[[issue](doc)](outer)' })]);
  expect(page.findings).toHaveLength(1);
  const view = render(<VulnAdvisoryCard finding={page.findings[0]} />);
  expect(view.container.textContent).not.toContain(encoded);
  expect(view.container.textContent).not.toContain('PRIVATE_BASIC_PASSWORD');
  expect(view.container.textContent).not.toContain('[issue](outer)');
  expect(view.container.textContent).toContain('issue');
  expect(view.container.textContent).toContain('чувствительные данные скрыты');
});

it('does not invent a headline authority for legacy or omitted advisory metadata', () => {
  const original = normalized().findings[0];
  const legacy = { ...original };
  delete legacy.advisory;
  delete legacy.severitySources;
  delete legacy.provenanceRef;
  for (const finding of [legacy, { ...original, advisory: { schemaVersion: 1 as const,
    state: 'omitted' as const, assessments: [], references: [], conflicts: [],
    conflictState: 'unknown' as const, limitations: ['scan_budget' as const] } }]) {
    const view = render(<VulnAdvisoryCard finding={finding} />);
    expect(screen.queryByText(/Источник severity:/)).toBeNull();
    expect(screen.getByText(/Совместимое значение severity, не авторитетная оценка источника/)).toBeTruthy();
    expect(screen.getByText(/Совместимое значение исправления, не авторитетная оценка источника/)).toBeTruthy();
    view.unmount();
  }
});
