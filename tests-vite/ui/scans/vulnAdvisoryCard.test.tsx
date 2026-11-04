import '@testing-library/jest-dom/vitest';
import { afterEach, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
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
function openSourceDetails() {
  const summary = screen.getByText('Подробности · описание уязвимости и источники', { selector: 'summary' });
  expect(summary.closest('details')).not.toHaveAttribute('open');
  fireEvent.click(summary);
  expect(summary.closest('details')).toHaveAttribute('open');
}

it('B2 same-source assessments keep ordinal, exact title/description/fix association and visible CVE identity', () => {
  const first = raw({ Title: 'First assessment', Description: 'First description', FixedVersion: '1.3', VendorSeverity: undefined });
  const second = raw({ Title: 'Second assessment', Description: 'Second description', FixedVersion: '1.9', VendorSeverity: undefined });
  const finding = normalized([first, second]).findings[0];
  expect(normalized([second, first]).findings[0]).toEqual(finding);
  render(<VulnAdvisoryCard finding={finding} />);
  expect(screen.getByText('CVE-2026-1234', { exact: true })).toBeVisible();
  openSourceDetails();
  const rows = screen.getAllByLabelText('Источник alpine'); expect(rows).toHaveLength(finding.advisory!.assessments.length);
  expect(finding.advisory!.assessments.filter(item => item.title.value)).toHaveLength(2);
  finding.advisory!.assessments.forEach((assessment, index) => {
    const row = within(rows[index]);
    expect(row.getByText(new RegExp(`Оценка источника №${index + 1}`))).toBeVisible();
    if (assessment.title.value) expect(row.getByText(new RegExp(assessment.title.value))).toBeVisible();
    if (assessment.description.value) expect(row.getByText(new RegExp(assessment.description.value))).toBeVisible();
    if (assessment.fixedVersion) expect(row.getByText(new RegExp(`исправление источника: ${assessment.fixedVersion}`))).toBeVisible();
    for (const other of finding.advisory!.assessments.filter(item => item !== assessment)) {
      if (other.title.value) expect(row.queryByText(new RegExp(other.title.value))).toBeNull();
      if (other.description.value) expect(row.queryByText(new RegExp(other.description.value))).toBeNull();
    }
  });
});

it('B2 distinguishes temporary Debian advisory identity visibly without claiming CVE', () => {
  const finding = { ...normalized().findings[0], cveId: 'TEMP-1234567-ABCDEF' };
  render(<VulnAdvisoryCard finding={finding} />);
  expect(screen.getByText('TEMP-1234567-ABCDEF · Уведомление Debian (не CVE)')).toBeVisible();
});

it('labels the source union as contributors, not origins of LOW, and preserves separate source assessments', () => {
  const page = normalized();
  expect(page.findings).toHaveLength(1);
  const finding = page.findings[0];
  expect(finding.severity).toBe('LOW');
  expect(finding.severitySources).toEqual(['alpine', 'nvd']);
  render(<VulnAdvisoryCard finding={finding} />);
  expect(screen.getByText(/Опасность требует уточнения\./)).toBeVisible();
  openSourceDetails();
  expect(screen.getByText(/Оценка сканера: LOW\. Источники: alpine, nvd/)).toBeVisible();
  expect(screen.queryByText(/Источник severity: alpine, nvd/)).toBeNull();
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
  expect(screen.getByText(/Опасность требует уточнения\./)).toBeVisible();
  expect(screen.getByText(/Версия исправления не подтверждена всеми источниками\./)).toBeVisible();
  openSourceDetails();
  expect(screen.getByText(/Поля с расхождениями: severity, fixedVersion/)).toBeVisible();
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
  expect(screen.getByText(/Опасность требует уточнения\./)).toBeVisible();
  expect(screen.getByText(/Версия исправления не подтверждена всеми источниками\./)).toBeVisible();
  openSourceDetails();
  expect(screen.getByText(/Поля с расхождениями: severity/)).toBeVisible();
  expect(screen.getByText(/Ограничения источника: assessment_limit/)).toBeVisible();
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
    expect(screen.getByText(/Опасность требует уточнения\./)).toBeVisible();
    expect(screen.getByText(/Версия исправления не подтверждена всеми источниками\./)).toBeVisible();
    expect(screen.getByText('Подробности · описание уязвимости и источники', { selector: 'summary' }).closest('details')).not.toHaveAttribute('open');
    view.unmount();
  }
});
