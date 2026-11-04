import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ReportRemediation, reportRemediationFacts } from '@/features/scans/ReportRemediation';
import { publicSafeFinding, type LlmFinding } from '@/shared/api/scans/llmFindingContract';
import type { SummarySource } from '@/shared/api/scans/llmSummaryClient';

function finding(patch: Record<string, unknown> = {}) {
  return publicSafeFinding.parse({
    check: 'vuln',
    findingId: `vuln-${'a'.repeat(64)}`,
    cveId: 'CVE-2026-1234',
    identifierKind: 'cve',
    severity: 'HIGH',
    ecosystem: 'deb',
    severitySources: ['debian'],
    provenanceRef: `target-${'b'.repeat(64)}`,
    packageName: 'libssl3',
    installedVersion: '1:3.0.1-1+deb12u1',
    fixedVersion: '1:3.0.2-1+deb12u2',
    fixedVersionReported: true,
    advisoryState: 'available',
    conflictState: 'none',
    conflicts: [],
    limitations: [],
    assessments: [{ source: 'nvd', severity: 'HIGH', fixedVersionReported: true, cvss: null }],
    ...patch,
  });
}
function source(value: LlmFinding): SummarySource {
  return {
    findingId: value.findingId,
    check: value.check,
    label: value.check === 'vuln' ? value.cveId : value.check,
    finding: value,
  };
}
function cell(root: HTMLElement, label: string) {
  return within(root).getByText(label, { selector: 'dt', exact: true }).parentElement!.querySelector('dd')!;
}
beforeEach(() =>
  vi.stubGlobal(
    'fetch',
    vi.fn(() => {
      throw Error('No network permitted in remediation tests');
    }),
  ),
);
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('independent deterministic same-finding remediation', () => {
  it('pairs each exact package, installed and reported-fixed field without joining findings or mutating evidence', () => {
    const first = finding();
    const second = finding({
      findingId: `vuln-${'c'.repeat(64)}`,
      packageName: 'libcrypto3',
      installedVersion: '2.1-7',
      fixedVersion: '2.9-8',
    });
    const original = structuredClone([first, second]);
    const { container } = render(
      <>
        {[first, second].map((value) => (
          <ReportRemediation key={value.findingId} source={source(value)} />
        ))}
      </>,
    );
    const cards = container.querySelectorAll<HTMLElement>('.report-remediation');
    expect(cards).toHaveLength(2);
    expect(cell(cards[0], 'Пакет')).toHaveTextContent(/^libssl3$/);
    expect(cell(cards[0], 'Установлено')).toHaveTextContent(/^1:3\.0\.1-1\+deb12u1$/);
    expect(cell(cards[0], 'Исправление по данным сканера')).toHaveTextContent(/^1:3\.0\.2-1\+deb12u2$/);
    expect(cards[0]).not.toHaveTextContent('libcrypto3');
    expect(cards[0]).not.toHaveTextContent('2.9-8');
    expect(cell(cards[1], 'Пакет')).toHaveTextContent(/^libcrypto3$/);
    expect(cell(cards[1], 'Установлено')).toHaveTextContent(/^2\.1-7$/);
    expect(cell(cards[1], 'Исправление по данным сканера')).toHaveTextContent(/^2\.9-8$/);
    expect(cards[1]).not.toHaveTextContent('libssl3');
    expect(reportRemediationFacts(first)).toEqual({
      findingId: first.findingId,
      packageName: 'libssl3',
      installedVersion: '1:3.0.1-1+deb12u1',
      reportedFixedVersion: '1:3.0.2-1+deb12u2',
      fixedVersionState: 'reported',
      conflictState: 'none',
      advisoryState: 'available',
    });
    expect([first, second]).toEqual(original);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('retains composite fix evidence verbatim, without selecting, sorting or calling a minimum version safe', () => {
    const exact = '9.0-1,1:3.0.9-2+deb12u3';
    const value = finding({ fixedVersion: exact });
    render(<ReportRemediation source={source(value)} />);
    expect(screen.getByText(exact, { selector: 'code', exact: true })).toBeVisible();
    expect(reportRemediationFacts(value)?.reportedFixedVersion).toBe(exact);
    expect(screen.getByText(/не выбранная минимальная или гарантированно безопасная версия/)).toBeVisible();
    expect(screen.queryByText('1:3.0.9-2+deb12u3', { exact: true })).not.toBeInTheDocument();
    expect(screen.queryByText('9.0-1', { exact: true })).not.toBeInTheDocument();
  });

  it('null means unknown, not no fix or an invented replacement image/tag/command', () => {
    const value = finding({ fixedVersion: null, fixedVersionReported: false });
    render(<ReportRemediation source={source(value)} />);
    expect(reportRemediationFacts(value)).toMatchObject({
      reportedFixedVersion: null,
      fixedVersionState: 'unknown',
    });
    expect(screen.getByText('Исправленная версия неизвестна')).toBeVisible();
    expect(screen.getByText(/Подтверждённого соответствия.*Docker-тег образа/)).toBeVisible();
    expect(
      screen.getByText(
        /сначала найдите подтверждённое исправление.*подходящая версия здесь не установлена.*После проверки совместимости обновления пересоберите образ и повторно проверьте/,
      ),
    ).toBeVisible();
    expect(document.body).not.toHaveTextContent(
      /docker pull|docker build|alpine:latest|debian:bookworm|исправления нет|образ безопасен/,
    );
  });

  it.each([true, false])(
    'omitted legacy remediation fields are not reconstructed from label, fixedVersionReported=%s',
    (reported) => {
      const {
        packageName: _package,
        installedVersion: _installed,
        fixedVersion: _fixed,
        ...legacy
      } = finding() as Extract<LlmFinding, { check: 'vuln' }>;
      void _package;
      void _installed;
      void _fixed;
      const value = publicSafeFinding.parse({ ...legacy, fixedVersionReported: reported });
      render(
        <ReportRemediation source={{ ...source(value), label: 'CVE-2026-1234 · pretend-package · 99.0' }} />,
      );
      expect(reportRemediationFacts(value)).toMatchObject({
        packageName: null,
        installedVersion: null,
        reportedFixedVersion: null,
        fixedVersionState: reported ? 'not-included' : 'unknown',
      });
      const root = document.querySelector<HTMLElement>('.report-remediation')!;
      expect(cell(root, 'Пакет')).toHaveTextContent('Не включён в источник');
      expect(cell(root, 'Установлено')).toHaveTextContent('Версия не включена в источник');
      expect(cell(root, 'Исправление по данным сканера')).toHaveTextContent(
        reported ? 'Исправление сообщено, точная версия не включена' : 'Исправленная версия неизвестна',
      );
      expect(root.querySelectorAll('dl code')).toHaveLength(0);
      expect(cell(root, 'Пакет')).not.toHaveTextContent('pretend-package');
      expect(cell(root, 'Исправление по данным сканера')).not.toHaveTextContent('99.0');
    },
  );

  it.each(['present', 'unknown'] as const)(
    'keeps %s source agreement explicit beside the exact representative fix',
    (conflictState) => {
      const value = finding({
        conflictState,
        conflicts: ['fixedVersion'],
        limitations: ['assessment_limit'],
      });
      render(<ReportRemediation source={source(value)} />);
      expect(screen.getByText('1:3.0.2-1+deb12u2', { selector: 'code' })).toBeVisible();
      expect(
        screen.getByText(
          conflictState === 'present' ? /Источники расходятся/ : /Согласованность источников неизвестна/,
        ),
      ).toBeVisible();
      expect(screen.getByText(/Источник содержит ограничения полноты данных/)).toBeVisible();
    },
  );

  it.each(['omitted', 'unknown'] as const)(
    'keeps %s advisory evidence honest without borrowing model prose',
    (advisoryState) => {
      const full = finding() as Extract<LlmFinding, { check: 'vuln' }>;
      const value =
        advisoryState === 'omitted'
          ? finding({ advisoryState })
          : publicSafeFinding.parse({
              check: full.check,
              findingId: full.findingId,
              cveId: full.cveId,
              identifierKind: full.identifierKind,
              severity: full.severity,
              ecosystem: full.ecosystem,
              severitySources: full.severitySources,
              provenanceRef: full.provenanceRef,
              fixedVersionReported: false,
              advisoryState,
            });
      render(<ReportRemediation source={source(value)} />);
      expect(
        screen.getByText(/Подробности advisory.*Эти данные не восстанавливаются из текста ИИ/),
      ).toBeVisible();
      expect(reportRemediationFacts(value)?.advisoryState).toBe(advisoryState);
    },
  );

  it.each(['absent', 'wrong-id', 'wrong-check'] as const)(
    'legacy or mismatched source %s cannot publish another finding versions',
    (mismatch) => {
      const original = source(finding());
      const value: SummarySource =
        mismatch === 'absent'
          ? { ...original, finding: undefined }
          : mismatch === 'wrong-id'
            ? { ...original, findingId: `vuln-${'f'.repeat(64)}` }
            : { ...original, check: 'secret' };
      render(<ReportRemediation source={value} />);
      expect(screen.queryByText('libssl3', { selector: 'code' })).not.toBeInTheDocument();
      expect(screen.queryByText('1:3.0.2-1+deb12u2', { selector: 'code' })).not.toBeInTheDocument();
      expect(document.querySelectorAll('dl')).toHaveLength(0);
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it('rejects malformed/extra unsafe fields rather than laundering them into technical facts', () => {
    const valid = finding();
    for (const patch of [
      { packageName: 'bad<script>' },
      { fixedVersion: 'https://unsafe.invalid' },
      { rawEvidence: 'PRIVATE_PAYLOAD' },
    ]) {
      const invalid = { ...valid, ...patch } as LlmFinding;
      expect(reportRemediationFacts(invalid)).toBeNull();
      const view = render(<ReportRemediation source={source(invalid)} />);
      expect(view.container.querySelectorAll('code')).toHaveLength(0);
      expect(view.container).not.toHaveTextContent(/PRIVATE_PAYLOAD|https:\/\/unsafe|bad<script>/);
      view.unmount();
    }
  });
});
