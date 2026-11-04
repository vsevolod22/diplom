import type { ReactNode } from 'react';

export const reportSourceTargets = {
  all: 'scan-a1-findings',
  vuln: 'scan-report-vulnerabilities',
  secret: 'scan-report-secrets',
  config: 'scan-report-config',
} as const;

export type ReportSourceCategory = keyof typeof reportSourceTargets;
export type ReportSourceNavigate = (category: ReportSourceCategory) => boolean;

export function isReportSourceCategory(value: unknown): value is ReportSourceCategory {
  return typeof value === 'string' && Object.hasOwn(reportSourceTargets, value);
}

const categoryLabels: Record<ReportSourceCategory, string> = {
  all: 'Находки и исправления',
  vuln: 'Уязвимости пакетов',
  secret: 'Возможные секреты',
  config: 'Настройки образа',
};

export function ReportSourceLink({
  category,
  onNavigate,
  disabled = false,
  children,
}: {
  category: ReportSourceCategory;
  onNavigate?: ReportSourceNavigate;
  disabled?: boolean;
  children?: ReactNode;
}) {
  const label = children ?? `Открыть раздел «${categoryLabels[category]}»`;
  // Without the page's reveal handler a hidden category cannot be a reliable destination.
  if (disabled || !onNavigate) return <span>{label} · переход сейчас недоступен</span>;
  return (
    <a
      href={`#${reportSourceTargets[category]}`}
      onClick={(event) => {
        event.preventDefault();
        onNavigate(category);
      }}
    >
      {label}
    </a>
  );
}
