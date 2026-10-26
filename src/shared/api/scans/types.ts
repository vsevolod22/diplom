export const scanChecks = ['secret', 'sbom', 'vuln', 'config'] as const;
export type ScanCheck = typeof scanChecks[number];
export type ScanOutcome = 'checked' | 'failed' | 'unsupported' | 'skipped' | 'not_authorized';

/** Completed durable checks, not elapsed work, an ETA, findings or a safety score. */
export type ScanProgress = {
  basis: 'durable-outcomes-v1';
  requestedChecks: ScanCheck[];
  outcomes: Partial<Record<ScanCheck, ScanOutcome | null>>;
  resolvedChecks: number;
  checkedChecks: number;
};
