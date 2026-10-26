import type { ScanCheck, ScanProgress, ScanStatus } from '@/shared/api/scans/scanTransport';

// Relative work budgets, NOT measured durations or an ETA. Config loads metadata;
// image checks also acquire layers, and vulnerability analysis includes DB work.
// See worker/outbox-consumer.ts and worker/archive-scan-worker.ts (read-only).
const CHECK_COST: Record<ScanCheck, number> = { config: 8, secret: 45, sbom: 35, vuln: 180 };
const ACQUISITION_COST = 60;
const FINALIZATION_COST = 12;
const ESTIMATE_CAP = 95;
const MAX_POINTS_PER_SECOND = 0.5;

export type ScanProgressEstimate = {
  scanId: string;
  plan: string;
  state: ScanStatus['state'];
  lastAt: number;
  runningMs: number;
  evidenceMs: number;
  evidence: string;
  durableOutcomes: ScanProgress['outcomes'] | undefined;
  observedCheckedCount: number | null;
  percent: number | null;
};

function model(scan: ScanStatus) {
  const requested = [
    ...new Set(scan.progress?.requestedChecks ?? scan.checks ?? (scan.check ? [scan.check] : [])),
  ].sort();
  const outcomes = requested.map((check) => {
    if (scan.progress) return scan.progress.outcomes[check] ?? null;
    const item = scan.perCheck?.[check];
    return item?.check === check ? item.outcome : null;
  });
  const hasImageChecks = requested.some((check) => check !== 'config');
  // Unknown check selection still gets a conservative generic image-work model,
  // not borrowed detail-cache data or fictitious per-check completion.
  const acquisition = hasImageChecks || !requested.length ? ACQUISITION_COST : 0;
  const total =
    acquisition +
    FINALIZATION_COST +
    (requested.length ? requested.reduce((sum, check) => sum + CHECK_COST[check], 0) : 260);
  const acquired = requested.some((check, index) => check !== 'config' && outcomes[index] === 'checked');
  const confirmedCost = requested.reduce(
    (sum, check, index) => sum + (outcomes[index] === 'checked' ? CHECK_COST[check] : 0),
    acquired ? acquisition : 0,
  );
  const pendingCost = requested.reduce(
    (sum, check, index) => sum + (outcomes[index] === null ? CHECK_COST[check] : 0),
    0,
  );
  return {
    plan: JSON.stringify(requested),
    evidence: JSON.stringify(outcomes),
    observedCheckedCount:
      scan.progress?.checkedChecks ??
      (scan.perCheck !== undefined ? outcomes.filter((outcome) => outcome === 'checked').length : null),
    floor: (ESTIMATE_CAP * confirmedCost) / total,
    // Failed/skipped/unsupported outcomes resolve counters, but do not prove that
    // their full cost was performed, or that acquisition succeeded.
    pendingCost: FINALIZATION_COST + (acquired ? 0 : acquisition) + (requested.length ? pendingCost : 260),
  };
}

/** Local observation only. updatedAt is NOT a start timestamp; the native DTO
 * exposes neither an attempt ID nor a runtime start. No storage or wire mutation.
 * Estimates the observed scan, not a measured current attempt. A repeat without
 * observable evidence changes cannot be identified. Reset on scan/selection change,
 * queue reentry, observed checkpoint regression, unmount or session change.
 */
export function estimateScanProgress(
  scan: ScanStatus,
  now: number,
  previous?: ScanProgressEstimate,
): ScanProgressEstimate {
  const work = model(scan);
  // A running -> running retry can clear checkpoints without a queued snapshot.
  // Treat lost durable outcomes/checked credit as a new observation, not proof of
  // a particular worker generation. Missing metadata alone is not a regression.
  const progress = scan.progress;
  const evidenceRegressed =
    scan.state === 'running' &&
    previous !== undefined &&
    ((previous.observedCheckedCount !== null &&
      work.observedCheckedCount !== null &&
      work.observedCheckedCount < previous.observedCheckedCount) ||
      (progress !== undefined &&
        previous.durableOutcomes !== undefined &&
        Object.entries(previous.durableOutcomes).some(([check, outcome]) => {
          const current = progress.outcomes[check as ScanCheck] ?? null;
          return outcome != null && (current === null || (outcome === 'checked' && current !== 'checked'));
        })));
  const reset =
    !previous ||
    previous.scanId !== scan.scanId ||
    previous.plan !== work.plan ||
    (scan.state === 'queued' && previous.state !== 'queued') ||
    evidenceRegressed;
  const prior = reset ? undefined : previous;
  const clock = Number.isFinite(now) ? Math.max(now, prior?.lastAt ?? now) : (prior?.lastAt ?? 0);
  const delta = prior ? clock - prior.lastAt : 0;
  const runningMs =
    (prior?.runningMs ?? 0) + (scan.state === 'running' && prior?.state === 'running' ? delta : 0);
  const evidenceMs = prior?.evidence === work.evidence ? prior.evidenceMs : runningMs;
  let percent = prior?.percent ?? null;
  if (scan.state === 'completed') percent = 100;
  else if (scan.state === 'queued') percent = 0;
  else if (scan.state === 'running') {
    const elapsed = Math.max(0, runningMs - evidenceMs) / 1000;
    // Time alone only approaches 75% of the unconfirmed work. Checkpoints raise
    // the floor, but rate limiting prevents artificial 25-point polling jumps.
    const target =
      work.floor + (ESTIMATE_CAP - work.floor) * 0.75 * (1 - Math.exp(-elapsed / work.pendingCost));
    const base = Math.min(99, percent ?? work.floor);
    percent = Math.max(base, Math.min(target, base + (delta / 1000) * MAX_POINTS_PER_SECOND));
    if (
      !scan.progress &&
      typeof scan.percent === 'number' &&
      Number.isFinite(scan.percent) &&
      scan.percent >= 0 &&
      scan.percent <= 100
    ) {
      percent = Math.max(percent, Math.min(99, scan.percent));
    }
  } else if (scan.state === 'cancelling') percent = Math.min(99, percent ?? work.floor);
  else if (percent !== null) percent = Math.min(99, percent);

  return {
    scanId: scan.scanId,
    plan: work.plan,
    state: scan.state,
    lastAt: clock,
    runningMs,
    evidenceMs,
    evidence: work.evidence,
    durableOutcomes: scan.progress ? { ...scan.progress.outcomes } : prior?.durableOutcomes,
    observedCheckedCount: work.observedCheckedCount ?? prior?.observedCheckedCount ?? null,
    percent,
  };
}
