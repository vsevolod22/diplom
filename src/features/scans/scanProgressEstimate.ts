import type { ScanProgress, ScanStatus } from '@/shared/api/scans/scanTransport';
import { scanCheckSnapshot, scanProgressPresentation } from './scanProgressPresentation';

// Compatibility shape for existing callers. Timing fields no longer grant work credit.
export type ScanProgressEstimate = {
  scanId: string;
  plan: string | null;
  state: ScanStatus['state'];
  observationPaused: boolean;
  lastAt: number;
  runningMs: number;
  evidenceMs: number;
  evidence: string;
  durableOutcomes: ScanProgress['outcomes'] | undefined;
  observedCheckedCount: number | null;
  percent: number | null;
};

/** Current evidence only: check counts are not fractions of bytes, time or total work.
 * Retained as a compatibility entry point; the panel needs no timer or local estimate.
 */
export function estimateScanProgress(
  scan: ScanStatus,
  now: number,
  previous?: ScanProgressEstimate,
): ScanProgressEstimate {
  void previous;
  const snapshot = scanCheckSnapshot(scan);
  const entries = [...snapshot.entries].sort((a, b) => a.check.localeCompare(b.check));
  return {
    scanId: scan.scanId,
    plan: entries.length ? JSON.stringify(entries.map(item => item.check)) : null,
    state: scan.state,
    observationPaused: !snapshot.known,
    lastAt: Number.isFinite(now) ? now : 0,
    runningMs: 0,
    evidenceMs: 0,
    evidence: JSON.stringify(entries.map(item => item.outcome)),
    durableOutcomes: scan.progress ? { ...scan.progress.outcomes } : undefined,
    observedCheckedCount: snapshot.checked,
    percent: scanProgressPresentation(scan).percent,
  };
}
