import { describe, expect, it } from 'vitest';
import { estimateScanProgress } from '@/features/scans/scanProgressEstimate';
import {
  parseCurrentStatus,
  type ScanCheck,
  type ScanProgress,
  type ScanStatus,
} from '@/shared/api/scans/scanTransport';

const scan = (patch: Partial<ScanStatus> = {}): ScanStatus => ({
  scanId: 'scan-1',
  state: 'running',
  percent: null,
  checks: ['secret', 'sbom', 'vuln', 'config'],
  ...patch,
});
const checked = (check: ScanCheck) => ({ check, coverage: 'image', outcome: 'checked' }) as const;
function durable(outcomes: ScanProgress['outcomes'] = {}): ScanStatus {
  return scan({
    progress: {
      basis: 'durable-outcomes-v1',
      requestedChecks: ['secret', 'sbom', 'vuln', 'config'],
      outcomes,
      resolvedChecks: Object.values(outcomes).filter((outcome) => outcome != null).length,
      checkedChecks: Object.values(outcomes).filter((outcome) => outcome === 'checked').length,
    },
  });
}

describe('snapshot-only scan progress compatibility entry point', () => {
  it('elapsed time, renders, stage and timestamps never invent progress', () => {
    const value = scan({ updatedAt: '2000-01-01T00:00:00Z', stage: 'vuln' });
    let previous = estimateScanProgress(value, 0);
    for (const at of [0, 0, 60_000, 600_000, 1e12, -100, NaN, Infinity]) {
      previous = estimateScanProgress({ ...value }, at, previous);
      expect(previous.percent).toBeNull();
      expect(previous.runningMs).toBe(0);
      expect(previous.evidenceMs).toBe(0);
    }
  });

  it.each(['config', 'secret', 'sbom', 'vuln'] as const)(
    '%s checked is a count, not weighted or equal-work percentage',
    (check) => {
      const value = scan({ perCheck: { [check]: checked(check) } });
      const result = estimateScanProgress(value, 1e12);
      expect(result.percent).toBeNull();
      expect(result.observedCheckedCount).toBe(1);
      expect(result.runningMs).toBe(0);
      expect(estimateScanProgress(scan({ checks: [check] }), 1e12).percent).toBeNull();
    },
  );

  it.each(['failed', 'skipped', 'unsupported', 'not_authorized'] as const)(
    '%s grants no checked-work or acquisition credit',
    (outcome) => {
      const result = estimateScanProgress(scan({ perCheck: { vuln: { ...checked('vuln'), outcome } } }), 0);
      expect(result.percent).toBeNull();
      expect(result.observedCheckedCount).toBe(0);
    },
  );

  it('durable outcomes override stale perCheck and server percent without mutating the snapshot', () => {
    const value = parseCurrentStatus({
      scanId: 'scan-1',
      state: 'running',
      result: null,
      checks: ['secret', 'sbom', 'vuln', 'config'],
      perCheck: { secret: null, sbom: null, vuln: null, config: null },
      progress: {
        basis: 'durable-outcomes-v1',
        requestedChecks: ['secret', 'sbom', 'vuln', 'config'],
        outcomes: { config: 'checked' },
        resolvedChecks: 1,
        checkedChecks: 1,
      },
    });
    const original = structuredClone(value);
    const result = estimateScanProgress({ ...value, perCheck: { vuln: checked('vuln') }, percent: 90 }, 0);
    expect(result.percent).toBeNull();
    expect(result.observedCheckedCount).toBe(1);
    expect(result.durableOutcomes).toEqual({ config: 'checked' });
    expect(value).toEqual(original);
    expect(value.percent).toBeNull();
    result.durableOutcomes!.config = 'failed';
    expect(value.progress!.outcomes.config).toBe('checked');
  });

  it('polling and new checkpoints report current counts without elapsed smoothing', () => {
    const previous = estimateScanProgress(durable(), 60_000);
    const value = durable({ secret: 'checked', vuln: 'failed' });
    const result = estimateScanProgress(value, 60_000, previous);
    expect(result.observedCheckedCount).toBe(1);
    expect(result.percent).toBeNull();
    expect(estimateScanProgress({ ...value }, 61_000, result)).toEqual(estimateScanProgress(value, 61_000));
  });

  it.each([
    { before: { secret: 'checked' }, next: {} },
    { before: { secret: 'failed' }, next: {} },
    { before: { secret: 'checked' }, next: { secret: 'failed' } },
    { before: { secret: 'checked' }, next: { sbom: 'checked' } },
    { before: { secret: 'checked', config: 'checked' }, next: { config: 'checked' } },
  ] satisfies Array<{ before: ScanProgress['outcomes']; next: ScanProgress['outcomes'] }>)(
    'durable regression is never masked by remembered evidence: $before -> $next',
    ({ before, next }) => {
      const previous = estimateScanProgress(durable(before), 120_000);
      const value = durable(next);
      const result = estimateScanProgress(value, 121_000, previous);
      expect(result).toEqual(estimateScanProgress(value, 121_000));
      expect(result.durableOutcomes).toEqual(next);
      expect(result.observedCheckedCount).toBe(
        Object.values(next).filter((outcome) => outcome === 'checked').length,
      );
      expect(result.percent).toBeNull();
    },
  );

  it('a dropped perCheck count is not recovered from memory', () => {
    const previous = estimateScanProgress(scan({ perCheck: { secret: checked('secret') } }), 120_000);
    const result = estimateScanProgress(scan({ perCheck: { secret: null } }), 121_000, previous);
    expect(result.observedCheckedCount).toBe(0);
    expect(result.percent).toBeNull();
    expect(result.runningMs).toBe(0);
  });

  it('missing evidence is unknown, not a paused remembered result', () => {
    const previous = estimateScanProgress(durable({ config: 'checked' }), 120_000);
    const result = estimateScanProgress(scan(), 121_000, previous);
    expect(result.observationPaused).toBe(true);
    expect(result.observedCheckedCount).toBeNull();
    expect(result.durableOutcomes).toBeUndefined();
    expect(result.percent).toBeNull();
    expect(estimateScanProgress(durable(), 122_000, result).observedCheckedCount).toBe(0);
  });

  it.each(['queued', 'cancelling', 'failed', 'partial', 'cancelled'] as const)(
    '%s never inherits an earlier server or local percentage',
    (state) => {
      const previous = estimateScanProgress(scan({ percent: 80 }), 0);
      const result = estimateScanProgress(scan({ state }), 700_000, previous);
      expect(result.percent).toBeNull();
      expect(result.runningMs).toBe(0);
      expect(estimateScanProgress(scan({ state, percent: 100 }), 900_000, result).percent).toBeNull();
    },
  );

  it('100 requires completed even when every check is resolved', () => {
    const value = durable({ secret: 'checked', sbom: 'checked', vuln: 'checked', config: 'checked' });
    const previous = estimateScanProgress(value, 1e12);
    expect(previous.percent).toBeNull();
    expect(previous.observedCheckedCount).toBe(4);
    expect(estimateScanProgress({ ...value, state: 'completed' }, 0, previous).percent).toBe(100);
    expect(estimateScanProgress(scan({ state: 'completed', percent: 0 }), 0).percent).toBe(100);
  });

  it.each(['queued', 'running', 'cancelling'] as const)(
    '%s missing selection stays indeterminate regardless of elapsed time',
    (state) => {
      const value = scan({ state, checks: undefined });
      for (const at of [0, 60_000, 1e12]) {
        const result = estimateScanProgress(value, at);
        expect(result.percent).toBeNull();
        expect(result.plan).toBeNull();
        expect(result.observedCheckedCount).toBeNull();
      }
    },
  );

  it('preserves valid explicit server zero and percentages only without durable progress', () => {
    for (const state of ['running', 'cancelling'] as const) {
      for (const percent of [0, 5, 90, 99.5]) {
        expect(estimateScanProgress(scan({ state, percent }), 0).percent).toBe(percent);
        expect(estimateScanProgress({ ...durable(), state, percent }, 0).percent).toBeNull();
      }
      for (const percent of [null, undefined, 100, NaN, Infinity, -1, 101]) {
        expect(estimateScanProgress(scan({ state, percent }), 0).percent).toBeNull();
      }
    }
  });

  it.each(['durable', 'perCheck'] as const)(
    'known -> missing -> same selection never revives stale %s evidence',
    (kind) => {
      const value =
        kind === 'durable'
          ? durable({ secret: 'checked' })
          : scan({ perCheck: { secret: checked('secret') } });
      const previous = estimateScanProgress(value, 120_000);
      const original = structuredClone(previous);
      const missing = scan({ checks: undefined, perCheck: {} });
      const result = estimateScanProgress(missing, 181_000, previous);
      expect(result.plan).toBeNull();
      expect(result.observedCheckedCount).toBeNull();
      expect(result.durableOutcomes).toBeUndefined();
      expect(result.percent).toBeNull();
      expect(estimateScanProgress(value, 182_000, result)).toEqual(estimateScanProgress(value, 182_000));
      expect(previous).toEqual(original);
      expect(missing.checks).toBeUndefined();
    },
  );

  it('first known selection after an unknown observation gains no elapsed credit', () => {
    const previous = estimateScanProgress(scan({ checks: undefined }), 180_000);
    const result = estimateScanProgress(scan(), 181_000, previous);
    expect(result.percent).toBeNull();
    expect(result.runningMs).toBe(0);
    expect(result.observationPaused).toBe(true);
  });

  it('different scan, selection, queue reentry and fresh observation are independent of previous state', () => {
    const previous = estimateScanProgress(
      scan({ percent: 80, perCheck: { secret: checked('secret') } }),
      120_000,
    );
    for (const value of [
      scan({ scanId: 'scan-2' }),
      scan({ checks: ['config'] }),
      scan({ state: 'queued' }),
      scan({ checks: ['config', 'vuln', 'sbom', 'secret'] }),
    ]) {
      expect(estimateScanProgress(value, 120_000, previous)).toEqual(estimateScanProgress(value, 120_000));
      expect(estimateScanProgress(value, 120_000, previous).percent).toBeNull();
    }
  });
});
