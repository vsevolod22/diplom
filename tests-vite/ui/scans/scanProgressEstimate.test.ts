import { describe, expect, it } from 'vitest';
import { estimateScanProgress, type ScanProgressEstimate } from '@/features/scans/scanProgressEstimate';
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
function after(value: ScanStatus, seconds: number) {
  return estimateScanProgress(value, seconds * 1000, estimateScanProgress(value, 0));
}

function durable(outcomes: ScanProgress['outcomes'] = {}): ScanStatus {
  const requestedChecks: ScanCheck[] = ['secret', 'sbom', 'vuln', 'config'];
  return scan({
    progress: {
      basis: 'durable-outcomes-v1',
      requestedChecks,
      outcomes,
      resolvedChecks: Object.values(outcomes).filter((outcome) => outcome != null).length,
      checkedChecks: Object.values(outcomes).filter((outcome) => outcome === 'checked').length,
    },
  });
}

describe('local weighted scan estimate', () => {
  it('advances with actual observed runtime, not render count, stage text or updatedAt', () => {
    const value = scan({ updatedAt: '2000-01-01T00:00:00Z', stage: 'vuln' });
    let result = estimateScanProgress(value, 0);
    expect(result.percent).toBe(0);
    for (let i = 0; i < 100; i++) result = estimateScanProgress({ ...value }, 0, result);
    expect(result.percent).toBe(0);
    result = estimateScanProgress(value, 60_000, result);
    expect(result.percent).toBeGreaterThan(0);
    expect(result.percent).toBeLessThan(25);
  });

  it('is monotonic and bounded with late checkpoints, missing metadata and clock rollback', () => {
    let result = estimateScanProgress(scan(), 0);
    let previous = result.percent!;
    for (let second = 1; second <= 600; second++) {
      const perCheck =
        second < 120 || second > 500 ? undefined : { secret: checked('secret'), config: checked('config') };
      result = estimateScanProgress(scan({ perCheck }), second * 1000, result);
      expect(result.percent).toBeGreaterThanOrEqual(previous);
      expect(result.percent! - previous).toBeLessThanOrEqual(0.500001);
      expect(result.percent).toBeLessThan(100);
      previous = result.percent!;
    }
    expect(estimateScanProgress(scan(), -100, result).percent).toBe(previous);
    expect(estimateScanProgress(scan(), NaN, result).percent).toBe(previous);
    expect(estimateScanProgress(scan(), Number.MAX_SAFE_INTEGER, result).percent).toBeLessThanOrEqual(95);
  });

  it('weights acquisition and long vulnerability work above config, never equal 25% per check', () => {
    const config = estimateScanProgress(scan({ perCheck: { config: checked('config') } }), 0);
    const secret = estimateScanProgress(scan({ perCheck: { secret: checked('secret') } }), 0);
    const vuln = estimateScanProgress(scan({ perCheck: { vuln: checked('vuln') } }), 0);
    expect(config.percent).toBeGreaterThan(0);
    expect(config.percent).toBeLessThan(5);
    expect(secret.percent).toBeGreaterThan(config.percent!);
    expect(vuln.percent).toBeGreaterThan(secret.percent!);
    for (const result of [config, secret, vuln]) expect(result.percent).not.toBe(25);
    expect(after(scan({ checks: ['config'] }), 30).percent).toBeGreaterThan(
      after(scan({ checks: ['vuln'] }), 30).percent!,
    );
  });

  it.each(['failed', 'skipped', 'unsupported', 'not_authorized'] as const)(
    '%s grants no checked-work or acquisition credit',
    (outcome) => {
      const result = estimateScanProgress(scan({ perCheck: { vuln: { ...checked('vuln'), outcome } } }), 0);
      expect(result.percent).toBe(0);
    },
  );

  it('uses durable outcomes rather than stale perCheck and preserves the null server contract', () => {
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
    expect(result.percent).toBeGreaterThan(0);
    expect(result.percent).toBeLessThan(5);
    expect(value).toEqual(original);
    expect(value.percent).toBeNull();
  });

  it('does not jump when a checkpoint arrives or reset on each polling snapshot', () => {
    let result = after(scan(), 60);
    const before = result.percent!;
    const checkpoint = scan({ perCheck: { vuln: checked('vuln') } });
    result = estimateScanProgress(checkpoint, 60_000, result);
    expect(result.percent).toBe(before);
    result = estimateScanProgress({ ...checkpoint }, 61_000, result);
    expect(result.percent).toBeGreaterThan(before);
    expect(result.percent! - before).toBeLessThanOrEqual(0.5);
  });

  it.each([
    { before: { secret: 'checked' }, next: {} },
    { before: { secret: 'failed' }, next: {} },
    { before: { secret: 'checked' }, next: { secret: 'failed' } },
    { before: { secret: 'checked' }, next: { sbom: 'checked' } },
    { before: { secret: 'checked', config: 'checked' }, next: { config: 'checked' } },
  ] satisfies Array<{ before: ScanProgress['outcomes']; next: ScanProgress['outcomes'] }>)(
    'resets running -> running on observed durable regression: $before -> $next',
    ({ before, next }) => {
      const previous = after(durable(before), 120);
      expect(previous.percent).toBeGreaterThan(0);
      const value = durable(next);
      const reset = estimateScanProgress(value, 120_000, previous);
      expect(reset).toEqual(estimateScanProgress(value, 120_000));
      expect(reset.runningMs).toBe(0);
      expect(reset.percent).toBeLessThan(100);
      const resumed = estimateScanProgress(value, 121_000, reset);
      expect(resumed.percent).toBeGreaterThanOrEqual(reset.percent!);
      expect(resumed.percent! - reset.percent!).toBeLessThanOrEqual(0.5);
      expect(estimateScanProgress(value, 1e12, resumed).percent).toBeLessThan(100);
    },
  );

  it('resets on an observed checked-count drop without durable progress', () => {
    const previous = after(scan({ perCheck: { secret: checked('secret') } }), 120);
    const value = scan({ perCheck: { secret: null } });
    const reset = estimateScanProgress(value, 120_000, previous);
    expect(reset.runningMs).toBe(0);
    expect(reset.percent).toBe(0);
  });

  it('retains the observation for unchanged evidence; an invisible repeat cannot be inferred', () => {
    const value = durable({ config: 'checked' });
    const previous = after(value, 120);
    const unchanged = estimateScanProgress(durable({ config: 'checked' }), 121_000, previous);
    expect(unchanged.runningMs).toBe(121_000);
    expect(unchanged.percent).toBeGreaterThanOrEqual(previous.percent!);
    expect(unchanged.percent).toBeLessThan(100);
    const missing = estimateScanProgress(scan(), 122_000, unchanged);
    expect(missing.runningMs).toBe(122_000);
    expect(missing.percent).toBeGreaterThanOrEqual(unchanged.percent!);
    const cleared = estimateScanProgress(durable(), 123_000, missing);
    expect(cleared.runningMs).toBe(0);
    expect(cleared.percent).toBe(0);
  });

  it('does not count queue time; freezes cancelling, failed, partial and cancelled estimates', () => {
    let result = estimateScanProgress(scan({ state: 'queued' }), 0);
    result = estimateScanProgress(scan({ state: 'queued' }), 600_000, result);
    expect(result.percent).toBe(0);
    expect(result.runningMs).toBe(0);
    result = estimateScanProgress(scan(), 600_000, result);
    expect(result.percent).toBe(0);
    result = estimateScanProgress(scan(), 660_000, result);
    for (const state of ['cancelling', 'failed', 'partial', 'cancelled'] as const) {
      const stopped = estimateScanProgress(scan({ state, percent: 100 }), 700_000, result);
      expect(stopped.percent).toBe(result.percent);
      expect(estimateScanProgress(scan({ state }), 900_000, stopped).percent).toBe(stopped.percent);
      expect(stopped.percent).toBeLessThan(100);
    }
  });

  it('requires confirmed completed for 100, even with every checkpoint checked', () => {
    const value = scan({
      perCheck: {
        secret: checked('secret'),
        sbom: checked('sbom'),
        vuln: checked('vuln'),
        config: checked('config'),
      },
    });
    const result = after(value, 1e9);
    expect(result.percent).toBeLessThanOrEqual(95);
    expect(estimateScanProgress({ ...value, state: 'completed' }, 1e12, result).percent).toBe(100);
    for (const state of ['failed', 'partial', 'cancelled'] as const) {
      expect(estimateScanProgress(scan({ state, percent: 100 }), 0).percent).toBeNull();
    }
  });

  it('has a bounded generic estimate when metadata is absent and rejects invalid percentages', () => {
    for (const percent of [null, undefined, NaN, Infinity, -1, 101]) {
      const result = after(scan({ checks: undefined, percent }), 60);
      expect(Number.isFinite(result.percent)).toBe(true);
      expect(result.percent).toBeGreaterThan(0);
      expect(result.percent).toBeLessThan(100);
    }
    expect(after(scan({ percent: 100 }), 60).percent).toBe(99);
  });

  it('retains explicit server progress when later polls return null, without changing the snapshot', () => {
    const result = estimateScanProgress(scan({ percent: 90 }), 0);
    const value = scan();
    expect(estimateScanProgress(value, 1000, result).percent).toBe(90);
    expect(value.percent).toBeNull();
  });

  it('resets for a different scan, selection, queue reentry, or a fresh observation', () => {
    const result: ScanProgressEstimate = after(scan(), 120);
    expect(result.percent).toBeGreaterThan(0);
    for (const value of [
      scan({ scanId: 'scan-2' }),
      scan({ checks: ['config'] }),
      scan({ state: 'queued' }),
    ]) {
      const reset = estimateScanProgress(value, 120_000, result);
      expect(reset.percent).toBe(0);
      expect(reset.runningMs).toBe(0);
    }
    expect(estimateScanProgress(scan(), 120_000).percent).toBe(0);
    expect(
      estimateScanProgress(scan({ checks: ['config', 'vuln', 'sbom', 'secret'] }), 120_000, result).percent,
    ).toBe(result.percent);
  });
});
