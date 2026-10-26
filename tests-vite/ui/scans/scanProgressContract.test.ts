import { describe, expect, it } from 'vitest';
import { parseCurrentList, parseCurrentStatus, parseScanStatus, scanChecks, type ScanStatus } from '@/shared/api/scans/scanTransport';
import type { ScanCheck, ScanOutcome, ScanProgress } from '@/shared/api/scans/types';

const checks: ScanCheck[] = [...scanChecks];
const progress: ScanProgress = { basis: 'durable-outcomes-v1', requestedChecks: checks,
  outcomes: { secret: 'checked', sbom: 'failed', vuln: null, config: null }, resolvedChecks: 2, checkedChecks: 1 };
const running = { scanId: '00000000-0000-4000-8000-000000000001', state: 'running', checks,
  perCheck: { secret: null, sbom: null, vuln: null, config: null }, result: null, progress };
const checked = { check: 'secret', coverage: 'image', outcome: 'checked', errorCode: null, scannerVersion: '0.69.3', findingCount: 1 };

describe('durable-outcomes-v1 owner detail contract', () => {
  it('retains typed metadata while percent and unpublished results remain unknown', () => {
    const decoded: ScanStatus = parseCurrentStatus(running);
    const typed: ScanProgress | undefined = decoded.progress;
    expect(typed).toEqual(progress);
    expect(decoded.percent).toBeNull();
    expect(decoded.perCheck).toEqual(running.perCheck);
    expect(typed!.requestedChecks.length - typed!.resolvedChecks).toBe(2);
    expect(parseScanStatus(decoded)).toEqual(decoded);
  });

  it('accepts absent/null unresolved entries without inferring checked zero or remaining time', () => {
    for (const outcomes of [{}, { secret: null }, running.perCheck]) {
      const empty = { ...progress, outcomes, resolvedChecks: 0, checkedChecks: 0 };
      const decoded = parseCurrentStatus({ ...running, state: 'queued', progress: empty });
      expect(decoded.progress).toEqual(empty); expect(decoded.percent).toBeNull();
    }
    expect(parseCurrentStatus({ ...running, progress: undefined }).progress).toBeUndefined();
    expect(parseScanStatus({ scanId: 'legacy', state: 'running' }).progress).toBeUndefined();
  });

  it.each<ScanOutcome>(['checked', 'failed', 'unsupported', 'skipped', 'not_authorized'])('counts %s as resolved but only checked as checked', outcome => {
    const value: ScanProgress = { basis: 'durable-outcomes-v1', requestedChecks: ['secret'], outcomes: { secret: outcome },
      resolvedChecks: 1, checkedChecks: outcome === 'checked' ? 1 : 0 };
    expect(parseCurrentStatus({ ...running, checks: ['secret'], perCheck: { secret: null }, progress: value }).progress).toEqual(value);
  });

  const invalid: Array<[string, unknown]> = [
    ['unknown basis', { ...progress, basis: 'estimated-v1' }],
    ['null object', null],
    ['empty selected checks', { ...progress, requestedChecks: [] }],
    ['duplicate selected checks', { ...progress, requestedChecks: ['secret', 'secret'] }],
    ['unordered selected checks', { ...progress, requestedChecks: ['sbom', 'secret'] }],
    ['unknown selected check', { ...progress, requestedChecks: ['docker'] }],
    ['different subset', { ...progress, requestedChecks: ['secret', 'sbom'] }],
    ['unknown outcome key', { ...progress, outcomes: { docker: 'checked' } }],
    ['outcome for unselected check', { ...progress, requestedChecks: ['vuln'], outcomes: { secret: 'checked' }, resolvedChecks: 1, checkedChecks: 1 }],
    ['unknown outcome', { ...progress, outcomes: { secret: 'safe' } }],
    ['undefined outcome', { ...progress, outcomes: { secret: undefined }, resolvedChecks: 0, checkedChecks: 0 }],
    ['array outcomes', { ...progress, outcomes: [], resolvedChecks: 0, checkedChecks: 0 }],
    ['object outcome', { ...progress, outcomes: { secret: { outcome: 'checked', findings: [] } } }],
    ['false resolved count', { ...progress, resolvedChecks: 4 }],
    ['false checked count', { ...progress, checkedChecks: 2 }],
    ['negative count', { ...progress, resolvedChecks: -1 }],
    ['fractional count', { ...progress, resolvedChecks: 1.5 }],
    ['oversized count', { ...progress, resolvedChecks: 5 }],
    ['nonfinite count', { ...progress, checkedChecks: Infinity }],
    ['string count', { ...progress, resolvedChecks: '2' }],
    ['missing count', { basis: progress.basis, requestedChecks: checks, outcomes: progress.outcomes, checkedChecks: 1 }],
    ...['findings', 'findingCount', 'componentCount', 'reason', 'raw', 'scannerLog', 'leaseToken', 'tokens', 'checkedAt', 'percent', 'eta'].map(key =>
      [`forbidden ${key}`, { ...progress, [key]: 'PRIVATE_CANARY' }] as [string, unknown]),
  ];
  it.each(invalid)('fails closed for %s in both status decoders', (_name, value) => {
    expect(() => parseCurrentStatus({ ...running, progress: value })).toThrow();
    expect(() => parseScanStatus({ ...running, progress: value })).toThrow();
  });

  it('rejects inherited data, accessors and magic outcome keys without invoking getters', () => {
    let reads = 0;
    const inherited = Object.create({ secret: 'checked' });
    const accessor = Object.defineProperty({}, 'secret', { enumerable: true, get: () => { reads++; return 'checked'; } });
    const magic = JSON.parse('{"__proto__":"checked"}');
    for (const outcomes of [inherited, accessor, magic]) {
      expect(() => parseCurrentStatus({ ...running, progress: { ...progress, outcomes } })).toThrow();
      expect(() => parseScanStatus({ ...running, progress: { ...progress, outcomes } })).toThrow();
    }
    expect(reads).toBe(0);
  });

  it('rejects missing check identity, premature published reports and queued resolved outcomes', () => {
    for (const value of [
      { ...running, checks: undefined }, { ...running, checks: ['vuln'] },
      { ...running, perCheck: { ...running.perCheck, secret: checked } },
      { ...running, state: 'queued' },
    ]) {
      expect(() => parseCurrentStatus(value)).toThrow();
      expect(() => parseScanStatus(value)).toThrow();
    }
    expect(() => parseCurrentStatus({ ...running, result: checked })).toThrow();
  });

  it.each(['completed', 'partial', 'failed', 'cancelled'])('terminal %s metadata must match published outcomes including unknown interrupted siblings', state => {
    const value = { ...running, state, perCheck: { ...running.perCheck, secret: checked },
      progress: { ...progress, outcomes: { secret: 'checked' }, resolvedChecks: 1, checkedChecks: 1 } };
    expect(parseCurrentStatus(value).progress).toEqual(value.progress);
    expect(parseScanStatus(value).progress).toEqual(value.progress);
    for (const bad of [progress, { ...value.progress, outcomes: {}, resolvedChecks: 0, checkedChecks: 0 }]) {
      expect(() => parseCurrentStatus({ ...value, progress: bad })).toThrow();
      expect(() => parseScanStatus({ ...value, progress: bad })).toThrow();
    }
  });

  it('does not add detail-only progress to the native public list or derive a percent from resolved checks', () => {
    const digest = `sha256:${'a'.repeat(64)}`;
    const list = parseCurrentList({ scans: [{ scanId: running.scanId, state: 'running', digest, platform: 'linux/amd64',
      targetLabel: `registry-1.docker.io/library/alpine@${digest}`, progress }], nextCursor: null });
    expect(list.scans[0].progress).toBeUndefined(); expect(list.scans[0].percent).toBeNull();
    expect(() => parseScanStatus({ ...running, percent: 50 })).toThrow();
    expect(parseCurrentStatus({ ...running, percent: 50 }).percent).toBeNull();
    expect(parseCurrentStatus({ ...running, progress: { ...progress, outcomes: { secret: 'checked', sbom: 'checked', vuln: 'checked', config: 'checked' },
      resolvedChecks: 4, checkedChecks: 4 } }).percent).toBeNull();
  });
});
