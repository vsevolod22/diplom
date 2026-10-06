import { isDeepStrictEqual } from 'node:util';
import type { ImageConfigResult, Classification } from './contract.js';
import { buildResult } from './result.js';
import { POLICY } from './policy.js';

export type ReportTarget = { digest: string; platform: string };
export const configFailure = (): ImageConfigResult => buildResult({ outcome: 'failed', reason: 'OCI_IDENTITY_REJECTED' }, { dockerfile: false, iac: false });

/** Reconstruct the entire closed report; never persist an untrusted object's extra fields. */
export function validateConfigReport(value: unknown, target: ReportTarget, enabled: boolean): ImageConfigResult {
  try {
    const report = value as ImageConfigResult;
    const coverage = report.config;
    const allowed = coverage.outcome === 'checked' ? coverage.reason === undefined :
      coverage.outcome === 'unsupported' ? coverage.reason === 'USER_NOT_RESOLVABLE' :
      coverage.outcome === 'failed' ? ['OCI_IDENTITY_REJECTED', 'CONFIG_LIMIT_EXCEEDED', 'INVALID_CONFIG'].includes(coverage.reason!) :
      coverage.outcome === 'skipped' && coverage.reason === 'CHECK_DISABLED';
    if (!allowed || enabled === (coverage.outcome === 'skipped') || !Array.isArray(report.findings) || report.findings.length > 1) throw new Error();
    const finding = report.findings[0];
    let classification: Classification | undefined;
    if (finding) {
      if (!['DEFAULT_ROOT', 'NUMERIC_ROOT'].includes(finding.classification) ||
          !/^sha256:[a-f0-9]{64}$/.test(finding.configDigest) || finding.manifestDigest !== target.digest ||
          [finding.platform.os, finding.platform.architecture, finding.platform.variant].filter(Boolean).join('/') !== target.platform) throw new Error();
      classification = finding.classification;
    }
    const expected = buildResult(coverage, { dockerfile: false, iac: false }, finding ? {
      manifestDigest: target.digest, configDigest: finding.configDigest, platform: finding.platform,
    } : undefined, classification);
    if (!isDeepStrictEqual(report, expected) || Buffer.byteLength(JSON.stringify(expected)) > POLICY.resultBytes) throw new Error();
    return expected;
  } catch { throw new TypeError('Invalid config report'); }
}

export function sanitizeConfigReport(value: unknown, target: ReportTarget, enabled: boolean): ImageConfigResult {
  try { return validateConfigReport(value, target, enabled); }
  catch { return enabled ? configFailure() : buildResult({ outcome: 'skipped', reason: 'CHECK_DISABLED' }, { dockerfile: false, iac: false }); }
}
