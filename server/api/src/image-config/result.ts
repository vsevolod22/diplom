import { createHash } from 'node:crypto';
import type { Classification, Coverage, Finding, ImageConfigResult } from './contract.js';
import { CHECKS_VERSION, fail, POLICY, POLICY_VERSION, RULE_ID } from './policy.js';
import type { VerifiedInput } from './verified-input.js';

export function enforceOutputBounds(result: unknown, findingCount: number): void {
  if (findingCount > POLICY.findings || Buffer.byteLength(JSON.stringify(result), 'utf8') > POLICY.resultBytes) {
    fail('CONFIG_LIMIT_EXCEEDED');
  }
}

export function buildResult(coverage: Coverage, sources: { dockerfile: boolean; iac: boolean },
  verified?: Readonly<VerifiedInput>, classification?: Classification): ImageConfigResult {
  const findings: Finding[] = [];
  if (classification && verified && coverage.outcome === 'checked') {
    // JSON tuple encoding prevents concatenation ambiguity; platform order is explicit.
    const tuple = [verified.manifestDigest, verified.configDigest,
      [verified.platform.os, verified.platform.architecture, verified.platform.variant ?? null], CHECKS_VERSION, RULE_ID, '/config/User'];
    findings.push({
      findingId: `sha256:${createHash('sha256').update(JSON.stringify(tuple)).digest('hex')}`,
      ruleId: RULE_ID,
      category: 'image-config',
      severity: 'MEDIUM',
      severitySource: CHECKS_VERSION,
      classification,
      message: classification === 'DEFAULT_ROOT' ? 'Image metadata uses the default root user.' : 'Image metadata declares numeric UID 0.',
      recommendation: 'Set an explicit non-zero numeric image user; verify runtime identity separately.',
      location: '/config/User',
      manifestDigest: verified.manifestDigest,
      configDigest: verified.configDigest,
      platform: { os: verified.platform.os, architecture: verified.platform.architecture,
        ...(verified.platform.variant === undefined ? {} : { variant: verified.platform.variant }) },
    });
  }
  const config: Coverage = { outcome: coverage.outcome, ...(coverage.reason ? { reason: coverage.reason } : {}) };
  const result: ImageConfigResult = {
    checksVersion: CHECKS_VERSION,
    resourcePolicyVersion: POLICY_VERSION,
    supportedRuleIds: [RULE_ID],
    completedRuleIds: config.outcome === 'checked' ? [RULE_ID] : [],
    config,
    rules: [{ ruleId: RULE_ID, ...config }],
    history: { outcome: 'unsupported', reason: 'RULE_NOT_IMPLEMENTED' },
    dockerfile: { outcome: 'unsupported', reason: sources.dockerfile ? 'SOURCE_ANALYZER_UNSUPPORTED' : 'SOURCE_NOT_PROVIDED' },
    iac: { outcome: 'unsupported', reason: sources.iac ? 'SOURCE_ANALYZER_UNSUPPORTED' : 'SOURCE_NOT_PROVIDED' },
    findings,
  };
  enforceOutputBounds(result, findings.length);
  return result;
}
