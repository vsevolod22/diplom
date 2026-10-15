import { z } from 'zod';

const rule = z.literal('IMGCFG_USER_ROOT');
const checksVersion = z.literal('image-config-user-v1');
const resourcePolicyVersion = z.literal('image-config-policy-v1');
const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const configCoverage = z.discriminatedUnion('outcome', [
  z.strictObject({ outcome: z.literal('checked') }),
  z.strictObject({ outcome: z.literal('skipped'), reason: z.literal('CHECK_DISABLED') }),
  z.strictObject({ outcome: z.literal('unsupported'), reason: z.literal('USER_NOT_RESOLVABLE') }),
  z.strictObject({ outcome: z.literal('failed'), reason: z.enum(['OCI_IDENTITY_REJECTED', 'CONFIG_LIMIT_EXCEEDED', 'INVALID_CONFIG']) }),
]);
const ruleCoverage = z.union([
  z.strictObject({ ruleId: rule, outcome: z.literal('checked') }),
  z.strictObject({ ruleId: rule, outcome: z.literal('skipped'), reason: z.literal('CHECK_DISABLED') }),
  z.strictObject({ ruleId: rule, outcome: z.literal('unsupported'), reason: z.literal('USER_NOT_RESOLVABLE') }),
  z.strictObject({ ruleId: rule, outcome: z.literal('failed'), reason: z.enum(['OCI_IDENTITY_REJECTED', 'CONFIG_LIMIT_EXCEEDED', 'INVALID_CONFIG']) }),
]);
const source = z.strictObject({ outcome: z.literal('unsupported'), reason: z.literal('SOURCE_NOT_PROVIDED') });
const configFinding = z.strictObject({ findingId: digest, ruleId: rule, category: z.literal('image-config'),
  severity: z.literal('MEDIUM'), severitySource: checksVersion, classification: z.enum(['DEFAULT_ROOT', 'NUMERIC_ROOT']),
  message: z.enum(['Image metadata uses the default root user.', 'Image metadata declares numeric UID 0.']),
  recommendation: z.literal('Set an explicit non-zero numeric image user; verify runtime identity separately.'),
  location: z.literal('/config/User'), manifestDigest: digest, configDigest: digest,
  platform: z.strictObject({ os: z.literal('linux'), architecture: z.literal('amd64') }),
}).refine(finding => finding.message === (finding.classification === 'DEFAULT_ROOT'
  ? 'Image metadata uses the default root user.' : 'Image metadata declares numeric UID 0.'));

export const imageConfigReport = z.strictObject({ checksVersion, resourcePolicyVersion,
  supportedRuleIds: z.tuple([rule]), completedRuleIds: z.union([z.tuple([]), z.tuple([rule])]),
  config: configCoverage, rules: z.tuple([ruleCoverage]),
  history: z.strictObject({ outcome: z.literal('unsupported'), reason: z.literal('RULE_NOT_IMPLEMENTED') }),
  dockerfile: source, iac: source, findings: z.array(configFinding).max(1),
}).superRefine((report, context) => {
  const coverage: Partial<z.infer<typeof ruleCoverage>> = { ...report.rules[0] };
    delete coverage.ruleId;
  if (JSON.stringify(coverage) !== JSON.stringify(report.config) ||
      (report.completedRuleIds.length === 1) !== (report.config.outcome === 'checked') ||
      report.config.outcome !== 'checked' && report.findings.length > 0 ||
      new TextEncoder().encode(JSON.stringify(report)).length > 16384) {
    context.addIssue({ code: 'custom', message: 'Inconsistent image config evidence' });
  }
});
export const wireConfigCoverage = z.strictObject({ check: z.literal('config'), coverage: z.literal('image'),
  outcome: z.enum(['checked', 'failed', 'unsupported', 'skipped']), reason: z.enum(['CHECK_DISABLED', 'USER_NOT_RESOLVABLE',
    'OCI_IDENTITY_REJECTED', 'CONFIG_LIMIT_EXCEEDED', 'INVALID_CONFIG']).optional(), checksVersion, resourcePolicyVersion,
  supportedRuleIds: z.tuple([rule]), completedRuleIds: z.union([z.tuple([]), z.tuple([rule])]), findingCount: z.number().int().min(0).max(1),
});
export type ImageConfigReport = z.infer<typeof imageConfigReport>;
