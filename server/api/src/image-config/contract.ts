import type { CHECKS_VERSION, POLICY_VERSION, RULE_ID } from './policy.js';

export interface Platform {
  readonly os: string;
  readonly architecture: string;
  readonly variant?: string;
}

export interface AuthorizedImageInput {
  readonly identity: {
    readonly registry: string;
    readonly repository: string;
    readonly manifestDigest: string;
    readonly platform: Platform;
  };
  readonly manifestBytes: Uint8Array;
  readonly configBytes: Uint8Array;
}

/** Bootstrap-only capability. Its implementation must recognize server-issued opaque
 * handles bound to an authorized scan and pinned target, not trust fields in a DTO.
 * Returning bytes asserts upstream authorization, NOT local content verification.
 */
export interface TrustedCallerPort {
  resolveAuthorizedTarget(handle: unknown): AuthorizedImageInput | undefined | Promise<AuthorizedImageInput | undefined>;
}

// Unknown fields deliberately allowed, but never forwarded to the port or echoed.
export interface AnalyzeRequest {
  readonly enabled?: unknown;
  readonly target?: unknown;
  readonly dockerfileProvided?: unknown;
  readonly iacProvided?: unknown;
  readonly [key: string]: unknown;
}

export type Outcome = 'checked' | 'unsupported' | 'failed' | 'skipped';
export type Reason = 'CHECK_DISABLED' | 'INVALID_CHECK_FLAG' | 'INVALID_RESOURCE_POLICY' |
  'OCI_IDENTITY_REJECTED' | 'CONFIG_LIMIT_EXCEEDED' | 'INVALID_CONFIG' | 'USER_NOT_RESOLVABLE' |
  'RULE_NOT_IMPLEMENTED' | 'SOURCE_NOT_PROVIDED' | 'SOURCE_ANALYZER_UNSUPPORTED';
export interface Coverage {
  outcome: Outcome;
  reason?: Reason;
}
export type Classification = 'DEFAULT_ROOT' | 'NUMERIC_ROOT';
export interface Finding {
  findingId: string;
  ruleId: typeof RULE_ID;
  category: 'image-config';
  severity: 'MEDIUM';
  severitySource: typeof CHECKS_VERSION;
  classification: Classification;
  message: string;
  recommendation: string;
  location: '/config/User';
  manifestDigest: string;
  configDigest: string;
  platform: Platform;
}
export interface ImageConfigResult {
  checksVersion: typeof CHECKS_VERSION;
  resourcePolicyVersion: typeof POLICY_VERSION;
  supportedRuleIds: (typeof RULE_ID)[];
  completedRuleIds: (typeof RULE_ID)[];
  config: Coverage;
  rules: { ruleId: typeof RULE_ID; outcome: Outcome; reason?: Reason }[];
  history: Coverage;
  dockerfile: Coverage;
  iac: Coverage;
  findings: Finding[];
}
export interface ImageConfigModule {
  analyze(request: AnalyzeRequest): Promise<ImageConfigResult>;
}
