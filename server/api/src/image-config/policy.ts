export const CHECKS_VERSION = 'image-config-user-v1' as const;
export const POLICY_VERSION = 'image-config-policy-v1' as const;
export const RULE_ID = 'IMGCFG_USER_ROOT' as const;

export const POLICY = Object.freeze({
  manifestBytes: 1_000_000,
  configBytes: 1_000_000,
  totalBytes: 2_000_000,
  depth: 32,
  nodes: 16_384,
  collection: 4096,
  keyBytes: 256,
  stringBytes: 8192,
  history: 1024,
  env: 1024,
  labels: 256,
  userBytes: 256,
  resultBytes: 16_384,
  findings: 1,
});

export type FailureReason = 'INVALID_CONFIG' | 'OCI_IDENTITY_REJECTED' | 'CONFIG_LIMIT_EXCEEDED';

// Never carry input, parser messages, or a nested caller error across the module boundary.
export class ConfigFailure extends Error {
  constructor(readonly reason: FailureReason) { super(reason); }
}
export function fail(reason: FailureReason): never { throw new ConfigFailure(reason); }
