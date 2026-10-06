import type { AnalyzeRequest, ImageConfigModule, TrustedCallerPort } from './contract.js';
import { ConfigFailure, type FailureReason } from './policy.js';
import { buildResult } from './result.js';
import { evaluateUser } from './user-rule.js';
import { createVerifier } from './verified-input.js';

export type { AnalyzeRequest, AuthorizedImageInput, Coverage, Finding, ImageConfigModule, ImageConfigResult, Platform, TrustedCallerPort } from './contract.js';
export { CHECKS_VERSION, POLICY_VERSION, POLICY, RULE_ID } from './policy.js';

/** Install only in trusted server composition. This is a pure module contract,
 * not an HTTP endpoint, fetcher, authorization service, or report/ledger adapter.
 */
export function createImageConfigModule(trustedCallerPort: TrustedCallerPort): ImageConfigModule {
  // Capture the capability once: requests cannot install a verifier/port or weaken policy.
  const resolve = trustedCallerPort.resolveAuthorizedTarget.bind(trustedCallerPort);
  const verifier = createVerifier();
  return Object.freeze({
    async analyze(request: AnalyzeRequest) {
      const sources = { dockerfile: false, iac: false };
      try {
        if (typeof request !== 'object' || request === null || Array.isArray(request)) {
          return buildResult({ outcome: 'failed', reason: 'INVALID_CHECK_FLAG' }, sources);
        }
        // DTO data only: accessors/prototype flags never execute or activate a check.
        sources.dockerfile = Object.getOwnPropertyDescriptor(request, 'dockerfileProvided')?.value === true;
        sources.iac = Object.getOwnPropertyDescriptor(request, 'iacProvided')?.value === true;
        const flag = Object.getOwnPropertyDescriptor(request, 'enabled');
        const enabled: unknown = flag?.value;
        if (!flag || enabled === false) {
          return buildResult({ outcome: 'skipped', reason: 'CHECK_DISABLED' }, sources);
        }
        if (enabled !== true) return buildResult({ outcome: 'failed', reason: 'INVALID_CHECK_FLAG' }, sources);
        // A supplied override is an error, not a hint or an opportunity to disable bounds.
        if (['policy', 'resourcePolicy', 'resourcePolicyVersion', 'checksVersion'].some(key => Object.hasOwn(request, key))) {
          return buildResult({ outcome: 'failed', reason: 'INVALID_RESOURCE_POLICY' }, sources);
        }
        const input = await resolve(Object.getOwnPropertyDescriptor(request, 'target')?.value);
        if (!input) return buildResult({ outcome: 'failed', reason: 'OCI_IDENTITY_REJECTED' }, sources);
        const receipt = verifier.verify(input);
        const verified = verifier.read(receipt);
        const rule = evaluateUser(verified.user);
        return buildResult(rule.coverage, sources, verified, rule.classification);
      } catch (error) {
        return buildResult({ outcome: 'failed', reason: classifyFailure(error) }, sources);
      }
    },
  });
}

function classifyFailure(error: unknown): FailureReason {
  try {
    // Both instanceof and descriptor inspection can execute traps on a thrown Proxy.
    const reason: unknown = error instanceof ConfigFailure ? Object.getOwnPropertyDescriptor(error, 'reason')?.value : undefined;
    if (reason === 'INVALID_CONFIG' || reason === 'CONFIG_LIMIT_EXCEEDED') return reason;
  } catch {
    // Classification failure must not expose another exception or inspect its payload.
  }
  return 'OCI_IDENTITY_REJECTED';
}
