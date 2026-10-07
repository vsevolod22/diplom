import { NGINX_SUPPORTED_CANDIDATE } from './bounded-image-archive.js';
import type { ArchiveReceipt } from './bounded-image-archive.js';

export const NGINX_LOCAL_BINDING = Object.freeze({ qualificationId: 'nginx-local-0dcc-v1', version: 1,
  configDigest: NGINX_SUPPORTED_CANDIDATE.configDigest, profileVersion: 'nginx-alpine-amd64-v2-candidate',
  checksVersion: 'trivy-0.69.3-archive-v1', resourcePolicyVersion: 'nginx-archive-resources-v1', scannerVersion: '0.69.3' });
export type LocalExecutionBinding = typeof NGINX_LOCAL_BINDING;
export const NGINX_LOCAL_POLICY = Object.freeze({ ...NGINX_SUPPORTED_CANDIDATE, ...NGINX_LOCAL_BINDING,
  allowedCheckSets: Object.freeze([Object.freeze(['secret']), Object.freeze(['sbom']), Object.freeze(['vuln']), Object.freeze(['secret', 'sbom', 'vuln'])]),
  evidence: Object.freeze(['DIP-ARTF-1', 'DIP-ARTF-6', 'DIP-ARTF-28']),
  expiryProofSources: Object.freeze({
    'test_nginx_db_path.py': 'e5c4e2c81831c376f9ebd86a6665c36fda87519a9dea6de5f0b66eb209b56c34',
    'nginx-db-fixtures.mjs': '20665f7270d4b28f9565da5a5272e7f624ed839a579b3a2f81cfebe7fb624cf1',
    'nginx-db-browser.mjs': '372d89b2bfe81b789cc7ae880bdb3098c416c468935e6a2f90fdadf7391b7a1b',
  }) });
export const localChecksAllowed = (checks: readonly string[]) => NGINX_LOCAL_POLICY.allowedCheckSets.some(set => JSON.stringify(set) === JSON.stringify(checks));
export function validLocalBinding(value: unknown): value is LocalExecutionBinding {
  return !!value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === Object.keys(NGINX_LOCAL_BINDING).length &&
    Object.entries(NGINX_LOCAL_BINDING).every(([key, expected]) => (value as Record<string, unknown>)[key] === expected);
}
export function exactLocalTarget(target: { registry: string; repository: string; digest: string; platform: string }) {
  return ['registry', 'repository', 'digest', 'platform'].every(key => target[key as keyof typeof target] === NGINX_LOCAL_POLICY[key as 'registry']);
}
export function localReceiptMatches(receipt: ArchiveReceipt, scannerVersion: string) {
  return exactLocalTarget(receipt) && receipt.configDigest === NGINX_LOCAL_BINDING.configDigest &&
    receipt.profileVersion === NGINX_LOCAL_BINDING.profileVersion && receipt.checksVersion === NGINX_LOCAL_BINDING.checksVersion &&
    receipt.resourcePolicyVersion === NGINX_LOCAL_BINDING.resourcePolicyVersion && scannerVersion === NGINX_LOCAL_BINDING.scannerVersion;
}
