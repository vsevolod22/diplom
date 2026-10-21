import { lstatSync } from 'node:fs';
import { FREE_MODEL, FREE_PROVIDER, PUBLIC_FREE_MODEL, PUBLIC_FREE_PROVIDER, type LlmPolicy } from './policy.js';
import { PUBLIC_OPENROUTER_KEY_FILE } from './public-key-file.js';

export type PublicCredentialStatus = 'unconfigured' | 'missing' | 'unsafe' | 'metadata-valid';
// Metadata only: never opens a credential, constructs a provider or follows an env path.
// Production callers always use the fixed path; the argument is a filesystem test seam.
export function publicKeyMetadata(path = PUBLIC_OPENROUTER_KEY_FILE): PublicCredentialStatus {
  try {
    const info = lstatSync(path), uid = process.getuid?.();
    if (!info.isFile() || info.nlink !== 1 || info.size < 17 || info.size > 513 ||
        ![0o400, 0o600].includes(info.mode & 0o777) || uid === undefined ||
        info.uid !== uid) return 'unsafe';
    return 'metadata-valid';
  } catch (error) {
    return error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT' ? 'missing' : 'unsafe';
  }
}
export function publicCredentialStatus(env: NodeJS.ProcessEnv = process.env): PublicCredentialStatus {
  if (env.OPENROUTER_API_KEY_FILE === undefined) return 'unconfigured';
  if (env.OPENROUTER_API_KEY_FILE !== PUBLIC_OPENROUTER_KEY_FILE || env.OPENROUTER_API_KEY !== undefined) return 'unsafe';
  return publicKeyMetadata();
}

export function catalogProfile(policy: LlmPolicy | null) {
  const base = { checkedOn: '2026-10-21', liveVerified: false as const };
  if (policy?.freeOnly && policy.model === PUBLIC_FREE_MODEL && policy.providers.length === 1 && policy.providers[0] === PUBLIC_FREE_PROVIDER)
    return { ...base, status: 'catalog-listed-unprobed' as const, model: PUBLIC_FREE_MODEL, endpoint: PUBLIC_FREE_PROVIDER, zdrListed: true };
  if (policy?.freeOnly && policy.model === FREE_MODEL && policy.providers.length === 1 && policy.providers[0] === FREE_PROVIDER)
    return { ...base, status: 'no-catalog-endpoints' as const, model: FREE_MODEL, endpoint: FREE_PROVIDER, zdrListed: false };
  return { ...base, status: 'unverified-profile' as const, zdrListed: false };
}

export function publicReadiness(policy: LlmPolicy | null, credential: PublicCredentialStatus,
  quotaAvailable: boolean, historyAvailable: boolean) {
  const provider = catalogProfile(policy);
  const blockers: string[] = [];
  if (!policy?.freeOnly) blockers.push('configuration-required');
  if (credential !== 'metadata-valid') blockers.push(credential === 'missing' || credential === 'unconfigured' ? 'public-key-required' : 'public-key-unsafe');
  if (!quotaAvailable) blockers.push('quota-store-unavailable');
  if (!historyAvailable) blockers.push('history-store-unavailable');
  if (provider.status !== 'catalog-listed-unprobed') blockers.push('provider-profile-unavailable');
  return { status: blockers.length ? 'setup-required' : 'locally-configured', localReady: blockers.length === 0,
    blockers, credential, quota: quotaAvailable ? 'available' : 'unavailable', history: historyAvailable ? 'available' : 'unavailable',
    provider, generationVerified: false, requiresConsent: true, acceptsCredentials: false,
    setupAction: 'operator-public-file-configuration' };
}
