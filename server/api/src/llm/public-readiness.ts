import { lstatSync } from 'node:fs';
import { FREE_MODEL, FREE_PROVIDER, PUBLIC_FREE_MODEL, PUBLIC_FREE_PROVIDER, publicFreePolicy, type LlmPolicy } from './policy.js';
import { PUBLIC_OPENROUTER_KEY_FILE } from './public-key-file.js';
import { MODULEAPI_ESTIMATE_SOURCE, type ModuleApiReadiness, type ModuleApiReadinessBlocker, type OpenAiReadiness, type OpenAiReadinessBlocker, type TranslationReadiness, type TranslationReadinessBlocker } from './provider-browser-contract.js';
import type { OpenAiRuntimeResolver, ModuleApiRuntimeResolver } from './provider-runtime.js';

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

export function openAiReadiness(resolver: OpenAiRuntimeResolver, quotaAvailable: boolean, historyAvailable: boolean): OpenAiReadiness {
  const { configuration, runtime } = resolver.inspect();
  const keyReady = resolver.credentialReady();
  const blockers: OpenAiReadinessBlocker[] = [];
  if (!configuration) blockers.push('configuration-required');
  if (!keyReady) blockers.push('environment-key-required');
  if (!runtime) blockers.push('accounting-configuration-required');
  if (!quotaAvailable) blockers.push('quota-store-unavailable');
  if (!historyAvailable) blockers.push('history-store-unavailable');
  return { status: blockers.length ? 'setup-required' : 'locally-configured', localReady: blockers.length === 0, blockers,
    credential: keyReady ? 'environment-valid' : 'unavailable', quota: quotaAvailable ? 'available' : 'unavailable',
    history: historyAvailable ? 'available' : 'unavailable', accounting: runtime ? 'configured' : 'unavailable',
    provider: { name: 'OpenAI', model: configuration?.policy.model ?? null,
      status: configuration ? 'configured-unprobed' : 'configuration-unavailable', liveVerified: false },
    generationVerified: false, requiresConsent: true, acceptsCredentials: false, setupAction: 'operator-server-environment-configuration' };
}

export function moduleApiReadiness(resolver: ModuleApiRuntimeResolver, quotaAvailable: boolean, historyAvailable: boolean): ModuleApiReadiness {
  const { configuration, runtime } = resolver.inspect();
  const keyReady = resolver.credentialReady();
  const blockers: ModuleApiReadinessBlocker[] = [];
  if (!configuration) blockers.push('configuration-required');
  if (!keyReady) blockers.push('environment-key-required');
  if (!runtime) blockers.push('accounting-configuration-required');
  if (!quotaAvailable) blockers.push('quota-store-unavailable');
  if (!historyAvailable) blockers.push('history-store-unavailable');
  return { status: blockers.length ? 'setup-required' : 'locally-configured', localReady: blockers.length === 0, blockers,
    credential: keyReady ? 'environment-valid' : 'unavailable', quota: quotaAvailable ? 'available' : 'unavailable',
    history: historyAvailable ? 'available' : 'unavailable', accounting: runtime ? 'configured' : 'unavailable',
    costBasis: MODULEAPI_ESTIMATE_SOURCE,
    provider: { name: 'ModuleAPI', model: configuration?.policy.model ?? null,
      status: configuration ? 'configured-unprobed' : 'configuration-unavailable', liveVerified: false,
      retention: 'unknown', operatorApprovedRouting: true, zeroDataRetentionVerified: false, tariffVerified: false },
    generationVerified: false, requiresConsent: true, acceptsCredentials: false, setupAction: 'operator-server-environment-configuration' };
}

export function catalogProfile(policy: LlmPolicy | null) {
  const base = { checkedOn: '2026-10-21', liveVerified: false as const };
  // Coordinator-supplied 2026-10-29 catalog listing, not product qualification.
  // The endpoint retains prompts (non-ZDR); no-training does not mean no-storage.
  if (publicFreePolicy(policy))
    return { checkedOn: '2026-10-29', liveVerified: false as const, status: 'catalog-listed-unprobed' as const,
      model: PUBLIC_FREE_MODEL, endpoint: PUBLIC_FREE_PROVIDER, zdrListed: false as const, retention: 'no-training' as const };
  if (policy?.freeOnly && policy.model === FREE_MODEL && policy.providers.length === 1 && policy.providers[0] === FREE_PROVIDER)
    return { ...base, status: 'no-catalog-endpoints' as const, model: FREE_MODEL, endpoint: FREE_PROVIDER, zdrListed: false as const };
  return { ...base, status: 'unverified-profile' as const, zdrListed: false as const };
}

export function translationReadiness(policy: LlmPolicy | null, credential: PublicCredentialStatus,
  quotaAvailable: boolean, quotaCompatible: boolean):
  Omit<TranslationReadiness, 'scanId' | 'digest' | 'platform' | 'reportVersion'> {
  // Preserve the informational wire field without claiming history availability.
  // Unlike summary/chat, translation has no history dependency and never probes it.
  const base = publicReadiness(policy, credential, quotaAvailable, false);
  const blockers: TranslationReadinessBlocker[] = base.blockers.filter(blocker => blocker !== 'history-store-unavailable');
  if (!quotaCompatible) blockers.push('quota-policy-incompatible');
  return { ...base, operation: 'translation', provider: { ...base.provider, name: 'OpenRouter' }, blockers,
    status: blockers.length ? 'setup-required' : 'locally-configured', localReady: blockers.length === 0 };
}

export function publicReadiness(policy: LlmPolicy | null, credential: PublicCredentialStatus,
  quotaAvailable: boolean, historyAvailable: boolean) {
  const provider = catalogProfile(policy);
  const blockers: Array<Exclude<TranslationReadinessBlocker, 'quota-policy-incompatible'> | 'history-store-unavailable'> = [];
  if (!publicFreePolicy(policy)) blockers.push('configuration-required');
  if (credential !== 'metadata-valid') blockers.push(credential === 'missing' || credential === 'unconfigured' ? 'public-key-required' : 'public-key-unsafe');
  if (!quotaAvailable) blockers.push('quota-store-unavailable');
  if (!historyAvailable) blockers.push('history-store-unavailable');
  if (provider.status !== 'catalog-listed-unprobed') blockers.push('provider-profile-unavailable');
  return { status: blockers.length ? 'setup-required' as const : 'locally-configured' as const, localReady: blockers.length === 0,
    blockers, credential, quota: quotaAvailable ? 'available' as const : 'unavailable' as const,
    history: historyAvailable ? 'available' as const : 'unavailable' as const,
    provider, generationVerified: false as const, requiresConsent: true as const, acceptsCredentials: false as const,
    setupAction: 'operator-public-file-configuration' as const };
}
