import { moduleApiConfigurationError } from './moduleapi-policy.js';

export type ModuleApiEnvironment = Readonly<Record<string, string | undefined>>;
const validKey = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_-]{16,512}$/.test(value);

// Lazy, server-only, no module-load I/O, cache, trimming or file/provider fallback.
// Call only from trusted composition after configuration and admission checks.
export function readModuleApiKeyEnvironment(env: ModuleApiEnvironment = process.env): string {
  try {
    const key = env.MODULE_API_KEY;
    if (validKey(key)) return key;
  } catch { /* Never retain the source exception or its potentially sensitive text. */ }
  throw moduleApiConfigurationError();
}

// Local readiness only: never returns the value, a fragment, length or fingerprint.
export function moduleApiKeyEnvironmentReady(env: ModuleApiEnvironment = process.env): boolean {
  try { return validKey(env.MODULE_API_KEY); } catch { return false; }
}
