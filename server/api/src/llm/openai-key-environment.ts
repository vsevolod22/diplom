import { openAiConfigurationError } from './openai-policy.js';

export type OpenAiEnvironment = Readonly<Record<string, string | undefined>>;
const validKey = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_-]{16,512}$/.test(value);

// Lazy, server-only, no module-load I/O, cache, trimming or file/provider fallback.
// Call only from trusted composition after configuration and admission checks.
export function readOpenAiKeyEnvironment(env: OpenAiEnvironment = process.env): string {
  try {
    const key = env.OPENAI_API_KEY;
    if (validKey(key)) return key;
  } catch { /* Never retain the source exception or its potentially sensitive text. */ }
  throw openAiConfigurationError();
}

// Local readiness only: never returns the value, a fragment, length or fingerprint.
export function openAiKeyEnvironmentReady(env: OpenAiEnvironment = process.env): boolean {
  try { return validKey(env.OPENAI_API_KEY); } catch { return false; }
}
