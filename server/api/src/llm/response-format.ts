import { PUBLIC_FREE_MODEL, PUBLIC_FREE_PROVIDER, type LlmPolicy } from './policy.js';
import type { TranslationText } from './translation-contract.js';

type Operation = { kind: 'summary' } | { kind: 'chat' } | { kind: 'translation'; text: TranslationText };
const string = { type: 'string' };
const citations = { type: 'array', items: string };
const binding = { scanId: string, digest: string, platform: string, reportVersion: string };
const objectSchema = (properties: Record<string, unknown>) => ({
  type: 'object', properties, required: Object.keys(properties), additionalProperties: false,
});

// Shape only: local validators still enforce bindings, citations, byte limits,
// Russian prose, source identifiers and safety. No provider-side repair/plugin.
export function responseFormat(policy: LlmPolicy, operation: Operation) {
  // Structured-output support was checked for this exact endpoint, not for the
  // separate legacy/Apodex profile. Unsupported requests fail, never downgrade.
  if (!policy.freeOnly || policy.model !== PUBLIC_FREE_MODEL || policy.providers.length !== 1 || policy.providers[0] !== PUBLIC_FREE_PROVIDER)
    return { type: 'json_object' };
  const properties = operation.kind === 'summary' ? { ...binding,
    hypotheses: { type: 'array', items: objectSchema({ text: string, citations }) },
  } : operation.kind === 'chat' ? { ...binding, text: string, citations } : {
    title: { type: operation.text.title === null ? 'null' : 'string' },
    description: { type: operation.text.description === null ? 'null' : 'string' },
  };
  return { type: 'json_schema', json_schema: {
    name: `scanner_${operation.kind}`, strict: true, schema: objectSchema(properties),
  } };
}
