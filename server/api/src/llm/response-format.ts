import { publicFreePolicy, type LlmPolicy } from './policy.js';
import type { TranslationText } from './translation-contract.js';

type Operation = { kind: 'summary' } | { kind: 'chat' } | { kind: 'translation'; text: TranslationText };
const string = { type: 'string' };
const citations = { type: 'array', items: string };
const binding = { scanId: string, digest: string, platform: string, reportVersion: string };
const objectSchema = (properties: Record<string, unknown>) => ({
  type: 'object', properties, required: Object.keys(properties), additionalProperties: false,
});

// Provider bounds prevent an open-ended summary array from exhausting output
// tokens. Local validators still enforce bindings, citations, byte limits,
// Russian prose, source identifiers and safety. No provider-side repair/plugin.
export function responseFormat(policy: LlmPolicy, operation: Operation) {
  // Require the existing strict schemas for the public profile; unsupported
  // provider parameters fail closed, never downgrade to JSON-object mode.
  if (!publicFreePolicy(policy))
    return { type: 'json_object' };
  const properties = operation.kind === 'summary' ? { ...binding,
    hypotheses: { type: 'array', minItems: 1, maxItems: 6,
          items: objectSchema({ text: { type: 'string', maxLength: 320 },
            citations: { ...citations, minItems: 1, maxItems: 2 } }) },
  } : operation.kind === 'chat' ? { ...binding, text: string, citations } : {
    title: { type: operation.text.title === null ? 'null' : 'string' },
    description: { type: operation.text.description === null ? 'null' : 'string' },
  };
  return { type: 'json_schema', json_schema: {
    name: `scanner_${operation.kind}`, strict: true, schema: objectSchema(properties),
  } };
}
