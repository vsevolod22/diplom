export type OpenAiOperation = 'summary' | 'chat';

// A finite alphabet, not a technical-token allowlist. Exact values live in sources.
export const OPENAI_NARRATIVE_PATTERN =
  '^[А-Яа-яЁё][ .,;:!?«»—–-]*[А-Яа-яЁё][ .,;:!?«»—–-]*[А-Яа-яЁё][А-Яа-яЁё .,;:!?«»—–-]*$';
const narrative = new RegExp(OPENAI_NARRATIVE_PATTERN, 'u');
export function openAiNarrative(value: string): boolean {
  // JS $ can match before a final newline; require the entire original string.
  return narrative.exec(value)?.[0] === value;
}

const string = () => ({ type: 'string' });
const objectSchema = (properties: Record<string, unknown>) => ({ type: 'object', properties,
  required: Object.keys(properties), additionalProperties: false });

// Fresh objects prevent callers from mutating the schema used by another request
// or by policy hashing. Both paths use this same complete response format.
export function openAiResponseFormat(operation: OpenAiOperation) {
  const citations = { type: 'array', items: string(), minItems: 1, maxItems: operation === 'summary' ? 2 : 3 };
  const fields = { scanId: string(), digest: string(), platform: string(), reportVersion: string() };
  const text = { type: 'string', pattern: OPENAI_NARRATIVE_PATTERN, maxLength: operation === 'summary' ? 320 : 600 };
  const properties = operation === 'summary' ? { ...fields, hypotheses: { type: 'array', minItems: 1, maxItems: 6,
    items: objectSchema({ text, citations }) } } : { ...fields, text, citations };
  return { type: 'json_schema', json_schema: { name: `scanner_${operation}`, strict: true, schema: objectSchema(properties) } };
}
