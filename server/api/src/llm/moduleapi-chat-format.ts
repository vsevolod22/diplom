import { openAiResponseFormat, type OpenAiOperation } from './openai-response-contract.js';

// Markdown layout is permitted, not a new channel for ungrounded identifiers,
// numbers, URLs or commands. Exact technical facts stay in verified source cards.
export const MODULEAPI_CHAT_PATTERN = '^[А-Яа-яЁё .,;:!?«»—–#*_`\\n-]+$';
const markdownNarrative = new RegExp(MODULEAPI_CHAT_PATTERN, 'u');
export function moduleApiChatNarrative(value: string): boolean {
  return markdownNarrative.exec(value)?.[0] === value && (value.match(/[А-Яа-яЁё]/gu)?.length ?? 0) >= 3;
}
export function moduleApiResponseFormat(operation: OpenAiOperation) {
  const format = openAiResponseFormat(operation);
  if (operation === 'summary') return format;
  return { ...format, json_schema: { ...format.json_schema, schema: {
    ...format.json_schema.schema,
    properties: { ...format.json_schema.schema.properties,
      text: { type: 'string', pattern: MODULEAPI_CHAT_PATTERN, maxLength: 600 },
    },
  } } };
}
