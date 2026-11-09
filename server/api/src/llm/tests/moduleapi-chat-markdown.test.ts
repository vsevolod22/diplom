import assert from 'node:assert/strict';
import test from 'node:test';
import { MODULEAPI_MODEL, MODULEAPI_PROMPTS, createModuleApiPolicy } from '../moduleapi-policy.js';
import { moduleApiChatNarrative, moduleApiResponseFormat } from '../moduleapi-chat-format.js';
import { openAiResponseFormat } from '../openai-response-contract.js';
import { OPENAI_PROMPTS } from '../openai-prompts.js';
import { prepareModuleApiChat, validateModuleApiPreparedReply } from '../moduleapi-prepared-request.js';
import { openAiSettings, openAiHistory, openAiReply } from './openai-core.fixture.js';

function prepared() {
  const policy = createModuleApiPolicy({ ...openAiSettings, model: MODULEAPI_MODEL, retention: 'unknown',
    monetaryLimit: 'capped' }, MODULEAPI_PROMPTS);
  assert.ok(policy);
  return { policy, request: prepareModuleApiChat(openAiHistory, policy) };
}
test('ModuleAPI chat emits and accepts Russian Markdown without changing summary/OpenAI contracts', () => {
  const { policy, request } = prepared();
  const wire = JSON.parse(request.body);
  assert.equal(wire.messages[0].content, MODULEAPI_PROMPTS.chat);
  assert.notEqual(MODULEAPI_PROMPTS.chat, OPENAI_PROMPTS.chat);
  assert.equal(MODULEAPI_PROMPTS.summary, OPENAI_PROMPTS.summary);
  assert.deepEqual(moduleApiResponseFormat('summary'), openAiResponseFormat('summary'));
  assert.deepEqual(wire.response_format, moduleApiResponseFormat('chat'));
  const text = '## Главное\n\n**Проверьте находку.**\n\n- Уточните контекст.\n- Исправьте причину и повторите проверку.';
  const result = validateModuleApiPreparedReply(request, policy, openAiReply('chat', text));
  assert.equal(result.operation, 'chat');
  assert.ok('text' in result.value);
  assert.equal(result.value.text, text);
  assert.equal(wire.stream, false);
});
test('Markdown layout never bypasses technical alphabet, safety, source or length bounds', () => {
  for (const text of ['##', 'аб', 'Hello', 'Сканер: node', 'Находка 123', '[ссылка](https://example.test)',
    '<script>опасно</script>', '```sh\ncurl example.test\n```', 'Секрет sk-testlongkey', 'Ответ\rподмена']) {
    assert.equal(moduleApiChatNarrative(text), false);
  }
  const { policy, request } = prepared();
  for (const value of [openAiReply('chat', 'я'.repeat(601)),
    { ...openAiReply('chat', '## Проверка\n\nПодтвердите находку.'), citations: ['foreign'] },
    { ...openAiReply('chat', '## Проверка\n\nПодтвердите находку.'), reportVersion: 'f'.repeat(64) },
    openAiReply('chat', '## Проверка\n\nЗапустите curl.')]) {
    assert.throws(() => validateModuleApiPreparedReply(request, policy, value));
  }
});
test('ModuleAPI policy hash covers the Markdown schema and independent chat prompt', () => {
  const { policy } = prepared();
  const legacy = createModuleApiPolicy({ ...openAiSettings, model: MODULEAPI_MODEL, retention: 'unknown',
    monetaryLimit: 'capped' }, { ...MODULEAPI_PROMPTS, chat: OPENAI_PROMPTS.chat });
  assert.ok(legacy);
  assert.notEqual(policy.version, legacy.version);
});
