import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseRuntimeJson } from './runtime-json.js';

test('raw runtime intake preserves duplicate and integer lexical fences', () => {
  assert.deepEqual(parseRuntimeJson(Buffer.from('{"n":1}')), { n: 1 });
  for (const text of [
    '{"n":1,"n":2}',
    '{"n":1.0}',
    '{"n":1e0}',
    '{"n":9007199254740992}',
    '{"__proto__":1}',
  ]) {
    assert.throws(() => parseRuntimeJson(Buffer.from(text)), /INVALID_RUNTIME_INPUT/);
  }
  assert.throws(() => parseRuntimeJson(Buffer.from([0xff])), /INVALID_RUNTIME_INPUT/);
  assert.throws(() => parseRuntimeJson(Buffer.alloc(65537, 32)), /INVALID_RUNTIME_INPUT/);
});
