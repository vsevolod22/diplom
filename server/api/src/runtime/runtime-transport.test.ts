import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RuntimeTransport, parseCapabilities } from '../../../../src/shared/api/scans/runtimeTransport.js';

const capabilities = {
  schemaVersion: 'runtime-capabilities-v1',
  historicalImport: true,
  liveCapture: false,
  liveReason: 'QUALIFICATION_MISSING',
  host: 'not_authorized',
  rawIntake: 'parent-bootstrap-required',
};

test('dedicated browser transport preserves raw signed-package lexemes, bounded bytes and account generation fences', async () => {
  const original = globalThis.fetch;
  let current = true;
  let calls = 0;
  try {
    const api = new RuntimeTransport('owner', () => current);
    globalThis.fetch = async (_url, init) => {
      calls++;
      assert.equal(init?.credentials, 'same-origin');
      assert.equal(init?.cache, 'no-store');
      assert.match(String(init?.body), /"n":1\.0,"n":2/);
      return new Response(JSON.stringify({ captureId: 'a'.repeat(32), created: true }));
    };
    const result = await api.submitImport('b'.repeat(32), '{"n":1.0,"n":2}');
    assert.equal(result.captureId, 'a'.repeat(32));
    assert.equal(calls, 1);
    await assert.rejects(api.submitImport('b'.repeat(32), ' '.repeat(65536)), /INVALID_RUNTIME_INPUT/);
    assert.equal(calls, 1);
    globalThis.fetch = async () => {
      calls++;
      current = false;
      return new Response(JSON.stringify(capabilities));
    };
    await assert.rejects(api.capabilities(), /RUNTIME_ACCESS_CHANGED/);
    await assert.rejects(api.capabilities(), /RUNTIME_ACCESS_CHANGED/);
    assert.equal(calls, 2);
    current = true;
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify(capabilities).replace(
          '"historicalImport":true',
          '"historicalImport":true,"historicalImport":true',
        ),
      );
    await assert.rejects(api.capabilities(), /INVALID_RUNTIME_INPUT/);
    globalThis.fetch = async () => new Response(' '.repeat(65537));
    await assert.rejects(api.capabilities(), /INVALID_RUNTIME_INPUT/);
    assert.throws(() => parseCapabilities({ ...capabilities, liveCapture: true }), /INVALID_RUNTIME_INPUT/);
    assert.throws(
      () => parseCapabilities({ ...capabilities, host: 'linux-host-scanned' }),
      /INVALID_RUNTIME_INPUT/,
    );
  } finally {
    globalThis.fetch = original;
  }
});
