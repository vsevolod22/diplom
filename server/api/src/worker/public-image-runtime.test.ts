import assert from 'node:assert/strict';
import test from 'node:test';
import { publicResourceEnvelope } from './worker-runtime.js';

// Stubbed kernel evidence only; this is not a live container/cgroup qualification.
const kernel = { 'memory.max': '4294967296', 'memory.swap.max': '0', 'cpu.max': '100000 100000', 'pids.max': '128' };
function envelope(values: Record<string, string> = kernel, bytes = 2304 * 1024 ** 2, type = 0x01021994, link = false) {
  const scratch = () => ({ info: { isDirectory: () => true, isSymbolicLink: () => link },
    fs: { type, blocks: bytes / 4096, bsize: 4096 } });
  return publicResourceEnvelope(name => values[name], scratch as unknown as NonNullable<Parameters<typeof publicResourceEnvelope>[1]>);
}
test('public resource composition requires explicit finite memory/CPU/PID and physical tmpfs bounds', () => {
  assert.equal(envelope(), true);
  for (const [key, value] of [['memory.max', 'max'], ['memory.max', '1073741824'], ['memory.swap.max', 'max'],
    ['cpu.max', 'max 100000'], ['pids.max', 'max']]) assert.equal(envelope({ ...kernel, [key]: value }), false);
  assert.equal(envelope(kernel, 2048 * 1024 ** 2), false);
  assert.equal(envelope(kernel, 4096 * 1024 ** 2), false);
  assert.equal(envelope(kernel, 2304 * 1024 ** 2, 123), false);
  assert.equal(envelope(kernel, 2304 * 1024 ** 2, 0x01021994, true), false);
});
