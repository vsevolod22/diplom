import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { LayerTarValidator, ARCHIVE_LIMITS as L } from './layer-tar-validator.js';
import { inflateLayer } from './bounded-image-archive.js';
function tar(path = 'etc/alpine-release', data: Buffer = Buffer.from('3.21.0'), type = '0', link = '') {
  const header = Buffer.alloc(512);
  header.write(path); header.write('0000644\0', 100); header.write('0000000\0', 108); header.write('0000000\0', 116);
  header.write(data.length.toString(8).padStart(11, '0') + '\0', 124); header.write('00000000000\0', 136);
  header.fill(32, 148, 156); header.write(type, 156); header.write(link, 157); header.write('ustar\0', 257); header.write('00', 263);
  header.write(header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0') + '\0 ', 148);
  return Buffer.concat([header, data, Buffer.alloc((512 - data.length % 512) % 512), Buffer.alloc(1024)]);
}
function validate(bytes: Buffer, budget = { bytes: 0, entries: 0, paxRecords: 0 }) {
  const validator = new LayerTarValidator(budget);
  for (let offset = 0; offset < bytes.length; offset += 37) validator.push(bytes.subarray(offset, offset + 37));
  return validator.finish();
}
test('incremental tar validates complete bytes and diffId including trailing padding', () => {
  const bytes = tar();
  assert.deepEqual(validate(bytes), { diffId: `sha256:${createHash('sha256').update(bytes).digest('hex')}`, bytes: bytes.length });
  assert.doesNotThrow(() => validate(tar('bin/sh', Buffer.alloc(0), '2', '/bin/busybox')));
  assert.doesNotThrow(() => validate(tar('usr/bin/sh', Buffer.alloc(0), '1', 'bin/busybox')));
});
test('tar rejects escaping/absolute entries, devices, hardlink escapes, checksums and truncated end', () => {
  for (const bytes of [tar('../escape'), tar('/escape'), tar('device', Buffer.alloc(0), '3'),
    tar('link', Buffer.alloc(0), '1', '../escape'), tar().subarray(0, 1536)]) assert.throws(() => validate(bytes));
  const broken = tar(); broken[0] ^= 1; assert.throws(() => validate(broken));
  assert.throws(() => validate(Buffer.concat([tar(), Buffer.from('X')])));
});
test('attempt-wide expanded and entry budgets enforce N and N+1', () => {
  const bytes = tar();
  assert.doesNotThrow(() => validate(bytes, { bytes: L.expandedTotal - bytes.length, entries: L.entries - 1, paxRecords: 0 }));
  assert.throws(() => validate(bytes, { bytes: L.expandedTotal - bytes.length + 1, entries: 0, paxRecords: 0 }));
  assert.throws(() => validate(bytes, { bytes: 0, entries: L.entries, paxRecords: 0 }));
});
test('streaming gzip verifies CRC, ISIZE, exact single member and diffId', async () => {
  const directory = await mkdtemp(`${tmpdir()}/dip-layer-`);
  try {
    const bytes = tar(), compressed = gzipSync(bytes);
    const inputs = [compressed, Buffer.concat([compressed, compressed]), Buffer.concat([compressed, Buffer.from('junk')]), compressed.subarray(0, compressed.length - 1)];
    const corrupt = Buffer.from(compressed); corrupt[corrupt.length - 8] ^= 1; inputs.push(corrupt);
    for (const [index, input] of inputs.entries()) {
      await writeFile(`${directory}/${index}.gz`, input);
      const run = inflateLayer(`${directory}/${index}.gz`, `${directory}/${index}.tar`, { bytes: 0, entries: 0, paxRecords: 0 });
      if (index === 0) assert.equal((await run).diffId, validate(bytes).diffId);
      else await assert.rejects(run);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});
function pax(key: string, value: string): Buffer {
  let length = key.length + Buffer.byteLength(value) + 4;
  while (Buffer.byteLength(`${length} ${key}=${value}\n`) !== length) length = Buffer.byteLength(`${length} ${key}=${value}\n`);
  return Buffer.from(`${length} ${key}=${value}\n`);
}
test('PAX effective paths, field/record caps and malformed extensions fail closed', () => {
  const layer = (value: Buffer) => Buffer.concat([tar('PaxHeader', value, 'x').subarray(0, -1024), tar('safe')]);
  assert.doesNotThrow(() => validate(layer(pax('path', 'a'.repeat(L.fieldBytes)))));
  assert.throws(() => validate(layer(pax('path', 'a'.repeat(L.fieldBytes + 1)))));
  for (const value of [pax('path', '../escape'), pax('GNU.sparse.map', '0,1'), pax('path', 'bad\0value'),
    Buffer.from('999 path=truncated\n'), Buffer.concat([pax('path', 'safe'), pax('path', 'duplicate')])]) assert.throws(() => validate(layer(value)));
  const value = layer(pax('mtime', '0'));
  assert.doesNotThrow(() => validate(value, { bytes: 0, entries: 0, paxRecords: L.paxRecords - 1 }));
  assert.throws(() => validate(value, { bytes: 0, entries: 0, paxRecords: L.paxRecords }));
  assert.throws(() => validate(layer(Buffer.alloc(L.extensionBytes + 1))));
});
