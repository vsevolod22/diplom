import assert from 'node:assert/strict';
import { mkdtemp, open, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { gzipSync } from 'node:zlib';
import { inflateLayer } from './bounded-image-archive.js';
import { LayerTarValidator, ArchiveRejected, type TarBudget } from './layer-tar-validator.js';
import { PUBLIC_IMAGE_PROFILE, PUBLIC_IMAGE_LIMITS as L } from './public-image-policy.js';
import { tar, tarHeader, sha } from './public-image.test-fixtures.js';

function validate(bytes: Buffer, budget: TarBudget = { bytes: 0, entries: 0, paxRecords: 0 }) {
  const validator = new LayerTarValidator(budget, PUBLIC_IMAGE_PROFILE);
  for (let offset = 0; offset < bytes.length; offset += 37) validator.push(bytes.subarray(offset, offset + 37));
  return validator.finish();
}
function pax(key: string, value: string) {
  let length = Buffer.byteLength(key + value) + 4;
  while (Buffer.byteLength(`${length} ${key}=${value}\n`) !== length) length = Buffer.byteLength(`${length} ${key}=${value}\n`);
  return Buffer.from(`${length} ${key}=${value}\n`);
}

test('public validator streams tar/diffIDs, enforces expanded total and entries N/N+1 across layers', () => {
  const bytes = tar();
  assert.deepEqual(validate(bytes), { diffId: sha(bytes), bytes: bytes.length });
  const budget = { bytes: L.expandedTotal - bytes.length, entries: L.entries - 1, paxRecords: 0 };
  validate(bytes, budget);
  assert.equal(budget.bytes, L.expandedTotal); assert.equal(budget.entries, L.entries);
  assert.throws(() => validate(bytes, budget), ArchiveRejected);
  assert.throws(() => validate(bytes, { bytes: L.expandedTotal - bytes.length + 1, entries: 0, paxRecords: 0 }), ArchiveRejected);
  assert.throws(() => validate(bytes, { bytes: 0, entries: L.entries, paxRecords: 0 }), ArchiveRejected);
  for (const bytes of [tar('../escape'), tar('/escape'), tar('device', Buffer.alloc(0), '3'),
    tar('link', Buffer.alloc(0), '1', '../escape'), tar().subarray(0, -512), Buffer.concat([tar(), Buffer.from('X')])]) {
    assert.throws(() => validate(bytes), ArchiveRejected);
  }
  assert.doesNotThrow(() => validate(tar('bin/sh', Buffer.alloc(0), '2', '/bin/busybox')));
});

test('expanded-layer N/N+1 is bounded-memory even for 512 MiB of trailing zero padding', () => {
  const validator = new LayerTarValidator({ bytes: 0, entries: 0, paxRecords: 0 }, PUBLIC_IMAGE_PROFILE);
  // Reuse a single 64 KiB buffer, never allocate the expanded layer in memory.
  const chunk = Buffer.alloc(64 * 1024);
  for (let size = 0; size < L.expandedLayer; size += chunk.length) validator.push(chunk);
  assert.equal(validator.finish().bytes, L.expandedLayer);
  const over = new LayerTarValidator({ bytes: 0, entries: 0, paxRecords: 0 }, PUBLIC_IMAGE_PROFILE);
  for (let size = 0; size < L.expandedLayer; size += chunk.length) over.push(chunk);
  assert.throws(() => over.push(Buffer.alloc(1)), ArchiveRejected);
  assert.throws(() => over.finish(), ArchiveRejected);
  assert.throws(() => over.push(Buffer.alloc(0)), ArchiveRejected);
});

test('file, extension, field and PAX aggregate caps retain fail-closed framing and legacy defaults', () => {
  const publicValidator = new LayerTarValidator({ bytes: 0, entries: 0, paxRecords: 0 }, PUBLIC_IMAGE_PROFILE);
  assert.doesNotThrow(() => publicValidator.push(tarHeader('large', L.fileBytes)));
  const over = new LayerTarValidator({ bytes: 0, entries: 0, paxRecords: 0 }, PUBLIC_IMAGE_PROFILE);
  assert.throws(() => over.push(tarHeader('large', L.fileBytes + 1)), ArchiveRejected);
  const legacy = new LayerTarValidator({ bytes: 0, entries: 0, paxRecords: 0 });
  assert.throws(() => legacy.push(tarHeader('large', L.fileBytes)), ArchiveRejected);
  const extension = (data: Buffer) => Buffer.concat([tar('PaxHeader', data, 'x').subarray(0, -1024), tar('safe')]);
  assert.doesNotThrow(() => validate(extension(pax('path', 'a'.repeat(L.fieldBytes)))));
  for (const data of [pax('path', 'a'.repeat(L.fieldBytes + 1)), pax('path', '../escape'), pax('GNU.sparse.map', '0,1'),
    pax('path', 'bad\0value'), Buffer.alloc(L.extensionBytes + 1)]) {
    assert.throws(() => validate(extension(data)), ArchiveRejected);
  }
  const bytes = extension(pax('mtime', '0'));
  assert.doesNotThrow(() => validate(bytes, { bytes: 0, entries: 0, paxRecords: L.paxRecords - 1 }));
  assert.throws(() => validate(bytes, { bytes: 0, entries: 0, paxRecords: L.paxRecords }), ArchiveRejected);
});

test('public inflation enforces fixed-header single gzip member/CRC/ISIZE, cancellation and aggregate before writing', async () => {
  const root = await mkdtemp(`${tmpdir()}/dip-public-inflate-`);
  try {
    const bytes = tar(), compressed = gzipSync(bytes);
    const crc = Buffer.from(compressed); crc[crc.length - 8] ^= 1;
    const size = Buffer.from(compressed); size[size.length - 4] ^= 1;
    const optional = Buffer.from(compressed); optional[3] = 8;
    const invalidTar = tar(); invalidTar[0] ^= 1;
    const inputs = [compressed, Buffer.concat([compressed, compressed]), Buffer.concat([compressed, Buffer.from('junk')]),
      compressed.subarray(0, -1), crc, size, optional, gzipSync(invalidTar)];
    for (const [index, input] of inputs.entries()) {
      await writeFile(`${root}/${index}.gz`, input);
      const run = inflateLayer(`${root}/${index}.gz`, `${root}/${index}.tar`, { bytes: 0, entries: 0, paxRecords: 0 }, undefined, PUBLIC_IMAGE_PROFILE);
      if (index === 0) assert.deepEqual(await run, { diffId: sha(bytes), bytes: bytes.length });
      else await assert.rejects(run);
    }
    await assert.rejects(inflateLayer(`${root}/0.gz`, `${root}/aggregate.tar`,
      { bytes: L.expandedTotal - bytes.length + 1, entries: 0, paxRecords: 0 }, undefined, PUBLIC_IMAGE_PROFILE), ArchiveRejected);
    assert.equal((await stat(`${root}/aggregate.tar`)).size, 0);
    const signal = AbortSignal.abort();
    await assert.rejects(inflateLayer(`${root}/0.gz`, `${root}/abort.tar`, { bytes: 0, entries: 0, paxRecords: 0 }, signal, PUBLIC_IMAGE_PROFILE));
    await assert.rejects(stat(`${root}/abort.tar`), { code: 'ENOENT' });
    const large = await open(`${root}/oversized.gz`, 'wx');
    try { await large.truncate(L.compressedLayer + 1); } finally { await large.close(); }
    await assert.rejects(inflateLayer(`${root}/oversized.gz`, `${root}/oversized.tar`,
      { bytes: 0, entries: 0, paxRecords: 0 }, undefined, PUBLIC_IMAGE_PROFILE), ArchiveRejected);
    assert.equal((await stat(`${root}/oversized.tar`)).size, 0);
  } finally { await rm(root, { recursive: true, force: true }); }
});
