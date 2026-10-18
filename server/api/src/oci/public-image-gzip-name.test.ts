import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { gzipSync } from 'node:zlib';
import { inflateLayer, prepareBoundedImageArchive } from './bounded-image-archive.js';
import { ArchiveRejected } from './layer-tar-validator.js';
import { PUBLIC_IMAGE_LIMITS as L, PUBLIC_IMAGE_PROFILE, isPublicReceipt } from './public-image-policy.js';
import { fixture, sha, tar } from './public-image.test-fixtures.js';

function namedGzip(bytes: Buffer, name: Buffer = Buffer.from('synthetic-layer.tar')) {
  const compressed = gzipSync(bytes);
  const header = Buffer.from(compressed.subarray(0, 10)); header[3] = 8;
  return Buffer.concat([header, name, Buffer.from([0]), compressed.subarray(10)]);
}
async function scratch(run: (root: string) => Promise<void>) {
  const root = await mkdtemp(`${tmpdir()}/dip-public-gzip-name-`);
  try { await run(root); } finally { await rm(root, { recursive: true, force: true }); }
}

test('public single-member gzip FNAME preserves the entire validated tar and diffID', async () => {
  await scratch(async root => {
    const bytes = tar();
    await writeFile(`${root}/layer.gz`, namedGzip(bytes));
    const checked = await inflateLayer(`${root}/layer.gz`, `${root}/layer.tar`, { bytes: 0, entries: 0, paxRecords: 0 },
      undefined, PUBLIC_IMAGE_PROFILE);
    assert.deepEqual(checked, { diffId: sha(bytes), bytes: bytes.length });
    assert.equal(sha(await readFile(`${root}/layer.tar`)), sha(bytes));
  });
});

test('public gzip FNAME is metadata only: empty and bounded N-byte names are not interpreted as paths or text', async () => {
  await scratch(async root => {
    const bytes = tar();
    const names = [Buffer.alloc(0), Buffer.alloc(L.fieldBytes, 0xff), Buffer.from('../not-an-output-path')];
    for (const [index, name] of names.entries()) {
      await writeFile(`${root}/${index}.gz`, namedGzip(bytes, name));
      assert.equal((await inflateLayer(`${root}/${index}.gz`, `${root}/${index}.tar`,
        { bytes: 0, entries: 0, paxRecords: 0 }, undefined, PUBLIC_IMAGE_PROFILE)).diffId, sha(bytes));
    }
  });
});

test('gzip FNAME N+1, missing terminator and absent deflate bytes reject without unbounded scanning', async () => {
  await scratch(async root => {
    const bytes = tar(), valid = namedGzip(bytes);
    const missing = Buffer.concat([valid.subarray(0, 10), Buffer.alloc(L.fieldBytes + 1, 65), valid.subarray(-8)]);
    const emptyBody = Buffer.concat([valid.subarray(0, 10), Buffer.from([0]), valid.subarray(-8)]);
    for (const [index, input] of [namedGzip(bytes, Buffer.alloc(L.fieldBytes + 1, 65)), missing, emptyBody].entries()) {
      await writeFile(`${root}/${index}.gz`, input);
      await assert.rejects(inflateLayer(`${root}/${index}.gz`, `${root}/${index}.tar`,
        { bytes: 0, entries: 0, paxRecords: 0 }, undefined, PUBLIC_IMAGE_PROFILE),
        (error: unknown) => error instanceof ArchiveRejected && error.reason === (index === 2 ? 'GZIP_HEADER' : 'GZIP_NAME') &&
          error.message === 'Image archive rejected');
    }
  });
});

test('legacy fixed gzip header remains unchanged; other optional/reserved flags remain rejected publicly', async () => {
  await scratch(async root => {
    const bytes = tar(), input = namedGzip(bytes);
    await writeFile(`${root}/legacy.gz`, input);
    await assert.rejects(inflateLayer(`${root}/legacy.gz`, `${root}/legacy.tar`, { bytes: 0, entries: 0, paxRecords: 0 }),
      (error: unknown) => error instanceof ArchiveRejected && error.reason === 'GZIP_HEADER');
    for (const flags of [1, 2, 4, 16, 32, 64, 128, 9, 10, 12, 24]) {
      const bad = Buffer.from(input); bad[3] = flags;
      await writeFile(`${root}/${flags}.gz`, bad);
      await assert.rejects(inflateLayer(`${root}/${flags}.gz`, `${root}/${flags}.tar`,
        { bytes: 0, entries: 0, paxRecords: 0 }, undefined, PUBLIC_IMAGE_PROFILE),
        (error: unknown) => error instanceof ArchiveRejected && error.reason === 'GZIP_HEADER');
    }
  });
});

test('public named gzip still rejects concatenation, trailing bytes, CRC/ISIZE corruption and malformed tar', async () => {
  await scratch(async root => {
    const bytes = tar(), valid = namedGzip(bytes);
    const crc = Buffer.from(valid); crc[crc.length - 8] ^= 1;
    const size = Buffer.from(valid); size[size.length - 4] ^= 1;
    const brokenTar = Buffer.from(bytes); brokenTar[0] ^= 1;
    const inputs = [Buffer.concat([valid, valid]), Buffer.concat([valid, Buffer.from('junk')]), crc, size,
      valid.subarray(0, -1), namedGzip(brokenTar)];
    for (const [index, input] of inputs.entries()) {
      await writeFile(`${root}/${index}.gz`, input);
      await assert.rejects(inflateLayer(`${root}/${index}.gz`, `${root}/${index}.tar`,
        { bytes: 0, entries: 0, paxRecords: 0 }, undefined, PUBLIC_IMAGE_PROFILE), (error: unknown) =>
        index !== 2 && index !== 3 || error instanceof ArchiveRejected && error.reason === 'GZIP_INTEGRITY');
    }
  });
});

test('public acquisition includes all named-gzip bytes in compressed identity and keeps receipt/cleanup invariants', async () => {
  await scratch(async root => {
    const bytes = tar();
    const source = fixture({ bytes, compressed: namedGzip(bytes) });
    const prepared = await prepareBoundedImageArchive(undefined, source.target, PUBLIC_IMAGE_PROFILE, source.request, root);
    try {
      assert.equal(isPublicReceipt(prepared.receipt), true);
      assert.deepEqual(prepared.receipt.layerDigests, [sha(source.compressed)]);
      assert.deepEqual(prepared.receipt.diffIds, [sha(bytes)]);
      assert.equal(prepared.metrics.compressedBytes, source.compressed.length);
      assert.equal(prepared.metrics.expandedBytes, bytes.length);
    } finally { await prepared.cleanup(); }
    assert.deepEqual(await readdir(root), []);
    const invalid = fixture({ bytes, compressed: namedGzip(bytes, Buffer.alloc(L.fieldBytes + 1, 65)) });
    await assert.rejects(prepareBoundedImageArchive(undefined, invalid.target, PUBLIC_IMAGE_PROFILE, invalid.request, root),
      (error: unknown) => error instanceof ArchiveRejected && error.reason === 'GZIP_NAME' && error.message === 'Image archive rejected');
    assert.deepEqual(await readdir(root), []);
  });
});
