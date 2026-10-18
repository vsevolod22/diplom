import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { gzipSync } from 'node:zlib';
import { inflateLayer } from './bounded-image-archive.js';
import { ArchiveRejected, LayerTarValidator, type ArchiveResourceProfile } from './layer-tar-validator.js';
import { PUBLIC_IMAGE_PROFILE } from './public-image-policy.js';
import { sha, tar } from './public-image.test-fixtures.js';

function pax(key: string, value: string): Buffer {
  let length = Buffer.byteLength(`${key}=${value}\n`) + 2;
  while (Buffer.byteLength(`${length} ${key}=${value}\n`) !== length) length = Buffer.byteLength(`${length} ${key}=${value}\n`);
  return Buffer.from(`${length} ${key}=${value}\n`);
}
function checksum(bytes: Buffer): Buffer {
  bytes.fill(32, 148, 156);
  const sum = bytes.subarray(0, 512).reduce((total, byte) => total + byte, 0);
  bytes.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return bytes;
}
function format(bytes: Buffer, gnu: boolean): Buffer {
  const result = Buffer.from(bytes);
  result.write(gnu ? 'ustar  \0' : 'ustar\0' + '00', 257, 'ascii');
  return checksum(result);
}
const extension = (type: string, payload: Buffer) => tar('Extension', payload, type).subarray(0, -1024);
function mixed(field: 'path' | 'linkpath', gnuValue: string, paxValue: string, gnuFirst: boolean, type = '1') {
  const gnu = extension(field === 'path' ? 'L' : 'K', Buffer.from(`${gnuValue}\0`));
  const posix = extension('x', pax(field, paxValue));
  return Buffer.concat([...(gnuFirst ? [gnu, posix] : [posix, gnu]), tar('entry', Buffer.alloc(0), type, 'safe/header-link')]);
}
function validate(bytes: Buffer, profile: ArchiveResourceProfile, chunkSize = 37) {
  const validator = new LayerTarValidator({ bytes: 0, entries: 0, paxRecords: 0 }, profile);
  for (let offset = 0; offset < bytes.length; offset += chunkSize) validator.push(bytes.subarray(offset, offset + chunkSize));
  return validator.finish();
}
function malformedMagic(gnu: boolean, offset: number) {
  const bytes = format(tar(), gnu);
  bytes[offset] |= 0x80;
  return checksum(bytes); // A valid checksum must not hide invalid format bytes.
}
function malformedPax(digit: number) {
  const payload = pax('path', 'safe/path');
  payload[digit] |= 0x80;
  return Buffer.concat([extension('x', payload), tar('entry')]);
}

for (const profile of ['legacy', PUBLIC_IMAGE_PROFILE] as const) {
  test(`${profile}: R1 rejects mixed PAX/GNU link overrides in both orders for hardlinks and symlinks`, () => {
    for (const type of ['1', '2']) {
      for (const gnuFirst of [false, true]) {
        // Reject even equal values: competing extension families are unsupported,
        // not a precedence rule inferred from one particular downstream reader.
        for (const gnuValue of ['../escape', '/absolute', 'safe/other-link', 'safe/pax-link']) {
          const bytes = mixed('linkpath', gnuValue, 'safe/pax-link', gnuFirst, type);
          for (const chunk of [1, 37, 512]) assert.throws(() => validate(bytes, profile, chunk), ArchiveRejected,
            `type=${type} gnuFirst=${gnuFirst} gnuValue=${gnuValue} chunk=${chunk}`);
        }
      }
    }
  });

  test(`${profile}: R1 rejects competing PAX/GNU path overrides, including equal safe values`, () => {
    for (const gnuFirst of [false, true]) {
      for (const gnuPath of ['safe/gnu-path', 'safe/pax-path']) {
        assert.throws(() => validate(mixed('path', gnuPath, 'safe/pax-path', gnuFirst, '0'), profile), ArchiveRejected);
      }
    }
  });

  test(`${profile}: R2 rejects high-bit bytes at every USTAR/GNU magic and version position`, () => {
    for (const gnu of [false, true]) {
      for (let offset = 257; offset < 265; offset++) {
        const bytes = malformedMagic(gnu, offset);
        for (const chunk of [1, 37, 512]) assert.throws(() => validate(bytes, profile, chunk), ArchiveRejected,
          `gnu=${gnu} offset=${offset} chunk=${chunk}`);
      }
    }
  });

  test(`${profile}: R2 requires raw ASCII decimal PAX length digits, not high-bit aliases`, () => {
    const digits = pax('path', 'safe/path').indexOf(32);
    for (let digit = 0; digit < digits; digit++) {
      for (const chunk of [1, 37, 512]) assert.throws(() => validate(malformedPax(digit), profile, chunk), ArchiveRejected);
    }
    for (const prefix of ['0', '+1', '-1', '1.0', '\t1']) {
      const payload = Buffer.from(`${prefix} path=safe/path\n`);
      assert.throws(() => validate(Buffer.concat([extension('x', payload), tar('entry')]), profile), ArchiveRejected);
    }
  });

  test(`${profile}: exact USTAR/GNU and standalone PAX/GNU overrides remain valid`, () => {
    const examples = [format(tar(), false), format(tar(), true),
      Buffer.concat([extension('x', pax('path', 'safe/pax-path')), tar('placeholder')]),
      Buffer.concat([extension('L', Buffer.from('safe/gnu-path\0')), tar('placeholder')]),
      Buffer.concat([extension('g', pax('mtime', '0')), tar('ordinary')]),
    ];
    for (const type of ['1', '2']) {
      examples.push(
        Buffer.concat([extension('x', pax('linkpath', 'safe/pax-link')), tar('link', Buffer.alloc(0), type, 'safe/header-link')]),
        Buffer.concat([extension('K', Buffer.from('safe/gnu-link\0')), tar('link', Buffer.alloc(0), type, 'safe/header-link')]),
        // Different semantic fields can use different extension families safely.
        Buffer.concat([extension('L', Buffer.from('safe/gnu-path\0')), extension('x', pax('linkpath', 'safe/pax-link')),
          tar('link', Buffer.alloc(0), type, 'safe/header-link')]),
        Buffer.concat([extension('K', Buffer.from('safe/gnu-link\0')), extension('x', pax('path', 'safe/pax-path')),
          tar('link', Buffer.alloc(0), type, 'safe/header-link')]),
      );
    }
    examples.push(Buffer.concat([extension('K', Buffer.from('../image-symlink\0')), tar('link', Buffer.alloc(0), '2', 'safe/header-link')]));
    for (const bytes of examples) {
      for (const chunk of [1, 37, 512]) assert.deepEqual(validate(bytes, profile, chunk), { diffId: sha(bytes), bytes: bytes.length });
    }
    assert.throws(() => validate(Buffer.concat([extension('K', Buffer.from('../escape\0')),
      tar('link', Buffer.alloc(0), '1', 'safe/header-link')]), profile), ArchiveRejected);
  });

  test(`${profile}: gzip inflation cannot return a diffID for mixed overrides or malformed raw encodings`, async () => {
    const directory = await mkdtemp(`${tmpdir()}/dip-public-tar-review-`);
    try {
      const invalid = [mixed('linkpath', '../escape', 'safe/link', true),
        mixed('linkpath', '/absolute', 'safe/link', false), malformedMagic(false, 257), malformedMagic(true, 264), malformedPax(0)];
      for (const [index, bytes] of invalid.entries()) {
        await writeFile(`${directory}/${index}.gz`, gzipSync(bytes));
        await assert.rejects(inflateLayer(`${directory}/${index}.gz`, `${directory}/${index}.tar`,
          { bytes: 0, entries: 0, paxRecords: 0 }, undefined, profile), ArchiveRejected);
      }
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
}
