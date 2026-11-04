import { constants as fsConstants } from 'node:fs';
import { open } from 'node:fs/promises';
import { Transform, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { constants, createZstdDecompress } from 'node:zlib';
import { ArchiveRejected, LayerTarValidator, type TarBudget } from './layer-tar-validator.js';
import { PUBLIC_IMAGE_LIMITS as L, PUBLIC_IMAGE_PROFILE } from './public-image-policy.js';
import { imageFailureDetail, type ImageFailureDetail } from './image-failure.js';

const ZSTD_WINDOW = 128 * 1024 ** 2;
const reject = (detail: ImageFailureDetail = { reason: 'IMAGE_INVALID', stage: 'decode' }): never => {
  throw new ArchiveRejected(undefined, detail);
};

// One ordinary frame only. The native decoder verifies compressed blocks, content
// size and checksum; this bounded parser additionally rejects concatenation/skips.
class ZstdFrame {
  private header = Buffer.alloc(0);
  private needed = 5;
  private state: 'header' | 'block' | 'payload' | 'checksum' | 'done' = 'header';
  private remaining = 0;
  private last = false;
  private checksum = false;
  private blocks = 0;
  private blockMaximum = 128 * 1024;
  push(bytes: Buffer): void {
    let offset = 0;
    while (offset < bytes.length) {
      if (this.state === 'done') reject();
      if (this.state === 'payload' || this.state === 'checksum') {
        const length = Math.min(this.remaining, bytes.length - offset);
        this.remaining -= length; offset += length;
        if (!this.remaining) {
          if (this.state === 'checksum') this.state = 'done';
          else this.afterBlock();
        }
        continue;
      }
      const length = Math.min(this.needed - this.header.length, bytes.length - offset);
      this.header = Buffer.concat([this.header, bytes.subarray(offset, offset + length)]);
      offset += length;
      if (this.header.length !== this.needed) continue;
      if (this.state === 'header') {
        if (this.needed === 5) {
          if (this.header.readUInt32LE(0) !== 0xfd2fb528) reject();
          const descriptor = this.header[4];
          if (descriptor & 0x18) reject(); // Reserved/unused bits must be zero.
          if (descriptor & 3) reject({ reason: 'FORMAT_UNSUPPORTED', stage: 'decode' });
          const single = !!(descriptor & 0x20), flag = descriptor >>> 6;
          this.needed = 5 + (single ? 0 : 1) + (flag === 0 ? single ? 1 : 0 : 2 ** flag);
          if (this.header.length < this.needed) continue;
        }
        this.frameHeader();
        this.state = 'block'; this.needed = 3; this.header = Buffer.alloc(0);
      } else {
        if (++this.blocks > 100_000) reject({ reason: 'FORMAT_UNSUPPORTED', stage: 'decode' });
        const value = this.header.readUIntLE(0, 3), type = (value >>> 1) & 3, size = value >>> 3;
        if (type === 3 || size > this.blockMaximum) reject();
        this.last = !!(value & 1); this.remaining = type === 1 ? 1 : size;
        this.header = Buffer.alloc(0); this.state = 'payload';
        if (!this.remaining) this.afterBlock();
      }
    }
  }
  private frameHeader(): void {
    const descriptor = this.header[4], single = !!(descriptor & 0x20), flag = descriptor >>> 6;
    this.checksum = !!(descriptor & 4);
    const start = single ? 5 : 6, length = flag === 0 ? single ? 1 : 0 : 2 ** flag;
    const contentSize = length === 8 ? this.header.readBigUInt64LE(start) :
      length ? BigInt(this.header.readUIntLE(start, length) + (length === 2 ? 256 : 0)) : undefined;
    if (contentSize !== undefined && contentSize > BigInt(L.expandedLayer))
      reject({ reason: 'RESOURCE_LIMIT', stage: 'decode', resource: 'expanded_bytes' });
    const wd = this.header[5], base = 2 ** (10 + (wd >>> 3));
    const window = single ? Number(contentSize) : base + (base / 8) * (wd & 7);
    if (!Number.isSafeInteger(window) || window > ZSTD_WINDOW)
      reject({ reason: 'FORMAT_UNSUPPORTED', stage: 'decode' });
    this.blockMaximum = Math.min(window, 128 * 1024);
  }
  private afterBlock(): void {
    if (!this.last) { this.state = 'block'; this.needed = 3; }
    else if (this.checksum) { this.state = 'checksum'; this.remaining = 4; }
    else this.state = 'done';
  }
  finish(): void { if (this.state !== 'done') reject(); }
}

export async function decodePublicLayer(path: string, output: string, budget: TarBudget,
  encoding: 'raw' | 'zstd', signal?: AbortSignal) {
  signal?.throwIfAborted();
  const source = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  let destination: Awaited<ReturnType<typeof open>> | undefined;
  try {
    const info = await source.stat();
    if (!info.isFile() || info.size <= 0) reject();
    if (info.size > L.compressedLayer) reject({ reason: 'RESOURCE_LIMIT', stage: 'decode', resource: 'layer_bytes' });
    destination = await open(output, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    const validator = new LayerTarValidator(budget, PUBLIC_IMAGE_PROFILE);
    const sink = new Writable({ write(chunk: Buffer, _encoding, callback) {
      try {
        validator.push(chunk);
        void destination!.writeFile(chunk).then(() => callback(), () => callback(new ArchiveRejected()));
      } catch (error) { callback(error instanceof Error ? error : new ArchiveRejected()); }
    } });
    const input = source.createReadStream({ autoClose: false });
    if (encoding === 'raw') await pipeline(input, sink, { signal });
    else {
      const frame = new ZstdFrame();
      const framing = new Transform({ transform(chunk: Buffer, _encoding, callback) {
        try { frame.push(chunk); callback(null, chunk); }
        catch (error) { callback(error instanceof Error ? error : new ArchiveRejected()); }
      }, flush(callback) {
        try { frame.finish(); callback(); }
        catch (error) { callback(error instanceof Error ? error : new ArchiveRejected()); }
      } });
      // Independent native limit prevents allocation beyond the parser's window bound.
      const decoder = createZstdDecompress({ params: { [constants.ZSTD_d_windowLogMax]: 27 } });
      await pipeline(input, framing, decoder, sink, { signal });
      if (decoder.bytesWritten !== info.size) reject();
    }
    return validator.finish();
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new ArchiveRejected(undefined, imageFailureDetail(error));
  } finally { await source.close(); await destination?.close(); }
}
