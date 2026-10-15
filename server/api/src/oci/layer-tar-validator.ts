import { createHash } from 'node:crypto';

export const ARCHIVE_LIMITS = Object.freeze({ maxLayers: 32, compressedLayer: 32 * 1024 ** 2,
  compressedTotal: 96 * 1024 ** 2, wireBytes: 112 * 1024 ** 2, requests: 160, deadlineMs: 180_000,
  expandedLayer: 128 * 1024 ** 2, expandedTotal: 256 * 1024 ** 2, entries: 50_000,
  fileBytes: 64 * 1024 ** 2, extensionBytes: 64 * 1024, fieldBytes: 512, paxRecords: 1024,
  archiveBytes: 272 * 1024 ** 2, scratchBytes: 448 * 1024 ** 2 });
export class ArchiveRejected extends Error {
  constructor() { super('Image archive rejected'); }
}
export type TarBudget = { bytes: number; entries: number; paxRecords: number };
const reject = (): never => { throw new ArchiveRejected(); };
function text(bytes: Buffer): string {
  const end = bytes.indexOf(0);
  try { return new TextDecoder('utf-8', { fatal: true }).decode(end < 0 ? bytes : bytes.subarray(0, end)); }
  catch { return reject(); }
}
function octal(bytes: Buffer): number {
  const value = text(bytes).trim();
  if (!/^[0-7]+$/.test(value)) return reject();
  const result = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(result)) return reject();
  return result;
}
function name(value: string, link = false, symlink = false): string {
  // eslint-disable-next-line no-control-regex -- Intentionally reject control characters in archive paths and links.
  if (!value || Buffer.byteLength(value) > ARCHIVE_LIMITS.fieldBytes || /[\x00-\x1f\x7f\\]/.test(value)) return reject();
  if (symlink) return value; // Image symlinks are never resolved or extracted on the host.
  if (value.startsWith('/')) return reject();
  const parts = value.split('/');
  if (parts.includes('..') || (link && parts.every(part => !part || part === '.'))) return reject();
  return value;
}

// Incremental tar framing: only one bounded extension payload is buffered. Every
// header, data byte, padding byte and trailing zero is charged before processing.
export class LayerTarValidator {
  private pending = Buffer.alloc(0);
  private remaining = 0;
  private padding = 0;
  private extension: Buffer[] | undefined;
  private extensionType = '';
  private zeros = 0;
  private ended = false;
  private local: Record<string, string> = {};
  private global: Record<string, string> = {};
  private longName: string | undefined;
  private longLink: string | undefined;
  private size = 0;
  private hash = createHash('sha256');
  constructor(private budget: TarBudget) {}
  push(chunk: Buffer): void {
    this.size += chunk.length; this.budget.bytes += chunk.length;
    if (this.size > ARCHIVE_LIMITS.expandedLayer || this.budget.bytes > ARCHIVE_LIMITS.expandedTotal) reject();
    this.hash.update(chunk);
    let offset = 0;
    while (offset < chunk.length) {
      if (this.ended) {
        if (chunk.subarray(offset).some(byte => byte !== 0)) reject();
        return;
      }
      if (this.remaining) {
        const length = Math.min(this.remaining, chunk.length - offset);
        if (this.extension) this.extension.push(Buffer.from(chunk.subarray(offset, offset + length)));
        this.remaining -= length; offset += length;
        if (!this.remaining && this.extension) this.parseExtension();
      } else if (this.padding) {
        const length = Math.min(this.padding, chunk.length - offset);
        if (chunk.subarray(offset, offset + length).some(byte => byte !== 0)) reject();
        this.padding -= length; offset += length;
      } else {
        const length = Math.min(512 - this.pending.length, chunk.length - offset);
        this.pending = Buffer.concat([this.pending, chunk.subarray(offset, offset + length)]);
        offset += length;
        if (this.pending.length === 512) { const header = this.pending; this.pending = Buffer.alloc(0); this.header(header); }
      }
    }
  }
  finish(): { diffId: string; bytes: number } {
    if (!this.ended || this.remaining || this.padding || this.pending.length || Object.keys(this.local).length || this.longName || this.longLink) reject();
    return { diffId: `sha256:${this.hash.digest('hex')}`, bytes: this.size };
  }
  private header(header: Buffer): void {
    if (header.every(byte => byte === 0)) { if (++this.zeros === 2) this.ended = true; return; }
    if (this.zeros || ++this.budget.entries > ARCHIVE_LIMITS.entries) reject();
    const checksum = octal(header.subarray(148, 156));
    let actual = 0;
    for (let i = 0; i < 512; i++) actual += i >= 148 && i < 156 ? 32 : header[i];
    if (checksum !== actual) reject();
    const magic = header.subarray(257, 263).toString('ascii');
    const version = header.subarray(263, 265).toString('ascii');
    const gnu = magic === 'ustar ' && version === ' \0';
    if (!(magic === 'ustar\0' && version === '00') && !gnu) reject();
    const type = String.fromCharCode(header[156] || 48);
    const size = octal(header.subarray(124, 136));
    if (!['0', '5', '1', '2', 'x', 'g', 'L', 'K'].includes(type)) reject();
    if (['x', 'g', 'L', 'K'].includes(type)) {
      if (type === 'x' && Object.keys(this.local).length || type === 'L' && this.longName || type === 'K' && this.longLink) reject();
      if (!size || size > ARCHIVE_LIMITS.extensionBytes) reject();
      this.extension = []; this.extensionType = type;
    } else {
      const attributes = { ...this.global, ...this.local };
      const prefix = gnu ? '' : text(header.subarray(345, 500));
      name(attributes.path ?? this.longName ?? [prefix, text(header.subarray(0, 100))].filter(Boolean).join('/'));
      if (type === '1' || type === '2') name(attributes.linkpath ?? this.longLink ?? text(header.subarray(157, 257)), true, type === '2');
      if (attributes.size !== undefined && attributes.size !== String(size)) reject();
      if (size > ARCHIVE_LIMITS.fileBytes || (type !== '0' && size !== 0)) reject();
      this.local = {}; this.longName = undefined; this.longLink = undefined;
    }
    this.remaining = size; this.padding = (512 - size % 512) % 512;
  }
  private parseExtension(): void {
    const bytes = Buffer.concat(this.extension!); this.extension = undefined;
    if (this.extensionType === 'L' || this.extensionType === 'K') {
      const value = text(bytes);
      name(value, this.extensionType === 'K', this.extensionType === 'K');
      if (this.extensionType === 'L') this.longName = value; else this.longLink = value;
      return;
    }
    if (bytes.includes(0)) reject();
    const attributes: Record<string, string> = {};
    let offset = 0;
    while (offset < bytes.length) {
      if (++this.budget.paxRecords > ARCHIVE_LIMITS.paxRecords) reject();
      const space = bytes.indexOf(32, offset);
      if (space < 0 || space - offset > 8) reject();
      const lengthText = bytes.subarray(offset, space).toString('ascii');
      if (!/^[1-9][0-9]*$/.test(lengthText)) reject();
      const length = Number(lengthText);
      if (length <= space - offset + 2 || offset + length > bytes.length || bytes[offset + length - 1] !== 10) reject();
      const record = text(bytes.subarray(space + 1, offset + length - 1));
      const equals = record.indexOf('=');
      if (equals < 1) reject();
      const key = record.slice(0, equals), value = record.slice(equals + 1);
      // Unknown extensions can change extraction semantics (sparse, xattrs etc.).
      if (!['path', 'linkpath', 'size', 'mtime', 'atime', 'ctime', 'uid', 'gid', 'uname', 'gname'].includes(key) || key in attributes) reject();
      // eslint-disable-next-line no-control-regex -- Intentionally reject control characters in PAX attributes.
      if (Buffer.byteLength(value) > ARCHIVE_LIMITS.fieldBytes || /[\x00-\x1f\x7f]/.test(value)) reject();
      attributes[key] = value; offset += length;
    }
    if (this.extensionType === 'g') {
      if (['path', 'linkpath', 'size'].some(key => key in attributes)) reject();
      this.global = { ...this.global, ...attributes };
    } else this.local = attributes;
  }
}
