import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, rm, statfs } from 'node:fs/promises';
import { createInflateRaw } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { Writable } from 'node:stream';
import { gatewayGet, dockerHubManifestFetch } from './gateway-transport.js';
import { inspectNginxCandidate } from './nginx-candidate.js';
import { ARCHIVE_LIMITS as L, ArchiveRejected, LayerTarValidator, type TarBudget } from './layer-tar-validator.js';
import { ArchiveAttemptBudget } from './archive-budget.js';

export const NGINX_ARCHIVE_TARGET = Object.freeze({ registry: 'registry-1.docker.io', repository: 'library/nginx',
  digest: 'sha256:b17b00f7ef0038aeb11362157f49006a130628ee711cefcced871405d046f114',
  configDigest: 'sha256:42ce3d3585d47518cb0c1ef4bd3d8a65c1edfcbbfd423eda86990a83f378b111', platform: 'linux/amd64' });
// Separately discovered exact candidate, never a tag/env-defined admission policy.
export const NGINX_SUPPORTED_CANDIDATE = Object.freeze({ registry: 'registry-1.docker.io', repository: 'library/nginx',
  digest: 'sha256:0dcc88822d45581e65ae329f8be769762bf628d3b2bb7d2a077d4aa5c98b30e3',
  configDigest: 'sha256:dc73b49f5124cf2ee538dfbdfbd121f0b4ccdcb20fea30f3a81bd477c02e2bb5', platform: 'linux/amd64' });
export const NGINX_ARCHIVE_CANDIDATES = Object.freeze([NGINX_ARCHIVE_TARGET, NGINX_SUPPORTED_CANDIDATE]);
export type ArchiveTarget = typeof NGINX_ARCHIVE_CANDIDATES[number];
export const archiveProfileVersion = (target: ArchiveTarget) => target.digest === NGINX_ARCHIVE_TARGET.digest
  ? 'nginx-alpine-amd64-v1' : 'nginx-alpine-amd64-v2-candidate';
export type ArchiveReceipt = ArchiveTarget & { layerDigests: string[]; diffIds: string[];
  archiveSha256: string; profileVersion: string; resourcePolicyVersion: string; checksVersion: string };
const hash = (bytes: Buffer) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const fail = (): never => { throw new ArchiveRejected(); };
const crcTable = Array.from({ length: 256 }, (_, value) => {
  for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});

export async function inflateLayer(path: string, output: string, budget: TarBudget, signal?: AbortSignal) {
  const source = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  const destination = await open(output, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    const size = (await source.stat()).size;
    const header = Buffer.alloc(10), trailer = Buffer.alloc(8);
    if (size < 18 || (await source.read(header, 0, 10, 0)).bytesRead !== 10 ||
        (await source.read(trailer, 0, 8, size - 8)).bytesRead !== 8 ||
        header[0] !== 31 || header[1] !== 139 || header[2] !== 8 || header[3] !== 0) fail();
    // A single fixed-header gzip member only; no optional fields, concatenation or trailing payload.
    const inflate = createInflateRaw();
    const validator = new LayerTarValidator(budget);
    let crc = 0xffffffff, bytes = 0;
    await pipeline(source.createReadStream({ start: 10, end: size - 9, autoClose: false }), inflate,
      new Writable({ write(chunk: Buffer, _encoding, callback) {
        try {
          validator.push(chunk); bytes += chunk.length;
          for (const byte of chunk) crc = crcTable[(crc ^ byte) & 255] ^ (crc >>> 8);
          void destination.writeFile(chunk).then(() => callback(), () => callback(new ArchiveRejected()));
        } catch { callback(new ArchiveRejected()); }
      } }), { signal });
    if (inflate.bytesWritten !== size - 18 || ((crc ^ 0xffffffff) >>> 0) !== trailer.readUInt32LE(0) ||
        bytes !== trailer.readUInt32LE(4)) fail();
    return validator.finish();
  } finally { await source.close(); await destination.close(); }
}

function tarHeader(name: string, size: number): Buffer {
  if (!/^[a-zA-Z0-9/._-]+$/.test(name) || name.length > 100 || !Number.isSafeInteger(size) || size < 0) fail();
  const header = Buffer.alloc(512);
  header.write(name); header.write('0000600\0', 100); header.write('0000000\0', 108); header.write('0000000\0', 116);
  header.write(size.toString(8).padStart(11, '0') + '\0', 124); header.write('00000000000\0', 136);
  header.fill(32, 148, 156); header[156] = 48; header.write('ustar\0', 257); header.write('00', 263);
  const sum = header.reduce((total, byte) => total + byte, 0);
  header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return header;
}

export async function recoverArchiveScratch(): Promise<void> {
  const root = '/tmp/trivy/jobs';
  try {
    const info = await lstat(root);
    if (!info.isDirectory() || info.isSymbolicLink() || info.mode & 0o077 || info.uid !== process.getuid?.()) fail();
    for (const entry of await readdir(root, { withFileTypes: true })) {
      if (!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(entry.name) || !entry.isDirectory()) fail();
      await rm(`${root}/${entry.name}`, { recursive: true, force: true });
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new ArchiveRejected();
  }
}

// Internal fixed candidate only. This is not upload/local-image admission and does
// not make the candidate qualified. Caller owns cleanup, including scanner phases.
export async function prepareNginxArchive(signal?: AbortSignal, target: ArchiveTarget = NGINX_ARCHIVE_TARGET) {
  if (!NGINX_ARCHIVE_CANDIDATES.some(candidate => Object.entries(candidate).every(([key, value]) => target[key as keyof ArchiveTarget] === value))) fail();
  signal = AbortSignal.any([...(signal ? [signal] : []), AbortSignal.timeout(L.deadlineMs)]);
  const root = '/tmp/trivy/jobs';
  await mkdir(root, { recursive: true, mode: 0o700 });
  const rootHandle = await open(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { const info = await rootHandle.stat(); if (info.mode & 0o077 || info.uid !== process.getuid?.()) fail(); }
  finally { await rootHandle.close(); }
  const directory = `${root}/${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 });
  const cleanup = () => rm(directory, { recursive: true, force: true });
  const budget = new ArchiveAttemptBudget();
  let stickyFailure = false;
  let active: { digest: string; handle: Awaited<ReturnType<typeof open>>; hash: ReturnType<typeof createHash>; bytes: number; size: number } | undefined;
  let config: Buffer | undefined;
  const reserve = async (bytes: number) => {
    budget.reserve(bytes);
    const filesystem = await statfs(directory);
    if (filesystem.bavail * filesystem.bsize < bytes + 16 * 1024 ** 2) fail();
  };
  const fetch = dockerHubManifestFetch({ host: 'egress', port: 8080 }, 'library/nginx', async (gateway, url, headers, maximum) => {
    if (stickyFailure || signal?.aborted) fail();
        const remaining = budget.request();
    const isLayer = !!active && (url.hostname === 'production.cloudfront.docker.com' || url.pathname.endsWith(encodeURIComponent(active.digest)) || url.pathname.endsWith(active.digest));
    try {
      const chunks: Buffer[] = [];
      const response = await gatewayGet(gateway, url, headers, isLayer ? L.compressedLayer : maximum ?? 4_000_000,
        remaining, async (chunk, status) => {
          if (signal?.aborted) fail();
          budget.wire(chunk.length);
          if (isLayer && status === 200) {
            active!.bytes += chunk.length; budget.layer(chunk.length);
            if (active!.bytes > active!.size) fail();
            active!.hash.update(chunk); await active!.handle.writeFile(chunk);
          } else chunks.push(Buffer.from(chunk));
        }, signal);
      return { ...response, body: Buffer.concat(chunks) };
    } catch { stickyFailure = true; throw new ArchiveRejected(); }
  });
  try {

    const candidate = await inspectNginxCandidate({ registry: target.registry, repository: target.repository, selector: target.digest, canonical: `${target.registry}/${target.repository}@${target.digest}` }, async (host, path) => {
      const result = await fetch(host, path);
      if (path.includes('/blobs/')) config = result.body;
      return result;
    });
    if (candidate.digest !== target.digest || candidate.configDigest !== target.configDigest || !config || hash(config) !== target.configDigest) fail();
    const details = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(config));
    const diffIds: unknown = details.rootfs?.diff_ids;
    if (details.rootfs?.type !== 'layers' || !Array.isArray(diffIds) || diffIds.length !== candidate.layers.length ||
        diffIds.some(value => typeof value !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(value))) fail();
    const tarBudget: TarBudget = { bytes: 0, entries: 0, paxRecords: 0 };
    const layers: Array<{ path: string; size: number; name: string }> = [];
    for (const [index, layer] of candidate.layers.entries()) {
      await reserve(layer.size + L.expandedLayer);
      const compressed = `${directory}/${index}.gz`, expanded = `${directory}/${index}.tar`;
      const handle = await open(compressed, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      active = { digest: layer.digest, handle, hash: createHash('sha256'), bytes: 0, size: layer.size };
      try {
        await fetch(target.registry, `/v2/library/nginx/blobs/${layer.digest}`);
        if (active.bytes !== layer.size || `sha256:${active.hash.digest('hex')}` !== layer.digest) fail();
      } finally { await handle.close(); }
      active = undefined;
      const validated = await inflateLayer(compressed, expanded, tarBudget, signal);
      if (validated.diffId !== (diffIds as string[])[index]) fail();
      await rm(compressed); budget.release(layer.size + L.expandedLayer - validated.bytes);
      layers.push({ path: expanded, size: validated.bytes, name: `${index}/layer.tar` });
    }
    const archivePath = `${directory}/image.tar`;
    const archive = await open(archivePath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    let archiveBytes = 0;
    const archiveHash = createHash('sha256');
    const write = async (chunk: Buffer) => {
      if (signal?.aborted) fail();
      archiveBytes += chunk.length;
      if (archiveBytes > L.archiveBytes) fail();
      await reserve(chunk.length); archiveHash.update(chunk); await archive.writeFile(chunk);
    };
    const member = async (name: string, bytes: Buffer) => {
      await write(tarHeader(name, bytes.length)); await write(bytes);
      await write(Buffer.alloc((512 - bytes.length % 512) % 512));
    };
    try {
      const configName = `${target.configDigest.slice(7)}.json`;
      await member(configName, config!);
      await member('manifest.json', Buffer.from(JSON.stringify([{ Config: configName, RepoTags: [], Layers: layers.map(layer => layer.name) }])));
      for (const layer of layers) {
        await write(tarHeader(layer.name, layer.size));
        // Consume/delete per layer so retained layers + archive never require 2x total space.
        const input = await open(layer.path, constants.O_RDONLY | constants.O_NOFOLLOW);
                try { for await (const chunk of input.createReadStream({ autoClose: false })) await write(chunk); }
                finally { await input.close(); }
        await write(Buffer.alloc((512 - layer.size % 512) % 512));
        await rm(layer.path); budget.release(layer.size);
      }
      await write(Buffer.alloc(1024)); await archive.chmod(0o400);
    } finally { await archive.close(); }
    const receipt: ArchiveReceipt = { ...target, layerDigests: Object.freeze(candidate.layers.map(layer => layer.digest)) as unknown as string[], diffIds: Object.freeze(diffIds as string[]) as unknown as string[],
      archiveSha256: `sha256:${archiveHash.digest('hex')}`, profileVersion: archiveProfileVersion(target),
      resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' };
    return { archivePath, directory, receipt: Object.freeze(receipt), cleanup,
      metrics: { wireBytes: budget.wireBytes, requests: budget.requests, compressedBytes: budget.compressedBytes,
              expandedBytes: tarBudget.bytes, entries: tarBudget.entries, archiveBytes, reservationPeak: budget.reservationPeak } };
  } catch { await cleanup(); throw new ArchiveRejected(); }
}
