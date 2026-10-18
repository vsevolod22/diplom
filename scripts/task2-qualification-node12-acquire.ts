// Standalone exact candidate acquisition; generic validators only. No nginx receipt.
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open, rm, statfs, readdir, lstat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dockerHubManifestFetch, gatewayGet } from '../server/api/src/oci/gateway-transport.ts';
import { inflateLayer } from '../server/api/src/oci/bounded-image-archive.ts';
import { ARCHIVE_LIMITS as L, type TarBudget } from '../server/api/src/oci/layer-tar-validator.ts';
import { ArchiveAttemptBudget } from '../server/api/src/oci/archive-budget.ts';

export const PIN = Object.freeze({ registry: 'registry-1.docker.io', repository: 'library/node',
  digest: 'sha256:4517380049fc3c9aacceae7764fcf3500354b0ac8a47e4afb35b5bbeb75b9498',
  configDigest: 'sha256:bb6d28039b8cec9aa8d9032f9aa640a792a60c2cb1644691627bf046aab27c8b',
  configBytes: 6584, manifestBytes: 1158, platform: 'linux/amd64',
  layers: Object.freeze([
    { digest: 'sha256:df9b9388f04ad6279a7410b85cedfdcb2208c0a003da7ab5613af71079148139', size: 2814559 },
    { digest: 'sha256:3bf6d738020517f4622814e8c21db4b4aaa78ae7cab4e4f872c11696886c6285', size: 24910721 },
    { digest: 'sha256:7939e601ee5e4737cf7fdb6d1dfe31ca4c2697109290462f694710761450aef0', size: 2358237 },
    { digest: 'sha256:31f0fb9de071269230cb0f786012ae4e81d26e489b1fe922e57b5201e6bc9ab0', size: 451 },
  ]) });
export const hash = (bytes: Buffer) => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
export function requireSafe(ok: unknown, label: string): asserts ok { if (!ok) throw new Error(label); }
export function exactManifest(bytes: Buffer) {
  requireSafe(bytes.length === PIN.manifestBytes && hash(bytes) === PIN.digest, 'manifest-binding');
  const value = JSON.parse(bytes.toString('utf8'));
  requireSafe(value.schemaVersion === 2 && value.mediaType === 'application/vnd.docker.distribution.manifest.v2+json' &&
    value.config?.digest === PIN.configDigest && value.config.size === PIN.configBytes && value.config.urls === undefined &&
    value.config.mediaType === 'application/vnd.docker.container.image.v1+json' &&
    Array.isArray(value.layers) && value.layers.length === PIN.layers.length && value.layers.length <= L.maxLayers &&
    value.layers.every((layer: { digest?: unknown; size: number; urls?: unknown; mediaType?: unknown }, i: number) => layer.digest === PIN.layers[i].digest && layer.size === PIN.layers[i].size &&
      layer.size <= L.compressedLayer && layer.urls === undefined && layer.mediaType === 'application/vnd.docker.image.rootfs.diff.tar.gzip') &&
    value.layers.reduce((n: number, l: { size: number }) => n + l.size, 0) <= L.compressedTotal, 'manifest-schema');
  return value;
}
export function configIdentity(bytes: Buffer, expectedDigest = PIN.configDigest, expectedSize = PIN.configBytes, count = PIN.layers.length) {
  requireSafe(bytes.length === expectedSize && hash(bytes) === expectedDigest, 'config-binding');
  const value = JSON.parse(bytes.toString('utf8'));
  requireSafe(value.os === 'linux' && value.architecture === 'amd64' && value.variant === undefined &&
    value.rootfs?.type === 'layers' && Array.isArray(value.rootfs.diff_ids) && value.rootfs.diff_ids.length === count &&
    value.rootfs.diff_ids.every((v: unknown) => typeof v === 'string' && /^sha256:[a-f0-9]{64}$/.test(v)), 'config-platform-rootfs');
  // No Env/history/config values leave this function; bytes remain transient only.
  return { configDigest: expectedDigest, diffIds: value.rootfs.diff_ids as string[], os: value.os, architecture: value.architecture };
}
export function tarHeader(name: string, size: number) {
  requireSafe(/^[a-zA-Z0-9][a-zA-Z0-9/._-]{0,98}$/.test(name) && !name.split('/').includes('..') && Number.isSafeInteger(size) && size >= 0 && size <= L.archiveBytes, 'archive-member');
  const h = Buffer.alloc(512);
  h.write(name); h.write('0000444\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(size.toString(8).padStart(11, '0') + '\0', 124); h.write('00000000000\0', 136);
  h.fill(32, 148, 156); h[156] = 48; h.write('ustar\0', 257); h.write('00', 263);
  h.write(h.reduce((n, b) => n + b, 0).toString(8).padStart(6, '0') + '\0 ', 148);
  return h;
}

export async function acquireExact() {
  const budget = new ArchiveAttemptBudget();
  const signal = AbortSignal.timeout(L.deadlineMs);
  const tarBudget: TarBudget = { bytes: 0, entries: 0, paxRecords: 0 };
  let sticky = false;
  let active: { handle: Awaited<ReturnType<typeof open>>; bytes: number; size: number; hash: ReturnType<typeof createHash> } | undefined;
  let maxScratch = 0;
  const scratch = async () => {
    let total = 0;
    for (const name of await readdir('/work')) {
      const s = await lstat('/work/' + name);
      requireSafe(s.isFile() && !s.isSymbolicLink(), 'scratch-entry'); total += s.size;
    }
    requireSafe(total <= L.scratchBytes, 'scratch-cap');
    maxScratch = Math.max(maxScratch, total); return total;
  };
  const reserve = async (bytes: number) => {
    budget.reserve(bytes);
    const s = await statfs('/work');
    requireSafe(s.bavail * s.bsize >= bytes + 16 * 1024 ** 2, 'scratch-free');
  };
  const request = dockerHubManifestFetch({ host: 'task2-gateway', port: 8080 }, PIN.repository, async (gateway, url, headers, maximum) => {
    requireSafe(!sticky && !signal.aborted, 'acquisition-aborted');
    const remaining = budget.request();
    const isLayer = !!active && (url.hostname === 'production.cloudfront.docker.com' || url.pathname.includes('/blobs/'));
    const cap = isLayer ? Math.min(L.compressedLayer, active!.size) : Math.min(maximum ?? 4_000_000, url.pathname.includes('/blobs/') ? PIN.configBytes : 4_000_000);
    try {
      const chunks: Buffer[] = [];
      const result = await gatewayGet(gateway, url, headers, cap, remaining, async (bytes, status) => {
        budget.wire(bytes.length);
        if (isLayer && status === 200) {
          active!.bytes += bytes.length; budget.layer(bytes.length);
          requireSafe(active!.bytes <= active!.size, 'compressed-size');
          active!.hash.update(bytes); await active!.handle.writeFile(bytes);
        } else chunks.push(Buffer.from(bytes));
      }, signal);
      return { ...result, body: Buffer.concat(chunks) };
    } catch { sticky = true; throw new Error('bounded-gateway-transport-failed'); }
  });
  const manifestResponse = await request(PIN.registry, `/v2/${PIN.repository}/manifests/${PIN.digest}`);
  exactManifest(manifestResponse.body);
  const configResponse = await request(PIN.registry, `/v2/${PIN.repository}/blobs/${PIN.configDigest}`);
  const configBytes = configResponse.body;
  const identity = configIdentity(configBytes);
  const layerEvidence = [];
  for (const [i, layer] of PIN.layers.entries()) {
    await reserve(layer.size + L.expandedLayer);
    const compressed = `/work/${i}.gz`, expanded = `/work/${i}.tar`;
    const handle = await open(compressed, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    active = { handle, bytes: 0, size: layer.size, hash: createHash('sha256') };
    try {
      await request(PIN.registry, `/v2/${PIN.repository}/blobs/${layer.digest}`);
      requireSafe(active.bytes === layer.size && 'sha256:' + active.hash.digest('hex') === layer.digest, 'compressed-hash');
    } finally { await handle.close(); }
    active = undefined;
    const validated = await inflateLayer(compressed, expanded, tarBudget, signal);
    requireSafe(validated.diffId === identity.diffIds[i], 'inflated-diffid');
    await scratch();
    layerEvidence.push({ digest: layer.digest, compressedBytes: layer.size, diffId: validated.diffId, expandedBytes: validated.bytes });
    await rm(compressed); budget.release(layer.size + L.expandedLayer - validated.bytes);
  }
  const file = await open('/work/image.tar', constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o400);
  const archiveHash = createHash('sha256'); let archiveBytes = 0;
  const write = async (bytes: Buffer) => {
    requireSafe(!signal.aborted, 'archive-deadline'); budget.remaining();
    archiveBytes += bytes.length; requireSafe(archiveBytes <= L.archiveBytes, 'archive-cap');
    await reserve(bytes.length); archiveHash.update(bytes); await file.writeFile(bytes);
  };
  const member = async (name: string, bytes: Buffer) => {
    await write(tarHeader(name, bytes.length)); await write(bytes); await write(Buffer.alloc((512 - bytes.length % 512) % 512));
  };
  try {
    // The original config (including public image Env) exists ONLY in memory/tmpfs.
    // It must not be projected/replaced: native ImageID must match the remote config.
    const configName = PIN.configDigest.slice(7) + '.json';
    await member(configName, configBytes);
    await member('manifest.json', Buffer.from(JSON.stringify([{ Config: configName, RepoTags: [], Layers: PIN.layers.map((_, i) => `${i}/layer.tar`) }])));
    for (const [i, layer] of layerEvidence.entries()) {
      await write(tarHeader(`${i}/layer.tar`, layer.expandedBytes));
      const input = await open(`/work/${i}.tar`, constants.O_RDONLY | constants.O_NOFOLLOW);
      try { for await (const bytes of input.createReadStream({ autoClose: false })) await write(bytes as Buffer); }
      finally { await input.close(); }
      await write(Buffer.alloc((512 - layer.expandedBytes % 512) % 512));
      await scratch(); await rm(`/work/${i}.tar`); budget.release(layer.expandedBytes);
    }
    await write(Buffer.alloc(1024)); await file.chmod(0o444);
  } finally { await file.close(); }
  await scratch();
  return { kind: 'standalone-exact-remote-acquisition-no-production-receipt', ...identity,
    manifestDigest: PIN.digest, registry: PIN.registry, repository: PIN.repository, layers: layerEvidence,
    archiveSha256: 'sha256:' + archiveHash.digest('hex'), archiveBytes,
    metrics: { requests: budget.requests, wireBytes: budget.wireBytes, compressedBytes: budget.compressedBytes,
      expandedBytes: tarBudget.bytes, entries: tarBudget.entries, paxRecords: tarBudget.paxRecords,
      reservationPeak: budget.reservationPeak, observedScratchPeak: maxScratch },
    durationMs: L.deadlineMs - budget.remaining(), configEnvPersistedOutsideMemory: false };
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify({ ok: true, acquisition: await acquireExact() })); }
  catch { console.log(JSON.stringify({ ok: false, failure: 'exact-acquisition-rejected-no-retry' })); process.exitCode = 1; }
}
