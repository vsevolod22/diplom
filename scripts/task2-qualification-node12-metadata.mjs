// Exactly one new official Node12 candidate. Metadata only; no Docker, config,
// layers, Env, DB or production admission. Never replaces earlier observations.
import { createHash } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';

const output = new URL('../server/deploy/proof/task2-node12-metadata.json', import.meta.url);
if (existsSync(output)) throw new Error('node12-evidence-already-exists');
const tag = '12.22.12-alpine3.15';
const check = (ok, label) => { if (!ok) throw new Error(label); };
const digest = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
const validDigest = value => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
const validSize = (value, max) => Number.isSafeInteger(value) && value > 0 && value <= max;
const limits = Object.freeze({ requests: 3, wireBytes: 8_032_768, objectBytes: 4_000_000,
  configBytes: 1_000_000, tokenBytes: 32768, deadlineMs: 45000, requestMs: 15000,
  maxLayers: 32, compressedLayer: 32 * 1024 ** 2, compressedTotal: 96 * 1024 ** 2 });
const evidence = { startedAt: new Date().toISOString(), candidate: `registry-1.docker.io/library/node:${tag}`,
  candidateInvestigations: 1, scope: 'anonymous metadata only; not native detection or admission',
  discoveryCompleted: false, limits, requests: 0, wireBytes: 0, layerAcquisitionAttempted: false, scannerAttempted: false };
const deadline = AbortSignal.timeout(limits.deadlineMs);
async function bounded(url, headers = {}, max = limits.objectBytes) {
  const u = new URL(url);
  check(u.protocol === 'https:' && !u.port && !u.username && !u.password && !u.hash &&
    ['auth.docker.io', 'registry-1.docker.io'].includes(u.hostname), 'metadata-host-rejected');
  check(++evidence.requests <= limits.requests, 'metadata-request-budget');
  const response = await fetch(u, { headers, redirect: 'error', signal: AbortSignal.any([deadline, AbortSignal.timeout(limits.requestMs)]) });
  check(response.status === 200, 'metadata-http-status');
  const chunks = []; let size = 0;
  for await (const bytes of response.body) {
    size += bytes.length; evidence.wireBytes += bytes.length;
    check(size <= max && evidence.wireBytes <= limits.wireBytes, 'metadata-byte-budget');
    chunks.push(Buffer.from(bytes));
  }
  return Buffer.concat(chunks);
}
try {
  const auth = JSON.parse(await bounded('https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/node:pull', {}, limits.tokenBytes));
  check(typeof auth.token === 'string' && auth.token.length <= 8192 && /^[\x21-\x7e]+$/.test(auth.token), 'anonymous-token-bound');
  const headers = { authorization: `Bearer ${auth.token}`, accept: 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' };
  const indexBytes = await bounded(`https://registry-1.docker.io/v2/library/node/manifests/${tag}`, headers);
  const index = JSON.parse(indexBytes);
  check(index.schemaVersion === 2 && ['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json'].includes(index.mediaType) &&
    Array.isArray(index.manifests) && index.manifests.length <= 1024, 'index-schema');
  const matches = index.manifests.filter(m => m.platform?.os === 'linux' && m.platform?.architecture === 'amd64' && m.platform?.variant === undefined);
  check(matches.length === 1 && validDigest(matches[0].digest) && validSize(matches[0].size, limits.objectBytes), 'unique-bounded-amd64');
  const manifestBytes = await bounded('https://registry-1.docker.io/v2/library/node/manifests/' + matches[0].digest, headers);
  check(digest(manifestBytes) === matches[0].digest && manifestBytes.length === matches[0].size, 'child-manifest-binding');
  const manifest = JSON.parse(manifestBytes);
  check(manifest.schemaVersion === 2 && ['application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'].includes(manifest.mediaType), 'manifest-schema');
  check(validDigest(manifest.config?.digest) && validSize(manifest.config.size, limits.configBytes) && manifest.config.urls === undefined &&
    ['application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json'].includes(manifest.config.mediaType), 'config-descriptor');
  check(Array.isArray(manifest.layers) && manifest.layers.length > 0 && manifest.layers.length <= limits.maxLayers && manifest.layers.every(l =>
    validDigest(l.digest) && validSize(l.size, Number.MAX_SAFE_INTEGER) && l.urls === undefined &&
    ['application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.docker.image.rootfs.diff.tar.gzip'].includes(l.mediaType)), 'layer-descriptors');
  const descriptor = ({ digest, size, mediaType }) => ({ digest, size, mediaType });
  const layers = manifest.layers.map(descriptor);
  const compressedTotal = layers.reduce((n, l) => n + l.size, 0);
  check(Number.isSafeInteger(compressedTotal), 'compressed-sum');
  Object.assign(evidence, { discoveryCompleted: true, indexDigest: digest(indexBytes), manifestDigest: matches[0].digest,
    manifestBytes: manifestBytes.length, platform: 'linux/amd64', config: descriptor(manifest.config), layers,
    largestCompressedLayer: Math.max(...layers.map(l => l.size)), compressedTotal,
    compressedEnvelopeFits: layers.every(l => l.size <= limits.compressedLayer) && compressedTotal <= limits.compressedTotal,
    allCapsVerified: false,
    unverifiedCaps: ['128MiB-inflated-layer', '256MiB-inflated-total', '64MiB-file', '50000-entries', '1024-PAX-records', '272MiB-archive', '448MiB-scratch', '180s-acquisition', '112MiB-acquisition-wire'],
    actualOsAndEol: 'not inspected; tag is not scanner OS evidence', npmPositive: 'not tested',
    receipt: 'none; exact Node receipt is not currently accepted; no nginx identity substituted' });
} catch {
  evidence.failure = 'bounded-single-candidate-metadata-failed-no-retry';
  process.exitCode = 1;
} finally {
  evidence.finishedAt = new Date().toISOString();
  writeFileSync(output, JSON.stringify(evidence, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
  console.log(JSON.stringify({ discoveryCompleted: evidence.discoveryCompleted, compressedEnvelopeFits: evidence.compressedEnvelopeFits,
    allCapsVerified: false, requests: evidence.requests, artifact: 'server/deploy/proof/task2-node12-metadata.json' }));
}
