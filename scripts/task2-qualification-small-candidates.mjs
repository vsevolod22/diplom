// Successor to the earlier Node 22 observation. At most two metadata candidates,
// stop at the first compressed-envelope fit. No config or layer bytes acquired here.
import { writeFileSync, existsSync } from 'node:fs';
import { check, sha256 } from './task2-qualification-native.mjs';
const output = new URL('../server/deploy/proof/task2-small-node-metadata.json', import.meta.url);
check(!existsSync(output), 'successor-evidence-already-exists');
const evidence = { startedAt: new Date().toISOString(), scope: 'anonymous metadata only; inflated sizes and npm positivity unknown',
  candidates: [], success: false, requests: 0, wireBytes: 0 };
const deadline = AbortSignal.timeout(60000);
async function bounded(url, headers = {}, max = 4_000_000) {
  const u = new URL(url);
  check(u.protocol === 'https:' && !u.port && !u.username && !u.password && ['auth.docker.io', 'registry-1.docker.io'].includes(u.hostname), 'public-host');
  check(++evidence.requests <= 5, 'metadata-request-budget');
  const response = await fetch(u, { headers, redirect: 'error', signal: AbortSignal.any([deadline, AbortSignal.timeout(15000)]) });
  check(response.status === 200, 'public-http-status');
  let size = 0; const chunks = [];
  for await (const bytes of response.body) {
    size += bytes.length; evidence.wireBytes += bytes.length;
    check(size <= max && evidence.wireBytes <= 16_000_000, 'metadata-byte-budget');
    chunks.push(Buffer.from(bytes));
  }
  return Buffer.concat(chunks);
}
try {
  const auth = JSON.parse(await bounded('https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/node:pull', {}, 32768));
  check(typeof auth.token === 'string' && auth.token.length <= 8192, 'anonymous-token-bound');
  const headers = { authorization: `Bearer ${auth.token}`, accept: 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' };
  for (const tag of ['14.0.0-alpine3.11', '16.0.0-alpine3.13']) {
    const item = { tag, repository: 'library/node', registry: 'registry-1.docker.io', platform: 'linux/amd64' };
    evidence.candidates.push(item);
    const bytes = await bounded(`https://registry-1.docker.io/v2/library/node/manifests/${tag}`, headers);
    const index = JSON.parse(bytes);
    check(index.schemaVersion === 2 && Array.isArray(index.manifests) && index.manifests.length <= 1024, 'index-schema');
    const matches = index.manifests.filter(m => m.platform?.os === 'linux' && m.platform?.architecture === 'amd64' && m.platform?.variant === undefined);
    check(matches.length === 1 && /^sha256:[a-f0-9]{64}$/.test(matches[0].digest), 'unique-amd64');
    const manifestBytes = await bounded('https://registry-1.docker.io/v2/library/node/manifests/' + matches[0].digest, headers);
    check(manifestBytes.length === matches[0].size && 'sha256:' + sha256(manifestBytes) === matches[0].digest, 'child-manifest-binding');
    const manifest = JSON.parse(manifestBytes);
    check(manifest.schemaVersion === 2 && /^sha256:[a-f0-9]{64}$/.test(manifest.config?.digest) && manifest.config.size > 0 && manifest.config.size <= 1_000_000, 'config-descriptor');
    check(Array.isArray(manifest.layers) && manifest.layers.length > 0 && manifest.layers.length <= 32 && manifest.layers.every(l =>
      /^sha256:[a-f0-9]{64}$/.test(l.digest) && Number.isSafeInteger(l.size) && l.size > 0 && !l.urls &&
      ['application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.docker.image.rootfs.diff.tar.gzip'].includes(l.mediaType)), 'layer-descriptors');
    const compressedBytes = manifest.layers.reduce((n, l) => n + l.size, 0);
    Object.assign(item, { indexDigest: 'sha256:' + sha256(bytes), digest: matches[0].digest, manifestSize: manifestBytes.length,
      config: manifest.config, layers: manifest.layers, compressedBytes,
      compressedEnvelopeFits: manifest.layers.every(l => l.size <= 32 * 1024 ** 2) && compressedBytes <= 96 * 1024 ** 2,
      inflatedEnvelope: 'unknown until bounded verified acquisition' });
    if (item.compressedEnvelopeFits) { evidence.selected = item; break; }
  }
  evidence.success = !!evidence.selected;
} catch {
  evidence.failure = 'bounded-metadata-discovery-failed-no-retry';
} finally {
  evidence.finishedAt = new Date().toISOString();
  writeFileSync(output, JSON.stringify(evidence, null, 2) + '\n', { flag: 'wx' });
  console.log(JSON.stringify({ success: evidence.success, investigated: evidence.candidates.length, selected: evidence.selected?.tag,
    artifact: 'server/deploy/proof/task2-small-node-metadata.json' }));
  if (!evidence.success) process.exitCode = 1;
}
