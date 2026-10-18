// Public metadata only: no layer download, Docker pull, config/Env read, or admission change.
import { writeFileSync } from 'node:fs';
import { check, sha256 } from './task2-qualification-native.mjs';
const artifact = new URL('../server/deploy/proof/task2-npm-remote-candidate.json', import.meta.url);
const evidence = { checkedAt: new Date().toISOString(), candidate: 'registry-1.docker.io/library/node:22.14.0-alpine3.21',
  scope: 'anonymous public index and child-manifest metadata only; NOT npm detection or executed qualification', success: false };
async function bounded(url, headers = {}) {
  const u = new URL(url);
  check(u.protocol === 'https:' && ['auth.docker.io', 'registry-1.docker.io'].includes(u.hostname), 'public-host');
  const response = await fetch(url, { headers, redirect: 'error', signal: AbortSignal.timeout(15000) });
  check(response.status === 200, 'public-http-status');
  const chunks = []; let size = 0;
  for await (const bytes of response.body) {
    size += bytes.length;
    check(size <= 4_000_000, 'public-metadata-bound');
    chunks.push(Buffer.from(bytes));
  }
  return Buffer.concat(chunks);
}
try {
  // Anonymous repository-scoped bearer is transient and never emitted/stored.
  const auth = JSON.parse((await bounded('https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/node:pull')).toString());
  const headers = { authorization: `Bearer ${auth.token}`, accept: 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' };
  const bytes = await bounded('https://registry-1.docker.io/v2/library/node/manifests/22.14.0-alpine3.21', headers);
  const index = JSON.parse(bytes);
  const target = index.manifests.filter(m => m.platform?.os === 'linux' && m.platform?.architecture === 'amd64' && !m.platform?.variant);
  check(target.length === 1 && /^sha256:[a-f0-9]{64}$/.test(target[0].digest), 'unique-amd64-candidate');
  const manifestBytes = await bounded('https://registry-1.docker.io/v2/library/node/manifests/' + target[0].digest, headers);
  check('sha256:' + sha256(manifestBytes) === target[0].digest, 'manifest-hash');
  const manifest = JSON.parse(manifestBytes);
  check(manifest.layers.length <= 32 && manifest.layers.every(l => /^sha256:[a-f0-9]{64}$/.test(l.digest) && Number.isSafeInteger(l.size)), 'layer-descriptors');
  Object.assign(evidence, { success: true, indexDigest: 'sha256:' + sha256(bytes), digest: target[0].digest,
    configDigest: manifest.config.digest, platform: 'linux/amd64', layers: manifest.layers,
    compressedBytes: manifest.layers.reduce((n, l) => n + l.size, 0),
    exceedsCurrent32MiBLayerCap: manifest.layers.some(l => l.size > 32 * 1024 ** 2),
    exceedsCurrent96MiBTotalCap: manifest.layers.reduce((n, l) => n + l.size, 0) > 96 * 1024 ** 2,
    npmPositive: 'NOT TESTED; exact package inventory requires separately authorized bounded layer acquisition',
    currentPolicy: 'ordinary Alpine only; archive identity/receipt/local qualification nginx only',
    next: 'Do not widen generic repository/platform/guards. Review an exact Node candidate profile and per-candidate resource envelope, or select a smaller npm-bearing fixture. Verify config, layers/diffIDs, tar budgets, OS support, npm inventory/CVEs, then exact admission/receipt binding in a separate change.' });
} catch {
  evidence.failure = 'Bounded public metadata discovery unavailable; no policy or running resources changed.';
  process.exitCode = 1;
} finally {
  writeFileSync(artifact, JSON.stringify(evidence, null, 2) + '\n');
  console.log(JSON.stringify({ success: evidence.success, artifact: 'server/deploy/proof/task2-npm-remote-candidate.json' }));
}
