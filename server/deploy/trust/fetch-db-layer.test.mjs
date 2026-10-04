import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { manifestDescriptor, saveLayer } from './fetch-db-layer.mjs';
const sha = b => `sha256:${createHash('sha256').update(b).digest('hex')}`;
const doc = layer => ({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json',
  artifactType: 'application/vnd.aquasec.trivy.config.v1+json',
  config: { mediaType: 'application/vnd.oci.empty.v1+json', size: 2, digest: sha('{}') },
  layers: [{ mediaType: 'application/vnd.aquasec.trivy.db.layer.v1.tar+gzip', digest: sha(layer), size: layer.length }] });
test('OCI manifest bytes, header, layer shape and bounds are bound to the pin', () => {
  const layer = Buffer.from('test compressed bytes');
  const json = Buffer.from(JSON.stringify(doc(layer)));
  assert.deepEqual(manifestDescriptor(json, sha(json), sha(json)), { digest: sha(layer), size: layer.length });
  for (const [bytes, expected, header] of [
    [json, sha('other'), sha(json)], [json, sha(json), sha('other')],
    [Buffer.from(JSON.stringify({ ...doc(layer), layers: [] })), sha(json), sha(json)],
    [Buffer.from(JSON.stringify({ ...doc(layer), layers: [doc(layer).layers[0], doc(layer).layers[0]] })), sha(json), sha(json)],
    [Buffer.from(JSON.stringify({ ...doc(layer), layers: [{ ...doc(layer).layers[0], size: 600 * 1024 ** 2 }] })), sha(json), sha(json)],
  ]) assert.throws(() => manifestDescriptor(bytes, expected, header));
});
test('layer is accepted only when complete and hash-matched', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ghcr-layer-'));
  const layer = Buffer.from('content');
  try {
    const path = join(directory, 'layer.tar.gz');
    await saveLayer(new Response(layer), path, { digest: sha(layer), size: layer.length });
    assert.deepEqual(await readFile(path), layer);
    await assert.rejects(saveLayer(new Response(layer), path, { digest: sha(layer), size: layer.length }));
    await assert.rejects(saveLayer(new Response(layer), join(directory, 'truncated'), { digest: sha(layer), size: layer.length + 1 }));
    await assert.rejects(saveLayer(new Response(layer), join(directory, 'wrong'), { digest: sha('wrong'), size: layer.length }));
    await assert.rejects(saveLayer(new Response(layer), join(directory, 'large'), { digest: sha(layer), size: layer.length - 1 }));
  } finally { await rm(directory, { recursive: true, force: true }); }
});
