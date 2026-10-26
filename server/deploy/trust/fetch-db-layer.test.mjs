import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { manifestDescriptor, saveLayer, fetchDbLayer, parseBlobRedirect, cveTimeout,
  transportFailureDetails, transportFailureReceipt, parseTransportFailureReceipt } from './fetch-db-layer.mjs';
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

async function transportFixture(t) {
  const parent = await mkdtemp(join(tmpdir(), 'cve-transport-offline-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const layer = Buffer.from('disposable offline layer'), bytes = Buffer.from(JSON.stringify(doc(layer)));
  const pin = sha(bytes), destination = join(parent, 'download'), calls = [], logs = [];
  let clock = 0;
  const state = { fail: null, redirect: false, advance: 0, body: null };
  const request = async (url, options) => {
    calls.push({ url, options }); clock += state.advance;
    const boundary = url.includes('/token?') ? 'token' : url.includes('/manifests/') ? 'manifest' : url.startsWith('https://ghcr.io/') ? 'blob' : 'cdn';
    if (state.fail === boundary) return new Response('PRIVATE-UPSTREAM-BODY', { status: 503 });
    if (boundary === 'token') return new Response(JSON.stringify({ token: 'PRIVATE-BEARER-'.repeat(4) }));
    if (boundary === 'manifest') return new Response(bytes, { headers: { 'content-type': 'application/vnd.oci.image.manifest.v1+json', 'docker-content-digest': pin } });
    if (boundary === 'blob' && state.redirect) return new Response(null, { status: 307, headers: { location: 'https://pkg-containers.githubusercontent.com/opaque?signature=PRIVATE-QUERY' } });
    return new Response(state.body ?? layer);
  };
  return { parent, destination, calls, logs, layer, bytes, pin, state, request,
    run: (options = {}, args = [pin, destination]) => fetchDbLayer(args, { request, now: () => clock, log: v => logs.push(v), ...options }),
    advance: value => { clock += value; } };
}
function finiteTransport(boundary, cause, status) {
  return error => {
    const detail = transportFailureDetails(error);
    assert.equal(detail.boundary, boundary); assert.equal(detail.cause, cause);
    if (status) assert.equal(detail.status, status);
    assert(!error.message.includes('PRIVATE')); assert(!JSON.stringify(error).includes('PRIVATE'));
    for (const key of ['cause', 'url', 'stdout', 'stderr', 'headers', 'args']) assert(!Object.hasOwn(error, key));
    assert.deepEqual(parseTransportFailureReceipt(transportFailureReceipt(error) + '\n'), detail);
    return true;
  };
}
for (const name of ['token', 'manifest', 'blob', 'cdn']) test('finite HTTP failure: ' + name + ', without upstream payload or retry', async t => {
  const x = await transportFixture(t); x.state.fail = name; x.state.redirect = name === 'cdn';
  await assert.rejects(x.run(), finiteTransport(name === 'token' ? 'token-body' : name === 'manifest' ? 'manifest-request' : 'blob-request', 'HTTP_STATUS', 503));
  assert.equal(x.calls.length, name === 'token' ? 1 : name === 'manifest' ? 2 : name === 'blob' ? 3 : 4);
  assert.equal(x.logs.length, 0);
  if (name === 'blob' || name === 'cdn') assert.deepEqual(await readdir(x.destination), [], 'failed unsigned directory is preserved, not removed');
});
test('exact pinned layer, single allowlisted redirect, no bearer on CDN and unchanged success receipt', async t => {
  const x = await transportFixture(t); x.state.redirect = true; await x.run();
  assert.deepEqual(await readFile(join(x.destination, 'layer.tar.gz')), x.layer);
  assert.deepEqual(await readFile(join(x.destination, 'manifest.json')), x.bytes);
  assert.equal(x.calls.length, 4); assert(x.calls[2].options.headers.Authorization);
  assert.equal(x.calls[3].options.headers, undefined); assert.equal(x.calls[3].options.redirect, 'manual');
  assert(x.logs[0].startsWith('Downloaded exact OCI manifest ')); assert(!x.logs.join('').includes('PRIVATE'));
});
for (const url of ['http://pkg-containers.githubusercontent.com/x', 'https://other.invalid/x',
  'https://pkg-containers.githubusercontent.com.evil.invalid/x', 'https://user:pass@pkg-containers.githubusercontent.com/x',
  'https://pkg-containers.githubusercontent.com:444/x', 'https://pkg-containers.githubusercontent.com/x#fragment',
  ' https://pkg-containers.githubusercontent.com/x', 'https://pkg-containers.githubusercontent.com/\\x',
  'https://pkg-containers.githubusercontent.com/' + 'x'.repeat(16384)]) test('strict redirect refuses non-allowlisted/ambiguous candidate without network', () => {
  assert.throws(() => parseBlobRedirect(url), finiteTransport('blob-redirect', 'REDIRECT_POLICY'));
});
test('signed query is opaque and explicit default HTTPS port remains compatible', () => {
  assert.equal(parseBlobRedirect('https://pkg-containers.githubusercontent.com/x?sig=a%2Fb'), 'https://pkg-containers.githubusercontent.com/x?sig=a%2Fb');
  assert.equal(parseBlobRedirect('https://pkg-containers.githubusercontent.com:443/x'), 'https://pkg-containers.githubusercontent.com/x');
});
for (const cap of [0, -1, NaN, Infinity, 2147483648]) test('invalid timeout refuses before dispatch: ' + cap, () => {
  assert.throws(() => cveTimeout(cap, 100, 0));
});
test('timeout is integer floor, never zero, and does not extend the absolute deadline', () => {
  assert.equal(cveTimeout(100, 101.75, 2.25), 99);
  assert.throws(() => cveTimeout(100, 10.25, 10));
  assert.throws(() => cveTimeout(100, Infinity, 0)); assert.throws(() => cveTimeout(100, 10, NaN));
});
test('token and manifest share one operation deadline, not a new request budget', async t => {
  const x = await transportFixture(t); x.state.advance = 31000;
  await assert.rejects(x.run({ timeoutMs: 60000 }, ['discover']), finiteTransport('manifest-body', 'TIMEOUT'));
  assert.equal(x.calls.length, 2); assert.equal(x.logs.length, 0);
});
for (const body of [Buffer.from('short'), Buffer.alloc(100), Buffer.alloc(24, 7)]) test('failed layer size/hash preserves partial evidence without manifest publication', async t => {
  const x = await transportFixture(t); x.state.body = body;
  await assert.rejects(x.run(), error => ['SIZE', 'HASH'].includes(transportFailureDetails(error)?.cause));
  assert.deepEqual(await readdir(x.destination), ['layer.tar.gz']); assert.equal(x.calls.length, 3);
});
test('deadline covers streamed body, not just response headers; partial layer remains', async t => {
  const x = await transportFixture(t);
  x.state.body = new ReadableStream({ start(c) { c.enqueue(x.layer.subarray(0, 2)); }, pull(c) { x.advance(1000); c.enqueue(x.layer.subarray(2)); c.close(); } });
  await assert.rejects(x.run({ timeoutMs: 100 }), finiteTransport('blob-body', 'TIMEOUT'));
  assert.deepEqual(await readdir(x.destination), ['layer.tar.gz']);
});
for (const stalled of ['headers', 'body']) test('absolute abort signal bounds a stalled mock ' + stalled + ' without sockets/retry', async t => {
  const x = await transportFixture(t), keepAlive = setTimeout(() => {}, 500);
  t.after(() => clearTimeout(keepAlive));
  let calls = 0;
  const request = async (url, options) => {
    calls++;
    if (stalled === 'headers') return new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => reject(Error('PRIVATE-TIMEOUT')), { once: true }));
    if (url.includes('/blobs/')) return new Response(new ReadableStream({ start(controller) {
      options.signal.addEventListener('abort', () => controller.error(Error('PRIVATE-TIMEOUT')), { once: true });
    } }));
    return x.request(url, options);
  };
  await assert.rejects(x.run({ request, timeoutMs: 30 }), finiteTransport(stalled === 'headers' ? 'token-request' : 'blob-body', 'TIMEOUT'));
  assert.equal(calls, stalled === 'headers' ? 1 : 3);
  if (stalled === 'body') assert.deepEqual(await readdir(x.destination), ['layer.tar.gz']);
});
test('bad args are rejected before token request or filesystem writes', async t => {
  const x = await transportFixture(t);
  for (const args of [[], ['discover', 'extra'], ['stage-latest'], ['not-a-pin', x.destination], [x.pin, 'relative'], [x.pin, x.destination, 'extra']])
    await assert.rejects(x.run({}, args), finiteTransport('arguments', 'VALIDATION'));
  assert.equal(x.calls.length, 0); assert.deepEqual(await readdir(x.parent), []);
});
test('native cause is finite, no error getter or raw error message is read', async t => {
  const x = await transportFixture(t), error = new Proxy({}, { get() { assert.fail('raw getter'); } });
  await assert.rejects(x.run({ request: async () => { throw error; } }), finiteTransport('token-request', 'UNKNOWN'));
  await assert.rejects(x.run({ request: async () => { throw Object.assign(Error('PRIVATE-URL'), { cause: { code: 'ENOTFOUND' } }); } }), finiteTransport('token-request', 'DNS'));
});
for (const httpStatus of [401, 403, 429, 500, 503]) test('HTTP class/status is finite without upstream text: ' + httpStatus, async t => {
  const x = await transportFixture(t);
  await assert.rejects(x.run({ request: async () => new Response('PRIVATE', { status: httpStatus }) }), finiteTransport('token-body', 'HTTP_STATUS', httpStatus));
});
for (const defect of ['manifest-header', 'manifest-json', 'token-limit', 'token-json', 'content-length', 'second-redirect']) test('transport guard remains fail-closed: ' + defect, async t => {
  const x = await transportFixture(t);
  const request = async (url, options) => {
    if (defect === 'token-limit' && url.includes('/token?')) return new Response('x'.repeat(16385));
    if (defect === 'token-json' && url.includes('/token?')) return new Response('PRIVATE-NOT-JSON');
    if (defect === 'manifest-header' && url.includes('/manifests/')) return new Response(x.bytes, { headers: { 'content-type': 'application/vnd.oci.image.manifest.v1+json', 'docker-content-digest': sha('wrong') } });
    if (defect === 'manifest-json' && url.includes('/manifests/')) {
      const b = Buffer.from('PRIVATE-NOT-JSON'); return new Response(b, { headers: { 'content-type': 'application/vnd.oci.image.manifest.v1+json', 'docker-content-digest': sha(b) } });
    }
    if (defect === 'content-length' && url.includes('/blobs/')) return new Response(x.layer, { headers: { 'content-length': 'not-a-number' } });
    if (defect === 'second-redirect' && url.startsWith('https://pkg-containers.')) return new Response(null, { status: 302, headers: { location: 'https://foreign.invalid/PRIVATE' } });
    return x.request(url, options);
  };
  x.state.redirect = defect === 'second-redirect';
  const expected = { 'manifest-header': ['manifest-validation', 'HASH'], 'manifest-json': ['manifest-validation', 'JSON'],
    'token-limit': ['token-body', 'RESPONSE_LIMIT'], 'token-json': ['token-json', 'JSON'], 'content-length': ['blob-body', 'CONTENT_LENGTH'], 'second-redirect': ['blob-request', 'HTTP_STATUS', 302] };
  const args = [defect === 'manifest-json' ? sha('PRIVATE-NOT-JSON') : x.pin, x.destination];
  await assert.rejects(x.run({ request }, args), finiteTransport(...expected[defect]));
  assert(!x.logs.join('').includes('PRIVATE'));
  assert(!x.calls.some(c => c.url.startsWith('https://foreign.invalid/')));
});
test('failure receipt parser is exact, bounded, and cannot carry forged fields', () => {
  const receipt = 'CVE_TRANSPORT_FAILURE ' + JSON.stringify({ version: 1, boundary: 'blob-request', cause: 'HTTP_STATUS', status: 429 }) + '\n';
  assert.equal(parseTransportFailureReceipt(receipt).status, 429);
  for (const text of [receipt + 'PRIVATE', receipt.replace('blob-request', 'PRIVATE'), receipt.replace('429}', '429,"url":"PRIVATE"}'), 'x'.repeat(65537), receipt.trim()]) assert.equal(parseTransportFailureReceipt(text), null);
});
