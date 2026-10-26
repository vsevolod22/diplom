#!/usr/bin/env node
// Operator-side transport only. No signing key or worker credentials are available here.
// A mutable :2 tag is discovery, never the identity used to download a release.
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir, open, lstat } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ORIGIN = 'https://ghcr.io';
const REPO = 'aquasecurity/trivy-db';
const ACCEPT = 'application/vnd.oci.image.manifest.v1+json';
const LAYER = 'application/vnd.aquasec.trivy.db.layer.v1.tar+gzip';
const SHA = /^sha256:[a-f0-9]{64}(?![\s\S])/;
const MAX_LAYER = 512 * 1024 * 1024;
const BOUNDARIES = ['arguments', 'deadline', 'token-request', 'token-body', 'token-json', 'manifest-request', 'manifest-body',
  'manifest-validation', 'blob-request', 'blob-redirect', 'blob-body', 'destination', 'layer-write', 'layer-validation', 'manifest-write'];
const CAUSES = ['VALIDATION', 'TIMEOUT', 'DNS', 'CONNECT', 'TLS', 'NETWORK', 'HTTP_STATUS', 'REDIRECT_POLICY',
  'RESPONSE_LIMIT', 'CONTENT_LENGTH', 'JSON', 'MANIFEST', 'SIZE', 'HASH', 'FILESYSTEM_IO', 'UNKNOWN'];
const failures = new WeakMap();
const own = (v, k) => v && typeof v === 'object' ? Object.getOwnPropertyDescriptor(v, k)?.value : undefined;
function fail(boundary = 'manifest-validation', cause = 'VALIDATION', status) {
  if (!BOUNDARIES.includes(boundary) || !CAUSES.includes(cause)) { boundary = 'arguments'; cause = 'UNKNOWN'; }
  const detail = Object.freeze({ version: 1, boundary, cause,
    ...(cause === 'HTTP_STATUS' && Number.isInteger(status) && status >= 100 && status <= 599 ? { status } : {}) });
  const error = Error('DB transport validation failed'); failures.set(error, detail); return error;
}
export function transportFailureDetails(error) { return failures.get(error) ?? null; }
export function transportFailureReceipt(error) {
  return 'CVE_TRANSPORT_FAILURE ' + JSON.stringify(transportFailureDetails(error) ?? { version: 1, boundary: 'arguments', cause: 'UNKNOWN' });
}
export function parseTransportFailureReceipt(text) {
  if (typeof text !== 'string' || text.length > 512 || !text.startsWith('CVE_TRANSPORT_FAILURE ') || !text.endsWith('\n')) return null;
  try {
    const d = JSON.parse(text.slice(22, -1));
    if (!d || d.version !== 1 || !BOUNDARIES.includes(d.boundary) || !CAUSES.includes(d.cause)) return null;
    const status = d.status;
    const canonical = { version: 1, boundary: d.boundary, cause: d.cause,
      ...(d.cause === 'HTTP_STATUS' && Number.isInteger(status) && status >= 100 && status <= 599 ? { status } : {}) };
    return text === 'CVE_TRANSPORT_FAILURE ' + JSON.stringify(canonical) + '\n' ? Object.freeze(canonical) : null;
  } catch { return null; }
}
export function cveTimeout(cap, deadline, now) {
  if (![cap, deadline, now].every(Number.isFinite) || cap < 1 || cap > 2147483647) throw fail('deadline', 'TIMEOUT');
  const ms = Math.floor(Math.min(cap, deadline - now));
  if (ms < 1) throw fail('deadline', 'TIMEOUT');
  return ms;
}
function nativeCause(error) {
  const code = own(error, 'code') ?? own(own(error, 'cause'), 'code');
  if (['ENOTFOUND', 'EAI_AGAIN'].includes(code)) return 'DNS';
  if (['ECONNREFUSED', 'UND_ERR_CONNECT_TIMEOUT'].includes(code)) return 'CONNECT';
  if (['ETIMEDOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT'].includes(code)) return 'TIMEOUT';
  if (['CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'ERR_TLS_CERT_ALTNAME_INVALID'].includes(code)) return 'TLS';
  if (['ECONNRESET', 'EPIPE', 'UND_ERR_SOCKET'].includes(code)) return 'NETWORK';
  if (['EIO', 'ENOSPC', 'EACCES', 'EPERM', 'ENOENT', 'EEXIST', 'ELOOP'].includes(code)) return 'FILESYSTEM_IO';
  return 'UNKNOWN';
}
async function step(boundary, work, context, response) {
  try { context?.tick(boundary); return await work(); }
  catch (error) {
    if (failures.has(error)) throw error;
    throw fail(boundary, context?.aborted(response) ? 'TIMEOUT' : nativeCause(error));
  }
}
function ensure(ok, boundary, cause = 'VALIDATION') { if (!ok) throw fail(boundary, cause); }

export function manifestDescriptor(bytes, expected, header) {
  ensure(SHA.test(expected) && header === expected && bytes.length <= 65536, 'manifest-validation', 'MANIFEST');
  ensure(`sha256:${createHash('sha256').update(bytes).digest('hex')}` === expected, 'manifest-validation', 'HASH');
  let doc; try { doc = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw fail('manifest-validation', 'JSON'); }
  ensure(doc?.schemaVersion === 2 && doc.mediaType === ACCEPT && doc.artifactType === 'application/vnd.aquasec.trivy.config.v1+json' &&
    Array.isArray(doc.layers) && doc.layers.length === 1 && doc.layers[0].mediaType === LAYER && SHA.test(doc.layers[0].digest) &&
    Number.isSafeInteger(doc.layers[0].size) && doc.layers[0].size >= 1 && doc.layers[0].size <= MAX_LAYER &&
    doc.config?.mediaType === 'application/vnd.oci.empty.v1+json', 'manifest-validation', 'MANIFEST');
  return { digest: doc.layers[0].digest, size: doc.layers[0].size };
}
function lengthBound(response, max, boundary) {
  const length = response.headers.get('content-length');
  ensure(length === null || /^\d{1,16}$/.test(length), boundary, 'CONTENT_LENGTH');
  ensure(length === null || Number(length) <= max, boundary, 'RESPONSE_LIMIT');
}
async function status(response, boundary) {
  if (response.status === 200) return;
  try { await response.body?.cancel(); } catch { /* No body is diagnostic evidence. */ }
  throw fail(boundary, 'HTTP_STATUS', response.status);
}
async function bounded(response, max, boundary, context) {
  return step(boundary, async () => {
    await status(response, boundary); ensure(response.body, boundary); lengthBound(response, max, boundary);
    const pieces = []; let size = 0;
    for await (const chunk of response.body) {
      context?.tick(boundary); size += chunk.byteLength;
      ensure(size <= max, boundary, 'RESPONSE_LIMIT'); pieces.push(chunk);
    }
    context?.tick(boundary); return Buffer.concat(pieces, size);
  }, context, response);
}
export function parseBlobRedirect(url) {
  ensure(typeof url === 'string' && url.length > 0 && url.length <= 16384 && !/[\\\x00-\x20\x7f#]/.test(url), 'blob-redirect', 'REDIRECT_POLICY');
  let parsed; try { parsed = new URL(url); } catch { throw fail('blob-redirect', 'REDIRECT_POLICY'); }
  ensure(parsed.protocol === 'https:' && !parsed.username && !parsed.password && !/^https:\/\/[^/?#]*@/i.test(url) && !parsed.port &&
    parsed.hostname === 'pkg-containers.githubusercontent.com', 'blob-redirect', 'REDIRECT_POLICY');
  return parsed.href; // Signed query stays opaque; never logged or forwarded with bearer.
}
function transportContext(request, now, budget) {
  const start = now(), deadline = start + budget;
  cveTimeout(budget, deadline, start);
  const signal = AbortSignal.timeout(budget), responses = new WeakMap();
  return {
    tick(boundary) { const current = now(); if (signal.aborted || !Number.isFinite(current) || deadline - current < 1) throw fail(boundary, 'TIMEOUT'); },
    aborted(response) { return signal.aborted || Boolean(response && responses.get(response)?.aborted); },
    async request(url, options, boundary) {
      const timeout = cveTimeout(180000, deadline, now()), combined = AbortSignal.any([signal, AbortSignal.timeout(timeout)]);
      try {
        const response = await request(url, { ...options, redirect: 'manual', signal: combined });
        responses.set(response, combined); return response;
      } catch (error) { throw fail(boundary, combined.aborted ? 'TIMEOUT' : nativeCause(error)); }
    },
  };
}
async function token(context) {
  const response = await context.request(`${ORIGIN}/token?service=ghcr.io&scope=repository:${REPO}:pull`, {}, 'token-request');
  const bytes = await bounded(response, 16384, 'token-body', context);
  let parsed; try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw fail('token-json', 'JSON'); }
  ensure(parsed && typeof parsed.token === 'string' && parsed.token.length >= 32 && parsed.token.length <= 12000, 'token-json');
  return parsed.token;
}
function auth(bearer) { return { Authorization: `Bearer ${bearer}`, Accept: ACCEPT }; }
async function manifest(reference, bearer, context) {
  const response = await context.request(`${ORIGIN}/v2/${REPO}/manifests/${reference}`, { headers: auth(bearer) }, 'manifest-request');
  await status(response, 'manifest-request');
  ensure(response.headers.get('content-type')?.split(';')[0] === ACCEPT, 'manifest-validation', 'MANIFEST');
  const bytes = await bounded(response, 65536, 'manifest-body', context), actual = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  ensure(response.headers.get('docker-content-digest') === actual, 'manifest-validation', 'HASH');
  return { bytes, actual };
}
async function blobResponse(digest, bearer, context) {
  const initial = await context.request(`${ORIGIN}/v2/${REPO}/blobs/${digest}`, { headers: { Authorization: `Bearer ${bearer}` } }, 'blob-request');
  if (initial.status === 200) return initial;
  if (initial.status !== 307 && initial.status !== 302) await status(initial, 'blob-request');
  const location = initial.headers.get('location');
  try { await initial.body?.cancel(); } catch { /* No upstream body retention. */ }
  const redirected = parseBlobRedirect(location);
  const final = await context.request(redirected, {}, 'blob-request'); // No bearer on CDN, no second redirect.
  await status(final, 'blob-request'); return final;
}

export async function saveLayer(response, destination, descriptor, context) {
  return step('blob-body', async () => {
    await status(response, 'blob-body'); ensure(response.body && SHA.test(descriptor.digest) && Number.isSafeInteger(descriptor.size) && descriptor.size >= 1 && descriptor.size <= MAX_LAYER, 'layer-validation', 'SIZE');
    lengthBound(response, descriptor.size, 'blob-body');
    const fd = await step('layer-write', () => open(destination, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600), context);
    const sha = createHash('sha256'); let size = 0;
    try {
      for await (const bytes of response.body) {
        context?.tick('blob-body'); size += bytes.byteLength;
        ensure(size <= descriptor.size && size <= MAX_LAYER, 'layer-validation', 'SIZE'); sha.update(bytes);
        await step('layer-write', () => fd.writeFile(bytes), context);
      }
      context?.tick('blob-body'); ensure(size === descriptor.size, 'layer-validation', 'SIZE');
      ensure(`sha256:${sha.digest('hex')}` === descriptor.digest, 'layer-validation', 'HASH');
      await step('layer-write', () => fd.sync(), context);
    } finally { await fd.close(); }
  }, context, response);
}

export async function fetchDbLayer(argv, { request = fetch, now = () => performance.now(), timeoutMs, log = console.log } = {}) {
  ensure(Array.isArray(argv), 'arguments');
  const [reference, requestedDestination] = argv;
  ensure(argv.every(v => typeof v === 'string') && (reference === 'discover' ? argv.length === 1 : argv.length === 2 &&
    (reference === 'stage-latest' || SHA.test(reference)) && isAbsolute(requestedDestination) && resolve(requestedDestination) === requestedDestination && !/[\x00-\x1f\x7f]/.test(requestedDestination)), 'arguments');
  const budget = timeoutMs ?? (reference === 'discover' ? 60000 : 240000);
  ensure(Number.isInteger(budget) && budget >= 1 && budget <= (reference === 'discover' ? 60000 : 240000), 'arguments');
  const context = transportContext(request, now, budget), bearer = await token(context);
  if (reference === 'discover') {
    const found = await manifest('2', bearer, context);
    log(`Review upstream tag :2, then download by digest: ${found.actual}`); return;
  }
  let pinned = reference, destination = requestedDestination;
  if (reference === 'stage-latest') {
    const found = await manifest('2', bearer, context); pinned = found.actual;
    await step('destination', async () => {
      const parent = await lstat(destination); ensure(parent.isDirectory() && !parent.isSymbolicLink(), 'destination');
    }, context);
    const staged = join(destination, pinned);
    let exists = false;
    await step('destination', async () => { try { await lstat(staged); exists = true; } catch (error) { if (own(error, 'code') !== 'ENOENT') throw error; } }, context);
    if (exists) { log(`Candidate ${pinned} already exists; verify it before reuse.`); return; }
    destination = staged;
  }
  const result = await manifest(pinned, bearer, context), layer = manifestDescriptor(result.bytes, pinned, result.actual);
  await step('destination', async () => {
    const parent = await lstat(resolve(dirname(destination))); ensure(parent.isDirectory() && !parent.isSymbolicLink(), 'destination');
    await mkdir(destination, { mode: 0o700 });
  }, context);
  // Preserve every partial failure. Only the separate reviewed operator
  // disposition may move an EMPTY parent workspace; no downloader rm/adoption.
  const response = await blobResponse(layer.digest, bearer, context);
  await saveLayer(response, join(destination, 'layer.tar.gz'), layer, context);
  await step('manifest-write', async () => {
    const fd = await open(join(destination, 'manifest.json'), constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    try { await fd.writeFile(result.bytes); await fd.sync(); } finally { await fd.close(); }
  }, context);
  log(`Downloaded exact OCI manifest ${pinned}, layer ${layer.digest}; unsigned staging only.`);
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  fetchDbLayer(process.argv.slice(2)).catch(error => { console.error(transportFailureReceipt(error)); process.exitCode = 1; });
