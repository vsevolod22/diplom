#!/usr/bin/env node
// Operator-side transport only. No signing key or worker credentials are available here.
// A mutable :2 tag is discovery, never the identity used to download a release.
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir, open, lstat, rm } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ORIGIN = 'https://ghcr.io';
const REPO = 'aquasecurity/trivy-db';
const ACCEPT = 'application/vnd.oci.image.manifest.v1+json';
const LAYER = 'application/vnd.aquasec.trivy.db.layer.v1.tar+gzip';
const SHA = /^sha256:[a-f0-9]{64}$/;
const MAX_LAYER = 512 * 1024 * 1024;
const fail = () => new Error('DB transport validation failed');

export function manifestDescriptor(bytes, expected, header) {
  if (!SHA.test(expected) || header !== expected || bytes.length > 65536 ||
      `sha256:${createHash('sha256').update(bytes).digest('hex')}` !== expected) throw fail();
  const doc = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (doc.schemaVersion !== 2 || doc.mediaType !== ACCEPT || doc.artifactType !== 'application/vnd.aquasec.trivy.config.v1+json' ||
      !Array.isArray(doc.layers) || doc.layers.length !== 1 ||
      doc.layers[0].mediaType !== LAYER || !SHA.test(doc.layers[0].digest) ||
      !Number.isSafeInteger(doc.layers[0].size) || doc.layers[0].size < 1 || doc.layers[0].size > MAX_LAYER ||
      !doc.config || doc.config.mediaType !== 'application/vnd.oci.empty.v1+json') throw fail();
  return { digest: doc.layers[0].digest, size: doc.layers[0].size };
}

async function bounded(response, max) {
  if (!response.ok || !response.body || Number(response.headers.get('content-length')) > max) throw fail();
  const pieces = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.byteLength;
    if (size > max) throw fail();
    pieces.push(chunk);
  }
  return Buffer.concat(pieces, size);
}

function endpoint(url) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.port) throw fail();
  return parsed;
}

async function request(url, options = {}) {
  const response = await fetch(url, { ...options, redirect: 'manual', signal: AbortSignal.timeout(180_000) });
  return response;
}

async function token() {
  const url = `${ORIGIN}/token?service=ghcr.io&scope=repository:${REPO}:pull`;
  const bytes = await bounded(await request(url), 16384);
  const parsed = JSON.parse(bytes.toString('utf8'));
  if (!parsed || typeof parsed.token !== 'string' || parsed.token.length < 32 || parsed.token.length > 12000) throw fail();
  return parsed.token;
}

function auth(tokenValue) { return { Authorization: `Bearer ${tokenValue}`, Accept: ACCEPT }; }

async function manifest(reference, bearer) {
  const response = await request(`${ORIGIN}/v2/${REPO}/manifests/${reference}`, { headers: auth(bearer) });
  if (response.status !== 200 || response.headers.get('content-type')?.split(';')[0] !== ACCEPT) throw fail();
  const bytes = await bounded(response, 65536);
  const actual = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  if (response.headers.get('docker-content-digest') !== actual) throw fail();
  return { bytes, actual };
}

async function blobResponse(digest, bearer) {
  const initial = await request(`${ORIGIN}/v2/${REPO}/blobs/${digest}`, { headers: { Authorization: `Bearer ${bearer}` } });
  if (initial.status === 200) return initial;
  if (initial.status !== 307 && initial.status !== 302) throw fail();
  const location = initial.headers.get('location');
  if (!location) throw fail();
  const redirected = endpoint(location);
  // The GHCR blob CDN is distinct from its authenticated registry. Never forward the bearer.
  if (redirected.hostname !== 'pkg-containers.githubusercontent.com') throw fail();
  const final = await request(redirected.href);
  if (final.status !== 200 || !final.body) throw fail();
  return final;
}

export async function saveLayer(response, destination, descriptor) {
  if (response.status !== 200 || !response.body || Number(response.headers.get('content-length')) > descriptor.size) throw fail();
  const fd = await open(destination, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  const sha = createHash('sha256');
  let size = 0;
  try {
    for await (const bytes of response.body) {
      size += bytes.byteLength;
      if (size > descriptor.size || size > MAX_LAYER) throw fail();
      sha.update(bytes);
      await fd.writeFile(bytes);
    }
    if (size !== descriptor.size || `sha256:${sha.digest('hex')}` !== descriptor.digest) throw fail();
    await fd.sync();
  } finally { await fd.close(); }
}

async function main() {
  let [reference, destination] = process.argv.slice(2);
  if (!reference || (reference !== 'discover' && (!destination || !isAbsolute(destination))) ||
      !['discover', 'stage-latest'].includes(reference) && !SHA.test(reference)) throw fail();
  const bearer = await token();
  if (reference === 'discover') {
    const found = await manifest('2', bearer);
    console.log(`Review upstream tag :2, then download by digest: ${found.actual}`);
    return;
  }
  // A timer MAY pre-stage an update, but cannot sign or activate it: the operator
  // must still independently accept the digest and approve the release.
  let pinned = reference;
  if (reference === 'stage-latest') {
    const found = await manifest('2', bearer);
    pinned = found.actual;
    const parent = await lstat(destination);
    if (!parent.isDirectory() || parent.isSymbolicLink()) throw fail();
    const staged = join(destination, pinned);
    try { await lstat(staged); console.log(`Candidate ${pinned} already exists; verify it before reuse.`); return; }
    catch (error) { if (error.code !== 'ENOENT') throw fail(); }
    destination = staged;
  }
  const result = await manifest(pinned, bearer);
  const layer = manifestDescriptor(result.bytes, pinned, result.actual);
  const parent = resolve(dirname(destination));
  const st = await lstat(parent);
  if (!st.isDirectory() || st.isSymbolicLink()) throw fail();
  await mkdir(destination, { mode: 0o700 }); // exclusive: never replace a published release
  try {
    const response = await blobResponse(layer.digest, bearer);
    await saveLayer(response, join(destination, 'layer.tar.gz'), layer);
    const fd = await open(join(destination, 'manifest.json'), constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    try { await fd.writeFile(result.bytes); await fd.sync(); } finally { await fd.close(); }
    console.log(`Downloaded exact OCI manifest ${pinned}, layer ${layer.digest}; unsigned staging only.`);
  } catch {
    await rm(destination, { recursive: true, force: true });
    throw fail();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main().catch(() => { console.error('DB transport validation failed'); process.exitCode = 1; });
