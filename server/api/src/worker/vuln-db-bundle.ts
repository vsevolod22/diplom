import { createHash, createPublicKey, timingSafeEqual, verify } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { isAbsolute, join, parse, sep } from 'node:path';

// Envelope preflight only. This does not parse Trivy 0.69.3 metadata, prove DB usability,
// check CVEs, or authorize admission. Never hand the result to an admission decision.
const MAX_DESCRIPTOR_BYTES = 4096;
const MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;
const MAX_DB_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_DOWNLOAD_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_UPDATE_AGE_MS = 48 * 60 * 60 * 1000;
const MAX_UPDATE_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000;
const failure = () => new Error('Vulnerability DB bundle preflight failed');

export type BundlePreflightOptions = {
  directory: string;
  trustedPublicKeyPem: string;
  expectedSigner: string;
  expectedSource: string;
  expectedSchemaVersion: number;
  expectedArtifactSha256: string;
  expectedManifestDigest: string;
  now?: Date;
};

export type VerifiedDbIdentity = {
  envelopeVersion: number;
  signer: string;
  source: string;
  schemaVersion: number;
  artifactSha256: string;
  metadataSha256: string;
  dbSha256: string;
  manifestDigest: string;
  updatedAt: string;
  downloadedAt: string;
  nextUpdate: string;
};

function timestamp(value: unknown): number {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,9}Z$/.test(value)) throw failure();
  const millis = value.replace(/\.(\d{1,9})Z$/, (_, fraction: string) => `.${fraction.padEnd(3, '0').slice(0, 3)}Z`);
  const time = Date.parse(millis);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== millis) throw failure();
  return time;
}

// Shared at-use/write-boundary policy; identity alone is not cryptographic verification.
export function assertDbFreshness(descriptor: Pick<VerifiedDbIdentity, 'updatedAt' | 'downloadedAt' | 'nextUpdate'>, now = Date.now()): void {
  const updated = timestamp(descriptor.updatedAt), downloaded = timestamp(descriptor.downloadedAt), next = timestamp(descriptor.nextUpdate);
  if (!Number.isFinite(now) || updated > now + MAX_CLOCK_SKEW_MS || downloaded > now + MAX_CLOCK_SKEW_MS ||
      downloaded < updated || now - updated > MAX_UPDATE_AGE_MS || now - downloaded > MAX_DOWNLOAD_AGE_MS ||
      next <= updated || next - updated > MAX_UPDATE_INTERVAL_MS || now >= next) throw failure();
}

async function rejectSymlinkAncestors(directory: string): Promise<void> {
  if (!isAbsolute(directory) || directory !== parse(directory).root && directory.endsWith(sep)) throw failure();
  let current = parse(directory).root;
  for (const part of directory.slice(current.length).split(sep).filter(Boolean)) {
    if (part === '.' || part === '..') throw failure();
    current = join(current, part);
    const stat = await lstat(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw failure();
  }
}

// Open with NOFOLLOW; reject non-regular files and read at most the configured cap.
// The same descriptor and artifact file descriptors are checked before and after reading.
async function readBounded(path: string, limit: number, hashOnly = false): Promise<Buffer> {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat();
    if (!before.isFile() || before.size < 1 || before.size > limit) throw failure();
    const chunks: Buffer[] = [];
    const hash = hashOnly ? createHash('sha256') : null;
    let total = 0;
    while (true) {
      const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, limit + 1 - total));
      const { bytesRead } = await file.read(chunk, 0, chunk.length, null);
      if (!bytesRead) break;
      total += bytesRead;
      if (total > limit) throw failure();
      if (hash) hash.update(chunk.subarray(0, bytesRead));
      else chunks.push(chunk.subarray(0, bytesRead));
    }
    const after = await file.stat();
    if (total !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || after.ino !== before.ino) throw failure();
    return hash ? hash.digest() : Buffer.concat(chunks, total);
  } finally {
    await file.close();
  }
}

/** Fixed files: descriptor.json (canonical UTF-8 JSON), descriptor.sig (raw 64-byte Ed25519 signature), bundle.bin. */
export async function preflightVulnDbBundle(options: BundlePreflightOptions): Promise<{
  kind: 'envelope-preflight-only'; artifactSha256: string; schemaVersion: number; identity: Readonly<VerifiedDbIdentity>;
}> {
  try {
    const { directory, expectedSigner, expectedSource, expectedSchemaVersion, expectedArtifactSha256, expectedManifestDigest } = options;
    if (typeof directory !== 'string' || typeof expectedSigner !== 'string' || !expectedSigner ||
        typeof expectedSource !== 'string' || !expectedSource ||
        !Number.isSafeInteger(expectedSchemaVersion) || expectedSchemaVersion < 1 ||
        typeof expectedArtifactSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(expectedArtifactSha256) ||
                typeof expectedManifestDigest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(expectedManifestDigest) ||
                !expectedSource.endsWith(`@${expectedManifestDigest}`)) throw failure();
    const now = (options.now ?? new Date()).getTime();
    if (!Number.isFinite(now)) throw failure();
    const key = createPublicKey(options.trustedPublicKeyPem);
    if (key.asymmetricKeyType !== 'ed25519') throw failure();
    await rejectSymlinkAncestors(directory);
    await rejectSymlinkAncestors(join(directory, 'db'));
    const descriptorBytes = await readBounded(join(directory, 'descriptor.json'), MAX_DESCRIPTOR_BYTES);
    const signature = await readBounded(join(directory, 'descriptor.sig'), 64);
    if (signature.length !== 64 || !verify(null, descriptorBytes, key, signature)) throw failure();
    const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(descriptorBytes));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw failure();
    const value = parsed as Record<string, unknown>;
    // Exact serialization disallows extra/duplicate fields, noncanonical encodings and key reordering.
    const descriptor: VerifiedDbIdentity = {
      envelopeVersion: value.envelopeVersion as number,
      signer: value.signer as string,
      source: value.source as string,
      schemaVersion: value.schemaVersion as number,
      artifactSha256: value.artifactSha256 as string,
      metadataSha256: value.metadataSha256 as string,
      dbSha256: value.dbSha256 as string,
      manifestDigest: value.manifestDigest as string,
      updatedAt: value.updatedAt as string,
      downloadedAt: value.downloadedAt as string,
      nextUpdate: value.nextUpdate as string,
    };
    if (JSON.stringify(descriptor) !== descriptorBytes.toString('utf8') ||
        descriptor.envelopeVersion !== 1 || descriptor.signer !== expectedSigner ||
        descriptor.source !== expectedSource || descriptor.schemaVersion !== expectedSchemaVersion ||
        descriptor.manifestDigest !== expectedManifestDigest ||
        !/^[a-f0-9]{64}$/.test(descriptor.artifactSha256) ||
        !/^[a-f0-9]{64}$/.test(descriptor.metadataSha256) ||
                !/^[a-f0-9]{64}$/.test(descriptor.dbSha256)) throw failure();
    const metadataBytes = await readBounded(join(directory, 'db', 'metadata.json'), 4096);
    const metadataHash = createHash('sha256').update(metadataBytes).digest();
    if (!timingSafeEqual(metadataHash, Buffer.from(descriptor.metadataSha256, 'hex'))) throw failure();
    const metadata: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(metadataBytes));
    if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) throw failure();
    const db = metadata as Record<string, unknown>;
    if (db.Version !== descriptor.schemaVersion || db.UpdatedAt !== descriptor.updatedAt ||
        db.DownloadedAt !== descriptor.downloadedAt || db.NextUpdate !== descriptor.nextUpdate) throw failure();
    assertDbFreshness(descriptor, now);
    const pinnedHash = Buffer.from(expectedArtifactSha256, 'hex');
    if (!timingSafeEqual(Buffer.from(descriptor.artifactSha256, 'hex'), pinnedHash)) throw failure();
    const artifactHash = await readBounded(join(directory, 'bundle.bin'), MAX_ARTIFACT_BYTES, true);
    if (!timingSafeEqual(artifactHash, pinnedHash)) throw failure();
    // Bind the actual read-only cache bytes too; gzip integrity alone says nothing about extracted DB.
    const dbHash = await readBounded(join(directory, 'db', 'trivy.db'), MAX_DB_BYTES, true);
    if (!timingSafeEqual(dbHash, Buffer.from(descriptor.dbSha256, 'hex'))) throw failure();
    // Hashing the real DB can cross NextUpdate; initial preflight time is not sufficient.
    assertDbFreshness(descriptor, options.now?.getTime() ?? Date.now());
    return { kind: 'envelope-preflight-only', artifactSha256: expectedArtifactSha256, schemaVersion: expectedSchemaVersion, identity: Object.freeze(descriptor) };
  } catch {
    // Never leak raw paths, descriptor contents, signature verification or filesystem errors.
    throw failure();
  }
}
