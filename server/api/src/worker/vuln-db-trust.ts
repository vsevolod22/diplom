import { createHash, createPublicKey } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';

export type DbTrustAnchor = Readonly<{ publicKeyPath: string; expectedSpkiSha256: string }>;

export const PRODUCTION_DB_TRUST_ANCHOR: DbTrustAnchor = Object.freeze({
  publicKeyPath: fileURLToPath(new URL('../../../deploy/trust/db-signing-key.pub.pem', import.meta.url)),
  expectedSpkiSha256: 'd75c6f6b2384de68978090fc837387ab4f3e878ee004bccf27ea98a84fbee078',
});

// Only the separately composed LOCAL entrypoints call this reader. Paths are not configurable.
export function localDbTrustAnchorFromEnv(env: Readonly<NodeJS.ProcessEnv> = process.env): DbTrustAnchor {
  const hash = env.LOCAL_CVE_TRUST_SHA256;
  if (hash === undefined) return PRODUCTION_DB_TRUST_ANCHOR;
  if (typeof hash !== 'string' || hash.length !== 64 || !/^[a-f0-9]{64}$/.test(hash)) throw new Error('Invalid LOCAL CVE trust fingerprint');
  return Object.freeze({ publicKeyPath: '/opt/local-db-trust/public.pem', expectedSpkiSha256: hash });
}

// Host verification may supply an explicit host path; runtime env selection never does.
export function readDbTrustPublicKey(anchor: DbTrustAnchor = PRODUCTION_DB_TRUST_ANCHOR): string {
  const failure = () => new Error('Vulnerability DB trust anchor validation failed');
  try {
    if (!isAbsolute(anchor.publicKeyPath) || anchor.expectedSpkiSha256.length !== 64 ||
        !/^[a-f0-9]{64}$/.test(anchor.expectedSpkiSha256)) throw failure();
    const fd = openSync(anchor.publicKeyPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    let pem: string;
    try {
      const before = fstatSync(fd);
      if (!before.isFile() || before.size < 1 || before.size > 8192) throw failure();
      const bytes = Buffer.alloc(8193);
      let total = 0;
      while (total < bytes.length) {
        const count = readSync(fd, bytes, total, bytes.length - total, null);
        if (!count) break;
        total += count;
      }
      const after = fstatSync(fd);
      if (total > 8192 || total !== before.size || after.size !== before.size ||
          after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || after.ino !== before.ino) throw failure();
      pem = bytes.subarray(0, total).toString('utf8');
    } finally { closeSync(fd); }
    // createPublicKey also accepts private PEMs; reject them before invoking the parser.
    if (!/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END PUBLIC KEY-----\s*$/.test(pem)) throw failure();
    const key = createPublicKey({ key: pem, format: 'pem', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519' ||
        createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex') !== anchor.expectedSpkiSha256) throw failure();
    return pem;
  } catch { throw failure(); }
}
