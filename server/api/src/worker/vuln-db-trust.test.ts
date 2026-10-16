import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { type TestContext } from 'node:test';
import { localDbTrustAnchorFromEnv, PRODUCTION_DB_TRUST_ANCHOR, readDbTrustPublicKey } from './vuln-db-trust.js';

function fixture(t: TestContext) {
  const directory = mkdtempSync(join(tmpdir(), 'db-trust-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const { publicKey } = generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const publicKeyPath = join(directory, 'public.pem');
  const expectedSpkiSha256 = createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
  writeFileSync(publicKeyPath, pem);
  return { directory, pem, anchor: Object.freeze({ publicKeyPath, expectedSpkiSha256 }) };
}
const fail = { message: 'Vulnerability DB trust anchor validation failed' };

test('explicit host path accepts only the matching Ed25519 SPKI fingerprint, not the PEM hash', t => {
  const { anchor, pem } = fixture(t);
  assert.equal(readDbTrustPublicKey(anchor), pem);
  for (const expectedSpkiSha256 of ['0'.repeat(64), createHash('sha256').update(pem).digest('hex'),
    anchor.expectedSpkiSha256.toUpperCase(), anchor.expectedSpkiSha256 + '\n']) {
    assert.throws(() => readDbTrustPublicKey({ ...anchor, expectedSpkiSha256 }), fail);
  }
});

test('non-Ed25519 public keys are rejected even with the correct SPKI hash', t => {
  const { anchor } = fixture(t);
  for (const publicKey of [generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey,
    generateKeyPairSync('ed448').publicKey]) {
    writeFileSync(anchor.publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }));
    const expectedSpkiSha256 = createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    assert.throws(() => readDbTrustPublicKey({ ...anchor, expectedSpkiSha256 }), fail);
  }
});

test('rejects private labels, mixed/trailing PEM blocks and malformed PEM before public-key parsing', t => {
  const { anchor, pem } = fixture(t);
  for (const value of ['-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n',
    '-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n',
    pem + pem, pem + 'untrusted trailing bytes', pem.replace('MCow', '!!!!'), '']) {
    writeFileSync(anchor.publicKeyPath, value);
    assert.throws(() => readDbTrustPublicKey(anchor), fail);
  }
});

test('public PEM read is bounded to 8192 bytes inclusive', t => {
  const { anchor, pem } = fixture(t);
  const bounded = pem.padEnd(8192, '\n');
  writeFileSync(anchor.publicKeyPath, bounded);
  assert.equal(readDbTrustPublicKey(anchor), bounded);
  writeFileSync(anchor.publicKeyPath, bounded + '\n');
  assert.throws(() => readDbTrustPublicKey(anchor), fail);
});

test('missing, nonregular and symlinked public-key paths fail closed without leaking paths', t => {
  const { anchor, directory } = fixture(t);
  const link = join(directory, 'link.pem'), folder = join(directory, 'folder');
  symlinkSync(anchor.publicKeyPath, link);
  mkdirSync(folder);
  for (const publicKeyPath of [link, folder, join(directory, 'missing.pem'), 'relative.pem']) {
    assert.throws(() => readDbTrustPublicKey({ ...anchor, publicKeyPath }), error => {
      assert.ok(error instanceof Error);
      assert.equal(error.message, fail.message);
      assert.equal(error.cause, undefined);
      return true;
    });
  }
});

test('LOCAL env reads only the hash, fixes the mount path, freezes selection and defaults to the unchanged production anchor', () => {
  assert.ok(Object.isFrozen(PRODUCTION_DB_TRUST_ANCHOR));
  assert.equal(PRODUCTION_DB_TRUST_ANCHOR.expectedSpkiSha256,
    'd75c6f6b2384de68978090fc837387ab4f3e878ee004bccf27ea98a84fbee078');
  assert.ok(PRODUCTION_DB_TRUST_ANCHOR.publicKeyPath.endsWith('/deploy/trust/db-signing-key.pub.pem'));
  assert.equal(localDbTrustAnchorFromEnv({}), PRODUCTION_DB_TRUST_ANCHOR);
  const reads: PropertyKey[] = [];
  const env = new Proxy({ LOCAL_CVE_TRUST_SHA256: 'a'.repeat(64), LOCAL_CVE_TRUST_PATH: '/not/allowed.pem' }, {
    get(target, key, receiver) { reads.push(key); return Reflect.get(target, key, receiver); },
  });
  const anchor = localDbTrustAnchorFromEnv(env);
  assert.deepEqual(reads, ['LOCAL_CVE_TRUST_SHA256']);
  assert.deepEqual(anchor, { publicKeyPath: '/opt/local-db-trust/public.pem', expectedSpkiSha256: 'a'.repeat(64) });
  assert.ok(Object.isFrozen(anchor));
});

test('every invalid present LOCAL hash throws rather than falling back, including empty and trailing newline', () => {
  for (const hash of ['', 'A'.repeat(64), 'g'.repeat(64), 'a'.repeat(63), 'a'.repeat(65),
    ' a'.repeat(32), 'a'.repeat(64) + '\n', 'sha256:' + 'a'.repeat(64)]) {
    assert.throws(() => localDbTrustAnchorFromEnv({ LOCAL_CVE_TRUST_SHA256: hash }), { message: 'Invalid LOCAL CVE trust fingerprint' });
  }
});
