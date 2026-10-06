import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { dbProofConfig, type DbProofConfig } from './nginx-db-proof-profile.js';

function fixture() {
  const { publicKey } = generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const config: DbProofConfig = { keyFingerprint: createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex'),
    manifestDigest: `sha256:${'a'.repeat(64)}`, artifactSha256: 'b'.repeat(64), phase: 'normal' };
  return { pem, config };
}
test('disposable trust stays separately identified with fixed path/schema/signer', () => {
  const { pem, config } = fixture();
  const result = dbProofConfig(config, pem);
  assert.equal(result.vuln.releaseDir, '/opt/release'); assert.equal(result.vuln.cacheDir, '/tmp/trivy');
  assert.equal(result.vuln.trust.expectedSchemaVersion, 2); assert.equal(result.vuln.trust.expectedSigner, 'local-db-operator-v1');
  assert.equal('now' in result.vuln.trust, false);
  assert.equal(result.vuln.trust.expectedSource, `ghcr.io/aquasecurity/trivy-db@${config.manifestDigest}`);
  for (const bad of [{ ...config, keyFingerprint: 'c'.repeat(64) }, { ...config, phase: 'clock' },
    { ...config, now: 'fake' }, { ...config, manifestDigest: 'latest' }, { ...config, releaseDir: '/foreign' }]) {
    assert.throws(() => dbProofConfig(bad as DbProofConfig, pem));
  }
  assert.throws(() => dbProofConfig(config, fixture().pem));
});
test('production entrypoints never import test trust, and production anchor cannot be a fixture key', async () => {
  for (const file of ['../app.module.ts', '../worker/worker.main.ts', './nginx-proof.main.ts']) {
    const content = await readFile(new URL(file, import.meta.url), 'utf8');
    assert.equal(content.includes('nginx-db-proof'), false);
  }
  const pem = await readFile(new URL('../../../deploy/trust/db-signing-key.pub.pem', import.meta.url), 'utf8');
  const { config } = fixture();
  const keyFingerprint = createHash('sha256').update((await import('node:crypto')).createPublicKey(pem).export({ type: 'spki', format: 'der' })).digest('hex');
  assert.throws(() => dbProofConfig({ ...config, keyFingerprint }, pem));
});
