import { createHash, createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { LedgerStore } from '../ledger/ledger-store.js';
import type { OciResolver } from './oci-resolver.js';
import { NginxProofScansService } from './nginx-proof-profile.js';
import { preflightVulnDbBundle } from '../worker/vuln-db-bundle.js';
import type { VulnScanOptions } from '../worker/vuln-worker.js';

const productionFingerprint = 'd75c6f6b2384de68978090fc837387ab4f3e878ee004bccf27ea98a84fbee078';
export type DbProofConfig = { keyFingerprint: string; manifestDigest: string; artifactSha256: string;
  phase: 'normal' | 'queued' | 'during' | 'precommit' };

// This module is imported only by dedicated proof entrypoints, never selected by
// production environment flags. The public test key is independently identified.
export async function readDbProofConfig(): Promise<{ config: DbProofConfig; vuln: Omit<VulnScanOptions, 'timeoutMs' | 'signal'> }> {
  const config = JSON.parse(await readFile('/proof/db-proof.json', 'utf8')) as DbProofConfig;
  const pem = await readFile('/proof/test-key.pub.pem', 'utf8');
  return dbProofConfig(config, pem);
}
export function dbProofConfig(config: DbProofConfig, pem: string) {
  const key = createPublicKey(pem);
  const fingerprint = createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
  if (!config || Object.keys(config).sort().join(',') !== 'artifactSha256,keyFingerprint,manifestDigest,phase' ||
      key.asymmetricKeyType !== 'ed25519' || fingerprint === productionFingerprint || fingerprint !== config.keyFingerprint ||
      !/^sha256:[a-f0-9]{64}$/.test(config.manifestDigest) || !/^[a-f0-9]{64}$/.test(config.artifactSha256) ||
      !['normal', 'queued', 'during', 'precommit'].includes(config.phase)) throw new Error('Invalid disposable DB proof');
  const vuln = { cacheDir: '/tmp/trivy', releaseDir: '/opt/release', trust: {
    trustedPublicKeyPem: pem, expectedSigner: 'local-db-operator-v1',
    expectedSource: `ghcr.io/aquasecurity/trivy-db@${config.manifestDigest}`, expectedSchemaVersion: 2,
    expectedManifestDigest: config.manifestDigest, expectedArtifactSha256: config.artifactSha256,
  } };
  return { config, vuln };
}
export class NginxDbProofScansService extends NginxProofScansService {
  constructor(ledger: LedgerStore, resolver: OciResolver, private readonly dbOptions: Omit<VulnScanOptions, 'timeoutMs' | 'signal'>) {
    super(ledger, resolver);
  }
  protected override async vulnDbReady(): Promise<boolean> {
    try { await preflightVulnDbBundle({ ...this.dbOptions.trust, directory: this.dbOptions.releaseDir }); return true; }
    catch { return false; }
  }
}
