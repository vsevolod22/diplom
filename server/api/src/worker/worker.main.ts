import { spawnSync } from 'node:child_process';
import { createHash, createPublicKey } from 'node:crypto';
import { connect } from 'node:net';
import { writeFileSync, unlinkSync, readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import type { VulnScanOptions } from './vuln-worker.js';
import { ScanLedger } from '../ledger/ledger.js';
import { consumeOne } from './outbox-consumer.js';

const file = process.env.SCAN_LEDGER_PATH;
const ready = process.env.SCAN_WORKER_READY_PATH;
if (!file || !ready || !process.env.TRIVY_CACHE_DIR) throw new Error('Worker storage is required');
const ledger = new ScanLedger(file);
const version = spawnSync('trivy', ['--version'], { stdio: 'ignore', timeout: 5000,
  env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp' } });
if (version.status !== 0) throw new Error('Scanner binary unavailable');

// Only the pinned public key is read by the worker. The private signing key
// remains with the offline operator and is never passed to the scanner.
function vulnConfig(): Omit<VulnScanOptions, 'timeoutMs' | 'signal'> | undefined {
  const releaseDir = process.env.SCAN_VULN_RELEASE_DIR;
  const manifest = process.env.SCAN_VULN_MANIFEST_DIGEST;
  const artifact = process.env.SCAN_VULN_ARTIFACT_SHA256;
  if (process.env.SCAN_VULN_ENABLED !== 'true' || !releaseDir || !isAbsolute(releaseDir) ||
      !/^sha256:[a-f0-9]{64}$/.test(manifest ?? '') || !/^[a-f0-9]{64}$/.test(artifact ?? '')) return undefined;
  try {
    const key = readFileSync(new URL('../../../deploy/trust/db-signing-key.pub.pem', import.meta.url));
    const publicKey = createPublicKey(key);
    if (createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex') !==
        'd75c6f6b2384de68978090fc837387ab4f3e878ee004bccf27ea98a84fbee078') return undefined;
    return { cacheDir: process.env.TRIVY_CACHE_DIR!, releaseDir, trust: {
      trustedPublicKeyPem: key.toString('utf8'), expectedSigner: 'local-db-operator-v1',
      expectedSource: `ghcr.io/aquasecurity/trivy-db@${manifest}`, expectedSchemaVersion: 2,
      expectedManifestDigest: manifest!, expectedArtifactSha256: artifact!,
    } };
  } catch { return undefined; }
}
const vuln = vulnConfig();

function gatewayReady(): Promise<boolean> {
  return new Promise(resolve => {
    const socket = connect({ host: 'egress', port: 8080, timeout: 2000 });
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', () => { socket.destroy(); resolve(false); });
    socket.once('timeout', () => { socket.destroy(); resolve(false); });
  });
}

let stopping = false;
process.on('SIGTERM', () => { stopping = true; });
process.on('SIGINT', () => { stopping = true; });
try {
  while (!stopping) {
    if (!(await gatewayReady())) {
      try { unlinkSync(ready); } catch { /* absent marker */ }
      await new Promise(resolve => setTimeout(resolve, 2000));
      continue;
    }
    // Heartbeat is ephemeral evidence of a live process, not proof of an intact
    // network boundary. Deployment inspection and negative probes are still required.
    writeFileSync(ready, String(Date.now()), { mode: 0o600 });
    await consumeOne(ledger, { timeoutMs: 60_000, dbDir: process.env.TRIVY_CACHE_DIR!, vuln });
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
} finally {
  try { unlinkSync(ready); } catch { /* absent marker */ }
  ledger.close();
}
