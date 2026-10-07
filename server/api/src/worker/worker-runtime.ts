import { spawnSync } from 'node:child_process';
import { createHash, createPublicKey } from 'node:crypto';
import { connect } from 'node:net';
import { writeFileSync, unlinkSync, readFileSync, constants, openSync, closeSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import type { VulnScanOptions } from './vuln-worker.js';
import { ScanLedger } from '../ledger/ledger.js';
import { consumeOne } from './outbox-consumer.js';
import { recoverArchiveScratch } from '../oci/bounded-image-archive.js';
import { NGINX_LOCAL_POLICY } from '../oci/nginx-local-policy.js';

const localReady = '/data/nginx-local.ready';
function marker(path: string, text: string) {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(fd, text); } finally { closeSync(fd); }
}
export function localResourceEnvelope(read = (name: string) => readFileSync(`/sys/fs/cgroup/${name}`, 'utf8').trim()): boolean {
  return read('memory.max') === '1073741824' && read('memory.swap.max') === '0' &&
    read('cpu.max') === '100000 100000' && read('pids.max') === '128';
}
function vulnConfig(): Omit<VulnScanOptions, 'timeoutMs' | 'signal'> | undefined {
  const releaseDir = process.env.SCAN_VULN_RELEASE_DIR, manifest = process.env.SCAN_VULN_MANIFEST_DIGEST, artifact = process.env.SCAN_VULN_ARTIFACT_SHA256;
  if (process.env.SCAN_VULN_ENABLED !== 'true' || !releaseDir || !isAbsolute(releaseDir) ||
      !/^sha256:[a-f0-9]{64}$/.test(manifest ?? '') || !/^[a-f0-9]{64}$/.test(artifact ?? '')) return undefined;
  try {
    const key = readFileSync(new URL('../../../deploy/trust/db-signing-key.pub.pem', import.meta.url));
    const publicKey = createPublicKey(key);
    if (createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex') !==
        'd75c6f6b2384de68978090fc837387ab4f3e878ee004bccf27ea98a84fbee078') return undefined;
    return { cacheDir: process.env.TRIVY_CACHE_DIR!, releaseDir, trust: { trustedPublicKeyPem: key.toString('utf8'),
      expectedSigner: 'local-db-operator-v1', expectedSource: `ghcr.io/aquasecurity/trivy-db@${manifest}`, expectedSchemaVersion: 2,
      expectedManifestDigest: manifest!, expectedArtifactSha256: artifact! } };
  } catch { return undefined; }
}
function gatewayReady(): Promise<boolean> {
  return new Promise(resolve => {
    const socket = connect({ host: 'egress', port: 8080, timeout: 2000 });
    const end = (ready: boolean) => { socket.destroy(); resolve(ready); };
    socket.once('connect', () => end(true)); socket.once('error', () => end(false)); socket.once('timeout', () => end(false));
  });
}
export async function runWorker(archivePolicy?: 'local' | 'proof') {
  const file = process.env.SCAN_LEDGER_PATH, ready = process.env.SCAN_WORKER_READY_PATH;
  if (!file || !ready || !process.env.TRIVY_CACHE_DIR) throw new Error('Worker storage is required');
  const clear = (path: string) => { try { unlinkSync(path); } catch { /* absent marker */ } };
  clear(localReady);
  if (archivePolicy === 'local' && (file !== '/data/ledger.sqlite' || ready !== '/data/worker.ready' ||
      process.env.TRIVY_CACHE_DIR !== '/tmp/trivy' || !localResourceEnvelope())) throw new Error('LOCAL resource envelope required');
  await recoverArchiveScratch();
  const version = spawnSync('/usr/local/bin/trivy', ['--version'], { timeout: 5000, maxBuffer: 4096, encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'], env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp' } });
  if (version.status !== 0 || !/^Version: 0\.69\.3\r?$/m.test(version.stdout ?? '')) throw new Error('Scanner binary unavailable');
  const vuln = vulnConfig(), ledger = new ScanLedger(file), controller = new AbortController();
  const stop = () => controller.abort();
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
  let updating = false;
  const heartbeat = async () => {
    if (updating) return;
    updating = true;
    try {
      if (archivePolicy === 'local' && !localResourceEnvelope()) controller.abort();
      if (controller.signal.aborted || !(await gatewayReady()) || controller.signal.aborted) {
        clear(ready); clear(localReady); return;
      }
      marker(ready, String(Date.now()));
      if (archivePolicy === 'local') marker(localReady, JSON.stringify({ qualificationId: NGINX_LOCAL_POLICY.qualificationId,
        version: NGINX_LOCAL_POLICY.version, at: Date.now() }));
    } catch { clear(ready); clear(localReady); controller.abort(); }
    finally { updating = false; }
  };
  const timer = setInterval(() => { void heartbeat(); }, 1000);
  try {
    await heartbeat();
    while (!controller.signal.aborted) {
      if (archivePolicy === 'local' && !localResourceEnvelope()) { controller.abort(); break; }
      if (await gatewayReady() && !controller.signal.aborted) await consumeOne(ledger, { timeoutMs: 60_000, dbDir: process.env.TRIVY_CACHE_DIR, vuln, archivePolicy, signal: controller.signal });
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  } finally {
    clearInterval(timer); controller.abort();
    while (updating) await new Promise(resolve => setTimeout(resolve, 20));
    clear(ready); clear(localReady); ledger.close();
    process.off('SIGTERM', stop); process.off('SIGINT', stop);
  }
}
