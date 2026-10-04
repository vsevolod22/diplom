import { spawn } from 'node:child_process';
import { lstat, stat } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { TextDecoder } from 'node:util';
import type { Job } from '../ledger/ledger.js';
import { preflightVulnDbBundle, type BundlePreflightOptions } from './vuln-db-bundle.js';
import { parseVulnFindings, type VulnFinding } from './vuln-findings.js';

const MAX_REPORT_BYTES = 8_000_000;
export type VulnScanResult = { ok: true; findings: VulnFinding[]; scannerVersion: '0.69.3' } |
  { ok: false; errorCode: 'SCAN_FAILED' | 'SCAN_TIMEOUT' };
export type VulnScanOptions = {
  timeoutMs: number;
  cacheDir: string;
  releaseDir: string;
  trust: Omit<BundlePreflightOptions, 'directory' | 'now'>;
  signal?: AbortSignal;
};
type Lifecycle = { spawn: typeof spawn; stopWorker: () => void; preflight: typeof preflightVulnDbBundle };
const lifecycleDefault: Lifecycle = { spawn, stopWorker: () => process.exit(1), preflight: preflightVulnDbBundle };
const fail = (timeout = false): VulnScanResult => ({ ok: false, errorCode: timeout ? 'SCAN_TIMEOUT' : 'SCAN_FAILED' });

// A separate read-only bind mount of releaseDir/db at cacheDir/db is required by deployment.
// File identity checks prevent a writable cache DB from silently replacing the preflighted bytes;
// they do not establish that the mount is read-only or protect against a hostile host.
async function sameMountedDb(releaseDir: string, cacheDir: string): Promise<boolean> {
  const mount = await lstat(join(cacheDir, 'db'));
  if (!mount.isDirectory() || mount.isSymbolicLink()) return false;
  for (const name of ['metadata.json', 'trivy.db']) {
    const source = await stat(join(releaseDir, 'db', name));
    const target = await lstat(join(cacheDir, 'db', name));
    if (!source.isFile() || !target.isFile() || target.isSymbolicLink() ||
        source.dev !== target.dev || source.ino !== target.ino) return false;
  }
  return true;
}

// Scanner-only stage; never use an envelope preflight or a zero-findings result as admission evidence.
export async function scanVulnPinned(job: Job, options: VulnScanOptions,
  lifecycle: Lifecycle = lifecycleDefault): Promise<VulnScanResult> {
  if (job.registry !== 'registry-1.docker.io' || job.repository !== 'library/alpine' ||
      !/^sha256:[a-f0-9]{64}$/.test(job.digest) || job.platform !== 'linux/amd64' ||
      job.scope !== 'image' || job.checks !== '["vuln"]' ||
      !/^\/tmp\/[A-Za-z0-9/_-]{1,128}$/.test(options.cacheDir) ||
      !isAbsolute(options.releaseDir) || options.releaseDir.includes('..') ||
            options.releaseDir === options.cacheDir ||
      !Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1000 || options.timeoutMs > 600_000 ||
      !options.trust || options.signal?.aborted) return fail();
  try {
    await lifecycle.preflight({ ...options.trust, directory: options.releaseDir, now: new Date() });
    if (options.signal?.aborted || !(await sameMountedDb(options.releaseDir, options.cacheDir))) return fail();
  } catch { return fail(); }
  if (options.signal?.aborted) return fail();

  const image = `${job.registry}/${job.repository}@${job.digest}`;
  const args = ['image', '--image-src', 'remote', '--scanners', 'vuln', '--skip-db-update',
    '--skip-java-db-update', '--offline-scan', '--cache-dir', options.cacheDir,
    '--platform', job.platform, '--format', 'json', image];
  return new Promise(resolve => {
    let child: ReturnType<typeof spawn>;
    try {
      child = lifecycle.spawn('/usr/local/bin/trivy', args, {
        shell: false, stdio: ['ignore', 'pipe', 'ignore'],
        env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', HTTPS_PROXY: 'http://egress:8080',
          HTTP_PROXY: 'http://egress:8080', NO_PROXY: '',
          SSL_CERT_FILE: process.env.SSL_CERT_FILE || '/etc/ssl/certs/ca-certificates.crt' },
      });
    } catch { resolve(fail()); return; }
    let closed = false;
    let killed = false;
    let timedOut = false;
    let cancelled = false;
    let bytes = 0;
    const chunks: Buffer[] = [];
    let fallback: ReturnType<typeof setTimeout> | undefined;
    const kill = () => {
      if (killed) return;
      killed = true;
      try { child.kill('SIGKILL'); } catch { /* close or fallback still required */ }
      fallback = setTimeout(() => lifecycle.stopWorker(), 2000);
    };
    const abort = () => { cancelled = true; kill(); lifecycle.stopWorker(); };
    const timer = setTimeout(() => { timedOut = true; kill(); }, options.timeoutMs);
    const finish = (result: VulnScanResult) => {
      if (closed) return;
      closed = true;
      clearTimeout(timer);
      clearTimeout(fallback);
      options.signal?.removeEventListener('abort', abort);
      resolve(result);
    };
    child.stdout?.on('data', (chunk: Buffer) => {
      if (killed) return;
      bytes += chunk.length;
      if (bytes > MAX_REPORT_BYTES) kill();
      else chunks.push(chunk);
    });
    child.on('error', () => { if (!closed) kill(); });
    child.on('close', code => {
      if (cancelled || timedOut || killed || code !== 0 || !child.stdout) return finish(fail(timedOut));
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, bytes));
        const findings = parseVulnFindings(JSON.parse(text) as unknown, image, job.platform);
        finish({ ok: true, findings, scannerVersion: '0.69.3' });
      } catch { finish(fail()); }
    });
    if (options.signal?.aborted) abort();
    else options.signal?.addEventListener('abort', abort, { once: true });
    if (options.signal?.aborted && !cancelled) abort();
  });
}
