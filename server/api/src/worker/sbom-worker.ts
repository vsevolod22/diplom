import { spawn } from 'node:child_process';
import { TextDecoder } from 'node:util';
import type { Job } from '../ledger/ledger.js';
import { parseImageSbom, type ImageSbom } from './cyclonedx-components.js';

const MAX_SBOM_BYTES = 2_000_000;
export type SbomScanResult = { ok: true; sbom: ImageSbom; scannerVersion: '0.69.3' } |
  { ok: false; errorCode: 'SCAN_FAILED' | 'SCAN_TIMEOUT' };

// Scanner-only stage: do not enqueue SBOM requests until fenced persistence and scoped reads exist.
// Container isolation, binary pinning and registry-only egress remain deployment obligations.
export function scanSbomPinned(job: Job, options: { timeoutMs: number; cacheDir: string; signal?: AbortSignal },
  lifecycle: { spawn: typeof spawn; stopWorker: () => void } = { spawn, stopWorker: () => process.exit(1) }): Promise<SbomScanResult> {
  const fail = (timeout = false): SbomScanResult => ({ ok: false, errorCode: timeout ? 'SCAN_TIMEOUT' : 'SCAN_FAILED' });
  if (job.registry !== 'registry-1.docker.io' || job.repository !== 'library/alpine' ||
      !/^sha256:[a-f0-9]{64}$/.test(job.digest) || job.platform !== 'linux/amd64' ||
      job.scope !== 'image' || job.checks !== '["sbom"]' ||
      !/^\/tmp\/[A-Za-z0-9/_-]{1,128}$/.test(options.cacheDir) ||
      !Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1000 || options.timeoutMs > 600_000)
    return Promise.resolve(fail());
  const image = `${job.registry}/${job.repository}@${job.digest}`;
  // CycloneDX generation does not need a vulnerability scanner or vulnerability DB.
  const args = ['image', '--image-src', 'remote', '--skip-db-update', '--skip-java-db-update',
    '--offline-scan', '--cache-dir', options.cacheDir, '--platform', job.platform,
    '--format', 'cyclonedx', image];
  return new Promise(resolve => {
    let child: ReturnType<typeof spawn>;
    try {
      child = lifecycle.spawn('trivy', args, {
        shell: false, stdio: ['ignore', 'pipe', 'ignore'],
        env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', HTTPS_PROXY: 'http://egress:8080',
          HTTP_PROXY: 'http://egress:8080', NO_PROXY: '',
          SSL_CERT_FILE: process.env.SSL_CERT_FILE || '/etc/ssl/certs/ca-certificates.crt' },
      });
    } catch { resolve(fail()); return; }
    let closed = false;
    let killed = false;
    let timedOut = false;
    let cancelled = options.signal?.aborted ?? false;
    let bytes = 0;
    const chunks: Buffer[] = [];
    let fallback: ReturnType<typeof setTimeout> | undefined;
    const kill = () => {
      if (killed) return;
      killed = true;
      child.kill('SIGKILL');
      // A descendant may hold stdout open after exit; terminate the isolated container.
      fallback = setTimeout(() => lifecycle.stopWorker(), 2000);
    };
    const abort = () => { cancelled = true; kill(); lifecycle.stopWorker(); };
    const timer = setTimeout(() => { timedOut = true; kill(); }, options.timeoutMs);
    const finish = (result: SbomScanResult) => {
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
      if (bytes > MAX_SBOM_BYTES) kill();
      else chunks.push(chunk);
    });
    child.on('error', kill);
    child.on('close', code => {
      if (cancelled || timedOut || killed || code !== 0 || !child.stdout) return finish(fail(timedOut));
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, bytes));
        const sbom = parseImageSbom(JSON.parse(text) as unknown, image, job.platform);
        finish({ ok: true, sbom, scannerVersion: '0.69.3' });
      } catch { finish(fail()); }
    });
    if (cancelled) abort();
    else options.signal?.addEventListener('abort', abort, { once: true });
    if (options.signal?.aborted && !cancelled) abort();
  });
}
