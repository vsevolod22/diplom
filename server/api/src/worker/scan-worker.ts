import { spawn } from 'node:child_process';
import type { Job } from '../ledger/ledger.js';
import { scannerFailure, type ScannerFailure } from './scanner-errors.js';
import { parseSecretFindings, type SecretFinding } from './secret-findings.js';

export type ScanResult = { ok: true; findings: SecretFinding[]; scannerVersion: '0.69.3' } | { ok: false; failure: ScannerFailure };

// Intended for a separately network-isolated worker container. This process cannot
// establish the container's network boundary: deployment must enforce it independently.
// The injected lifecycle is only for exercising stuck pipes without a real Trivy process.
const workerLifecycle: { spawn: typeof spawn; stopWorker: () => void } = {
  spawn, stopWorker: () => process.exit(1),
};

export async function scanPinned(job: Job, options: { timeoutMs: number; dbDir: string; signal?: AbortSignal },
  lifecycle: typeof workerLifecycle = workerLifecycle): Promise<ScanResult> {
  if (!/^sha256:[a-f0-9]{64}$/.test(job.digest) ||
      !/^linux\/[a-z0-9]+(?:\/[a-z0-9]+)?$/.test(job.platform) ||
      !/^[a-z0-9.-]+$/.test(job.registry) || !/^[a-z0-9/._-]+$/.test(job.repository) ||
      job.checks !== '["secret"]' || job.scope !== 'image' ||
            !options.dbDir || options.timeoutMs < 1000 || options.timeoutMs > 600_000) {
    return { ok: false, failure: scannerFailure(null) };
  }
  const args = ['image', '--image-src', 'remote', '--scanners', 'secret', '--skip-db-update', '--skip-java-db-update',
    '--offline-scan', '--cache-dir', options.dbDir,
    '--platform', job.platform, '--format', 'json', `${job.registry}/${job.repository}@${job.digest}`];
  return new Promise(resolve => {
    let settled = false;
    let timedOut = false;
    let cancelled = options.signal?.aborted ?? false;
    let killed = false;
    let spawnFailed = false;
    let output = '';
    let outputBytes = 0;
    let killFallback: ReturnType<typeof setTimeout> | undefined;
    const child = lifecycle.spawn('trivy', args, {
      env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', HTTPS_PROXY: 'http://egress:8080',
        HTTP_PROXY: 'http://egress:8080', NO_PROXY: '',
                // Go TLS verifies the peer against the OS trust store (or an explicitly
                // mounted trusted CA in the disposable proof deployment); never --insecure.
                SSL_CERT_FILE: process.env.SSL_CERT_FILE || '/etc/ssl/certs/ca-certificates.crt' },
      stdio: ['ignore', 'pipe', 'ignore'], // stderr can include signed URLs
      shell: false,
    });
    const done = (result: ScanResult) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        clearTimeout(killFallback);
        options.signal?.removeEventListener('abort', abort);
        resolve(result);
      }
    };
    const kill = () => {
      if (killed) return;
      killed = true;
      child.kill('SIGKILL');
      // 'exit' alone is insufficient: a descendant can keep stdout open.
      // Never return to the consumer unless 'close' confirms the pipe is gone.
      killFallback = setTimeout(() => lifecycle.stopWorker(), 2000);
    };
    const abort = () => {
      cancelled = true;
      kill();
      // The consumer races abort against this promise and can claim the next job
      // before 'close'. Terminate the container even if SIGKILL succeeds.
      lifecycle.stopWorker();
    };
    const timer = setTimeout(() => { timedOut = true; kill(); }, options.timeoutMs);
    child.stdout?.on('data', (chunk: Buffer) => {
      if (killed) return;
      outputBytes += chunk.length;
      if (outputBytes > 8_000_000) kill();
      else output += chunk.toString('utf8');
    });
    child.on('error', () => { spawnFailed = true; kill(); });
    child.on('close', code => {
      if (cancelled || timedOut || killed || spawnFailed || code !== 0)
        return done({ ok: false, failure: scannerFailure(spawnFailed ? null : code, timedOut) });
      try {
        const findings = parseSecretFindings(JSON.parse(output) as unknown);
        done({ ok: true, findings, scannerVersion: '0.69.3' });
      } catch { done({ ok: false, failure: scannerFailure(null) }); }
    });
    if (cancelled) abort(); else options.signal?.addEventListener('abort', abort, { once: true });
    // Cover a signal that fired between the initial check and listener registration.
    if (options.signal?.aborted && !cancelled) abort();
  });
}
