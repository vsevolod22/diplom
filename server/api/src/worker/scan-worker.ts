import { spawn } from 'node:child_process';
import type { Job } from '../ledger/ledger.js';
import { scannerFailure, type ScannerFailure } from './scanner-errors.js';

export type ScanResult = { ok: true; findingCount: number } | { ok: false; failure: ScannerFailure };

// Intended for a separately network-isolated worker container. This process cannot
// establish the container's network boundary: deployment must enforce it independently.
export async function scanPinned(job: Job, options: { timeoutMs: number; dbDir: string }): Promise<ScanResult> {
  if (!/^sha256:[a-f0-9]{64}$/.test(job.digest) ||
      !/^linux\/[a-z0-9]+(?:\/[a-z0-9]+)?$/.test(job.platform) ||
      !/^[a-z0-9.-]+$/.test(job.registry) || !/^[a-z0-9/._-]+$/.test(job.repository) ||
      !options.dbDir || options.timeoutMs < 1000 || options.timeoutMs > 600_000) {
    return { ok: false, failure: scannerFailure(null) };
  }
  const args = ['image', '--image-src', 'remote', '--skip-db-update', '--skip-java-db-update',
    '--offline-scan', '--cache-dir', options.dbDir,
    '--platform', job.platform, '--format', 'json', `${job.registry}/${job.repository}@${job.digest}`];
  return new Promise(resolve => {
    let settled = false;
    let timedOut = false;
    let output = '';
    const done = (result: ScanResult) => { if (!settled) { settled = true; resolve(result); } };
    const child = spawn('trivy', args, {
      env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', HTTPS_PROXY: 'http://egress:8080',
        HTTP_PROXY: 'http://egress:8080', NO_PROXY: '' },
      stdio: ['ignore', 'pipe', 'ignore'], // stderr can include signed URLs
      shell: false,
    });
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, options.timeoutMs);
    child.stdout?.on('data', (chunk: Buffer) => {
      if (output.length + chunk.length > 8_000_000) {
        child.kill('SIGKILL');
      } else output += chunk.toString('utf8');
    });
    child.on('error', () => { clearTimeout(timer); done({ ok: false, failure: scannerFailure(null) }); });
    child.on('close', code => {
      clearTimeout(timer);
      if (timedOut || code !== 0) return done({ ok: false, failure: scannerFailure(code, timedOut) });
      try {
        const parsed: unknown = JSON.parse(output);
        if (!parsed || typeof parsed !== 'object' || !Array.isArray((parsed as { Results?: unknown }).Results)) throw new Error();
        // Do not return arbitrary strings or signed URLs from scanner output.
        const results = (parsed as { Results: Array<{ Vulnerabilities?: unknown[]; Secrets?: unknown[] }> }).Results;
        const findingCount = results.reduce((sum, item) => sum + (Array.isArray(item.Vulnerabilities) ? item.Vulnerabilities.length : 0) +
          (Array.isArray(item.Secrets) ? item.Secrets.length : 0), 0);
        done({ ok: true, findingCount });
      } catch { done({ ok: false, failure: scannerFailure(null) }); }
    });
  });
}
