import type { CombinedOutcome, Job, ScanLedger } from '../ledger/ledger.js';
import { scanPinned, type ScanResult } from './scan-worker.js';
import { scanSbomPinned, type SbomScanResult } from './sbom-worker.js';
import { scanVulnPinned, type VulnScanOptions, type VulnScanResult } from './vuln-worker.js';
import { scannerFailure } from './scanner-errors.js';
import { assertArchiveDbFreshness } from './archive-result-contract.js';
import { scanNginxArchive } from './archive-scan-worker.js';
import { NGINX_ARCHIVE_CANDIDATES } from '../oci/bounded-image-archive.js';

type Options = { timeoutMs: number; dbDir: string; signal?: AbortSignal;
  vuln?: Omit<VulnScanOptions, 'timeoutMs' | 'signal'> };
type Check = CombinedOutcome['check'];
const order: Check[] = ['secret', 'sbom', 'vuln'];
function checks(value: string): Check[] | null {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 3 ||
        parsed.some((check, index) => !order.includes(check) || index > 0 &&
          order.indexOf(parsed[index - 1]) >= order.indexOf(check)) ||
        JSON.stringify(parsed) !== value) return null;
    return parsed as Check[];
  } catch { return null; }
}

// Called only by a separately isolated worker process. An expired lease may start
// another attempt; every persistence operation is fenced by the ledger.
export async function consumeOne(ledger: ScanLedger, options: Options,
  runner: (job: Job, options: { timeoutMs: number; dbDir: string; signal?: AbortSignal }) => Promise<ScanResult> = scanPinned,
  now = Date.now(),
  sbomRunner: (job: Job, options: { timeoutMs: number; cacheDir: string; signal?: AbortSignal }) => Promise<SbomScanResult> = scanSbomPinned,
  vulnRunner: (job: Job, options: VulnScanOptions) => Promise<VulnScanResult> = scanVulnPinned,
  archiveRunner: typeof scanNginxArchive = scanNginxArchive): Promise<boolean> {
  // The claim API cannot inspect checks until after claiming; reserve the maximum
  // sequential budget for every claim so even a three-check job stays fenced.
  if (options.signal?.aborted) return false;
  const job = ledger.claim(now, 3 * options.timeoutMs + 27_000, 627_000);
  if (!job) return false;
  const canonical = checks(job.checks);
  // Preserve legacy single-runner injection for unsupported check sets, but
  // never attribute its output to verified coverage.
  const requested = canonical ?? (['secret'] as const);
  if (job.scope !== 'image') {
    ledger.finish(job.scanId, job.attempts, 'failed');
    return true;
  }
  const controller = new AbortController();
  const callerAbort = () => controller.abort();
  options.signal?.addEventListener('abort', callerAbort, { once: true });
  if (options.signal?.aborted) controller.abort();
  const poll = () => {
    try { if (!ledger.attemptActive(job.scanId, job.attempts)) controller.abort(); }
    catch { controller.abort(); }
  };
  poll();
  if (controller.signal.aborted) {
    options.signal?.removeEventListener('abort', callerAbort);
    return true;
  }
  const interval = setInterval(poll, 100);
  let onAbort!: () => void;
  const aborted = new Promise<null>(resolve => {
    onAbort = () => resolve(null);
    controller.signal.addEventListener('abort', onAbort, { once: true });
  });
  const outcomes: CombinedOutcome[] = [];
  const image = `${job.registry}/${job.repository}@${job.digest}`;
  try {
    if (job.repository === 'library/nginx') {
      const target = NGINX_ARCHIVE_CANDIDATES.find(candidate => Object.entries(candidate).every(([key, value]) => key === 'configDigest' || job[key as keyof Job] === value));
      if (!canonical || !target) {
        ledger.finish(job.scanId, job.attempts, 'failed'); return true;
      }
      // Exact-candidate qualification jobs use either internal fixtures or the
      // separately composed proof HTTP ingress. Production admission stays closed.
      try {
        const report = await archiveRunner(canonical, { signal: controller.signal, target,
          vuln: options.vuln ? { ...options.vuln, timeoutMs: 120_000, signal: controller.signal } : undefined });
        poll();
        if (!controller.signal.aborted) {
          try { assertArchiveDbFreshness(report); }
          catch { report.vuln = { outcome: 'failed', reason: 'DB_UNAVAILABLE' }; }
          try { ledger.finishArchive(job.scanId, job.attempts, report); }
          catch (error) {
            // A NextUpdate crossing inside BEGIN IMMEDIATE must not erase independent checks.
            try { assertArchiveDbFreshness(report); } catch {
              report.vuln = { outcome: 'failed', reason: 'DB_UNAVAILABLE' };
              ledger.finishArchive(job.scanId, job.attempts, report); return true;
            }
            throw error;
          }
        }
      } catch { if (!controller.signal.aborted) ledger.finish(job.scanId, job.attempts, 'failed'); }
      return true;
    }
    for (const check of requested) {
      poll();
      if (controller.signal.aborted) return true;
      const pinnedJob = { ...job, checks: JSON.stringify([check]) };
      // A runner that ignores abort cannot hold this consumer indefinitely.
      if (check === 'secret') {
        const result = await Promise.race([
          Promise.resolve().then(() => runner(pinnedJob, { timeoutMs: options.timeoutMs, dbDir: options.dbDir, signal: controller.signal }))
            .catch((): ScanResult => ({ ok: false, failure: scannerFailure(null) })), aborted,
        ]);
        if (result === null || controller.signal.aborted) return true;
        outcomes.push(result.ok ? { check, outcome: 'checked', findings: result.findings, scannerVersion: result.scannerVersion } :
          { check, outcome: 'failed', errorCode: result.failure.errorCode });
      } else if (check === 'sbom') {
        const result = await Promise.race([
          Promise.resolve().then(() => sbomRunner(pinnedJob, { timeoutMs: options.timeoutMs, cacheDir: options.dbDir, signal: controller.signal }))
            .catch((): SbomScanResult => ({ ok: false, errorCode: 'SCAN_FAILED' })), aborted,
        ]);
        if (result === null || controller.signal.aborted) return true;
        outcomes.push(result.ok ? { check, outcome: 'checked', sbom: result.sbom, scannerVersion: result.scannerVersion } :
          { check, outcome: 'failed', errorCode: result.errorCode });
      } else {
        const result = await Promise.race([
          Promise.resolve().then<Promise<VulnScanResult> | { ok: false; errorCode: 'SCAN_UNAVAILABLE' }>(() => options.vuln
            ? vulnRunner(pinnedJob, { ...options.vuln, timeoutMs: options.timeoutMs, signal: controller.signal })
            : { ok: false as const, errorCode: 'SCAN_UNAVAILABLE' as const })
            .catch((): VulnScanResult => ({ ok: false, errorCode: 'SCAN_FAILED' })), aborted,
        ]);
        if (result === null || controller.signal.aborted) return true;
        outcomes.push(result.ok ? { check, outcome: 'checked', image, findings: result.findings, scannerVersion: result.scannerVersion } :
          { check, outcome: 'failed', errorCode: result.errorCode });
      }
    }
  } finally {
    clearInterval(interval);
    controller.signal.removeEventListener('abort', onAbort);
    options.signal?.removeEventListener('abort', callerAbort);
  }
  poll();
  if (controller.signal.aborted) return true;
  if (!canonical) ledger.finish(job.scanId, job.attempts, 'failed');
  else if (requested.length > 1) ledger.finishCombined(job.scanId, job.attempts, outcomes);
  else {
    const result = outcomes[0];
    if (result.outcome === 'failed') ledger.finish(job.scanId, job.attempts, 'failed', result.errorCode);
    else if (result.check === 'secret') ledger.finishWithResult(job.scanId, job.attempts, result.findings, result.scannerVersion);
    else if (result.check === 'sbom') ledger.finishWithSbom(job.scanId, job.attempts, result.sbom, result.scannerVersion);
    else ledger.finishWithVuln(job.scanId, job.attempts, result.image, result.findings, result.scannerVersion);
  }
  return true;
}
