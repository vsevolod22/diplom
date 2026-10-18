import type { CombinedOutcome, Job, ScanLedger } from '../ledger/ledger.js';
import { scanPinned, type ScanResult } from './scan-worker.js';
import { scanSbomPinned, type SbomScanResult } from './sbom-worker.js';
import { scanVulnPinned, type VulnScanOptions, type VulnScanResult } from './vuln-worker.js';
import { scannerFailure } from './scanner-errors.js';
import { assertArchiveDbFreshness } from './archive-result-contract.js';
import { LEGACY_DB_POLICY, CURRENT_DB_POLICY, DbPolicyContractError, DbUsabilityError } from './cve-db-policy.mjs';
import { scanNginxArchive, scanPublicImageArchive } from './archive-scan-worker.js';
import { validPublicTarget } from '../oci/public-image-policy.js';
import { NGINX_ARCHIVE_CANDIDATES } from '../oci/bounded-image-archive.js';
import { runImageConfig } from './image-config-runner.js';
import type { ConfigLoader } from '../oci/pinned-image-config.js';
import { exactLocalTarget, localChecksAllowed, validLocalBinding } from '../oci/nginx-local-policy.js';

type Options = { timeoutMs: number; dbDir: string; signal?: AbortSignal; configLoader?: ConfigLoader; archivePolicy?: 'local' | 'proof'; publicImagePolicy?: boolean;
  vuln?: Omit<VulnScanOptions, 'timeoutMs' | 'signal'> };
type Check = CombinedOutcome['check'] | 'config';
const order: Check[] = ['secret', 'sbom', 'vuln', 'config'];
function checks(value: string): Check[] | null {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 4 ||
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
  archiveRunner: typeof scanNginxArchive = scanNginxArchive,
  publicArchiveRunner: typeof scanPublicImageArchive = scanPublicImageArchive): Promise<boolean> {
  // Reserve the legacy sequential budget. claim adds the bounded config budget
  // only when config is selected, preserving existing lease timing for old jobs.
  if (options.signal?.aborted) return false;
  const job = ledger.claim(now, 3 * options.timeoutMs + 27_000, 627_000);
  if (!job) return false;
  const canonical = checks(job.checks);
  // Only this process's explicit composition can opt generic jobs into archives.
  // A stored executionProfile is never public-image authority; Alpine stays legacy.
  const publicArchive = options.publicImagePolicy === true && !job.executionProfile &&
    job.repository !== 'library/alpine' && validPublicTarget(job) && !!canonical &&
    !(job.repository === 'library/nginx' && options.archivePolicy);
  // Composition policy precedes config loading, archive acquisition and every scanner.
  if ((!publicArchive && (job.executionProfile || job.repository === 'library/nginx') && !(options.archivePolicy === 'local'
    ? exactLocalTarget(job) && validLocalBinding(job.executionProfile) && !!canonical && localChecksAllowed(canonical)
    : options.archivePolicy === 'proof' && !job.executionProfile && !!canonical && NGINX_ARCHIVE_CANDIDATES.some(target =>
      target.registry === job.registry && target.repository === job.repository && target.digest === job.digest && target.platform === job.platform))) ||
      options.publicImagePolicy === true && job.repository !== 'library/alpine' && !publicArchive && !options.archivePolicy) {
    ledger.finish(job.scanId, job.attempts, 'failed', undefined, job.leaseToken); return true;
  }
  // Preserve legacy single-runner injection for unsupported check sets, but
  // never attribute its output to verified coverage.
  const requested = (canonical ?? ['secret']).filter((check): check is CombinedOutcome['check'] => check !== 'config');
  if (job.scope !== 'image') {
    ledger.finish(job.scanId, job.attempts, 'failed', undefined, job.leaseToken);
    return true;
  }
  const controller = new AbortController();
  const callerAbort = () => controller.abort();
  options.signal?.addEventListener('abort', callerAbort, { once: true });
  if (options.signal?.aborted) controller.abort();
  const poll = () => {
    try { if (!ledger.checkpointActive(job)) controller.abort(); }
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
    const config = await runImageConfig(ledger, job, controller.signal, options.configLoader, options.publicImagePolicy === true);
    poll();
    if (controller.signal.aborted) return true;
    if (canonical?.includes('config') && !ledger.checkpointConfig(job, config)) return true;
    if ((publicArchive || job.repository === 'library/nginx') && requested.length) {
      const legacyTarget = publicArchive ? undefined : NGINX_ARCHIVE_CANDIDATES.find(candidate =>
        Object.entries(candidate).every(([key, value]) => key === 'configDigest' || job[key as keyof Job] === value));
      const target = publicArchive ? { registry: job.registry, repository: job.repository, digest: job.digest, platform: job.platform } : legacyTarget;
      if (!canonical || !target) {
        ledger.finish(job.scanId, job.attempts, 'failed', undefined, job.leaseToken); return true;
      }
      // Only the selected exact LOCAL composition or explicit isolated proof
      // reaches this path; the default API and worker remain closed.
      let report: Awaited<ReturnType<typeof archiveRunner>> | null;
      let checkpointFailure: { error: unknown } | undefined;
      let checkpointCommitted = false;
      try {
        const selectedRunner = (options: Omit<Parameters<typeof scanNginxArchive>[1], 'target'>) => {
                  if (publicArchive) return publicArchiveRunner(requested, { ...options, target });
                  if (!legacyTarget) throw new TypeError('Missing exact archive target');
                  return archiveRunner(requested, { ...options, target: legacyTarget });
                };
                report = await Promise.race([selectedRunner({ signal: controller.signal,
          onCheckpoint: (check, completed) => {
            if (controller.signal.aborted) return false;
            try {
              const accepted = ledger.checkpointArchive(job, check, completed);
              if (!accepted) controller.abort();
              else checkpointCommitted = true;
              return accepted;
            } catch (error) {
              // Keep the original storage/contract error even when abort wins the race,
              // cleanup throws, or an injected runner swallows callback exceptions.
              checkpointFailure = { error };
              controller.abort();
              throw error;
            }
          },
          vuln: options.vuln ? { ...options.vuln, policy: job.cvePolicy ?? LEGACY_DB_POLICY, timeoutMs: 120_000, signal: controller.signal } : undefined }), aborted]);
        if (checkpointFailure) throw checkpointFailure.error;
      } catch (error) {
        if (checkpointFailure) throw checkpointFailure.error;
        // A runner/cleanup failure after a commit cannot invent failures for completed
        // siblings or make their checkpoints inaccessible to cancellation/recovery.
        if (checkpointCommitted || error instanceof DbPolicyContractError || error instanceof TypeError) throw error;
        poll();
        if (!controller.signal.aborted) ledger.finishCombined(job.scanId, job.attempts,
          requested.map(check => ({ check, outcome: 'failed', errorCode: 'SCAN_FAILED' })), config, job.leaseToken);
        return true;
      }
      if (report === null) return true;
      poll();
      if (!controller.signal.aborted) {
        try { assertArchiveDbFreshness(report, Date.now(), job.cvePolicy ?? LEGACY_DB_POLICY); }
        catch (error) {
          if (!(error instanceof DbUsabilityError)) throw error;
          report.vuln = { outcome: 'failed', reason: 'DB_UNAVAILABLE' };
        }
        // Persistence is outside the scanner fallback. Only a genuine DB freshness
        // crossing is converted to the existing CVE outcome; SQLite errors propagate.
        try { ledger.finishArchive(job.scanId, job.attempts, report, config, job.leaseToken); }
        catch (error) {
          if (!(error instanceof DbUsabilityError)) throw error;
          report.vuln = { outcome: 'failed', reason: 'DB_UNAVAILABLE' };
          ledger.finishArchive(job.scanId, job.attempts, report, config, job.leaseToken);
        }
      }
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
        outcomes.push(result.ok ? { check, outcome: 'checked', image, findings: result.findings, scannerVersion: result.scannerVersion,
                  ...(job.cvePolicy === CURRENT_DB_POLICY ? { dbEvidence: result.dbEvidence } : {}) } :
          { check, outcome: 'failed', errorCode: result.errorCode });
      }
      if (canonical && !ledger.checkpointCombined(job, outcomes[outcomes.length - 1])) return true;
    }
    poll();
    if (!controller.signal.aborted && canonical) ledger.finishCombined(job.scanId, job.attempts, outcomes, config, job.leaseToken);
  } finally {
    clearInterval(interval);
    controller.signal.removeEventListener('abort', onAbort);
    options.signal?.removeEventListener('abort', callerAbort);
  }
  poll();
  if (controller.signal.aborted) return true;
  if (!canonical) ledger.finish(job.scanId, job.attempts, 'failed', undefined, job.leaseToken);

  return true;
}
