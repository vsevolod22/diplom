import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, stat, symlink } from 'node:fs/promises';
import { prepareNginxArchive, NGINX_ARCHIVE_TARGET, type ArchiveTarget, type ArchiveReceipt } from '../oci/bounded-image-archive.js';
import { validateArchiveJson, type ArchiveBinding } from '../oci/archive-identity.js';
import { ARCHIVE_LIMITS } from '../oci/layer-tar-validator.js';
import { preparePublicImageArchive } from '../oci/public-image-archive.js';
import { PUBLIC_IMAGE_LIMITS, isPublicReceipt, validPublicTarget, type PublicImageTarget } from '../oci/public-image-policy.js';
import { publicOs } from './public-image-evidence.js';
import { parseImageSbom, type ImageSbom } from './cyclonedx-components.js';
import { parseSecretFindings, type SecretFinding } from './secret-findings.js';
import { parseVulnFindings, type VulnFinding } from './vuln-findings.js';
import { assertDbFreshness, preflightVulnDbBundle, type VerifiedDbIdentity } from './vuln-db-bundle.js';
import type { VulnScanOptions } from './vuln-worker.js';
import { CURRENT_DB_POLICY, LEGACY_DB_POLICY, evaluateDbPolicy, type DbPolicyReceipt } from './cve-db-policy.mjs';
import { runArchiveProcess } from './archive-process.js';
import { auditArchiveScratch } from './archive-scratch.js';

type Failure = { outcome: 'failed'; reason: 'SCAN_FAILED' | 'SCAN_TIMEOUT' | 'DB_UNAVAILABLE' };
type Unsupported = { outcome: 'unsupported'; reason: 'OS_EOL' | 'OS_UNKNOWN' | 'NODE_INVENTORY_ABSENT' | 'NODE_INVENTORY_UNKNOWN' };
export type ArchiveScanReport = {
  receipt: ArchiveReceipt; scannerVersion: '0.69.3'; checkedAt: number;
  metrics: Awaited<ReturnType<typeof prepareNginxArchive>>['metrics'] & { scratchPeak: number };
  secret?: { outcome: 'checked'; findings: SecretFinding[] } | Failure;
  sbom?: { outcome: 'checked'; sbom: ImageSbom } | Failure;
  vuln?: { outcome: 'checked'; findings: VulnFinding[]; db: Readonly<VerifiedDbIdentity>;
    os: { outcome: 'checked' }; node: { outcome: 'checked' } | Unsupported; dbPolicy?: DbPolicyReceipt } |
    (Failure | Unsupported) & { db?: Readonly<VerifiedDbIdentity>; os?: Unsupported; node?: Unsupported; dbPolicy?: DbPolicyReceipt };
};

const failure = (reason: Failure['reason'] = 'SCAN_FAILED'): Failure => ({ outcome: 'failed', reason });

async function verifiedArchive(binding: ArchiveBinding): Promise<void> {
  const file = await open(binding.archivePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat();
    if (!before.isFile() || before.size > (isPublicReceipt(binding.receipt) ? PUBLIC_IMAGE_LIMITS.archiveBytes : ARCHIVE_LIMITS.archiveBytes) || before.mode & 0o222) throw new Error('Invalid archive');
    const hash = createHash('sha256');
    for await (const chunk of file.createReadStream({ autoClose: false })) hash.update(chunk);
    const after = await file.stat();
    if (`sha256:${hash.digest('hex')}` !== binding.receipt.archiveSha256 || before.size !== after.size ||
        before.ino !== after.ino || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw new Error('Invalid archive');
  } finally { await file.close(); }
}
async function verifiedDb(options: VulnScanOptions) {
  const result = await preflightVulnDbBundle({ ...options.trust, directory: options.releaseDir, policy: options.policy ?? LEGACY_DB_POLICY });
  const mount = await lstat(`${options.cacheDir}/db`);
  if (!mount.isDirectory() || mount.isSymbolicLink()) throw new Error('Invalid DB mount');
  for (const name of ['metadata.json', 'trivy.db']) {
    const source = await stat(`${options.releaseDir}/db/${name}`), mounted = await lstat(`${options.cacheDir}/db/${name}`);
    if (!mounted.isFile() || mounted.isSymbolicLink() || source.dev !== mounted.dev || source.ino !== mounted.ino) throw new Error('Invalid DB mount');
  }
  return result.identity;
}
async function invoke(check: 'secret' | 'sbom' | 'vuln', binding: ArchiveBinding, directory: string, signal: AbortSignal): Promise<unknown> {
  await verifiedArchive(binding);
  return runArchiveProcess(check, binding.archivePath, directory, signal);
}

function requireArchiveScanner(): void {
  const binary = spawnSync('/usr/local/bin/trivy', ['--version'], { timeout: 5000, maxBuffer: 4096,
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp' } });
  if (binary.status !== 0 || !/^Version: 0\.69\.3\r?$/m.test(binary.stdout ?? '')) throw new Error('Archive scanner unavailable');
}
// Internal lifecycle injection exercises runner -> ledger failures without network/Trivy.
// HTTP callers and production options cannot supply these dependencies.
const archiveLifecycle = { requireScanner: requireArchiveScanner, prepare: prepareNginxArchive,
  invoke, verifiedDb, audit: auditArchiveScratch };
// Internal test seam can tighten, never replace or extend, the production deadline.
type DeadlineLifecycle = { deadlineSignal?: AbortSignal };

// Closed qualification runner: there is intentionally no admission/enable flag.
// Both exact candidates remain unqualified; the old candidate retains the EOL negative proof.
export async function scanNginxArchive(checks: Array<'secret' | 'sbom' | 'vuln'>,
  options: { signal?: AbortSignal; vuln?: VulnScanOptions; target?: ArchiveTarget;
      onCheckpoint?: (check: 'secret' | 'sbom' | 'vuln', report: ArchiveScanReport) => boolean },
  lifecycle: typeof archiveLifecycle & DeadlineLifecycle = archiveLifecycle): Promise<ArchiveScanReport> {
  return scanArchiveChecks(checks, options, { ...lifecycle,
    prepare: signal => lifecycle.prepare(signal, options.target ?? NGINX_ARCHIVE_TARGET) }, false);
}

const publicArchiveLifecycle = { ...archiveLifecycle, prepare: preparePublicImageArchive };
export async function scanPublicImageArchive(checks: Array<'secret' | 'sbom' | 'vuln'>,
  options: { signal?: AbortSignal; vuln?: VulnScanOptions; target: PublicImageTarget;
    onCheckpoint?: (check: 'secret' | 'sbom' | 'vuln', report: ArchiveScanReport) => boolean },
  lifecycle: typeof publicArchiveLifecycle & DeadlineLifecycle = publicArchiveLifecycle): Promise<ArchiveScanReport> {
  if (!validPublicTarget(options.target)) throw new TypeError('Invalid public archive target');
  const target = Object.freeze({ ...options.target });
  return scanArchiveChecks(checks, options, { ...lifecycle, prepare: async signal => {
    const archive = await lifecycle.prepare(signal, target);
    if (!isPublicReceipt(archive.receipt) || ['registry', 'repository', 'digest', 'platform', 'configDigest'].some(key =>
      target[key as keyof PublicImageTarget] !== undefined && archive.receipt[key as keyof PublicImageTarget] !== target[key as keyof PublicImageTarget])) {
      await archive.cleanup(); throw new TypeError('Unbound public archive');
    }
    return archive;
  } }, true);
}

type Lifecycle = Omit<typeof archiveLifecycle, 'prepare'> & DeadlineLifecycle & {
  prepare: (signal?: AbortSignal) => ReturnType<typeof prepareNginxArchive>;
};
async function scanArchiveChecks(checks: Array<'secret' | 'sbom' | 'vuln'>,
  options: { signal?: AbortSignal; vuln?: VulnScanOptions;
    onCheckpoint?: (check: 'secret' | 'sbom' | 'vuln', report: ArchiveScanReport) => boolean },
  lifecycle: Lifecycle, publicImage: boolean): Promise<ArchiveScanReport> {
  const limits = publicImage ? PUBLIC_IMAGE_LIMITS : ARCHIVE_LIMITS;
  const order = ['secret', 'sbom', 'vuln'];
  if (!checks.length || checks.length > 3 || checks.some((check, index) => !order.includes(check) ||
    index > 0 && order.indexOf(checks[index - 1]) >= order.indexOf(check))) throw new Error('Invalid archive checks');
  lifecycle.requireScanner();
  const controller = new AbortController();
  const signal = AbortSignal.any([controller.signal, ...(options.signal ? [options.signal] : []),
      AbortSignal.timeout(600_000), ...(lifecycle.deadlineSignal ? [lifecycle.deadlineSignal] : [])]);
  const archive = await lifecycle.prepare(signal);
  const targetImage = `${archive.receipt.registry}/${archive.receipt.repository}@${archive.receipt.digest}`;
  const binding = { receipt: archive.receipt, archivePath: archive.archivePath };
  let scratchPeak = archive.metrics.archiveBytes;
  let monitoring = false, scratchInvalid = false, checkpointAccepted = false;
  const abortedFailure = () => failure(scratchInvalid ? 'SCAN_FAILED' : 'SCAN_TIMEOUT');
  const monitor = setInterval(() => {
    if (monitoring) return; monitoring = true;
    void (async () => {
      const bytes = await lifecycle.audit(archive.directory, options.vuln ? `${options.vuln.cacheDir}/db` : undefined, undefined, limits);
      scratchPeak = Math.max(scratchPeak, bytes);
    })().catch(() => { scratchInvalid = true; controller.abort(); }).finally(() => { monitoring = false; });
  }, 100);
  const report: ArchiveScanReport = { receipt: archive.receipt, scannerVersion: '0.69.3', checkedAt: 0,
    metrics: { ...archive.metrics, scratchPeak } };
  try {
    await mkdir(`${archive.directory}/cache`, { mode: 0o700 });
    if (options.vuln) await symlink(`${options.vuln.cacheDir}/db`, `${archive.directory}/cache/db`);
    for (const check of checks) {
      if (signal.aborted) { report[check] = abortedFailure(); continue; }
      try {
        let db: Readonly<VerifiedDbIdentity> | undefined;
        if (check === 'vuln') {
          try { if (!options.vuln) throw new Error(); db = await lifecycle.verifiedDb(options.vuln); }
          catch { report.vuln = failure('DB_UNAVAILABLE'); continue; }
        }
        const value = await lifecycle.invoke(check, binding, archive.directory, signal);
        if (check === 'sbom') report.sbom = { outcome: 'checked', sbom: parseImageSbom(value, targetImage, 'linux/amd64', binding) };
        else {
          const raw = validateArchiveJson(value, binding);
          if (check === 'secret') report.secret = { outcome: 'checked', findings: parseSecretFindings(raw, publicImage ? binding : undefined) };
          else {
            const metadata = raw.Metadata as { OS?: { Family?: string; Name?: string; EOSL?: boolean }; };
            let after: Readonly<VerifiedDbIdentity>;
            try {
              after = await lifecycle.verifiedDb(options.vuln!);
              if (JSON.stringify(after) !== JSON.stringify(db)) throw new Error('DB changed');
            } catch {
              report.vuln = signal.aborted ? abortedFailure() : failure('DB_UNAVAILABLE');
              continue;
            }
            const os = metadata.OS;
            if (publicImage) {
              const evidence = publicOs(os);
              // Missing/unknown OS is explicitly not a checked zero; no language
              // inventory absence is inferred from a tag or an omitted analyzer.
              const nodeUnknown: Unsupported = { outcome: 'unsupported', reason: 'NODE_INVENTORY_UNKNOWN' };
              if (!evidence) {
                report.vuln = { outcome: 'unsupported', reason: 'OS_UNKNOWN', db: after,
                  os: { outcome: 'unsupported', reason: 'OS_UNKNOWN' }, node: nodeUnknown };
              } else {
                const findings = parseVulnFindings(raw, targetImage, 'linux/amd64', binding);
                const results = raw.Results as Array<{ Type?: string; Packages?: unknown[] }>;
                const node = results.some(result => ['node-pkg', 'npm', 'yarn', 'pnpm'].includes(result.Type ?? '') && (result.Packages?.length ?? 0) > 0);
                const nodeCoverage = node ? { outcome: 'checked' as const } : nodeUnknown;
                report.vuln = evidence.eol ? { outcome: 'unsupported', reason: 'OS_EOL', db: after,
                  os: { outcome: 'unsupported', reason: 'OS_EOL' }, node: nodeUnknown } :
                  { outcome: 'checked', findings, db: after, os: { outcome: 'checked' }, node: nodeCoverage };
              }
            } else {
              if (!os || Array.isArray(os) || os.Family !== 'alpine' || typeof os.Name !== 'string' ||
                  !/^3\.[0-9]+\.[0-9]+$/.test(os.Name) || os.EOSL !== undefined && typeof os.EOSL !== 'boolean') {
                throw new Error('Invalid OS evidence');
              }
              // Pinned Trivy 0.69.3 omits false EOSL; only a validated true is EOL evidence.
              // Missing/unknown/malformed required OS evidence is failed, not unsupported.
              if (os.EOSL === true) {
                const reason = 'OS_EOL';
                report.vuln = { outcome: 'unsupported', reason, db, os: { outcome: 'unsupported', reason },
                  node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' } };
              } else {
                const findings = parseVulnFindings(raw, targetImage, 'linux/amd64', binding);
                const results = raw.Results as Array<{ Type?: string; Packages?: unknown[] }>;
                const node = results.some(result => result.Type === 'node-pkg' && result.Packages && result.Packages.length > 0);
                report.vuln = { outcome: 'checked', findings, db: after, os: { outcome: 'checked' },
                  node: node ? { outcome: 'checked' } : { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' } };
              }
            }
          }
        }
      } catch { report[check] = signal.aborted ? abortedFailure() : failure(); }
      finally {
        if (options.onCheckpoint && !signal.aborted) {
          // A completed subprocess and parser are not enough: close the scratch audit
          // for this check before granting durable publication authority.
          while (monitoring) await new Promise(resolve => setTimeout(resolve, 10));
          try {
            const bytes = await lifecycle.audit(archive.directory, options.vuln ? `${options.vuln.cacheDir}/db` : undefined, undefined, limits);
            scratchPeak = Math.max(scratchPeak, bytes);
            if (bytes > limits.scratchBytes) { scratchInvalid = true; controller.abort(); }
          } catch { scratchInvalid = true; controller.abort(); }
          if (!signal.aborted) {
            const completed: ArchiveScanReport = { receipt: report.receipt, scannerVersion: report.scannerVersion,
              checkedAt: Date.now(), metrics: { ...archive.metrics, scratchPeak }, [check]: report[check] };
            if (completed.vuln && completed.vuln.outcome !== 'failed' && completed.vuln.db) {
              try {
                const policy = options.vuln?.policy ?? LEGACY_DB_POLICY;
                assertDbFreshness(completed.vuln.db, completed.checkedAt, policy);
                if (policy === CURRENT_DB_POLICY) completed.vuln = { ...completed.vuln,
                  dbPolicy: evaluateDbPolicy(completed.vuln.db, policy, completed.checkedAt) };
              } catch { completed.vuln = failure('DB_UNAVAILABLE'); }
            }
            // Synchronous callback: its SQLite transaction competes directly with cancel.
            // Exceptions are not scanner failures and must not be swallowed/relabelled.
            if (options.onCheckpoint(check, completed)) checkpointAccepted = true;
            else controller.abort();
          }
        }
      }
    }
    clearInterval(monitor);
    while (monitoring) await new Promise(resolve => setTimeout(resolve, 10));
    try {
      const finalBytes = await lifecycle.audit(archive.directory, options.vuln ? `${options.vuln.cacheDir}/db` : undefined, undefined, limits);
      scratchPeak = Math.max(scratchPeak, finalBytes);
      if (finalBytes > limits.scratchBytes) throw new Error('Invalid archive scratch');
    } catch { scratchInvalid = true; controller.abort(); }
    // Accepted audited evidence belongs to the fenced checkpoint, not this mutable
    // report. A later audit/deadline failure must retain recovery authority instead
    // of delivering replacement failures (or any later unaudited checked output).
    if (signal.aborted && checkpointAccepted) throw new Error('Archive interrupted after accepted checkpoint');
    if (signal.aborted) for (const check of checks) report[check] = abortedFailure();
    // Capture true completion once; ledger replaces only the provisional evaluation at its own fence.
    report.checkedAt = Date.now(); report.metrics.scratchPeak = scratchPeak;
    if (report.vuln && report.vuln.outcome !== 'failed' && report.vuln.db) {
      try {
        const policy = options.vuln?.policy ?? LEGACY_DB_POLICY;
        assertDbFreshness(report.vuln.db, report.checkedAt, policy);
        if (policy === CURRENT_DB_POLICY) report.vuln.dbPolicy = evaluateDbPolicy(report.vuln.db, policy, report.checkedAt);
      } catch { report.vuln = failure('DB_UNAVAILABLE'); }
    }
    return report;
  } finally { clearInterval(monitor); while (monitoring) await new Promise(resolve => setTimeout(resolve, 10)); await archive.cleanup(); }
}
