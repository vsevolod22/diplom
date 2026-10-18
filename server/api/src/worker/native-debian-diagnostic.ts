// Explicit opt-in diagnostic executable. Never writes scanner JSON, findings or DB rows.
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir, open, symlink, lstat, stat } from 'node:fs/promises';
import { preparePublicImageArchive } from '../oci/public-image-archive.js';
import { validateArchiveJson, validateArchiveSbom } from '../oci/archive-identity.js';
import { runArchiveProcess } from './archive-process.js';
import { parseImageSbom } from './cyclonedx-components.js';
import { parseVulnFindings, PUBLIC_VULN_SOURCES } from './vuln-findings.js';
import { publicOs, publicPackageName, publicPackageVersion, publicResultEcosystem } from './public-image-evidence.js';
import { buildVulnConfig } from './worker-runtime.js';
import { localDbTrustAnchorFromEnv } from './vuln-db-trust.js';
import { preflightVulnDbBundle } from './vuln-db-bundle.js';
import { CURRENT_DB_POLICY, evaluateDbPolicy } from './cve-db-policy.mjs';
import { validateArchiveReport } from './archive-result-contract.js';
import type { ArchiveScanReport } from './archive-scan-worker.js';
import { auditArchiveScratch } from './archive-scratch.js';
import { PUBLIC_IMAGE_LIMITS } from '../oci/public-image-policy.js';

const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const array = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
const counter = () => { const counts: Record<string, number> = {}; return { counts, add(label: string) { counts[label] = (counts[label] ?? 0) + 1; } }; };
const failures: Record<string, string> = {
  'Invalid public SBOM identity': 'SBOM_IDENTITY', 'Mismatched public SBOM identity': 'SBOM_PACKAGE_IDENTITY',
  'Invalid SBOM qualifiers': 'SBOM_QUALIFIERS', 'Unbound public SBOM OS package': 'SBOM_OS_QUALIFIERS',
  'Unsupported SBOM qualifiers': 'SBOM_LANGUAGE_QUALIFIERS', 'Invalid SBOM OS': 'SBOM_OS',
  'Invalid SBOM package': 'SBOM_PACKAGE', 'No verified SBOM packages': 'SBOM_EMPTY',
  'Invalid package inventory': 'VULN_INVENTORY', 'Vulnerability missing package inventory': 'VULN_INVENTORY_MATCH',
  'Invalid vulnerability': 'VULN_CORE', 'Invalid public severity source': 'VULN_SOURCE',
  'Invalid vulnerability result': 'VULN_RESULT', 'No verified OS coverage': 'VULN_OS_COVERAGE',
  'Unsupported public result type': 'VULN_RESULT_TYPE',
};
const rejected = (error: unknown) => error instanceof Error && Object.hasOwn(failures, error.message) ? failures[error.message] : 'OTHER_REJECTION';

async function main() {
  const signal = AbortSignal.timeout(540_000);
  const scanner = spawnSync('/usr/local/bin/trivy', ['--version'], { timeout: 5000, maxBuffer: 4096,
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp' } });
  if (scanner.status !== 0 || !/^Version: 0\.69\.3\r?$/m.test(scanner.stdout ?? '')) throw Error('scanner');
  const options = buildVulnConfig(undefined, localDbTrustAnchorFromEnv(), true);
  if (!options) throw Error('setup');
  const mount = await lstat(`${options.cacheDir}/db`);
  if (!mount.isDirectory() || mount.isSymbolicLink()) throw Error('mount');
  for (const name of ['metadata.json', 'trivy.db']) {
    const source = await stat(`${options.releaseDir}/db/${name}`), mounted = await lstat(`${options.cacheDir}/db/${name}`);
    if (!mounted.isFile() || mounted.isSymbolicLink() || source.dev !== mounted.dev || source.ino !== mounted.ino) throw Error('mount');
  }
  const db = await preflightVulnDbBundle({ ...options.trust, directory: options.releaseDir, policy: CURRENT_DB_POLICY });
  const archive = await preparePublicImageArchive(signal, { registry: 'registry-1.docker.io', repository: 'library/debian',
    digest: 'sha256:a4672c0cb26fbdde88e38fa2dfb6c681942306680e41e4378b28770b6e79ee91', platform: 'linux/amd64' });
  try {
    await mkdir(`${archive.directory}/cache`, { mode: 0o700 });
    await symlink(`${options.cacheDir}/db`, `${archive.directory}/cache/db`);
    const binding = { receipt: archive.receipt, archivePath: archive.archivePath };
    const image = `${archive.receipt.registry}/${archive.receipt.repository}@${archive.receipt.digest}`;
    const summary: Record<string, unknown> = { acquisition: { entries: archive.metrics.entries, layers: archive.receipt.diffIds.length }, scannerVerified: true };
    for (const check of ['sbom', 'vuln'] as const) {
      const file = await open(archive.archivePath, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const before = await file.stat(); const hash = createHash('sha256');
        for await (const chunk of file.createReadStream({ autoClose: false })) hash.update(chunk);
        const after = await file.stat();
        if (!before.isFile() || before.mode & 0o222 || before.size > PUBLIC_IMAGE_LIMITS.archiveBytes ||
            `sha256:${hash.digest('hex')}` !== archive.receipt.archiveSha256 || before.size !== after.size ||
            before.ino !== after.ino || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw Error('archive');
      } finally { await file.close(); }
      const stats = { bytes: 0, exitCode: -999 };
      let value: unknown;
      try {
        value = await runArchiveProcess(check, archive.archivePath, archive.directory, signal, { launch(command, args, opts) {
          const child = spawn(command, args, opts);
          child.stdout!.on('data', (chunk: Buffer) => { stats.bytes += chunk.length; });
          child.on('close', code => { stats.exitCode = code ?? -999; }); return child;
        } });
      } catch { summary[check] = { label: 'INVOKE_FAILED', ...stats }; continue; }
      if (check === 'sbom') {
        validateArchiveSbom(value, binding);
        const bom = value as Record<string, unknown>;
        const components = array(bom.components);
        const osItems = components.filter(item => object(item) && item.type === 'operating-system') as Record<string, unknown>[];
        const os = osItems.length === 1 ? publicOs({ Family: osItems[0].name, Name: osItems[0].version }) : undefined;
        const issues = counter();
        for (const item of components) {
          if (!object(item)) { issues.add('COMPONENT_NOT_OBJECT'); continue; }
          if (item.type === 'operating-system') continue;
          if (item.type !== 'library') issues.add('COMPONENT_TYPE');
          if (!publicPackageVersion(item.version)) issues.add('VERSION_GRAMMAR');
          if (typeof item.purl !== 'string') { issues.add('PURL_MISSING'); continue; }
          const match = /^pkg:([a-z]+)\/([^?#]+)@([^/?#]+)(?:\?([^#]+))?$/.exec(item.purl);
          if (!match) { issues.add('PURL_SHAPE'); continue; }
          if (match[1] !== 'deb') { issues.add('NON_DEB_COMPONENT'); continue; }
          const path = decodeURIComponent(match[2]), version = decodeURIComponent(match[3]);
          if (version !== item.version) issues.add('PURL_VERSION_MISMATCH');
          const purlEpoch = new URLSearchParams(match[4] ?? '').get('epoch');
          if (purlEpoch && `${purlEpoch}:${version}` === item.version) issues.add('PURL_EPOCH_VERSION_MATCH');
          if (path !== `${os?.name}/${item.name}`) issues.add('PURL_NAME_MISMATCH');
          if (!publicPackageName(item.name, 'deb')) issues.add('NAME_GRAMMAR');
          const qualifiers = new URLSearchParams(match[4] ?? '');
          if ([...qualifiers].length !== 2) issues.add('QUALIFIER_COUNT');
          for (const key of qualifiers.keys()) issues.add(key === 'arch' ? 'QUALIFIER_ARCH' : key === 'distro' ? 'QUALIFIER_DISTRO' : key === 'epoch' ? 'QUALIFIER_EPOCH' : 'QUALIFIER_OTHER');
          if (!['amd64', 'all'].includes(qualifiers.get('arch') ?? '')) issues.add('ARCH_MISMATCH');
          if (![os?.version, `${os?.name}-${os?.version}`].includes(qualifiers.get('distro') ?? '')) issues.add('DISTRO_MISMATCH');
          if (qualifiers.has('epoch')) issues.add(/^[0-9]+$/.test(qualifiers.get('epoch') ?? '') ? 'EPOCH_NUMERIC' : 'EPOCH_INVALID');
        }
        let normalized: Record<string, unknown>;
        try { const result = parseImageSbom(value, image, 'linux/amd64', binding);
          const bytes = await auditArchiveScratch(archive.directory, `${options.cacheDir}/db`, undefined, PUBLIC_IMAGE_LIMITS);
          validateArchiveReport({ receipt: archive.receipt, scannerVersion: '0.69.3', checkedAt: Date.now(),
            metrics: { ...archive.metrics, scratchPeak: bytes }, sbom: { outcome: 'checked', sbom: result } }, ['sbom'], CURRENT_DB_POLICY);
          normalized = { label: 'CHECKED', components: result.components.length,
            deb: result.components.filter(component => component.ecosystem === 'deb').length, envelopeVerified: true }; }
        catch (error) { normalized = { label: rejected(error) }; }
        summary.sbom = { ...stats, identityVerified: true, components: components.length, osComponents: osItems.length,
          osSupported: !!os, issues: issues.counts, normalized };
      } else {
        const raw = validateArchiveJson(value, binding);
        const metadata = raw.Metadata as Record<string, unknown>;
        const os = publicOs(metadata.OS); const issues = counter();
        let packages = 0, vulnerabilities = 0;
        for (const result of array(raw.Results)) {
          if (!object(result)) { issues.add('RESULT_NOT_OBJECT'); continue; }
          let ecosystem;
          try { ecosystem = publicResultEcosystem(result, os?.name); } catch { issues.add('RESULT_TYPE_UNSUPPORTED'); continue; }
          issues.add(ecosystem === 'deb' ? 'DEB_RESULT' : 'NON_DEB_RESULT');
          const inventory = array(result.Packages); packages += inventory.length;
          for (const pkg of inventory) {
            if (!object(pkg)) { issues.add('PACKAGE_NOT_OBJECT'); continue; }
            if (!publicPackageName(pkg.Name, ecosystem)) issues.add('NAME_GRAMMAR');
            if (!publicPackageVersion(pkg.Version)) issues.add('VERSION_GRAMMAR');
            if (pkg.Epoch !== undefined) issues.add(typeof pkg.Epoch === 'number' && Number.isSafeInteger(pkg.Epoch) ? 'PACKAGE_EPOCH_INTEGER' : 'PACKAGE_EPOCH_OTHER');
            if (pkg.Release !== undefined) issues.add(typeof pkg.Release === 'string' && pkg.Release.length > 0 ? 'PACKAGE_RELEASE_STRING' : 'PACKAGE_RELEASE_OTHER');
          }
          for (const vuln of array(result.Vulnerabilities)) {
            vulnerabilities++;
            if (!object(vuln)) { issues.add('VULN_NOT_OBJECT'); continue; }
            if (!/^CVE-[0-9]{4}-[0-9]{4,12}$/.test(String(vuln.VulnerabilityID))) {
              issues.add('NON_CVE_ID');
              issues.add(/^TEMP-[0-9]{7}-[A-F0-9]{6}$/.test(String(vuln.VulnerabilityID)) ? 'DEBIAN_TEMP_ID' :
                /^GHSA-[a-z0-9-]+$/.test(String(vuln.VulnerabilityID)) ? 'GHSA_ID' : 'OTHER_ID');
            }
            if (!publicPackageName(vuln.PkgName, ecosystem)) issues.add('VULN_NAME_GRAMMAR');
            if (!publicPackageVersion(vuln.InstalledVersion)) issues.add('VULN_VERSION_GRAMMAR');
            if (vuln.PkgPath !== undefined) issues.add(typeof vuln.PkgPath === 'string' && vuln.PkgPath.length === 0 ? 'PKG_PATH_EMPTY' : 'PKG_PATH_PRESENT');
            if (vuln.SeveritySource != null && !PUBLIC_VULN_SOURCES.includes(String(vuln.SeveritySource))) issues.add('SEVERITY_SOURCE_UNKNOWN');
            if (object(vuln.VendorSeverity)) for (const [source, level] of Object.entries(vuln.VendorSeverity)) {
              if (!PUBLIC_VULN_SOURCES.includes(source)) issues.add('VENDOR_SOURCE_UNKNOWN');
              if (!Number.isInteger(level) || (level as number) < 0 || (level as number) > 4) issues.add('VENDOR_LEVEL_INVALID');
            }
            if (!inventory.some(pkg => object(pkg) && pkg.Name === vuln.PkgName && pkg.Version === vuln.InstalledVersion)) {
              issues.add('EXACT_INVENTORY_MISMATCH');
              if (inventory.some(pkg => object(pkg) && pkg.Name === vuln.PkgName &&
                  Number.isSafeInteger(pkg.Epoch) && (pkg.Epoch as number) > 0 && `${pkg.Epoch}:${pkg.Version}` === vuln.InstalledVersion)) issues.add('EPOCH_INVENTORY_MATCH');
              if (inventory.some(pkg => object(pkg) && pkg.Name === vuln.PkgName &&
                  `${typeof pkg.Epoch === 'number' && pkg.Epoch > 0 ? `${pkg.Epoch}:` : ''}${pkg.Version}${typeof pkg.Release === 'string' && pkg.Release ? `-${pkg.Release}` : ''}` === vuln.InstalledVersion)) issues.add('CANONICAL_DEBIAN_INVENTORY_MATCH');
            }
          }
        }
        let normalized: Record<string, unknown>;
        try { const findings = parseVulnFindings(value, image, 'linux/amd64', binding);
          if (!os || os.eol) throw Error('coverage');
          const checkedAt = Date.now();
          const bytes = await auditArchiveScratch(archive.directory, `${options.cacheDir}/db`, undefined, PUBLIC_IMAGE_LIMITS);
          const report: ArchiveScanReport = { receipt: archive.receipt, scannerVersion: '0.69.3', checkedAt,
            metrics: { ...archive.metrics, scratchPeak: bytes }, vuln: { outcome: 'checked', findings, db: db.identity,
              dbPolicy: evaluateDbPolicy(db.identity, CURRENT_DB_POLICY, checkedAt), os: { outcome: 'checked' },
              node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_UNKNOWN' } } };
          validateArchiveReport(report, ['vuln'], CURRENT_DB_POLICY);
          normalized = { label: 'CHECKED', findings: findings.length, deb: findings.filter(finding => finding.ecosystem === 'deb').length,
            cve: findings.filter(finding => finding.cveId.startsWith('CVE-')).length,
            debianTemp: findings.filter(finding => finding.cveId.startsWith('TEMP-')).length, envelopeVerified: true }; }
        catch (error) { normalized = { label: rejected(error) }; }
        summary.vuln = { ...stats, identityVerified: true, osSupported: !!os, results: array(raw.Results).length,
          packages, vulnerabilities, issues: issues.counts, normalized };
      }
      await auditArchiveScratch(archive.directory, `${options.cacheDir}/db`, undefined, PUBLIC_IMAGE_LIMITS);
    }
    const after = await preflightVulnDbBundle({ ...options.trust, directory: options.releaseDir, policy: CURRENT_DB_POLICY });
    if (JSON.stringify(db.identity) !== JSON.stringify(after.identity)) throw Error('db');
    summary.dbVerifiedUnchanged = true;
    console.log(JSON.stringify(summary));
  } finally { await archive.cleanup(); }
}
main().catch(() => { console.log(JSON.stringify({ label: 'DIAGNOSTIC_FAILED' })); process.exitCode = 1; });
