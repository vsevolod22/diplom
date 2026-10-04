import { createHash } from 'node:crypto';
import { validateArchiveJson, type ArchiveBinding } from '../oci/archive-identity.js';

// Data-only normalizer. The caller must separately enforce a successful Trivy 0.69.3
// subprocess, bounded JSON input bytes, and an isolated, pinned scan invocation.
export type VulnFinding = {
  findingId: string;
  cveId: string;
  ecosystem: 'apk' | 'npm';
  packageName: string;
  installedVersion: string;
  severity: 'UNKNOWN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  severitySources: string[];
  provenanceRef: string;
  fixedVersion: string | null;
};
export const MAX_VULN_FINDINGS = 1000;
const imagePattern = /^registry-1\.docker\.io\/library\/alpine@sha256:[a-f0-9]{64}$/;
const versionPattern = /^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,79}$/;
const apkNamePattern = /^[a-z0-9][a-z0-9._+-]{0,127}$/;
const npmNamePattern = /^(?:@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*|[a-z0-9][a-z0-9._-]*)$/;
const severities = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
// Only recognized advisory authorities can leave this boundary as text.
const sources = new Set([
  'alpine', 'nvd', 'ghsa', 'npm', 'nodejs-security-wg', 'osv', 'cve',
  'redhat', 'ubuntu', 'photon', 'amazon', 'oracle-oval', 'julia', 'alma',
  'azure', 'rocky', 'cbl-mariner', 'bitnami', 'ruby-advisory-db', 'bottlerocket',
]);

const object = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
function validSource(value: unknown): value is string {
  return typeof value === 'string' && sources.has(value);
}
function validVersion(value: unknown): value is string {
  return typeof value === 'string' && versionPattern.test(value);
}
// Never propagate the path: only bounded relative ASCII segments contribute to the hash.
function validPackagePath(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 512 &&
    value.split('/').every(segment => segment.length > 0 && segment.length <= 128 &&
      segment !== '.' && segment !== '..' && /^[A-Za-z0-9@._+-]+$/.test(segment));
}

export function parseVulnFindings(value: unknown, image: string, platform: string, binding?: ArchiveBinding): VulnFinding[] {
  if (binding) {
    validateArchiveJson(value, binding);
    if (image !== `${binding.receipt.registry}/${binding.receipt.repository}@${binding.receipt.digest}` || platform !== binding.receipt.platform)
      throw new Error('Unbound archive vulnerabilities');
  }
  if ((!binding && !imagePattern.test(image)) || platform !== 'linux/amd64' || !object(value) ||
      value.SchemaVersion !== 2 || value.ArtifactType !== 'container_image' || value.ArtifactName !== (binding?.archivePath ?? image) ||
      !object(value.Metadata) || (!binding && (!Array.isArray(value.Metadata.RepoDigests) ||
      value.Metadata.RepoDigests.length !== 1 || value.Metadata.RepoDigests[0] !== image)) ||
      !object(value.Metadata.ImageConfig) || value.Metadata.ImageConfig.os !== 'linux' ||
      value.Metadata.ImageConfig.architecture !== 'amd64' ||
      !object(value.Metadata.OS) || value.Metadata.OS.Family !== 'alpine' ||
      !validVersion(value.Metadata.OS.Name) || !Array.isArray(value.Results) ||
      value.Results.length > MAX_VULN_FINDINGS) throw new Error('Invalid or unbound vulnerability report');

  const findings: VulnFinding[] = [];

  let count = 0;
  let verifiedOsCoverage = false;
  let packageCount = 0;
  if (value.Results.length === 0) throw new Error('No vulnerability coverage');
  const byLocation = new Map<string, VulnFinding>();
  for (const result of value.Results as unknown[]) {
    if (!object(result) || typeof result.Target !== 'string' || result.Target.length === 0 ||
        result.Target.length > 512 || /[\x00-\x1f\x7f]/.test(result.Target) ||
        /(?:https?:\/\/|[?#])/.test(result.Target) ||
        !((result.Class === 'os-pkgs' && result.Type === 'alpine') ||
        (result.Class === 'lang-pkgs' && result.Type === 'node-pkg')) ||
        (result.Secrets !== undefined && (!Array.isArray(result.Secrets) || result.Secrets.length !== 0)) ||
        (result.Vulnerabilities !== undefined && !Array.isArray(result.Vulnerabilities)) ||
        (Array.isArray(result.Vulnerabilities) && result.Vulnerabilities.length > MAX_VULN_FINDINGS))
      throw new Error('Invalid vulnerability result');
    const ecosystem = result.Type === 'alpine' ? 'apk' : 'npm';
    if (result.Packages !== undefined) {
      if (!Array.isArray(result.Packages) ||
          (packageCount += result.Packages.length) > MAX_VULN_FINDINGS)
        throw new Error('Invalid package inventory');
      for (const pkg of result.Packages as unknown[]) {
        if (!object(pkg) || typeof pkg.Name !== 'string' || pkg.Name.length > 128 ||
            !(ecosystem === 'apk' ? apkNamePattern : npmNamePattern).test(pkg.Name) ||
            !validVersion(pkg.Version)) throw new Error('Invalid package inventory');
      }
    }
    if (ecosystem === 'apk' &&
        ((Array.isArray(result.Packages) && result.Packages.length > 0) ||
         (Array.isArray(result.Vulnerabilities) && result.Vulnerabilities.length > 0)))
      verifiedOsCoverage = true;
    // An empty/missing Vulnerabilities list is not proof of a scan without inventory.
    if ((!Array.isArray(result.Vulnerabilities) || result.Vulnerabilities.length === 0) &&
        (!Array.isArray(result.Packages) || result.Packages.length === 0))
      throw new Error('No vulnerability coverage');
    // Targets can contain local paths: retain only a bounded opaque provenance key.
    const targetRef = `target-${createHash('sha256').update(result.Target).digest('hex')}`;
    for (const raw of (result.Vulnerabilities ?? []) as unknown[]) {
      if (++count > MAX_VULN_FINDINGS) throw new Error('Too many vulnerabilities');
      if (!object(raw) || typeof raw.VulnerabilityID !== 'string' ||
          !/^CVE-[0-9]{4}-[0-9]{4,12}$/.test(raw.VulnerabilityID) ||
          typeof raw.PkgName !== 'string' || raw.PkgName.length > 128 ||
          !(ecosystem === 'apk' ? apkNamePattern : npmNamePattern).test(raw.PkgName) ||
          !validVersion(raw.InstalledVersion) ||
          (raw.FixedVersion !== undefined && raw.FixedVersion !== '' && !validVersion(raw.FixedVersion)) ||
          typeof raw.Severity !== 'string' || !severities.includes(raw.Severity as typeof severities[number]) ||
          (raw.SeveritySource != null && !validSource(raw.SeveritySource)) ||
          (ecosystem === 'npm' && !validPackagePath(raw.PkgPath))) throw new Error('Invalid vulnerability');
      // Missing/null source is not evidence that Alpine (or any vendor) supplied the severity.
      const severitySources = new Set<string>([raw.SeveritySource == null ? 'unknown' : raw.SeveritySource as string]);
      if (raw.VendorSeverity !== undefined) {
        if (!object(raw.VendorSeverity) || Object.keys(raw.VendorSeverity).length > 16)
          throw new Error('Invalid severity sources');
        for (const [source, level] of Object.entries(raw.VendorSeverity)) {
          if (!validSource(source) || !Number.isInteger(level) || (level as number) < 0 || (level as number) > 4)
            throw new Error('Invalid severity source');
          severitySources.add(source);
        }
      }
      const fixedVersion = raw.FixedVersion === undefined || raw.FixedVersion === '' ? null : raw.FixedVersion as string;
      const provenanceRef = ecosystem === 'npm'
        ? `target-${createHash('sha256').update(JSON.stringify([result.Target, raw.PkgPath])).digest('hex')}`
        : targetRef;
      const key = JSON.stringify([...(binding ? [image, platform, 'vuln'] : []), ecosystem, provenanceRef, raw.VulnerabilityID, raw.PkgName, raw.InstalledVersion]);
      const existing = byLocation.get(key);
      if (existing) {
        if (existing.severity !== raw.Severity || existing.fixedVersion !== fixedVersion)
          throw new Error('Conflicting vulnerability assessments');
        existing.severitySources = [...new Set([...existing.severitySources, ...severitySources])].sort();
        continue;
      }
      const finding: VulnFinding = { findingId: `vuln-${createHash('sha256').update(key).digest('hex')}`,
        cveId: raw.VulnerabilityID, ecosystem, packageName: raw.PkgName,
        installedVersion: raw.InstalledVersion, severity: raw.Severity as VulnFinding['severity'],
        severitySources: [...severitySources].sort(), provenanceRef, fixedVersion };
      byLocation.set(key, finding);
      findings.push(finding);
    }
  }
  if (!verifiedOsCoverage) throw new Error('No verified OS coverage');
  return findings;
}
