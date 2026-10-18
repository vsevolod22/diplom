// Bounded normalized identities shared by the public CVE and CycloneDX boundaries.
export const PUBLIC_ECOSYSTEMS = ['apk', 'deb', 'rpm', 'npm', 'pypi', 'gem', 'gomod', 'cargo', 'maven', 'composer', 'nuget'] as const;
export type PackageEcosystem = typeof PUBLIC_ECOSYSTEMS[number];
export const PUBLIC_OS_ECOSYSTEMS: Readonly<Record<string, PackageEcosystem>> = Object.freeze({
  alpine: 'apk', debian: 'deb', ubuntu: 'deb', redhat: 'rpm', centos: 'rpm', rocky: 'rpm', alma: 'rpm', oracle: 'rpm', amazon: 'rpm',
});
const languageTypes: Readonly<Record<string, PackageEcosystem>> = Object.freeze({
  'node-pkg': 'npm', npm: 'npm', yarn: 'npm', pnpm: 'npm',
    'python-pkg': 'pypi', pip: 'pypi', pipenv: 'pypi', poetry: 'pypi', uv: 'pypi',
    gemspec: 'gem', bundler: 'gem', gobinary: 'gomod', gomod: 'gomod',
  'rust-binary': 'cargo', cargo: 'cargo', 'jar': 'maven', pom: 'maven', 'gradle': 'maven',
  composer: 'composer', 'dotnet-core': 'nuget', nuget: 'nuget',
});
export function publicResultEcosystem(result: Record<string, unknown>, family?: string): PackageEcosystem {
  const type = typeof result.Type === 'string' ? result.Type : '';
  const ecosystem = result.Class === 'os-pkgs' && type === family && Object.hasOwn(PUBLIC_OS_ECOSYSTEMS, type)
    ? PUBLIC_OS_ECOSYSTEMS[type]
    : result.Class === 'lang-pkgs' && Object.hasOwn(languageTypes, type) ? languageTypes[type] : undefined;
  if (!ecosystem) throw new Error('Unsupported public result type');
  return ecosystem;
}
export function publicPackageName(value: unknown, ecosystem: PackageEcosystem): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128) return false;
  if (ecosystem === 'npm') return /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(value);
  if (ecosystem === 'gomod' && ['stdlib', 'toolchain'].includes(value)) return true;
    if (ecosystem === 'gomod') return /^[A-Za-z0-9][A-Za-z0-9._+-]*(?:\/[A-Za-z0-9][A-Za-z0-9._+-]*)+$/.test(value);
  if (ecosystem === 'composer') return /^[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*$/.test(value);
  if (ecosystem === 'maven') return /^[A-Za-z0-9][A-Za-z0-9._-]*:[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value);
  return /^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(value);
}
export const publicPackageVersion = (value: unknown): value is string =>
  typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._+~:!,-]{0,79}$/.test(value);
// Trivy's Debian inventory separates epoch/upstream/revision; InstalledVersion
// and CycloneDX display versions carry their canonical dpkg composition.
export function publicDebianVersion(version: unknown, epoch?: unknown, release?: unknown): string | undefined {
  if (!publicPackageVersion(version) || epoch !== undefined && (typeof epoch !== 'number' ||
      !Number.isSafeInteger(epoch) || epoch < 0 || epoch > 2_147_483_647) ||
      release !== undefined && (typeof release !== 'string' || release !== '' && !publicPackageVersion(release))) return undefined;
  if (epoch !== undefined && version.includes(':')) return undefined;
  const canonical = `${typeof epoch === 'number' && epoch > 0 ? `${epoch}:` : ''}${version}${release ? `-${release}` : ''}`;
  return publicPackageVersion(canonical) ? canonical : undefined;
}
export const publicVulnerabilityId = (value: unknown, ecosystem: PackageEcosystem): value is string =>
  typeof value === 'string' && (/^CVE-[0-9]{4}-[0-9]{4,12}$/.test(value) ||
    ecosystem === 'deb' && /^TEMP-[0-9]{7}-[A-F0-9]{6}$/.test(value));

export function publicOs(value: unknown): { name: string; version: string; eol: boolean } | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const os = value as Record<string, unknown>;
  if (typeof os.Family !== 'string' || !Object.hasOwn(PUBLIC_OS_ECOSYSTEMS, os.Family) ||
      typeof os.Name !== 'string' || !/^[0-9]+(?:\.[0-9]+){0,3}$/.test(os.Name) || os.Name.length > 80 ||
      os.EOSL !== undefined && typeof os.EOSL !== 'boolean') return undefined;
  return { name: os.Family, version: os.Name, eol: os.EOSL === true };
}
