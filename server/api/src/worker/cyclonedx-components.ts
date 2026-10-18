import { validateArchiveSbom, type ArchiveBinding } from '../oci/archive-identity.js';
import { isPublicReceipt } from '../oci/public-image-policy.js';
import { PUBLIC_ECOSYSTEMS, PUBLIC_OS_ECOSYSTEMS, publicOs, publicPackageName, publicPackageVersion, publicDebianVersion, type PackageEcosystem } from './public-image-evidence.js';

// Allowlist for a future SBOM stage: no raw Trivy JSON, URLs, paths or properties cross into results.
export type SbomComponent = { ecosystem: PackageEcosystem; name: string; version: string };
export type ImageSbom = { image: string; platform: 'linux/amd64'; os: { name: string; version: string }; components: SbomComponent[] };

const object = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const identifier = (value: unknown, max: number): value is string =>
  typeof value === 'string' && value.length > 0 && value.length <= max &&
  /^[A-Za-z0-9@][A-Za-z0-9@._+/-]*$/.test(value);

function publicPackageIdentity(purl: string, name: string, version: string, os: ReturnType<typeof publicOs>, group?: unknown): { ecosystem: PackageEcosystem; distro?: string; name?: string } {
  const match = /^pkg:([a-z]+)\/([^?#]+)@([^/?#]+)(?:\?([^#]+))?$/.exec(purl);
  if (!match || !os) throw new Error('Invalid public SBOM identity');
  const ecosystem = match[1] === 'golang' ? 'gomod' : match[1];
  if (!(PUBLIC_ECOSYSTEMS as readonly string[]).includes(ecosystem)) throw new Error('Unsupported SBOM ecosystem');
  const kind = ecosystem as PackageEcosystem;
  let path: string, encodedVersion: string;
  try { path = decodeURIComponent(match[2]); encodedVersion = decodeURIComponent(match[3]); }
  catch { throw new Error('Invalid SBOM encoding'); }
  const osPackage = ['apk', 'deb', 'rpm'].includes(kind);
  const slash = path.indexOf('/');
  const namespace = path.slice(0, slash), packageName = path.slice(slash + 1);
  const normalizedName = kind === 'maven' ? path.replace('/', ':') : osPackage ? packageName : path;
  const displayName = typeof group === 'string' && ['maven', 'npm', 'composer'].includes(kind)
    ? `${group}${kind === 'maven' ? ':' : '/'}${name}` : name;
  if (normalizedName !== displayName || !publicPackageName(displayName, kind) || !publicPackageVersion(version))
    throw new Error('Mismatched public SBOM identity');
  const qualifiers = new Map<string, string>();
  for (const part of match[4]?.split('&') ?? []) {
    const pair = /^([a-z_]+)=([A-Za-z0-9._+-]+)$/.exec(part);
    if (!pair || qualifiers.has(pair[1])) throw new Error('Invalid SBOM qualifiers');
    qualifiers.set(pair[1], pair[2]);
  }
  const epoch = qualifiers.get('epoch');
  if (epoch !== undefined && (kind !== 'deb' || !/^[1-9][0-9]{0,9}$/.test(epoch))) throw new Error('Invalid SBOM epoch');
  const identityVersion = epoch === undefined ? encodedVersion : publicDebianVersion(encodedVersion, Number(epoch));
  if (identityVersion !== version) throw new Error('Mismatched public SBOM identity');
  if (osPackage) {
    const architectures = kind === 'deb' ? ['amd64', 'all'] : ['x86_64', 'noarch'];
    if (PUBLIC_OS_ECOSYSTEMS[os.name] !== kind || namespace !== os.name || slash < 1 || qualifiers.size !== (epoch === undefined ? 2 : 3) ||
        !architectures.includes(qualifiers.get('arch') ?? '') ||
        ![os.version, `${os.name}-${os.version}`].includes(qualifiers.get('distro') ?? ''))
      throw new Error('Unbound public SBOM OS package');
    return { ecosystem: kind, distro: os.version };
  }
  // Other qualifiers (download URLs, paths, custom fields) are not supported evidence.
  if (qualifiers.size) throw new Error('Unsupported SBOM qualifiers');
  return { ecosystem: kind, name: displayName };
}

function packageIdentity(purl: string, name: string, version: string): { ecosystem: 'apk' | 'npm'; distro?: string } {
  // Compare the identity encoded in the purl rather than trusting unrelated display fields.
  const match = /^pkg:(apk|npm)\/([^?#]+)@([^/?#]+)(?:\?([^#]+))?$/.exec(purl);
  if (!match) throw new Error('Invalid SBOM package identity');
  let path: string;
  let purlVersion: string;
  try {
    path = decodeURIComponent(match[2]);
    purlVersion = decodeURIComponent(match[3]);
  } catch { throw new Error('Invalid SBOM package encoding'); }
  if (purlVersion !== version ||
      (match[1] === 'apk' ? path !== `alpine/${name}` : path !== name) ||
      !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._+-]*$/.test(name))
    throw new Error('Mismatched SBOM package identity');
  const qualifiers = match[4];
  if (!qualifiers) {
    if (match[1] === 'apk') throw new Error('Unbound SBOM package identity');
    return { ecosystem: 'npm' };
  }
  // Actual Alpine Trivy output includes these two qualifiers. Bind them to the
  // selected architecture and the OS component, rejecting arbitrary metadata.
  const q = /^(?:arch=x86_64&distro=|distro=)([0-9]+(?:\.[0-9]+){2})(?:&arch=x86_64)?$/.exec(qualifiers);
  if (match[1] !== 'apk' || !q || !qualifiers.includes('arch=x86_64') ||
      qualifiers.split('&').length !== 2) throw new Error('Invalid SBOM package qualifiers');
  return { ecosystem: 'apk', distro: q[1] };
}

export function parseImageSbom(value: unknown, image: string, platform: string, binding?: ArchiveBinding): ImageSbom {
  const publicImage = !!binding && isPublicReceipt(binding.receipt);
  if (binding) {
    validateArchiveSbom(value, binding);
    if (image !== `${binding.receipt.registry}/${binding.receipt.repository}@${binding.receipt.digest}` || platform !== binding.receipt.platform)
      throw new Error('Unbound archive SBOM');
  }
  if ((!binding && !/^registry-1\.docker\.io\/library\/alpine@sha256:[a-f0-9]{64}$/.test(image)) || platform !== 'linux/amd64' ||
      !object(value) || value.bomFormat !== 'CycloneDX' || value.specVersion !== '1.6' ||
      !object(value.metadata) || !object(value.metadata.component) ||
      value.metadata.component.type !== 'container' || value.metadata.component.name !== (binding?.archivePath ?? image) ||
      !Array.isArray(value.components) || value.components.length === 0 || value.components.length > 1000) {
    throw new Error('Invalid or unbound SBOM');
  }
  let os: ImageSbom['os'] | undefined;
  const components: SbomComponent[] = [];
  const seen = new Set<string>();
  const distros: string[] = [];
  // Actual CycloneDX OS components are not ordered ahead of libraries.
  const osItems = publicImage ? value.components.filter(entry => object(entry) && entry.type === 'operating-system') : [];
  const publicOS = osItems.length === 1 && object(osItems[0]) ? publicOs({ Family: osItems[0].name, Name: osItems[0].version }) : undefined;
  for (const item of value.components as unknown[]) {
    if (!object(item)) throw new Error('Invalid SBOM component');
    if (item.type === 'operating-system') {
      if (os || (publicImage ? !publicOs({ Family: item.name, Name: item.version }) :
          item.name !== 'alpine' || !identifier(item.version, 80))) throw new Error('Invalid SBOM OS');
      os = { name: item.name as string, version: item.version as string };
      continue;
    }
    if (item.type !== 'library' || (publicImage ? typeof item.name !== 'string' || !publicPackageVersion(item.version) :
            !identifier(item.name, 128) || !identifier(item.version, 80)) ||
        typeof item.purl !== 'string' || item.purl.length > 512) throw new Error('Invalid SBOM package');
    const identity: { ecosystem: PackageEcosystem; distro?: string; name?: string } = publicImage ?
          publicPackageIdentity(item.purl, item.name as string, item.version as string, publicOS, item.group) :
          packageIdentity(item.purl, item.name as string, item.version as string);
    if (identity.distro) distros.push(identity.distro);
    const component: SbomComponent = { ecosystem: identity.ecosystem, name: identity.name ?? item.name as string, version: item.version as string };
    const key = JSON.stringify(component);
    if (!seen.has(key)) { seen.add(key); components.push(component); }
  }
  if (!os || components.length === 0 || distros.some(distro => distro !== os.version))
    throw new Error('No verified SBOM packages');
  return { image, platform: 'linux/amd64', os, components };
}
