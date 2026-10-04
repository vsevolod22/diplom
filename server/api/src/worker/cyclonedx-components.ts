// Allowlist for a future SBOM stage: no raw Trivy JSON, URLs, paths or properties cross into results.
export type SbomComponent = { ecosystem: 'apk' | 'npm'; name: string; version: string };
export type ImageSbom = { image: string; platform: 'linux/amd64'; os: { name: string; version: string }; components: SbomComponent[] };

const object = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const identifier = (value: unknown, max: number): value is string =>
  typeof value === 'string' && value.length > 0 && value.length <= max &&
  /^[A-Za-z0-9@][A-Za-z0-9@._+/-]*$/.test(value);

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

export function parseImageSbom(value: unknown, image: string, platform: string): ImageSbom {
  if (!/^registry-1\.docker\.io\/library\/alpine@sha256:[a-f0-9]{64}$/.test(image) || platform !== 'linux/amd64' ||
      !object(value) || value.bomFormat !== 'CycloneDX' || value.specVersion !== '1.6' ||
      !object(value.metadata) || !object(value.metadata.component) ||
      value.metadata.component.type !== 'container' || value.metadata.component.name !== image ||
      !Array.isArray(value.components) || value.components.length === 0 || value.components.length > 1000) {
    throw new Error('Invalid or unbound SBOM');
  }
  let os: ImageSbom['os'] | undefined;
  const components: SbomComponent[] = [];
  const seen = new Set<string>();
  const distros: string[] = [];
  for (const item of value.components as unknown[]) {
    if (!object(item)) throw new Error('Invalid SBOM component');
    if (item.type === 'operating-system') {
      if (os || item.name !== 'alpine' || !identifier(item.version, 80)) throw new Error('Invalid SBOM OS');
      os = { name: 'alpine', version: item.version };
      continue;
    }
    if (item.type !== 'library' || !identifier(item.name, 128) || !identifier(item.version, 80) ||
        typeof item.purl !== 'string' || item.purl.length > 512) throw new Error('Invalid SBOM package');
    const identity = packageIdentity(item.purl, item.name, item.version);
    if (identity.distro) distros.push(identity.distro);
    const component: SbomComponent = { ecosystem: identity.ecosystem, name: item.name, version: item.version };
    const key = JSON.stringify(component);
    if (!seen.has(key)) { seen.add(key); components.push(component); }
  }
  if (!os || components.length === 0 || distros.some(distro => distro !== os.version))
    throw new Error('No verified SBOM packages');
  return { image, platform: 'linux/amd64', os, components };
}
