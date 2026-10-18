import { NGINX_ARCHIVE_CANDIDATES, archiveProfileVersion, type ArchiveReceipt } from './bounded-image-archive.js';
import { ArchiveRejected } from './layer-tar-validator.js';
import { isPublicReceipt } from './public-image-policy.js';
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const same = (value: unknown, expected: string[]) => Array.isArray(value) && value.length === expected.length &&
  [...value].every((item, index) => item === expected[index]);
export type ArchiveBinding = { receipt: ArchiveReceipt; archivePath: string };
export function validArchiveBinding(binding: ArchiveBinding): boolean {
  if (!object(binding) || !object(binding.receipt) || typeof binding.archivePath !== 'string' ||
      !/^\/tmp\/trivy\/jobs\/[a-f0-9-]{36}\/image\.tar$/.test(binding.archivePath)) return false;
  const { receipt } = binding;
  if (isPublicReceipt(receipt)) return true;
  const target = NGINX_ARCHIVE_CANDIDATES.find(candidate => Object.entries(candidate).every(([key, value]) => receipt[key as keyof typeof candidate] === value));
  return !!target &&
    receipt.profileVersion === archiveProfileVersion(target) && receipt.resourcePolicyVersion === 'nginx-archive-resources-v1' &&
    receipt.checksVersion === 'trivy-0.69.3-archive-v1' && /^sha256:[a-f0-9]{64}$/.test(receipt.archiveSha256) &&
    Array.isArray(receipt.diffIds) && Array.isArray(receipt.layerDigests) &&
    receipt.diffIds.length > 0 && receipt.diffIds.length <= 32 && receipt.layerDigests.length === receipt.diffIds.length &&
    [...receipt.diffIds, ...receipt.layerDigests].every(value => /^sha256:[a-f0-9]{64}$/.test(value));
}
export function validateArchiveJson(value: unknown, binding: ArchiveBinding): Record<string, unknown> {
  if (!validArchiveBinding(binding) || !object(value) || value.SchemaVersion !== 2 || value.ArtifactType !== 'container_image' ||
      value.ArtifactName !== binding.archivePath || !object(value.Metadata) || value.Metadata.ImageID !== binding.receipt.configDigest ||
      !same(value.Metadata.DiffIDs, binding.receipt.diffIds) || !object(value.Metadata.ImageConfig) ||
      value.Metadata.ImageConfig.os !== 'linux' || value.Metadata.ImageConfig.architecture !== 'amd64' ||
      value.Metadata.ImageConfig.variant !== undefined || !object(value.Metadata.ImageConfig.rootfs) ||
      value.Metadata.ImageConfig.rootfs.type !== 'layers' || !same(value.Metadata.ImageConfig.rootfs.diff_ids, binding.receipt.diffIds) ||
      value.Metadata.RepoDigests !== undefined) throw new ArchiveRejected();
  return value;
}
export function validateArchiveSbom(value: unknown, binding: ArchiveBinding): Record<string, unknown> {
  if (!validArchiveBinding(binding) || !object(value) || value.bomFormat !== 'CycloneDX' || value.specVersion !== '1.6' ||
      !object(value.metadata) || !object(value.metadata.component) || value.metadata.component.type !== 'container' ||
      value.metadata.component.name !== binding.archivePath || !Array.isArray(value.metadata.component.properties) ||
      value.metadata.component.properties.length > 128) throw new ArchiveRejected();
  const properties = value.metadata.component.properties;
  const identities = properties.filter(item => object(item) && item.name === 'aquasecurity:trivy:ImageID');
  const diffIds = properties.filter(item => object(item) && item.name === 'aquasecurity:trivy:DiffID');
  if (identities.length !== 1 || identities[0].value !== binding.receipt.configDigest ||
      // CycloneDX properties are unordered in actual Trivy 0.69.3. Preserve
            // multiplicity; ordered layer identity remains bound by verified config/JSON.
            !same(diffIds.map(item => item.value).sort(), [...binding.receipt.diffIds].sort())) throw new ArchiveRejected();
  return value;
}
