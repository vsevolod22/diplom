import type { ArchiveReceipt } from './bounded-image-archive.js';

export const PUBLIC_IMAGE_PROFILE = 'public-hub-amd64-v1';
export const PUBLIC_IMAGE_RESOURCE_POLICY = 'public-hub-resources-v1';
export const PUBLIC_IMAGE_CHECKS_VERSION = 'trivy-0.69.3-public-archive-v1';
export const PUBLIC_IMAGE_LIMITS = Object.freeze({
  maxLayers: 64, compressedLayer: 128 * 1024 ** 2, compressedTotal: 512 * 1024 ** 2,
  wireBytes: 544 * 1024 ** 2, requests: 320, deadlineMs: 180_000,
  expandedLayer: 512 * 1024 ** 2, expandedTotal: 1024 * 1024 ** 2, entries: 100_000,
  fileBytes: 256 * 1024 ** 2, extensionBytes: 64 * 1024, fieldBytes: 512, paxRecords: 1024,
  archiveBytes: 1152 * 1024 ** 2, scratchBytes: 2048 * 1024 ** 2,
  maxObjectBytes: 4_000_000, maxConfigBytes: 1_000_000,
  inspectionWireBytes: 16_000_000, inspectionRequests: 12, inspectionDeadlineMs: 30_000,
});

export type PublicImageTarget = {
  registry: string; repository: string; digest: string; configDigest?: string; platform: string;
};
export const publicObject = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === 'object' && !Array.isArray(value);
export const publicDigest = (value: unknown): value is `sha256:${string}` =>
  typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
export function validPublicRepository(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 255 &&
    /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/.test(value) &&
    value.split('/').every(part => part.length <= 128);
}
export function validPublicTarget(target: unknown): target is PublicImageTarget & Record<string, unknown> {
  return publicObject(target) && target.registry === 'registry-1.docker.io' &&
    validPublicRepository(target.repository) && publicDigest(target.digest) &&
    (target.configDigest === undefined || publicDigest(target.configDigest)) && target.platform === 'linux/amd64';
}

// A profile string alone is never admission. Receipts keep the existing shape and
// must bind every immutable identity field and a bounded, ordered layer inventory.
export function isPublicReceipt(receipt: unknown): receipt is ArchiveReceipt & { profileVersion: typeof PUBLIC_IMAGE_PROFILE } {
  const keys = ['registry', 'repository', 'digest', 'configDigest', 'platform', 'layerDigests', 'diffIds',
    'archiveSha256', 'profileVersion', 'resourcePolicyVersion', 'checksVersion'];
  if (!publicObject(receipt) || Object.keys(receipt).length !== keys.length || keys.some(key => !Object.hasOwn(receipt, key))) return false;
  if (!validPublicTarget(receipt) || !publicObject(receipt) || !publicDigest(receipt.configDigest) ||
      receipt.profileVersion !== PUBLIC_IMAGE_PROFILE || receipt.resourcePolicyVersion !== PUBLIC_IMAGE_RESOURCE_POLICY ||
      receipt.checksVersion !== PUBLIC_IMAGE_CHECKS_VERSION || !publicDigest(receipt.archiveSha256) ||
      !Array.isArray(receipt.layerDigests) || !Array.isArray(receipt.diffIds) ||
      receipt.layerDigests.length < 1 || receipt.layerDigests.length > PUBLIC_IMAGE_LIMITS.maxLayers ||
      receipt.layerDigests.length !== receipt.diffIds.length) return false;
  // Array#every skips holes; explicit iteration does not.
  for (let index = 0; index < receipt.layerDigests.length; index++) {
    if (!publicDigest(receipt.layerDigests[index]) || !publicDigest(receipt.diffIds[index])) return false;
  }
  return true;
}
