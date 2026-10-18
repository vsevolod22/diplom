import { randomUUID } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { PUBLIC_IMAGE_PROFILE, PUBLIC_IMAGE_RESOURCE_POLICY, PUBLIC_IMAGE_CHECKS_VERSION } from '../oci/public-image-policy.js';
import type { ArchiveReceipt } from '../oci/bounded-image-archive.js';
import type { scanPublicImageArchive, ArchiveScanReport } from './archive-scan-worker.js';
import type { VulnScanOptions } from './vuln-worker.js';
import { auditArchiveScratch } from './archive-scratch.js';

// Synthetic identities only: these fixtures do not claim actual Trivy or registry qualification.
export const publicTarget = { registry: 'registry-1.docker.io', repository: 'example/application',
  digest: `sha256:${'a'.repeat(64)}`, configDigest: `sha256:${'b'.repeat(64)}`, platform: 'linux/amd64' } as const;
export const publicReceipt: ArchiveReceipt = { ...publicTarget, layerDigests: [`sha256:${'c'.repeat(64)}`],
  diffIds: [`sha256:${'d'.repeat(64)}`], archiveSha256: `sha256:${'e'.repeat(64)}`,
  profileVersion: PUBLIC_IMAGE_PROFILE, resourcePolicyVersion: PUBLIC_IMAGE_RESOURCE_POLICY, checksVersion: PUBLIC_IMAGE_CHECKS_VERSION };
export const publicArchivePath = `/tmp/trivy/jobs/${randomUUID()}/image.tar`;
export const publicBinding = { receipt: publicReceipt, archivePath: publicArchivePath };
export const publicImage = `${publicTarget.registry}/${publicTarget.repository}@${publicTarget.digest}`;
export const publicMetrics = { wireBytes: 100, requests: 5, compressedBytes: 50, expandedBytes: 2048,
  entries: 1, archiveBytes: 7, reservationPeak: 4096 };
export const publicRaw = (family = 'debian', version = '12.12') => ({
  SchemaVersion: 2, ArtifactType: 'container_image', ArtifactName: publicArchivePath,
  Metadata: { ImageID: publicTarget.configDigest, DiffIDs: publicReceipt.diffIds,
    Layers: publicReceipt.diffIds.map(DiffID => ({ DiffID, Size: 2048 })),
    ImageConfig: { os: 'linux', architecture: 'amd64', rootfs: { type: 'layers', diff_ids: publicReceipt.diffIds },
      config: { Env: ['CANARY_SECRET=do-not-publish'] } }, OS: { Family: family, Name: version } },
  Results: [{ Class: 'os-pkgs', Type: family, Target: `${family} ${version}`, Packages: [{ Name: 'libc6', Version: '2.36-9' }] }] as unknown[],
});
export const publicBom = () => ({ bomFormat: 'CycloneDX', specVersion: '1.6', metadata: { component: {
  type: 'container', name: publicArchivePath, properties: [
    { name: 'aquasecurity:trivy:ImageID', value: publicTarget.configDigest },
    ...publicReceipt.diffIds.map(value => ({ name: 'aquasecurity:trivy:DiffID', value })),
  ],
} }, components: [
  { type: 'library', name: 'libc6', version: '2.36-9', purl: 'pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12.12' },
  { type: 'operating-system', name: 'debian', version: '12.12' },
] as unknown[] });
export function publicDb() {
  return { envelopeVersion: 1, signer: 'local-db-operator-v1', source: `ghcr.io/aquasecurity/trivy-db@sha256:${'f'.repeat(64)}`,
    schemaVersion: 2, manifestDigest: `sha256:${'f'.repeat(64)}`, artifactSha256: 'a'.repeat(64), metadataSha256: 'b'.repeat(64),
    dbSha256: 'c'.repeat(64), updatedAt: new Date(Date.now() - 60_000).toISOString(), downloadedAt: new Date(Date.now() - 30_000).toISOString(),
    nextUpdate: new Date(Date.now() + 3_600_000).toISOString() };
}
export const publicVulnOptions: VulnScanOptions = { timeoutMs: 120_000, cacheDir: '/synthetic/cache', releaseDir: '/synthetic/release',
  trust: { trustedPublicKeyPem: '', expectedSigner: 'local-db-operator-v1', expectedSource: '', expectedSchemaVersion: 2,
    expectedArtifactSha256: 'a'.repeat(64), expectedManifestDigest: `sha256:${'f'.repeat(64)}` } };
export type PublicLifecycle = NonNullable<Parameters<typeof scanPublicImageArchive>[2]>;
export async function publicLifecycle(invoke: PublicLifecycle['invoke'] = async check => check === 'sbom' ? publicBom() : publicRaw()) {
  const directory = await mkdtemp(`${tmpdir()}/public-image-fixture-`);
  await mkdir(`${directory}/attempt`); await writeFile(`${directory}/attempt/image.tar`, 'archive');
  const identity = publicDb();
  const lifecycle: PublicLifecycle = { requireScanner() {}, prepare: async () => ({ receipt: publicReceipt,
    archivePath: publicArchivePath, directory: `${directory}/attempt`, metrics: publicMetrics,
    cleanup: async () => rm(directory, { recursive: true, force: true }) }), invoke,
    audit: auditArchiveScratch, verifiedDb: async () => identity };
  return { directory, lifecycle };
}
export const publicReport = (): ArchiveScanReport => ({ receipt: publicReceipt, scannerVersion: '0.69.3', checkedAt: Date.now(),
  metrics: { ...publicMetrics, scratchPeak: 7 }, secret: { outcome: 'checked', findings: [] } });
