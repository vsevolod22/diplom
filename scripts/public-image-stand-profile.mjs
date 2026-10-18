import { join } from 'node:path';

export const PUBLIC_IMAGE_PROFILE = 'public-images';
export const PUBLIC_IMAGE_COMMANDS = Object.freeze({
  api: Object.freeze(['node', '--import', 'tsx', 'src/oci/public-image.main.ts']),
  worker: Object.freeze(['node', '--import', 'tsx', 'src/worker/public-image-worker.main.ts']),
});
export const PUBLIC_IMAGE_TMPFS = Object.freeze([
  '/tmp:rw,noexec,nosuid,uid=65532,gid=65532,size=16m',
  '/tmp/trivy:rw,noexec,nosuid,uid=65532,gid=65532,size=2304m',
]);
export const PUBLIC_IMAGE_MEMORY = 4294967296;
export const PUBLIC_IMAGE_ACTIVATION_BLOCKED = 'Public-image activation BLOCKED: source-only profile; reviewed rollout acknowledgement, drained writers and a consistent verified backup are required. Profile-persistent up/status/stop/refresh and rollback are not implemented. Do not bypass with direct Compose or migrate the live database.';

export function assertStandProfile(profile) {
  if (!['default', PUBLIC_IMAGE_PROFILE].includes(profile)) throw new Error('Unknown LOCAL stand profile.');
}

// Offline structural validation only: no filesystem, key, DB or Docker access.
// Live release verification remains the responsibility of validateCveRelease.
export function publicImageCveConfig(root, value) {
  if (value === null) return null;
  const keys = ['version', 'release', 'manifestDigest', 'artifactSha256', 'publicKeySha256'];
  if (!value || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(keys.sort()) || value.version !== 1 ||
      typeof value.release !== 'string' || !/^db-releases\/[a-z0-9][a-z0-9_-]{0,127}$/.test(value.release) ||
      typeof value.manifestDigest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(value.manifestDigest) ||
      typeof value.artifactSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.artifactSha256) ||
      typeof value.publicKeySha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.publicKeySha256)) {
    throw new Error('Invalid public-image CVE planning metadata.');
  }
  return Object.freeze({ ...value, releaseHostDir: join(root, '.local-stand', value.release),
    publicKeyPath: join(root, '.local-stand/trust/db-signing-key.pub.pem') });
}

export function publicImageRolloutPlan(composeFiles, cve) {
  return {
    profile: PUBLIC_IMAGE_PROFILE,
    mode: 'source-only', activation: 'blocked', cve,
    composeFiles,
    commands: PUBLIC_IMAGE_COMMANDS,
    worker: { memoryBytes: PUBLIC_IMAGE_MEMORY, memorySwapTotalBytes: PUBLIC_IMAGE_MEMORY,
      swapBytes: 0, cpus: 1, pids: 128, tmpfs: PUBLIC_IMAGE_TMPFS },
    retained: ['dip-local-full_auth_accounts:/auth', 'dip-local-full_scan_ledger:/data',
      'existing JWT (no rotation)', 'CVE release/public trust/DB read-only binds when enabled'],
    requiredBeforeActivation: [
      'Reviewed rollout acknowledgement bound to the source revision, image IDs, profile and database schema.',
      'Admission closed; scheduler/refresh excluded by the shared lock; API and worker writers drained; no active leases or other volume writers.',
      'Consistent account and ledger/report backup including SQLite WAL state, existing JWT preserved privately; integrity and restore verified.',
      'Profile-persistent up/status/stop/refresh plus interrupted/mixed-profile recovery and reviewed rollback implemented and tested.',
      'Isolated restore rehearsal and live cgroup/tmpfs/DB trust/readiness qualification; never auto-migrate a live DB.',
    ],
    warning: PUBLIC_IMAGE_ACTIVATION_BLOCKED,
  };
}
