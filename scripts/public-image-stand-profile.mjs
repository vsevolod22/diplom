import { join } from 'node:path';
import { createHash, createPublicKey } from 'node:crypto';
import { directory, layout, readBounded } from './setup-local-cve.mjs';

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
export const PUBLIC_IMAGE_ACTIVATION_BLOCKED =
  'Public-image activation BLOCKED: source-only profile; reviewed rollout acknowledgement, drained writers and a consistent verified backup are required. Profile-persistent up/status/stop/refresh and rollback are not implemented. Do not bypass with direct Compose or migrate the live database.';

export function assertStandProfile(profile) {
  if (!['default', PUBLIC_IMAGE_PROFILE].includes(profile)) throw new Error('Unknown LOCAL stand profile.');
}

// Offline structural validation only: no filesystem, key, DB or Docker access.
// Live release verification remains the responsibility of validateCveRelease.
export function publicImageCveConfig(root, value, profileVersion = 1) {
  if (![1, 2].includes(profileVersion)) throw new Error('Invalid public CVE profile version.');
  if (value === null) return null;
  const keys = ['version', 'release', 'manifestDigest', 'artifactSha256', 'publicKeySha256'];
  if (
    !value ||
    Object.values(value).some((v) => typeof v === 'string' && /[\x00-\x1f]/.test(v)) ||
    JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(keys.sort()) ||
    value.version !== 1 ||
    typeof value.release !== 'string' ||
    !/^db-releases\/[a-z0-9][a-z0-9_-]{0,127}$/.test(value.release) ||
    typeof value.manifestDigest !== 'string' ||
    !/^sha256:[a-f0-9]{64}$/.test(value.manifestDigest) ||
    typeof value.artifactSha256 !== 'string' ||
    !/^[a-f0-9]{64}$/.test(value.artifactSha256) ||
    typeof value.publicKeySha256 !== 'string' ||
    !/^[a-f0-9]{64}$/.test(value.publicKeySha256)
  ) {
    throw new Error('Invalid public-image CVE planning metadata.');
  }
  const state = profileVersion === 2 ? '.local-public-images' : '.local-stand';
  return Object.freeze({
    ...value,
    releaseHostDir: join(root, state, value.release),
    publicKeyPath: join(
      root,
      state,
      'trust',
      profileVersion === 2 ? `${value.publicKeySha256}.pub.pem` : 'db-signing-key.pub.pem',
    ),
  });
}

// Structure/public-anchor validation only; runtime freshness/authentication is
// still established by the backend verifier. This never opens a private key.
export function validatePublicImageCveRelease(root, value) {
  const cve = publicImageCveConfig(root, value, 2);
  if (!cve) throw new Error('Public CVE release required.');
  const state = join(root, '.local-public-images');
  directory(state, 0o700);
  directory(join(state, 'trust'), 0o700);
  directory(join(state, 'db-releases'), 0o700);
  layout(cve.releaseHostDir, true, true);
  const key = createPublicKey(readBounded(cve.publicKeyPath, 8192, 0o444));
  if (
    key.asymmetricKeyType !== 'ed25519' ||
    createHash('sha256')
      .update(key.export({ type: 'spki', format: 'der' }))
      .digest('hex') !== value.publicKeySha256
  )
    throw new Error('Public CVE anchor mismatch.');
  return cve;
}

export function publicImageRolloutPlan(composeFiles, cve) {
  return {
    profile: PUBLIC_IMAGE_PROFILE,
    mode: 'source-only',
    activation: 'blocked',
    cve,
    composeFiles,
    commands: PUBLIC_IMAGE_COMMANDS,
    worker: {
      memoryBytes: PUBLIC_IMAGE_MEMORY,
      memorySwapTotalBytes: PUBLIC_IMAGE_MEMORY,
      swapBytes: 0,
      cpus: 1,
      pids: 128,
      tmpfs: PUBLIC_IMAGE_TMPFS,
    },
    retained: [
      'dip-local-full_auth_accounts:/auth',
      'dip-local-full_scan_ledger:/data',
      'existing JWT (no rotation)',
      'CVE release/public trust/DB read-only binds when enabled',
    ],
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
