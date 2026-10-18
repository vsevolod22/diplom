import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { RuntimeImageLinkAdapter } from './runtime-image-link.adapter.js';
import type { LedgerStore } from '../ledger/ledger-store.js';
import type { ConfigLoader } from '../oci/pinned-image-config.js';
import type { Job } from '../ledger/ledger.js';
import type { Capture } from '../../../runtime/src/contract.js';
const hash = (b: Buffer) => `sha256:${createHash('sha256').update(b).digest('hex')}`;

test('image adapter uses same verifier instance, no root finding, exact owner/config/platform and genuine independent image outcomes', async () => {
  const configBytes = Buffer.from(
    JSON.stringify({ os: 'linux', architecture: 'amd64', config: { User: '1000' } }),
  );
  const manifestBytes = Buffer.from(
    JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      config: {
        digest: hash(configBytes),
        size: configBytes.length,
        mediaType: 'application/vnd.oci.image.config.v1+json',
      },
      layers: [],
    }),
  );
  const job: Job = {
    scanId: '00000000-0000-0000-0000-000000000001',
    registry: 'registry-1.docker.io',
    repository: 'library/alpine',
    digest: hash(manifestBytes),
    platform: 'linux/amd64',
    checks: '["sbom","vuln"]',
    scope: 'image',
    attempts: 0,
  };
  let calls = 0;
  const loader: ConfigLoader = async () => {
    calls++;
    return {
      identity: {
        registry: job.registry,
        repository: job.repository,
        manifestDigest: job.digest,
        platform: { os: 'linux', architecture: 'amd64' },
      },
      manifestBytes,
      configBytes,
    };
  };
  let checkedAt = '2026-10-08T00:00:00.000Z';
  const images = {
    ledger: {
      sbom: () => ({ outcome: 'checked', scannerVersion: '0.69.3', checkedAt }),
      vuln: () => ({ outcome: 'failed' }),
    },
  } as unknown as LedgerStore;
  const adapter = RuntimeImageLinkAdapter.controlled(
    images,
    (subject, id) => (subject === 'owner' && id === job.scanId ? job : undefined),
    loader,
  );
  const c = {
    imageConfigDigest: hash(configBytes),
    imageSemantics: 'docker-config-sha256-v1',
    hash: 'a'.repeat(64),
  } as Capture;
  const link = await adapter.resolve('owner', job.scanId, c);
  assert.equal(link.configDigest, hash(configBytes));
  assert.equal(link.manifestDigest, job.digest);
  assert.equal(link.sbom.outcome, 'checked');
  assert.equal(link.sbom.scannerVersion, '0.69.3');
  assert.equal(link.vuln.outcome, 'failed');
  assert.equal(link.vuln.scannerVersion, null);
  assert.equal(calls, 1);
  await assert.rejects(adapter.resolve('stranger', job.scanId, c), /IMAGE_LINK_UNAVAILABLE/);
  assert.equal(calls, 1);
  await assert.rejects(
    adapter.resolve('owner', job.scanId, { ...c, imageConfigDigest: `sha256:${'b'.repeat(64)}` }),
    /IMAGE_IDENTITY_MISMATCH/,
  );
  const bad = RuntimeImageLinkAdapter.controlled(
    images,
    () => job,
    async () => ({
      identity: {
        registry: job.registry,
        repository: job.repository,
        manifestDigest: job.digest,
        platform: { os: 'linux', architecture: 'arm64' },
      },
      manifestBytes,
      configBytes,
    }),
  );
  await assert.rejects(bad.resolve('owner', job.scanId, c), /IMAGE_LINK_UNAVAILABLE/);
  checkedAt = '2026-10-08 12:34:56';
  assert.equal((await adapter.resolve('owner', job.scanId, c)).sbom.checkedAt, '2026-10-08T12:34:56.000Z');
  for (const invalid of [
    '2026-02-30 12:34:56',
    '2026-10-08T12:34:56',
    '2026-10-08T12:34:56+02:00',
    '',
    'PRIVATE_DATE_CANARY',
  ]) {
    checkedAt = invalid;
    await assert.rejects(adapter.resolve('owner', job.scanId, c), /^Error: IMAGE_LINK_UNAVAILABLE$/);
  }
});
