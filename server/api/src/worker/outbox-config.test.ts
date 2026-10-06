import assert from 'node:assert/strict';
import { configBytes } from './config-test-fixtures.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { ScanLedger } from '../ledger/ledger.js';
import { createPinnedConfigLoader } from '../oci/pinned-image-config.js';
import { consumeOne } from './outbox-consumer.js';

for (const [user, expected] of [['0', 'checked'], ['1000', 'checked'], ['CANARY_USER', 'unsupported'], [null, 'checked'],
  [false, 'failed'], [0, 'failed'], [[], 'failed'], [{}, 'failed']] as const) {
  test(`actual consumer + pinned loader + module + SQLite config-only ${typeof user}:${JSON.stringify(user)}`, async () => {
    const dir = mkdtempSync(join(tmpdir(), 'outbox-config-'));
    const ledger = new ScanLedger(join(dir, 'ledger.sqlite'));
    try {
      const bytes = configBytes(user);
      const id = ledger.enqueue({ subject: 'alice', idempotencyKey: 'config-only', registry: 'registry-1.docker.io',
        repository: 'library/alpine', digest: bytes.digest, platform: 'linux/amd64', checks: '["config"]' }).scanId;
      let calls = 0;
      const configLoader = createPinnedConfigLoader(async (_gateway, url, _headers, cap, deadline, _sink, signal) => {
        calls++; assert.equal(cap, 1_000_000); assert.ok(deadline! <= 30_000); assert.ok(signal);
        const body = url.pathname.includes('/manifests/') ? bytes.manifest : bytes.config;
        return { status: 200, headers: { 'content-type': url.pathname.includes('/manifests/') ? 'application/vnd.oci.image.manifest.v1+json' : 'application/octet-stream' }, body };
      });
      await consumeOne(ledger, { timeoutMs: 1000, dbDir: '/unused', configLoader }, async () => { throw new Error('legacy must not run'); }, 1000);
      assert.equal(calls, 2);
      const result = ledger.configResult(id, 'alice')!;
      assert.equal(result.config.outcome, expected);
      assert.equal(result.checksVersion, 'image-config-user-v1');
            assert.equal(result.resourcePolicyVersion, 'image-config-policy-v1');
            assert.deepEqual(result.completedRuleIds, expected === 'checked' ? ['IMGCFG_USER_ROOT'] : []);
            if (user === null) assert.equal(result.findings[0]?.classification, 'DEFAULT_ROOT');
            if (expected === 'failed') {
              assert.equal(result.config.reason, 'INVALID_CONFIG');
              assert.deepEqual(result.findings, []);
            }
      assert.equal(result.history.outcome, 'unsupported');
      assert.equal(result.dockerfile.reason, 'SOURCE_NOT_PROVIDED');
      assert.equal(result.iac.reason, 'SOURCE_NOT_PROVIDED');
      assert.equal(JSON.stringify(result).includes('CANARY'), false);
      assert.equal(ledger.state(id, 'alice'), expected === 'checked' ? 'completed' : 'failed');
      assert.equal(ledger.configResult(id, 'bob'), undefined);
      assert.deepEqual(ledger.events(id, 'alice', null)?.map(event => event.state), ['queued', 'running', expected === 'checked' ? 'completed' : 'failed']);
    } finally { ledger.close(); rmSync(dir, { recursive: true, force: true }); }
  });
}

for (const configOk of [false, true]) for (const siblingsOk of [false, true]) {
  test(`four-check consumer preserves config=${configOk} and all legacy siblings=${siblingsOk} independently`, async () => {
    const dir = mkdtempSync(join(tmpdir(), 'outbox-config-independent-'));
    const ledger = new ScanLedger(join(dir, 'ledger.sqlite'));
    try {
      const bytes = configBytes(configOk ? '0' : false);
      const image = `registry-1.docker.io/library/alpine@${bytes.digest}`;
      const id = ledger.enqueue({ subject: 'alice', idempotencyKey: 'all-four', registry: 'registry-1.docker.io',
        repository: 'library/alpine', digest: bytes.digest, platform: 'linux/amd64', checks: '["secret","sbom","vuln","config"]' }).scanId;
      // Trust fields belong only to the injected scanner fixture; no DB preflight/live CVE proof is claimed.
      const vuln = { cacheDir: '/unused', releaseDir: '/unused', trust: { trustedPublicKeyPem: 'fixture-only',
        expectedSigner: 'fixture-only', expectedSource: 'fixture-only', expectedSchemaVersion: 2,
        expectedManifestDigest: `sha256:${'b'.repeat(64)}`, expectedArtifactSha256: 'c'.repeat(64) } };
      await consumeOne(ledger, { timeoutMs: 1000, dbDir: '/unused', vuln, configLoader: createPinnedConfigLoader(async (_gateway, url) => ({
        status: 200, headers: { 'content-type': url.pathname.includes('/manifests/') ? 'application/vnd.oci.image.manifest.v1+json' : 'application/octet-stream' },
        body: url.pathname.includes('/manifests/') ? bytes.manifest : bytes.config,
      })) }, async () => {
        if (!siblingsOk) throw new Error('controlled scanner failure');
        return { ok: true, findings: [], scannerVersion: '0.69.3' };
      },
      1000, async () => siblingsOk ? { ok: true, scannerVersion: '0.69.3', sbom: { image, platform: 'linux/amd64',
        os: { name: 'alpine', version: '3.21.3' }, components: [{ ecosystem: 'apk', name: 'busybox', version: '1.2-r0' }] } }
        : { ok: false, errorCode: 'SCAN_TIMEOUT' }, async () => siblingsOk
          ? { ok: true, scannerVersion: '0.69.3', image, findings: [] } : { ok: false, errorCode: 'SCAN_TIMEOUT' });
      assert.equal(ledger.configResult(id, 'alice')?.config.outcome, configOk ? 'checked' : 'failed');
      for (const result of [ledger.result(id, 'alice'), ledger.sbom(id, 'alice'), ledger.vuln(id, 'alice')]) {
        assert.equal(result?.outcome, siblingsOk ? 'checked' : 'failed');
      }
      const expected = configOk && siblingsOk ? 'completed' : configOk || siblingsOk ? 'partial' : 'failed';
      assert.equal(ledger.state(id, 'alice'), expected);
      assert.deepEqual(ledger.events(id, 'alice', null)?.map(event => event.state), ['queued', 'running', expected]);
    } finally { ledger.close(); rmSync(dir, { recursive: true, force: true }); }
  });
}

test('off branch persists skipped and preserves legacy outcome without config I/O', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'outbox-config-off-'));
  const ledger = new ScanLedger(join(dir, 'ledger.sqlite'));
  try {
    const id = ledger.enqueue({ subject: 'alice', idempotencyKey: 'config-off', registry: 'registry-1.docker.io',
      repository: 'library/alpine', digest: configBytes().digest, platform: 'linux/amd64', checks: '["secret"]' }).scanId;
    await consumeOne(ledger, { timeoutMs: 1000, dbDir: '/unused', configLoader: async () => { throw new Error('must not load'); } },
      async () => ({ ok: true, findings: [], scannerVersion: '0.69.3' }), 1000);
    assert.equal(ledger.state(id, 'alice'), 'completed');
    assert.deepEqual(ledger.configResult(id, 'alice')?.config, { outcome: 'skipped', reason: 'CHECK_DISABLED' });
    assert.equal(ledger.result(id, 'alice')?.outcome, 'checked');
  } finally { ledger.close(); rmSync(dir, { recursive: true, force: true }); }
});
