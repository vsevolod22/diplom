import assert from 'node:assert/strict';
import test from 'node:test';
import { access } from 'node:fs/promises';
import { PUBLIC_IMAGE_LIMITS } from '../oci/public-image-policy.js';
import { NGINX_SUPPORTED_CANDIDATE, archiveProfileVersion } from '../oci/bounded-image-archive.js';
import { parseSecretFindings } from './secret-findings.js';
import { parseVulnFindings } from './vuln-findings.js';
import { parseImageSbom } from './cyclonedx-components.js';
import { validateArchiveReport } from './archive-result-contract.js';
import { scanNginxArchive, scanPublicImageArchive } from './archive-scan-worker.js';
import { PUBLIC_ECOSYSTEMS } from './public-image-evidence.js';
import { publicBinding, publicBom, publicDb, publicImage, publicLifecycle, publicRaw, publicReceipt, publicReport,
  publicTarget, publicVulnOptions } from './public-image-test-fixtures.js';

const parseVuln = (value: unknown) => parseVulnFindings(value, publicImage, 'linux/amd64', publicBinding);
const parseBom = (value: unknown) => parseImageSbom(value, publicImage, 'linux/amd64', publicBinding);
const rawVuln = (name = 'libc6', version = '2.36-9') => ({ VulnerabilityID: 'CVE-2026-12345', PkgName: name,
  InstalledVersion: version, Severity: 'HIGH', SeveritySource: 'debian', VendorSeverity: { debian: 3, nvd: 3 },
  PkgPath: 'app/installed-package', Title: 'CANARY_SECRET', Env: ['CANARY_SECRET'] });

test('public CVE evidence covers the bounded ecosystem enum without raw paths/Env', () => {
  const cases = [
    ['apk', 'os-pkgs', 'alpine', 'busybox'], ['deb', 'os-pkgs', 'debian', 'libc6'], ['rpm', 'os-pkgs', 'redhat', 'glibc'],
    ['npm', 'lang-pkgs', 'node-pkg', '@org/module'], ['pypi', 'lang-pkgs', 'python-pkg', 'requests'],
    ['gem', 'lang-pkgs', 'gemspec', 'rack'], ['gomod', 'lang-pkgs', 'gobinary', 'github.com/org/module'],
    ['cargo', 'lang-pkgs', 'cargo', 'serde'], ['maven', 'lang-pkgs', 'jar', 'org.example:artifact'],
    ['composer', 'lang-pkgs', 'composer', 'vendor/package'], ['nuget', 'lang-pkgs', 'dotnet-core', 'Newtonsoft.Json'],
  ];
  assert.deepEqual(cases.map(([ecosystem]) => ecosystem), [...PUBLIC_ECOSYSTEMS]);
  for (const [ecosystem, Class, Type, Name] of cases) {
    const raw = publicRaw(Class === 'os-pkgs' ? Type : 'debian', '12');
    const result = { Class, Type, Target: '/app/inventory', Packages: [{ Name, Version: '1.2.3' }],
      Vulnerabilities: [rawVuln(Name, '1.2.3')] };
    raw.Results = Class === 'os-pkgs' ? [result] : [...raw.Results, result];
    const findings = parseVuln(raw);
    assert.equal(findings.length, 1); assert.equal(findings[0].ecosystem, ecosystem);
    assert.equal(JSON.stringify(findings).includes('/app/'), false);
    assert.equal(JSON.stringify(findings).includes('CANARY'), false);
    assert.equal(JSON.stringify(findings).includes('Env'), false);
  }
});

test('public CVE unknown types, uninspected inventory, mismatched OS and unsafe sources fail closed', () => {
  const base = publicRaw();
  for (const result of [
    { Class: 'lang-pkgs', Type: 'future-analyzer', Packages: [{ Name: 'pkg', Version: '1' }] },
    { Class: 'os-pkgs', Type: 'ubuntu', Packages: [{ Name: 'pkg', Version: '1' }] },
    { Class: 'os-pkgs', Type: 'debian', Packages: [] },
    { Class: 'os-pkgs', Type: 'debian', Vulnerabilities: [rawVuln()] },
    { Class: 'os-pkgs', Type: 'debian', Packages: [{ Name: 'other', Version: '1' }], Vulnerabilities: [rawVuln()] },
    { Class: 'os-pkgs', Type: 'debian', Packages: [{ Name: 'libc6', Version: '2.36-9' }], Vulnerabilities: [{ ...rawVuln(), SeveritySource: 'https://secret' }] },
    { Class: 'os-pkgs', Type: 'debian', Packages: [{ Name: 'libc6', Version: '2.36-9' }], Vulnerabilities: [{ ...rawVuln(), VendorSeverity: { debian: 5 } }] },
  ]) assert.throws(() => parseVuln({ ...base, Results: [{ Target: '/app/inventory', ...result }] }));
  assert.throws(() => parseVuln({ ...base, Results: [] }));
  assert.throws(() => parseVuln({ ...base, Metadata: { ...base.Metadata, ImageID: `sha256:${'f'.repeat(64)}` } }));
  assert.throws(() => parseVuln({ ...base, Metadata: { ...base.Metadata, DiffIDs: [] } }));
});

test('public actual CycloneDX shape binds Debian/Ubuntu/RHEL/Alpine purls and language identities', () => {
  for (const [family, version, kind, arch] of [
    ['alpine', '3.22.1', 'apk', 'x86_64'], ['debian', '12.12', 'deb', 'amd64'], ['ubuntu', '24.04', 'deb', 'amd64'],
    ['redhat', '9.5', 'rpm', 'x86_64'], ['rocky', '9.5', 'rpm', 'noarch'], ['alma', '9.5', 'rpm', 'x86_64'],
  ]) {
    const bom = publicBom();
    bom.components = [
      { type: 'operating-system', name: family, version },
      { type: 'library', name: 'package', version: '1.2.3', purl: `pkg:${kind}/${family}/package@1.2.3?arch=${arch}&distro=${family}-${version}` },
      { type: 'library', group: 'org.example', name: 'artifact', version: '1', purl: 'pkg:maven/org.example/artifact@1' },
      { type: 'library', group: '@org', name: 'module', version: '1', purl: 'pkg:npm/%40org/module@1' },
      ...[['pypi', 'requests'], ['gem', 'rack'], ['golang', 'github.com/org/module'], ['cargo', 'serde'],
        ['composer', 'vendor/package'], ['nuget', 'Newtonsoft.Json']].map(([ecosystem, name]) => ({
          type: 'library', name, version: '1', purl: `pkg:${ecosystem}/${name}@1`, properties: [{ name: 'Env', value: 'CANARY_SECRET' }],
        })),
    ];
    const sbom = parseBom(bom);
    assert.equal(sbom.os.name, family); assert.equal(sbom.components[0].ecosystem, kind);
    assert.equal(sbom.components[1].name, 'org.example:artifact'); assert.equal(sbom.components[2].name, '@org/module');
    assert.equal(JSON.stringify(sbom).includes('CANARY'), false);
  }
});

test('public CycloneDX rejects mismatched purls, unsupported components, identity and qualifiers', () => {
  const base = publicBom();
  const library = base.components[0] as Record<string, unknown>;
  for (const change of [
    { name: 'other' }, { version: '2' }, { purl: 'pkg:deb/ubuntu/libc6@2.36-9?arch=amd64&distro=debian-12.12' },
    { purl: 'pkg:deb/debian/libc6@2.36-9?arch=arm64&distro=debian-12.12' },
    { purl: 'pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-13' },
    { purl: 'pkg:deb/debian/libc6@2.36-9?arch=amd64&arch=amd64' },
    { purl: 'pkg:generic/libc6@2.36-9' }, { purl: 'pkg:pypi/libc6@2.36-9?url=secret' },
    { type: 'file' }, { name: '/raw/path' },
  ]) assert.throws(() => parseBom({ ...base, components: [base.components[1], { ...library, ...change }] }));
  assert.throws(() => parseBom({ ...base, components: [library] }));
  assert.throws(() => parseBom({ ...base, components: Array(1001).fill(library) }));
  assert.throws(() => parseBom({ ...base, metadata: { component: { ...base.metadata.component, properties: [] } } }));
});

test('public runner retains independent partial results and audited per-check envelopes', async () => {
  const { directory, lifecycle } = await publicLifecycle(async check => check === 'sbom' ? { invalid: true } : publicRaw());
  const checkpoints: string[] = [];
  const report = await scanPublicImageArchive(['secret', 'sbom', 'vuln'], { target: publicTarget, vuln: publicVulnOptions,
    onCheckpoint(check, completed) { validateArchiveReport(completed, [check]); checkpoints.push(check); return true; } }, lifecycle);
  assert.deepEqual(checkpoints, ['secret', 'sbom', 'vuln']);
  assert.equal(report.secret?.outcome, 'checked'); assert.equal(report.sbom?.outcome, 'failed');
  assert.equal(report.vuln?.outcome, 'checked');
  assert.deepEqual(report.vuln?.node, { outcome: 'unsupported', reason: 'NODE_INVENTORY_UNKNOWN' });
  validateArchiveReport(report, ['secret', 'sbom', 'vuln']);
  await assert.rejects(access(directory));
});

test('public runner OS evidence, EOL and missing inventories never manufacture checked-zero coverage', async () => {
  for (const [OS, expected] of [
    [undefined, 'OS_UNKNOWN'], [{ Family: 'unknown', Name: '1' }, 'OS_UNKNOWN'],
    [{ Family: 'debian', Name: '12', EOSL: true }, 'OS_EOL'],
    [{ Family: 'debian', Name: '12', EOSL: false }, 'checked'],
  ] as const) {
    const { lifecycle } = await publicLifecycle(async () => ({ ...publicRaw('debian', '12'), Metadata: { ...publicRaw().Metadata, OS } }));
    const report = await scanPublicImageArchive(['vuln'], { target: publicTarget, vuln: publicVulnOptions }, lifecycle);
    assert.equal(report.vuln?.outcome === 'unsupported' ? report.vuln.reason : report.vuln?.outcome, expected);
    assert.deepEqual(report.vuln?.node, { outcome: 'unsupported', reason: 'NODE_INVENTORY_UNKNOWN' });
    validateArchiveReport(report, ['vuln']);
  }
  for (const Results of [[], [{ Class: 'os-pkgs', Type: 'debian', Target: 'debian', Packages: [] }],
    [...publicRaw().Results, { Class: 'lang-pkgs', Type: 'future', Target: 'app', Packages: [{ Name: 'pkg', Version: '1' }] }]]) {
    const { lifecycle } = await publicLifecycle(async () => ({ ...publicRaw(), Results }));
    const report = await scanPublicImageArchive(['vuln'], { target: publicTarget, vuln: publicVulnOptions }, lifecycle);
    assert.deepEqual(report.vuln, { outcome: 'failed', reason: 'SCAN_FAILED' });
  }
});

test('public runner DB failures preserve Secrets, storage errors escape unchanged and cleanup runs', async () => {
  const first = await publicLifecycle();
  first.lifecycle.verifiedDb = async () => { throw new Error('fixture DB unavailable'); };
  const partial = await scanPublicImageArchive(['secret', 'vuln'], { target: publicTarget, vuln: publicVulnOptions }, first.lifecycle);
  assert.equal(partial.secret?.outcome, 'checked'); assert.deepEqual(partial.vuln, { outcome: 'failed', reason: 'DB_UNAVAILABLE' });
  const second = await publicLifecycle(); const storageError = new Error('checkpoint storage failure');
  await assert.rejects(scanPublicImageArchive(['secret'], { target: publicTarget,
    onCheckpoint() { throw storageError; } }, second.lifecycle), error => error === storageError);
  await assert.rejects(access(second.directory));
});

test('public checkpoint cancellation stops subsequent scanners and scratch policy violations fail closed', async () => {
  const calls: string[] = []; const { lifecycle } = await publicLifecycle(async check => { calls.push(check); return publicRaw(); });
  const cancelled = await scanPublicImageArchive(['secret', 'vuln'], { target: publicTarget, vuln: publicVulnOptions,
    onCheckpoint() { return false; } }, lifecycle);
  assert.deepEqual(calls, ['secret']); assert.deepEqual(cancelled.secret, { outcome: 'failed', reason: 'SCAN_TIMEOUT' });
  const invalid = await publicLifecycle();
  invalid.lifecycle.audit = async (_directory, _db, _filesystem, limits) => { assert.equal(limits?.scratchBytes, PUBLIC_IMAGE_LIMITS.scratchBytes); throw Error('scratch'); };
  const report = await scanPublicImageArchive(['secret'], { target: publicTarget, onCheckpoint() { assert.fail('unsafe checkpoint'); } }, invalid.lifecycle);
  assert.deepEqual(report.secret, { outcome: 'failed', reason: 'SCAN_FAILED' });
});

test('public envelopes reject extra/raw fields, invalid metrics and legacy-only absence claims', () => {
  const base = publicReport(); validateArchiveReport(base, ['secret']);
  for (const change of [
    { metrics: { ...base.metrics, scratchPeak: PUBLIC_IMAGE_LIMITS.scratchBytes + 1 } },
    { metrics: { ...base.metrics, entries: 0.5 } }, { metrics: { ...base.metrics, requests: -1 } },
    { metrics: { ...base.metrics, Env: 'CANARY' } }, { receipt: { ...publicReceipt, configDigest: 'forged' } },
    { secret: { outcome: 'checked', findings: [], raw: 'CANARY' } },
    { secret: { outcome: 'checked', findings: [{ findingId: 'secret-0-0', ruleId: 'raw-rule', line: 1, evidenceRef: '/raw/path' }] } },
  ]) assert.throws(() => validateArchiveReport({ ...base, ...change } as typeof base, ['secret']));
  validateArchiveReport({ ...base, metrics: { ...base.metrics, expandedBytes: PUBLIC_IMAGE_LIMITS.expandedTotal } }, ['secret']);
  const unsupported = { outcome: 'unsupported', reason: 'OS_UNKNOWN', db: publicDb(),
    os: { outcome: 'unsupported', reason: 'OS_UNKNOWN' }, node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_UNKNOWN' } } as const;
  const publicUnsupported = { ...base, secret: undefined, vuln: unsupported }; delete publicUnsupported.secret;
  validateArchiveReport(publicUnsupported, ['vuln']);
  assert.throws(() => validateArchiveReport({ ...publicUnsupported, vuln: { ...unsupported,
    node: { outcome: 'unsupported', reason: 'NODE_INVENTORY_ABSENT' } } }, ['vuln']));
  assert.throws(() => validateArchiveReport({ ...base, secret: { outcome: 'checked', findings: [], raw: 'CANARY' } } as typeof base, ['secret']));
  const legacyReceipt = { ...publicReceipt, ...NGINX_SUPPORTED_CANDIDATE, profileVersion: archiveProfileVersion(NGINX_SUPPORTED_CANDIDATE),
    resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' };
  assert.throws(() => validateArchiveReport({ ...base, receipt: legacyReceipt,
    metrics: { ...base.metrics, expandedBytes: PUBLIC_IMAGE_LIMITS.expandedTotal } }, ['secret']));
});

test('public positive Node inventory is checked, missing OS inventory and empty Node are not checked zero', async () => {
  const { lifecycle } = await publicLifecycle(async () => ({ ...publicRaw(), Results: [...publicRaw().Results,
    { Class: 'lang-pkgs', Type: 'node-pkg', Target: 'app/package.json', Packages: [{ Name: '@org/module', Version: '1.2.3' }] }] }));
  const report = await scanPublicImageArchive(['vuln'], { target: publicTarget, vuln: publicVulnOptions }, lifecycle);
  assert.equal(report.vuln?.outcome, 'checked'); assert.deepEqual(report.vuln?.node, { outcome: 'checked' });
  validateArchiveReport(report, ['vuln']);
  for (const Results of [[{ Class: 'lang-pkgs', Type: 'node-pkg', Target: 'app/package.json', Packages: [{ Name: 'module', Version: '1' }] }],
    [...publicRaw().Results, { Class: 'lang-pkgs', Type: 'node-pkg', Target: 'app/package.json', Packages: [] }]]) {
    const fixture = await publicLifecycle(async () => ({ ...publicRaw(), Results }));
    const failed = await scanPublicImageArchive(['vuln'], { target: publicTarget, vuln: publicVulnOptions }, fixture.lifecycle);
    assert.deepEqual(failed.vuln, { outcome: 'failed', reason: 'SCAN_FAILED' });
  }
});

test('public Secrets allow 64 verified inspected layers, legacy still caps at 32', () => {
  const diffIds = Array.from({ length: 64 }, (_, index) => `sha256:${index.toString(16).padStart(64, '0')}`);
  const receipt = { ...publicReceipt, diffIds, layerDigests: diffIds };
  const raw = publicRaw();
  const value = { ...raw, Metadata: { ...raw.Metadata, DiffIDs: diffIds, Layers: diffIds.map(DiffID => ({ DiffID, Size: 512 })),
    ImageConfig: { ...raw.Metadata.ImageConfig, rootfs: { type: 'layers', diff_ids: diffIds } } }, Results: [] };
  assert.deepEqual(parseSecretFindings(value, { ...publicBinding, receipt }), []);
  assert.throws(() => parseSecretFindings(value));
  assert.throws(() => parseSecretFindings({ ...value, Metadata: { ...value.Metadata, Layers: [] } }, { ...publicBinding, receipt }));
});

test('public runner target mismatch cleans up and external abort never publishes', async () => {
  const mismatched = await publicLifecycle();
  await assert.rejects(scanPublicImageArchive(['secret'], { target: { ...publicTarget, digest: `sha256:${'f'.repeat(64)}` } }, mismatched.lifecycle), TypeError);
  await assert.rejects(access(mismatched.directory));
  const controller = new AbortController();
  const cancelled = await publicLifecycle(async () => { controller.abort(); return publicRaw(); });
  const report = await scanPublicImageArchive(['secret'], { target: publicTarget, signal: controller.signal,
    onCheckpoint() { assert.fail('Cancelled check must not publish'); } }, cancelled.lifecycle);
  assert.deepEqual(report.secret, { outcome: 'failed', reason: 'SCAN_TIMEOUT' });
});

test('legacy nginx wrapper still selects its exact target and Alpine-only parser', async () => {
  const { lifecycle } = await publicLifecycle();
  const receipt = { ...publicReceipt, ...NGINX_SUPPORTED_CANDIDATE, profileVersion: archiveProfileVersion(NGINX_SUPPORTED_CANDIDATE),
    resourcePolicyVersion: 'nginx-archive-resources-v1', checksVersion: 'trivy-0.69.3-archive-v1' };
  const report = await scanNginxArchive(['vuln'], { target: NGINX_SUPPORTED_CANDIDATE, vuln: publicVulnOptions }, { ...lifecycle,
    prepare: async (_signal, target) => { assert.deepEqual(target, NGINX_SUPPORTED_CANDIDATE); return { ...await lifecycle.prepare(undefined, publicTarget), receipt }; },
    invoke: async () => { const raw = publicRaw(); return { ...raw, Metadata: { ...raw.Metadata, ImageID: receipt.configDigest } }; },
  });
  assert.deepEqual(report.vuln, { outcome: 'failed', reason: 'SCAN_FAILED' });
});
