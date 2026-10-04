import assert from 'node:assert/strict';
import test from 'node:test';
import { MAX_VULN_FINDINGS, parseVulnFindings } from './vuln-findings.js';

const image = `registry-1.docker.io/library/alpine@sha256:${'a'.repeat(64)}`;
const platform = 'linux/amd64';
const canary = 'CANARY-secret-credential';
const vuln = () => ({ VulnerabilityID: 'CVE-2025-12345', PkgName: 'busybox', InstalledVersion: '1.36.1-r2',
  FixedVersion: '1.36.1-r3', Severity: 'HIGH', SeveritySource: 'alpine', VendorSeverity: { alpine: 3, nvd: 4 },
  Title: canary, Description: canary, PrimaryURL: `https://example.com/?token=${canary}`, References: [canary] });
const report = () => ({ SchemaVersion: 2, ArtifactType: 'container_image', ArtifactName: image,
  Metadata: { RepoDigests: [image], ImageConfig: { os: 'linux', architecture: 'amd64' }, OS: { Family: 'alpine', Name: '3.21.3' } },
  Results: [{ Target: 'alpine:3.21.3 (alpine 3.21.3)', Class: 'os-pkgs', Type: 'alpine', Vulnerabilities: [vuln()] },
    { Target: '/app/package-lock.json', Class: 'lang-pkgs', Type: 'node-pkg', Vulnerabilities: [
      { ...vuln(), PkgName: '@org/module', PkgPath: 'app/node_modules/lodash/package.json', InstalledVersion: '1.2.3', FixedVersion: '', SeveritySource: 'ghsa', VendorSeverity: { ghsa: 3 } } ] }] });
const parse = (input: unknown, target = image, arch = platform) => parseVulnFindings(input, target, arch);

test('OS and node-pkg findings are bounded data, never raw scanner evidence', () => {
  const findings = parse(report());
  assert.equal(findings.length, 2);
  assert.deepEqual(findings.map(({ ecosystem, packageName, fixedVersion }) => ({ ecosystem, packageName, fixedVersion })), [
    { ecosystem: 'apk', packageName: 'busybox', fixedVersion: '1.36.1-r3' },
    { ecosystem: 'npm', packageName: '@org/module', fixedVersion: null },
  ]);
  assert.equal(findings[0].cveId, 'CVE-2025-12345');
  assert.equal(findings[0].installedVersion, '1.36.1-r2');
  assert.equal(findings[0].severity, 'HIGH');
  assert.deepEqual(findings[0].severitySources, ['alpine', 'nvd']);
  assert.match(findings[0].findingId, /^vuln-[a-f0-9]{64}$/);
  assert.match(findings[0].provenanceRef, /^target-[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify(findings).includes(canary));
  assert.ok(!JSON.stringify(findings).includes('package-lock'));
  assert.ok(!JSON.stringify(findings).includes('node_modules'));
  assert.deepEqual(parse(report()), findings);
});

test('same location merges sources; distinct target provenance survives', () => {
  const base = report();
  const os = base.Results[0];
  const findings = parse({ ...base, Results: [{ ...os, Vulnerabilities: [vuln(), vuln(),
    { ...vuln(), SeveritySource: 'ghsa' }] }, { ...os, Target: 'other-os-target' }] });
  assert.equal(findings.length, 2);
  assert.equal(new Set(findings.map(f => f.findingId)).size, 2);
  assert.deepEqual(findings[0].severitySources, ['alpine', 'ghsa', 'nvd']);
  assert.notEqual(findings[0].provenanceRef, findings[1].provenanceRef);
});

test('image binding, schema, platform and coverage fail closed', () => {
  const base = report();
  assert.throws(() => parse(base, image.replace('a', 'b')));
  assert.throws(() => parse(base, image, 'linux/arm64'));
  assert.throws(() => parse({ ...base, ArtifactName: 'untrusted' }));
  assert.throws(() => parse({ ...base, Metadata: { ...base.Metadata, RepoDigests: [image, image] } }));
  assert.throws(() => parse({ ...base, Metadata: { ...base.Metadata, ImageConfig: { os: 'linux', architecture: 'arm64' } } }));
  assert.throws(() => parse({ ...base, Metadata: { ...base.Metadata, OS: { Family: 'ubuntu', Name: '3.21.3' } } }));
  assert.throws(() => parse({ ...base, SchemaVersion: 1 }));
  assert.throws(() => parse({ ...base, Results: undefined }));
  assert.throws(() => parse({ ...base, Results: [{ ...base.Results[0], Type: 'debian' }] }));
  assert.throws(() => parse({ ...base, Results: [{ ...base.Results[0], Secrets: [{ Match: canary }] }] }));
  assert.throws(() => parse({ ...base, Results: [] }));
});

test('invalid CVE, package, versions, severity and unbounded input are rejected', () => {
  const base = report();
  const withVuln = (change: Record<string, unknown>) => ({ ...base, Results: [
    { ...base.Results[0], Vulnerabilities: [{ ...vuln(), ...change }] }] });
  for (const change of [
    { VulnerabilityID: 'GHSA-1234' }, { PkgName: `https://${canary}` },
    { InstalledVersion: `1.0?token=${canary}` }, { FixedVersion: `https://${canary}` },
    { Severity: 'EXTREME' }, { SeveritySource: canary }, { VendorSeverity: { [canary]: 3 } },
    { VendorSeverity: { alpine: 99 } }, { FixedVersion: null },
  ]) assert.throws(() => parse(withVuln(change)));
  assert.throws(() => parse({ ...base, Results: Array(MAX_VULN_FINDINGS + 1).fill(base.Results[0]) }));
  assert.throws(() => parse({ ...base, Results: [{ ...base.Results[0], Vulnerabilities: Array(MAX_VULN_FINDINGS + 1).fill(vuln()) }] }));
  assert.throws(() => parse({ ...base, Results: [{ ...base.Results[0], Target: 'x'.repeat(513) }] }));
  assert.throws(() => parse({ ...base, Results: [{ ...base.Results[0], Target: `https://example.com/${canary}` }] }));
  assert.throws(() => parse(null));
});

test('Trivy 0.69.3 OS missing/null SeveritySource is unknown; Node ghsa is retained', () => {
  const base = report();
  const os = base.Results[0];
  const node = base.Results[1];
  const osWithoutSource = { ...vuln(), SeveritySource: undefined, VendorSeverity: undefined };
  const result = parse({ ...base, Results: [
    { ...os, Vulnerabilities: [osWithoutSource, { ...osWithoutSource, SeveritySource: null },
      { ...osWithoutSource, SeveritySource: 'nvd' }] }, node,
  ] });
  assert.equal(result.length, 2);
  assert.deepEqual(result[0].severitySources, ['nvd', 'unknown']);
  assert.deepEqual(result[1].severitySources, ['ghsa']);
  assert.equal(result[0].findingId, parse({ ...base, Results: [{ ...os, Vulnerabilities: [vuln()] }] })[0].findingId);
  assert.equal(result[0].findingId, parse({ ...base, Results: [
    { ...os, Vulnerabilities: [{ ...vuln(), Severity: 'LOW', FixedVersion: '' }] }] })[0].findingId);
  assert.throws(() => parse({ ...base, Results: [{ ...os, Vulnerabilities: [vuln(),
    { ...vuln(), Severity: 'LOW' }] }] }));
  assert.throws(() => parse({ ...base, Results: [{ ...os, Vulnerabilities: [vuln(),
    { ...vuln(), FixedVersion: '1.36.1-r4' }] }] }));
});

test('real clean Alpine shape requires verified positive OS package inventory', () => {
  const base = report();
  const os = base.Results[0];
  const clean = { ...os, Packages: Array.from({ length: 16 }, (_, i) =>
    ({ Name: `alpine-package-${i}`, Version: '1.36.1-r2', Description: canary })), Vulnerabilities: undefined };
  assert.deepEqual(parse({ ...base, Results: [clean] }), []);
  assert.ok(!JSON.stringify(parse({ ...base, Results: [clean] })).includes(canary));
  assert.throws(() => parse({ ...base, Results: [{ ...clean, Packages: [] }] }));
  assert.throws(() => parse({ ...base, Results: [{ ...clean, Packages: undefined }] }));
  assert.throws(() => parse({ ...base, Results: [{ ...clean, Packages: [{ Name: `https://${canary}`, Version: '1' }] }] }));
  assert.throws(() => parse({ ...base, Results: [{ ...clean, Packages: [{ Name: 'busybox', Version: `1?${canary}` }] }] }));
  assert.throws(() => parse({ ...base, Results: [{ ...clean, Packages: Array(MAX_VULN_FINDINGS + 1).fill(clean.Packages[0]) }] }));
  assert.throws(() => parse({ ...base, Results: [
    { ...clean, Packages: Array(MAX_VULN_FINDINGS).fill(clean.Packages[0]) }, clean] }));
  assert.throws(() => parse({ ...base, Results: [{ ...clean, Type: 'debian' }] }));
  assert.throws(() => parse({ ...base, Results: [{ ...base.Results[1], Vulnerabilities: undefined }] }));
  assert.throws(() => parse({ ...base, Results: [base.Results[1]] }));
});

test('observed Trivy 0.69.3 vendor sources remain bounded and validated', () => {
  const base = report();
  const authorities = ['redhat', 'ubuntu', 'photon', 'amazon', 'oracle-oval', 'julia', 'alma',
    'azure', 'rocky', 'nvd', 'cbl-mariner', 'ghsa', 'bitnami', 'ruby-advisory-db'];
  const vendor = Object.fromEntries(authorities.map((source, index) => [source, index % 4 + 1]));
  const os = base.Results[0];
  const findings = parse({ ...base, Results: [{ ...os, Vulnerabilities: [
    { ...vuln(), SeveritySource: null, VendorSeverity: vendor },
  ] }, base.Results[1]] });
  assert.deepEqual(findings[0].severitySources, [...authorities, 'unknown'].sort());
  assert.deepEqual(findings[1].severitySources, ['ghsa']);
  assert.ok(!JSON.stringify(findings).includes(canary));
  assert.throws(() => parse({ ...base, Results: [{ ...os, Vulnerabilities: [
    { ...vuln(), VendorSeverity: { ...vendor, [canary]: 3 } },
  ] }] }));
});

test('Node package path distinguishes location without leaking raw path', () => {
  const base = report();
  const node = base.Results[1];
  const item = node.Vulnerabilities[0];
  const other = { ...item, PkgPath: 'app/node_modules/copy/lodash/package.json', SeveritySource: 'nvd' };
  const findings = parse({ ...base, Results: [base.Results[0], { ...node, Vulnerabilities: [item, item, other] }] });
  assert.equal(findings.length, 3);
  assert.notEqual(findings[1].findingId, findings[2].findingId);
  assert.notEqual(findings[1].provenanceRef, findings[2].provenanceRef);
  assert.equal(findings[1].findingId, parse(base)[1].findingId);
  assert.ok(!JSON.stringify(findings).includes('node_modules'));
  for (const path of [undefined, null, '', '/app/node_modules/lodash/package.json',
    '../app/node_modules/lodash/package.json', 'app/../node_modules/lodash/package.json',
    'app//node_modules/lodash/package.json', 'https://host/file',
    `app/node_modules/lodash/package.json?token=${canary}`, 'app\\node_modules\\lodash',
    'app/node_modules/evil\npackage.json', 'x'.repeat(513)]) {
    assert.throws(() => parse({ ...base, Results: [base.Results[0],
      { ...node, Vulnerabilities: [{ ...item, PkgPath: path }] }] }));
  }
});
