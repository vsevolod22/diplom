import assert from 'node:assert/strict';
import test from 'node:test';
import { publicDebianVersion } from './public-image-evidence.js';
import { parseImageSbom } from './cyclonedx-components.js';
import { parseVulnFindings } from './vuln-findings.js';
import { validateArchiveReport } from './archive-result-contract.js';
import { publicBinding, publicBom, publicDb, publicImage, publicRaw, publicReport } from './public-image-test-fixtures.js';

// Minimal sanitized shapes observed in native Trivy 0.69.3 Debian output. Names,
// versions and advisory IDs below are fixture data, not saved native report bytes.
const upstream = '4.13+dfsg1';
const revision = '1+deb12u1';
const installed = `1:${upstream}-${revision}`;
const pkg = () => ({ Name: 'sample-deb', Version: upstream, Release: revision, Epoch: 1 });
const vulnerability = (id = 'CVE-2026-12345') => ({ VulnerabilityID: id, PkgName: 'sample-deb', InstalledVersion: installed,
  Severity: 'HIGH', SeveritySource: 'debian', VendorSeverity: { debian: 3 }, Description: 'CANARY_SECRET',
});
const report = () => ({ ...publicRaw(), Results: [{ Target: 'debian inventory', Class: 'os-pkgs', Type: 'debian',
  Packages: [pkg()], Vulnerabilities: [vulnerability(), vulnerability('TEMP-0000000-ABCDEF')] }] });
const parse = (value: unknown) => parseVulnFindings(value, publicImage, 'linux/amd64', publicBinding);

function bom() {
  const value = publicBom();
  value.components[0] = { type: 'library', name: 'sample-deb', version: installed,
    purl: `pkg:deb/debian/sample-deb@${upstream}-${revision}?arch=amd64&distro=debian-12.12&epoch=1` };
  return value;
}

test('native Debian split epoch/upstream/revision canonicalization remains bounded and exact', () => {
  assert.equal(publicDebianVersion(upstream, 1, revision), installed);
  assert.equal(publicDebianVersion(upstream, undefined, revision), `${upstream}-${revision}`);
  assert.equal(publicDebianVersion(upstream, 0), upstream);
  assert.equal(publicDebianVersion(upstream), upstream);
  for (const epoch of [-1, 0.5, NaN, Infinity, 2_147_483_648, '1', null]) assert.equal(publicDebianVersion(upstream, epoch, revision), undefined);
  for (const release of ['../revision', '1?secret=x', '\n1', 1, null]) assert.equal(publicDebianVersion(upstream, 1, release), undefined);
  assert.equal(publicDebianVersion('1:4.13', 1), undefined);
  assert.equal(publicDebianVersion('v'.repeat(80), 1, '1'), undefined);
});

test('native Debian CycloneDX epoch qualifier binds exact full display version, never drops epoch', () => {
  const parsed = parseImageSbom(bom(), publicImage, 'linux/amd64', publicBinding);
  assert.deepEqual(parsed.components, [{ ecosystem: 'deb', name: 'sample-deb', version: installed }]);
  const value = bom(); const library = value.components[0] as Record<string, unknown>;
  const replace = (changes: Record<string, unknown>) => ({ ...value, components: [{ ...library, ...changes }, value.components[1]] });
  for (const purl of [
    String(library.purl).replace('&epoch=1', '&epoch=2'), String(library.purl).replace('&epoch=1', '&epoch=01'),
    String(library.purl).replace('&epoch=1', '&epoch=0'), String(library.purl).replace('&epoch=1', '&epoch=-1'),
    String(library.purl).replace('&epoch=1', '&epoch=2147483648'), `${library.purl}&epoch=1`,
    `${library.purl}&unknown=x`, String(library.purl).replace('&epoch=1', ''),
    String(library.purl).replace(`@${upstream}`, `@1%3A${upstream}`),
  ]) assert.throws(() => parseImageSbom(replace({ purl }), publicImage, 'linux/amd64', publicBinding));
  assert.throws(() => parseImageSbom(replace({ version: `${upstream}-${revision}` }), publicImage, 'linux/amd64', publicBinding));
});

test('native Debian CVE plus TEMP advisory IDs retain every finding and bind canonical installed inventory', () => {
  const findings = parse(report());
  assert.equal(findings.length, 2); assert.deepEqual(findings.map(finding => finding.cveId), ['CVE-2026-12345', 'TEMP-0000000-ABCDEF']);
  assert.ok(findings.every(finding => finding.installedVersion === installed && finding.ecosystem === 'deb'));
  assert.deepEqual(findings[1].advisory?.references, [], 'A TEMP advisory is not a CVE/NVD URL');
  assert.equal(JSON.stringify(findings).includes('CANARY'), false);
  const base = publicReport(); delete base.secret;
  const value = { ...base, vuln: { outcome: 'checked' as const, findings, db: publicDb(), os: { outcome: 'checked' as const },
    node: { outcome: 'unsupported' as const, reason: 'NODE_INVENTORY_UNKNOWN' as const } } };
  validateArchiveReport(value, ['vuln']);
  for (const invalidPkg of [{ ...pkg(), Epoch: 2 }, { ...pkg(), Release: 'other' }, { ...pkg(), Version: 'other' },
    { ...pkg(), Name: 'other' }, { ...pkg(), Epoch: '1' }, { ...pkg(), Release: null }]) {
    const raw = report(); raw.Results[0].Packages = [invalidPkg as ReturnType<typeof pkg>]; assert.throws(() => parse(raw));
  }
});

test('TEMP namespace stays public Debian-only; malformed and unrelated advisory IDs fail rather than disappear', () => {
  for (const id of ['TEMP-0000000-abcdef', 'TEMP-123-ABCDEF', 'TEMP-0000000-ABCDEF/secret', 'GHSA-xxxx-yyyy-zzzz', 'DSA-1234-1']) {
    const value = report(); value.Results[0].Vulnerabilities = [vulnerability(id)]; assert.throws(() => parse(value));
  }
  const ubuntu = report(); ubuntu.Metadata.OS.Family = 'ubuntu'; ubuntu.Results[0].Type = 'ubuntu'; assert.throws(() => parse(ubuntu));
  const legacyImage = `registry-1.docker.io/library/alpine@sha256:${'a'.repeat(64)}`;
  assert.throws(() => parseVulnFindings({ SchemaVersion: 2, ArtifactType: 'container_image', ArtifactName: legacyImage,
    Metadata: { RepoDigests: [legacyImage], ImageConfig: { os: 'linux', architecture: 'amd64' }, OS: { Family: 'alpine', Name: '3.21.3' } },
    Results: [{ Class: 'os-pkgs', Type: 'alpine', Target: 'alpine inventory', Packages: [{ Name: 'sample-deb', Version: installed }],
      Vulnerabilities: [vulnerability('TEMP-0000000-ABCDEF')] }] }, legacyImage, 'linux/amd64'));
});
