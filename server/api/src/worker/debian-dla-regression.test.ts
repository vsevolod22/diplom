import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { parseVulnFindings } from './vuln-findings.js';
import { validateArchiveReport } from './archive-result-contract.js';
import { publicBinding, publicDb, publicImage, publicRaw, publicReport } from './public-image-test-fixtures.js';
import { PUBLIC_IMAGE_PROFILE } from '../oci/public-image-policy.js';
import { parseCurrentVuln } from '../../../../src/shared/api/scans/scanTransport.js';
import { countVulnerabilityIdentifiers } from '../../../../src/shared/api/scans/publicVulnerabilityIdentifiers.js';
import { safeHistoryFinding } from '../llm/history-sources.js';
import { prepareSummary } from '../llm/prepared-request.js';
import { policyFromEnvironment } from '../llm/policy.js';
import { validateReply } from '../llm/response.js';
import type { ReportContext, SafeFinding } from '../llm/report-context.js';

// Minimal public advisory identities only; native scanner bytes stay in ignored local evidence.
const ids = ['DLA-4783-1', 'DLA-4792-1', 'DLA-4854-1'];
const raw = (identifiers = ids) => ({ ...publicRaw(), Results: [{ Target: 'debian inventory', Class: 'os-pkgs', Type: 'debian',
  Packages: [{ Name: 'liblzma5', Version: '5.4.1', Release: '0.2' }, { Name: 'tzdata', Version: '2023c', Release: '5' }],
  Vulnerabilities: identifiers.map((VulnerabilityID, index) => ({ VulnerabilityID, PkgName: index === 0 ? 'liblzma5' : 'tzdata',
    InstalledVersion: index === 0 ? '5.4.1-0.2' : '2023c-5', Severity: 'UNKNOWN' })) }] });
const parse = (value: unknown) => parseVulnFindings(value, publicImage, 'linux/amd64', publicBinding);
function page(findings: ReturnType<typeof parse>, image = publicImage, counts = countVulnerabilityIdentifiers(findings), total = findings.length, nextCursor: number | null = null) {
  return { outcome: 'checked', coverage: 'image', image, platform: 'linux/amd64', profile: PUBLIC_IMAGE_PROFILE,
    identifierCounts: counts, findingCount: total, scannerVersion: '0.69.3', checkedAt: '2026-11-03T00:00:00.000Z', findings, nextCursor };
}
function archive(findings: ReturnType<typeof parse>) {
  const base = publicReport(); delete base.secret;
  return { ...base, vuln: { outcome: 'checked' as const, findings, db: publicDb(), os: { outcome: 'checked' as const },
    node: { outcome: 'unsupported' as const, reason: 'NODE_INVENTORY_UNKNOWN' as const } } };
}

test('DLA preserves all three exact Debian advisory rows through normalization and archive contract', () => {
  const findings = parse(raw());
  assert.deepEqual(findings.map(f => f.cveId), ids);
  assert.ok(findings.every(f => f.ecosystem === 'deb' && f.fixedVersion === null));
  for (const finding of findings) assert.deepEqual(finding.advisory?.references, []);
  validateArchiveReport(archive(findings), ['vuln']);
});

test('DLA rejects malformed namespace, wrong class/OS/ecosystem and unmatched inventory instead of dropping rows', () => {
  for (const id of ['dla-4783-1', ' DLA-4783-1', 'DLA-4783-1\n', 'DLA-4783-1/x', 'DLA-0-1', 'DLA-4783-0', `DLA-${'9'.repeat(80)}-1`, 'DSA-4783-1']) {
    assert.throws(() => parse(raw([id])), id);
  }
  for (const mutate of [
    (v: ReturnType<typeof raw>) => { v.Results[0].Class = 'lang-pkgs'; },
    (v: ReturnType<typeof raw>) => { v.Metadata.OS.Family = 'ubuntu'; v.Results[0].Type = 'ubuntu'; },
    (v: ReturnType<typeof raw>) => { v.Results[0].Type = 'alpine'; },
    (v: ReturnType<typeof raw>) => { v.Results[0].Class = 'lang-pkgs'; v.Results[0].Type = 'npm'; },
    (v: ReturnType<typeof raw>) => { v.Results[0].Packages = []; },
  ]) { const value = raw(); mutate(value); assert.throws(() => parse(value)); }
});

test('CVE/TEMP retain stable finding identity and historical counts without a DLA field', () => {
  const findings = parse(raw(['CVE-2026-12345', 'TEMP-0000000-ABCDEF']));
  const provenanceRef = `target-${createHash('sha256').update('debian inventory').digest('hex')}`;
  for (const f of findings) {
    const key = JSON.stringify([publicImage, 'linux/amd64', 'vuln', 'deb', provenanceRef, f.cveId, f.packageName, f.installedVersion]);
    assert.equal(f.findingId, `vuln-${createHash('sha256').update(key).digest('hex')}`);
  }
  validateArchiveReport(archive(findings), ['vuln']);
  assert.deepEqual(countVulnerabilityIdentifiers(findings), { cve: 1, debianTemp: 1 });
  assert.equal(parseCurrentVuln(page(findings)).outcome, 'checked');
});

test('frontend DTO accepts exact DLA counts only with public profile and consistent nonnegative totals', () => {
  const value = page(parse(raw()));
  assert.deepEqual(parseCurrentVuln(value).identifierCounts, { cve: 0, debianTemp: 0, debianDla: 3 });
  for (const identifierCounts of [{ cve: 0, debianTemp: 0 }, { cve: 3, debianTemp: 0 }, { cve: 0, debianTemp: 0, debianDla: -1 }, { cve: 0, debianTemp: 0, debianDla: 2 }]) {
    assert.throws(() => parseCurrentVuln({ ...value, identifierCounts }));
  }
  const { profile: _profile, ...unmarked } = value;
  assert.throws(() => parseCurrentVuln(unmarked));
});

test('LLM prepared sources and citation grounding retain exact DLA kind without invented or uncited IDs', () => {
  const findings: SafeFinding[] = parse(raw()).map(f => ({ check: 'vuln', findingId: f.findingId, severity: f.severity,
    cveId: f.cveId, identifierKind: 'debian-dla', ecosystem: f.ecosystem, severitySources: f.severitySources,
    provenanceRef: f.provenanceRef, fixedVersionReported: false, advisoryState: 'unknown', packageName: f.packageName,
    installedVersion: f.installedVersion, fixedVersion: null }));
  for (const f of findings) { assert.equal(safeHistoryFinding(f), true); assert.equal(safeHistoryFinding({ ...f, identifierKind: 'cve' }), false); }
  const report: ReportContext = { scanId: '00000000-0000-4000-8000-000000000001', digest: publicBinding.receipt.digest,
    platform: 'linux/amd64', reportVersion: 'a'.repeat(64), state: 'completed', attempt: 1, requestedChecks: ['vuln'],
    coverage: { vuln: { outcome: 'checked' }, secret: {}, sbom: {}, config: {} }, findings, findingCount: 3,
    profile: PUBLIC_IMAGE_PROFILE, identifierCounts: { cve: 0, debianTemp: 0, debianDla: 3 }, checkedIsNotSafe: true,
    omittedEvidence: 'All free text, URLs, credentials, env and raw output excluded; package identities and versions are sanitized scanner facts' };
  const policy = policyFromEnvironment({ LLM_ENABLED: 'true', LLM_MODEL: 'fixture/fake-model', LLM_PROVIDER_ALLOWLIST: 'FixtureProvider',
    LLM_POLICY_REVISION: 'fixture-v1', LLM_ROUTING_APPROVED: 'true', LLM_REGION: 'global', LLM_RETENTION: 'no-storage',
    LLM_TIMEOUT_MS: '1000', LLM_REQUEST_BYTES: '262144', LLM_RESPONSE_BYTES: '65536', LLM_MAX_FINDINGS: '1000',
    LLM_OUTPUT_TOKENS: '256', LLM_REQUEST_BUDGET_USD: '0.5', LLM_INPUT_PRICE_PER_MILLION_USD: '1', LLM_OUTPUT_PRICE_PER_MILLION_USD: '1' });
  assert.ok(policy);
  const input = JSON.parse(JSON.parse(prepareSummary(report, policy).body).messages[1].content);
  assert.deepEqual(input.findings, findings);
  const answer = (id: string, citation = findings[0].findingId) => ({ scanId: report.scanId, digest: report.digest,
    platform: report.platform, reportVersion: report.reportVersion,
    hypotheses: [{ text: `Сканер сообщил ${id}. Проверьте применимость исправления.`, citations: [citation] }] });
  assert.equal(validateReply(answer(ids[0]), report, true).scannerFacts[0].cveId, ids[0]);
  for (const id of ['DLA-9999-1', 'DLA-4783-2', ids[1], 'CVE-2026-4783']) assert.throws(() => validateReply(answer(id), report, true));
  assert.throws(() => validateReply(answer(ids[0], `vuln-${'f'.repeat(64)}`), report, true));
});

const replayDirectory = process.env.NODE_DLA_REPLAY_DIR;
test('opt-in native 440-row replay retains 431 CVE, 6 TEMP and all 3 DLA through paged frontend DTO', { skip: !replayDirectory }, () => {
  const bytes = readFileSync(join(replayDirectory!, 'scanner.private.json'));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), '69277afee2131f161651203864d1a776e336e9029d20e6b011f600d8fc003c22');
  const reduced = JSON.parse(readFileSync(join(replayDirectory!, 'reduced-public-fixture.json'), 'utf8'));
  const findings = parseVulnFindings(JSON.parse(bytes.toString('utf8')), reduced.image, 'linux/amd64', reduced.binding);
  assert.equal(findings.length, 440);
  const counts = countVulnerabilityIdentifiers(findings);
  assert.deepEqual(counts, { cve: 431, debianTemp: 6, debianDla: 3 });
  assert.deepEqual(findings.filter(f => f.cveId.startsWith('DLA-')).map(f => f.cveId), ids);
  const report = archive(findings); report.receipt = reduced.binding.receipt; report.vuln.db = reduced.dbIdentity;
  validateArchiveReport(report, ['vuln']);
  let decoded = 0;
  for (let offset = 0; offset < findings.length; offset += 100) {
    const rows = findings.slice(offset, offset + 100);
    const parsed = parseCurrentVuln(page(rows, reduced.image, counts, 440, offset + rows.length < 440 ? offset + rows.length : null));
    assert.equal(parsed.outcome, 'checked'); decoded += parsed.findings.length;
  }
  assert.equal(decoded, 440);
});
