import assert from 'node:assert/strict';
import test from 'node:test';
import { chmodSync, linkSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { readPublicProviderKey, PUBLIC_OPENROUTER_KEY_FILE } from '../public-key-file.js';
import { productionProvider } from '../openrouter-provider.js';
import { selectSummaryReport } from '../summary-context.js';
import { selectHistoryContext } from '../history-context.js';
import { safeHistoryFinding } from '../history-sources.js';
import { prepareSummary } from '../prepared-request.js';
import { policyFromEnvironment, PUBLIC_FREE_MODEL, PUBLIC_FREE_PROVIDER } from '../policy.js';
import { catalogProfile, publicCredentialStatus, publicKeyMetadata, publicReadiness } from '../public-readiness.js';
import type { ReportContext } from '../report-context.js';
import { fixtureEnv, fixtureReport } from './fixtures.js';
import { cleanText } from '../history-contract.js';
import { PUBLIC_IMAGE_PROFILE } from '../../oci/public-image-policy.js';
import { quotaPolicyFromEnvironment } from '../quota-policy.js';
import { HISTORY_AUTHORITY } from '../history-runtime.js';
import { HISTORY } from '../history-contract.js';

const policy = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'apodex/apodex-1.1-mini:free',
  LLM_PROVIDER_ALLOWLIST: 'novita/bf16', LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0',
  LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' })!;

test('public helper settings are accepted by actual policy/quota/history parsers, without loading any state', () => {
  const source = readFileSync(new URL('../../../../../scripts/public-llm-config.py', import.meta.url), 'utf8');
  const config = source.match(/CONFIG = """([\s\S]*?)"""/)![1];
  const env = Object.fromEntries(config.split('\n').filter(line => line && !line.startsWith('#')).map(line => {
    const at = line.indexOf('='); return [line.slice(0, at), line.slice(at + 1)];
  }));
  const profile = policyFromEnvironment(env), quota = quotaPolicyFromEnvironment(env);
  assert.ok(profile?.freeOnly); assert.equal(profile.model, PUBLIC_FREE_MODEL); assert.deepEqual(profile.providers, [PUBLIC_FREE_PROVIDER]);
  assert.ok(quota); assert.equal(quota.user.costMicros, 0); assert.equal(quota.scan.costMicros, 0);
  assert.equal(env.LLM_HISTORY_AUTHORITY, HISTORY_AUTHORITY); assert.equal(env.LLM_HISTORY_REVISION, HISTORY.version);
  assert.equal(env.OPENROUTER_API_KEY_FILE, PUBLIC_OPENROUTER_KEY_FILE); assert.equal(env.OPENROUTER_API_KEY, undefined);
});

test('public key file is lazy/exclusive, bounded single raw secret; no unsafe source or fallback', () => {
  const dir = mkdtempSync(join(tmpdir(), 'public-key-')), key = 'sk-or-synthetic-disposable-public-fixture';
  const file = join(dir, 'key');
  try {
    writeFileSync(file, key + '\n', { mode: 0o600 });
    assert.equal(readPublicProviderKey(file), key);
    chmodSync(file, 0o400); assert.equal(readPublicProviderKey(file), key);
    chmodSync(file, 0o644); assert.throws(() => readPublicProviderKey(file)); chmodSync(file, 0o600);
    const alias = join(dir, 'symlink'); symlinkSync(file, alias); assert.throws(() => readPublicProviderKey(alias));
    const hardlink = join(dir, 'hardlink'); linkSync(file, hardlink); assert.throws(() => readPublicProviderKey(file)); rmSync(hardlink);
    for (const content of [key, key + '\n\n', 'OPENROUTER_API_KEY=' + key + '\n', key + '\r\n', '\ufeff' + key + '\n', 'a'.repeat(514), 'т'.repeat(40)]) {
      writeFileSync(file, content); assert.throws(() => readPublicProviderKey(file));
    }
    const folder = join(dir, 'folder'); mkdirSync(folder, { mode: 0o700 }); assert.throws(() => readPublicProviderKey(folder));
    assert.throws(() => readPublicProviderKey(join(dir, 'absent')));
    // Selection itself must reject arbitrary paths and ambiguity before opening anything.
    assert.throws(() => productionProvider({ OPENROUTER_API_KEY_FILE: file }));
    assert.throws(() => productionProvider({ OPENROUTER_API_KEY_FILE: PUBLIC_OPENROUTER_KEY_FILE, OPENROUTER_API_KEY: key }));
    assert.throws(() => productionProvider({ OPENROUTER_API_KEY_FILE: '' }));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('readiness is metadata-only, not credential validity or live generation proof', () => {
  const dir = mkdtempSync(join(tmpdir(), 'public-key-metadata-')), file = join(dir, 'key');
  try {
    assert.equal(publicKeyMetadata(file), 'missing');
    // Invalid bytes with a plausible length must NOT be read/validated by readiness.
    writeFileSync(file, 'invalid format!!!!!!!!\n', { mode: 0o400 });
    assert.equal(publicKeyMetadata(file), 'metadata-valid');
    chmodSync(file, 0o644); assert.equal(publicKeyMetadata(file), 'unsafe'); chmodSync(file, 0o400);
    const alias = join(dir, 'alias'); symlinkSync(file, alias); assert.equal(publicKeyMetadata(alias), 'unsafe');
    const hard = join(dir, 'hard'); linkSync(file, hard); assert.equal(publicKeyMetadata(file), 'unsafe'); rmSync(hard);
    assert.equal(publicCredentialStatus({}), 'unconfigured');
    assert.equal(publicCredentialStatus({ OPENROUTER_API_KEY_FILE: file }), 'unsafe');
    assert.equal(publicCredentialStatus({ OPENROUTER_API_KEY_FILE: PUBLIC_OPENROUTER_KEY_FILE, OPENROUTER_API_KEY: 'not-read' }), 'unsafe');
    const fresh = { ...policy, model: PUBLIC_FREE_MODEL, providers: [PUBLIC_FREE_PROVIDER] };
    assert.equal(publicReadiness(fresh, 'metadata-valid', true, true).status, 'locally-configured');
    assert.equal(publicReadiness(fresh, 'missing', true, true).localReady, false);
    assert.equal(publicReadiness(fresh, 'metadata-valid', false, true).localReady, false);
    assert.equal(publicReadiness(fresh, 'metadata-valid', true, false).localReady, false);
    assert.equal(catalogProfile(policy).status, 'no-catalog-endpoints');
    assert.equal(publicReadiness(policy, 'metadata-valid', true, true).localReady, false);
    const setup = publicReadiness(null, 'unconfigured', false, false);
    assert.equal(setup.generationVerified, false); assert.equal(setup.acceptsCredentials, false);
    assert.ok(setup.blockers.includes('configuration-required'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('whole counts/coverage are immutable through selection; mandatory evidence overflow never silently truncates', () => {
  const report: ReportContext = { ...fixtureReport, profile: PUBLIC_IMAGE_PROFILE, identifierCounts: { cve: 78, debianTemp: 2 },
    findingCount: 80, findings: Array.from({ length: 80 }, (_, n) => ({ check: 'vuln' as const,
      findingId: `vuln-${n.toString(16).padStart(64, '0')}`, severity: n === 79 ? 'CRITICAL' : n === 78 ? 'UNKNOWN' : 'LOW' })) };
  // Use the actual public discriminator rather than an environment-selected profile.
  const before = structuredClone(report);
  const selected = selectSummaryReport(report, policy, 65536);
  assert.deepEqual(report, before); assert.equal(selected.findingCount, 80);
  assert.deepEqual(selected.identifierCounts, { cve: 78, debianTemp: 2 }); assert.deepEqual(selected.coverage, report.coverage);
  assert.equal(selected.contextSelection!.selectedFindings + selected.contextSelection!.omittedFindings, 80);
  assert.ok(selected.findings.some(f => f.severity === 'CRITICAL')); assert.ok(selected.findings.some(f => f.severity === 'UNKNOWN'));
  assert.ok(prepareSummary(selected, policy).reserve.input <= 65536);
  assert.throws(() => selectSummaryReport(report, { ...policy, findings: 1 }, 65536));
  assert.throws(() => selectSummaryReport(report, policy, 1025));
    const optionalOnly: ReportContext = { ...report, findingCount: 1, findings: [report.findings[0]], identifierCounts: { cve: 1, debianTemp: 0 } };
    const emptyReserve = prepareSummary({ ...optionalOnly, findings: [], contextSelection: { totalFindings: 1, selectedFindings: 0,
      omittedFindings: 1, strategy: 'all-critical-and-unknown-then-severity', selectedFindingIds: [] } }, policy).reserve.input;
    assert.throws(() => selectSummaryReport(optionalOnly, policy, emptyReserve), 'never send a context without citable evidence');
  const head = { epoch: randomUUID(), revision: 0, turns: [], decisions: [], pending: null };
  const chat = selectHistoryContext(report, head, 'Explain remaining uncertainty.', policy, 65536);
  assert.equal(chat.context.report.findingCount, 80); assert.equal(chat.context.omission.findings + chat.context.report.findings.length, 80);
  assert.throws(() => selectHistoryContext(report, head, 'Explain.', { ...policy, findings: 1 }, 65536));
});

test('durable public citations preserve exact TEMP semantics and reject malformed IDs, ecosystem switches and raw fields', () => {
  const finding = { check: 'vuln', findingId: `vuln-${'a'.repeat(64)}`, severity: 'LOW', cveId: 'TEMP-1234567-ABCDEF',
    ecosystem: 'deb', identifierKind: 'debian-temp', severitySources: ['nvd'], provenanceRef: `target-${'b'.repeat(64)}`,
    fixedVersionReported: false, advisoryState: 'unknown' };
  assert.equal(safeHistoryFinding(finding), true);
  for (const change of [{ ecosystem: 'npm' }, { identifierKind: 'cve' }, { cveId: 'TEMP-123-ABCDEF' }, { cveId: 'TEMP-1234567-abcdef' },
    { raw: 'scanner-output' }, { packageName: 'sensitive-name' }, { cveId: 'GHSA-abcd-1234-5678' }]) {
    assert.equal(safeHistoryFinding({ ...finding, ...change }), false);
  }
  for (const ecosystem of ['apk', 'deb', 'rpm', 'npm', 'pypi', 'gem', 'gomod', 'cargo', 'maven', 'composer', 'nuget']) {
    assert.equal(safeHistoryFinding({ ...finding, ecosystem, cveId: 'CVE-2026-1234', identifierKind: 'cve' }), true);
  }
  for (const question of ['password=private-value', 'Bearer short-private-credential', '{"Results":[{"Secrets":[]}]}', 'api_key is private-value', 'DB_PASSWORD=private-value', 'AWS_SECRET_ACCESS_KEY=private-value', 'https://private.invalid']) {
    assert.throws(() => cleanText(question));
  }
});
