import { createHash } from 'node:crypto';
import { policyFromEnvironment } from '../policy.js';
import type { ReportContext } from '../report-context.js';

// Explicit fake settings, NOT approved production choices. No live requests in these tests.
export const fixtureEnv: NodeJS.ProcessEnv = {
  LLM_ENABLED: 'true', LLM_MODEL: 'fixture/fake-model', LLM_PROVIDER_ALLOWLIST: 'FixtureProvider',
  LLM_POLICY_REVISION: 'fixture-v1', LLM_ROUTING_APPROVED: 'true', LLM_REGION: 'global', LLM_RETENTION: 'no-storage',
  LLM_TIMEOUT_MS: '1000', LLM_REQUEST_BYTES: '262144', LLM_RESPONSE_BYTES: '65536', LLM_MAX_FINDINGS: '1000',
  LLM_OUTPUT_TOKENS: '256', LLM_REQUEST_BUDGET_USD: '0.5', LLM_INPUT_PRICE_PER_MILLION_USD: '1', LLM_OUTPUT_PRICE_PER_MILLION_USD: '1',
};
export const fixturePolicy = policyFromEnvironment(fixtureEnv)!;
export const fakeKey = 'sk-or-fixture-not-a-real-key-12345';
export const digest = `sha256:${'a'.repeat(64)}`;
export const image = `registry-1.docker.io/library/alpine@${digest}`;
export function vuln(index: number, severity: 'LOW' | 'CRITICAL' = 'LOW') {
  const cveId = `CVE-2025-${String(1000 + index)}`;
  const provenanceRef = `target-${'b'.repeat(64)}`;
  const packageName = 'busybox', installedVersion = '1.2-r0', ecosystem = 'apk' as const;
  const findingId = `vuln-${createHash('sha256').update(JSON.stringify([ecosystem, provenanceRef, cveId, packageName, installedVersion])).digest('hex')}`;
  return { findingId, cveId, ecosystem, packageName, installedVersion, severity, severitySources: ['nvd'], provenanceRef, fixedVersion: null };
}
export function reply(report: ReportContext) {
  return { scanId: report.scanId, digest: report.digest, platform: report.platform, reportVersion: report.reportVersion,
    hypotheses: [{ text: 'This finding may require operator investigation.', citations: [report.findings[0].findingId] }] };
}
export const fixtureReport: ReportContext = {
  scanId: '00000000-0000-4000-8000-000000000000', digest, platform: 'linux/amd64', reportVersion: 'c'.repeat(64),
  state: 'completed', attempt: 1, requestedChecks: ['vuln'], coverage: {
    secret: { outcome: 'unknown', reason: 'CHECK_NOT_REQUESTED' }, sbom: { outcome: 'unknown', reason: 'CHECK_NOT_REQUESTED' },
    config: { outcome: 'unknown', reason: 'CHECK_NOT_REQUESTED' }, vuln: { outcome: 'checked', findingCount: 1 },
  }, findings: [{ check: 'vuln', findingId: vuln(0).findingId, severity: 'LOW' }], findingCount: 1,
  checkedIsNotSafe: true, omittedEvidence: 'All free text, URLs, credentials, env, package strings and raw output excluded',
};
export function envelope(content: unknown = reply(fixtureReport)) {
  return { id: 'fixture-id', model: fixturePolicy.model, choices: [{ finish_reason: 'stop', message: {
    role: 'assistant', content: JSON.stringify(content), refusal: null, reasoning: null,
  } }], usage: { prompt_tokens: 500, completion_tokens: 32 } };
}
