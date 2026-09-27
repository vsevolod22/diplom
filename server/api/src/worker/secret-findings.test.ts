import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { parseSecretFindings } from './secret-findings.js';

test('untrusted scanner evidence is reduced to bounded identifiers and numeric locations', () => {
  const canary = 'CANARY-private-credential';
  const findings = parseSecretFindings({ Results: [{ Target: canary, Secrets: [{ RuleID: 'aws-key', StartLine: 12,
    Match: canary, Title: canary, Code: { Lines: [{ Content: canary }] } }] }] });
  assert.deepEqual(findings, [{ findingId: 'secret-0-0', ruleId: `rule-${createHash('sha256').update('aws-key').digest('hex').slice(0, 16)}`, line: 12, evidenceRef: 'result-0-secret-0' }]);
  assert.ok(!JSON.stringify(findings).includes(canary));
  assert.throws(() => parseSecretFindings({ Results: [{ Secrets: [{ RuleID: `https://${canary}` }] }] }));
  assert.throws(() => parseSecretFindings({ Results: [{ Secrets: 'not an array' }] }));
  assert.throws(() => parseSecretFindings({ Results: [{ Vulnerabilities: [{ Title: canary }] }] }));
  assert.throws(() => parseSecretFindings({ Results: [{ Secrets: Array.from({ length: 1001 }, () => ({ RuleID: 'a' })) }] }));
  assert.deepEqual(parseSecretFindings({ Results: [] }), []);
  assert.throws(() => parseSecretFindings({}));
});

test('clean Trivy image has no Results only when layer metadata proves image inspection', () => {
  const report = { SchemaVersion: 2, ArtifactType: 'container_image', Metadata: {
    Layers: [{}], DiffIDs: ['sha256:abc'], ImageConfig: {},
  } };
  assert.deepEqual(parseSecretFindings(report), []);
  assert.throws(() => parseSecretFindings({ ...report, Metadata: { Layers: [], DiffIDs: [], ImageConfig: {} } }));
  assert.throws(() => parseSecretFindings({ ...report, Results: null }));
});
