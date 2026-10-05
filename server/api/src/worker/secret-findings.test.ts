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
  assert.throws(() => parseSecretFindings({ Results: [] }));
  assert.throws(() => parseSecretFindings({ Results: [{}] }));
  assert.throws(() => parseSecretFindings({ Results: [[]] }));
  assert.throws(() => parseSecretFindings({}));
});

test('clean omitted/empty Results require meaningful layer inspection, not only image identity', () => {
  const diffId = `sha256:${'a'.repeat(64)}`;
  const metadata = { Layers: [{ DiffID: diffId, Size: 2048 }], DiffIDs: [diffId], ImageConfig: {} };
  const report = { SchemaVersion: 2, ArtifactType: 'container_image', Metadata: metadata };
  for (const Results of [undefined, [], [{}], [{ Secrets: [] }]]) {
    assert.deepEqual(parseSecretFindings({ ...report, Results }), []);
    for (const Metadata of [undefined, { ...metadata, Layers: undefined }, { ...metadata, Layers: [] },
      { ...metadata, Layers: [{}] }, { ...metadata, Layers: [null] },
      { ...metadata, Layers: [{ DiffID: `sha256:${'b'.repeat(64)}` }] },
      { ...metadata, DiffIDs: [] }, { ...metadata, ImageConfig: [] }]) {
      assert.throws(() => parseSecretFindings({ ...report, Results, Metadata }));
    }
  }
  for (const Results of [null, {}, [[]], [null], [{ Secrets: 'invalid' }], [{ Vulnerabilities: 'invalid' }]]) {
    assert.throws(() => parseSecretFindings({ ...report, Results }));
  }
});
