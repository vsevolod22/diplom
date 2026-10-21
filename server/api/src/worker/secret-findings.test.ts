import assert from 'node:assert/strict';
import crypto, { createHash } from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { isDeepStrictEqual } from 'node:util';
import test from 'node:test';
import { PUBLIC_IMAGE_CHECKS_VERSION, PUBLIC_IMAGE_PROFILE, PUBLIC_IMAGE_RESOURCE_POLICY } from '../oci/public-image-policy.js';
import type { ArchiveBinding } from '../oci/archive-identity.js';
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

const row = { RuleID: 'github-pat', StartLine: 12, EndLine: 12,
  Match: 'SYNTHETIC-PRIVATE-MATCH', Code: { Lines: [{ Content: 'SYNTHETIC-PRIVATE-CODE' }] } };
const result = (Secrets: unknown[], Target: unknown = '/synthetic/private.env') => ({ Class: 'secret', Type: '', Target, Secrets });
const expected = (r: number, s: number, line = 12, rule = 'github-pat') => ({ findingId: `secret-${r}-${s}`,
  ruleId: `rule-${createHash('sha256').update(rule).digest('hex').slice(0, 16)}`, line, evidenceRef: `result-${r}-secret-${s}` });
const same = (actual: unknown, wanted: unknown) => assert.equal(isDeepStrictEqual(actual, wanted), true);

function archive(version = 'a', platform = 'linux/amd64') {
  const imageDigest = `sha256:${version.repeat(64)}` as const;
  const diffId = `sha256:${'c'.repeat(64)}`;
  const binding: ArchiveBinding = { archivePath: '/tmp/trivy/jobs/00000000-0000-0000-0000-000000000000/image.tar', receipt: {
    registry: 'registry-1.docker.io', repository: 'qualification/synthetic-secrets', digest: imageDigest, configDigest: imageDigest, platform,
    layerDigests: [`sha256:${'b'.repeat(64)}`], diffIds: [diffId], archiveSha256: `sha256:${'d'.repeat(64)}`,
    profileVersion: PUBLIC_IMAGE_PROFILE, resourcePolicyVersion: PUBLIC_IMAGE_RESOURCE_POLICY, checksVersion: PUBLIC_IMAGE_CHECKS_VERSION,
  } };
  const raw = { SchemaVersion: 2, ArtifactType: 'container_image', ArtifactName: binding.archivePath,
    Metadata: { ImageID: imageDigest, DiffIDs: [diffId], Layers: [{ DiffID: diffId, Size: 2048 }],
      ImageConfig: { os: 'linux', architecture: 'amd64', rootfs: { type: 'layers', diff_ids: [diffId] } } },
    Results: [result([structuredClone(row), structuredClone(row)])] };
  return { raw, binding };
}

test('exact native-shaped duplicates are removed before emission, retaining first IDs and later original coordinates', () => {
  const raw = { Results: [result([row, structuredClone(row), { ...row, StartLine: 13 }])] };
  const before = structuredClone(raw);
  same(parseSecretFindings(raw), [expected(0, 0), expected(0, 2, 13)]);
  same(raw, before);
});

test('duplicate result groups merge only the same opaque location, while different file/line/rule stays distinct', () => {
  const raw = { Results: [result([row]), result([structuredClone(row)]), result([row], '/synthetic/other.env'),
    result([{ ...row, StartLine: 13 }, { ...row, RuleID: 'aws-access-key-id' }])] };
  same(parseSecretFindings(raw), [expected(0, 0), expected(2, 0), expected(3, 0, 13), expected(3, 1, 12, 'aws-access-key-id')]);
  // Input object key ordering is not a different observation.
  same(parseSecretFindings({ Results: [result([row, Object.fromEntries(Object.entries(row).reverse())])] }), [expected(0, 0)]);
});

test('same location/rule/line never collapses distinct matches, ranges, layer versions or other evidence', () => {
  const distinct = [row, { ...row, Match: 'SYNTHETIC-DIFFERENT-MATCH' }, { ...row, EndLine: 13 },
    { ...row, Layer: { DiffID: `sha256:${'a'.repeat(64)}` } }, { ...row, Layer: { DiffID: `sha256:${'b'.repeat(64)}` } },
    { ...row, Code: { Lines: [{ Content: 'SYNTHETIC-DIFFERENT-CODE' }] } }, { ...row, Title: 'different evidence' }];
  same(parseSecretFindings({ Results: [result(distinct)] }), distinct.map((_, s) => expected(0, s)));
  same(parseSecretFindings({ Results: [result([row]), { ...result([row]), Class: 'other' }, { ...result([row]), Type: 'other' }] }),
    [expected(0, 0), expected(1, 0), expected(2, 0)]);
});

test('ambiguous missing/invalid location is never treated as the same file; null lines are not evidence equality', () => {
  for (const Target of [undefined, null, '', 5, {}, 'x'.repeat(4097)]) {
    same(parseSecretFindings({ Results: [{ ...result([row, structuredClone(row)]), Target }, { ...result([row]), Target }] }),
      [expected(0, 0), expected(0, 1), expected(1, 0)]);
  }
  const findings = parseSecretFindings({ Results: [result([{ RuleID: 'github-pat' }, { RuleID: 'github-pat', StartLine: 'invalid' }])] });
  assert.equal(findings.length === 2 && findings.every(item => item.line === null), true);
});

test('dedup namespaces are report-local and bound image versions/platforms cannot inherit observations or authority', () => {
  for (const version of ['a', 'e']) {
    const { raw, binding } = archive(version);
    same(parseSecretFindings(raw, binding), [expected(0, 0)]);
    same(parseSecretFindings(raw, binding), [expected(0, 0)]);
    // Deliberately violate the runtime contract without weakening its production type.
        assert.throws(() => parseSecretFindings(raw, { ...binding, receipt: { ...binding.receipt,
          digest: 'invalid' as ArchiveBinding['receipt']['digest'] } }));
    assert.throws(() => parseSecretFindings(raw, { ...binding, receipt: { ...binding.receipt, configDigest: `sha256:${'f'.repeat(64)}` } }));
    assert.throws(() => parseSecretFindings(raw, { ...binding, receipt: { ...binding.receipt, platform: 'linux/arm64' } }));
  }
  for (const architecture of ['amd64', 'arm64']) {
    const { raw } = archive();
    raw.Metadata.ImageConfig.architecture = architecture;
    same(parseSecretFindings(raw), [expected(0, 0)]); // Existing unbound legacy API; no global cache.
  }
});

test('raw observation cap still rejects duplicate floods and invalid rows after an otherwise valid duplicate', () => {
  const duplicates = Array.from({ length: 1000 }, () => row);
  same(parseSecretFindings({ Results: [result(duplicates)] }), [expected(0, 0)]);
  assert.throws(() => parseSecretFindings({ Results: [result([...duplicates, row])] }));
  assert.throws(() => parseSecretFindings({ Results: [result(duplicates.slice(0, 600)), result(duplicates.slice(0, 500))] }));
  for (const invalid of [[], null, { ...row, RuleID: 'unsafe/rule' }]) {
    assert.throws(() => parseSecretFindings({ Results: [result([row, structuredClone(row), invalid])] }));
  }
});

test('only existing rule identifiers are hashed; paths, matched values and source text never become hash inputs', context => {
  let onlyRuleHashed = true, hashCalls = 0;
  const original = crypto.createHash;
  context.mock.method(crypto, 'createHash', (algorithm: string, options?: crypto.HashOptions) => {
    const hash = original(algorithm, options);
    const update = hash.update.bind(hash);
    hash.update = ((data: crypto.BinaryLike, encoding?: crypto.Encoding) => {
      onlyRuleHashed &&= data === 'github-pat'; hashCalls++;
      return typeof data === 'string' && encoding !== undefined ? update(data, encoding) : update(data);
    }) as typeof hash.update;
    return hash;
  });
  syncBuiltinESMExports();
  try {
    const findings = parseSecretFindings({ Results: [result([row, structuredClone(row)], 'SYNTHETIC-PRIVATE-PATH')] });
    assert.equal(findings.length === 1 && onlyRuleHashed && hashCalls > 0, true);
    const encoded = JSON.stringify(findings);
    assert.equal(['SYNTHETIC-PRIVATE-PATH', row.Match, row.Code.Lines[0].Content].some(value => encoded.includes(value)), false);
    assert.equal(Object.keys(findings[0]).sort().join(',') === 'evidenceRef,findingId,line,ruleId', true);
  } finally { context.mock.restoreAll(); syncBuiltinESMExports(); }
});
