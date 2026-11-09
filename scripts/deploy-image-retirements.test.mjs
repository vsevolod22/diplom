import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { IMAGE_RETIREMENTS, IMAGE_RETIREMENT_ACK, retirementReference, applyImageRetirements, captureImageRetirements } from './deploy-image-retirements.mjs';
import { captureBuildHistory } from './deploy-adapter.mjs';
import { archiveRootMatches } from './public-llm-deployment-catalog.mjs';
test('archive root tolerates remounted device numbering but not inode, membership or current-filesystem substitution', () => {
  const recorded = { dev: 1, ino: 123, names: ['complete.json', 'fenced'] };
  const current = { ...recorded, dev: 2 };
  assert.equal(archiveRootMatches(recorded, current, 2), true);
  assert.equal(archiveRootMatches(recorded, { ...current, ino: 124 }, 2), false);
  assert.equal(archiveRootMatches(recorded, { ...current, names: ['complete.json'] }, 2), false);
  assert.equal(archiveRootMatches(recorded, current, 3), false);
  assert.equal(archiveRootMatches({ ...recorded, dev: NaN }, current, 2), false);
});
const reference = { name: 'api', tag: 'dip-public-images-api:retained-' + 'a'.repeat(32), image: 'sha256:' + 'b'.repeat(64),
  origin: { kind: 'llm-retention', audit: 'deploy-' + 'a'.repeat(32), sha256: 'c'.repeat(64) } };
const other = { ...reference, name: 'web', tag: 'dip-public-images-web:retained-' + 'd'.repeat(32) };
const record = () => ({ version: 1, project: 'dip-public-images', nonce: 'e'.repeat(32), acknowledgement: IMAGE_RETIREMENT_ACK,
  createdAt: 1, references: [retirementReference(reference)] });
function fixture(t) {
  const root = fs.mkdtempSync(join(tmpdir(), 'image-retirement-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const parent = join(root, '.local-public-images', IMAGE_RETIREMENTS);
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const path = join(parent, 'e'.repeat(32) + '.json');
  fs.writeFileSync(path, JSON.stringify(record()), { mode: 0o600 });
  return { root, parent, path };
}
test('explicit retirement removes only exact obligations and does not mutate original history', () => {
  const refs = [reference, other], before = JSON.stringify(refs), result = applyImageRetirements(refs, [record()]);
  assert.deepEqual(result.references, [other]); assert.equal(result.retiredTags.has(reference.tag), true);
  assert.equal(JSON.stringify(refs), before);
  assert.deepEqual(applyImageRetirements(refs, []).references, refs);
});
for (const mode of ['ack', 'project', 'version', 'extra', 'origin', 'image', 'unknown', 'duplicate', 'empty']) {
  test(`retirement rejects ${mode}`, () => {
    const value = record();
    if (mode === 'ack') value.acknowledgement = 'yes';
    if (mode === 'project') value.project = 'protected-other-project';
    if (mode === 'version') value.version = 2;
    if (mode === 'extra') value.extra = true;
    if (mode === 'origin') value.references[0] = { ...value.references[0], origin: { ...reference.origin, sha256: 'f'.repeat(64) } };
    if (mode === 'image') value.references[0].image = 'sha256:' + 'f'.repeat(64);
    if (mode === 'unknown') value.references[0].tag = 'unrelated:old';
    if (mode === 'duplicate') value.references.push(value.references[0]);
    if (mode === 'empty') value.references = [];
    assert.throws(() => applyImageRetirements([reference], [value]));
  });
}
test('capture fences retirement file bytes and directory membership', t => {
  const f = fixture(t), captured = captureImageRetirements(f.root, [reference, other]);
  assert.deepEqual(captured.references, [other]); captured.verify();
  fs.writeFileSync(f.path, JSON.stringify({ ...record(), createdAt: 2 }));
  assert.throws(captured.verify);
});
test('capture rejects insecure files and symlinks', t => {
  const f = fixture(t); fs.chmodSync(f.path, 0o644);
  assert.throws(() => captureImageRetirements(f.root, [reference]));
  fs.chmodSync(f.path, 0o600); fs.renameSync(f.path, f.path + '.original'); fs.symlinkSync(f.path + '.original', f.path);
  assert.throws(() => captureImageRetirements(f.root, [reference]));
});
test('capture missing retirement directory is itself fenced', t => {
  const f = fixture(t); fs.rmSync(f.parent, { recursive: true });
  const captured = captureImageRetirements(f.root, [reference]); captured.verify();
  fs.mkdirSync(f.parent, { mode: 0o700 }); assert.throws(captured.verify);
});
test('actual deployment history keeps immutable original provenance but excludes waived live image checks', t => {
  const f = fixture(t), history = captureBuildHistory(f.root, null, [reference, other]);
  assert.deepEqual(history.allReferences.map(retirementReference), [reference, other]);
  assert.deepEqual(history.references.map(retirementReference), [other]); history.verify();
  fs.unlinkSync(f.path); assert.throws(history.verify);
});
