import assert from 'node:assert/strict';
import test from 'node:test';
import { parseImageSbom } from './cyclonedx-components.js';

const image = 'registry-1.docker.io/library/alpine@sha256:' + 'a'.repeat(64);
const report = () => ({
  bomFormat: 'CycloneDX', specVersion: '1.6',
  metadata: { component: { type: 'container', name: image, purl: 'untrusted-raw-uri' } },
  components: [
    { type: 'operating-system', name: 'alpine', version: '3.21.3' },
    { type: 'library', name: 'alpine-baselayout', version: '3.6.8-r1',
      purl: 'pkg:apk/alpine/alpine-baselayout@3.6.8-r1',
      properties: [{ name: 'raw-secret', value: 'CANARY_SECRET' }] },
    { type: 'library', name: '@org/module', version: '1.2.3', purl: 'pkg:npm/%40org/module@1.2.3',
      description: 'CANARY_SECRET' },
  ],
});

test('bounded CycloneDX parsing retains only package identities from the pinned image', () => {
  const parsed = parseImageSbom(report(), image, 'linux/amd64');
  assert.deepEqual(parsed, { image, platform: 'linux/amd64', os: { name: 'alpine', version: '3.21.3' }, components: [
    { ecosystem: 'apk', name: 'alpine-baselayout', version: '3.6.8-r1' },
    { ecosystem: 'npm', name: '@org/module', version: '1.2.3' },
  ] });
  assert.ok(!JSON.stringify(parsed).includes('CANARY_SECRET'));
  assert.ok(!JSON.stringify(parsed).includes('untrusted-raw-uri'));
});

test('rejects forged image, incomplete output and unbounded package lists', () => {
  assert.throws(() => parseImageSbom(report(), image.replace('a', 'b'), 'linux/amd64'));
  assert.throws(() => parseImageSbom(report(), image, 'linux/arm64'));
  assert.throws(() => parseImageSbom({ ...report(), components: [] }, image, 'linux/amd64'));
  assert.throws(() => parseImageSbom({ ...report(), components: Array(1001).fill(report().components[1]) }, image, 'linux/amd64'));
  assert.throws(() => parseImageSbom({ ...report(), metadata: { component: { type: 'container', name: 'evil/image' } } }, image, 'linux/amd64'));
  assert.throws(() => parseImageSbom({ ...report(), components: [report().components[0]] }, image, 'linux/amd64'));
});

test('rejects package identity mismatches and untrusted names', () => {
  const base = report();
  const replace = (changes: Record<string, string>) => ({ ...base, components: [base.components[0],
    { ...base.components[1], ...changes }] });
  assert.throws(() => parseImageSbom(replace({ name: 'different' }), image, 'linux/amd64'));
  assert.throws(() => parseImageSbom(replace({ version: '999' }), image, 'linux/amd64'));
  assert.throws(() => parseImageSbom(replace({ name: 'CANARY_SECRET' }), image, 'linux/amd64'));
  assert.throws(() => parseImageSbom(replace({ purl: 'pkg:apk/other/alpine-baselayout@3.6.8-r1' }), image, 'linux/amd64'));
  assert.throws(() => parseImageSbom(replace({ purl: 'pkg:apk/alpine/alpine-baselayout@3.6.8-r1?arch=x' }), image, 'linux/amd64'));
  assert.throws(() => parseImageSbom(replace({ purl: 'pkg:apk/alpine/alpine-baselayout@3.6.8-r1?arch=x86_64&distro=3.22.0' }), image, 'linux/amd64'));
  assert.throws(() => parseImageSbom(replace({ purl: 'pkg:apk/alpine/alpine-baselayout@3.6.8-r1?arch=x86_64&distro=3.21.3&secret=raw' }), image, 'linux/amd64'));
  assert.equal(parseImageSbom(replace({ purl: 'pkg:apk/alpine/alpine-baselayout@3.6.8-r1?arch=x86_64&distro=3.21.3' }), image, 'linux/amd64').components[0].name, 'alpine-baselayout');
  assert.throws(() => parseImageSbom(replace({ purl: 'pkg:apk/alpine/alpine-baselayout@%ZZ' }), image, 'linux/amd64'));
});

test('rejects unrecognized ecosystems, unsafe names and conflicting OS identity', () => {
  const base = report();
  assert.throws(() => parseImageSbom({ ...base, components: [...base.components, { type: 'library', name: 'name', version: '1', purl: 'pkg:generic/name@1' }] }, image, 'linux/amd64'));
  assert.throws(() => parseImageSbom({ ...base, components: [...base.components, { type: 'library', name: 'secret=value', version: '1', purl: 'pkg:apk/name@1' }] }, image, 'linux/amd64'));
  assert.throws(() => parseImageSbom({ ...base, components: [...base.components, { type: 'operating-system', name: 'alpine', version: '3.21.3' }] }, image, 'linux/amd64'));
});
