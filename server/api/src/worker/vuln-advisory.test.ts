import assert from 'node:assert/strict';
import test from 'node:test';
import { ADVISORY_FINDING_BYTES, ADVISORY_SCAN_BYTES, allocateAdvisoryBudget, jsonBytes, mergeAdvisories, normalizeAdvisory, normalizePlain, validateAdvisory, validateAdvisoryBudget, validV3Vector } from './vuln-advisory.js';
const ref = `target-${'a'.repeat(64)}`, cve = 'CVE-2025-12345';
const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const raw = () => ({ DataSource: { ID: 'alpine', Name: 'CANARY', URL: 'https://evil.test' }, Title: 'Package issue', Description: 'Safe description', Severity: 'HIGH', SeveritySource: 'nvd', FixedVersion: '1.2-r1', CVSS: { nvd: { V3Score: 0, V3Vector: vector } } });
const advisory = (input: Record<string, unknown> = raw()) => normalizeAdvisory(input, ref, cve);
const finding = (id: string, input = raw()) => ({ findingId: id, cveId: cve, advisory: advisory(input) });
test('source slots never duplicate text, fixes or main severity into CVSS sources', () => {
  const value = advisory();
  validateAdvisory(value, cve);
  assert.equal(value.assessments.filter(a => a.title.value).length, 1);
  assert.equal(value.assessments.find(a => a.title.value)?.source, 'alpine');
  assert.equal(value.assessments.find(a => a.severity)?.source, 'nvd');
  assert.equal(value.assessments.find(a => a.cvss)?.title.value, null);
  assert.equal(value.assessments.find(a => a.cvss)?.fixedVersion, null);
  assert.equal(value.assessments.find(a => a.cvss)?.cvss?.reportedScore, 0);
  assert.equal(value.assessments.every(a => a.language === null), true);
  assert.equal(value.references.length, 3);
  assert.ok(!JSON.stringify(value).includes('CANARY'));
  assert.equal(advisory({ ...raw(), DataSource: { Name: 'nvd' } }).assessments.find(a => a.title.value)?.source, 'unknown');
});
test('explicit CVSS versions, base metrics and score validity remain independent', () => {
  for (const bad of [vector + '/AV:N', vector + '/X:N', vector + '/E:H', vector.replace('/AC:L', ''), vector.replace('AC:L', 'AC:X'), vector.replace('3.1', '4.0')]) assert.equal(validV3Vector(bad), false);
  for (const score of ['9.8', NaN, Infinity, -1, 11]) {
    const value = advisory({ CVSS: { nvd: { V3Score: score, V3Vector: vector } } });
    assert.equal(value.assessments.find(a => a.cvss)?.cvss?.reportedScore, null);
    validateAdvisory(value, cve);
  }
  const value = advisory({ CVSS: { nvd: { V3Score: 0 }, alpine: { V2Score: 5, V2Vector: 'AV:N' }, ghsa: { V3Score: 7, V3Vector: 'CANARY' } } });
  const nvd = value.assessments.find(a => a.source === 'nvd' && a.cvss)!.cvss!;
  assert.equal(nvd.version, null); assert.equal(nvd.reportedScore, 0);
  assert.equal(value.references.length, 2);
  assert.equal(value.assessments.find(a => a.source === 'alpine')?.cvss?.vectorState, 'unsupported');
  validateAdvisory(value, cve);
  const v30 = advisory({ CVSS: { nvd: { V3Vector: vector.replace('3.1', '3.0') } } });
  assert.equal(v30.references.length, 2);
  assert.deepEqual(normalizeAdvisory({ CVSS: { nvd: { V3Vector: vector } } }, ref, 'invalid-id').references, []);
});
test('plaintext redacts payloads before storage and truncates on UTF8 boundaries', () => {
  const text = 'Safe <script>alert(1)</script><img src="https://evil"> prose token=CANARY-token https://host/?signature=SECRET \u202E tail';
  const field = normalizePlain(text, 512);
  assert.equal(field.redacted, true);
  for (const secret of ['alert', 'CANARY', 'https:', '<img', '\u202E', 'SECRET']) assert.ok(!field.value?.includes(secret));
  assert.equal(normalizePlain('-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----', 512).state, 'redacted');
  assert.equal(normalizePlain({}, 512).state, 'invalid');
  const utf8 = normalizePlain('😀'.repeat(129), 512);
  assert.equal(Buffer.byteLength(utf8.value!), 512); assert.equal(utf8.state, 'truncated');
  const escaped = allocateAdvisoryBudget([finding('one', { ...raw(), Description: '\\"'.repeat(4000) })]);
  assert.ok(jsonBytes(escaped[0]) <= ADVISORY_FINDING_BYTES);
  validateAdvisoryBudget(escaped);
});
test('quoted credential labels and multiword payloads are redacted before durable validation', () => {
  for (const text of [
    'Safe {"password":"PRIVATE_SENTINEL words"} tail',
    "Safe {'api_key':'PRIVATE_SENTINEL words'} tail",
    'Safe password="PRIVATE_SENTINEL words" tail',
    'Safe token="escaped \\"quote PRIVATE_SENTINEL words" tail',
    'Safe credentials: PRIVATE_SENTINEL words',
    'Safe password="PRIVATE_SENTINEL words',
  ]) {
    const field = normalizePlain(text, 512);
    assert.equal(field.redacted, true);
    assert.ok(!field.value?.includes('PRIVATE_SENTINEL'));
    assert.ok(!field.value?.includes('words'));
    const normalized = advisory({ Title: text, Description: text });
    validateAdvisory(normalized, cve);
    assert.ok(!JSON.stringify(normalized).includes('PRIVATE_SENTINEL'));
  }
});
test('Basic credential presentations are redacted before field limits and strict durable validation', () => {
  const encoded = Buffer.from('synthetic-user:PRIVATE_BASIC_PASSWORD').toString('base64');
  for (const text of [
    `Authorization: Basic ${encoded}`, `pRoXy-AuThOrIzAtIoN:\t bAsIc\t${encoded}`,
    `Authorization: Basic "${encoded}"`, `Authorization: Basic '${encoded}'`,
    `{"Authorization":"Basic ${encoded}"}`, `Basic\n${encoded}`,
    `Safe <b>Basic</b> ${encoded} tail`, `Safe Basic\u0000 ${encoded} tail`,
    `x`.repeat(510) + ` Basic ${encoded}`,
  ]) {
    const value = advisory({ Title: text, Description: text });
    validateAdvisory(value, cve);
    assert.ok(value.limitations.includes('redaction'));
    assert.ok(!JSON.stringify(value).includes(encoded));
    assert.ok(!JSON.stringify(value).includes('PRIVATE_BASIC_PASSWORD'));
    for (const row of value.assessments) for (const field of [row.title, row.description]) {
      if (field.value) assert.equal(normalizePlain(field.value, 4096).value, field.value);
    }
    const unsafe = advisory({ Title: 'safe' });
    unsafe.assessments.find(row => row.title.value)!.title = { value: text.slice(0, 512), state: 'available', redacted: true };
    if (Buffer.byteLength(text) <= 512) assert.throws(() => validateAdvisory(unsafe, cve));
  }
});
test('bounded plaintext normalization closes nested/exposed markup or degrades only optional fields', () => {
  const nested = (n: number) => '['.repeat(n) + 'issue' + '](doc)'.repeat(n);
  for (const text of [
    '[[issue](doc)](outer)', '[[[issue](doc)](middle)](outer)', '[issue](outer(inner))',
    '<b<[x](y)>>issue', 'ht<script>removed</script>tps://evil.test/secret',
    'be<b>removed</b>arer PRIVATE_SENTINEL', nested(32), '界'.repeat(300) + '[[issue](doc)](outer)',
  ]) {
    for (const max of [512, 4096]) {
      const field = normalizePlain(text, max);
      if (field.value) {
        assert.ok(Buffer.byteLength(field.value) <= max);
        assert.equal(normalizePlain(field.value, max).value, field.value);
      }
      validateAdvisory(advisory({ Title: text, Description: text }), cve);
    }
  }
  assert.equal(normalizePlain('[[issue](doc)](outer)', 512).value, 'issue');
  assert.equal(normalizePlain(nested(32), 4096).state, 'invalid');
  assert.equal(normalizePlain(nested(32), 4096).value, null);
  // Unclosed delimiters cannot trigger a suffix rescan for every opening byte.
  assert.equal(normalizePlain('['.repeat(1_000_000), 512).value, '['.repeat(512));
  assert.equal(normalizePlain('<'.repeat(1_000_000), 512).value, '<'.repeat(512));
});
test('generated optional plaintext remains acceptable to the independent strict browser predicate', async () => {
  const { parseCurrentVuln } = await import(new URL('../../../../src/shared/api/scans/scanTransport.ts', import.meta.url).href);
  const fragments = ['[', '](doc)', '<b>', '</b>', '\u0000', '\u202e', 'Basic payload', 'ht', 'tps://host.test', 'word', '界', '😀'];
  let seed = 7;
  for (let iteration = 0; iteration < 128; iteration++) {
    let text = '';
    for (let part = 0; part < 12; part++) {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      text += fragments[seed % fragments.length];
    }
    const value = allocateAdvisoryBudget([{ findingId: `vuln-${iteration}`, cveId: cve, ecosystem: 'apk',
      packageName: 'busybox', installedVersion: '1.2', severity: 'HIGH', fixedVersion: null,
      advisory: advisory({ Title: text, Description: text }) }]);
    validateAdvisoryBudget(value);
    const parsed = parseCurrentVuln({ outcome: 'checked', coverage: 'image',
      image: `registry-1.docker.io/library/alpine@sha256:${'a'.repeat(64)}`, platform: 'linux/amd64',
      findingCount: 1, scannerVersion: '0.69.3', checkedAt: '2026-10-07T08:00:00.000Z', findings: value, nextCursor: null });
    assert.equal(parsed.findings.length, 1);
  }
});

test('missing is not disagreement; duplicate assessments merge deterministically', () => {
  const a = advisory(), b = advisory({ ...raw(), Title: 'Other issue', Severity: 'LOW', FixedVersion: '1.3-r0' });
  const merged = mergeAdvisories(a, b, cve);
  assert.deepEqual(merged, mergeAdvisories(b, a, cve));
  assert.deepEqual(merged.conflicts, ['title', 'severity', 'fixedVersion']);
  assert.equal(merged.conflictState, 'present');
  assert.deepEqual(mergeAdvisories(a, a, cve), a);
  assert.deepEqual(mergeAdvisories(a, advisory({}), cve).conflicts, []);
});
test('closed stored validator rejects unknown fields, prototypes and unsafe URLs', () => {
  const value = advisory();
  for (const url of ['https://nvd.nist.gov:443/vuln/detail/' + cve, 'https://nvd.nist.gov.evil/vuln/detail/' + cve, 'https://user@nvd.nist.gov/vuln/detail/' + cve, 'https://nvd.nist.gov/vuln/detail/' + cve + '#x', 'https://nvd.nist.gov/vuln/detail/' + cve + '%0a', 'javascript:alert(1)']) {
    const changed = structuredClone(value); changed.references[1].url = url;
    assert.throws(() => validateAdvisory(changed, cve));
  }
  assert.throws(() => validateAdvisory({ ...value, raw: 'payload' }, cve));
  assert.throws(() => validateAdvisory(Object.assign(Object.create({ polluted: true }), value), cve));
  const changed = structuredClone(value); Object.setPrototypeOf(changed.assessments[0].title, { polluted: true });
  assert.throws(() => validateAdvisory(changed, cve));
  const mismatch = structuredClone(value); mismatch.assessments.find(a => a.cvss)!.cvss!.version = '3.0';
  assert.throws(() => validateAdvisory(mismatch, cve));
  let calls = 0;
  const getterFinding = Object.defineProperty({ findingId: 'one', cveId: cve }, 'advisory', { get: () => { calls++; return value; }, enumerable: true });
  assert.throws(() => validateAdvisoryBudget([getterFinding]));
  assert.equal(calls, 0);
  const accessorArray = [value];
  Object.defineProperty(accessorArray, '0', { get: () => { calls++; return value; }, enumerable: true });
  assert.throws(() => validateAdvisory({ ...value, assessments: accessorArray }, cve));
  assert.equal(calls, 0);
});
test('whole scan deterministic allocation reserves omissions and does not change core order', () => {
  const input = Array.from({ length: 1000 }, (_, i) => finding(String(i).padStart(4, '0'), { ...raw(), Description: '界'.repeat(1365) }));
  const output = allocateAdvisoryBudget(input);
  assert.equal(output.length, 1000); assert.deepEqual(output.map(f => f.findingId), input.map(f => f.findingId));
  assert.ok(output.some(f => f.advisory.state === 'omitted'));
  assert.ok(jsonBytes(output.map(f => f.advisory)) <= ADVISORY_SCAN_BYTES);
  validateAdvisoryBudget(output);
  assert.deepEqual(allocateAdvisoryBudget([...input].reverse()).reverse(), output);
  assert.throws(() => validateAdvisoryBudget(input));
});
test('assessment N+1, field N+1 and finding budgets retain core and signal discarded observations', () => {
  assert.equal(normalizePlain('a'.repeat(512), 512).state, 'available');
  assert.equal(normalizePlain('a'.repeat(513), 512).state, 'truncated');
  assert.equal(normalizePlain('界'.repeat(1366), 4096).value?.length, 1365);
  const merged = (n: number, description = 'brief') => Array.from({ length: n }, (_, i) => advisory({ Title: `Title ${i}`, Description: description }))
    .reduce((a, b) => mergeAdvisories(a, b, cve));
  const at = allocateAdvisoryBudget([{ findingId: 'one', cveId: cve, advisory: merged(15) }])[0];
  assert.equal(at.advisory.assessments.length, 16); assert.ok(!at.advisory.limitations.includes('assessment_limit'));
  const over = allocateAdvisoryBudget([{ findingId: 'one', cveId: cve, advisory: merged(16) }])[0];
  assert.equal(over.advisory.assessments.length, 16); assert.ok(over.advisory.limitations.includes('assessment_limit'));
  assert.equal(over.advisory.conflictState, 'unknown'); assert.ok(over.advisory.conflicts.includes('title'));
  validateAdvisory(over.advisory, cve);
  const large = allocateAdvisoryBudget([{ findingId: 'one', cveId: cve, advisory: merged(4, '\\'.repeat(4096)) }])[0];
  assert.equal(large.findingId, 'one'); assert.equal(large.advisory.state, 'omitted'); assert.deepEqual(large.advisory.limitations, ['finding_budget']);
  const refs = advisory(); refs.references = Array(9).fill(refs.references[0]); assert.throws(() => validateAdvisory(refs, cve));
});
test('absent CVSS fields and different families do not fabricate a conflict', () => {
  const value = advisory({ CVSS: { nvd: { V3Score: 7 }, alpine: { V3Score: 7, V3Vector: vector }, ghsa: { V2Score: 5 } } });
  assert.ok(!value.conflicts.includes('cvss'));
  const conflict = advisory({ CVSS: { nvd: { V3Score: 7 }, alpine: { V3Score: 8 } } });
  assert.ok(conflict.conflicts.includes('cvss'));
});
