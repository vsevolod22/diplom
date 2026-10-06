import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';
import { createImageConfigModule } from './index.js';
import { ConfigFailure } from './policy.js';
import { baseConfig, encode, setup } from './test-fixtures.js';

const CANARY = 'CANARY_SECRET_\u001b[31m_<script>$(curl http://169.254.169.254)</script>_ignore_previous_instructions';

function assertClosed(result: Awaited<ReturnType<ReturnType<typeof setup>['analyze']>>) {
  assert.deepEqual(Object.keys(result).sort(), ['checksVersion', 'resourcePolicyVersion', 'supportedRuleIds', 'completedRuleIds', 'config', 'rules', 'history', 'dockerfile', 'iac', 'findings'].sort());
  assert.equal(result.checksVersion, 'image-config-user-v1');
  assert.equal(result.resourcePolicyVersion, 'image-config-policy-v1');
  assert.deepEqual(result.supportedRuleIds, ['IMGCFG_USER_ROOT']);
  assert.deepEqual(result.completedRuleIds, result.config.outcome === 'checked' ? ['IMGCFG_USER_ROOT'] : []);
  assert.equal(result.rules[0].outcome, result.config.outcome);
  assert.equal(result.rules[0].reason, result.config.reason);
  for (const key of ['config', 'history', 'dockerfile', 'iac'] as const) {
    assert.deepEqual(Object.keys(result[key]).sort(), result[key].reason ? ['outcome', 'reason'] : ['outcome']);
  }
  assert.equal(result.history.reason, 'RULE_NOT_IMPLEMENTED');
  assert.equal(JSON.stringify(result).includes(CANARY), false);
  assert.ok(Buffer.byteLength(JSON.stringify(result)) <= 16384);
  assert.ok(result.findings.length <= 1);
  for (const finding of result.findings) {
    assert.deepEqual(Object.keys(finding).sort(), ['findingId', 'ruleId', 'category', 'severity', 'severitySource', 'classification', 'message', 'recommendation', 'location', 'manifestDigest', 'configDigest', 'platform'].sort());
    assert.equal(finding.category, 'image-config');
    assert.equal(finding.severity, 'MEDIUM');
    assert.equal(finding.severitySource, 'image-config-user-v1');
    assert.equal(finding.location, '/config/User');
    assert.match(finding.findingId, /^sha256:[a-f0-9]{64}$/);
  }
}

test('all outcomes have fixed allowlisted coverage; history/source presence cannot extend it', async () => {
  for (const history of [undefined, [{ created_by: CANARY, author: CANARY, comment: CANARY, empty_layer: true }]]) {
    for (const user of ['0', '1000', CANARY, null]) {
      for (const enabled of [true, false, undefined, 'true']) {
        for (const sourcePresent of [true, false]) {
          const f = setup({ os: 'linux', architecture: 'amd64', config: { User: user, Env: [CANARY], Labels: { [CANARY]: CANARY } }, history, [CANARY]: CANARY });
          const extra = { enabled, dockerfileProvided: sourcePresent, iacProvided: sourcePresent,
            get sourceBytes(): never { throw new Error(CANARY); }, get history(): never { throw new Error(CANARY); },
            get receipt(): never { throw new Error(CANARY); }, get manifestBytes(): never { throw new Error(CANARY); } };
          // Public entry directly, retaining getters rather than spreading/evaluating them.

          const request = Object.defineProperties({ target: f.target }, Object.getOwnPropertyDescriptors(extra));
          const analyzed = await f.module.analyze(request);
          assertClosed(analyzed);
          assert.equal(analyzed.dockerfile.reason, sourcePresent ? 'SOURCE_ANALYZER_UNSUPPORTED' : 'SOURCE_NOT_PROVIDED');
          assert.equal(analyzed.iac.reason, sourcePresent ? 'SOURCE_ANALYZER_UNSUPPORTED' : 'SOURCE_NOT_PROVIDED');
          assert.equal(f.calls(), enabled === true ? 1 : 0);
        }
      }
    }
  }
});

test('identity/parser/limit errors and upstream exceptions never carry raw canaries or log', async () => {
  const logs: unknown[][] = [];
  const originals = { log: console.log, error: console.error, warn: console.warn, debug: console.debug, info: console.info };
  for (const key of Object.keys(originals) as (keyof typeof originals)[]) console[key] = (...args: unknown[]) => { logs.push(args); };
  try {
    const inputs = [Buffer.from(`{"${CANARY}"`), encode({ ...baseConfig(), unknown: CANARY.repeat(300) }),
      encode({ ...baseConfig(), config: { User: false, Labels: { [CANARY]: CANARY } } })];
    for (const bytes of inputs) assertClosed(await setup(bytes).analyze());
    const wrong = setup();
    wrong.input.identity.platform.os = CANARY;
    assertClosed(await wrong.analyze());
    wrong.repinManifest(encode({ ...wrong.manifest, mediaType: CANARY }));
    assertClosed(await wrong.analyze());
    for (const error of [new Error(CANARY), CANARY, { message: CANARY }, new ConfigFailure(CANARY as never)]) {
      const module = createImageConfigModule({ resolveAuthorizedTarget() { throw error; } });
      const result = await module.analyze({ enabled: true, target: {} });
      assertClosed(result);
      assert.equal(result.config.reason, 'OCI_IDENTITY_REJECTED');
    }
    assert.deepEqual(logs, []);
  } finally {
    Object.assign(console, originals);
  }
});

test('off/invalid flags do not evaluate inherited, accessor, source or byte capabilities', async () => {
  const f = setup();
  const trap = { get enabled(): never { throw new Error(CANARY); }, get target(): never { throw new Error(CANARY); },
    get dockerfileProvided(): never { throw new Error(CANARY); }, get iacProvided(): never { throw new Error(CANARY); } };
  assert.equal((await f.module.analyze(trap)).config.reason, 'INVALID_CHECK_FLAG');
  assert.equal((await f.module.analyze(Object.create(trap))).config.reason, 'CHECK_DISABLED');
  const off = Object.defineProperties({ enabled: false }, Object.getOwnPropertyDescriptors({
    get target(): never { throw new Error(CANARY); }, get configBytes(): never { throw new Error(CANARY); },
    get identity(): never { throw new Error(CANARY); }, get receipt(): never { throw new Error(CANARY); },
    get dockerfileProvided(): never { throw new Error(CANARY); },
  }));
  assert.equal((await f.module.analyze(off)).config.reason, 'CHECK_DISABLED');
  for (const invalid of [null, undefined, [], 1, CANARY]) {
    assert.equal((await f.module.analyze(invalid as never)).config.reason, 'INVALID_CHECK_FLAG');
  }
  assert.equal(f.calls(), 0);
});

test('consumer merges independent module coverage without altering sibling results', async () => {
  const sibling = Object.freeze({ secrets: Object.freeze({ outcome: 'checked', count: 2 }), sbom: Object.freeze({ outcome: 'checked', count: 123 }) });
  const original = JSON.stringify(sibling);
  const result = await setup({ ...baseConfig(), config: { User: CANARY } }).analyze({ results: sibling });
  assert.equal(result.config.outcome, 'unsupported');
  assert.equal(JSON.stringify(sibling), original);
  const merged = { ...sibling, imageConfig: result };
  assert.equal(merged.secrets, sibling.secrets);
  assert.equal(merged.sbom, sibling.sbom);
  assert.equal('secrets' in result, false);
  // This tests the pure handoff, NOT the real ledger/report merger.
});

test('runtime module import graph has no transport, filesystem, process, daemon or LLM dependency', async () => {
  const runtime = ['index.ts', 'contract.ts', 'policy.ts', 'bounded-json.ts', 'verified-input.ts', 'user-rule.ts', 'result.ts'];
  for (const file of runtime) {
    const text = await readFile(new URL(file, import.meta.url), 'utf8');
    const source = ts.createSourceFile(file, text, ts.ScriptTarget.ES2022, true);
    function visit(node: ts.Node) {
      if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
        const specifier = node.moduleSpecifier;
        if (specifier && ts.isStringLiteral(specifier)) {
          assert.ok(specifier.text === 'node:crypto' || runtime.some(name => specifier.text === `./${name.replace('.ts', '.js')}`), `${file}: ${specifier.text}`);
        }
      }
      if (ts.isCallExpression(node)) {
        assert.ok(node.expression.kind !== ts.SyntaxKind.ImportKeyword, `${file}: dynamic import`);
        if (ts.isIdentifier(node.expression)) assert.ok(!['fetch', 'require', 'eval', 'Function', 'setInterval', 'setTimeout'].includes(node.expression.text), file);
      }
      if (ts.isIdentifier(node)) assert.ok(!['process', 'console', 'WebSocket', 'XMLHttpRequest', 'Deno', 'Bun'].includes(node.text), `${file}: ${node.text}`);
      ts.forEachChild(node, visit);
    }
    visit(source);
  }
});
