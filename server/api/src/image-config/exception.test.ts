import assert from 'node:assert/strict';
import test from 'node:test';
import { createImageConfigModule } from './index.js';
import { ConfigFailure, type FailureReason } from './policy.js';

const CANARY = 'EXCEPTION_CANARY_SECRET_<script>_\u001b[31m';

type ExceptionCase = { name: string; create: (onRead: () => never) => unknown };
const cases: ExceptionCase[] = [
  { name: 'throwing prototype trap', create: onRead => new Proxy({}, { getPrototypeOf: onRead }) },
  { name: 'throwing ConfigFailure descriptor trap', create: onRead => new Proxy(new ConfigFailure('INVALID_CONFIG'), { getOwnPropertyDescriptor: onRead }) },
  { name: 'revoked proxy', create: () => {
    const revoked = Proxy.revocable(new ConfigFailure('INVALID_CONFIG'), {});
    revoked.revoke();
    return revoked.proxy;
  } },
  { name: 'ConfigFailure reason getter', create: onRead => Object.defineProperty(new ConfigFailure('INVALID_CONFIG'), 'reason', { get: onRead }) },
  { name: 'inherited ConfigFailure reason getter', create: onRead => Object.create(Object.defineProperty(new ConfigFailure('INVALID_CONFIG'), 'reason', { get: onRead })) },
  { name: 'ordinary error getters', create: onRead => Object.defineProperties({}, {
    reason: { get: onRead }, message: { get: onRead }, stack: { get: onRead },
  }) },
  { name: 'proxy property getters', create: onRead => new Proxy(new ConfigFailure('OCI_IDENTITY_REJECTED'), { get: onRead }) },
  { name: 'reason coercion traps', create: onRead => Object.defineProperty(new ConfigFailure('INVALID_CONFIG'), 'reason', {
    value: { [Symbol.toPrimitive]: onRead, toString: onRead, valueOf: onRead },
  }) },
  { name: 'unallowlisted canary reason', create: () => new ConfigFailure(CANARY as never) },
  { name: 'raw canary string', create: () => CANARY },
  { name: 'null exception', create: () => null },
];

for (const asynchronous of [false, true]) {
  const mode = asynchronous ? 'rejected promise' : 'synchronous throw';
  for (const scenario of cases) {
    test(`public analyze contains ${scenario.name} (${mode})`, async t => {
      let reads = 0;
      const onRead = (): never => { reads++; throw new Error(CANARY); };
      const thrown = scenario.create(onRead);
      const logs: unknown[][] = [];
      for (const key of ['log', 'error', 'warn', 'debug', 'info'] as const) {
        t.mock.method(console, key, (...args: unknown[]) => { logs.push(args); });
      }
      const module = createImageConfigModule({ resolveAuthorizedTarget() {
        if (asynchronous) return Promise.reject(thrown);
        throw thrown;
      } });
      // Await without catching: any escaping exception/rejection fails this public-entry regression.
      const result = await module.analyze({ enabled: true, dockerfileProvided: true });
      assert.deepEqual(result, {
        checksVersion: 'image-config-user-v1',
        resourcePolicyVersion: 'image-config-policy-v1',
        supportedRuleIds: ['IMGCFG_USER_ROOT'], completedRuleIds: [],
        config: { outcome: 'failed', reason: 'OCI_IDENTITY_REJECTED' },
        rules: [{ ruleId: 'IMGCFG_USER_ROOT', outcome: 'failed', reason: 'OCI_IDENTITY_REJECTED' }],
        history: { outcome: 'unsupported', reason: 'RULE_NOT_IMPLEMENTED' },
        dockerfile: { outcome: 'unsupported', reason: 'SOURCE_ANALYZER_UNSUPPORTED' },
        iac: { outcome: 'unsupported', reason: 'SOURCE_NOT_PROVIDED' },
        findings: [],
      });
      assert.equal(JSON.stringify(result).includes(CANARY), false);
      assert.deepEqual(logs, []);
      assert.equal(reads, scenario.name === 'throwing prototype trap' || scenario.name === 'throwing ConfigFailure descriptor trap' ? 1 : 0);
    });
  }
  for (const reason of ['INVALID_CONFIG', 'CONFIG_LIMIT_EXCEEDED', 'OCI_IDENTITY_REJECTED'] as const satisfies readonly FailureReason[]) {
    test(`public analyze preserves genuine ${reason} (${mode})`, async () => {
      const module = createImageConfigModule({ resolveAuthorizedTarget() {
        const error = new ConfigFailure(reason);
        if (asynchronous) return Promise.reject(error);
        throw error;
      } });
      const result = await module.analyze({ enabled: true });
      assert.deepEqual(result.config, { outcome: 'failed', reason });
      assert.equal(result.rules[0].reason, reason);
      assert.deepEqual(result.findings, []);
      assert.deepEqual(result.completedRuleIds, []);
    });
  }
}
