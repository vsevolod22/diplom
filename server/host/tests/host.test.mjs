import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import {
  COMMANDS,
  HostCollector as ProductionHostCollector,
  createCommandRunner,
  projectOutput,
} from '../src/collector.mjs';
import { CaptureAuthority } from '../src/capture-authority.mjs';
import { SUPERVISOR_ID } from '../src/supervisor.mjs';

// Fresh isolated process-authority scope per fixture, never a claim of durable real consent.
class HostCollector extends ProductionHostCollector {
  constructor(options) {
    super({ authority: new CaptureAuthority(), ...options });
  }
}
import { EXCLUSIONS, PLAN_ID, SOURCE_VERSION, canonical, parseEnvelope, payload } from '../src/contract.mjs';
import { HostIntake, createSignedEnvelope, publicFingerprint } from '../src/intake.mjs';
import { main } from '../src/cli.mjs';

// These values are SYNTHETIC, not facts observed on this machine. No subprocess is spawned.
const NOW = Date.parse('2026-10-09T10:00:00.000Z');
const iso = (offset) => new Date(NOW + offset).toISOString();
const hex = (n) => n.toString(16).padStart(32, '0');
const auth = () => ({
  confirmed: true,
  reviewed: true,
  planId: PLAN_ID,
  issuedAt: iso(-1000),
  expiresAt: iso(299000),
  binding: { subject: hex(1), targetId: hex(2), targetVersion: 1, consentId: hex(3), nonce: hex(4) },
});
const outputs = ['15.0.1\n', '24.0.0\n', 'arm64\n', '17179869184\n', '8\n'];
const evidence = () => ({
  schema: 'host-evidence-v1',
  sourceVersion: SOURCE_VERSION,
  platform: 'native-macos',
  scope: PLAN_ID,
  binding: auth().binding,
  startedAt: iso(-500),
  endedAt: iso(-100),
  facts: Object.fromEntries(COMMANDS.map((c, i) => [c.fact, projectOutput(c.fact, outputs[i])])),
});
const keys = generateKeyPairSync('ed25519');
const enrollment = () => ({
  subject: hex(1),
  targetId: hex(2),
  targetVersion: 1,
  signerId: hex(5),
  sourceVersion: SOURCE_VERSION,
  publicKeyDer: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  fingerprint: publicFingerprint(keys.publicKey),
});
const signed = (e = evidence(), k = keys.privateKey) => createSignedEnvelope(e, hex(5), k);
const collector = (runner) => new HostCollector({ runner, platform: 'darwin', now: () => NOW });
const invalid = (operation) => assert.throws(operation, { message: 'INVALID_HOST_EVIDENCE' });
const denied = { host: 'not_authorized', engineQueried: false };

// Fake process exercises real command runner budgets without executing ANY public host command.
function fakeSpawn(effect, received = []) {
  return (...args) => {
    received.push(args);
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = (signal) => {
      child.signal = signal;
      queueMicrotask(() => child.emit('close', null));
      return true;
    };
    queueMicrotask(() => effect(child));
    return child;
  };
}

test('no opt-in, runtime-style consent, false review, malformed/expired authorization: zero commands', async () => {
  let sends = 0;
  const c = collector(async () => {
    sends++;
    throw new Error('must not execute');
  });
  for (const consent of [
    undefined,
    {},
    { confirmed: true },
    { ...auth(), confirmed: false },
    { ...auth(), reviewed: false },
    { ...auth(), planId: 'runtime-host-policy-v1' },
    { ...auth(), expiresAt: iso(0) },
    { ...auth(), issuedAt: iso(1) },
    { ...auth(), expiresAt: iso(300001) },
    { ...auth(), engine: true },
  ]) {
    assert.deepEqual(await c.collect(consent), denied);
  }
  assert.equal(sends, 0);
});

test('Linux is unsupported, not fictional qualification; absent opt-in remains not_authorized', async () => {
  const c = new HostCollector({
    platform: 'linux',
    now: () => NOW,
    runner: () => assert.fail('zero commands'),
  });
  assert.deepEqual(await c.collect(), denied);
  assert.deepEqual(await c.collect(auth()), {
    host: 'unsupported',
    reason: 'native_macos_only',
    engineQueried: false,
  });
});

test('synthetic capture records precisely five sanitized facts, unsigned provenance and explicit exclusions', async () => {
  const calls = [];
  const c = collector(async (command, limits) => {
    calls.push(command);
    assert.equal(limits.timeoutMs, 750);
    return projectOutput(command.fact, outputs[COMMANDS.indexOf(command)]);
  });
  const result = await c.collect(auth());
  assert.equal(result.host, 'captured');
  assert.equal(result.provenance, 'local_capture_unsigned');
  assert.equal(result.liveQualified, false);
  assert.equal(result.engineQueried, false);
  assert.deepEqual(calls, COMMANDS);
  assert.deepEqual(result.exclusions, EXCLUSIONS);
  assert.equal(payload(result.evidence), result.evidence);
  assert.equal(result.evidence.facts.logicalCpuCount.value, 8);
});

test('timeouts and invalid facts stay unavailable, not checked/security findings or fake completeness', async () => {
  let index = 0;
  const result = await collector(async () => {
    index++;
    if (index === 1) return { status: 'unavailable', reason: 'timeout' };
    if (index === 2) return { status: 'unavailable', reason: 'command_failed' };
    return projectOutput(COMMANDS[index - 1].fact, 'SECRET=value\n');
  }).collect(auth());
  assert.equal(result.host, 'captured');
  assert.equal(result.evidence.facts.productVersion.reason, 'timeout');
  assert.equal(result.evidence.facts.kernelRelease.reason, 'command_failed');
  assert.ok(!canonical(result).includes('PRIVATE_RAW_DIAGNOSTIC'));
  assert.ok(!canonical(result).includes('SECRET'));
  assert.ok(Object.values(result.evidence.facts).every((f) => f.status === 'unavailable'));
});

test('parser rejects raw diagnostics, control/extra lines, Unicode, unsafe/fractional/zero resources', () => {
  for (const text of [
    '15.0.1\n\n',
    '15.0.1\r\n',
    'SECRET=abc',
    '\u001b[1m15.0.1',
    'é',
    ' 15.0.1',
    'x'.repeat(1025),
  ]) {
    assert.equal(projectOutput('productVersion', text).status, 'unavailable');
  }
  for (const text of ['0', '-1', '1e3', '1.0', '4097', '9007199254740993']) {
    assert.equal(projectOutput('logicalCpuCount', text).status, 'unavailable');
  }
  assert.equal(projectOutput('arbitrary', '5').status, 'unavailable');
});

test('active1/queue0 fence and released slot; caller mutation cannot swap consent in flight', async () => {
  let release;
  const barrier = new Promise((resolve) => {
    release = resolve;
  });
  let sends = 0;
  const c = collector(async (command) => {
    sends++;
    if (sends === 1) await barrier;
    return projectOutput(command.fact, outputs[COMMANDS.indexOf(command)]);
  });
  const consent = auth();
  const pending = c.collect(consent);
  consent.binding.subject = hex(99);
  consent.expiresAt = iso(-1);
  assert.deepEqual(await c.collect(auth()), denied);
  const fresh = auth();
  fresh.binding.consentId = hex(20);
  fresh.binding.nonce = hex(21);
  assert.equal((await c.collect(fresh)).reason, 'busy');
  release();
  const result = await pending;
  assert.equal(result.evidence.binding.subject, hex(1));
  assert.deepEqual(await c.collect(auth()), denied);
  assert.equal(sends, 5);
  assert.equal((await c.collect(fresh)).host, 'captured');
  assert.equal(sends, 10);
});

test('abort, consent expiration and clock rollback fence publication and further dispatch', async () => {
  const abort = new AbortController();
  let sends = 0;
  const c = collector(async (command) => {
    sends++;
    abort.abort();
    return projectOutput(command.fact, outputs[0]);
  });
  assert.deepEqual(await c.collect(auth(), { signal: abort.signal }), denied);
  assert.equal(sends, 1);
  let clock = NOW;
  const expires = new HostCollector({
    platform: 'darwin',
    now: () => clock,
    runner: async () => {
      clock = NOW + 299000;
      return { status: 'unavailable', reason: 'timeout' };
    },
  });
  assert.deepEqual(await expires.collect(auth()), denied);
  clock = NOW;
  const rollback = new HostCollector({
    platform: 'darwin',
    now: () => clock,
    runner: async () => {
      clock = NOW - 1;
      return { status: 'unavailable', reason: 'timeout' };
    },
  });
  assert.deepEqual(await rollback.collect(auth()), denied);
});

test('total wall interval >5s never publishes', async () => {
  let clock = NOW;
  const c = new HostCollector({
    platform: 'darwin',
    now: () => clock,
    runner: async () => {
      clock += 5001;
      return { status: 'unavailable', reason: 'timeout' };
    },
  });
  assert.equal((await c.collect(auth())).reason, 'budget_exhausted');
});

test('monotonic >5s fences dispatch even when the wall clock does not advance', async () => {
  let elapsed = 0,
    sends = 0;
  const c = new HostCollector({
    platform: 'darwin',
    now: () => NOW,
    monotonic: () => elapsed,
    runner: async () => {
      sends++;
      elapsed += 5001;
      return { status: 'unavailable', reason: 'timeout' };
    },
  });
  assert.equal((await c.collect(auth())).reason, 'budget_exhausted');
  assert.equal(sends, 1);
});

test('exact1024 combined subprocess bytes accepted,1025 killed; all bytes remain synthetic', async () => {
  let killed;
  const run = createCommandRunner(
    fakeSpawn((child) => {
      child.stdout.emit('data', Buffer.from(outputs[0]));
      child.stderr.emit('data', Buffer.alloc(1024 - Buffer.byteLength(outputs[0])));
      child.emit('close', 0);
    }),
  );
  assert.equal((await run(COMMANDS[0], { timeoutMs: 750 })).status, 'observed');
  const excessive = createCommandRunner(
    fakeSpawn((child) => {
      const kill = child.kill;
      child.kill = (signal) => {
        killed = signal;
        return kill(signal);
      };
      child.stderr.emit('data', Buffer.alloc(1025));
    }),
  );
  assert.equal((await excessive(COMMANDS[0], { timeoutMs: 750 })).reason, 'output_limit');
  assert.equal(killed, 'SIGKILL');
});

test('real runner with fake subprocess uses fixed argv, shell false, ignored stdin, no inherited environment', async () => {
  const received = [];
  const run = createCommandRunner(
    fakeSpawn((child) => {
      child.stdout.emit('data', Buffer.from(outputs[0]));
      child.emit('close', 0);
    }, received),
  );
  assert.deepEqual(await run(COMMANDS[0], { timeoutMs: 750 }), { status: 'observed', value: '15.0.1' });
  assert.deepEqual(received, [
    [
      COMMANDS[0].file,
      COMMANDS[0].args,
      {
        shell: false,
        env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LC_ALL: 'C', LANG: 'C' },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    ],
  ]);
  assert.equal((await run({ ...COMMANDS[0] }, { timeoutMs: 750 })).status, 'unavailable');
  assert.equal(received.length, 1);
  assert.ok(Object.isFrozen(COMMANDS[0].args));
});

test('fake subprocess stdout+stderr 1024 cap, timeout, abort, failed exit and invalid UTF8 are sanitized', async () => {
  for (const [effect, reason] of [
    [
      (child) => {
        child.stdout.emit('data', Buffer.alloc(1000));
        child.stderr.emit('data', Buffer.alloc(25));
      },
      'output_limit',
    ],
    [() => {}, 'timeout'],
    [
      (child) => {
        child.stderr.emit('data', Buffer.from('PRIVATE'));
        child.emit('close', 1);
      },
      'command_failed',
    ],
    [
      (child) => {
        child.stdout.emit('data', Buffer.from([0xff]));
        child.emit('close', 0);
      },
      'invalid_output',
    ],
  ]) {
    assert.deepEqual(await createCommandRunner(fakeSpawn(effect))(COMMANDS[0], { timeoutMs: 5 }), {
      status: 'unavailable',
      reason,
    });
  }
  const abort = new AbortController();
  const run = createCommandRunner(fakeSpawn(() => abort.abort()));
  assert.equal((await run(COMMANDS[0], { timeoutMs: 750, signal: abort.signal })).reason, 'command_failed');
});

test('signed intake produces bounded historical artifact, never live or complete source proof', () => {
  const intake = new HostIntake(enrollment());
  const artifact = intake.accept(signed(), auth(), NOW);
  assert.equal(artifact.host, 'historical_import');
  assert.equal(artifact.verification, 'enrolled_ed25519_signature');
  assert.equal(artifact.liveQualified, false);
  assert.equal(artifact.engineQueried, false);
  assert.deepEqual(artifact.exclusions, EXCLUSIONS);
  assert.ok(Buffer.byteLength(canonical(artifact)) < 8192);
  artifact.evidence.facts.logicalCpuCount.value = 16;
  invalid(() => intake.accept(signed(), auth(), NOW));
});

test('intake default denies BEFORE parsing even malformed package and creates no Engine capability', () => {
  const intake = new HostIntake(enrollment());
  assert.deepEqual(intake.accept(Buffer.from('not JSON')), denied);
  assert.deepEqual(intake.accept(Buffer.from('not JSON'), { ...auth(), reviewed: false }, NOW), denied);
});

test('enrollment rejects missing trust, bad fingerprint, wrong key type and extra private metadata', () => {
  invalid(() => new HostIntake({}));
  invalid(() => new HostIntake({ ...enrollment(), fingerprint: '0'.repeat(64) }));
  invalid(() => new HostIntake({ ...enrollment(), privateKey: 'DO_NOT_READ' }));
  const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  invalid(
    () =>
      new HostIntake({
        ...enrollment(),
        publicKeyDer: ec.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
        fingerprint: publicFingerprint(ec.publicKey),
      }),
  );
});

test('hash is not signature; wrong signer/key, modified facts and signatures reject without consuming nonce', () => {
  const intake = new HostIntake(enrollment());
  const original = JSON.parse(signed().toString());
  for (const change of [
    (e) => {
      e.signature = 'A'.repeat(86);
    },
    (e) => {
      e.hash = '0'.repeat(64);
    },
    (e) => {
      e.signerId = hex(66);
    },
    (e) => {
      e.payload.facts.logicalCpuCount.value = 16;
    },
  ]) {
    const copy = structuredClone(original);
    change(copy);
    invalid(() => intake.accept(Buffer.from(canonical(copy)), auth(), NOW));
  }
  invalid(() => intake.accept(signed(evidence(), generateKeyPairSync('ed25519').privateKey), auth(), NOW));
  assert.equal(intake.accept(signed(), auth(), NOW).host, 'historical_import');
});

test('exact subject/target/version/consent/nonce binding; cross-target/owner/source denied', () => {
  for (const field of ['subject', 'targetId', 'targetVersion', 'consentId', 'nonce']) {
    const consent = auth();
    consent.binding[field] = field === 'targetVersion' ? 2 : hex(99);
    invalid(() => new HostIntake(enrollment()).accept(signed(), consent, NOW));
  }
  invalid(() => new HostIntake({ ...enrollment(), subject: hex(99) }).accept(signed(), auth(), NOW));
  for (const [field, value] of [
    ['platform', 'docker-desktop-linux-vm'],
    ['sourceVersion', 'operator-runtime-v1'],
    ['scope', 'whole-host'],
  ]) {
    const e = evidence();
    e[field] = value;
    invalid(() => signed(e));
  }
});

test('closed evidence forbids Dockerfile history, environment, paths, scanners and fabricated status', () => {
  for (const field of ['environment', 'history', 'dockerfile', 'raw', 'scanner', 'signatureVerified']) {
    const e = evidence();
    e[field] = 'PRIVATE';
    invalid(() => signed(e));
  }
  const e = evidence();
  e.facts.productVersion = { status: 'checked', value: '15.0.1' };
  invalid(() => signed(e));
  const newline = evidence();
  newline.binding.subject += '\n';
  invalid(() => signed(newline));
});

test('canonical-only raw intake denies duplicate/escaped/prototype keys, numeric lexemes, whitespace and UTF8 BOM', () => {
  const wire = signed().toString();
  for (const mutated of [
    wire.replace('"targetVersion":1', '"targetVersion":1,"targetVersion":1'),
    wire.replace('"targetVersion":1', '"targetVersion":1e0'),
    wire.replace('"targetVersion":1', '"targetVersion":1.0'),
    wire.replace('"targetVersion":1', '"targetVersion":-0'),
    wire.replace('"targetVersion":1', '"targetVersion":9007199254740993'),
    wire.replace('"targetVersion":1', '"targetVersion":1,"__proto__":{}'),
    wire.replace('"subject"', '"\\u0073ubject"'),
    ` ${wire}`,
    `${wire}\n`,
  ])
    invalid(() => parseEnvelope(Buffer.from(mutated)));
  invalid(() => parseEnvelope(Buffer.from([0xff])));
  invalid(() => parseEnvelope(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(wire)])));
  invalid(() => parseEnvelope(Buffer.alloc(8193)));
  invalid(() => parseEnvelope(Buffer.from('{"payload":' + '['.repeat(1000) + '0' + ']'.repeat(1000) + '}')));
});

test('freshness, future skew, consent interval and 5s capture duration fences', () => {
  for (const [start, end] of [
    [-2000, -100],
    [-500, 30001],
    [-500, -501],
    [-1000, 5001],
  ]) {
    const e = evidence();
    e.startedAt = iso(start);
    e.endedAt = iso(end);
    invalid(() => new HostIntake(enrollment()).accept(signed(e), auth(), NOW));
  }
  const old = evidence();
  old.startedAt = iso(-300501);
  old.endedAt = iso(-300001);
  invalid(() => new HostIntake(enrollment()).accept(signed(old), auth(), NOW));
  assert.deepEqual(
    new HostIntake(enrollment()).accept(signed(), { ...auth(), expiresAt: iso(0) }, NOW),
    denied,
  );
});

test('nonce AND consent consumed only on successful import; fixed128 report capacity no silent pruning', () => {
  const intake = new HostIntake(enrollment());
  for (let i = 0; i < 128; i++) {
    const consent = auth();
    consent.binding.nonce = hex(1000 + i);
    consent.binding.consentId = hex(2000 + i);
    const e = evidence();
    e.binding = consent.binding;
    assert.equal(intake.accept(signed(e), consent, NOW).host, 'historical_import');
  }
  const consent = auth();
  consent.binding.nonce = hex(9998);
  consent.binding.consentId = hex(9999);
  const e = evidence();
  e.binding = consent.binding;
  invalid(() => intake.accept(signed(e), consent, NOW));
  // These are process-local guards, NOT crash recovery or production idempotent history.
  assert.equal(new HostIntake(enrollment()).accept(signed(e), consent, NOW).host, 'historical_import');
});

test('consumed nonce cannot be reused with changed consent, or consent with a different nonce', () => {
  const intake = new HostIntake(enrollment());
  intake.accept(signed(), auth(), NOW);
  for (const field of ['nonce', 'consentId']) {
    const consent = auth();
    consent.binding[field] = hex(999);
    const e = evidence();
    e.binding = consent.binding;
    invalid(() => intake.accept(signed(e), consent, NOW));
  }
});

test('CLI plan/default/rejected flags are pure and never auto-collect or read private keys', async () => {
  const trap = { collect: () => assert.fail('no collector execution') };
  assert.deepEqual(await main([], trap, NOW), denied);
  const plan = await main(['--plan'], trap, NOW);
  assert.equal(plan.sourceQualification, 'not_established');
  assert.deepEqual(plan.commands, COMMANDS);
  for (const args of [
    ['--capture'],
    ['--capture', '--host-opt-in'],
    ['--private-key', 'forbidden'],
    ['--engine'],
  ]) {
    assert.deepEqual(await main(args, trap, NOW), denied);
  }
});

test('explicit CLI capture proposal hands only independently supplied closed host consent to a synthetic collector', async () => {
  let observed;
  const args = [
    '--capture',
    '--host-opt-in',
    '--single-invocation',
    '--parent-reviewed-supervisor',
    SUPERVISOR_ID,
    '--parent-reviewed-plan',
    PLAN_ID,
    '--subject',
    hex(1),
    '--target',
    hex(2),
    '--version',
    '1',
    '--consent',
    hex(3),
    '--nonce',
    hex(4),
    '--issued-at',
    iso(-1000),
    '--expires-at',
    iso(299000),
  ];
  assert.deepEqual(
    await main(
      args,
      {
        collect: (consent) => {
          observed = consent;
          return denied;
        },
      },
      NOW,
    ),
    denied,
  );
  assert.deepEqual(observed, auth());
});
