import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { CaptureAuthority } from '../src/capture-authority.mjs';
import {
  COMMANDS,
  CLEANUP_GRACE_MS,
  HostCollector,
  createCommandRunner,
  projectOutput,
} from '../src/collector.mjs';
import { PLAN_ID } from '../src/contract.mjs';
import { main, runCli } from '../src/cli.mjs';
import { INVOCATION_MS, SHUTDOWN_MS, SUPERVISOR_ID, supervise } from '../src/supervisor.mjs';

// Synthetic source/authority/process fixtures only. No real spawn, signal, PID, environment or host I/O.
const NOW = Date.parse('2026-10-09T10:00:00.000Z');
const hex = (n) => n.toString(16).padStart(32, '0');
const iso = (n) => new Date(NOW + n).toISOString();
const auth = (n = 1) => ({
  confirmed: true,
  reviewed: true,
  planId: PLAN_ID,
  issuedAt: iso(-1000),
  expiresAt: iso(299000),
  binding: {
    subject: hex(1),
    targetId: hex(2),
    targetVersion: 1,
    consentId: hex(n + 1000),
    nonce: hex(n + 2000),
  },
});
const outputs = ['15.0.1\n', '24.0.0\n', 'arm64\n', '17179869184\n', '8\n'];
const fact = (c) => projectOutput(c.fact, outputs[COMMANDS.indexOf(c)]);
const denied = { host: 'not_authorized', engineQueried: false };
const blocked = { host: 'blocked', reason: 'cleanup_unconfirmed', engineQueried: false };
const runnerBlocked = { status: 'blocked', reason: 'cleanup_unconfirmed' };
const make = (runner, authority = new CaptureAuthority()) =>
  new HostCollector({ runner, authority, platform: 'darwin', now: () => NOW });
const flush = async () => {
  for (let i = 0; i < 20; i++) await Promise.resolve();
};

class Timers {
  now = 0;
  #next = 0;
  #pending = new Map();
  setTimeout = (fn, delay) => {
    const id = ++this.#next;
    this.#pending.set(id, { fn, at: this.now + delay });
    return id;
  };
  clearTimeout = (id) => {
    this.#pending.delete(id);
  };
  advance(ms) {
    const end = this.now + ms;
    for (;;) {
      const due = [...this.#pending].filter(([, v]) => v.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
      if (!due) break;
      this.now = due[1].at;
      this.#pending.delete(due[0]);
      due[1].fn();
    }
    this.now = end;
  }
  get pending() {
    return this.#pending.size;
  }
}
function fakeChild(kill = () => true) {
  const c = new EventEmitter();
  c.stdout = new EventEmitter();
  c.stderr = new EventEmitter();
  c.destroyed = 0;
  c.unreferenced = 0;
  c.kills = [];
  c.stdout.destroy = c.stderr.destroy = () => {
    c.destroyed++;
  };
  c.unref = () => {
    c.unreferenced++;
  };
  c.kill = (signal) => {
    c.kills.push(signal);
    return kill();
  };
  return c;
}
function fakeProcess() {
  const p = new EventEmitter();
  p.writes = [];
  p.stdout = {
    write: (value) => {
      p.writes.push(value);
    },
  };
  return p;
}
function args(consent = auth()) {
  return [
    '--capture',
    '--host-opt-in',
    '--single-invocation',
    '--parent-reviewed-supervisor',
    SUPERVISOR_ID,
    '--parent-reviewed-plan',
    PLAN_ID,
    '--subject',
    consent.binding.subject,
    '--target',
    consent.binding.targetId,
    '--version',
    String(consent.binding.targetVersion),
    '--consent',
    consent.binding.consentId,
    '--nonce',
    consent.binding.nonce,
    '--issued-at',
    consent.issuedAt,
    '--expires-at',
    consent.expiresAt,
  ];
}

test('R1 consumes both identifiers synchronously BEFORE first synthetic observation; repeat denies', async () => {
  const authority = new CaptureAuthority();
  let sends = 0;
  const c = make((command) => {
    assert.equal(authority.used(auth().binding), true);
    sends++;
    return fact(command);
  }, authority);
  assert.equal((await c.collect(auth())).host, 'captured');
  assert.deepEqual(await c.collect(auth()), denied);
  for (const field of ['nonce', 'consentId', 'subject', 'targetId', 'targetVersion']) {
    const changed = auth();
    changed.binding[field] = field === 'targetVersion' ? 2 : hex(9999);
    assert.deepEqual(await c.collect(changed), denied);
  }
  assert.equal(sends, 5);
});

test('R1 concurrent repeat denies; busy distinct consent is NOT consumed and remains admissible', async () => {
  const authority = new CaptureAuthority();
  let release,
    sends = 0;
  const barrier = new Promise((resolve) => {
    release = resolve;
  });
  const c = make(async (command) => {
    sends++;
    if (sends === 1) await barrier;
    return fact(command);
  }, authority);
  const first = c.collect(auth());
  assert.deepEqual(await c.collect(auth()), denied);
  assert.deepEqual(
    await make(() => assert.fail('cross-instance repeated observation'), authority).collect(auth()),
    denied,
  );
  assert.equal((await c.collect(auth(2))).reason, 'busy');
  assert.equal(authority.used(auth(2).binding), false);
  release();
  assert.equal((await first).host, 'captured');
  assert.equal((await c.collect(auth(2))).host, 'captured');
  assert.equal(sends, 10);
});

test('R1 partial revoked attempt stays consumed, denies repetition with zero additional observations', async () => {
  const controller = new AbortController();
  let sends = 0;
  const c = make((command) => {
    sends++;
    controller.abort();
    return fact(command);
  });
  assert.deepEqual(await c.collect(auth(), { signal: controller.signal }), denied);
  assert.deepEqual(await c.collect(auth()), denied);
  assert.equal(sends, 1);
});

test('R1 failed/unavailable attempt stays consumed; initial aborted non-admission does not consume', async () => {
  let sends = 0;
  const authority = new CaptureAuthority();
  const c = make(() => {
    sends++;
    return { status: 'unavailable', reason: 'command_failed' };
  }, authority);
  const abort = new AbortController();
  abort.abort();
  assert.deepEqual(await c.collect(auth(), { signal: abort.signal }), denied);
  assert.equal(authority.used(auth().binding), false);
  assert.equal((await c.collect(auth())).host, 'captured');
  assert.deepEqual(await c.collect(auth()), denied);
  assert.equal(sends, 5);
});

test('R1 default module authority is shared across reconstructed collectors, not just per instance', async () => {
  let sends = 0;
  const runner = (command) => {
    sends++;
    return fact(command);
  };
  const options = { runner, platform: 'darwin', now: () => NOW };
  assert.equal((await new HostCollector(options).collect(auth(500))).host, 'captured');
  assert.deepEqual(await new HostCollector(options).collect(auth(500)), denied);
  assert.equal(sends, 5);
});

test('R1 capacity128 no pruning; fresh authority illustrates reset/new-process boundary, NOT durability', async () => {
  const authority = new CaptureAuthority();
  const c = make(fact, authority);
  for (let i = 1; i <= 128; i++) assert.equal((await c.collect(auth(i))).host, 'captured');
  assert.deepEqual(await c.collect(auth(129)), denied);
  assert.deepEqual(await c.collect(auth(1)), denied);
  assert.equal((await make(fact, new CaptureAuthority()).collect(auth(1))).host, 'captured');
});

test('R2 false/throw/true kill with NO close resolves at finite deadline, latches blocked and detaches owned handles', async () => {
  for (const kill of [
    () => false,
    () => {
      throw new Error('PRIVATE_DIAGNOSTIC');
    },
    () => true,
  ]) {
    const timers = new Timers(),
      child = fakeChild(kill);
    let spawns = 0,
      settled = false;
    const run = createCommandRunner(() => {
      spawns++;
      return child;
    }, timers);
    const pending = run(COMMANDS[0], { timeoutMs: 5 }).then((value) => {
      settled = true;
      return value;
    });
    timers.advance(5);
    await flush();
    assert.equal(settled, false);
    assert.deepEqual(child.kills, ['SIGKILL']);
    timers.advance(CLEANUP_GRACE_MS - 1);
    await flush();
    assert.equal(settled, false);
    timers.advance(1);
    await flush();
    assert.equal(settled, true);
    assert.deepEqual(await pending, runnerBlocked);
    assert.equal(child.destroyed, 2);
    assert.equal(child.unreferenced, 1);
    assert.equal(child.stdout.listenerCount('data'), 0);
    assert.equal(child.stderr.listenerCount('data'), 0);
    assert.equal(timers.pending, 0);
    child.emit('error', new Error('LATE_PRIVATE'));
    child.stdout.emit('error', new Error('LATE_STREAM_PRIVATE'));
    child.emit('close', 0);
    assert.deepEqual(await run(COMMANDS[1], { timeoutMs: 5 }), runnerBlocked);
    assert.equal(spawns, 1); // Late close cannot silently re-enable observation.
  }
});

test('R2 delayed known close holds active slot through cleanup then finite unavailable, no overlapping child', async () => {
  const timers = new Timers(),
    child = fakeChild();
  let spawns = 0;
  const run = createCommandRunner(() => {
    spawns++;
    return child;
  }, timers);
  const pending = run(COMMANDS[0], { timeoutMs: 5 });
  timers.advance(5);
  assert.deepEqual(await run(COMMANDS[1], { timeoutMs: 5 }), runnerBlocked);
  assert.equal(spawns, 1);
  timers.advance(CLEANUP_GRACE_MS - 1);
  child.emit('close', null);
  assert.deepEqual(await pending, { status: 'unavailable', reason: 'timeout' });
  assert.equal(timers.pending, 0);
});

test('R2 output limit and child error start the same finite close budget; raw errors never escape', async () => {
  for (const effect of [
    (c) => c.stdout.emit('data', Buffer.alloc(1025)),
    (c) => c.emit('error', new Error('PRIVATE_RAW')),
    (c) => c.stderr.emit('error', new Error('PRIVATE_STREAM')),
  ]) {
    const timers = new Timers(),
      child = fakeChild();
    const run = createCommandRunner(() => child, timers);
    const pending = run(COMMANDS[0], { timeoutMs: 750 });
    effect(child);
    timers.advance(CLEANUP_GRACE_MS);
    assert.deepEqual(await pending, runnerBlocked);
    assert.deepEqual(child.kills, ['SIGKILL']);
    assert.equal(timers.pending, 0);
  }
});

test('R2 unknown cleanup aborts whole capture, sticky blocked for fresh consent, no next command/no evidence', async () => {
  const timers = new Timers(),
    child = fakeChild(() => false);
  let spawns = 0;
  const run = createCommandRunner(() => {
    spawns++;
    return child;
  }, timers);
  const c = make(run);
  const pending = c.collect(auth());
  timers.advance(750 + CLEANUP_GRACE_MS);
  assert.deepEqual(await pending, blocked);
  assert.deepEqual(await c.collect(auth()), denied);
  assert.deepEqual(await c.collect(auth(2)), blocked);
  assert.equal(spawns, 1);
});

test('R2 unexpected runner throw cannot certify cleanup or continue capture', async () => {
  let sends = 0;
  const c = make(() => {
    sends++;
    throw new Error('PRIVATE_UNEXPECTED');
  });
  assert.deepEqual(await c.collect(auth()), blocked);
  assert.deepEqual(await c.collect(auth()), denied);
  assert.deepEqual(await c.collect(auth(2)), blocked);
  assert.equal(sends, 1);
});

test('R2 CLI main requires single invocation/supervisor-review assertion and forwards the supplied AbortSignal', async () => {
  const trap = { collect: () => assert.fail('no observation') };
  assert.deepEqual(
    await main(
      args().filter((a) => a !== '--single-invocation'),
      trap,
      NOW,
    ),
    denied,
  );
  const unreviewed = args();
  unreviewed[4] = 'no-reviewed-leaf-supervisor';
  assert.deepEqual(await main(unreviewed, trap, NOW), {
    host: 'blocked',
    reason: 'supervisor_review_required',
    engineQueried: false,
  });
  const abort = new AbortController();
  let options;
  await main(
    args(),
    {
      collect: (_consent, supplied) => {
        options = supplied;
        return denied;
      },
    },
    NOW,
    { signal: abort.signal },
  );
  assert.equal(options.signal, abort.signal);
});

test('R2 runnable CLI SIGINT/SIGTERM relay abort, kill tracked fake child, refuse next dispatch/publication, remove handlers', async () => {
  for (const [signal, exitCode] of [
    ['SIGINT', 130],
    ['SIGTERM', 143],
  ]) {
    const timers = new Timers(),
      p = fakeProcess(),
      child = fakeChild();
    let spawns = 0;
    const c = make(
      createCommandRunner(() => {
        spawns++;
        return child;
      }, timers),
    );
    const pending = runCli(args(), { processLike: p, collector: c, now: NOW, timers });
    await flush();
    assert.equal(spawns, 1);
    p.emit(signal);
    assert.deepEqual(child.kills, ['SIGKILL']);
    child.emit('close', null);
    await flush();
    assert.deepEqual(await pending, { result: denied, exitCode });
    assert.equal(p.exitCode, exitCode);
    assert.equal(p.writes.length, 1);
    assert.deepEqual(JSON.parse(p.writes[0]), denied);
    assert.equal(spawns, 1);
    assert.equal(p.listenerCount('SIGINT'), 0);
    assert.equal(p.listenerCount('SIGTERM'), 0);
    assert.equal(timers.pending, 0);
    assert.deepEqual(await c.collect(auth()), denied);
  }
});

test('R2 failed child kill through CLI yields blocked exit1, finite result and no evidence', async () => {
  const timers = new Timers(),
    p = fakeProcess(),
    child = fakeChild(() => false);
  const c = make(createCommandRunner(() => child, timers));
  const pending = runCli(args(), { processLike: p, collector: c, now: NOW, timers });
  await flush();
  p.emit('SIGTERM');
  timers.advance(CLEANUP_GRACE_MS);
  await flush();
  assert.deepEqual(await pending, { result: blocked, exitCode: 1 });
  assert.equal(p.writes.length, 1);
  assert.equal(timers.pending, 0);
});

test('R2 supervisor stops uncooperative work finitely, suppresses late capture publication and repeat signal effects', async () => {
  const timers = new Timers(),
    p = fakeProcess();
  let release,
    observedSignal,
    aborts = 0,
    settled = false;
  const work = (signal) => {
    observedSignal = signal;
    signal.addEventListener('abort', () => aborts++);
    return new Promise((resolve) => {
      release = resolve;
    });
  };
  const pending = supervise(work, { processLike: p, timers }).then((value) => {
    settled = true;
    return value;
  });
  await flush();
  p.emit('SIGINT');
  p.emit('SIGTERM');
  assert.equal(observedSignal.aborted, true);
  timers.advance(SHUTDOWN_MS - 1);
  await flush();
  assert.equal(settled, false);
  timers.advance(1);
  await flush();
  assert.deepEqual(await pending, { result: blocked, exitCode: 1 });
  assert.equal(aborts, 1);
  assert.equal(timers.pending, 0);
  release({ host: 'captured', evidence: 'MUST_NOT_PUBLISH' });
  await flush();
  assert.equal(p.listenerCount('SIGINT'), 0);
  assert.equal(p.listenerCount('SIGTERM'), 0);
});

test('R2 invocation stall aborts at5500ms, hard-finite blocked resolution by5650ms, no OS-timing claim', async () => {
  const timers = new Timers(),
    p = fakeProcess();
  let signal,
    settled = false;
  const pending = supervise(
    (s) => {
      signal = s;
      return new Promise(() => {});
    },
    { processLike: p, timers },
  ).then((value) => {
    settled = true;
    return value;
  });
  await flush();
  timers.advance(INVOCATION_MS - 1);
  assert.equal(signal.aborted, false);
  timers.advance(1);
  assert.equal(signal.aborted, true);
  assert.equal(settled, false);
  timers.advance(SHUTDOWN_MS);
  await flush();
  assert.deepEqual(await pending, { result: blocked, exitCode: 1 });
  assert.equal(timers.pending, 0);
});

test('R2 pure plan declares unestablished process-tree boundary, no review/global-signal side effects after completion', async () => {
  const timers = new Timers(),
    p = fakeProcess(),
    trap = { collect: () => assert.fail('no observation') };
  const outcome = await runCli(['--plan'], { processLike: p, collector: trap, now: NOW, timers });
  assert.equal(outcome.result.supervisorId, SUPERVISOR_ID);
  assert.match(outcome.result.processTreeQualification, /not_established/);
  assert.match(outcome.result.actualCapture, /blocked_pending/);
  assert.equal(p.listenerCount('SIGINT'), 0);
  assert.equal(p.listenerCount('SIGTERM'), 0);
  assert.equal(timers.pending, 0);
});
