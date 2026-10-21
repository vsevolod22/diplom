import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { llmBridgeFixture } from './public-cve-bridge-llm-fixtures.mjs';
import { publicImageStand, PROJECT } from './public-image-stand.mjs';
import { publicLlmComposeArguments } from './public-llm-stand.mjs';
import { publicCveFailure } from './refresh-public-cve.mjs';
for (const supplied of [false, true])
  test(`CVE default bridge preserves seven-service LLM ${supplied ? 'key-mounted' : 'key-absent'} descriptor and FOUR native stores`, async (t) => {
    const f = llmBridgeFixture(t, supplied),
      metadata = ['llm-profile.json', 'compose.llm-env.json', 'compose.images.json'].map((n) => [
        n,
        fs.readFileSync(join(f.stand, n)),
        fs.statSync(join(f.stand, n)).ino,
      ]);
    const gateway = f.containers.find((c) => c.Name === `/${PROJECT}-llm-egress-1`),
      web = f.containers.find((c) => c.Name === `/${PROJECT}-web-1`);
    assert.equal(
      (await f.refresh([], { integration: undefined, docker: f.llmDocker, run: f.llmRun })).outcome,
      'activated',
    );
    for (const [n, b, ino] of metadata) {
      assert.deepEqual(fs.readFileSync(join(f.stand, n)), b);
      assert.equal(fs.statSync(join(f.stand, n)).ino, ino);
    }
    assert.equal(f.containers.find((c) => c.Id === gateway.Id).State.StartedAt, gateway.State.StartedAt);
    assert(f.containers.some((c) => c.Id === web.Id && c.State.Running));
    const audit = join(f.stand, 'llm-deployments', fs.readdirSync(join(f.stand, 'llm-deployments'))[0]);
    for (const phase of ['fenced', 'before-api', 'after-api'])
      for (const group of ['core', 'llm'])
        for (const role of ['auth', 'ledger'])
          assert(fs.statSync(join(audit, phase, group, role + '.sqlite')).size > 0);
    for (const call of f.calls.filter((c) => c.kind === 'docker' && c.args[0] === 'compose')) {
      const prospective = call.args.includes(join(f.stand, '.operation.lock/candidate.cve.json'));
      const expected = publicLlmComposeArguments(f.root, [], {
        cve: true,
        llm: true,
        pinned: true,
        prospectiveCve: prospective,
      });
      assert.deepEqual(call.args.slice(0, expected.length), expected);
    }
    const helperCreates = f.calls.filter((c) => c.args[0] === 'create');
    assert.equal(helperCreates.length, 3);
    for (const c of helperCreates)
      assert(
        !c.args.some(
          (a) => a.includes('/run/secrets') || a.startsWith('OPENROUTER_') || a.includes('public_llm_key'),
        ),
      );
  });
for (const fault of ['history-drift', 'quota-drift'])
  test(`four-store ${fault} keeps web fenced and shared HOLD`, async (t) => {
    const f = llmBridgeFixture(t);
    f.fault = fault;
    await assert.rejects(
      f.refresh([], { integration: undefined, docker: f.llmDocker, run: f.llmRun }),
      (e) => {
        assert(publicCveFailure(e).hold);
        return true;
      },
    );
    assert.equal(f.containers.find((c) => c.Name === `/${PROJECT}-web-1`).State.Running, false);
    assert(fs.existsSync(join(f.stand, '.operation.lock/mutation.json')));
  });
test('main ordinary up dispatches persisted LLM binding to publicLlmStand, never six-service Compose', async (t) => {
  const f = llmBridgeFixture(t);
  let calls = 0;
  const result = await publicImageStand(['up', '--build'], {
    root: f.root,
    run: () => assert.fail('six-service lifecycle must not run'),
    llmStand: async (args, options) => {
      calls++;
      assert.deepEqual(args, ['up', '--build', '--ack-public-maintenance']);
      assert.equal(options.root, f.root);
      return { outcome: 'delegated' };
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.outcome, 'delegated');
});
test('main status and stop validate the seven-service fixed descriptor and never read a key', async (t) => {
  const f = llmBridgeFixture(t, true),
    logs = [];
  const run = async (args, options) => {
    if (args[0] === 'container' && args[1] === 'stop' && args.length > 6) {
      for (const c of f.containers.filter((c) => args.includes(c.Id))) {
        c.State.Running = false;
        c.State.Status = 'exited';
      }
      f.attachments();
      return '';
    }
    return f.llmDocker(args, { ...options, timeout: options.timeout ?? 30000 });
  };
  assert.equal(
    (await publicImageStand(['status'], { root: f.root, run, log: (s) => logs.push(s) })).containers.length,
    7,
  );
  assert(logs.some((s) => s.includes('7 services, 6 networks')));
  assert.equal(
    (await publicImageStand(['stop'], { root: f.root, run, log: (s) => logs.push(s) })).containers.length,
    7,
  );
  assert(f.containers.every((c) => !c.State.Running));
  assert(!fs.existsSync(join(f.stand, '.operation.lock')));
});
for (const name of ['llm-profile.json', 'compose.llm-env.json', 'compose.images.json', 'source-overlay'])
  test(`persisted LLM ${name} inode drift during config refuses before admission fence`, async (t) => {
    const f = llmBridgeFixture(t);
    let changed = false;
    f.beforeDocker = (args) => {
      if (changed || args[0] !== 'compose' || !args.includes('config')) return;
      changed = true;
      const path =
        name === 'source-overlay'
          ? join(f.root, 'server/deploy/compose.public-llm.yaml')
          : join(f.stand, name);
      fs.copyFileSync(path, path + '.next');
      fs.chmodSync(path + '.next', fs.statSync(path).mode & 0o777);
      fs.renameSync(path + '.next', path);
    };
    await assert.rejects(f.refresh([], { integration: undefined, docker: f.llmDocker, run: f.llmRun }));
    assert(changed);
    assert(!f.calls.some((c) => c.kind === 'docker' && (c.args[1] === 'stop' || c.args.includes('up'))));
    assert(!fs.existsSync(join(f.stand, '.operation.lock')));
  });
