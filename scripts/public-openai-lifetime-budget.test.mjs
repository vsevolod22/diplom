import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { lifetimeBudgetFixture } from './public-openai-lifetime-budget.mjs';
import { validateOpenAiDeployment } from './public-openai-descriptor.mjs';

const FIELD = 'LLM_QUOTA_LIFETIME_USER_COST_MICROS';
const BACKUP = '.lifetime-budget.original';
const PENDING = '.lifetime-budget.pending';
const helper = fileURLToPath(new URL('./public-openai-lifetime-budget.py', import.meta.url));
const cli = fileURLToPath(new URL('./public-openai-lifetime-budget.mjs', import.meta.url));
const json = value => JSON.stringify(value, null, 2) + '\n';
function descriptor(mode = 'uncapped') {
  const environment = {
    LLM_PROVIDER: 'openai', OPENAI_ENABLED: 'true', OPENAI_MODEL: 'gpt-5.4-mini-2026-03-17',
    OPENAI_ROUTING_APPROVED: 'true', OPENAI_RETENTION: 'no-training', OPENAI_POLICY_REVISION: 'v1',
    OPENAI_ACCOUNTING_REVISION: 'v1', LLM_QUOTA_REVISION: 'v1', OPENAI_MONETARY_LIMIT: mode,
    LLM_QUOTA_MONETARY_LIMIT: mode, LLM_QUOTA_ENABLED: 'true', LLM_QUOTA_WINDOW: 'utc-day',
  };
  const numbers = {
    OPENAI_INPUT_PRICE_MICROS_PER_MILLION: 750000, OPENAI_OUTPUT_PRICE_MICROS_PER_MILLION: 4500000,
    OPENAI_TIMEOUT_MS: 90000, OPENAI_REQUEST_BYTES: 262144, OPENAI_RESPONSE_BYTES: 65536,
    OPENAI_INPUT_TOKENS: 65536, OPENAI_OUTPUT_TOKENS: 4096, OPENAI_FINDINGS: 1000, OPENAI_MAX_CONCURRENT: 8,
    LLM_QUOTA_USER_INPUT: 1048576, LLM_QUOTA_USER_OUTPUT: 131072, LLM_QUOTA_SCAN_INPUT: 262144,
    LLM_QUOTA_SCAN_OUTPUT: 16384, LLM_QUOTA_WARNING_PERCENT: 80, LLM_QUOTA_REQUEST_INPUT: 65536,
    LLM_QUOTA_OBSERVATION_TOKENS: 1048576, LLM_QUOTA_OBSERVATION_COST_MICROS: 1000000,
    LLM_QUOTA_RECEIPT_MS: 300000, LLM_QUOTA_REPLAY_DAYS: 7, LLM_QUOTA_MAX_ROWS: 100000,
    LLM_QUOTA_DB_BYTES: 67108864, LLM_QUOTA_DISK_HEADROOM_BYTES: 134217728,
    LLM_QUOTA_BUSY_MS: 1000, LLM_QUOTA_CLEANUP_BATCH: 256,
  };
  for (const [key, value] of Object.entries(numbers)) environment[key] = String(value);
  if (mode === 'capped') Object.assign(environment, { OPENAI_REQUEST_BUDGET_MICROS: '100000',
    OPENAI_USER_BUDGET_MICROS: '500000', OPENAI_SCAN_BUDGET_MICROS: '500000',
    LLM_QUOTA_USER_COST_USD: '0.5', LLM_QUOTA_SCAN_COST_USD: '0.5' });
  return { version: 6, provider: 'OpenAI', keyVolume: null, openrouter: { version: 1, keyVolume: null },
    monetaryLimit: mode, environment, credentialVolume: 'openai-secrets', operations: 'public-images-v2' };
}
function fixture(t, mode) {
  // Avoid macOS's system /var alias; the tested path itself must have no aliases.
  const root = fs.mkdtempSync(join(fs.realpathSync(tmpdir()), 'lifetime-budget-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const directory = join(root, '.local/state/diplom-public-images/llm');
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 }); fs.chmodSync(directory, 0o700);
  fs.mkdirSync(join(root, '.local-public-images'), { mode: 0o700 });
  const target = join(directory, 'openai-deployment.json'), value = descriptor(mode);
  fs.writeFileSync(target, json(value), { mode: 0o600 });
  return { root, directory, target, value, operator: lifetimeBudgetFixture(root),
    lock: join(root, '.local-public-images/.operation.lock') };
}
function expected(value) {
  const after = structuredClone(value); after.environment[FIELD] = '5000000'; return after;
}
function runHelper(f, harness = "import runpy, sys; runpy.run_path(sys.argv[1])['main']()", commit = 'COMMIT', ack = 'ACK') {
  return childProcess.spawnSync('python3', ['-I', '-B', '-c', harness, helper], {
    input: JSON.stringify({ settings: f.directory, apply: true }) + `\n${commit}\n${ack}\n`,
    encoding: 'utf8', timeout: 10000, maxBuffer: 262144,
  });
}
// Patch only the builtin spawn binding, never production paths or helper code.
// Every subprocess remains the local Python helper against the temporary root.
async function withHelper(t, harness, work) {
  const spawn = childProcess.spawn;
  const mocked = t.mock.method(childProcess, 'spawn', (command, args, options) => {
    assert.equal(command, 'python3');
    assert.deepEqual(args, ['-I', '-B', helper]);
    assert.deepEqual(options.env, { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' });
    return spawn(command, ['-I', '-B', '-c', harness, helper], options);
  });
  syncBuiltinESMExports();
  try { return await work(); }
  finally { mocked.mock.restore(); syncBuiltinESMExports(); }
}

for (const output of ['32768', '131072']) test(`offline check/apply adds only lifetime budget, preserves output ${output}`, async t => {
  const f = fixture(t);
  f.value.environment.LLM_QUOTA_USER_OUTPUT = output;
  // Preserve historical identity, revision strings and optional operations exactly.
  f.value.openrouter = { version: 5, keyVolume: null, timing: 'public-8081-90s-v1', profile: 'public-8081-remediation-4k-v1' };
  f.value.environment.OPENAI_POLICY_REVISION = 'policy-custom';
  if (output === '32768') delete f.value.operations;
  const bytes = Buffer.from(JSON.stringify(f.value));
  fs.writeFileSync(f.target, bytes);
  const before = fs.statSync(f.target);
  assert.deepEqual(await f.operator.check(), { status: 'check', field: FIELD, from: null, to: '5000000' });
  assert.deepEqual(fs.readFileSync(f.target), bytes);
  assert.equal(fs.statSync(f.target).ino, before.ino);
  assert.deepEqual(fs.readdirSync(f.directory), ['openai-deployment.json']);
  assert.equal(fs.existsSync(f.lock), false);
  assert.deepEqual(await f.operator.apply(), { status: 'applied', field: FIELD, from: null, to: '5000000' });
  const after = JSON.parse(fs.readFileSync(f.target));
  assert.deepEqual(after, expected(f.value));
  assert.deepEqual(validateOpenAiDeployment(after), after);
  assert.deepEqual(fs.readFileSync(f.target + BACKUP), bytes);
  assert.equal(fs.statSync(f.target).mode & 0o7777, 0o600);
  assert.equal(fs.statSync(f.target + BACKUP).mode & 0o7777, 0o600);
  assert.equal(fs.statSync(f.target + BACKUP).nlink, 1);
  assert.deepEqual(fs.readdirSync(f.directory).sort(), ['openai-deployment.json', 'openai-deployment.json' + BACKUP].sort());
  assert.equal(fs.existsSync(f.lock), false);
  const published = fs.readFileSync(f.target);
  await assert.rejects(f.operator.apply, /LIFETIME_BUDGET_HOLD/);
  assert.deepEqual(fs.readFileSync(f.target), published);
  assert.deepEqual(fs.readFileSync(f.target + BACKUP), bytes);
  assert.equal(fs.existsSync(f.lock), true);
});

for (const mutation of ['capped', 'present-exact', 'present-other', 'present-null', 'duplicate', 'duplicate-environment',
  'mode', 'hardlink', 'symlink', 'parent-mode', 'parent-symlink', 'invalid', 'constant', 'oversized', 'unknown', 'unknown-top']) {
  test(`reject before publication and retain dispatch HOLD: ${mutation}`, async t => {
    const f = fixture(t, mutation === 'capped' ? 'capped' : 'uncapped');
    if (mutation.startsWith('present-')) {
      f.value.environment[FIELD] = mutation === 'present-exact' ? '5000000' : mutation === 'present-other' ? '1' : null;
      fs.writeFileSync(f.target, json(f.value));
    }
    if (mutation === 'duplicate') fs.writeFileSync(f.target, json(f.value).replace('"version": 6,', '"version": 6, "version": 6,'));
    if (mutation === 'duplicate-environment') fs.writeFileSync(f.target, json(f.value).replace('"LLM_PROVIDER": "openai",', '"LLM_PROVIDER": "openai", "LLM_PROVIDER": "openai",'));
    if (mutation === 'mode') fs.chmodSync(f.target, 0o644);
    if (mutation === 'hardlink') fs.linkSync(f.target, join(f.root, 'alias'));
    if (mutation === 'symlink') { fs.renameSync(f.target, f.target + '.real'); fs.symlinkSync(f.target + '.real', f.target); }
    if (mutation === 'parent-mode') fs.chmodSync(f.directory, 0o755);
    if (mutation === 'parent-symlink') { fs.renameSync(f.directory, f.directory + '.real'); fs.symlinkSync(f.directory + '.real', f.directory); }
    if (mutation === 'invalid') fs.writeFileSync(f.target, 'invalid');
    if (mutation === 'constant') fs.writeFileSync(f.target, json(f.value).replace('"version": 6', '"version": NaN'));
    if (mutation === 'oversized') fs.writeFileSync(f.target, json(f.value) + ' '.repeat(16385));
    if (mutation === 'unknown') { f.value.environment.UNKNOWN = 'rejected'; fs.writeFileSync(f.target, json(f.value)); }
    if (mutation === 'unknown-top') { f.value.UNKNOWN = 'rejected'; fs.writeFileSync(f.target, json(f.value)); }
    const before = fs.readFileSync(f.target);
    await assert.rejects(f.operator.apply, /LIFETIME_BUDGET_HOLD/);
    assert.deepEqual(fs.readFileSync(f.target), before);
    assert.equal(fs.existsSync(f.target + BACKUP), false);
    assert.equal(fs.existsSync(f.target + PENDING), false);
    assert.equal(fs.existsSync(f.lock), true);
  });
}
for (const suffix of [BACKUP, PENDING, '.lifetime-budget.lock']) for (const kind of ['file', 'symlink']) {
  test(`refuse existing lifetime artifact ${suffix} (${kind}) without clobber`, async t => {
    const f = fixture(t), collision = f.target + suffix;
    if (kind === 'file') fs.writeFileSync(collision, 'evidence', { mode: 0o600 });
    else fs.symlinkSync(join(f.root, 'missing-evidence'), collision);
    const before = fs.readFileSync(f.target), stamp = fs.lstatSync(collision);
    await assert.rejects(f.operator.apply, /LIFETIME_BUDGET_HOLD/);
    assert.deepEqual(fs.readFileSync(f.target), before);
    assert.equal(fs.lstatSync(collision).ino, stamp.ino);
    if (kind === 'file') assert.equal(fs.readFileSync(collision, 'utf8'), 'evidence');
    else assert.equal(fs.readlinkSync(collision), join(f.root, 'missing-evidence'));
    assert.equal(fs.existsSync(f.lock), true);
  });
}
test('quota-output artifacts remain independent and untouched', async t => {
  const f = fixture(t);
  for (const suffix of ['.quota-output.original', '.quota-output.pending']) fs.writeFileSync(f.target + suffix, 'prior evidence');
  await f.operator.apply();
  for (const suffix of ['.quota-output.original', '.quota-output.pending']) assert.equal(fs.readFileSync(f.target + suffix, 'utf8'), 'prior evidence');
  assert.deepEqual(JSON.parse(fs.readFileSync(f.target)), expected(f.value));
});
test('existing shared operation lock blocks dispatch', async t => {
  const f = fixture(t);
  fs.mkdirSync(f.lock, { mode: 0o700 });
  const before = fs.statSync(f.lock);
  await assert.rejects(f.operator.apply, /HOLD/);
  assert.equal(fs.statSync(f.lock).ino, before.ino);
  assert.equal(fs.existsSync(f.target + BACKUP), false);
});
test('directory flock blocks a competing helper without publication', async t => {
  const f = fixture(t);
  const result = runHelper(f, `
import fcntl, os, runpy, sys
fd = os.open(${JSON.stringify(f.directory)}, os.O_RDONLY | os.O_DIRECTORY)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
runpy.run_path(sys.argv[1])['main']()
`);
  assert.equal(result.error, undefined);
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, '');
  assert.deepEqual(JSON.parse(fs.readFileSync(f.target)), f.value);
  assert.equal(fs.existsSync(f.target + BACKUP), false);
});

test('helper tolerates read-driven atime changes throughout apply', t => {
  const f = fixture(t);
  const result = runHelper(f, `
import os, runpy, sys
from types import SimpleNamespace
module = runpy.run_path(sys.argv[1])
real_fstat, real_stat, real_read = os.fstat, os.stat, os.read
reads = [0]
fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
def observed(value):
    return SimpleNamespace(**{key: getattr(value, key) for key in fields},
                           st_atime=reads[0], st_atime_ns=reads[0] * 1000000000)
def read(*args):
    result = real_read(*args)
    reads[0] += 1
    return result
os.read = read
os.fstat = lambda *args, **kwargs: observed(real_fstat(*args, **kwargs))
os.stat = lambda *args, **kwargs: observed(real_stat(*args, **kwargs))
module['main']()
assert reads[0] >= 8
`);
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout.trim().split('\n')[1]).status, 'applied');
  assert.deepEqual(JSON.parse(fs.readFileSync(f.target)), expected(f.value));
  assert.deepEqual(JSON.parse(fs.readFileSync(f.target + BACKUP)), f.value);
});
for (const field of ['st_mtime_ns', 'st_ctime_ns']) test(`stable stamps reject changed ${field}`, t => {
  const f = fixture(t);
  const result = runHelper(f, `
import os, runpy, sys
from types import SimpleNamespace
module = runpy.run_path(sys.argv[1])
real_fstat, real_read = os.fstat, os.read
reads = [0]
attrs = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
def read(*args):
    result = real_read(*args)
    reads[0] += 1
    return result
def observed(fd):
    value = real_fstat(fd)
    values = {key: getattr(value, key) for key in attrs}
    values[${JSON.stringify(field)}] += reads[0]
    return SimpleNamespace(**values)
os.read, os.fstat = read, observed
module['main']()
`);
  assert.equal(result.error, undefined);
  assert.notEqual(result.status, 0);
  assert.equal(fs.existsSync(f.target + BACKUP), false);
});
for (const [commit, ack] of [['NO', 'ACK'], ['COMMIT', 'NO']]) test(`helper requires exact ${commit === 'NO' ? 'COMMIT' : 'ACK'}`, t => {
  const f = fixture(t), before = fs.readFileSync(f.target);
  const result = runHelper(f, undefined, commit, ack);
  assert.equal(result.error, undefined);
  assert.notEqual(result.status, 0);
  if (commit === 'NO') {
    assert.deepEqual(fs.readFileSync(f.target), before);
    assert.equal(fs.existsSync(f.target + BACKUP), false);
  } else {
    assert.deepEqual(JSON.parse(fs.readFileSync(f.target)), expected(f.value));
    assert.deepEqual(fs.readFileSync(f.target + BACKUP), before);
  }
});

for (const change of [
  "after['environment']['LLM_QUOTA_USER_OUTPUT'] = '32768'",
  "after['environment']['OPENAI_INPUT_PRICE_MICROS_PER_MILLION'] = '750001'",
  "after['environment']['OPENAI_POLICY_REVISION'] = 'v2'",
  "after['environment']['LLM_QUOTA_LIFETIME_USER_COST_MICROS'] = '5000001'",
  "after['credentialVolume'] = None; after['environment']['OPENAI_ENABLED'] = 'false'",
  "after.pop('operations')",
]) test(`parent rejects any additional semantic transition: ${change}`, async t => {
  const f = fixture(t), before = fs.readFileSync(f.target);
  await withHelper(t, `
import base64, json, runpy, sys
module = runpy.run_path(sys.argv[1])
emit = module['emit']
def tamper(value):
    if 'after' in value:
        after = json.loads(base64.b64decode(value['after']))
        ${change}
        value['after'] = base64.b64encode(json.dumps(after).encode()).decode()
    emit(value)
module['main'].__globals__['emit'] = tamper
module['main']()
`, async () => { await assert.rejects(f.operator.apply, /LIFETIME_BUDGET_HOLD/); });
  assert.deepEqual(fs.readFileSync(f.target), before);
  assert.equal(fs.existsSync(f.target + BACKUP), false);
  assert.equal(fs.existsSync(f.lock), true);
});
test('mutation between prepare and COMMIT is fenced before backup creation', async t => {
  const f = fixture(t), before = fs.readFileSync(f.target);
  await withHelper(t, `
import os, runpy, sys
module = runpy.run_path(sys.argv[1])
emit = module['emit']
def mutate(value):
    if 'before' in value:
        path = ${JSON.stringify(f.target)}
        stamp = os.stat(path)
        os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 1000000000))
    emit(value)
module['main'].__globals__['emit'] = mutate
module['main']()
`, async () => { await assert.rejects(f.operator.apply, /LIFETIME_BUDGET_HOLD/); });
  assert.deepEqual(fs.readFileSync(f.target), before);
  assert.equal(fs.existsSync(f.target + BACKUP), false);
  assert.equal(fs.existsSync(f.lock), true);
});
for (const phase of ['prepare', 'result', 'exit']) test(`parent bounds stalled ${phase} and retains uncertain lock`, { timeout: 10000 }, async t => {
  const f = fixture(t), before = fs.readFileSync(f.target);
  const operator = lifetimeBudgetFixture(f.root, { phaseTimeoutMs: 250 });
  await withHelper(t, `
import runpy, sys, time
module = runpy.run_path(sys.argv[1])
emit = module['emit']
def stall(value):
    if 'status' in value and ${JSON.stringify(phase)} == 'result':
        time.sleep(60)
    emit(value)
module['main'].__globals__['emit'] = stall
if ${JSON.stringify(phase)} == 'prepare':
    time.sleep(60)
module['main']()
if ${JSON.stringify(phase)} == 'exit':
    time.sleep(60)
`, async () => { await assert.rejects(operator.apply, /LIFETIME_BUDGET_HOLD/); });
  assert.equal(fs.existsSync(f.lock), true);
  if (phase === 'prepare') {
    assert.deepEqual(fs.readFileSync(f.target), before);
    assert.equal(fs.existsSync(f.target + BACKUP), false);
  } else {
    assert.deepEqual(JSON.parse(fs.readFileSync(f.target)), expected(f.value));
    assert.deepEqual(fs.readFileSync(f.target + BACKUP), before);
  }
});
test('parent bounds unterminated helper output without waiting for timeout', { timeout: 10000 }, async t => {
  const f = fixture(t);
  await withHelper(t, "import sys, time; sys.stdout.write('x' * 262144); sys.stdout.flush(); time.sleep(60)",
    async () => { await assert.rejects(f.operator.apply, /LIFETIME_BUDGET_HOLD/); });
  assert.equal(fs.existsSync(f.lock), true);
  assert.equal(fs.existsSync(f.target + BACKUP), false);
});
test('failed rename preserves original, exact backup, pending and shared HOLD', async t => {
  const f = fixture(t), before = fs.readFileSync(f.target);
  await withHelper(t, `
import os, runpy, sys
module = runpy.run_path(sys.argv[1])
def fail_rename(*args, **kwargs):
    raise OSError('simulated publication failure')
os.rename = fail_rename
module['main']()
`, async () => { await assert.rejects(f.operator.apply, /LIFETIME_BUDGET_HOLD/); });
  assert.deepEqual(fs.readFileSync(f.target), before);
  assert.deepEqual(fs.readFileSync(f.target + BACKUP), before);
  assert.deepEqual(JSON.parse(fs.readFileSync(f.target + PENDING)), expected(f.value));
  assert.equal(fs.existsSync(f.lock), true);
});
for (const apply of [false, true]) test(`parent requires exact result bytes (${apply ? 'apply' : 'check'})`, async t => {
  const f = fixture(t), before = fs.readFileSync(f.target);
  await withHelper(t, `
import runpy, sys
module = runpy.run_path(sys.argv[1])
emit = module['emit']
def tamper(value):
    if 'status' in value:
        value['bytes'] = ''
    emit(value)
module['main'].__globals__['emit'] = tamper
module['main']()
`, async () => { await assert.rejects(apply ? f.operator.apply : f.operator.check, /LIFETIME_BUDGET_HOLD/); });
  assert.equal(fs.existsSync(f.lock), apply);
  if (apply) {
    assert.deepEqual(fs.readFileSync(f.target + BACKUP), before);
    assert.deepEqual(JSON.parse(fs.readFileSync(f.target)), expected(f.value));
  } else {
    assert.deepEqual(fs.readFileSync(f.target), before);
    assert.deepEqual(fs.readdirSync(f.directory), ['openai-deployment.json']);
  }
});
test('CLI refuses filesystem/timeout overrides before any dispatch', t => {
  const f = fixture(t);
  const result = childProcess.spawnSync(process.execPath, [cli, '--apply', f.root, '--timeout=1'], {
    encoding: 'utf8', timeout: 10000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /LIFETIME_BUDGET_HOLD/);
  assert.equal(fs.existsSync(f.lock), false);
});
