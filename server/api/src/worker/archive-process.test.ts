import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { runArchiveProcess } from './archive-process.js';

const archive = '/tmp/trivy/jobs/00000000-0000-4000-8000-000000000000/image.tar';
const directory = archive.slice(0, archive.lastIndexOf('/'));
type Launch = NonNullable<NonNullable<Parameters<typeof runArchiveProcess>[4]>['launch']>;
function launchCode(code: string): Launch {
  return ((binary, args, options) => {
    assert.equal(binary, '/usr/local/bin/trivy');
    assert.ok(Array.isArray(args));
    assert.deepEqual(args.slice(0, 3), ['image', '--input', archive]);
    assert.equal(options?.shell, false);
    assert.deepEqual(options?.env, { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: directory, TMPDIR: directory });
    assert.deepEqual(options?.stdio, ['ignore', 'pipe', 'ignore']);
    return spawn(process.execPath, ['-e', code], options);
  });
}
const signal = () => new AbortController().signal;
test('archive process fixed argv/environment and exact byte cap accept bounded valid JSON', async () => {
  const value = await runArchiveProcess('secret', archive, directory, signal(), {
    launch: launchCode('process.stdout.write(JSON.stringify("a".repeat(999998)))'),
  });
  assert.equal((value as string).length, 999998);
});
test('archive process N+1 bytes and multibyte output fail even with exit zero', async () => {
  for (const code of ['process.stdout.write(JSON.stringify("a".repeat(999999)))',
    'process.stdout.write(JSON.stringify("é".repeat(500000)))']) {
    await assert.rejects(runArchiveProcess('secret', archive, directory, signal(), { launch: launchCode(code) }),
      { message: 'Archive scanner failed' });
  }
});
test('malformed, truncated, invalid UTF-8 and nonzero output cannot produce coverage or raw errors', async () => {
  for (const code of ['process.stdout.write("SECRET_CANARY")', 'process.stdout.write("{")',
    'process.stdout.write(Buffer.from([0xff]))', 'process.stdout.write("{}");process.exitCode=1']) {
    await assert.rejects(runArchiveProcess('vuln', archive, directory, signal(), { launch: launchCode(code) }),
      { message: 'Archive scanner failed' });
  }
});
test('real subprocess timeout and caller cancellation kill bounded execution', async () => {
  await assert.rejects(runArchiveProcess('secret', archive, directory, signal(), {
    launch: launchCode('setInterval(()=>{},1000)'), timeoutMs: 100,
  }), { message: 'Archive scanner failed' });
  const controller = new AbortController();
  const pending = runArchiveProcess('sbom', archive, directory, controller.signal, {
    launch: launchCode('setInterval(()=>{},1000)'),
  });
  controller.abort();
  await assert.rejects(pending, { message: 'Archive scanner failed' });
  let launched = false;
  await assert.rejects(runArchiveProcess('secret', archive, directory, controller.signal, {
    launch: () => { launched = true; throw new Error('SECRET_CANARY'); },
  }));
  assert.equal(launched, false);
});
test('missing pinned binary fails without leaking OS diagnostics', async () => {
  const launch: Launch = (_binary, _args, options) => spawn('/nonexistent/archive-scanner-test', [], options);
  await assert.rejects(runArchiveProcess('secret', archive, directory, signal(), { launch }),
    { message: 'Archive scanner failed' });
});
