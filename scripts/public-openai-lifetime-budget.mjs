// Offline descriptor maintenance only. Uncertain dispatch deliberately leaves the
// persistent shared operation lock for reviewed operator reconciliation.

import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { acquireLock } from './public-image-stand.mjs';
import { validateOpenAiDeployment, validateOpenAiBuildDeployment } from './public-openai-descriptor.mjs';
const HERE = dirname(fileURLToPath(import.meta.url));
const SETTINGS = '.local/state/diplom-public-images/llm';
const HOLD = 'LIFETIME_BUDGET_HOLD: preserve shared lock and artifacts for operator inspection.';
const FIELD = 'LLM_QUOTA_LIFETIME_USER_COST_MICROS';
const VALUE = '5000000';
const PHASE_TIMEOUT_MS = 10000;
const need = v => { if (!v) throw Error(HOLD); };
async function run(root, settings, apply, phaseTimeoutMs = PHASE_TIMEOUT_MS) {
  let lock;
  if (apply) lock = acquireLock(root);
  let child;
  try {
    child = spawn('python3', ['-I', '-B', join(HERE, 'public-openai-lifetime-budget.py')], {
      stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' },
    });
  } catch { lock?.release(); throw Error(HOLD); }
  // No finally-release: even an error event after dispatch is treated as uncertain.
  let reader;
  try {
    let fail;
    const failed = new Promise((_, reject) => { fail = reject; });
    failed.catch(() => {});
    const exited = new Promise((resolveExit, reject) => {
      child.once('error', error => { fail(error); reject(error); });
      child.once('close', code => {
        if (code === 0) resolveExit();
        else { fail(Error(HOLD)); reject(Error(HOLD)); }
      });
    });
    exited.catch(() => {});
    child.stderr.resume();
    child.stderr.on('error', fail);
    child.stdout.on('error', fail);
    child.stdin.on('error', fail);
    let received = 0;
    child.stdout.on('data', chunk => {
      received += chunk.length;
      // Two bounded protocol lines; also bound unterminated output before readline.
      if (received > 2 * 65537) fail(Error(HOLD));
    });
    reader = createInterface({ input: child.stdout });
    const lines = reader[Symbol.asyncIterator]();
    const phase = async operation => {
      let timer;
      try {
        return await Promise.race([operation, failed, new Promise((_, reject) => {
          timer = setTimeout(() => reject(Error(HOLD)), phaseTimeoutMs);
        })]);
      } finally { clearTimeout(timer); }
    };
    const receive = async () => {
      const line = await phase(lines.next()); need(!line.done && Buffer.byteLength(line.value) <= 65536);
      return JSON.parse(line.value);
    };
    child.stdin.write(JSON.stringify({ settings, apply }) + '\n');
    const prepared = await receive();
    const before = JSON.parse(Buffer.from(prepared.before, 'base64').toString('utf8'));
    const after = JSON.parse(Buffer.from(prepared.after, 'base64').toString('utf8'));
    need(isDeepStrictEqual(validateOpenAiDeployment(before), before));
    need(isDeepStrictEqual(validateOpenAiDeployment(after), after));
    need(before.monetaryLimit === 'uncapped' && !Object.hasOwn(before.environment, FIELD));
    const expected = structuredClone(before); expected.environment[FIELD] = VALUE;
    need(isDeepStrictEqual(expected, after));
    validateOpenAiBuildDeployment({ prior: before, next: after });
    lock?.verify();
    child.stdin.write('COMMIT\n');
    const result = await receive();
    need(result.status === (apply ? 'applied' : 'check'));
    need(result.bytes === (apply ? prepared.after : prepared.before));
    lock?.verify();
    child.stdin.end('ACK\n');
    await phase(exited);
    lock?.verify(); lock?.release();
    reader.close();
    return { status: result.status, field: FIELD, from: null, to: VALUE };
  } catch {
    child.stdin.destroy();
    reader?.close();
    child.stdout.destroy();
    child.stderr.destroy();
    child.kill('SIGKILL');
    throw Error(HOLD);
  }
}
// Test injection is import-only; CLI accepts no filesystem or timeout override.
export function lifetimeBudgetFixture(root, { phaseTimeoutMs = PHASE_TIMEOUT_MS } = {}) {
  need(resolve(root) === root);
  need(Number.isInteger(phaseTimeoutMs) && phaseTimeoutMs > 0 && phaseTimeoutMs <= PHASE_TIMEOUT_MS);
  return { check: () => run(root, join(root, SETTINGS), false, phaseTimeoutMs),
    apply: () => run(root, join(root, SETTINGS), true, phaseTimeoutMs) };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    need(process.argv.length === 3 && ['--check', '--apply'].includes(process.argv[2]));
    console.log(JSON.stringify(await run(dirname(HERE), join(homedir(), SETTINGS), process.argv[2] === '--apply')));
  } catch { console.error(HOLD); process.exitCode = 1; }
}
