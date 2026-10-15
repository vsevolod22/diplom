import { spawn } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import net from 'node:net';

const root = fileURLToPath(new URL('../', import.meta.url));
const output = `${root}test-results/task16-chat-browser-r5`;
await mkdir(output, { recursive: true });
const environment = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'LANG'].filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]));
environment.NODE_ENV = 'test';
const child = spawn(process.execPath, ['--import', './server/api/node_modules/tsx/dist/loader.mjs', 'tests-e2e/task16-chat-browser.r5.mjs'], {
  cwd: root, env: environment, detached: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
});
const start = Date.now();
let log = '', port, timedOut = false;
const cleanupSignals = [];
child.on('message', message => { port = message.port; });
for (const pipe of [child.stdout, child.stderr]) pipe.on('data', chunk => {
  log += chunk.toString();
  process.stdout.write(chunk);
});
function killGroup(signal) {
  if (!child.pid) return;
  try { process.kill(-child.pid, signal); cleanupSignals.push({ signal, group: 'sent' }); }
  catch (error) {
    cleanupSignals.push({ signal, group: error.code });
    if (error.code !== 'ESRCH' && error.code !== 'EPERM') throw error;
    // Some terminal sandboxes reject negative-PID signals even after a clean exit.
    if (error.code === 'EPERM' && child.exitCode === null && child.signalCode === null) child.kill(signal);
  }
}
const deadline = setTimeout(() => {
  timedOut = true;
  killGroup('SIGKILL');
}, 31000);
const signals = () => { killGroup('SIGKILL'); };
process.on('SIGTERM', signals); process.on('SIGINT', signals);
let result;
try {
  result = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve({ code, signal }));
  });
} finally {
  clearTimeout(deadline);
  // Reap any descendant surviving the child's own finally, including Chromium or Vite workers.
  killGroup('SIGKILL');
}
const listenerClosed = port === undefined ? null : await new Promise(resolve => {
  const socket = net.connect({ host: '127.0.0.1', port });
  socket.once('connect', () => { socket.destroy(); resolve(false); });
  socket.once('error', () => resolve(true));
  socket.setTimeout(1000, () => { socket.destroy(); resolve(false); });
});
await writeFile(`${output}/manager.log`, log);
const managed = { ...result, childPid: child.pid, timedOut, deadlineMs: 31000, durationMs: Date.now() - start,
  cleanEnvironmentKeys: Object.keys(environment), cleanupSignals, processGroupCleanup: 'group signal attempted; EPERM disclosed, live-child fallback; child closes Chromium/Vite in finally', listener: { port, closed: listenerClosed },
  synthetic: true, backendStarted: false, externalServices: false };
await writeFile(`${output}/manager.json`, JSON.stringify(managed, null, 2));
try {
  const manifest = JSON.parse(await readFile(`${output}/manifest.json`, 'utf8'));
  for (const name of ['manager.json', 'manager.log']) {
    const path = `test-results/task16-chat-browser-r5/${name}`;
    const bytes = await readFile(`${root}${path}`);
    manifest.files = manifest.files.filter(file => file.path !== path);
    manifest.files.push({ path, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
  }
  await writeFile(`${output}/manifest.json`, JSON.stringify(manifest, null, 2));
} catch (error) { if (error.code !== 'ENOENT') throw error; }
console.log(`Managed child exit=${result.code} signal=${result.signal}; own listener closed=${listenerClosed}; timedOut=${timedOut}`);
process.exitCode = timedOut ? 124 : result.code ?? 1;
if (listenerClosed === false) process.exitCode = 1;
