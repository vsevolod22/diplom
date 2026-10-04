import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const localDir = join(root, '.local-auth');
process.umask(0o077);
mkdirSync(localDir, { recursive: true, mode: 0o700 });
chmodSync(localDir, 0o700);
const database = join(localDir, 'auth.sqlite');
if (existsSync(database)) chmodSync(database, 0o600);

const origin = 'http://127.0.0.1:5173';
const target = 'http://127.0.0.1:3001';
const env = {
  ...process.env,
  AUTH_DB_PATH: database,
  AUTH_ORIGIN: origin,
  AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true',
  AUTH_DEV_PROXY_TARGET: target,
  SCAN_JWT_SECRET: randomBytes(48).toString('hex'),
  SCAN_JWT_ISSUER: 'diplom-local-auth',
  SCAN_JWT_AUDIENCE: 'diplom-local-auth',
  SCAN_BIND_ADDRESS: '127.0.0.1',
  PORT: '3001',
};
const children = [];
let stopping = false;
function stop(code) {
  if (stopping) return;
  stopping = true;
  for (const child of children) {
    if (child.pid) {
      try {
        if (process.platform === 'win32') child.kill('SIGTERM');
        else process.kill(-child.pid, 'SIGTERM');
      } catch { /* The child already exited. */ }
    }
  }
  process.exitCode = code;
}
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => stop(0));
function launch(label, args) {
  const child = spawn('pnpm', args, { cwd: root, env, stdio: 'inherit', detached: process.platform !== 'win32' });
  children.push(child);
  child.on('error', error => { console.error(`${label}: ${error.message}`); stop(1); });
  child.on('exit', code => {
    if (!stopping) { console.error(`${label} stopped (exit ${code ?? 'signal'}).`); stop(1); }
  });
}
launch('Auth API', ['--filter', '@diplom/scan-api', 'start']);
launch('Vite', ['exec', 'vite', '--host', '127.0.0.1', '--port', '5173', '--strictPort']);

async function waitFor(url, expected) {
  for (let attempt = 0; attempt < 60 && !stopping; attempt++) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(750) });
      if (response.status === expected) return;
    } catch { /* Wait until both listeners are available. */ }
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  if (!stopping) { console.error(`Local server did not become ready: ${url}`); stop(1); }
}
await Promise.all([waitFor(`${target}/api/v1/auth/me`, 401), waitFor(origin, 200)]);
if (!stopping) {
  console.log(`\nOpen ${origin}/register to create an account, then ${origin}/account. Guest demo: ${origin}/demo/scans`);
  console.log('Stop both local servers with Ctrl+C. Accounts remain in the ignored .local-auth directory.');
}
