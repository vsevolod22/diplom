import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
// This shortcut is local only. Public deployments must explicitly supply an HTTPS origin,
// a managed secret and an external TLS terminator; see server/deploy/README.md.
const env = {
  ...process.env,
  AUTH_ORIGIN: 'http://127.0.0.1:8080',
  AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true',
  SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: process.env.SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS ?? 'true',
  SCAN_JWT_SECRET: randomBytes(48).toString('hex'),
};
const child = spawn('docker', ['compose', '-f', 'server/deploy/compose.stand.yaml', 'up', '--build'], {
  cwd: root,
  env,
  stdio: 'inherit',
});
child.on('error', error => { console.error(`Cannot start Docker stand: ${error.message}`); process.exitCode = 1; });
child.on('exit', (code, signal) => { process.exitCode = signal ? 1 : code ?? 1; });
