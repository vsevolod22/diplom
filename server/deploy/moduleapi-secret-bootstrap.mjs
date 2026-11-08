// API-only entrypoint, not a provider/key-file fallback. Node >=24.11.1 on Linux.
// COPY this public source to /app/server/deploy/moduleapi-secret-bootstrap.mjs.
// Entrypoint: ["/usr/local/bin/node", "--disable-warning=ExperimentalWarning",
//              "/app/server/deploy/moduleapi-secret-bootstrap.mjs"]
// Keep the public API command and working directory below unchanged. Mount the
// external moduleapi-secrets volume READ ONLY at /run/moduleapi-secrets, API only.
import * as fs from 'node:fs';
import { pathToFileURL } from 'node:url';

export const SECRET_DIRECTORY = '/run/moduleapi-secrets';
export const SECRET_PATH = `${SECRET_DIRECTORY}/server.env`;
export const SECRET_VOLUME = 'moduleapi-secrets';
export const API_WORKDIR = '/app/server/api';
export const API_EXECUTABLE = '/usr/local/bin/node';
export const BOOTSTRAP_SOURCE = 'server/deploy/moduleapi-secret-bootstrap.mjs';
export const BOOTSTRAP_TARGET = '/app/server/deploy/moduleapi-secret-bootstrap.mjs';
export const API_ENTRYPOINT = Object.freeze([API_EXECUTABLE, '--disable-warning=ExperimentalWarning', BOOTSTRAP_TARGET]);
export const API_COMMAND = Object.freeze(['node', '--import', 'tsx', 'src/oci/public-image.main.ts']);
export const MAX_SECRET_BYTES = 552;
const PREFIX = 'MODULEAPI_ENABLED=false\nMODULE_API_KEY=';
const OWNER = 65532;
const CODES = new Set(['E_ARGUMENTS', 'E_RUNTIME', 'E_METADATA', 'E_PAYLOAD', 'E_READ', 'E_EXEC']);

export class SecretRefusal extends Error {
  constructor(code) {
    super(CODES.has(code) ? code : 'E_RUNTIME');
    this.code = this.message;
  }
}

export function failureCode(error) {
  return error instanceof SecretRefusal && CODES.has(error.code) ? error.code : 'E_RUNTIME';
}

// Deliberately not dotenv: exactly two ordered ASCII assignments, one final LF.
// No expansion, source/eval, quotes, comments, duplicates, CRLF or extra keys.
export function parseSecretPayload(payload) {
  if (!Buffer.isBuffer(payload) || payload.length < 56 || payload.length > MAX_SECRET_BYTES
      || payload.some((byte) => byte > 127)) throw new SecretRefusal('E_PAYLOAD');
  const text = payload.toString('ascii');
  if (!text.startsWith(PREFIX) || !text.endsWith('\n')) throw new SecretRefusal('E_PAYLOAD');
  const key = text.slice(PREFIX.length, -1);
  if (!/^[A-Za-z0-9_-]{16,512}$/.test(key)) throw new SecretRefusal('E_PAYLOAD');
  return key;
}

function directoryMetadata(info) {
  if (!info.isDirectory() || (info.mode & 0o7777) !== 0o700
      || info.uid !== OWNER || info.gid !== OWNER) throw new SecretRefusal('E_METADATA');
}

function fileMetadata(info) {
  if (!info.isFile() || (info.mode & 0o7777) !== 0o400 || info.nlink !== 1
      || info.uid !== OWNER || info.gid !== OWNER || info.size < 56
      || info.size > MAX_SECRET_BYTES) throw new SecretRefusal('E_METADATA');
}

function sameFile(left, right) {
  return ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeMs', 'ctimeMs']
    .every((key) => left[key] === right[key]);
}

// Import-only seam for synthetic filesystem adapters. Production has no path,
// owner or IO overrides. Linux /proc/self/fd anchors opens to verified dir FDs.
export function readSecretFile(io = fs) {
  const { O_RDONLY, O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK } = io.constants;
  let runFd;
  let directoryFd;
  let fileFd;
  const payload = Buffer.alloc(MAX_SECRET_BYTES + 1);
  try {
    if (![O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK].every(Number.isInteger)) {
      throw new SecretRefusal('E_RUNTIME');
    }
    runFd = io.openSync('/run', O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    const run = io.fstatSync(runFd);
    if (!run.isDirectory() || run.uid !== 0 || (run.mode & 0o022) !== 0) {
      throw new SecretRefusal('E_METADATA');
    }
    directoryFd = io.openSync(`/proc/self/fd/${runFd}/moduleapi-secrets`, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    directoryMetadata(io.fstatSync(directoryFd));
    fileFd = io.openSync(`/proc/self/fd/${directoryFd}/server.env`, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    const before = io.fstatSync(fileFd);
    fileMetadata(before);
    let length = 0;
    while (length < payload.length) {
      const count = io.readSync(fileFd, payload, length, payload.length - length, null);
      if (count === 0) break;
      length += count;
    }
    const after = io.fstatSync(fileFd);
    fileMetadata(after);
    directoryMetadata(io.fstatSync(directoryFd));
    if (length !== before.size || !sameFile(before, after)) throw new SecretRefusal('E_METADATA');
    return parseSecretPayload(payload.subarray(0, length));
  } catch (error) {
    if (error instanceof SecretRefusal) throw error;
    throw new SecretRefusal('E_READ');
  } finally {
    payload.fill(0);
    for (const fd of [fileFd, directoryFd, runFd]) {
      if (fd !== undefined) {
        try { io.closeSync(fd); } catch { /* Never print filesystem diagnostics. */ }
      }
    }
  }
}

// Test seam never starts a process by itself. Caller must explicitly supply exec.
export function bootstrap({ argv, env, cwd, executable, uid, gid, readKey, exec }) {
  // A missing/malformed volume must never inherit a usable ambient credential.
  delete env.MODULE_API_KEY;
  // Drop, never inspect or forward, a credential for the other paid recipient.
  delete env.OPENAI_API_KEY;
  if (!Array.isArray(argv) || argv.length !== API_COMMAND.length
      || argv.some((value, index) => value !== API_COMMAND[index])) throw new SecretRefusal('E_ARGUMENTS');
  if (cwd !== API_WORKDIR || executable !== API_EXECUTABLE || uid !== OWNER || gid !== OWNER
      || typeof exec !== 'function' || typeof readKey !== 'function'
      || ['NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED',
        // Node HTTP debugging can print authenticated headers after execve.
        'NODE_DEBUG', 'NODE_DEBUG_NATIVE', 'NODE_V8_COVERAGE', 'SSLKEYLOGFILE',
        'SSL_CERT_FILE', 'SSL_CERT_DIR'].some(name => env[name])) throw new SecretRefusal('E_RUNTIME');
  const key = readKey();
  if (typeof key !== 'string' || !/^[A-Za-z0-9_-]{16,512}$/.test(key)) throw new SecretRefusal('E_PAYLOAD');
  const childEnv = { ...env, MODULEAPI_ENABLED: env.MODULEAPI_ENABLED ?? 'false', MODULE_API_KEY: key };
  try {
    // execve replaces PID 1: no supervisor, child relay, shell or fallback spawn.
    exec(API_EXECUTABLE, [API_EXECUTABLE, ...API_COMMAND.slice(1)], childEnv);
  } catch {
    throw new SecretRefusal('E_EXEC');
  } finally {
    delete childEnv.MODULE_API_KEY;
  }
  throw new SecretRefusal('E_EXEC'); // A real successful exec never returns.
}

export function main() {
  try {
    if (process.platform !== 'linux' || process.execArgv.length !== 1 ||
        process.execArgv[0] !== '--disable-warning=ExperimentalWarning') throw new SecretRefusal('E_RUNTIME');
    bootstrap({ argv: process.argv.slice(2), env: process.env, cwd: process.cwd(),
      executable: process.execPath, uid: process.getuid?.(), gid: process.getgid?.(),
      readKey: readSecretFile, exec: typeof process.execve === 'function' ? process.execve.bind(process) : undefined });
  } catch (error) {
    delete process.env.MODULE_API_KEY;
    delete process.env.OPENAI_API_KEY;
    process.stderr.write(`MODULEAPI_SECRET_${failureCode(error)}\n`);
    return 78;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main();
}
