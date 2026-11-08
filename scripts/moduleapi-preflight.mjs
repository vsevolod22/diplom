// Metadata only. Import/default execution is inert; no runtime/provider activation.
import * as fs from 'node:fs';
import https from 'node:https';
import { userInfo } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { checkServerIdentity } from 'node:tls';

const HOST = 'moduleapi.pro';
const CANDIDATE = 'gpt-5.4-mini';
const PREFIX = Buffer.from('MODULEAPI_ENABLED=false\nMODULE_API_KEY=');
const MAX_FILE_BYTES = PREFIX.length + 512 + 1;
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_HEADER_BYTES = 16 * 1024;
const TIMEOUT_MS = 15_000;
const refuse = () => { throw new Error('MODULEAPI_PREFLIGHT_REFUSED'); };
const summary = () => ({ provider: 'ModuleAPI', httpStatus: null, modelListed: false,
  generationVerified: false, activated: false });

function checkProcess(env, execArgv) {
  // Node processes these before JS starts. Refusing here cannot undo a hostile
  // preload; the operator must launch a trusted Node process/environment.
  const forbidden = ['NODE_OPTIONS', 'NODE_DEBUG', 'NODE_DEBUG_NATIVE', 'NODE_PATH',
    'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_EXTRA_CA_CERTS', 'SSLKEYLOGFILE',
    'SSL_CERT_FILE', 'SSL_CERT_DIR'];
  if (forbidden.some(name => Object.hasOwn(env, name)) || execArgv.length !== 0) refuse();
}

function parseCredential(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < PREFIX.length + 17 || bytes.length > MAX_FILE_BYTES ||
      !bytes.subarray(0, PREFIX.length).equals(PREFIX) || bytes.at(-1) !== 10) refuse();
  const key = bytes.subarray(PREFIX.length, -1);
  for (const char of key) {
    if (!(char >= 65 && char <= 90 || char >= 97 && char <= 122 ||
      char >= 48 && char <= 57 || char === 45 || char === 95)) refuse();
  }
  return Buffer.from(key);
}

function sameIdentity(a, b) {
  return a.dev === b.dev && a.ino === b.ino && a.uid === b.uid && a.gid === b.gid &&
    a.mode === b.mode && a.nlink === b.nlink && a.size === b.size &&
    a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
}

function readCredential({ filesystem, home, uid }) {
  if (!Number.isInteger(uid) || uid < 0 || !isAbsolute(home) || resolve(home) !== home ||
      filesystem.realpathSync(home) !== home) refuse();
  const { O_RDONLY, O_NOFOLLOW, O_DIRECTORY, O_NONBLOCK } = filesystem.constants;
  if (![O_NOFOLLOW, O_DIRECTORY, O_NONBLOCK].every(value => Number.isInteger(value) && value > 0)) refuse();
  const directory = join(home, '.diplom-moduleapi');
  const file = join(directory, 'server.env');
  const descriptors = [];
  const proofs = [];
  let bytes, key;
  const verify = () => {
    for (const { path, fd, info } of proofs) {
      if (!sameIdentity(info, filesystem.fstatSync(fd, { bigint: true })) ||
          !sameIdentity(info, filesystem.lstatSync(path, { bigint: true }))) refuse();
    }
  };
  const openChecked = (path, directoryEntry, privateDirectory = false) => {
    const before = filesystem.lstatSync(path, { bigint: true });
    if (before.uid !== BigInt(uid) || (directoryEntry ? !before.isDirectory() : !before.isFile()) ||
        (directoryEntry ? privateDirectory ? (before.mode & 0o7777n) !== 0o700n :
          (before.mode & 0o7022n) !== 0n :
          (before.mode & 0o7777n) !== 0o600n || before.nlink !== 1n ||
          before.size < BigInt(PREFIX.length + 17) || before.size > BigInt(MAX_FILE_BYTES))) refuse();
    const fd = filesystem.openSync(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | (directoryEntry ? O_DIRECTORY : 0));
    descriptors.push(fd);
    if (!sameIdentity(before, filesystem.fstatSync(fd, { bigint: true }))) refuse();
    proofs.push({ path, fd, info: before });
    verify();
    return fd;
  };
  try {
    openChecked(home, true);
    openChecked(directory, true, true);
    const fd = openChecked(file, false);
    bytes = Buffer.alloc(MAX_FILE_BYTES + 1);
    let count = 0;
    while (count < bytes.length) {
      verify();
      const read = filesystem.readSync(fd, bytes, count, bytes.length - count, count);
      if (read === 0) break;
      count += read;
    }
    verify();
    if (BigInt(count) !== proofs.at(-1).info.size) refuse();
    key = parseCredential(bytes.subarray(0, count));
    return key;
  } finally {
    bytes?.fill(0);
    // Close every handle even if one close fails. No untrusted error is exposed.
    let failed = false;
    for (const fd of descriptors.reverse()) {
      try { filesystem.closeSync(fd); } catch { failed = true; }
    }
    if (failed) { key?.fill(0); refuse(); }
  }
}

function responseFraming(message) {
  if (message.httpVersion !== '1.1' || !Array.isArray(message.rawHeaders) || message.rawHeaders.length % 2 ||
      message.rawHeaders.length > 512) refuse();
  const headers = new Map();
  let bytes = 32; // Conservative status-line allowance in addition to Node's parser cap.
  for (let index = 0; index < message.rawHeaders.length; index += 2) {
    const name = message.rawHeaders[index];
    const value = message.rawHeaders[index + 1];
    if (typeof name !== 'string' || typeof value !== 'string' ||
        !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || /[\r\n\0]/.test(value)) refuse();
    bytes += Buffer.byteLength(name) + Buffer.byteLength(value) + 4;
    if (bytes > MAX_HEADER_BYTES) refuse();
    const lower = name.toLowerCase();
    if (headers.has(lower) && ['content-length', 'transfer-encoding', 'content-type', 'content-encoding'].includes(lower)) refuse();
    headers.set(lower, value.trim());
  }
  if (!/^application\/json(?:\s*;\s*charset=(?:utf-8|"utf-8"))?$/i.test(headers.get('content-type') ?? '') ||
      !/^(?:identity)?$/i.test(headers.get('content-encoding') ?? '')) refuse();
  const length = headers.get('content-length');
  const transfer = headers.get('transfer-encoding');
  if (length !== undefined) {
    if (transfer !== undefined || !/^(?:0|[1-9][0-9]{0,6})$/.test(length) || Number(length) > MAX_BODY_BYTES) refuse();
    return Number(length);
  }
  if (transfer?.toLowerCase() !== 'chunked') refuse();
  return null;
}

function modelListed(bytes) {
  const root = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  if (!root || typeof root !== 'object' || Array.isArray(root) || Object.hasOwn(root, 'error') ||
      !Array.isArray(root.data) || root.data.length > 512) refuse();
  const ids = new Set();
  for (const item of root.data) {
    if (!item || typeof item !== 'object' || Array.isArray(item) || typeof item.id !== 'string' ||
        item.id.length === 0 || item.id.length > 256 || /[\u0000-\u0020\u007f]/u.test(item.id) || ids.has(item.id)) refuse();
    ids.add(item.id);
  }
  return ids.has(CANDIDATE);
}

function probeModels(key, { request, checkIdentity, setTimer, clearTimer, now }) {
  return new Promise(resolveResult => {
    const deadline = now() + TIMEOUT_MS;
    let req, response, timer, settled = false, verified = false, status = null;
    let chunks = [], received = 0;
    const finish = (ok, listed = false) => {
      if (settled) return;
      settled = true;
      ok = ok && now() < deadline;
      clearTimer(timer);
      for (const chunk of chunks) chunk.fill(0);
      chunks = [];
      // Keep error listeners attached during teardown; errors never enter output.
      response?.destroy();
      req?.destroy();
      resolveResult({ ok, httpStatus: status, modelListed: ok && listed });
    };
    timer = setTimer(() => finish(false), TIMEOUT_MS);
    try {
      req = request({ protocol: 'https:', hostname: HOST, port: 443, servername: HOST,
        path: '/v1/models', method: 'GET', agent: false, rejectUnauthorized: true,
        minVersion: 'TLSv1.2', checkServerIdentity: checkIdentity, maxHeaderSize: MAX_HEADER_BYTES,
        insecureHTTPParser: false, joinDuplicateHeaders: false,
        headers: { Authorization: `Bearer ${key.toString('ascii')}`, Accept: 'application/json',
          'Accept-Encoding': 'identity', Connection: 'close' } }, message => {
        response = message;
        message.on('error', () => finish(false));
        if (settled) { message.destroy(); return; }
        try {
          if (!verified || now() >= deadline) refuse();
          if (!Number.isInteger(message.statusCode) || message.statusCode < 200 || message.statusCode > 599) refuse();
          status = message.statusCode;
          if (status !== 200) refuse();
          const expectedBytes = responseFraming(message);
          message.on('data', chunk => {
            if (settled) return;
            if (now() >= deadline || !Buffer.isBuffer(chunk) || received + chunk.length > MAX_BODY_BYTES ||
                expectedBytes !== null && received + chunk.length > expectedBytes) { finish(false); return; }
            received += chunk.length;
            chunks.push(Buffer.from(chunk));
          });
          message.once('aborted', () => finish(false));
          message.once('close', () => { if (!message.complete || !message.readableEnded) finish(false); });
          message.once('end', () => {
            if (settled) return;
            let body;
            try {
              if (now() >= deadline || !message.complete || message.aborted || !message.readableEnded || received === 0 ||
                  expectedBytes !== null && received !== expectedBytes ||
                  !Array.isArray(message.rawTrailers) || message.rawTrailers.length !== 0) refuse();
              body = Buffer.concat(chunks, received);
              finish(true, modelListed(body));
            } catch { finish(false); }
            finally { body?.fill(0); }
          });
        } catch { finish(false); }
      });
      req.on('error', () => finish(false));
      req.once('close', () => { if (!response) finish(false); });
      req.once('upgrade', (_response, socket) => { socket.destroy(); finish(false); });
      req.once('connect', (_response, socket) => { socket.destroy(); finish(false); });
      req.once('information', () => finish(false));
      req.once('socket', socket => {
        socket.on('error', () => finish(false));
        // Do not end/flush the HTTP request (including Authorization) until TLS
        // has both a verified chain and the fixed hostname identity.
        socket.once('secureConnect', () => {
          if (settled) return;
          try {
            if (now() >= deadline || socket.encrypted !== true || socket.authorized !== true ||
                checkIdentity(HOST, socket.getPeerCertificate(true)) !== undefined) refuse();
            verified = true;
            req.end();
          } catch { finish(false); }
        });
      });
    } catch { finish(false); }
  });
}

async function run(argv, { env, execArgv, credentials, probe }) {
  const result = summary();
  if (argv.length === 0) return { code: 0, result };
  if (argv.length !== 1 || argv[0] !== '--check-model-access') return { code: 1, result };
  let key;
  try {
    checkProcess(env, execArgv);
    key = credentials();
    const checked = await probe(key);
    result.httpStatus = checked.httpStatus;
    result.modelListed = checked.ok && checked.modelListed;
    return { code: checked.ok && checked.modelListed ? 0 : 1, result };
  } catch { return { code: 1, result }; }
  finally { key?.fill(0); }
}

// Explicit offline seams only. The executable path never accepts injected JSON,
// credentials, paths, URLs, environment grants or collaborators from its caller.
export const moduleApiPreflightForTest = Object.freeze({ parseCredential, readCredential,
  responseFraming, modelListed, probeModels, run });

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const outcome = await run(process.argv.slice(2), { env: process.env, execArgv: process.execArgv,
    credentials() {
      const account = userInfo(); // POSIX passwd account; never HOME/XDG overrides.
      if (typeof process.getuid !== 'function' || typeof process.geteuid !== 'function' ||
          process.getuid() !== process.geteuid() || account.uid !== process.getuid()) refuse();
      return readCredential({ filesystem: fs, home: account.homedir, uid: account.uid });
    },
    probe: key => probeModels(key, { request: https.request, checkIdentity: checkServerIdentity,
      setTimer: setTimeout, clearTimer: clearTimeout, now: () => performance.now() }) });
  process.stdout.write(`${JSON.stringify(outcome.result)}\n`);
  process.exitCode = outcome.code;
}
