import assert from 'node:assert/strict';
import test from 'node:test';
import { constants } from 'node:fs';
import { readSecretFile, parseSecretPayload, failureCode, MAX_SECRET_BYTES,
  bootstrap, API_COMMAND, API_EXECUTABLE, API_WORKDIR } from './moduleapi-secret-bootstrap.mjs';

const key = 'synthetic_not_a_real_key_123456';
const payload = Buffer.from('MODULEAPI_ENABLED=false\nMODULE_API_KEY=' + key + '\n');
const metadata = (directory, patch = {}) => ({ mode: directory ? 0o40700 : 0o100400, uid: 65532, gid: 65532,
  nlink: 1, size: directory ? 0 : payload.length, dev: 1, ino: directory ? 2 : 3, mtimeMs: 1, ctimeMs: 1,
  isDirectory: () => directory, isFile: () => !directory, ...patch });
function fixture(patch = {}) {
  const paths = [], closed = []; let offset = 0, reads = 0, buffer;
  return { paths, closed, get buffer() { return buffer; }, constants,
    openSync(path, flags) {
      paths.push([path, flags]);
      if (patch.openError) throw Error(key);
      return paths.length;
    },
    fstatSync(fd) {
      if (fd === 1) return metadata(true, { uid: 0, mode: 0o40755, ...patch.run });
      if (fd === 2) return metadata(true, patch.directory);
      reads++; return metadata(false, reads > 1 ? { ...patch.file, ...patch.after } : patch.file);
    },
    readSync(_fd, target, start, length) {
      buffer = target; const count = Math.min(7, length, payload.length - offset);
      payload.copy(target, start, offset, offset + count); offset += count; return count;
    },
    closeSync(fd) { closed.push(fd); },
  };
}

test('bootstrap reads only fixed FD-anchored nofollow paths, handles partial reads and wipes buffers', () => {
  const io = fixture(); assert.equal(readSecretFile(io), key);
  assert.deepEqual(io.paths.map(([path]) => path), ['/run', '/proc/self/fd/1/moduleapi-secrets', '/proc/self/fd/2/server.env']);
  assert.ok(io.paths.every(([, flags]) => flags & constants.O_NOFOLLOW));
  assert.ok(io.paths[2][1] & constants.O_NONBLOCK);
  assert.deepEqual(io.closed, [3, 2, 1]); assert.ok(io.buffer.every(byte => byte === 0));
});
for (const [name, patch] of Object.entries({
  'unsafe run': { run: { mode: 0o40777 } }, 'wrong owner': { directory: { uid: 0 } },
  'wrong directory mode': { directory: { mode: 0o40755 } }, 'writable file': { file: { mode: 0o100600 } },
  'hardlink': { file: { nlink: 2 } }, 'oversize': { file: { size: MAX_SECRET_BYTES + 1 } },
  'metadata race': { after: { ino: 99 } }, 'symlink/open failure': { openError: true },
})) test(`bootstrap refuses ${name} without sensitive diagnostics`, () => {
  const io = fixture(patch);
  assert.throws(() => readSecretFile(io), error => {
    assert.ok(['E_METADATA', 'E_READ'].includes(failureCode(error))); assert.ok(!String(error).includes(key)); return true;
  });
  if (io.buffer) assert.ok(io.buffer.every(byte => byte === 0));
});

test('read failure is sanitized, closes every owned descriptor and wipes partial bytes', () => {
  const io = fixture(); const read = io.readSync;
  io.readSync = (...args) => { read(...args); throw Error(key); };
  assert.throws(() => readSecretFile(io), error => failureCode(error) === 'E_READ' && !String(error).includes(key));
  assert.deepEqual(io.closed, [3, 2, 1]); assert.ok(io.buffer.every(byte => byte === 0));
});

test('metadata fences reject all file identity, content-size and timestamp changes', () => {
  for (const after of [{ size: payload.length + 1 }, { mtimeMs: 2 }, { ctimeMs: 2 }, { uid: 0 },
    { gid: 0 }, { nlink: 2 }, { dev: 2 }, { mode: 0o104400 }]) {
    const io = fixture({ after });
    assert.throws(() => readSecretFile(io), error => failureCode(error) === 'E_METADATA');
    assert.deepEqual(io.closed, [3, 2, 1]); assert.ok(io.buffer.every(byte => byte === 0));
  }
});

test('missing nofollow primitives refuse before opening any secret path', () => {
  const io = fixture(); io.constants = { ...constants, O_NOFOLLOW: undefined };
  assert.throws(() => readSecretFile(io), error => failureCode(error) === 'E_RUNTIME');
  assert.deepEqual(io.paths, []);
});

test('strict secret payload rejects dotenv syntax, activation, duplicate/extra assignments and out-of-bounds keys', () => {
  assert.equal(parseSecretPayload(payload), key);
  for (const text of [payload.toString().replace('false', 'true'), payload.toString().replaceAll('\n', '\r\n'),
    payload.toString() + 'EXTRA=1\n', payload.toString() + 'MODULE_API_KEY=' + key + '\n',
    'MODULEAPI_ENABLED=false\nMODULE_API_KEY="' + key + '"\n',
    ...[15, 513].map(length => 'MODULEAPI_ENABLED=false\nMODULE_API_KEY=' + 'x'.repeat(length) + '\n')]) {
    assert.throws(() => parseSecretPayload(Buffer.from(text)), error => failureCode(error) === 'E_PAYLOAD');
  }
  assert.equal(failureCode(Error(key)), 'E_RUNTIME');
  assert.throws(() => parseSecretPayload(Buffer.from('OPENAI_ENABLED=false\nOPENAI_API_KEY=' + key + '\n')));
  for (const length of [16, 512]) assert.equal(parseSecretPayload(Buffer.from('MODULEAPI_ENABLED=false\nMODULE_API_KEY=' + 'x'.repeat(length) + '\n')), 'x'.repeat(length));
});

function runtime(patch = {}) {
  return { argv: [...API_COMMAND], env: {}, cwd: API_WORKDIR, executable: API_EXECUTABLE, uid: 65532, gid: 65532,
    readKey: () => key, exec: () => { throw Error('synthetic exec'); }, ...patch };
}

test('bootstrap replaces ambient ModuleAPI key, never reads OpenAI key and defaults disabled', () => {
  let snapshot, child, reads = 0;
  const env = { MODULE_API_KEY: 'synthetic_ambient_not_authority' };
  Object.defineProperty(env, 'OPENAI_API_KEY', { enumerable: true, configurable: true,
    get: () => assert.fail('OpenAI credential must never be read') });
  assert.throws(() => bootstrap(runtime({ env, readKey: () => { reads++; return key; }, exec(executable, args, value) {
    assert.equal(executable, API_EXECUTABLE); assert.deepEqual(args, [API_EXECUTABLE, ...API_COMMAND.slice(1)]);
    child = value; snapshot = { ...value };
  } })), error => failureCode(error) === 'E_EXEC');
  assert.equal(reads, 1); assert.equal(snapshot.MODULE_API_KEY, key); assert.equal(snapshot.MODULEAPI_ENABLED, 'false');
  assert.equal(Object.hasOwn(snapshot, 'OPENAI_API_KEY'), false);
  assert.equal(Object.hasOwn(env, 'MODULE_API_KEY'), false); assert.equal(Object.hasOwn(child, 'MODULE_API_KEY'), false);
});

test('bootstrap respects separately explicit activation but the disabled file marker never enables it', () => {
  let child;
  assert.throws(() => bootstrap(runtime({ env: { MODULEAPI_ENABLED: 'true' }, exec(_file, _args, env) { child = { ...env }; } })));
  assert.equal(child.MODULEAPI_ENABLED, 'true');
});

for (const patch of [{ argv: ['sh'] }, { cwd: '/' }, { uid: 0 }, { gid: 0 }, { executable: '/evil/node' },
  { exec: undefined }, ...['NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED',
    'NODE_DEBUG', 'NODE_DEBUG_NATIVE', 'NODE_V8_COVERAGE', 'SSLKEYLOGFILE', 'SSL_CERT_FILE', 'SSL_CERT_DIR']
    .map(name => ({ env: { [name]: 'unsafe' } }))]) {
  test('bootstrap rejects execution/ambient trust overrides before opening credential', () => {
    let read = false;
    assert.throws(() => bootstrap(runtime({ ...patch, readKey: () => { read = true; return key; } })));
    assert.equal(read, false);
  });
}

test('missing or malformed ModuleAPI secret never falls back to ambient key or exec', () => {
  for (const readKey of [() => { throw Error(key); }, () => '', () => 'invalid']) {
    const env = { MODULE_API_KEY: key }; let called = false;
    assert.throws(() => bootstrap(runtime({ env, readKey, exec: () => { called = true; } })));
    assert.equal(called, false); assert.equal(Object.hasOwn(env, 'MODULE_API_KEY'), false);
  }
});
