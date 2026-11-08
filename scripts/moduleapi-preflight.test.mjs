import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { moduleApiPreflightForTest as preflight } from './moduleapi-preflight.mjs';

const KEY = 'synthetic_moduleapi_key_0123456789';
const payload = key => Buffer.from(`MODULEAPI_ENABLED=false\nMODULE_API_KEY=${key}\n`);
const bodyFor = id => Buffer.from(JSON.stringify({ object: 'list', data: [{ id }] }));
const listedBody = bodyFor('gpt-5.4-mini');
const expectedSummary = { provider: 'ModuleAPI', httpStatus: null, modelListed: false,
  generationVerified: false, activated: false };
const script = fileURLToPath(new URL('./moduleapi-preflight.mjs', import.meta.url));

function credentialFixture(t) {
  const temporary = fs.mkdtempSync(join(tmpdir(), 'moduleapi-preflight-test-'));
  const home = fs.realpathSync(temporary);
  fs.chmodSync(home, 0o700);
  const directory = join(home, '.diplom-moduleapi');
  const file = join(directory, 'server.env');
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.writeFileSync(file, payload(KEY), { mode: 0o600 });
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return { home, directory, file, uid: process.getuid(), filesystem: fs };
}

// No real sockets, HTTPS, DNS, account lookup or credential sources in this seam.
function mockHttps({ body = listedBody, chunks = [body], status = 200, headers,
  authorized = true, encrypted = true, identityError = false, complete = true,
  readableEnded = true, aborted = false, trailers = [], httpVersion = '1.1',
  responseEvent = 'end', stall = false, requestError = false, socketError = false,
  information = false, deadlineAtEnd = false, timeAtSecure = 0, timeAtResponse = 0,
  timeAtEnd = 0 } = {}) {
  let callback, timerCallback, cleared = 0, calls = 0, ended = 0, destroyed = 0, clock = 0;
  let captured;
  const req = new EventEmitter();
  const socket = new EventEmitter();
  const response = new EventEmitter();
  socket.authorized = authorized;
  socket.encrypted = encrypted;
  socket.getPeerCertificate = detailed => { assert.equal(detailed, true); return { synthetic: true }; };
  socket.destroy = () => { destroyed++; };
  response.statusCode = status;
  response.httpVersion = httpVersion;
  response.rawHeaders = headers ?? ['Content-Type', 'application/json; charset=utf-8', 'Content-Length', String(body.length)];
  response.rawTrailers = trailers;
  response.complete = complete;
  response.aborted = aborted;
  response.readableEnded = readableEnded;
  response.destroy = () => { destroyed++; };
  req.destroy = () => { destroyed++; };
  req.end = () => {
    ended++;
    if (stall) return;
    queueMicrotask(() => {
      if (information) { req.emit('information', { statusCode: 103 }); return; }
      clock = timeAtResponse;
      callback(response);
      for (const chunk of chunks) response.emit('data', chunk);
      clock = timeAtEnd;
      if (deadlineAtEnd) timerCallback();
      response.emit(responseEvent, responseEvent === 'error' ? new Error(KEY) : undefined);
    });
  };
  const dependencies = {
    request(options, onResponse) {
      calls++;
      captured = options;
      callback = onResponse;
      queueMicrotask(() => {
        if (requestError) { req.emit('error', new Error(KEY)); return; }
        req.emit('socket', socket);
        if (socketError) { socket.emit('error', new Error(KEY)); return; }
        clock = timeAtSecure;
        socket.emit('secureConnect');
      });
      return req;
    },
    checkIdentity(host, certificate) {
      assert.equal(host, 'moduleapi.pro');
      assert.deepEqual(certificate, { synthetic: true });
      return identityError ? new Error(KEY) : undefined;
    },
    setTimer(fn, milliseconds) {
      assert.equal(milliseconds, 15_000);
      timerCallback = fn;
      return 42;
    },
    clearTimer(id) { assert.equal(id, 42); cleared++; },
    now: () => clock,
  };
  return { dependencies, req, socket, response, timeout: () => timerCallback(),
    state: () => ({ calls, ended, destroyed, cleared, options: captured }) };
}

async function probe(options) {
  const mock = mockHttps(options);
  const result = await preflight.probeModels(Buffer.from(KEY), mock.dependencies);
  assert.equal(mock.state().calls, 1);
  assert.equal(mock.state().cleared, 1);
  assert.ok(mock.state().destroyed >= 1);
  return { result, mock };
}

test('import and default executable are inert, with a finite summary only', () => {
  for (const args of [
    ['--input-type=module', '-e', `await import(${JSON.stringify(new URL('./moduleapi-preflight.mjs', import.meta.url).href)})`],
    [script],
    [script, '--check-model-access', '--url=https://untrusted.invalid'],
    [script, '--help'],
  ]) {
    const result = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 5000,
      env: { PATH: '/usr/bin:/bin', HOME: '/nonexistent-synthetic-home', MODULE_API_KEY: KEY } });
    assert.equal(result.error, undefined);
    assert.equal(result.stderr, '');
    assert.ok(!result.stdout.includes(KEY));
    if (args[0] === '--input-type=module') {
      assert.equal(result.status, 0);
      assert.equal(result.stdout, '');
    } else {
      assert.deepEqual(JSON.parse(result.stdout), expectedSummary);
      assert.equal(result.status, args.length === 1 ? 0 : 1);
    }
  }
});

test('strict disabled credential grammar accepts only 16..512 ASCII key bytes', () => {
  for (const length of [16, 32, 512]) {
    const bytes = payload('a'.repeat(length));
    const key = preflight.parseCredential(bytes);
    assert.equal(key.length, length);
    key.fill(0);
    assert.ok(bytes.includes(97)); // Independent copy, not a view into the source.
    bytes.fill(0);
  }
});

test('credential grammar refuses injection, whitespace, enabled marker and malformed bytes', () => {
  for (const bytes of [
    payload('a'.repeat(15)), payload('a'.repeat(513)), payload(`${KEY} `), payload(`${KEY}\t`),
    payload(`${KEY}\nEVIL=true`), payload(`${KEY}\r`), payload(`${KEY}=x`), payload('é'.repeat(16)),
    payload(KEY).subarray(0, -1), Buffer.concat([payload(KEY), Buffer.from('\n')]),
    Buffer.from(payload(KEY).toString().replace('false', 'true')),
    Buffer.from(payload(KEY).toString().replace('MODULE_API_KEY', 'MODULEAPI_KEY')),
    Buffer.from(payload(KEY).toString().replaceAll('\n', '\r\n')),
    Buffer.from(`MODULE_API_KEY=${KEY}\nMODULEAPI_ENABLED=false\n`),
    Buffer.from(`\ufeff${payload(KEY).toString()}`), Buffer.alloc(1_000_000),
  ]) assert.throws(() => preflight.parseCredential(bytes), /^Error: MODULEAPI_PREFLIGHT_REFUSED$/);
});

test('protected synthetic host file is accepted, short reads are handled, buffers are zeroed', t => {
  const fixture = credentialFixture(t);
  const buffers = [];
  const closed = [];
  const filesystem = { ...fs,
    readSync(fd, buffer, offset, count, position) {
      buffers.push(buffer);
      return fs.readSync(fd, buffer, offset, Math.min(count, 7), position);
    },
    closeSync(fd) { closed.push(fd); fs.closeSync(fd); },
  };
  const key = preflight.readCredential({ ...fixture, filesystem });
  assert.equal(key.toString(), KEY);
  key.fill(0);
  assert.equal(closed.length, 3);
  assert.ok(buffers.length > 1);
  assert.ok(buffers.every(buffer => buffer.every(byte => byte === 0)));
});

for (const [name, mutate] of [
  ['file mode0400', f => fs.chmodSync(f.file, 0o400)],
  ['file mode0640', f => fs.chmodSync(f.file, 0o640)],
  ['file special bits', f => fs.chmodSync(f.file, 0o4600)],
  ['parent mode0755', f => fs.chmodSync(f.directory, 0o755)],
  ['home writable by group', f => fs.chmodSync(f.home, 0o720)],
  ['hardlinked file', f => fs.linkSync(f.file, join(f.home, 'hardlink'))],
  ['oversized file', f => fs.writeFileSync(f.file, Buffer.alloc(553))],
  ['empty file', f => fs.truncateSync(f.file, 0)],
  ['symlink file', f => { fs.renameSync(f.file, join(f.home, 'target')); fs.symlinkSync(join(f.home, 'target'), f.file); }],
  ['symlink directory', f => { fs.renameSync(f.directory, join(f.home, 'target')); fs.symlinkSync(join(f.home, 'target'), f.directory); }],
  ['nonregular file', f => { fs.unlinkSync(f.file); fs.mkdirSync(f.file, { mode: 0o600 }); }],
]) {
  test(`credential reader refuses ${name} before reading bytes`, t => {
    const fixture = credentialFixture(t);
    mutate(fixture);
    let reads = 0;
    assert.throws(() => preflight.readCredential({ ...fixture,
      filesystem: { ...fs, readSync() { reads++; throw new Error('must not read'); } } }));
    assert.equal(reads, 0);
  });
}

test('owner mismatch, unavailable nofollow, and noncanonical home refuse before opening', t => {
  const fixture = credentialFixture(t);
  for (const overrides of [
    { uid: fixture.uid + 1 }, { home: `${fixture.home}/../anything` }, { home: 'relative' },
    { filesystem: { ...fs, constants: { ...fs.constants, O_NOFOLLOW: 0 } } },
  ]) assert.throws(() => preflight.readCredential({ ...fixture, ...overrides }));
});

test('open identity substitution, post-read path replacement, and metadata mutation refuse', t => {
  const fixture = credentialFixture(t);
  for (const stage of ['open', 'after-read', 'directory', 'home']) {
    let read = false;
    let altered = false;
    let opened = 0;
    const filesystem = { ...fs,
      openSync(...args) { opened++; return fs.openSync(...args); },
      readSync(...args) { read = true; return fs.readSync(...args); },
      fstatSync(fd, options) {
        const info = fs.fstatSync(fd, options);
        if (stage === 'open' && opened === 3) return Object.assign(info, { ino: info.ino + 1n });
        return info;
      },
      lstatSync(path, options) {
        const info = fs.lstatSync(path, options);
        if (read && path === (stage === 'directory' ? fixture.directory : stage === 'home' ? fixture.home : fixture.file)) {
          altered = true;
          info.ctimeNs += 1n;
        }
        return info;
      },
    };
    assert.throws(() => preflight.readCredential({ ...fixture, filesystem }));
    assert.ok(stage === 'open' || altered);
  }
});

test('no-follow/nonblocking opens and descriptor cleanup are mandatory even on read failure', t => {
  const fixture = credentialFixture(t);
  let closed = 0;
  const filesystem = { ...fs,
    openSync(path, flags) {
      assert.ok(flags & fs.constants.O_NOFOLLOW);
      assert.ok(flags & fs.constants.O_NONBLOCK);
      if (path !== fixture.file) assert.ok(flags & fs.constants.O_DIRECTORY);
      return fs.openSync(path, flags);
    },
    readSync() { throw new Error(KEY); },
    closeSync(fd) { closed++; fs.closeSync(fd); },
  };
  assert.throws(() => preflight.readCredential({ ...fixture, filesystem }));
  assert.equal(closed, 3);
});

test('descriptor-close failure still closes all handles and becomes a redacted refusal', async t => {
  const fixture = credentialFixture(t);
  let closed = 0;
  const out = await preflight.run(['--check-model-access'], { env: {}, execArgv: [],
    credentials: () => preflight.readCredential({ ...fixture, filesystem: { ...fs,
      closeSync(fd) {
        fs.closeSync(fd);
        closed++;
        if (closed === 1) throw new Error(KEY);
      },
    } }),
    probe() { assert.fail('no request on cleanup failure'); },
  });
  assert.equal(closed, 3);
  assert.deepEqual(out, { code: 1, result: expectedSummary });
});

test('runtime guards run before any credential access; arbitrary CLI grants never work', async () => {
  for (const name of ['NODE_OPTIONS', 'NODE_DEBUG', 'NODE_DEBUG_NATIVE', 'NODE_PATH',
    'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_EXTRA_CA_CERTS', 'SSLKEYLOGFILE', 'SSL_CERT_FILE', 'SSL_CERT_DIR']) {
    for (const value of ['', KEY]) {
      let reads = 0;
      const out = await preflight.run(['--check-model-access'], { env: { [name]: value }, execArgv: [],
        credentials() { reads++; throw new Error(KEY); }, probe() { assert.fail('no HTTPS'); } });
      assert.equal(reads, 0);
      assert.deepEqual(out, { code: 1, result: expectedSummary });
    }
  }
  for (const [argv, execArgv] of [
    [[], []], [['--check-model-access', '--file=elsewhere'], []],
    [['--check-model-access', '--grant={"approved":true}'], []],
    [['--check-model-access=true'], []], [['--check-model-access'], ['--inspect']],
    [['--check-model-access'], ['--tls-keylog=elsewhere']],
  ]) {
    const out = await preflight.run(argv, { env: {}, execArgv,
      credentials() { assert.fail('no credential access'); }, probe() { assert.fail('no HTTPS'); } });
    assert.deepEqual(out.result, expectedSummary);
    assert.equal(out.code, argv.length === 0 ? 0 : 1);
  }
});

test('fixed HTTPS GET/TLS/header bounds; request is ended only after verified TLS', async () => {
  const { result, mock } = await probe();
  assert.deepEqual(result, { ok: true, httpStatus: 200, modelListed: true });
  const { options, ended } = mock.state();
  assert.equal(ended, 1);
  assert.equal(options.protocol, 'https:');
  assert.equal(options.hostname, 'moduleapi.pro');
  assert.equal(options.servername, 'moduleapi.pro');
  assert.equal(options.port, 443);
  assert.equal(options.path, '/v1/models');
  assert.equal(options.method, 'GET');
  assert.equal(options.agent, false);
  assert.equal(options.rejectUnauthorized, true);
  assert.equal(options.maxHeaderSize, 16384);
  assert.equal(options.minVersion, 'TLSv1.2');
  assert.equal(options.insecureHTTPParser, false);
  assert.equal(options.headers.Authorization, `Bearer ${KEY}`);
  assert.equal(options.headers['Accept-Encoding'], 'identity');
  assert.equal(options.checkServerIdentity, mock.dependencies.checkIdentity);
});

for (const [name, options] of [
  ['unauthorized chain', { authorized: false }], ['unencrypted socket', { encrypted: false }],
  ['hostname mismatch', { identityError: true }], ['request error', { requestError: true }],
  ['socket error', { socketError: true }],
]) {
  test(`TLS/send gate refuses ${name} without sending HTTP`, async () => {
    const { result, mock } = await probe(options);
    assert.deepEqual(result, { ok: false, httpStatus: null, modelListed: false });
    assert.equal(mock.state().ended, 0);
  });
}

test('one absolute 15s deadline covers a stalled connection/body and is fail closed on late success', async () => {
  const mock = mockHttps({ stall: true });
  const pending = preflight.probeModels(Buffer.from(KEY), mock.dependencies);
  mock.timeout();
  assert.deepEqual(await pending, { ok: false, httpStatus: null, modelListed: false });
  await new Promise(resolve => queueMicrotask(resolve));
  assert.equal(mock.state().ended, 0);
  mock.req.emit('error', new Error(KEY)); // Teardown errors are consumed.
  const late = await probe({ deadlineAtEnd: true });
  assert.equal(late.result.ok, false);
});

test('monotonic clock rejects overdue TLS, response and end even before timer dispatch', async () => {
  for (const options of [{ timeAtSecure: 15_000 }, { timeAtResponse: 15_000 }, { timeAtEnd: 15_000 }]) {
    const { result, mock } = await probe(options);
    assert.equal(result.ok, false);
    if (options.timeAtSecure) assert.equal(mock.state().ended, 0);
  }
  assert.equal((await probe({ timeAtSecure: 14_999, timeAtResponse: 14_999, timeAtEnd: 14_999 })).result.ok, true);
});

test('body stalls, request-close, upgrades and CONNECT are terminal, without retry', async () => {
  for (const event of ['timeout', 'close', 'upgrade', 'connect']) {
    const mock = mockHttps({ stall: true });
    const pending = preflight.probeModels(Buffer.from(KEY), mock.dependencies);
    await new Promise(resolve => queueMicrotask(resolve));
    assert.equal(mock.state().ended, 1);
    if (event === 'timeout') mock.timeout();
    else if (event === 'close') mock.req.emit('close');
    else mock.req.emit(event, mock.response, mock.socket);
    assert.equal((await pending).ok, false);
    assert.equal(mock.state().calls, 1);
  }
  const mock = mockHttps({ responseEvent: 'stalled' });
  const pending = preflight.probeModels(Buffer.from(KEY), mock.dependencies);
  await new Promise(resolve => setImmediate(resolve));
  mock.timeout();
  assert.deepEqual(await pending, { ok: false, httpStatus: 200, modelListed: false });
});

for (const status of [201, 204, 301, 302, 307, 308, 400, 401, 403, 429, 500, 503]) {
  test(`HTTP ${status} is finite, redacted and never followed/retried`, async () => {
    const { result } = await probe({ status, body: Buffer.from(KEY) });
    assert.deepEqual(result, { ok: false, httpStatus: status, modelListed: false });
    assert.ok(!JSON.stringify(result).includes(KEY));
  });
}

for (const [name, options] of [
  ['wrong content type', { headers: ['Content-Type', 'text/html', 'Content-Length', String(listedBody.length)] }],
  ['unknown charset', { headers: ['Content-Type', 'application/json; charset=latin1', 'Content-Length', String(listedBody.length)] }],
  ['compressed response', { headers: ['Content-Type', 'application/json', 'Content-Encoding', 'gzip', 'Content-Length', String(listedBody.length)] }],
  ['duplicate content-length', { headers: ['Content-Type', 'application/json', 'Content-Length', '1', 'content-length', '1'] }],
  ['duplicate content-type', { headers: ['Content-Type', 'application/json', 'content-type', 'application/json', 'Content-Length', '1'] }],
  ['CL and TE', { headers: ['Content-Type', 'application/json', 'Content-Length', '1', 'Transfer-Encoding', 'chunked'] }],
  ['unknown TE', { headers: ['Content-Type', 'application/json', 'Transfer-Encoding', 'gzip, chunked'] }],
  ['no explicit framing', { headers: ['Content-Type', 'application/json'] }],
  ['CL overflow', { headers: ['Content-Type', 'application/json', 'Content-Length', '1048577'] }],
  ['CL sign', { headers: ['Content-Type', 'application/json', 'Content-Length', '+123'] }],
  ['CL leading zero', { headers: ['Content-Type', 'application/json', 'Content-Length', '0123'] }],
  ['CL short body', { headers: ['Content-Type', 'application/json', 'Content-Length', String(listedBody.length + 1)] }],
  ['CL long body', { headers: ['Content-Type', 'application/json', 'Content-Length', String(listedBody.length - 1)] }],
  ['header cap', { headers: ['Content-Type', 'application/json', 'Content-Length', String(listedBody.length), 'X-Untrusted', 'x'.repeat(16384)] }],
  ['bad raw header pair', { headers: ['Content-Type'] }],
  ['header control', { headers: ['Content-Type', 'application/json\r\nEVIL', 'Content-Length', '1'] }],
  ['header count', { headers: Array.from({ length: 514 }, () => 'x') }],
  ['HTTP/1.0', { httpVersion: '1.0' }], ['incomplete framing', { complete: false }],
  ['not readable-ended', { readableEnded: false }], ['aborted flag', { aborted: true }],
  ['aborted event', { responseEvent: 'aborted' }], ['response error', { responseEvent: 'error' }],
  ['premature close', { responseEvent: 'close', complete: false }],
  ['trailers', { trailers: ['X-Untrusted', KEY] }], ['informational response', { information: true }],
]) {
  test(`response validation refuses ${name}`, async () => {
    const { result } = await probe(options);
    assert.equal(result.ok, false);
    assert.equal(result.modelListed, false);
    assert.ok(!JSON.stringify(result).includes(KEY));
  });
}

test('chunked and exact content-length framing both accept complete UTF-8 JSON', async () => {
  const { result } = await probe({ headers: ['Content-Type', 'application/json; charset="utf-8"',
    'Content-Encoding', 'identity', 'Transfer-Encoding', 'chunked'],
  chunks: [listedBody.subarray(0, 10), listedBody.subarray(10)] });
  assert.equal(result.ok, true);
  assert.equal(result.modelListed, true);
});

test('body cap is exactly 1MiB, including chunked bodies', async () => {
  const base = JSON.stringify({ data: [{ id: 'gpt-5.4-mini' }], padding: '' });
  const atLimit = Buffer.from(base.replace('"padding":""', `"padding":"${'x'.repeat(1048576 - Buffer.byteLength(base))}"`));
  assert.equal(atLimit.length, 1048576);
  assert.equal((await probe({ body: atLimit })).result.ok, true);
  const tooLarge = Buffer.concat([atLimit, Buffer.from(' ')]);
  assert.equal((await probe({ body: tooLarge, headers: ['Content-Type', 'application/json', 'Transfer-Encoding', 'chunked'] })).result.ok, false);
});

for (const [name, body] of [
  ['invalid UTF-8', Buffer.concat([listedBody, Buffer.from([0xc3, 0x28])])],
  ['UTF-8 BOM', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), listedBody])],
  ['malformed JSON', Buffer.from('{')], ['empty body', Buffer.alloc(0)],
  ['wrong root', Buffer.from('[]')], ['missing data', Buffer.from('{}')],
  ['nonarray data', Buffer.from('{"data":{}}')],
  ['error envelope', Buffer.from('{"data":[],"error":"untrusted"}')],
  ['nonobject item', Buffer.from('{"data":[null]}')], ['missing ID', Buffer.from('{"data":[{}]}')],
  ['nonstring ID', Buffer.from('{"data":[{"id":42}]}')], ['empty ID', bodyFor('')],
  ['large ID', bodyFor('x'.repeat(257))], ['control in ID', bodyFor('evil\nmodel')],
  ['duplicate ID', Buffer.from('{"data":[{"id":"gpt-5.4-mini"},{"id":"gpt-5.4-mini"}]}')],
]) {
  test(`catalogue rejects ${name} without exposing provider text`, async () => {
    assert.equal((await probe({ body })).result.ok, false);
  });
}

test('512 models accepted; 513 rejected; candidate is exact, not a versioned alias', async () => {
  const data = Array.from({ length: 512 }, (_, index) => ({ id: index === 0 ? 'gpt-5.4-mini' : `synthetic-${index}` }));
  assert.equal((await probe({ body: Buffer.from(JSON.stringify({ data })) })).result.modelListed, true);
  data.push({ id: 'extra' });
  assert.equal((await probe({ body: Buffer.from(JSON.stringify({ data })) })).result.ok, false);
  const alias = await probe({ body: bodyFor('gpt-5.4-mini-2026-03-17') });
  assert.deepEqual(alias.result, { ok: true, httpStatus: 200, modelListed: false });
});

test('full run prints no provider strings, status errors or credential material; memory cleared best effort', async () => {
  for (const mode of ['listed', 'unlisted', 'unauthorized', 'provider-error', 'read-error', 'probe-error']) {
    let key;
    const out = await preflight.run(['--check-model-access'], {
      env: { MODULE_API_KEY: 'ignored-ambient-value', MODULEAPI_ENABLED: 'true', HOME: '/ignored' }, execArgv: [],
      credentials() {
        if (mode === 'read-error') throw new Error(KEY);
        key = Buffer.from(KEY);
        return key;
      },
      async probe(receivedKey) {
        assert.equal(receivedKey, key);
        if (mode === 'probe-error') throw new Error(KEY);
        const options = mode === 'unlisted' ? { body: bodyFor(KEY) } :
          mode === 'unauthorized' ? { authorized: false } :
          mode === 'provider-error' ? { status: 401, body: Buffer.from(KEY) } : {};
        return (await probe(options)).result;
      },
    });
    assert.deepEqual(Object.keys(out.result), Object.keys(expectedSummary));
    assert.equal(out.result.generationVerified, false);
    assert.equal(out.result.activated, false);
    assert.equal(out.code, mode === 'listed' ? 0 : 1);
    assert.ok(!JSON.stringify(out).includes(KEY));
    assert.ok(!JSON.stringify(out).includes('ignored'));
    if (key) assert.ok(key.every(byte => byte === 0));
  }
});
