// Socket-free bootstrap/middleware regression; never imports AppModule or opens a database.
const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const { createRequire } = require('node:module');
const { PassThrough } = require('node:stream');
const { EventEmitter } = require('node:events');
const vm = require('node:vm');

const root = resolve(__dirname, '../../..');
const apiRequire = createRequire(resolve(root, 'server/api/package.json'));
const ts = apiRequire('typescript');
const { ExpressAdapter } = apiRequire('@nestjs/platform-express');
const { RuntimeIdentity } = apiRequire('./src/runtime/browser-runtime-identity.ts');
const { createRuntimeIntake, runtimeBody } = apiRequire('./src/runtime/runtime-intake.ts');
const { RuntimeApiService } = apiRequire('./src/runtime/runtime-api.service.ts');
const runtimeHttp = apiRequire('./src/runtime/runtime-http.ts');
const { parseRuntimeJson } = apiRequire('./src/runtime/runtime-json.ts');
const { originForRequest } = apiRequire('./src/auth/auth.controller.ts');
const { parseCapabilities } = apiRequire('../../src/shared/api/scans/runtimeTransport.ts');
const { registerHistoryIngress, historyBodyParsed } = apiRequire('./src/llm/history-ingress.ts');
const origin = 'http://127.0.0.1:8080';
const token = 'a'.repeat(43); // Synthetic session input; no credential or key file is accessed.
const originalOrigin = process.env.AUTH_ORIGIN;
const originalLocal = process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP;
before(() => {
  process.env.AUTH_ORIGIN = origin;
  process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = 'true';
});
after(() => {
  if (originalOrigin === undefined) delete process.env.AUTH_ORIGIN;
  else process.env.AUTH_ORIGIN = originalOrigin;
  if (originalLocal === undefined) delete process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP;
  else process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP = originalLocal;
});

function memoryModule(path, imports, globals = {}) {
  const source = readFileSync(resolve(root, path), 'utf8');
  const compiled = ts.transpileModule(source, { compilerOptions: {
    module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, experimentalDecorators: true,
  } }).outputText;
  const module = { exports: {} };
  vm.runInNewContext(compiled, { module, exports: module.exports, Buffer, Date, setTimeout, clearTimeout,
    require(name) {
      assert.ok(Object.hasOwn(imports, name), `unexpected source dependency: ${name}`);
      return imports[name];
    }, ...globals });
  return module.exports;
}

async function bootstrap(local = false) {
  const adapter = new ExpressAdapter(); // In-memory middleware stack only: no init/listen/server.
  const trace = [];
  const identity = new RuntimeIdentity({
    userForToken(value) {
      trace.push(['authentication', value]);
      return value === token ? { id: 'a'.repeat(32) } : null;
    },
  });
  const identityResolve = identity.resolve.bind(identity);
  identity.resolve = (req, mutation) => {
    trace.push(['identity', mutation, req.listenerCount('data')]);
    return identityResolve(req, mutation);
  };
  const appModule = {}, runtimeModule = {};
  const service = new RuntimeApiService(undefined, undefined, {});
  const markConfigured = service.configureRawIntake.bind(service);
  service.configureRawIntake = () => { trace.push(['descriptor-configured']); markConfigured(); };
  const app = {
    select(module) {
      assert.equal(module, runtimeModule);
      trace.push(['select-configured-runtime-module']);
      return { get(provider, options) {
        assert.equal(options.strict, true);
        if (provider === RuntimeIdentity) return identity;
        assert.equal(provider, RuntimeApiService);
        return service;
      } };
    },
    use(handler) { adapter.use(handler); trace.push(['raw-hook']); },
    useBodyParser(type, options) {
      trace.push(['ordinary-parser', type, options]);
      adapter.useBodyParser(type, false, options);
    },
    async listen(port, bind) { trace.push(['would-listen', port, bind]); },
  };
  const { configureParentIngress } = memoryModule('server/api/src/parent-ingress.ts', {
    './llm/history-ingress.js': { registerHistoryIngress },
    './runtime/runtime-api.module.js': { RuntimeApiModule: runtimeModule },
    './runtime/runtime-api.service.js': { RuntimeApiService },
    './runtime/browser-runtime-identity.js': { RuntimeIdentity },
    './runtime/runtime-intake.js': { createRuntimeIntake },
  });
  const imports = {
    'reflect-metadata': {},
    '@nestjs/core': { NestFactory: { async create(module, options) {
      assert.equal(module, appModule);
      assert.equal(options.bodyParser, false);
      assert.deepEqual(Object.keys(options).sort(), local ? ['bodyParser', 'logger'] : ['bodyParser']);
      if (local) assert.equal(options.logger, false);
      trace.push(['create-body-parser-disabled']);
      return app;
    } } },
    './app.module.js': { AppModule: appModule },
    './parent-ingress.js': { configureParentIngress },
    '../parent-ingress.js': { configureParentIngress },
    './nginx-local.module.js': { NginxLocalModule: appModule },
  };
  const source = readFileSync(resolve(root, local ? 'server/api/src/oci/nginx-local.main.ts' : 'server/api/src/main.ts'), 'utf8');
  if (!local) assert.equal((source.match(/void main\(\);/g) || []).length, 1);
  const compiled = ts.transpileModule(local ? source : source.replace('void main();', 'module.exports.ready = main();'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const module = { exports: {} };
  const execution = vm.runInNewContext(local ? `(async () => { ${compiled}\n})()` : compiled, {
    module, exports: module.exports, Buffer,
    process: { env: { SCAN_JWT_SECRET: 'synthetic-test-only-value-32-bytes',
      SCAN_JWT_ISSUER: 'synthetic-test', SCAN_JWT_AUDIENCE: 'synthetic-test' },
      on(name) { trace.push(['shutdown-handler', name]); }, exit() { throw new Error('unexpected process exit'); } },
    require(name) {
      assert.ok(Object.hasOwn(imports, name), `unexpected bootstrap dependency: ${name}`);
      return imports[name];
    },
  });
  await (local ? execution : module.exports.ready);
  return { handlers: adapter.getInstance().router.stack.map(layer => layer.handle), trace, service };
}

function dispatch(handlers, path, body, extra = {}, send = true, options = {}) {
  const req = new PassThrough();
  req.url = path;
  req.originalUrl = path;
  req.method = options.method ?? 'POST';
  req.complete = false;
  req.httpVersion = '1.1';
  req.socket = Object.assign(new EventEmitter(), { readable: true, writable: true,
    remoteAddress: options.peer ?? '127.0.0.1', destroy() { throw new Error('unexpected socket operation'); } });
  req.headers = { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)),
    origin, cookie: `demo_session=${token}`, ...extra };
  for (const key of Object.keys(req.headers)) if (req.headers[key] === undefined) delete req.headers[key];
  req.rawHeaders = options.rawHeaders ?? Object.entries(req.headers).flat();
  req.once('end', () => { req.complete = true; });
  const res = new EventEmitter();
  const headers = new Map();
  let complete;
  const done = new Promise(resolve => { complete = resolve; });
  res.headersSent = false;
  res.statusCode = 200;
  res.setHeader = (key, value) => headers.set(key.toLowerCase(), value);
  res.getHeader = key => headers.get(key.toLowerCase());
  res.removeHeader = key => headers.delete(key.toLowerCase());
  res.writeHead = (status, values) => { res.statusCode = status; res.headersSent = true;
    for (const [key, value] of Object.entries(values)) res.setHeader(key, value); };
  res.end = value => { res.headersSent = true; complete({ req, res, headers, response: value }); };
  let index = 0;
  const next = error => {
    if (error) { complete({ req, res, headers, error }); return; }
    if (index === handlers.length) { complete({ req, res, headers, reachedController: true }); return; }
    handlers[index++](req, res, next);
  };
  next();
  if (send && !res.headersSent) req.end(body);
  return { req, res, done };
}

const prefix = '/api/v1/browser/runtime';
test('actual main disables automatic parsing at creation and retains both raw hooks before ordinary parsers', async () => {
  const { handlers, trace } = await bootstrap();
  assert.deepEqual(trace.map(row => row[0]), ['create-body-parser-disabled', 'select-configured-runtime-module',
    'raw-hook', 'raw-hook', 'ordinary-parser', 'ordinary-parser', 'descriptor-configured', 'would-listen']);
  assert.equal(trace[4][1], 'json');
  assert.equal(trace[4][2], undefined, 'existing JSON defaults are not enlarged or narrowed');
  assert.equal(trace[5][1], 'urlencoded');
  assert.equal(trace[5][2].extended, true);
  // Installed Nest11.2.6 adapter also has its initial request/response hook middleware.
  assert.equal(handlers.length, 5);
  assert.equal(handlers[3].name, 'jsonParser');
  assert.equal(handlers[4].name, 'urlencodedParser');
});

test('missing/invalid cookie is rejected before data listeners, JSON parsing or raw-slot admission', async () => {
  const { handlers, trace } = await bootstrap();
  for (const cookie of [undefined, `demo_session=${'b'.repeat(43)}`]) {
    // A partial, deliberately malformed JSON request is never read or submitted to ordinary JSON.
    const { req, done } = dispatch(handlers, `${prefix}/imports`, '{', { cookie }, false);
    const result = await done;
    assert.equal(result.res.statusCode, 401);
    assert.equal(req.listenerCount('data'), 0);
    assert.equal(req.body, undefined);
    assert.throws(() => runtimeBody(req), /RUNTIME_RAW_INTAKE_REQUIRED/);
    assert.equal(result.headers.get('cache-control'), 'no-store');
  }
  assert.ok(trace.filter(row => row[0] === 'identity').every(row => row[1] === true && row[2] === 0));
  // A permitted request after anonymous partial attempts proves they did not consume the global slots.
  const valid = await dispatch(handlers, `${prefix}/consents`, '{}').done;
  assert.equal(valid.reachedController, true);
  assert.deepEqual(runtimeBody(valid.req), {});
});

test('wrong Origin and conflicting Bearer are denied before cookie lookup/body read', async () => {
  const { handlers, trace } = await bootstrap();
  for (const headers of [{ origin: 'https://foreign.invalid' }, { authorization: 'Bearer synthetic-invalid' }]) {
    const result = await dispatch(handlers, `${prefix}/consents`, '{', headers, false).done;
    assert.ok([400, 403].includes(result.res.statusCode));
    assert.equal(result.req.listenerCount('data'), 0);
  }
  assert.equal(trace.filter(row => row[0] === 'authentication').length, 0);
});

test('inclusive control1024/import65536 raw limits survive ordinary JSON with no parsed-body fallback', async () => {
  const { handlers, trace } = await bootstrap();
  for (const [route, cap] of [['consents', 1024], ['imports', 65536]]) {
    const accepted = await dispatch(handlers, `${prefix}/${route}`, '{}'.padEnd(cap, ' ')).done;
    assert.equal(accepted.reachedController, true);
    assert.deepEqual(runtimeBody(accepted.req), {});
    assert.equal(accepted.req.body, undefined, 'ordinary parser must not reparse a finished raw stream');
    const rejected = await dispatch(handlers, `${prefix}/${route}`, '{}'.padEnd(cap + 1, ' ')).done;
    assert.equal(rejected.res.statusCode, 413);
    assert.equal(rejected.req.listenerCount('data'), 0);
  }
  assert.ok(trace.filter(row => row[0] === 'identity').every(row => row[2] === 0));
});

test('duplicate/numeric runtime lexemes fail closed instead of JSON-normalizing', async () => {
  const { handlers } = await bootstrap();
  for (const body of ['{"x":1,"x":2}', '{"x":1.0}']) {
    const result = await dispatch(handlers, `${prefix}/imports`, body).done;
    assert.equal(result.res.statusCode, 400);
    assert.equal(result.req.body, undefined);
    assert.throws(() => runtimeBody(result.req), /RUNTIME_RAW_INTAKE_REQUIRED/);
  }
});

test('history raw parser still owns chat/decision streams and retains its8192 cap', async () => {
  const { handlers, trace } = await bootstrap();
  const scan = '01234567-89ab-cdef-0123-456789abcdef';
  for (const suffix of ['chat', 'history/decision']) {
    const body = JSON.stringify({ question: 'q'.repeat(2048) }).padEnd(8192, ' ');
    const result = await dispatch(handlers, `/api/v1/browser/scans/${scan}/llm/${suffix}`, body).done;
    assert.equal(result.reachedController, true);
    assert.equal(historyBodyParsed(result.req), true);
    assert.deepEqual(result.req.body, { question: 'q'.repeat(2048) });
    assert.throws(() => runtimeBody(result.req), /RUNTIME_RAW_INTAKE_REQUIRED/);
  }
  // Do not emit response finish: existing history refusal's socket-destroy callback must not run here.
  const denied = await dispatch(handlers, `/api/v1/browser/scans/${scan}/llm/chat`, '{}'.padEnd(8193, ' ')).done;
  assert.equal(denied.res.statusCode, 413);
  assert.equal(trace.filter(row => row[0] === 'identity').length, 0);
});

test('unrelated JSON and URL-encoded routes keep ordinary parsing; runtime query paths remain rejected', async () => {
  const { handlers } = await bootstrap();
  const json = await dispatch(handlers, '/api/v1/auth/login', '{"email":"synthetic@example.invalid"}').done;
  assert.equal(json.reachedController, true);
  assert.deepEqual(json.req.body, { email: 'synthetic@example.invalid' });
  const form = await dispatch(handlers, '/unrelated-form', 'a%5Bb%5D=value', {
    'content-type': 'application/x-www-form-urlencoded',
  }).done;
  assert.equal(form.reachedController, true);
  assert.deepEqual(form.req.body, { a: { b: 'value' } });
  const query = await dispatch(handlers, `${prefix}/imports?unexpected=1`, '{}').done;
  assert.equal(query.res.statusCode, 400);
});

test('nginx runtime source is default-off, allowlisted and bounded without changing old route limits', () => {
  const source = readFileSync(resolve(root, 'server/deploy/stand.nginx.conf'), 'utf8');
  assert.match(source, /set \$runtime_ingress_enabled 0;/);
  const runtime = source.slice(source.indexOf('        location = /api/v1/browser/runtime/imports'),
    source.indexOf('        # Only the cookie-bound browser controller'));
  assert.equal((runtime.match(/proxy_pass http:\/\/\$api_upstream;/g) || []).length, 4);
  assert.equal((runtime.match(/if \(\$runtime_ingress_enabled = 0\)/g) || []).length, 4);
  assert.equal((runtime.match(/client_max_body_size 64k;/g) || []).length, 1);
  assert.equal((runtime.match(/client_max_body_size 1k;/g) || []).length, 3);
  for (const directive of ['limit_req zone=runtime_ip burst=2 nodelay;',
    'limit_req zone=runtime_total burst=2 nodelay;', 'limit_conn runtime_connections 2;',
    'proxy_pass_request_headers on;', 'proxy_connect_timeout 2s;', 'proxy_read_timeout 10s;']) {
    assert.equal(runtime.split(directive).length - 1, 4, directive);
  }
  assert.equal((runtime.match(/if \(\$http_transfer_encoding != ""\)/g) || []).length, 3);
  assert.match(runtime, /location \/api\/v1\/browser\/runtime\/ \{ access_log off; return 404; \}/);
  assert.doesNotMatch(runtime, /proxy_set_header (?:Authorization|Cookie|Origin)|docker|runtime-job|proxy_pass[^;]*unix:/);
  assert.match(source, /location = \/api\/v1\/browser\/scans \{\s*client_max_body_size 1k;/);
  assert.match(source, /llm\/summary\$" \{\s*limit_except POST \{ deny all; \}\s*client_max_body_size 1k;/);
  assert.match(source, /location \^~ \/api\/ \{ return 404; \}/);
});

// R2 regressions use the selected LOCAL entrypoint and real middleware without a running app/DB.
test('selected LOCAL bootstrap installs shared ingress and keeps logger/bind/shutdown policy', async () => {
  const { trace, handlers, service } = await bootstrap(true);
  assert.deepEqual(trace.map(row => row[0]), ['create-body-parser-disabled', 'select-configured-runtime-module',
    'raw-hook', 'raw-hook', 'ordinary-parser', 'ordinary-parser', 'descriptor-configured', 'would-listen',
    'shutdown-handler', 'shutdown-handler']);
  assert.deepEqual(trace.slice(-2).map(row => row[1]), ['SIGTERM', 'SIGINT']);
  assert.equal(service.capabilities().rawIntake, 'authenticated-pre-json');
  assert.equal(service.capabilities().liveCapture, false);
  const raw = await dispatch(handlers, `${prefix}/consents`, '{}').done;
  assert.equal(raw.reachedController, true);
  assert.deepEqual(runtimeBody(raw.req), {});
  assert.equal(raw.req.body, undefined);
  const scan = '01234567-89ab-cdef-0123-456789abcdef';
  const history = await dispatch(handlers, `/api/v1/browser/scans/${scan}/llm/chat`, '{}').done;
  assert.equal(history.reachedController, true);
  assert.equal(historyBodyParsed(history.req), true);
});

test('LOCAL module metadata is additive runtime DI, retaining every LOCAL service/provider/controller', () => {
  const file = 'server/api/src/oci/nginx-local.module.ts';
  const source = ts.createSourceFile(file, readFileSync(resolve(root, file), 'utf8'), ts.ScriptTarget.ES2022, true);
  const imports = { '@nestjs/common': { Module: apiRequire('@nestjs/common').Module } };
  const tokens = {};
  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement) || statement.moduleSpecifier.text === '@nestjs/common') continue;
    const values = {};
    for (const binding of statement.importClause.namedBindings.elements) {
      const name = binding.name.text;
      const token = function (...args) { this.args = args; };
      Object.defineProperty(token, 'name', { value: name });
      values[name] = token; tokens[name] = token;
    }
    imports[statement.moduleSpecifier.text] = values;
  }
  const { NginxLocalModule } = memoryModule(file, imports);
  const names = key => Reflect.getMetadata(key, NginxLocalModule).map(value => value.name);
  assert.deepEqual(Array.from(names('imports')), ['AuthModule', 'LedgerModule', 'SecurityModule', 'OciModule', 'RuntimeApiModule']);
  assert.deepEqual(Array.from(names('controllers')), ['ScansController', 'BrowserScansController', 'LlmController']);
  const providers = Reflect.getMetadata('providers', NginxLocalModule);
  assert.deepEqual(Array.from(providers.slice(0, -1), token => token.name),
    ['BrowserIdentity', 'ReportReader', 'LlmRuntime', 'LlmService', 'LlmQuotaRuntime', 'llmExceptionProvider']);
  const local = providers.at(-1);
  assert.equal(local.provide, tokens.ScansService);
  assert.deepEqual(Array.from(local.inject), [tokens.LedgerStore, tokens.OciResolver]);
  const ledger = {}, resolver = {};
  const service = local.useFactory(ledger, resolver);
  assert.equal(service.constructor, tokens.NginxLocalScansService);
  assert.deepEqual(service.args, [ledger, resolver]);
});

test('mixed-case/query/trailing/encoded protected paths never escape into ordinary JSON', async () => {
  const { handlers, trace } = await bootstrap(true);
  const adapter = new ExpressAdapter();
  adapter.getInstance().post(`${prefix}/consents`, () => {});
  const route = adapter.getInstance().router.stack.find(layer => layer.route);
  assert.equal(route.match('/api/v1/browser/Runtime/consents'), true, 'installed Express is case-insensitive');
  assert.equal(route.match(`${prefix}/consents/`), true, 'installed Express admits a trailing slash');
  for (const path of ['/api/v1/browser/Runtime/consents', '/API/v1/browser/runtime/imports?x=1',
    `${prefix}/Consents`, `${prefix}/imports?x=1`, `${prefix}/consents/`, `${prefix}`, `${prefix}?x=1`,
    '/api/v1/browser/r%75ntime/imports', '/api/v1/browser%2Fruntime/imports', `${prefix}/imports%ZZ`,
    `${prefix}/../scans`, `http://synthetic.invalid${prefix}/imports`, `http:${prefix}/imports`,
    `custom:${prefix}/imports`]) {
    const denied = await dispatch(handlers, path, '{', { cookie: undefined }, false).done;
    assert.equal(denied.res.statusCode, 400, path);
    assert.equal(denied.req.listenerCount('data'), 0, path);
    assert.equal(denied.req.body, undefined, path);
    assert.throws(() => runtimeBody(denied.req), /RUNTIME_RAW_INTAKE_REQUIRED/);
  }
  assert.equal(trace.filter(row => row[0] === 'identity').length, 0);
  const unrelated = await dispatch(handlers, `${prefix}-other`, '{}').done;
  assert.equal(unrelated.reachedController, true);
  assert.deepEqual(unrelated.req.body, {}, 'prefix siblings must not be rewritten into the protected namespace');
});

test('actual Node empty/duplicate Authorization header presence denies raw intake and runtime read identity', async () => {
  const { IncomingMessage } = require('node:http');
  const { handlers, trace } = await bootstrap(true);
  let lookups = 0;
  const identity = new RuntimeIdentity({ userForToken() { lookups++; return { id: 'synthetic' }; } });
  for (const raw of [['Authorization', ''], ['aUtHoRiZaTiOn', 'Bearer synthetic'],
    ['Authorization', '', 'authorization', 'Bearer synthetic']]) {
    const message = new IncomingMessage(new EventEmitter()); // No net.Socket or server.
    message._addHeaderLines(raw, raw.length);
    assert.equal(runtimeHttp.hasRuntimeHeader(message, 'authorization'), true);
    assert.throws(() => identity.resolve(message), error => error.getStatus() === 403);
    const denied = await dispatch(handlers, `${prefix}/consents`, '{', { authorization: message.headers.authorization },
      false, { rawHeaders: message.rawHeaders }).done;
    assert.equal(denied.res.statusCode, 400);
    assert.equal(denied.req.listenerCount('data'), 0);
  }
  const emptyNormalized = await dispatch(handlers, `${prefix}/imports`, '{', { authorization: '' }, false).done;
  assert.equal(emptyNormalized.res.statusCode, 400);
  assert.equal(lookups, 0);
  assert.equal(trace.filter(row => row[0] === 'identity').length, 0);
});

test('sensitive duplicate and empty framing headers fail before authentication/body listeners', async () => {
  const { handlers, trace } = await bootstrap();
  for (const header of ['content-encoding', 'transfer-encoding', 'expect']) {
    const denied = await dispatch(handlers, `${prefix}/consents`, '{', { [header]: '' }, false).done;
    assert.equal(denied.res.statusCode, 400);
    assert.equal(denied.req.listenerCount('data'), 0);
  }
  for (const header of ['cookie', 'origin', 'content-type', 'content-length']) {
    const raw = ['Cookie', `demo_session=${token}`, 'Origin', origin, 'Content-Type', 'application/json',
      'Content-Length', '1', header, 'duplicate'];
    const denied = await dispatch(handlers, `${prefix}/consents`, '{', {}, false, { rawHeaders: raw }).done;
    assert.equal(denied.res.statusCode, 400);
    assert.equal(denied.req.listenerCount('data'), 0);
  }
  assert.equal(trace.filter(row => row[0] === 'identity').length, 0);
});

test('capabilities descriptor changes only after configuration and both browser literals remain compatible', () => {
  const service = new RuntimeApiService(undefined, undefined, {});
  assert.equal(service.capabilities().rawIntake, 'parent-bootstrap-required');
  service.configureRawIntake();
  assert.equal(service.capabilities().rawIntake, 'authenticated-pre-json');
  assert.equal(service.capabilities().historicalImport, false);
  assert.equal(service.capabilities().liveCapture, false);
  for (const rawIntake of ['parent-bootstrap-required', 'authenticated-pre-json']) {
    const parsed = parseCapabilities({ ...service.capabilities(), rawIntake });
    assert.equal(parsed.rawIntake, rawIntake);
    assert.equal(parsed.liveReason, 'QUALIFICATION_MISSING');
  }
  assert.throws(() => parseCapabilities({ ...service.capabilities(), rawIntake: 'live-qualified' }));
});

function freshRateIntake(identity) {
  // Isolated real source closure, not a production limiter reset or a globally patched clock.
  return memoryModule('server/api/src/runtime/runtime-intake.ts', {
    './runtime-json.js': { parseRuntimeJson }, '../auth/auth.controller.js': { originForRequest },
    './runtime-http.js': runtimeHttp,
  }).createRuntimeIntake(identity);
}

test('global pre-auth60 budget spans owners, nginx peers and forged forwarding headers; no lookup at61', async () => {
  let lookups = 0;
  const intake = freshRateIntake(req => { lookups++; return req.headers['synthetic-owner']; });
  for (let i = 0; i < 60; i++) {
    const result = await dispatch([intake], `${prefix}/consents`, '{}', {
      'synthetic-owner': `owner-${i}`, 'x-forwarded-for': `synthetic-client-${i}`,
    }, true, { peer: i % 2 ? 'proxy-one' : 'proxy-two' }).done;
    assert.equal(result.reachedController, true);
  }
  const denied = await dispatch([intake], `${prefix}/consents`, '{', {
    'synthetic-owner': 'another-owner', 'x-forwarded-for': 'another-client',
  }, false, { peer: 'new-peer' }).done;
  assert.equal(denied.res.statusCode, 429);
  assert.equal(denied.req.listenerCount('data'), 0);
  assert.equal(lookups, 60);
  let anonymousLookups = 0;
  const anonymous = freshRateIntake(() => { anonymousLookups++; throw new Error('UNAUTHORIZED'); });
  for (let i = 0; i < 60; i++) assert.equal((await dispatch([anonymous], `${prefix}/consents`, '{', {}, false).done).res.statusCode, 401);
  assert.equal((await dispatch([anonymous], `${prefix}/consents`, '{', {}, false).done).res.statusCode, 429);
  assert.equal(anonymousLookups, 60);
});

test('post-auth owner12 and global2/owner1 raw concurrency stay independent behind the same proxy', async () => {
  const intake = freshRateIntake(req => req.headers['synthetic-owner']);
  for (let i = 0; i < 12; i++) assert.equal((await dispatch([intake], `${prefix}/consents`, '{}',
    { 'synthetic-owner': 'owner-a' }).done).reachedController, true);
  assert.equal((await dispatch([intake], `${prefix}/consents`, '{', { 'synthetic-owner': 'owner-a' }, false).done).res.statusCode, 429);
  assert.equal((await dispatch([intake], `${prefix}/consents`, '{}', { 'synthetic-owner': 'owner-b' }).done).reachedController, true);
  const slots = freshRateIntake(req => req.headers['synthetic-owner']);
  const first = dispatch([slots], `${prefix}/consents`, '{}', { 'synthetic-owner': 'a' }, false);
  const same = await dispatch([slots], `${prefix}/consents`, '{}', { 'synthetic-owner': 'a' }, false).done;
  assert.equal(same.res.statusCode, 429);
  const second = dispatch([slots], `${prefix}/consents`, '{}', { 'synthetic-owner': 'b' }, false);
  assert.equal((await dispatch([slots], `${prefix}/consents`, '{}', { 'synthetic-owner': 'c' }, false).done).res.statusCode, 429);
  first.req.end('{}'); second.req.end('{}');
  assert.equal((await first.done).reachedController, true);
  assert.equal((await second.done).reachedController, true);
});

test('nginx exact history/chat allowlist is default-off8KiB45s/unbuffered chat with incoming headers preserved', () => {
  const source = readFileSync(resolve(root, 'server/deploy/stand.nginx.conf'), 'utf8');
  const chat = source.slice(source.indexOf('        # New history/chat paths'), source.indexOf('        # Bounded consent-bound LLM summary'));
  assert.match(source, /set \$history_ingress_enabled 0;/);
  assert.equal((chat.match(/if \(\$history_ingress_enabled = 0\)/g) || []).length, 3);
  assert.equal((chat.match(/proxy_pass_request_headers on;/g) || []).length, 3);
  assert.equal((chat.match(/client_max_body_size 8k;/g) || []).length, 2);
  assert.equal((chat.match(/limit_except POST/g) || []).length, 2);
  assert.equal((chat.match(/limit_except GET/g) || []).length, 1);
  assert.equal((chat.match(/proxy_read_timeout 45s;/g) || []).length, 3);
  assert.equal((chat.match(/proxy_buffering off;/g) || []).length, 1);
  assert.match(chat, /proxy_cache off;/);
  assert.match(chat, /gzip off;/);
  assert.match(chat, /llm\/history\/decision\$/);
  assert.match(chat, /llm\/chat\$/);
  assert.match(chat, /llm\/\(\?:history\|chat\/\(\?:context\|usage\)\)\$/);
  assert.doesNotMatch(chat, /proxy_set_header (?:Authorization|Cookie|Origin|Content-Type)|rewrite|sub_filter/);
  const summary = source.slice(source.indexOf('        # Bounded consent-bound LLM summary'), source.indexOf('        # Cancel is'));
  assert.match(summary, /client_max_body_size 1k;/);
  assert.match(summary, /proxy_read_timeout 35s;/);
});
