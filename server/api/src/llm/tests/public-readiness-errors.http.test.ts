import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { inspect } from 'node:util';
import { request as httpRequest } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { LoggerService } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { PublicImageModule, configurePublicImageIngress } from '../../oci/public-image.module.js';

const CANARY = 'READINESS_PRIVATE_BODY_CANARY';

test('public readiness sanitizes malformed/oversized GET and POST bodies and never logs raw pre-controller errors', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'readiness-errors-'));
  const env = { AUTH_DB_PATH: join(directory, 'auth.sqlite'), SCAN_LEDGER_PATH: join(directory, 'ledger.sqlite'),
    AUTH_ORIGIN: 'http://127.0.0.1:8081', AUTH_ALLOW_INSECURE_LOCAL_HTTP: 'true',
    SCAN_BROWSER_ALLOW_ALL_LOCAL_ACCOUNTS: 'true', SCAN_BROWSER_ALLOWED_USER_IDS: '', LLM_ENABLED: 'false' };
  const previous = Object.keys(env).map(k => process.env[k]); Object.assign(process.env, env);
  const entries: unknown[][] = [];
  const capture = (...args: unknown[]) => { entries.push(args); };
  // Logging is genuinely enabled: logger:false would hide the regression.
  const logger: LoggerService = { log: capture, error: capture, warn: capture, debug: capture, verbose: capture, fatal: capture };
  let app: NestExpressApplication | undefined;
  try {
    app = await NestFactory.create<NestExpressApplication>(PublicImageModule, { logger, bodyParser: false });
    app.use((req: { headers: Record<string, string | undefined> }, _res: unknown, next: (error?: Error) => void) => {
      if (req.headers['x-fixture-fault'] === 'pre-controller') {
        const error = new Error(`${CANARY}: private scanner/credential diagnostic`);
        Object.assign(error, { body: `${CANARY}: raw request body must not reach the default Nest logger` });
        next(error);
      } else next();
    });
    configurePublicImageIngress(app);
    await app.listen(0, '127.0.0.1');
    const port = (app.getHttpServer().address() as { port: number }).port;
    const send = (path: string, method: string, body = '', fault = false) => new Promise<{ status: number; cache: string | undefined; body: string }>((resolve, reject) => {
      const request = httpRequest({ host: '127.0.0.1', port, method, path,
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body),
          ...(fault ? { 'x-fixture-fault': 'pre-controller' } : {}) } }, response => {
        const chunks: Buffer[] = [];
        response.on('data', chunk => chunks.push(Buffer.from(chunk)));
        response.on('end', () => resolve({ status: response.statusCode!, cache: response.headers['cache-control'], body: Buffer.concat(chunks).toString('utf8') }));
      });
      request.on('error', reject); request.end(body);
    });
    const prefix = '/api/v1/browser/scans/00000000-0000-0000-0000-000000000000/llm/';
    // Express accepts case variants, a trailing slash and query strings. Match
    // those exact router-equivalent aliases, not arbitrary encoded/child paths.
    for (const suffix of ['readiness', 'readiness/', 'READINESS', 'ReAdInEsS/?probe=1']) {
      const path = prefix + suffix;
      const anonymous = await send(path, 'GET');
      assert.equal(anonymous.status, 401); assert.equal(anonymous.cache, 'no-store');
      assert.deepEqual(JSON.parse(anonymous.body), { errorCode: 'UNAUTHORIZED' });
      for (const method of ['GET', 'POST']) {
        for (const [body, expected] of [[`{"${CANARY}": BROKEN}`, 400], [`{"payload":"${CANARY}${'x'.repeat(120000)}"}`, 413]] as const) {
          const result = await send(path, method, body);
          assert.equal(result.status, expected); assert.equal(result.cache, 'no-store');
          assert.deepEqual(JSON.parse(result.body), { errorCode: 'LLM_INVALID_REQUEST' });
          assert.doesNotMatch(result.body, /READINESS_PRIVATE|payload|SyntaxError|stack|private scanner/);
        }
      }
      const unknown = await send(path, 'GET', '', true);
      assert.equal(unknown.status, 500); assert.equal(unknown.cache, 'no-store');
      assert.deepEqual(JSON.parse(unknown.body), { errorCode: 'LLM_UNAVAILABLE' });
    }
    const unrelated = await send(prefix + 'readiness/extra', 'GET');
    assert.equal(unrelated.status, 404); assert.equal(unrelated.cache, undefined);
    assert.ok(entries.length > 0, 'the real Nest logger was enabled and captured startup logging');
    assert.doesNotMatch(inspect(entries, { depth: 8 }), /READINESS_PRIVATE_BODY_CANARY|raw request body|private scanner\/credential/);
  } finally {
    await app?.close();
    Object.keys(env).forEach((key, i) => { if (previous[i] === undefined) delete process.env[key]; else process.env[key] = previous[i]; });
    rmSync(directory, { recursive: true, force: true });
  }
});
