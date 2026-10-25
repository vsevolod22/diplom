import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { HttpException, type ArgumentsHost } from '@nestjs/common';
import type { HttpAdapterHost } from '@nestjs/core';
import type { ServerResponse } from 'node:http';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { OpenRouterProvider, safeProviderFailure } from '../openrouter-provider.js';
import { OpenRouterHttpFailure } from '../openrouter-transport.js';
import { LlmExceptionFilter } from '../llm-exception.filter.js';
import { LlmService, type LlmRuntime } from '../llm.service.js';
import type { ReportReader } from '../report-context.js';
import type { LlmQuotaRuntime } from '../quota-runtime.js';
import { prepareSummary } from '../prepared-request.js';
import { policyFromEnvironment } from '../policy.js';
import { FixtureQuotaLedger, quotaPolicy } from './quota-fixtures.js';
import { envelope, fakeKey, fixtureEnv, fixturePolicy, fixtureReport } from './fixtures.js';

const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } });
const failureBody = (status: number, retryAfterSeconds?: number) => ({
  errorCode: status === 429 || status === 503 ? 'LLM_PROVIDER_RATE_LIMITED' : status === 401 ? 'LLM_PROVIDER_AUTH_FAILED' : 'LLM_PROVIDER_UNAVAILABLE',
  providerFailure: { kind: status === 429 || status === 503 ? 'rate_limited' : status === 401 ? 'auth_failed' : 'unavailable', status,
    ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}) },
});

test('native typed and injected HTTP errors retain classification; no body read, raw diagnostics, retry or fallback', async () => {
  for (const status of [401, 402, 403, 408, 429, 500, 502, 503]) {
    for (const native of [false, true]) {
      let calls = 0, cancelled = 0, reads = 0;
      const provider = new OpenRouterProvider(fakeKey, (async () => {
        calls++;
        if (native) throw new OpenRouterHttpFailure(status, '60');
        return new Response(new ReadableStream({ start() {}, pull() { reads++; }, cancel() { cancelled++; } }, { highWaterMark: 0 }),
          { status, headers: { 'retry-after': '60', 'content-type': 'text/plain', 'content-length': '999999999', 'x-provider-secret': 'CANARY' } });
      }) as typeof fetch);
      await assert.rejects(provider.summarize(fixtureReport, fixturePolicy, new AbortController().signal), error => {
        assert.ok(error instanceof HttpException);
        assert.deepEqual(error.getResponse(), failureBody(status, [429, 503].includes(status) ? 60 : undefined));
        assert.equal(error.getStatus(), [429, 503].includes(status) ? status : status === 401 ? 503 : 502);
        assert.doesNotMatch(JSON.stringify(error), /CANARY|Bearer|x-provider-secret/);
        return true;
      });
      assert.equal(calls, 1); assert.equal(reads, 0); assert.equal(cancelled, native ? 0 : 1);
    }
  }
});

test('HTTP 200 root/choice errors classify bounded integer codes, never publish content or parse provider metadata', async () => {
  for (const status of [401, 429, 503]) {
    for (const shape of ['root', 'choice', 'choice-only']) {
      const error = { code: status, message: 'CANARY-private', metadata: { raw: fakeKey, provider_code: 'CANARY' } };
      const value = shape === 'root' ? { error } : { ...(shape === 'choice' ? envelope() : {}), choices: [{ ...envelope().choices[0], error }] };
      const provider = new OpenRouterProvider(fakeKey, (async () => { const response = json(value); response.headers.set('retry-after', '60'); return response; }) as typeof fetch);
      await assert.rejects(provider.summarize(fixtureReport, fixturePolicy, new AbortController().signal), reason => {
        assert.ok(reason instanceof HttpException);
        assert.deepEqual(reason.getResponse(), failureBody(status, status === 401 ? undefined : 60)); return true;
      });
    }
  }
  for (const code of ['429', 429.1, 600, -1, null, { status: 429 }]) {
    const provider = new OpenRouterProvider(fakeKey, (async () => json({ ...envelope(), error: { code, message: 'CANARY' } })) as typeof fetch);
    await assert.rejects(provider.summarize(fixtureReport, fixturePolicy, new AbortController().signal), reason => {
      assert.ok(reason instanceof HttpException); assert.deepEqual(reason.getResponse(), { errorCode: 'LLM_PROVIDER_UNAVAILABLE' }); return true;
    });
  }
});

test('error envelopes account exact matching-model usage first; HTTP refusal keeps dispatched unknown liability', async () => {
  const policy = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'apodex/apodex-1.1-mini:free', LLM_PROVIDER_ALLOWLIST: 'novita/bf16',
    LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0', LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' })!;
  const dir = mkdtempSync(join(tmpdir(), 'provider-failure-accounting-'));
  const ledger = new FixtureQuotaLedger(join(dir, 'llm-usage.sqlite'), quotaPolicy);
  const prepared = prepareSummary(fixtureReport, policy);
  try {
    for (const mode of ['http', 'root', 'choice', 'foreign', 'fault', 'missing', 'choice-missing']) {
      const subject = `fixture-${mode}`;
      const id = ledger.reserve({ subject, scanId: fixtureReport.scanId, reportVersion: fixtureReport.reportVersion, policyVersion: policy.version, requestHash: prepared.hash }, prepared.reserve);
      assert.ok(ledger.dispatch(id));
      let observations = 0;
      const provider = new OpenRouterProvider(fakeKey, (async () => {
        if (mode === 'http') return new Response('CANARY-not-a-receipt', { status: 429, headers: { 'retry-after': '60' } });
        const error = { code: 429, message: 'CANARY' };
        return json({ model: mode === 'foreign' ? 'foreign/model' : policy.model,
          ...(mode === 'missing' || mode === 'choice-missing' ? {} : { usage: { prompt_tokens: 500, completion_tokens: 32, cost: mode === 'fault' ? 0.01 : 0 } }),
          ...(mode.startsWith('choice') ? { choices: [{ finish_reason: 'error', error }] } : { error }) });
      }) as typeof fetch);
      await assert.rejects(provider.summarizePrepared(prepared, policy, new AbortController().signal, {
        policy: quotaPolicy, observe: observation => { observations++; assert.equal(ledger.observe(id, observation), mode !== 'fault'); },
      }), error => { assert.ok(error instanceof HttpException); assert.equal((error.getResponse() as { errorCode: string }).errorCode, 'LLM_PROVIDER_RATE_LIMITED'); return true; });
      assert.equal(ledger.release(id), false, 'HTTP status never authorizes refund');
      const snapshot = ledger.snapshot(subject, fixtureReport.scanId);
      if (mode === 'root' || mode === 'choice') {
        assert.equal(observations, 1); assert.equal(snapshot.scan.used.output, 32); assert.equal(snapshot.scan.held.input, 0);
      } else {
        assert.equal(observations, mode === 'fault' ? 1 : 0); assert.ok(snapshot.scan.held.input >= prepared.reserve.input);
      }
    }
  } finally { ledger.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('summary service and exception filter preserve only validated metadata and bounded Retry-After', async () => {
  const provider = new OpenRouterProvider(fakeKey, (async () => new Response('CANARY', { status: 429, headers: { 'retry-after': '9999999999' } })) as typeof fetch);
  const service = new LlmService({ read: () => fixtureReport } as unknown as ReportReader,
    { policy: () => fixturePolicy, provider: () => provider } as unknown as LlmRuntime, {} as LlmQuotaRuntime);
  let failure: unknown;
  try {
    await service.summary(() => ({ subject: 'fixture-owner', scope: ['scan:read'] }), fixtureReport.scanId,
      { reportVersion: fixtureReport.reportVersion, consent: { accepted: true, policyVersion: fixturePolicy.version } }, new AbortController().signal);
    assert.fail('must fail');
  } catch (error) { failure = error; }
  assert.ok(failure instanceof HttpException);
  const headers = new Map<string, unknown>(); let reply: unknown, status: unknown;
  const response = { setHeader(name: string, value: unknown) { headers.set(name, value); } } as ServerResponse;
  const adapter = { isHeadersSent: () => false, reply: (_response: unknown, value: unknown, code: unknown) => { reply = value; status = code; } };
  const filter = new LlmExceptionFilter({ httpAdapter: adapter } as unknown as HttpAdapterHost);
  const host = { switchToHttp: () => ({ getRequest: () => ({ url: `/api/v1/browser/scans/${fixtureReport.scanId}/llm/summary` }), getResponse: () => response }) } as unknown as ArgumentsHost;
  filter.catch(failure, host);
  assert.equal(status, 429); assert.deepEqual(reply, failureBody(429, 86400));
  assert.equal(headers.get('Retry-After'), '86400'); assert.equal(headers.get('Cache-Control'), 'no-store');
  headers.clear();
  filter.catch(new HttpException({ ...failureBody(429), raw: 'CANARY', providerFailure: { kind: 'rate_limited', status: 429, retryAfterSeconds: 'CANARY' } }, 429), host);
  assert.deepEqual(reply, { errorCode: 'LLM_PROVIDER_RATE_LIMITED' }); assert.equal(headers.has('Retry-After'), false);
});

test('wire validator rejects contradictory/unbounded/private fields; production error path never logs or retries', () => {
  for (const providerFailure of [null, { kind: 'auth_failed', status: 429 }, { kind: 'rate_limited', status: '429' },
    { kind: 'rate_limited', status: 429, retryAfterSeconds: -1 }, { kind: 'rate_limited', status: 429, retryAfterSeconds: 86401 },
    { kind: 'rate_limited', status: 429, retryAfterSeconds: 1.5 }, { kind: 'rate_limited', status: 429, raw: 'CANARY' }])
    assert.equal(safeProviderFailure({ errorCode: 'LLM_PROVIDER_RATE_LIMITED', providerFailure }), undefined);
  for (const name of ['openrouter-transport', 'openrouter-provider', 'history-delivery', 'llm-exception.filter']) {
    const source = readFileSync(new URL(`../${name}.ts`, import.meta.url), 'utf8');
    assert.doesNotMatch(source, /console\.|allow_fallbacks:\s*true|rejectUnauthorized:\s*false|\.retry\(/);
  }
});
