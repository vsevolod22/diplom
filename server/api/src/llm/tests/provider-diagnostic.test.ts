import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { HttpException } from '@nestjs/common';
import type { ArgumentsHost } from '@nestjs/common';
import type { HttpAdapterHost } from '@nestjs/core';
import { OpenRouterProvider } from '../openrouter-provider.js';
import { LlmExceptionFilter } from '../llm-exception.filter.js';
import { abortDiagnostic, carryDiagnostic, diagnose, diagnostic, diagnosticHeaders, FAILURE_PHASES, FAILURE_REASONS } from '../provider-diagnostic.js';
import { fixturePolicy, fixtureReport, envelope, fakeKey, fixtureEnv } from './fixtures.js';
import { policyFromEnvironment } from '../policy.js';
import { prepareHistory, prepareSummary, prepareTranslation } from '../prepared-request.js';
import { quotaPolicy } from './quota-fixtures.js';

const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } });
async function failure(transport: typeof fetch, policy = fixturePolicy, signal = new AbortController().signal) {
  try { await new OpenRouterProvider(fakeKey, transport).summarize(fixtureReport, policy, signal); assert.fail('must reject'); }
  catch (error) { assert.ok(error instanceof HttpException); return error; }
}

test('diagnostic factories are finite, private, first-cause-only; exception body/message cannot forge headers', () => {
  const error = diagnose(new Error('PRIVATE'), 'tls', 'io_error');
  diagnose(error, 'deadline', 'timeout');
  assert.deepEqual(diagnostic(error), { phase: 'tls', reason: 'io_error' });
  assert.deepEqual(diagnosticHeaders(carryDiagnostic(error, new Error('SAFE'))), { 'X-LLM-Failure-Phase': 'tls', 'X-LLM-Failure-Reason': 'io_error' });
  assert.deepEqual(diagnosticHeaders({ phase: 'tls', reason: 'io_error', diagnostic: { phase: 'tls', reason: 'io_error' } }), {});
  assert.doesNotMatch(JSON.stringify(error), /PRIVATE|tls|reason/);
  const headers = new Map<string, unknown>(); let body: unknown;
  const response = { setHeader: (key: string, value: unknown) => headers.set(key, value) };
  const filter = new LlmExceptionFilter({ httpAdapter: { isHeadersSent: () => false, reply: (_response: unknown, value: unknown) => { body = value; } } } as unknown as HttpAdapterHost);
  const host = { switchToHttp: () => ({ getRequest: () => ({ url: `/api/v1/browser/scans/${fixtureReport.scanId}/llm/chat` }), getResponse: () => response }) } as unknown as ArgumentsHost;
  const forged = new HttpException({ errorCode: 'LLM_PROVIDER_UNAVAILABLE', diagnostic: { phase: 'tls', reason: 'io_error' }, message: 'PRIVATE' }, 502);
  filter.catch(forged, host); assert.equal(headers.has('X-LLM-Failure-Phase'), false);
  filter.catch(carryDiagnostic(error, forged), host); assert.equal(headers.get('X-LLM-Failure-Phase'), 'tls');
  assert.deepEqual(body, { errorCode: 'LLM_PROVIDER_UNAVAILABLE' });
  assert.ok(FAILURE_PHASES.length < 32 && FAILURE_REASONS.length < 32);
});

test('provider failures distinguish headers/body/json/model/envelope/finish/content/usage without changing error body', async () => {
  const cases = [
    [() => new Response('PRIVATE', { headers: { 'content-type': 'text/html' } }), 'headers', 'invalid_type'],
    [() => new Response('PRIVATE', { headers: { 'content-type': 'application/json', 'content-length': '999999' } }), 'headers', 'limit'],
    [() => new Response('PRIVATE', { headers: { 'content-type': 'application/json' } }), 'json', 'invalid_json'],
    [() => json({ ...envelope(), model: 'PRIVATE' }), 'model', 'mismatch'],
    [() => json({ ...envelope(), choices: [] }), 'envelope', 'invalid_shape'],
    [() => json({ ...envelope(), choices: [{ ...envelope().choices[0], finish_reason: 'length' }] }), 'finish', 'finish_length'],
    [() => json({ ...envelope(), choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: 'PRIVATE' } }] }), 'content', 'invalid_json'],
    [() => json({ ...envelope(), usage: { completion_tokens: 99999 } }), 'usage', 'invalid_receipt'],
  ] as const;
  for (const [response, phase, reason] of cases) {
    let calls = 0;
    const error = await failure((async () => { calls++; return response(); }) as typeof fetch);
    assert.deepEqual(error.getResponse(), { errorCode: 'LLM_PROVIDER_UNAVAILABLE' });
    assert.deepEqual(diagnostic(error), { phase, reason }); assert.equal(calls, 1);
    assert.doesNotMatch(JSON.stringify(error.getResponse()), /PRIVATE|phase|reason/);
  }
  const body = await failure((async () => new Response(new ReadableStream({ start(controller) { controller.error(new Error('PRIVATE')); } }), { headers: { 'content-type': 'application/json' } })) as typeof fetch);
  assert.deepEqual(diagnostic(body), { phase: 'body', reason: 'io_error' });
});

test('rejected finish values classify finitely without echoing native reasons or accepting valid-looking partial content', async () => {
  for (const [value, reason] of [
    ['length', 'finish_length'], ['content_filter', 'finish_content_filter'], ['tool_calls', 'finish_tool_calls'],
    ['function_call', 'finish_tool_calls'], ['error', 'finish_error'], ['PRIVATE-unknown-finish', 'finish_unknown'],
    ['STOP', 'finish_unknown'], [null, 'finish_unknown'], [undefined, 'finish_unknown'], [123, 'finish_unknown'], [{ raw: 'PRIVATE' }, 'finish_unknown'],
  ] as const) {
    let calls = 0;
    const error = await failure((async () => {
      calls++;
      return json({ ...envelope(), choices: [{ ...envelope().choices[0], finish_reason: value, native_finish_reason: 'PRIVATE-native' }] });
    }) as typeof fetch);
    assert.deepEqual(error.getResponse(), { errorCode: 'LLM_PROVIDER_UNAVAILABLE' });
    assert.deepEqual(diagnosticHeaders(error), { 'X-LLM-Failure-Phase': 'finish', 'X-LLM-Failure-Reason': reason });
    assert.equal(calls, 1);
    assert.doesNotMatch(JSON.stringify(error.getResponse()) + JSON.stringify(diagnosticHeaders(error)), /PRIVATE|native_finish_reason/);
  }
  let calls = 0;
  await assert.doesNotReject(new OpenRouterProvider(fakeKey, (async () => { calls++; return json(envelope()); }) as typeof fetch)
    .summarize(fixtureReport, fixturePolicy, new AbortController().signal));
  assert.equal(calls, 1, 'normalized stop still follows the unchanged success path');
});

test('public prepared requests keep explicit reasoning-off, exact configured output cap and privacy/free routing unchanged', () => {
  const policy = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'xingchen-agi/xing4.0-29b-a4b:free', LLM_PROVIDER_ALLOWLIST: 'phala',
    LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0', LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' })!;
  for (const request of [prepareSummary(fixtureReport, policy), prepareHistory({}, policy), prepareTranslation({ title: 'Memory flaw', description: null }, policy)]) {
    const body = JSON.parse(request.body);
    assert.equal(body.model, 'xingchen-agi/xing4.0-29b-a4b:free');
    assert.equal(body.max_tokens, policy.outputTokens);
    assert.equal(policy.outputTokens, 256, 'fixture cap is not the separate 1024-token input allowance');
    assert.deepEqual(body.reasoning, { enabled: false, exclude: true });
    assert.deepEqual(body.response_format, { type: 'json_object' }); assert.equal(body.stream, false);
    assert.deepEqual(body.provider, { only: ['phala'], allow_fallbacks: false, require_parameters: true,
      data_collection: 'deny', zdr: true, max_price: { prompt: 0, completion: 0, request: 0 } });
    assert.equal(request.reserve.input, Buffer.byteLength(request.body) + 1024);
    assert.equal(request.reserve.output, policy.outputTokens); assert.equal(request.reserve.costMicros, 0);
  }
});

test('caller abort, owned service deadline and adapter deadline remain distinct and cannot be overwritten by cleanup', async () => {
  const stalled = (async () => new Promise<Response>(() => {})) as typeof fetch;
  const timeout = await failure(stalled, { ...fixturePolicy, timeoutMs: 10 });
  assert.deepEqual(diagnostic(timeout), { phase: 'deadline', reason: 'timeout' });
  const caller = new AbortController(); caller.abort('PRIVATE raw caller reason');
  const cancelled = await failure(stalled, fixturePolicy, caller.signal);
  assert.deepEqual(diagnostic(cancelled), { phase: 'caller_abort', reason: 'aborted' });
  const service = new AbortController(); abortDiagnostic(service, 'deadline');
  const inherited = await failure(stalled, fixturePolicy, service.signal);
  assert.deepEqual(diagnostic(inherited), { phase: 'deadline', reason: 'timeout' });
  assert.doesNotMatch(JSON.stringify(inherited.getResponse()), /PRIVATE|reason|phase/);
});

test('usage observation failure is accounting, not an invented provider HTTP status or a second attempt', async () => {
  const policy = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'xingchen-agi/xing4.0-29b-a4b:free', LLM_PROVIDER_ALLOWLIST: 'phala',
    LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0', LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' })!;
  let calls = 0, observations = 0;
  const provider = new OpenRouterProvider(fakeKey, (async () => { calls++; return json({ ...envelope(), model: policy.model, usage: { prompt_tokens: 500, completion_tokens: 32, cost: 0 } }); }) as typeof fetch);
  await assert.rejects(provider.summarizePrepared(prepareSummary(fixtureReport, policy), policy, new AbortController().signal,
    { policy: quotaPolicy, observe() { observations++; throw new Error('PRIVATE store diagnostic'); } }), error => {
    assert.ok(error instanceof HttpException); assert.deepEqual(error.getResponse(), { errorCode: 'LLM_PROVIDER_UNAVAILABLE' });
    assert.deepEqual(diagnostic(error), { phase: 'accounting', reason: 'observation_failed' }); return true;
  });
  assert.equal(calls, 1); assert.equal(observations, 1);
});
