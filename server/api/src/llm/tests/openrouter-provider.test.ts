import assert from 'node:assert/strict';
import test from 'node:test';
import { HttpException } from '@nestjs/common';
import { OPENROUTER_ENDPOINT, productionProvider, OpenRouterProvider } from '../openrouter-provider.js';
import { policyFromEnvironment } from '../policy.js';
import { validateReply } from '../response.js';
import { envelope, fakeKey, fixtureEnv, fixturePolicy, fixtureReport, reply } from './fixtures.js';

const transport = (fn: (url: unknown, init?: RequestInit) => Promise<Response>) => fn as typeof fetch;
const json = (body: unknown) => new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
const errorCode = (code: string) => (error: unknown) => {
  assert.ok(error instanceof HttpException);
  assert.deepEqual(error.getResponse(), { errorCode: code });
  return true;
};

test('production factory/policy default off, missing private key and every undecided setting fail closed', async () => {
  assert.equal(policyFromEnvironment({}), null);
  assert.equal(policyFromEnvironment({ ...fixtureEnv, LLM_ENABLED: 'false' }), null);
  for (const name of Object.keys(fixtureEnv)) {
    const env = { ...fixtureEnv }; delete env[name];
    assert.equal(policyFromEnvironment(env), null, name);
  }
  for (const patch of [{ LLM_REGION: 'eu' }, { LLM_REGION: 'us' }, { LLM_RETENTION: 'undecided' },
    { LLM_MODEL: 'openrouter/auto' }, { LLM_MODEL: 'fixture/fake-model:online' }, { LLM_ROUTING_APPROVED: 'false' },
    { LLM_TIMEOUT_MS: '30001' }, { LLM_OUTPUT_TOKENS: '2049' }, { LLM_REQUEST_BUDGET_USD: 'NaN' }, { LLM_MAX_FINDINGS: '1001' }])
    assert.equal(policyFromEnvironment({ ...fixtureEnv, ...patch }), null);
  let calls = 0;
  assert.throws(() => productionProvider({}, transport(async () => { calls++; return json(envelope()); })), errorCode('LLM_CONFIGURATION_UNAVAILABLE'));
  assert.equal(calls, 0);
  assert.notEqual(policyFromEnvironment({ ...fixtureEnv, LLM_REQUEST_BUDGET_USD: '0.4' })!.version, fixturePolicy.version);
});

test('actual OpenRouter adapter uses fixed HTTPS/header/routing bounds, never endpoint override/tools/retries', async () => {
  let calls = 0;
  const provider = productionProvider({ OPENROUTER_API_KEY: fakeKey, OPENROUTER_ENDPOINT: 'https://attacker.invalid' }, transport(async (url, init) => {
    calls++;
    assert.equal(url, OPENROUTER_ENDPOINT);
    assert.equal(init?.redirect, 'error'); assert.equal(init?.method, 'POST');
    assert.deepEqual(init?.headers, { authorization: `Bearer ${fakeKey}`, 'content-type': 'application/json', accept: 'application/json' });
    const body = JSON.parse(String(init?.body));
    assert.equal(body.model, fixturePolicy.model); assert.equal(body.max_tokens, 256); assert.equal(body.stream, false);
    assert.equal(body.tools, undefined); assert.equal(body.provider.allow_fallbacks, false);
    assert.equal(body.provider.data_collection, 'deny'); assert.equal(body.provider.zdr, true);
    assert.deepEqual(body.provider.only, ['FixtureProvider']);
    assert.deepEqual(body.provider.max_price, { prompt: 1, completion: 1 });
    assert.ok(!String(init?.body).includes(fakeKey));
    assert.deepEqual(JSON.parse(body.messages[1].content), fixtureReport);
    return json(envelope());
  }));
  assert.ok(provider instanceof OpenRouterProvider);
  assert.deepEqual(validateReply(await provider.summarize(fixtureReport, fixturePolicy, new AbortController().signal), fixtureReport).hypotheses,
    [{ kind: 'hypothesis', ...reply(fixtureReport).hypotheses[0] }]);
  assert.equal(calls, 1);
});

test('request byte/token budget refusal and pre-abort have zero transport calls', async () => {
  let calls = 0;
  const provider = productionProvider({ OPENROUTER_API_KEY: fakeKey }, transport(async () => { calls++; return json(envelope()); }));
  await assert.rejects(provider.summarize(fixtureReport, { ...fixturePolicy, requestBytes: 1 }, new AbortController().signal), errorCode('LLM_CONFIGURATION_UNAVAILABLE'));
  await assert.rejects(provider.summarize(fixtureReport, { ...fixturePolicy, budgetUsd: 0.000001 }, new AbortController().signal), errorCode('LLM_CONFIGURATION_UNAVAILABLE'));
  const stopped = new AbortController(); stopped.abort();
  await assert.rejects(provider.summarize(fixtureReport, fixturePolicy, stopped.signal), errorCode('LLM_PROVIDER_UNAVAILABLE'));
  assert.equal(calls, 0);
});

test('HTTP failure/redirect and oversized declared/streaming response cancel without reading/echoing private body', async () => {
  for (const response of [new Response('CANARY-private', { status: 401 }), new Response('CANARY-private', { status: 302, headers: { location: 'https://attacker.invalid' } }),
    new Response('CANARY-private', { headers: { 'content-type': 'text/plain' } }),
    new Response('CANARY-private', { headers: { 'content-type': 'application/json', 'content-length': '999999999' } })]) {
    let calls = 0;
    const provider = productionProvider({ OPENROUTER_API_KEY: fakeKey }, transport(async () => { calls++; return response; }));
    await assert.rejects(provider.summarize(fixtureReport, fixturePolicy, new AbortController().signal), errorCode('LLM_PROVIDER_UNAVAILABLE'));
    assert.equal(calls, 1); assert.ok(response.body?.locked === false);
  }
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({ pull(c) { c.enqueue(new Uint8Array(20)); }, cancel() { cancelled = true; } });
  const provider = productionProvider({ OPENROUTER_API_KEY: fakeKey }, transport(async () => new Response(stream, { headers: { 'content-type': 'application/json' } })));
  await assert.rejects(provider.summarize(fixtureReport, { ...fixturePolicy, responseBytes: 32 }, new AbortController().signal), errorCode('LLM_PROVIDER_UNAVAILABLE'));
  assert.equal(cancelled, true);
});

test('finite deadline covers stalled fetch and stalled body; caller cancellation aborts transport', async () => {
  let signal: AbortSignal | undefined;
  const stalled = productionProvider({ OPENROUTER_API_KEY: fakeKey }, transport(async (_, init) => {
    signal = init?.signal as AbortSignal; return new Promise<Response>(() => {});
  }));
  await assert.rejects(stalled.summarize(fixtureReport, { ...fixturePolicy, timeoutMs: 15 }, new AbortController().signal), errorCode('LLM_PROVIDER_UNAVAILABLE'));
  assert.equal(signal?.aborted, true);
  let cancelled = false;
  const body = productionProvider({ OPENROUTER_API_KEY: fakeKey }, transport(async () => new Response(new ReadableStream({ cancel() { cancelled = true; } }), { headers: { 'content-type': 'application/json' } })));
  await assert.rejects(body.summarize(fixtureReport, { ...fixturePolicy, timeoutMs: 15 }, new AbortController().signal), errorCode('LLM_PROVIDER_UNAVAILABLE'));
  assert.equal(cancelled, true);
  const abort = new AbortController();
  const pending = stalled.summarize(fixtureReport, fixturePolicy, abort.signal); abort.abort();
  await assert.rejects(pending, errorCode('LLM_PROVIDER_UNAVAILABLE'));
});

test('strict envelope rejects wrong model, tools, truncation, output token overflow and malformed content safely', async () => {
  const malformed = [ { ...envelope(), model: 'foreign/model' }, { ...envelope(), usage: { completion_tokens: 257 } },
    { ...envelope(), choices: [{ finish_reason: 'length', message: { role: 'assistant', content: '{}' } }] },
    { ...envelope(), choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: '{}', tool_calls: [{}] } }] },
    { ...envelope(), choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: 'CANARY-private' } }] } ];
  for (const bad of malformed) {
    const provider = productionProvider({ OPENROUTER_API_KEY: fakeKey }, transport(async () => json(bad)));
    await assert.rejects(provider.summarize(fixtureReport, fixturePolicy, new AbortController().signal), errorCode('LLM_PROVIDER_UNAVAILABLE'));
  }
});

test('publication parser isolates current report citations and refuses links/markup/control/secret output', () => {
  for (const patch of [{ scanId: 'foreign' }, { digest: `sha256:${'b'.repeat(64)}` }, { platform: 'linux/arm64' }, { reportVersion: 'old' },
    { hypotheses: [{ text: 'A claim.', citations: ['foreign-id'] }] }, { extra: 'injected' }])
    assert.throws(() => validateReply({ ...reply(fixtureReport), ...patch }, fixtureReport), errorCode('LLM_INVALID_RESPONSE'));
  for (const text of ['<script>alert(1)</script>', 'See https://attacker.invalid', '[A fact](https://attacker.invalid)',
    'password=CANARY-private', 'CANARY-private', 'Unsafe\u202evalue', 'a'.repeat(2001)])
    assert.throws(() => validateReply({ ...reply(fixtureReport), hypotheses: [{ text, citations: [fixtureReport.findings[0].findingId] }] }, fixtureReport), errorCode('LLM_INVALID_RESPONSE'));
});
