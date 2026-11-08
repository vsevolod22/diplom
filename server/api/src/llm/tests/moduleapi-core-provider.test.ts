import { openAiSettings as baseSettings, openAiPrompts as moduleApiPrompts, openAiReport as moduleApiReport, openAiHistory as moduleApiHistory, openAiReply as moduleApiReply, openAiText as moduleApiText } from './openai-core.fixture.js';
import { openAiEnvelope } from './openai-core.fixture.js';
import assert from 'node:assert/strict';
import test from 'node:test';
import { setImmediate as immediate } from 'node:timers/promises';
import { HttpException } from '@nestjs/common';
import { ModuleApiProvider, type ModuleApiAccountingBinding, type ModuleApiGuardedTransport, type ModuleApiSendGuard } from '../moduleapi-provider.js';
import { MODULEAPI_ENDPOINT, MODULEAPI_MODEL, MODULEAPI_RETURNED_MODELS, createModuleApiPolicy, type ModuleApiSettings, type ModuleApiPolicy } from '../moduleapi-policy.js';
import { prepareModuleApiSummary, prepareModuleApiChat } from '../moduleapi-prepared-request.js';
import { diagnostic, diagnosticHeaders } from '../provider-diagnostic.js';
import type { ModuleApiUsage } from '../moduleapi-usage.js';

function harness(options: { policy?: ModuleApiPolicy; operation?: 'summary' | 'chat'; response?: () => Response;
  transport?: ModuleApiGuardedTransport; reserved?: boolean; observed?: boolean } = {}) {
  const policy = options.policy ?? makeModuleApiPolicy(), request = options.operation === 'chat' ? prepareModuleApiChat(moduleApiHistory, policy) : prepareModuleApiSummary(moduleApiReport, policy);
  const events: string[] = [], bindings: ModuleApiAccountingBinding[] = [], observations: ModuleApiUsage[] = [];
  let sends = 0, calls = 0;
  const transport: ModuleApiGuardedTransport = options.transport ?? { async sendGuarded(endpoint, init, guard) {
    calls++; assert.equal(endpoint, MODULEAPI_ENDPOINT); assert.equal(init.method, 'POST'); assert.equal(init.redirect, 'error');
    assert.equal(init.body, request.body); assert.equal((init.headers as Record<string, string>).authorization, `Bearer ${syntheticModuleApiKey}`);
    let response!: Response;
    guard(() => { sends++; events.push('send'); response = options.response?.() ?? moduleApiResponse(moduleApiEnvelope(moduleApiReply(options.operation))); return undefined; });
    return response;
  } };
  const provider = new ModuleApiProvider(policy, syntheticModuleApiKey, transport);
  const accounting = { assertReserved(binding: ModuleApiAccountingBinding) { events.push('reserved'); bindings.push(binding); return options.reserved ?? true; },
    observe(binding: ModuleApiAccountingBinding, usage: ModuleApiUsage) { events.push('observed'); bindings.push(binding); observations.push(usage); return options.observed ?? true; } };
  const guard: ModuleApiSendGuard = (binding, send) => { events.push('guard'); bindings.push(binding); send(); return undefined; };
  return { policy, request, provider, accounting, guard, events, bindings, observations, sends: () => sends, calls: () => calls,
    run: (signal = new AbortController().signal) => provider.generate(request, signal, accounting, guard) };
}
const fails = async (operation: Promise<unknown>, phase: string, reason: string, code = 'LLM_PROVIDER_UNAVAILABLE') => {
  await assert.rejects(operation, error => {
    assert.ok(error instanceof HttpException); assert.equal(error.getStatus(), 502); assert.deepEqual(error.getResponse(), { errorCode: code });
    assert.deepEqual(diagnostic(error), { phase, reason });
    assert.doesNotMatch(JSON.stringify(error.getResponse()) + JSON.stringify(diagnosticHeaders(error)), /synthetic-private|synthetic_moduleapi|Bearer|"choices":|"tool_calls":/);
    return true;
  });
};


const moduleApiSettings: ModuleApiSettings = { ...baseSettings, model: MODULEAPI_MODEL, retention: 'unknown', monetaryLimit: 'capped', requestBudgetMicros: 100_000 };
const makeModuleApiPolicy = (overrides: Partial<ModuleApiSettings> = {}) => {
  const policy = createModuleApiPolicy({ ...moduleApiSettings, ...overrides }, moduleApiPrompts);
  if (!policy) throw new Error('Invalid synthetic ModuleAPI policy fixture');
  return policy;
};

test('fixed endpoint, one guarded dispatch, durable binding/accounting before exact direct-Russian success; request is one-shot across provider instances', async () => {
  for (const operation of ['summary', 'chat'] as const) {
    const h = harness({ operation }), result = await h.run();
    assert.equal(result.operation, operation); assert.ok(JSON.stringify(result.value).includes(moduleApiText));
    assert.deepEqual(h.events, ['reserved', 'guard', 'send', 'observed']); assert.equal(h.calls(), 1); assert.equal(h.sends(), 1);
    assert.equal(h.observations[0].costMicros, 40); assert.equal(h.observations[0].source, 'moduleapi-server-estimated-configured-rates-not-invoice');
    for (const binding of h.bindings) {
      assert.ok(Object.isFrozen(binding)); assert.deepEqual(binding, { operation, policyVersion: h.policy.version, requestHash: h.request.hash, reserve: h.request.reserve });
      assert.equal(binding, h.bindings[0]);
    }
    assert.equal(JSON.stringify(h.provider), '{}');
    await fails(h.run(), 'request', 'rejected'); assert.equal(h.calls(), 1);
    const other = new ModuleApiProvider(h.policy, syntheticModuleApiKey, { async sendGuarded() { return assert.fail('same prepared object cannot be replayed via another instance'); } });
    await fails(other.generate(h.request, new AbortController().signal, h.accounting, h.guard), 'request', 'rejected');
  }
});

test('summary/chat accept omitted/default/null service tiers with exactly one configured-rate usage observation', async () => {
  for (const operation of ['summary', 'chat'] as const) {
    for (const tier of [undefined, 'default', null]) {
      const h = harness({ operation, response: () => moduleApiResponse({ ...moduleApiEnvelope(moduleApiReply(operation)), service_tier: tier }) });
      const result = await h.run();
      assert.equal(result.operation, operation); assert.ok(JSON.stringify(result.value).includes(moduleApiText));
      assert.deepEqual(h.events, ['reserved', 'guard', 'send', 'observed']);
      assert.equal(h.calls(), 1); assert.equal(h.sends(), 1); assert.equal(h.observations.length, 1);
      assert.deepEqual(result.usage, { normal: true, input: 20, output: 10, costMicros: 40,
        source: 'moduleapi-server-estimated-configured-rates-not-invoice' });
      assert.equal(h.observations[0], result.usage);
    }
  }
});

test('summary/chat reject non-default service tiers before usage observation without retries', async () => {
  for (const operation of ['summary', 'chat'] as const) {
    for (const tier of ['priority', 'flex', 'scale', 'auto', 'fast', '', 0, false, {}, []]) {
      const h = harness({ operation, response: () => moduleApiResponse({ ...moduleApiEnvelope(moduleApiReply(operation)), service_tier: tier }) });
      await fails(h.run(), 'envelope', 'invalid_shape');
      assert.deepEqual(h.events, ['reserved', 'guard', 'send']);
      assert.equal(h.calls(), 1); assert.equal(h.sends(), 1); assert.equal(h.observations.length, 0);
    }
  }
});

test('null service tier preserves exact model, usage, content and accounting rejection guards for summary/chat', async () => {
  for (const operation of ['summary', 'chat'] as const) {
    const response = () => ({ ...moduleApiEnvelope(moduleApiReply(operation)), service_tier: null });
    const model = harness({ operation, response: () => moduleApiResponse({ ...response(), model: 'gpt-5.4-mini-unknown' }) });
    await fails(model.run(), 'model', 'mismatch'); assert.equal(model.observations.length, 0);
    const usage = harness({ operation, response: () => moduleApiResponse({ ...response(), usage: null }) });
    await fails(usage.run(), 'usage', 'invalid_receipt');
    assert.deepEqual(usage.observations, [{ normal: false, source: 'moduleapi-server-estimated-configured-rates-not-invoice' }]);
    const content = harness({ operation, response: () => moduleApiResponse({ ...response(),
      choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: 'not JSON' } }] }) });
    await fails(content.run(), 'content', 'invalid_json'); assert.equal(content.observations.length, 1);
    const accounting = harness({ operation, observed: false, response: () => moduleApiResponse(response()) });
    await fails(accounting.run(), 'accounting', 'observation_failed'); assert.equal(accounting.observations.length, 1);
    for (const h of [model, usage, content, accounting]) { assert.equal(h.calls(), 1); assert.equal(h.sends(), 1); }
  }
});

test('reservation is mandatory before transport; denied and thrown reservation checks never dispatch', async () => {
  const denied = harness({ reserved: false }); await fails(denied.run(), 'accounting', 'rejected'); assert.equal(denied.calls(), 0);
  const h = harness();
  await fails(h.provider.generate(h.request, new AbortController().signal, { ...h.accounting, assertReserved() { throw new Error('synthetic-private'); } }, h.guard), 'accounting', 'rejected');
  assert.equal(h.calls(), 0);
  const policy = makeModuleApiPolicy();
  for (const key of ['', 'short', 'contains spaces synthetic', 'synthetic\r\nInjected:yes'])
    assert.throws(() => new ModuleApiProvider(policy, key, { async sendGuarded() { return moduleApiResponse(); } }));
});

test('strict synchronous fence rejects missing/double transport guard, no send, double send, thenable and late callbacks without accounting', async () => {
  for (const mode of ['missing', 'double-transport', 'no-send', 'double-send', 'async-guard', 'late-send'] as const) {
    let writes = 0, observations = 0, late: (() => void) | undefined;
    const policy = makeModuleApiPolicy(), request = prepareModuleApiSummary(moduleApiReport, policy);
    const provider = new ModuleApiProvider(policy, syntheticModuleApiKey, { async sendGuarded(_endpoint, _init, guard) {
      if (mode !== 'missing') guard(() => { writes++; return undefined; });
      if (mode === 'double-transport') { try { guard(() => { writes++; return undefined; }); } catch { /* keep candidate response, fence must still reject */ } }
      return moduleApiResponse();
    } });
    const guard: ModuleApiSendGuard = (_binding, send) => {
      if (mode === 'no-send') return undefined;
      if (mode === 'late-send') { late = send; return undefined; }
      send();
      if (mode === 'double-send') { try { send(); } catch { /* poisoning cannot be swallowed */ } }
      if (mode === 'async-guard') return Promise.resolve();
      return undefined;
    };
    await fails(provider.generate(request, new AbortController().signal, { assertReserved: () => true, observe() { observations++; return true; } }, guard), 'dispatch_guard', 'rejected');
    if (late) assert.throws(late); assert.ok(writes <= 1); assert.equal(observations, 0);
  }
});

test('caller abort/pre-abort and owned deadline stop bounded transport/body wait without retries or usage invention', async () => {
  const before = harness(), pre = new AbortController(); pre.abort();
  await fails(before.run(pre.signal), 'caller_abort', 'aborted'); assert.equal(before.calls(), 0); assert.deepEqual(before.observations, []);
  for (const reason of ['caller', 'deadline'] as const) {
    const policy = makeModuleApiPolicy({ timeoutMs: 20 }); let sent = 0;
    const h = harness({ policy, transport: { async sendGuarded(_endpoint, _init, guard) { guard(() => { sent++; return undefined; }); return new Promise<Response>(() => {}); } } });
    const controller = new AbortController(), operation = h.run(controller.signal);
    if (reason === 'caller') controller.abort();
    await fails(operation, reason === 'caller' ? 'caller_abort' : 'deadline', reason === 'caller' ? 'aborted' : 'timeout');
    assert.equal(sent, 1); assert.deepEqual(h.observations, []);
  }
  let cancelled = false;
  const h = harness({ response: () => new Response(new ReadableStream<Uint8Array>({ cancel() { cancelled = true; } }), { headers: { 'content-type': 'application/json' } }) });
  const controller = new AbortController(), operation = h.run(controller.signal); await immediate(); controller.abort();
  await fails(operation, 'caller_abort', 'aborted'); await immediate(); assert.equal(cancelled, true); assert.deepEqual(h.observations, []);
});

test('HTTP errors/redirects discard bodies; content type/length, byte limits and invalid UTF8/JSON fail finitely before observation', async () => {
  for (const status of [400, 401, 403, 429, 500, 503]) {
    let cancelled = false;
    const h = harness({ response: () => new Response(new ReadableStream<Uint8Array>({ cancel() { cancelled = true; } }), { status,
      headers: { 'content-type': 'application/json' } }) });
    await fails(h.run(), 'headers', 'http_error'); await immediate(); assert.equal(cancelled, true); assert.deepEqual(h.observations, []); assert.equal(h.calls(), 1);
  }
  for (const [response, phase, reason] of [
    [() => new Response('synthetic-private', { headers: { 'content-type': 'text/html' } }), 'headers', 'invalid_type'],
    [() => new Response('{}', { headers: { 'content-type': 'application/json', 'content-length': '999999' } }), 'headers', 'limit'],
    [() => new Response('{}', { headers: { 'content-type': 'application/json', 'content-length': '-1' } }), 'headers', 'limit'],
    [() => new Response('x'.repeat(8193), { headers: { 'content-type': 'application/json' } }), 'body', 'limit'],
    [() => new Response(new Uint8Array([0xff]), { headers: { 'content-type': 'application/json' } }), 'json', 'invalid_json'],
    [() => new Response('{', { headers: { 'content-type': 'application/json' } }), 'json', 'invalid_json'],
    [() => new Response('[]', { headers: { 'content-type': 'application/json' } }), 'envelope', 'invalid_shape'],
    [() => Object.defineProperty(moduleApiResponse(), 'redirected', { value: true }), 'headers', 'http_error'],
  ] as const) {
    const h = harness({ response }); await fails(h.run(), phase, reason); assert.equal(h.observations.length, 0); assert.equal(h.calls(), 1);
  }
});

test('model identity is exact; refusal/tool/annotation/finish/envelope rejects only after accounting known usage, never retries content', async () => {
  const envelope = moduleApiEnvelope();
  const cases: Array<{ value: unknown; phase: string; reason: string; observations: number }> = [
    { value: { ...envelope, model: 'gpt-5.4-mini-unknown' }, phase: 'model', reason: 'mismatch', observations: 0 },
    { value: { ...envelope, service_tier: 'priority' }, phase: 'envelope', reason: 'invalid_shape', observations: 0 },
    { value: { ...envelope, choices: [] }, phase: 'envelope', reason: 'invalid_shape', observations: 1 },
    { value: { ...envelope, error: { message: 'synthetic-private' } }, phase: 'envelope', reason: 'invalid_shape', observations: 1 },
  ];
  for (const [finish, reason] of [['length', 'finish_length'], ['content_filter', 'finish_content_filter'], ['tool_calls', 'finish_tool_calls'], ['synthetic-private', 'finish_unknown']] as const)
    cases.push({ value: { ...envelope, choices: [{ ...envelope.choices[0], finish_reason: finish }] }, phase: 'finish', reason, observations: 1 });
  for (const patch of [{ refusal: 'synthetic-private' }, { tool_calls: [{}] }, { annotations: [{}] }, { role: 'user' }, { extra: 'synthetic-private' }])
    cases.push({ value: { ...envelope, choices: [{ finish_reason: 'stop', message: { ...envelope.choices[0].message, ...patch } }] }, phase: 'content', reason: 'invalid_shape', observations: 1 });
  for (const entry of cases) {
    const h = harness({ response: () => moduleApiResponse(entry.value) }); await fails(h.run(), entry.phase, entry.reason);
    assert.equal(h.observations.length, entry.observations); assert.equal(h.calls(), 1);
  }
});

test('durable observation precedes content/Russian/source validation, and accounting failure supersedes otherwise invalid content', async () => {
  for (const [content, phase, reason] of [['not JSON', 'content', 'invalid_json'],
    [JSON.stringify(moduleApiReply('summary', 'This is English.')), 'language', 'not_russian'],
    [JSON.stringify({ ...moduleApiReply(), digest: `sha256:${'d'.repeat(64)}` }), 'content', 'invalid_content']] as const) {
    const envelope = moduleApiEnvelope(); envelope.choices[0].message.content = content;
    const h = harness({ response: () => moduleApiResponse(envelope) });
    await fails(h.run(), phase, reason, phase === 'content' && reason === 'invalid_json' ? 'LLM_PROVIDER_UNAVAILABLE' : 'LLM_INVALID_RESPONSE');
    assert.equal(h.observations.length, 1); assert.equal(h.observations[0].costMicros, 40); assert.equal(h.calls(), 1);
  }
  const bad = moduleApiEnvelope(); bad.choices[0].message.content = 'not JSON';
  const h = harness({ response: () => moduleApiResponse(bad), observed: false });
  await fails(h.run(), 'accounting', 'observation_failed'); assert.equal(h.observations.length, 1);
  const unknown = harness({ response: () => moduleApiResponse(moduleApiEnvelope(moduleApiReply(), null)) });
  await fails(unknown.run(), 'usage', 'invalid_receipt'); assert.deepEqual(unknown.observations, [{ normal: false, source: 'moduleapi-server-estimated-configured-rates-not-invoice' }]);
  const zero = harness({ response: () => moduleApiResponse(moduleApiEnvelope(moduleApiReply(), { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 })) });
  await fails(zero.run(), 'usage', 'invalid_receipt');
  assert.deepEqual(zero.observations, [{ normal: false, source: 'moduleapi-server-estimated-configured-rates-not-invoice' }]);
  assert.equal(zero.calls(), 1);
});

const syntheticModuleApiKey = 'synthetic_moduleapi_not_a_real_key_12345';
const moduleApiEnvelope = (...args: Parameters<typeof openAiEnvelope>) => ({ ...openAiEnvelope(...args), model: MODULEAPI_MODEL });
const moduleApiResponse = (value: unknown = moduleApiEnvelope()) => new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } });


test('only the two explicit returned-model identifiers are accepted; a cost header cannot become invoice authority', async () => {
  assert.ok(Object.isFrozen(MODULEAPI_RETURNED_MODELS));
  assert.deepEqual(MODULEAPI_RETURNED_MODELS, ['gpt-5.4-mini', 'gpt-5.4-mini-2026-03-17']);
  for (const operation of ['summary', 'chat'] as const) {
    for (const model of MODULEAPI_RETURNED_MODELS) {
      const h = harness({ operation, response: () => new Response(JSON.stringify({ ...moduleApiEnvelope(moduleApiReply(operation)), model }),
        { headers: { 'content-type': 'application/json', 'x-moduleapi-cost': '0' } }) });
      const result = await h.run();
      assert.equal(result.usage.source, 'moduleapi-server-estimated-configured-rates-not-invoice');
      assert.equal(result.usage.costMicros, 40);
      assert.equal(h.sends(), 1);
    }
    for (const model of [null, '', 'gpt-5.4-mini-2026-03-18', 'openai/gpt-5.4-mini', 'gpt-5.4-mini ', 1]) {
      const h = harness({ operation, response: () => moduleApiResponse({ ...moduleApiEnvelope(moduleApiReply(operation)), model }) });
      await fails(h.run(), 'model', 'mismatch');
      assert.equal(h.observations.length, 0); assert.equal(h.sends(), 1);
    }
  }
});
