import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FixtureQuotaLedger as QuotaLedger } from './quota-fixtures.js';
import { LlmService, LlmRuntime } from '../llm.service.js';
import { LlmQuotaRuntime } from '../quota-runtime.js';
import { ReportReader } from '../report-context.js';
import { prepareSummary } from '../prepared-request.js';
import { OpenRouterProvider, type UsageReceipt } from '../openrouter-provider.js';
import { policyFromEnvironment } from '../policy.js';
import { quotaPolicy } from './quota-fixtures.js';
import { fakeKey, fixtureEnv, fixtureReport, reply } from './fixtures.js';
const policy = policyFromEnvironment({ ...fixtureEnv, LLM_FREE_ONLY: 'true', LLM_MODEL: 'apodex/apodex-1.1-mini:free', LLM_PROVIDER_ALLOWLIST: 'novita/bf16',
  LLM_RETENTION: 'no-storage', LLM_REQUEST_BUDGET_USD: '0', LLM_INPUT_PRICE_PER_MILLION_USD: '0', LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0' })!;
const binding = { subject: 'owner', scanId: fixtureReport.scanId, reportVersion: fixtureReport.reportVersion, policyVersion: policy.version };

test('actual adapter accounts bounded usage before invalid finish/content; overages and malformed cost never refund', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'quota-receipts-'));
  const ledger = new QuotaLedger(join(dir, 'llm-usage.sqlite'), quotaPolicy);
  try {
    const prepared = prepareSummary(fixtureReport, policy);
    for (const [usage, state] of [
      [{ prompt_tokens: 500, completion_tokens: 32, cost: 0 }, 'settled'],
      [{ prompt_tokens: 500, completion_tokens: 300, cost: 0.0001 }, 'fault'],
      [{ prompt_tokens: 500, completion_tokens: 32 }, 'fault'],
    ] as const) {
      const subject = `owner-${state}-${String(usage.cost)}`;
      const id = ledger.reserve({ ...binding, subject, requestHash: prepared.hash }, prepared.reserve); ledger.dispatch(id);
      const provider = new OpenRouterProvider(fakeKey, (async () => new Response(JSON.stringify({ model: policy.model, usage,
        choices: [{ finish_reason: 'length', message: { role: 'assistant', content: 'not JSON CANARY' } }] }), { headers: { 'content-type': 'application/json' } })) as typeof fetch);
      await assert.rejects(provider.summarizePrepared(prepared, policy, new AbortController().signal, { policy: quotaPolicy, observe: obs => { ledger.observe(id, obs); } }));
      const snapshot = ledger.snapshot(subject, binding.scanId);
      if (state === 'settled') { assert.equal(snapshot.scan.used.output, 32); assert.equal(snapshot.scan.held.input, 0); }
      else { assert.equal(snapshot.reason, 'policy_fault'); assert.ok(snapshot.scan.held.input >= prepared.reserve.input); }
    }
  } finally { ledger.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('late server-bound receipt after service timeout settles once without publishing or a second dispatch', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'quota-late-'));
  const ledger = new QuotaLedger(join(dir, 'llm-usage.sqlite'), quotaPolicy);
  let observer: UsageReceipt | undefined, resolve!: (value: unknown) => void, calls = 0;
  const shortPolicy = { ...policy, timeoutMs: 10 };
  const runtime = { policy: () => shortPolicy, provider: () => ({ prepare: prepareSummary,
    summarize: async () => { throw new Error('wrong seam'); },
    summarizePrepared: (_request: unknown, _policy: unknown, _signal: unknown, receipt: UsageReceipt) => {
      calls++; observer = receipt; return new Promise<unknown>(done => { resolve = done; });
    } }) } as unknown as LlmRuntime;
  const reports = { read: () => fixtureReport } as unknown as ReportReader;
  const quotas = { ledger: () => ledger } as unknown as LlmQuotaRuntime;
  const service = new LlmService(reports, runtime, quotas);
  const identity = { subject: 'owner', scope: ['scan:read'] };
  try {
    await assert.rejects(service.summary(() => identity, binding.scanId, { reportVersion: fixtureReport.reportVersion,
      consent: { accepted: true, policyVersion: shortPolicy.version } }, new AbortController().signal));
    assert.equal(calls, 1); assert.ok(ledger.snapshot('owner', binding.scanId).scan.held.input > 0);
    observer!.observe({ normal: true, input: 500, output: 32, costMicros: 0 });
    observer!.observe({ normal: true, input: 500, output: 32, costMicros: 0 });
    resolve(reply(fixtureReport)); await new Promise(done => setTimeout(done, 5));
    assert.equal(calls, 1); assert.equal(ledger.snapshot('owner', binding.scanId).scan.used.output, 32);
    assert.equal(ledger.snapshot('owner', binding.scanId).scan.held.input, 0);
  } finally { ledger.close(); rmSync(dir, { recursive: true, force: true }); }
});
