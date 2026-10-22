import { webcrypto } from 'node:crypto';
import { QueryClient } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { scanSession, transitionScanSession } from '@/shared/api/auth/scanSession';
import { createAdvisoryTranslationClient } from '@/shared/api/scans/advisoryTranslationClient';
import {
  translationContextSchema,
  translationReplySchema,
  translationRequestSchema,
  translationSourceVersion,
} from '@/shared/api/scans/advisoryTranslationContract';
import {
  backendTranslation,
  contextFor,
  finding,
  replyFor,
  translationApi,
} from './advisoryTranslationFixtures';
import { json } from './llmChatFixtures';

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  transitionScanSession('alice', new QueryClient(), true);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});
const signal = () => new AbortController().signal;
const consentFor = (value = contextFor()) => ({
  accepted: true as const,
  policyVersion: value.policyVersion!,
});

it('accepts actual backend disclosure/source versions and translation validators, and sends the exact text-free POST DTO', async () => {
  const api = translationApi();
  const client = createAdvisoryTranslationClient(scanSession(), api.fetcher);
  const context = await client.context(
    api.context.scanId,
    { findingId: finding.findingId, assessmentIndex: 0 },
    signal(),
  );
  const result = await client.translate(context, consentFor(context), signal());
  expect(translationContextSchema.parse(api.context)).toEqual(context);
  expect(await translationSourceVersion(finding.cveId, finding.advisory!.assessments[0])).toBe(
    context.sourceVersion,
  );
  expect(
    backendTranslation.validateTranslationReply(result.translation, {
      title: finding.advisory!.assessments[0].title.value,
      description: finding.advisory!.assessments[0].description.value,
    }),
  ).toEqual(result.translation);
  const post = api.requests.find((request) => request.init.method === 'POST')!;
  const body = JSON.parse(String(post.init.body));
  expect(body).toEqual({
    reportVersion: context.reportVersion,
    findingId: context.findingId,
    assessmentIndex: 0,
    sourceVersion: context.sourceVersion,
    targetLanguage: 'ru',
    consent: consentFor(context),
  });
  expect(backendTranslation.translationRequest(body)).toMatchObject({
    findingId: context.findingId,
    sourceVersion: context.sourceVersion,
  });
  expect(post.path).toBe(`/api/v1/browser/scans/${context.scanId}/llm/translation`);
  expect(post.init).toMatchObject({ credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
  expect(api.requests[0].path).toBe(
    `/api/v1/browser/scans/${context.scanId}/llm/translation/context?findingId=${context.findingId}&assessmentIndex=0`,
  );
  expect(String(post.init.body)).not.toMatch(
    /Package issue|contains a vulnerability|apiKey|question|history/,
  );
});

it('fails closed on unaccepted consent, changed policy, invalid selection and extra DTO keys, with zero POST', async () => {
  const api = translationApi();
  const client = createAdvisoryTranslationClient(scanSession(), api.fetcher);
  for (const consent of [
    { ...consentFor(), accepted: false },
    { ...consentFor(), policyVersion: 'f'.repeat(64) },
    { ...consentFor(), text: 'unexpected' },
  ]) {
    await expect(
      client.translate(api.context, consent as ReturnType<typeof consentFor>, signal()),
    ).rejects.toThrow();
  }
  for (const assessmentIndex of [-1, 16, 0.5])
    await expect(
      client.context(api.context.scanId, { findingId: finding.findingId, assessmentIndex }, signal()),
    ).rejects.toThrow();
  expect(api.requests).toHaveLength(0);
  expect(
    translationRequestSchema.safeParse({
      reportVersion: api.context.reportVersion,
      findingId: finding.findingId,
      assessmentIndex: 0,
      sourceVersion: api.context.sourceVersion,
      targetLanguage: 'en',
      consent: consentFor(),
    }).success,
  ).toBe(false);
});

for (const change of [
  'report',
  'finding',
  'index',
  'sourceVersion',
  'source',
  'language',
  'model',
  'target',
  'extra',
  'markup',
  'missing',
] as const) {
  it(`rejects ${change} in a completed response instead of publishing a false translation`, async () => {
    const api = translationApi();
    const reply = replyFor() as Record<string, unknown>;
    if (change === 'report') reply.reportVersion = 'f'.repeat(64);
    if (change === 'finding') reply.findingId = `vuln-${'f'.repeat(64)}`;
    if (change === 'index') reply.assessmentIndex = 1;
    if (change === 'sourceVersion') reply.sourceVersion = 'f'.repeat(64);
    if (change === 'source') reply.source = { ...api.context.source, source: 'alpine' };
    if (change === 'language') reply.source = { ...api.context.source, language: 'ru' };
    if (change === 'model') reply.model = 'another/model';
    if (change === 'target') reply.targetLanguage = 'en';
    if (change === 'extra') reply.severity = 'LOW';
    if (change === 'markup') reply.translation = { title: '<img src=x>', description: null };
    if (change === 'missing') reply.translation = { title: null, description: null };
    api.post = async () => json(reply);
    const client = createAdvisoryTranslationClient(scanSession(), api.fetcher);
    await expect(client.translate(api.context, consentFor(), signal())).rejects.toThrow();
    expect(api.requests.filter((request) => request.init.method === 'POST')).toHaveLength(1);
  });
}

it('keeps CVE and Debian TEMP source identities distinct without inventing CVE mappings', () => {
  const temp = {
    ...finding,
    findingId: `vuln-${'f'.repeat(64)}`,
    cveId: 'TEMP-1234567-ABCDEF',
    ecosystem: 'deb' as const,
  };
  const cveContext = contextFor();
  const tempContext = contextFor(temp);
  expect(tempContext.findingId).not.toBe(cveContext.findingId);
  expect(tempContext.sourceVersion).not.toBe(cveContext.sourceVersion);
  expect(translationReplySchema.parse(replyFor(tempContext)).findingId).toBe(temp.findingId);
});

for (const status of [401, 403, 404, 429, 503]) {
  it(`does not retry or echo diagnostics for HTTP ${status}`, async () => {
    const api = translationApi();
    api.post = async () =>
      json(
        {
          errorCode: status === 429 ? 'LLM_QUOTA_EXCEEDED' : 'LLM_PROVIDER_UNAVAILABLE',
          diagnostics: 'private diagnostic',
        },
        status,
      );
    const client = createAdvisoryTranslationClient(scanSession(), api.fetcher);
    const failure = await client.translate(api.context, consentFor(), signal()).catch((error) => error);
    expect(failure.message).not.toContain('private diagnostic');
    expect(api.requests).toHaveLength(1);
  });
}

for (const kind of ['content-type', 'oversize', 'length', 'utf8', 'redirect'] as const) {
  it(`rejects unsafe ${kind} wire delivery`, async () => {
    const api = translationApi();
    api.post = async () => {
      if (kind === 'content-type')
        return new Response(JSON.stringify(replyFor()), { headers: { 'content-type': 'text/html' } });
      if (kind === 'oversize')
        return new Response(' '.repeat(65537), { headers: { 'content-type': 'application/json' } });
      if (kind === 'length')
        return new Response(JSON.stringify(replyFor()), {
          headers: { 'content-type': 'application/json', 'content-length': '1' },
        });
      if (kind === 'utf8')
        return new Response(new Uint8Array([0xff]), { headers: { 'content-type': 'application/json' } });
      const response = json(replyFor());
      Object.defineProperty(response, 'redirected', { value: true });
      return response;
    };
    const client = createAdvisoryTranslationClient(scanSession(), api.fetcher);
    await expect(client.translate(api.context, consentFor(), signal())).rejects.toThrow();
    expect(api.requests).toHaveLength(1);
  });
}

it('bounds noncooperative fetch timeout and never resends automatically', async () => {
  vi.useFakeTimers();
  const fetcher = vi.fn<typeof fetch>(() => new Promise(() => {}));
  const client = createAdvisoryTranslationClient(scanSession(), fetcher);
  const rejected = expect(client.translate(contextFor(), consentFor(), signal())).rejects.toMatchObject({
    code: 'TIMEOUT',
  });
  await vi.advanceTimersByTimeAsync(40001);
  await rejected;
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it('aborts a pending read and rejects late results after same-owner reauthentication', async () => {
  let finish!: (response: Response) => void;
  let requestSignal: AbortSignal | null | undefined;
  const fetcher = vi.fn<typeof fetch>((_input, init) => {
    requestSignal = init?.signal;
    return new Promise<Response>((resolve) => {
      finish = resolve;
    });
  });
  const client = createAdvisoryTranslationClient(scanSession(), fetcher);
  const rejected = expect(
    client.context(contextFor().scanId, { findingId: finding.findingId, assessmentIndex: 0 }, signal()),
  ).rejects.toMatchObject({ code: 'SESSION' });
  transitionScanSession('alice', new QueryClient(), true);
  finish(json(contextFor()));
  await rejected;
  expect(requestSignal?.aborted).toBe(true);
});
