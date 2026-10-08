import { z } from 'zod';
import { scanSession, subscribeScanSession } from '@/shared/api/auth/scanSession';
import { BROWSER_SCANS_PATH, type ScanStatus, type ScanTransport } from './scanTransport';

const hash = z.string().regex(/^[a-f0-9]{64}$/);
// Deliberately reject control/bidi characters in untrusted display text.
// eslint-disable-next-line no-control-regex
const unsafeDisplayText = /[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/;
const text = z
  .string()
  .min(1)
  .max(2000)
  .refine((value) => !unsafeDisplayText.test(value));
const tuple = {
  scanId: z.string().uuid(),
  digest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  platform: z.literal('linux/amd64'),
  reportVersion: hash,
};
const disclosure = z
  .object({
    provider: z.literal('OpenRouter'),
    model: z.string().min(1).max(160),
    providers: z.array(z.string().min(1).max(64)).min(1).max(8),
    region: z.literal('global'),
    retention: z.enum(['no-training', 'no-storage']),
    operatorApprovedRouting: z.literal(true),
    providerComplianceNotProvenByDeclaration: z.literal(true),
    requestBudgetUsd: z.number().finite().nonnegative().max(1),
    data: text,
    freeOnly: z.boolean().optional(),
    maxPrice: z
      .object({
        prompt: z.number().finite().nonnegative().max(1000),
        completion: z.number().finite().nonnegative().max(1000),
        request: z.number().finite().nonnegative().nullable(),
      })
      .optional(),
  })
  .refine(
    (policy) =>
      policy.freeOnly !== true ||
      (policy.requestBudgetUsd === 0 &&
        policy.maxPrice?.prompt === 0 &&
        policy.maxPrice.completion === 0 &&
        policy.maxPrice.request === 0),
  );
const contextSchema = z
  .object({
    ...tuple,
    enabled: z.boolean(),
    policyVersion: hash.nullable(),
    disclosure: disclosure.nullable(),
  })
  .refine((value) =>
    value.enabled
      ? value.policyVersion !== null && value.disclosure !== null
      : value.policyVersion === null && value.disclosure === null,
  );
const findingId = z.string().regex(/^(?:secret-\d{1,6}-\d{1,6}|vuln-[a-f0-9]{64}|sha256:[a-f0-9]{64})$/);
const replySchema = z.object({
  ...tuple,
  hypotheses: z
    .array(
      z.strictObject({
        kind: z.literal('hypothesis'),
        text,
        citations: z
          .array(findingId)
          .min(1)
          .max(20)
          .refine((ids) => new Set(ids).size === ids.length),
      }),
    )
    .min(1)
    .max(12),
  // Only these source fields are displayed. Other server facts never become generated HTML or links.
  scannerFacts: z
    .array(
      z.object({
        findingId: z.string().min(1).max(200),
        check: z.enum(['secret', 'vuln', 'config']),
        severity: z.string().max(20),
      }),
    )
    .max(1000),
});
export type SummaryContext = z.infer<typeof contextSchema>;
export type SummaryReply = z.infer<typeof replySchema>;
export type SummarySource = { findingId: string; check: 'secret' | 'vuln' | 'config'; label: string };
export type SummaryClient = ReturnType<typeof createSummaryClient>;
export class SummaryError extends Error {
  constructor(readonly code: string) {
    super('ИИ-сводка недоступна');
  }
}
export function summaryErrorMessage(error: unknown): string {
  const code = error instanceof SummaryError ? error.code : '';
  if (code === 'LLM_NO_EVIDENCE')
    return 'Нет подтверждённых находок для сводки. Это не означает, что непроверенные области безопасны.';
  if (['LLM_STALE_REPORT', 'LLM_STALE_POLICY', 'STALE'].includes(code))
    return 'Отчёт или политика изменились. Обновите условия и подтвердите согласие заново.';
  if (['LLM_CAPACITY', 'LLM_BUDGET_EXCEEDED', 'LLM_QUOTA_EXCEEDED'].includes(code))
    return 'Достигнут лимит запросов или бюджета. Попробуйте позднее; отчёт сканеров сохранён.';
  if (['TIMEOUT', 'LLM_REQUEST_ABORTED', 'LLM_PROVIDER_TIMEOUT'].includes(code))
    return 'Сводка не получена вовремя. Можно повторить вручную после нового согласия.';
  if (code === 'LLM_CONFIGURATION_UNAVAILABLE')
    return 'ИИ не настроен или выключен. Доступность модели и ключа не подтверждена.';
  if (code === 'SESSION') return 'Сессия изменилась. Сводка и согласие сброшены.';
  return 'Не удалось безопасно получить сводку. Исходный отчёт остаётся доступен; обновите условия или попробуйте позднее.';
}
export const contextFence = (value: SummaryContext) => JSON.stringify(value);
export function matchesSummaryTuple(
  value: Pick<SummaryContext, 'scanId' | 'digest' | 'platform' | 'reportVersion'>,
  context: SummaryContext,
) {
  return (
    value.scanId === context.scanId &&
    value.digest === context.digest &&
    value.platform === context.platform &&
    value.reportVersion === context.reportVersion
  );
}

export function createSummaryClient(session: ReturnType<typeof scanSession>, fetcher: typeof fetch = fetch) {
  const current = () => {
    const now = scanSession();
    return !!session.subject && now.subject === session.subject && now.generation === session.generation;
  };
  async function request(
    scanId: string,
    endpoint: 'context' | 'summary',
    signal: AbortSignal,
    body?: object,
  ): Promise<unknown> {
    if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(scanId))
      throw new SummaryError('INVALID');
    if (!current()) throw new SummaryError('SESSION');
    const controller = new AbortController();
    let timedOut = false;
    const abort = () => controller.abort();
    const unsubscribe = subscribeScanSession(abort);
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    const deadline = setTimeout(() => {
      timedOut = true;
      abort();
    }, 35_000);
    const stopped = new Promise<never>((_, reject) => {
      const rejectAbort = () =>
        reject(new SummaryError(!current() ? 'SESSION' : timedOut ? 'TIMEOUT' : 'ABORTED'));
      controller.signal.addEventListener('abort', rejectAbort, { once: true });
      if (controller.signal.aborted) rejectAbort();
    });
    const operation = async () => {
      if (controller.signal.aborted) throw new SummaryError('ABORTED');
      const response = await fetcher(`${BROWSER_SCANS_PATH}/${scanId}/llm/${endpoint}`, {
        method: body ? 'POST' : 'GET',
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
      });
      if (!current() || controller.signal.aborted) {
        void response.body?.cancel().catch(() => {});
        throw new SummaryError('SESSION');
      }
      const reader = response.body?.getReader();
      if (!reader) throw new SummaryError('INVALID');
      const cancelReader = () => {
        void reader.cancel().catch(() => {});
      };
      controller.signal.addEventListener('abort', cancelReader, { once: true });
      const chunks: Uint8Array[] = [];
      let size = 0;
      try {
        while (true) {
          const part = await reader.read();
          if (controller.signal.aborted) throw new SummaryError('ABORTED');
          if (part.done) break;
          size += part.value.byteLength;
          if (size > 65_536) throw new SummaryError('INVALID');
          chunks.push(part.value);
        }
      } finally {
        controller.signal.removeEventListener('abort', cancelReader);
        cancelReader();
        reader.releaseLock();
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
      }
      const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      if (!current() || controller.signal.aborted) throw new SummaryError('SESSION');
      if (!response.ok) {
        const code = z.object({ errorCode: z.string().regex(/^[A-Z_]{1,64}$/) }).safeParse(value);
        throw new SummaryError(code.success ? code.data.errorCode : 'UNAVAILABLE');
      }
      return value;
    };
    try {
      return await Promise.race([operation(), stopped]);
    } finally {
      clearTimeout(deadline);
      unsubscribe();
      signal.removeEventListener('abort', abort);
      controller.abort();
    }
  }
  return {
    current,
    async context(scanId: string, signal: AbortSignal) {
      const context = contextSchema.parse(await request(scanId, 'context', signal));
      if (context.scanId !== scanId) throw new SummaryError('STALE');
      return context;
    },
    async summary(context: SummaryContext, signal: AbortSignal) {
      if (!context.enabled || !context.policyVersion) throw new SummaryError('LLM_CONFIGURATION_UNAVAILABLE');
      const reply = replySchema.parse(
        await request(context.scanId, 'summary', signal, {
          reportVersion: context.reportVersion,
          consent: { accepted: true, policyVersion: context.policyVersion },
        }),
      );
      if (!matchesSummaryTuple(reply, context)) throw new SummaryError('STALE');
      return reply;
    },
  };
}

/** Read all checked finding pages, not the current UI tab/page. SBOM is inventory, not cited findings. */
export async function collectSummarySources(
  transport: ScanTransport,
  status: ScanStatus,
  signal: AbortSignal,
): Promise<SummarySource[]> {
  const sources: SummarySource[] = [];
  const ids = new Set<string>();
  const add = (source: SummarySource) => {
    if (signal.aborted || ids.has(source.findingId) || sources.length >= 1000)
      throw new SummaryError('INVALID');
    ids.add(source.findingId);
    sources.push(source);
  };
  for (const finding of status.config?.findings ?? [])
    add({ findingId: finding.findingId, check: 'config', label: `${finding.ruleId} · ${finding.severity}` });
  for (const check of ['secret', 'vuln'] as const) {
    if (status.perCheck?.[check]?.outcome !== 'checked') continue;
    let cursor: string | undefined;
    let total = 0;
    let expected: number | null | undefined;
    for (let index = 0; index < 21; index++) {
      const page =
        check === 'secret'
          ? await transport.results(status.scanId, cursor, signal)
          : await transport.vuln(status.scanId, cursor, signal);
      if (signal.aborted) throw new SummaryError('ABORTED');
      const count =
        'outcome' in page
          ? page.outcome === 'checked'
            ? page.findingCount
            : null
          : page.coverage.find((item) => item.check === 'Secrets' && item.status === 'checked')?.findingCount;
      if (count == null || count > 1000 || (expected !== undefined && expected !== count))
        throw new SummaryError('INVALID');
      expected = count;
      if ('image' in page && (!page.image.endsWith(`@${status.digest}`) || page.platform !== status.platform))
        throw new SummaryError('STALE');
      for (const finding of page.findings)
        add({
          findingId: finding.findingId,
          check,
          label:
            'cveId' in finding ? `${finding.cveId} · ${finding.severity}` : `${finding.ruleId} · Secrets`,
        });
      total += page.findings.length;
      if (page.nextCursor === null) {
        if (total !== expected || status.perCheck?.[check]?.findingCount !== expected)
          throw new SummaryError('INVALID');
        break;
      }
      if (!page.findings.length || page.nextCursor !== String(total) || index === 20)
        throw new SummaryError('INVALID');
      cursor = page.nextCursor;
    }
  }
  return sources;
}
export function verifiedSummarySources(reply: SummaryReply, sources: SummarySource[]) {
  const byId = new Map(sources.map((source) => [source.findingId, source]));
  const facts = new Map(reply.scannerFacts.map((fact) => [fact.findingId, fact]));
  if (facts.size !== reply.scannerFacts.length) throw new SummaryError('INVALID');
  const cited = new Set(reply.hypotheses.flatMap((hypothesis) => hypothesis.citations));
  for (const id of cited) {
    const source = byId.get(id);
    if (!source || facts.get(id)?.check !== source.check) throw new SummaryError('INVALID');
  }
  return sources.filter((source) => cited.has(source.findingId));
}
