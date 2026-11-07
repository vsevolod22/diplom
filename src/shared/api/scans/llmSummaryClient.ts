import { z } from 'zod';
import { isCveId, isDebianTempId, isDebianDlaId, identifierLabel } from './publicVulnerabilityIdentifiers';
import {
  freeProfileSchema,
  openAiDisclosureSchema,
  publicChatMetadataShape,
  scannerDisclosureData,
  validPublicChatMetadata,
  validScannerDisclosure,
} from './llmPublicContract';
import { publicSafeFinding, type LlmFinding } from './llmFindingContract';
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
  .strictObject({
    provider: z.literal('OpenRouter'),
    model: z.string().min(1).max(160),
    providers: z.array(z.string().min(1).max(64)).min(1).max(8),
    region: z.literal('global'),
    retention: z.enum(['no-training', 'no-storage']),
    operatorApprovedRouting: z.literal(true),
    providerComplianceNotProvenByDeclaration: z.literal(true),
    requestBudgetUsd: z.number().finite().nonnegative().max(1),
    data: scannerDisclosureData,
    freeOnly: z.boolean().optional(),
    maxPrice: z
      .strictObject({
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
        policy.maxPrice.request === 0 &&
        freeProfileSchema.safeParse({
          model: policy.model,
          providers: policy.providers,
          retention: policy.retention,
        }).success),
  )
  .refine(validScannerDisclosure);
export const summaryContextSchema = z
  .strictObject({
    ...tuple,
    enabled: z.boolean(),
    unavailableReason: z.literal('LLM_SUMMARY_UNSUPPORTED_REPORT').optional(),
    summaryResultRead: z.boolean().optional(),
    policyVersion: hash.nullable(),
    disclosure: z.discriminatedUnion('provider', [disclosure, openAiDisclosureSchema]).nullable(),
    ...publicChatMetadataShape,
  })
  .refine(validPublicChatMetadata)
  .refine((value) =>
    value.enabled
      ? value.policyVersion !== null && value.disclosure !== null
      : value.policyVersion === null && value.disclosure === null,
  )
  .refine(
    (value) =>
      value.unavailableReason === undefined ||
      (!value.enabled &&
        value.policyVersion === null &&
        value.disclosure === null &&
        value.summaryResultRead !== true),
  );
const findingId = z.string().regex(/^(?:secret-\d{1,6}-\d{1,6}|vuln-[a-f0-9]{64}|sha256:[a-f0-9]{64})$/);
const summaryContextSelectionSchema = z
  .strictObject({
    totalFindings: z.number().int().min(1).max(1000),
    selectedFindings: z.number().int().min(1).max(1000),
    omittedFindings: z.number().int().min(0).max(1000),
    strategy: z.literal('all-critical-and-unknown-then-severity'),
    selectedFindingIds: z
      .array(findingId)
      .min(1)
      .max(1000)
      .refine((ids) => new Set(ids).size === ids.length),
  })
  .refine(
    (selection) =>
      selection.selectedFindings === selection.selectedFindingIds.length &&
      selection.selectedFindings + selection.omittedFindings === selection.totalFindings,
  );
export const summaryReplySchema = z
  .strictObject({
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
    // Exact technical details come from server facts, never from generated prose.
    scannerFacts: z
      .array(
        z.union([
          // Earlier summary DTOs carried only these three fields.
          z.strictObject({
            findingId,
            check: z.enum(['secret', 'vuln', 'config']),
            severity: z.string().max(20),
          }),
          publicSafeFinding,
        ]),
      )
      .max(1000),
    ...publicChatMetadataShape,
    contextSelection: summaryContextSelectionSchema.optional(),
  })
  .refine(validPublicChatMetadata)
  .refine((reply) => {
    // Legacy replies have no public metadata. A native public reply carries the whole group,
    // while scannerFacts contains only cited rows from the selected subset, not all findings.
    if (reply.findingCount === undefined) return reply.contextSelection === undefined;
    const selection = reply.contextSelection;
    if (!selection || selection.totalFindings !== reply.findingCount) return false;
    const selected = new Set(selection.selectedFindingIds);
    const cited = new Set(reply.hypotheses.flatMap((paragraph) => paragraph.citations));
    const facts = new Set(reply.scannerFacts.map((fact) => fact.findingId));
    if (
      facts.size !== reply.scannerFacts.length ||
      facts.size !== cited.size ||
      [...cited].some((id) => !selected.has(id) || !facts.has(id))
    )
      return false;
    return reply.scannerFacts.every(
      (fact) => cited.has(fact.findingId) && publicSafeFinding.safeParse(fact).success,
    );
  });
export type SummaryContext = z.infer<typeof summaryContextSchema>;
export type SummaryReply = z.infer<typeof summaryReplySchema>;
export type SummarySource = {
  findingId: string;
  check: 'secret' | 'vuln' | 'config';
  label: string;
  finding?: LlmFinding;
};
export type SummaryClient = Omit<ReturnType<typeof createSummaryClient>, 'existing'> & {
  existing?: ReturnType<typeof createSummaryClient>['existing'];
};
// Mirror server/api/src/llm/provider-diagnostic.ts without importing backend runtime code.
const SUMMARY_FAILURE_PHASES = [
  'request', 'connect', 'tls', 'dispatch_guard', 'headers', 'body', 'json', 'model',
  'envelope', 'finish', 'content', 'usage', 'accounting', 'deadline', 'caller_abort',
  'language', 'grounding', 'translation_title', 'translation_description',
] as const;
const SUMMARY_FAILURE_REASONS = [
  'invalid_request', 'rejected', 'io_error', 'timeout', 'aborted', 'http_error',
  'invalid_type', 'limit', 'invalid_json', 'mismatch', 'invalid_shape', 'invalid_finish',
  'invalid_content', 'invalid_receipt', 'observation_failed', 'not_russian',
  'unknown_identifier', 'finish_length', 'finish_content_filter', 'finish_tool_calls',
  'finish_error', 'finish_unknown', 'null_mismatch', 'unsafe_text', 'invalid_markup',
  'identifier_mismatch', 'nonprose_changed', 'not_normalized', 'invalid_link',
] as const;
export type SummaryFailureDiagnostic = Readonly<{
  httpStatus: number;
  phase?: (typeof SUMMARY_FAILURE_PHASES)[number];
  reason?: (typeof SUMMARY_FAILURE_REASONS)[number];
}>;
function summaryFailureDiagnostic(
  httpStatus: number,
  phase: unknown,
  reason: unknown,
): SummaryFailureDiagnostic {
  const finitePhase = SUMMARY_FAILURE_PHASES.find((value) => value === phase);
  const finiteReason = SUMMARY_FAILURE_REASONS.find((value) => value === reason);
  return Object.freeze({
    httpStatus,
    ...(finitePhase && finiteReason ? { phase: finitePhase, reason: finiteReason } : {}),
  });
}
export class SummaryError extends Error {
  readonly diagnostic?: SummaryFailureDiagnostic;
  constructor(readonly code: string, readonly httpStatus?: number, diagnostic?: SummaryFailureDiagnostic) {
    super('ИИ-сводка недоступна');
    this.diagnostic = diagnostic
      ? summaryFailureDiagnostic(diagnostic.httpStatus, diagnostic.phase, diagnostic.reason)
      : undefined;
  }
}
export function isUnsupportedSummaryReport(error: unknown): boolean {
  return error instanceof SummaryError && error.code === 'LLM_SUMMARY_UNSUPPORTED_REPORT';
}
export function summaryErrorMessage(error: unknown): string {
  if (isUnsupportedSummaryReport(error))
    return 'ИИ-разбор недоступен для этого формата отчёта. Исходные результаты сканирования доступны ниже.';
  const code = error instanceof SummaryError ? error.code : '';
  if (code === 'LLM_NO_EVIDENCE')
    return 'Для разбора недостаточно находок. Это не означает, что образ безопасен.';
  if (['LLM_STALE_REPORT', 'LLM_STALE_POLICY', 'STALE'].includes(code))
    return 'Отчёт или условия разбора изменились. Повторите разбор вручную.';
  if (code === 'LLM_QUOTA_EXCEEDED')
    return 'Локальная квота ИИ не допускает новый разбор. Проверьте остаток и резервы; отчёт сканеров доступен.';
  if (code === 'LLM_QUOTA_UNAVAILABLE')
    return 'Не удалось проверить учёт ИИ. Генерация остановлена; остаток неизвестен. Отчёт сканеров доступен.';
  if (
    ['LLM_CAPACITY', 'LLM_BUDGET_EXCEEDED', 'LLM_PROVIDER_RATE_LIMITED'].includes(code)
  )
    return 'ИИ-разбор временно недоступен. Попробуйте позднее; отчёт сканеров доступен.';
  if (['TIMEOUT', 'LLM_REQUEST_ABORTED', 'LLM_PROVIDER_TIMEOUT'].includes(code))
    return 'Не дождались ответа ИИ. Можно повторить разбор вручную.';
  if (code === 'LLM_INVALID_RESPONSE' || code === 'INVALID')
    return 'Ответ ИИ не прошёл проверку достоверности или формата и не показан. Исходные находки сохранены; можно повторить разбор вручную.';
  if (code === 'ABORTED') return 'Разбор остановлен. Исходные находки доступны.';
  if (code === 'LLM_CONFIGURATION_UNAVAILABLE')
    return 'ИИ-разбор сейчас недоступен. Отчёт сканеров доступен.';
  if (code === 'SESSION') return 'Сессия изменилась. Откройте отчёт заново.';
  return 'Не удалось получить разбор ИИ. Отчёт сканеров доступен; можно повторить вручную.';
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
    const deadline = setTimeout(
      () => {
        timedOut = true;
        abort();
      },
      body ? 105_000 : 35_000,
    );
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
      const diagnostic = !response.ok && endpoint === 'summary' && body
        ? summaryFailureDiagnostic(
            response.status,
            response.headers.get('X-LLM-Failure-Phase'),
            response.headers.get('X-LLM-Failure-Reason'),
          )
        : undefined;
      let value: unknown;
      try {
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
        value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      } catch (error) {
        if (diagnostic && current() && !controller.signal.aborted)
          throw new SummaryError('INVALID', response.status, diagnostic);
        throw error;
      }
      if (!current() || controller.signal.aborted) throw new SummaryError('SESSION');
      if (!response.ok) {
        const code = z.object({ errorCode: z.string().regex(/^[A-Z_]{1,64}$/) }).safeParse(value);
        throw new SummaryError(code.success ? code.data.errorCode : 'UNAVAILABLE', response.status, diagnostic);
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
      const context = summaryContextSchema.parse(await request(scanId, 'context', signal));
      if (context.scanId !== scanId) throw new SummaryError('STALE');
      return context;
    },
    async existing(context: SummaryContext, signal: AbortSignal): Promise<SummaryReply | null> {
      let value: unknown;
      try {
        value = await request(context.scanId, 'summary', signal);
      } catch (error) {
        if (error instanceof SummaryError && error.code === 'LLM_SUMMARY_MISSING' && error.httpStatus === 404) return null;
        throw error;
      }
      const reply = summaryReplySchema.parse(value);
      if (!matchesSummaryTuple(reply, context)) throw new SummaryError('STALE');
      return reply;
    },
    async summary(context: SummaryContext, signal: AbortSignal) {
      if (context.unavailableReason === 'LLM_SUMMARY_UNSUPPORTED_REPORT')
        throw new SummaryError(context.unavailableReason);
      if (!context.enabled || !context.policyVersion) throw new SummaryError('LLM_CONFIGURATION_UNAVAILABLE');
      const reply = summaryReplySchema.parse(
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
    let cve = 0;
    let debianTemp = 0;
    let debianDla = 0;
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
      if (
        check === 'vuln' &&
        'outcome' in page &&
        page.outcome === 'checked' &&
        (page.profile !== status.profile ||
          page.identifierCounts?.cve !== status.identifierCounts?.cve ||
          page.identifierCounts?.debianTemp !== status.identifierCounts?.debianTemp ||
          (page.identifierCounts?.debianDla ?? 0) !== (status.identifierCounts?.debianDla ?? 0))
      )
        throw new SummaryError('STALE');
      if ('image' in page && (!page.image.endsWith(`@${status.digest}`) || page.platform !== status.platform))
        throw new SummaryError('STALE');
      for (const finding of page.findings) {
        if ('cveId' in finding) {
          if (isCveId(finding.cveId)) cve++;
          else if (isDebianTempId(finding.cveId)) debianTemp++;
          else if (isDebianDlaId(finding.cveId)) debianDla++;
        }
        add({
          findingId: finding.findingId,
          check,
          label:
            'cveId' in finding
              ? `${finding.cveId}${isCveId(finding.cveId) ? '' : ` · ${identifierLabel(finding.cveId)}`} · ${finding.severity}`
              : `${finding.ruleId} · Secrets`,
        });
      }
      total += page.findings.length;
      if (page.nextCursor === null) {
        if (
          total !== expected ||
          status.perCheck?.[check]?.findingCount !== expected ||
          (check === 'vuln' &&
            status.identifierCounts &&
            (cve !== status.identifierCounts.cve || debianTemp !== status.identifierCounts.debianTemp ||
                          debianDla !== (status.identifierCounts.debianDla ?? 0)))
        )
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
  return sources.filter((source) => cited.has(source.findingId)).map((source) => {
    // Keep legacy three-field facts usable; retain full validated server facts for citation cards.
    const finding = publicSafeFinding.safeParse(facts.get(source.findingId));
    return finding.success ? { ...source, finding: finding.data } : source;
  });
}
