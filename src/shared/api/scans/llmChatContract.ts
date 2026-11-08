import { z } from 'zod';
import {
  chatContextSelectionSchema,
  scannerDisclosureData,
  validScannerDisclosure,
  freeProfileSchema,
  openAiDisclosureSchema,
  openAiReadinessShape,
  validOpenAiReadiness,
  OPENAI_COST_BASIS,
  MODULEAPI_COST_BASIS,
  moduleApiDisclosureSchema,
  moduleApiReadinessShape,
  validModuleApiReadiness,
  publicChatMetadataShape,
  publicReadinessShape,
  providerFailureSchema,
  validProviderError,
  type ProviderErrorCode,
  type ProviderFailure,
  validPublicChatMetadata,
  validPublicReadiness,
} from './llmPublicContract';
import { publicSafeFinding } from './llmFindingContract';
import { vulnerabilityIdentifierKind } from './publicVulnerabilityIdentifiers';
import { serializedBytes, utf8Bytes } from './vulnAdvisory';

const hash = z.string().regex(/^[a-f0-9]{64}$/);
const uuid = z.string().regex(/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/);
const count = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
export const chatBindingSchema = z.strictObject({
  scanId: uuid,
  digest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  platform: z.literal('linux/amd64'),
  reportVersion: hash,
});
export type ChatBinding = z.infer<typeof chatBindingSchema>;
export const sameChatBinding = (a: ChatBinding, b: ChatBinding) =>
  a.scanId === b.scanId &&
  a.digest === b.digest &&
  a.platform === b.platform &&
  a.reportVersion === b.reportVersion;

// Mirror server/api/src/llm/chat-source-budget.ts: unchanged aggregate and wire
// limits, full source objects. The largest fixed citation frame leaves this exact
// byte budget for its source, including the terminating newline.
const budgetUuid = '00000000-0000-0000-0000-000000000000';
export const CHAT_SOURCE_BUDGET = Object.freeze({
  revision: 'immutable-full-citations-aggregate-v2',
  citationBytes:
    8192 -
    (serializedBytes({
      v: 1,
      deliveryMode: 'validated-completed-reply',
      nativeProviderStream: false,
      scanId: budgetUuid,
      digest: `sha256:${'0'.repeat(64)}`,
      platform: 'linux/amd64',
      reportVersion: '0'.repeat(64),
      epoch: budgetUuid,
      revision: Number.MAX_SAFE_INTEGER,
      mutationId: budgetUuid,
      turnId: budgetUuid,
      type: 'citation',
      seq: 51,
      index: 31,
      source: null,
    }) -
      4 +
      1),
  sourcesBytes: 32 * 2048,
});

// Match the actual conservative server text boundary, including UTF-8 rather than JS length.
export function validChatText(value: string, limit = 2048) {
  return (
    !!value.trim() &&
    utf8Bytes(value) <= limit &&
    // eslint-disable-next-line no-control-regex
    !/[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\ud800-\udfff<>]|CANARY|[a-z][a-z0-9+.-]*:\/\/|javascript:|data:|file:|www\.|[A-Za-z0-9_+/=-]{40,}|\b(?:Bearer|password|api[_-]?key|token|secret)\s*[:=]|\b(?:sk-|sk-or-|AKIA)[A-Za-z0-9_-]+/iu.test(
      value,
    )
  );
}
const text = (limit: number) => z.string().refine((v) => validChatText(v, limit));
export const chatSourceSchema = z
  .strictObject({ ...chatBindingSchema.shape, finding: publicSafeFinding })
  .refine(
    ({ finding: f }) =>
      f.check !== 'vuln' ||
      (vulnerabilityIdentifierKind(f.cveId) === 'cve'
        ? f.identifierKind === undefined || f.identifierKind === 'cve'
        : f.identifierKind === vulnerabilityIdentifierKind(f.cveId) && f.ecosystem === 'deb'),
  )
  .refine((v) => serializedBytes(v) <= CHAT_SOURCE_BUDGET.citationBytes);
const sources = z
  .array(chatSourceSchema)
  .max(32)
  .refine(
    (v) => v.reduce((sum, source) => sum + serializedBytes(source), 0) <= CHAT_SOURCE_BUDGET.sourcesBytes,
  )
  .refine((v) => new Set(v.map((s) => s.finding.findingId)).size === v.length);
export const chatReplySchema = z
  .strictObject({
    ...chatBindingSchema.shape,
    kind: z.literal('hypothesis'),
    text: text(16384),
    sources: sources.refine((v) => v.length > 0),
  })
  .refine((v) => v.sources.every((s) => sameChatBinding(s, v)));
const turnBase = {
  id: uuid,
  mutationId: uuid,
  question: text(2048),
  report: chatBindingSchema,
  createdAt: count,
};
const turn = z.union([
  z
    .strictObject({ ...turnBase, state: z.literal('completed'), reply: chatReplySchema })
    .refine((v) => sameChatBinding(v.reply, v.report)),
  z.strictObject({ ...turnBase, state: z.enum(['pending', 'failed', 'cancelled', 'interrupted']) }),
]);
export const chatHistorySchema = z
  .strictObject({
    ...chatBindingSchema.shape,
    epoch: uuid,
    revision: count,
    turns: z.array(turn).max(256),
    decisions: z
      .array(
        z
          .strictObject({
            id: uuid,
            mutationId: uuid,
            kind: z.literal('user-decision'),
            text: text(2048),
            report: chatBindingSchema,
            sources,
          })
          .refine((v) => v.sources.every((s) => sameChatBinding(s, v.report))),
      )
      .max(128),
    pending: z.strictObject({ turnId: uuid, state: z.literal('pending') }).nullable(),
    retention: z.literal(
      'Confirmed history persists until separately authorized operator lifecycle; no automatic expiry or reset.',
    ),
  })
  .refine((v) => {
    const entries = [...v.turns, ...v.decisions];
    const pending = v.turns.filter((t) => t.state === 'pending');
    return (
      entries.every((e) => e.report.scanId === v.scanId) &&
      new Set(entries.map((e) => e.id)).size === entries.length &&
      new Set(entries.map((e) => e.mutationId)).size === entries.length &&
      pending.length === (v.pending ? 1 : 0) &&
      (!v.pending || pending[0].id === v.pending.turnId) &&
      entries.reduce(
        (n, e) =>
          n + ('sources' in e ? e.sources.length : e.state === 'completed' ? e.reply.sources.length : 0),
        0,
      ) <= 4096
    );
  });
const chatDisclosureFields = {
  sentData: z.literal(
    'Cleaned question, all user history/accepted decisions and selected findings with complete coverage.',
  ),
  localRetention: z.literal(
    'Durable owner+scan history until separately authorized operator lifecycle; capacity can refuse; context cache only, not output cache.',
  ),
};
const openAiChatDisclosure = z.discriminatedUnion('monetaryLimit', [
  openAiDisclosureSchema.options[0].extend(chatDisclosureFields),
  openAiDisclosureSchema.options[1].extend(chatDisclosureFields),
]);
const moduleApiChatDisclosure = z.discriminatedUnion('monetaryLimit', [
  moduleApiDisclosureSchema.options[0].extend(chatDisclosureFields),
  moduleApiDisclosureSchema.options[1].extend(chatDisclosureFields),
]);
const disclosure = z
  .strictObject({
    provider: z.literal('OpenRouter'),
    model: z.enum(['apodex/apodex-1.1-mini:free', 'dots-studio/dots-3-note-preview:free']),
    providers: z.tuple([z.enum(['novita/bf16', 'atlas-cloud/fp8'])]),
    region: z.literal('global'),
    retention: z.enum(['no-storage', 'no-training']),
    operatorApprovedRouting: z.literal(true),
    providerComplianceNotProvenByDeclaration: z.literal(true),
    requestBudgetUsd: z.literal(0),
    freeOnly: z.literal(true),
    maxPrice: z.strictObject({ prompt: z.literal(0), completion: z.literal(0), request: z.literal(0) }),
    data: scannerDisclosureData,
    sentData: z.literal(
      'Cleaned question, all user history/accepted decisions and selected findings with complete coverage.',
    ),
    localRetention: z.literal(
      'Durable owner+scan history until separately authorized operator lifecycle; capacity can refuse; context cache only, not output cache.',
    ),
  })
  .refine(
    (v) =>
      freeProfileSchema.safeParse({ model: v.model, providers: v.providers, retention: v.retention })
        .success && validScannerDisclosure(v),
  );
export const chatContextSchema = z
  .strictObject({
    ...chatBindingSchema.shape,
    epoch: uuid,
    revision: count,
    enabled: z.boolean(),
    policyVersion: hash.nullable(),
    disclosure: z
      .discriminatedUnion('provider', [disclosure, openAiChatDisclosure, moduleApiChatDisclosure])
      .nullable(),
    limits: z.strictObject({ questionBytes: z.literal(2048), bodyBytes: z.literal(8192) }),
    deliveryMode: z.literal('completed-response'),
    pending: z.boolean(),
    ...publicChatMetadataShape,
  })
  .refine(validPublicChatMetadata)
  .refine((v) =>
    v.enabled ? !!v.policyVersion && !!v.disclosure : v.policyVersion === null && v.disclosure === null,
  );
export const duplicateSchema = z.strictObject({
  duplicate: z.literal(true),
  id: uuid,
  state: z.enum(['pending', 'completed', 'failed', 'cancelled', 'interrupted']),
  epoch: uuid,
  revision: count,
});
export const chatReceiptSchema = z.discriminatedUnion('source', [
  z.strictObject({
    input: count,
    output: count.max(4096),
    costMicros: z.literal(0),
    source: z.literal('server-validated-provider-reported-not-invoice'),
  }),
  z.strictObject({
    input: count.positive(),
    output: count.max(4096),
    costMicros: count.positive(),
    source: z.literal(OPENAI_COST_BASIS),
  }),
  z.strictObject({
    input: count.positive(),
    output: count.max(4096),
    costMicros: count.positive(),
    source: z.literal(MODULEAPI_COST_BASIS),
  }),
]);
export function chatReceiptMatchesProvider(usage: z.infer<typeof chatReceiptSchema>, context: ChatContext) {
  return (
    !!context.disclosure &&
    usage.source ===
      (context.disclosure.provider === 'OpenAI'
        ? OPENAI_COST_BASIS
        : context.disclosure.provider === 'ModuleAPI'
          ? MODULEAPI_COST_BASIS
          : 'server-validated-provider-reported-not-invoice')
  );
}
export const chatResultSchema = z.union([
  duplicateSchema,
  z
    .strictObject({
      ...chatBindingSchema.shape,
      epoch: uuid,
      revision: count,
      turnId: uuid,
      deliveryMode: z.enum(['completed-response', 'validated-completed-reply']),
      reply: chatReplySchema,
      usage: chatReceiptSchema,
      ...publicChatMetadataShape,
      contextSelection: chatContextSelectionSchema.optional(),
    })
    .refine(validPublicChatMetadata)
    .refine(
      (v) =>
        v.deliveryMode !== 'completed-response' ||
        !v.reply.sources.some(
          (source) => source.finding.check === 'vuln' && source.finding.identifierKind !== undefined,
        ) ||
        v.findingCount !== undefined,
    )
    .refine((v) =>
      v.findingCount === undefined
        ? v.contextSelection === undefined
        : !!v.contextSelection &&
          v.contextSelection.findings + v.contextSelection.selectedFindingIds.length === v.findingCount &&
          v.reply.sources.every((source) =>
            v.contextSelection!.selectedFindingIds.includes(source.finding.findingId),
          ),
    )
    .refine((v) => sameChatBinding(v.reply, v)),
]);
export const chatReadinessSchema = z.union([
  z.strictObject({ ...chatBindingSchema.shape, ...publicReadinessShape }).refine(validPublicReadiness),
  z.strictObject({ ...chatBindingSchema.shape, ...openAiReadinessShape }).refine(validOpenAiReadiness),
  z.strictObject({ ...chatBindingSchema.shape, ...moduleApiReadinessShape }).refine(validModuleApiReadiness),
]);
export type ChatReadiness = z.infer<typeof chatReadinessSchema>;
export type ChatContext = z.infer<typeof chatContextSchema>;
export type ChatHistory = z.infer<typeof chatHistorySchema>;
export type ChatSource = z.infer<typeof chatSourceSchema>;
export type ChatReply = z.infer<typeof chatReplySchema>;
export type ChatResult = z.infer<typeof chatResultSchema>;
export const chatContextFence = (v: ChatContext) => JSON.stringify(v);

export const CHAT_DELIVERY = Object.freeze({
  lineBytes: 8192,
  totalBytes: 196608,
  frames: 52,
  deltaBytes: 1024,
});
const frameBase = {
  ...chatBindingSchema.shape,
  v: z.literal(1),
  seq: count.max(51),
  deliveryMode: z.literal('validated-completed-reply'),
  nativeProviderStream: z.literal(false),
  epoch: uuid,
  revision: count,
  mutationId: uuid,
  turnId: uuid,
};
export const chatFrameSchema = z.union([
  z.strictObject({ ...frameBase, type: z.literal('usage'), usage: chatReceiptSchema }),
  z.strictObject({
    ...frameBase,
    type: z.literal('citation'),
    index: count.max(31),
    source: chatSourceSchema,
  }),
  z.strictObject({
    ...frameBase,
    type: z.literal('delta'),
    index: count.max(16),
    text: z
      .string()
      .min(1)
      .refine((v) => utf8Bytes(v) <= CHAT_DELIVERY.deltaBytes),
  }),
  z.strictObject({
    ...frameBase,
    type: z.literal('done'),
    outcome: z.literal('completed'),
    kind: z.literal('hypothesis'),
    textBytes: count.max(16384),
    citationCount: count.min(1).max(32),
    deltaCount: count.min(1).max(17),
  }),
  z.strictObject({
    ...frameBase,
    type: z.literal('done'),
    outcome: z.literal('duplicate'),
    state: duplicateSchema.shape.state,
  }),
  z
    .strictObject({
      ...frameBase,
      type: z.literal('error'),
      errorCode: z.enum([
        'LLM_UNAVAILABLE',
        'LLM_PROVIDER_RATE_LIMITED',
        'LLM_PROVIDER_AUTH_FAILED',
        'LLM_PROVIDER_UNAVAILABLE',
      ]),
      providerFailure: providerFailureSchema.optional(),
      receipt: z.enum(['accepted', 'unavailable']),
    })
    .refine(validProviderError),
]);

// Frames never reach a renderer. Publication requires clean EOF, whole-reply validation and durable reread.
export function createChatFrameParser(context: ChatContext, mutationId: string) {
  uuid.parse(mutationId);
  let tuple: { turnId: string; revision: number } | undefined;
  let seq = 0,
    deltaCount = 0,
    textBytes = 0,
    sourcesBytes = 0,
    text = '';
  let usage: z.infer<typeof chatReceiptSchema> | undefined;
  const sources: ChatSource[] = [];
  let terminal:
    | ChatResult
    | {
        errorCode: 'LLM_UNAVAILABLE' | ProviderErrorCode;
        providerFailure?: ProviderFailure;
      }
    | undefined;
  const invalid = (): never => {
    throw new Error('Invalid chat delivery');
  };
  return {
    accept(raw: unknown) {
      if (terminal || seq >= CHAT_DELIVERY.frames) invalid();
      const frame = chatFrameSchema.parse(raw);
      if (
        frame.seq !== seq++ ||
        !sameChatBinding(frame, context) ||
        frame.epoch !== context.epoch ||
        frame.mutationId !== mutationId
      )
        invalid();
      if (tuple && (frame.turnId !== tuple.turnId || frame.revision !== tuple.revision)) invalid();
      tuple ??= { turnId: frame.turnId, revision: frame.revision };
      if (frame.type === 'error') {
        if ((frame.receipt === 'accepted') !== !!usage || frame.revision !== context.revision + 2) invalid();
        // Classified provider failures carry no answer fragments. Legacy delivery errors can follow partial writes.
        if (frame.errorCode !== 'LLM_UNAVAILABLE' && (sources.length || deltaCount)) invalid();
        terminal = {
          errorCode: frame.errorCode,
          ...(frame.providerFailure ? { providerFailure: frame.providerFailure } : {}),
        };
      } else if (frame.type === 'usage') {
        if (
          frame.seq !== 0 ||
          frame.revision !== context.revision + 2 ||
          !chatReceiptMatchesProvider(frame.usage, context)
        )
          invalid();
        usage = frame.usage;
      } else if (frame.type === 'citation') {
        if (
          !usage ||
          deltaCount ||
          frame.index !== sources.length ||
          !sameChatBinding(frame.source, context) ||
          sources.some((s) => s.finding.findingId === frame.source.finding.findingId)
        )
          invalid();
        sourcesBytes += serializedBytes(frame.source);
        if (sourcesBytes > CHAT_SOURCE_BUDGET.sourcesBytes) invalid();
        sources.push(frame.source);
      } else if (frame.type === 'delta') {
        if (!usage || !sources.length || frame.index !== deltaCount++) invalid();
        textBytes += utf8Bytes(frame.text);
        if (textBytes > 16384) invalid();
        text += frame.text;
      } else if (frame.outcome === 'duplicate') {
        if (frame.seq !== 0 || frame.revision < context.revision) invalid();
        terminal = duplicateSchema.parse({
          duplicate: true,
          id: frame.turnId,
          state: frame.state,
          epoch: frame.epoch,
          revision: frame.revision,
        });
      } else {
        if (
          !usage ||
          !deltaCount ||
          frame.textBytes !== textBytes ||
          frame.deltaCount !== deltaCount ||
          frame.citationCount !== sources.length
        )
          invalid();
        const reply = chatReplySchema.parse({
          ...contextBinding(context),
          kind: 'hypothesis',
          text,
          sources,
        });
        const value = {
          ...contextBinding(context),
          epoch: frame.epoch,
          revision: frame.revision,
          turnId: frame.turnId,
          deliveryMode: frame.deliveryMode,
          reply,
          usage,
        };
        if (serializedBytes(value) > 102400) invalid();
        terminal = chatResultSchema.parse(value);
      }
    },
    finish() {
      if (!terminal) return invalid();
      return terminal;
    },
  };
}
function contextBinding(value: ChatBinding): ChatBinding {
  return {
    scanId: value.scanId,
    digest: value.digest,
    platform: value.platform,
    reportVersion: value.reportVersion,
  };
}

export function verifiedChatSources(
  reply: ChatReply,
  available: readonly { findingId: string; check: string }[],
) {
  const byId = new Map(available.map((s) => [s.findingId, s.check]));
  return reply.sources.every(
    (s) => sameChatBinding(s, reply) && byId.get(s.finding.findingId) === s.finding.check,
  );
}
