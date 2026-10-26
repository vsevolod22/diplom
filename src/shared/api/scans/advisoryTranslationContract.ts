import { z } from 'zod';
import { advisorySource, provenanceRef, utf8Bytes } from './vulnAdvisory';
import { chatBindingSchema, sameChatBinding, validChatText } from './llmChatContract';
import type { AdvisoryV1 } from './vulnAdvisory';

const hash = z.string().regex(/^[a-f0-9]{64}$/);
const displayText = (bytes: number) =>
  z
    .string()
    .min(1)
    .refine((value) => validChatText(value, bytes));
export const translationSelectionSchema = z.strictObject({
  findingId: z.string().regex(/^vuln-[a-f0-9]{64}$/),
  assessmentIndex: z.number().int().min(0).max(15),
});
export const translationSourceSchema = z.strictObject({
  source: advisorySource,
  provenanceRef,
  language: z
    .string()
    .max(35)
    .regex(/^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/)
    .nullable(),
});
const binding = {
  ...chatBindingSchema.shape,
  ...translationSelectionSchema.shape,
  sourceVersion: hash,
  targetLanguage: z.literal('ru'),
  source: translationSourceSchema,
};
// Match the existing policy disclosure, without accepting arbitrary extra wire fields.
const disclosure = z
  .strictObject({
    provider: z.literal('OpenRouter'),
    model: displayText(160),
    providers: z.array(displayText(64)).min(1).max(8),
    region: z.literal('global'),
    retention: z.enum(['no-training', 'no-storage']),
    operatorApprovedRouting: z.literal(true),
    providerComplianceNotProvenByDeclaration: z.literal(true),
    requestBudgetUsd: z.number().finite().nonnegative().max(1),
    freeOnly: z.boolean(),
    maxPrice: z.strictObject({
      prompt: z.number().finite().nonnegative().max(1000),
      completion: z.number().finite().nonnegative().max(1000),
      request: z.number().finite().nonnegative().nullable(),
    }),
    data: displayText(2000),
    targetLanguage: z.literal('ru'),
    machineTranslation: z.literal(true),
    // Client-side automation after saved account opt-in, never server GET dispatch.
    automaticDispatch: z.literal('account-preference'),
    persistentTranslationCache: z.literal(false),
  })
  .refine(
    (value) =>
      !value.freeOnly ||
      (value.requestBudgetUsd === 0 &&
        value.maxPrice.prompt === 0 &&
        value.maxPrice.completion === 0 &&
        value.maxPrice.request === 0),
  );
export const translationContextSchema = z
  .strictObject({
    ...binding,
    enabled: z.boolean(),
    policyVersion: hash.nullable(),
    disclosure: disclosure.nullable(),
  })
  .refine((value) =>
    value.enabled
      ? value.policyVersion !== null && value.disclosure !== null
      : value.policyVersion === null && value.disclosure === null,
  );
export const translationRequestSchema = z.strictObject({
  reportVersion: hash,
  ...translationSelectionSchema.shape,
  sourceVersion: hash,
  targetLanguage: z.literal('ru'),
  consent: z.strictObject({ accepted: z.literal(true), policyVersion: hash }),
});
export const translationReplySchema = z.strictObject({
  ...binding,
  translation: z
    .strictObject({
      title: displayText(2048).nullable(),
      description: displayText(16384).nullable(),
    })
    .refine((value) => value.title !== null || value.description !== null),
  machineTranslated: z.literal(true),
  model: displayText(160),
  provider: z.literal('OpenRouter'),
  generatedAt: z.iso.datetime(),
});
export type TranslationContext = z.infer<typeof translationContextSchema>;
export type TranslationReply = z.infer<typeof translationReplySchema>;
export type TranslationSelection = z.infer<typeof translationSelectionSchema>;
export type AdvisoryAssessment = AdvisoryV1['assessments'][number];
export const translationContextFence = (value: TranslationContext) => JSON.stringify(value);
export async function translationSourceVersion(vulnerabilityId: string, assessment: AdvisoryAssessment) {
  // Exact selected-advisory-ru-v1 wire revision shared with the server. Include original states and CVE/TEMP identity.
  const bytes = new TextEncoder().encode(
    JSON.stringify(['selected-advisory-ru-v1', vulnerabilityId, assessment]),
  );
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, '0')).join('');
}
export function sameTranslationBinding(
  value: TranslationReply | TranslationContext,
  context: TranslationContext,
) {
  return (
    sameChatBinding(value, context) &&
    value.findingId === context.findingId &&
    value.assessmentIndex === context.assessmentIndex &&
    value.sourceVersion === context.sourceVersion &&
    value.targetLanguage === context.targetLanguage &&
    value.source.source === context.source.source &&
    value.source.provenanceRef === context.source.provenanceRef &&
    value.source.language === context.source.language
  );
}
export function translatableField(field: AdvisoryAssessment['title'], limit = 4096) {
  return (
    (field.state === 'available' || field.state === 'truncated') &&
    !field.redacted &&
    field.value !== null &&
    field.value === field.value.trim() &&
    utf8Bytes(field.value) <= limit &&
    validChatText(field.value, limit) &&
    !/https?:|mailto:|\b[A-Za-z0-9.-]+\.(?:com|net|org|io|ru|test|invalid)\b/iu.test(field.value)
  );
}
export function hasTranslationText(assessment: AdvisoryAssessment) {
  return translatableField(assessment.title, 512) || translatableField(assessment.description);
}
export function matchesTranslationSource(context: TranslationContext, assessment: AdvisoryAssessment) {
  return (
    context.source.source === assessment.source &&
    context.source.provenanceRef === assessment.provenanceRef &&
    context.source.language === assessment.language
  );
}
export function matchesTranslationFields(reply: TranslationReply, assessment: AdvisoryAssessment) {
  // The server may further restrict egress. A hidden/ineligible field can never acquire translated text.
  return (
    (reply.translation.title === null || translatableField(assessment.title, 512)) &&
    (reply.translation.description === null || translatableField(assessment.description))
  );
}
