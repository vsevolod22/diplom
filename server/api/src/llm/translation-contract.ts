import { createHash } from 'node:crypto';
import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { normalizePlain, type AdvisoryAssessment, type AdvisoryV1 } from '../worker/vuln-advisory.js';
import { cleanText } from './history-contract.js';
import { disclosure, PUBLIC_FREE_MODEL, PUBLIC_FREE_PROVIDER, type LlmPolicy } from './policy.js';
import { exact, invalidReply } from './response.js';
import type { FailureReason } from './provider-diagnostic.js';
import { russianHumanText, technicalIdentifiers, withoutPreservedIdentifiers, withoutRuntimeBrand } from './russian-text.js';

export const TRANSLATION = Object.freeze({ revision: 'selected-advisory-ru-v1', bodyBytes: 1024, busyMs: 100,
  titleBytes: 512, descriptionBytes: 4096, replyTitleBytes: 2048, replyDescriptionBytes: 16384 });
export type TranslationBinding = { scanId: string; digest: string; platform: string; reportVersion: string;
  findingId: string; assessmentIndex: number; sourceVersion: string };
export type TranslationSource = Pick<AdvisoryAssessment, 'source' | 'provenanceRef' | 'language'>;
export type TranslationText = { title: string | null; description: string | null };
export type TranslationSnapshot = TranslationBinding & { source: TranslationSource; text: TranslationText };
export const invalidTranslationRequest = (): never => { throw new BadRequestException({ errorCode: 'LLM_INVALID_REQUEST' }); };
export const translationUnavailable = (): never => { throw new ConflictException({ errorCode: 'LLM_TRANSLATION_UNAVAILABLE' }); };
export const translationEnabled = (policy: LlmPolicy | null): policy is LlmPolicy => !!policy?.freeOnly &&
  policy.model === PUBLIC_FREE_MODEL && policy.providers.length === 1 && policy.providers[0] === PUBLIC_FREE_PROVIDER;
export const translationPolicy = (policy: LlmPolicy): string => createHash('sha256')
  .update(JSON.stringify([TRANSLATION.revision, policy.version, 'selected-normalized-text-only', 'ru'])).digest('hex');
export function translationDisclosure(policy: LlmPolicy) {
  return { ...disclosure(policy), data: 'Only the selected normalized advisory title and description eligible for translation; no other report metadata, package data, history, raw evidence or credentials. Identifiers within the selected text remain unchanged.',
    // Client automation requires saved account opt-in; server GETs never dispatch.
    targetLanguage: 'ru' as const, machineTranslation: true, automaticDispatch: 'account-preference' as const, persistentTranslationCache: false };
}
export function translationSelection(findingId: unknown, assessmentIndex: unknown): { findingId: string; assessmentIndex: number } {
  if (typeof findingId !== 'string' || !/^vuln-[a-f0-9]{64}$/.test(findingId) ||
      !Number.isInteger(assessmentIndex) || (assessmentIndex as number) < 0 || (assessmentIndex as number) > 15) return invalidTranslationRequest();
  return { findingId, assessmentIndex: assessmentIndex as number };
}
export function translationQuery(query: unknown) {
  if (!exact(query, ['findingId', 'assessmentIndex']) || typeof query.assessmentIndex !== 'string' ||
      !/^(?:[0-9]|1[0-5])$/.test(query.assessmentIndex)) return invalidTranslationRequest();
  return translationSelection(query.findingId, Number(query.assessmentIndex));
}
export function translationRequest(body: unknown) {
  if (!exact(body, ['reportVersion', 'findingId', 'assessmentIndex', 'sourceVersion', 'targetLanguage', 'consent']) ||
      body.targetLanguage !== 'ru' || typeof body.reportVersion !== 'string' || !/^[a-f0-9]{64}$/.test(body.reportVersion) ||
      typeof body.sourceVersion !== 'string' || !/^[a-f0-9]{64}$/.test(body.sourceVersion)) return invalidTranslationRequest();
  return { ...translationSelection(body.findingId, body.assessmentIndex), reportVersion: body.reportVersion,
    sourceVersion: body.sourceVersion, consent: body.consent };
}
function textFailure(value: string, ceiling: number): FailureReason | undefined {
  try { if (cleanText(value, ceiling) !== value) return 'unsafe_text'; }
  catch { return 'unsafe_text'; }
  if (normalizePlain(value, ceiling).value !== value) return 'not_normalized';
  if (/https?:|mailto:|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/iu.test(withoutRuntimeBrand(value))) return 'invalid_link';
  return undefined;
}
const safeText = (value: string, ceiling: number): boolean => textFailure(value, ceiling) === undefined;
export function checkedTranslationText(value: unknown): TranslationText {
  if (!exact(value, ['title', 'description']) ||
      value.title !== null && (typeof value.title !== 'string' || !safeText(value.title, TRANSLATION.titleBytes)) ||
      value.description !== null && (typeof value.description !== 'string' || !safeText(value.description, TRANSLATION.descriptionBytes)))
    return invalidTranslationRequest();
  if (value.title === null && value.description === null) return translationUnavailable();
  return { title: value.title as string | null, description: value.description as string | null };
}
function eligible(field: AdvisoryAssessment['title'], ceiling: number): string | null {
  if (!['available', 'truncated'].includes(field.state) || field.redacted || field.value === null || !safeText(field.value, ceiling)) return null;
  return field.value;
}
export function selectedTranslation(advisory: AdvisoryV1 | undefined, assessmentIndex: number, cveId: string) {
  if (!advisory || advisory.state !== 'available') return translationUnavailable();
  const assessment = advisory.assessments[assessmentIndex];
  if (!assessment) throw new NotFoundException({ errorCode: 'SCAN_NOT_FOUND' });
  const text = { title: eligible(assessment.title, TRANSLATION.titleBytes), description: eligible(assessment.description, TRANSLATION.descriptionBytes) };
  if (text.title === null && text.description === null) return translationUnavailable();
  // Version includes the original field states and identity, not just the egress subset.
  const sourceVersion = createHash('sha256').update(JSON.stringify([TRANSLATION.revision, cveId, assessment])).digest('hex');
  return { sourceVersion, source: { source: assessment.source, provenanceRef: assessment.provenanceRef, language: assessment.language }, text };
}
export function translationBinding(snapshot: TranslationSnapshot): TranslationBinding {
  return { scanId: snapshot.scanId, digest: snapshot.digest, platform: snapshot.platform, reportVersion: snapshot.reportVersion,
    findingId: snapshot.findingId, assessmentIndex: snapshot.assessmentIndex, sourceVersion: snapshot.sourceVersion };
}
const identifiers = (text: string) => [...new Set(text.match(/\b(?:CVE|TEMP)-[A-Za-z0-9-]+/gi) ?? [])].sort();
function translatedField(value: unknown, original: string | null, ceiling: number,
  phase: 'translation_title' | 'translation_description'): string | null {
  if (original === null) { if (value !== null) return invalidReply(phase, 'null_mismatch'); return null; }
  if (value === null) return invalidReply(phase, 'null_mismatch');
  if (typeof value !== 'string') return invalidReply(phase, 'invalid_type');
  if (Buffer.byteLength(value) > ceiling) return invalidReply(phase, 'limit');
  const failure = textFailure(value, ceiling);
  if (failure) return invalidReply(phase, failure);
  if (/[`*#~[\]{}\\]/u.test(withoutPreservedIdentifiers(value, original))) return invalidReply(phase, 'invalid_markup');
  if (JSON.stringify(identifiers(value)) !== JSON.stringify(identifiers(original))) return invalidReply(phase, 'identifier_mismatch');
  const supplied = technicalIdentifiers(original), returned = technicalIdentifiers(value);
  if (supplied.some(token => !returned.includes(token)) || returned.some(token => !supplied.includes(token)))
    return invalidReply(phase, 'identifier_mismatch');
  const prose = withoutPreservedIdentifiers(original, original);
  if (/\p{L}/u.test(prose)) {
    if (!russianHumanText(value, original)) return invalidReply(phase, 'not_russian');
  } else if (value !== original) return invalidReply(phase, 'nonprose_changed');
  return value;
}
export function validateTranslationReply(value: unknown, original: TranslationText): TranslationText {
  if (!exact(value, ['title', 'description'])) return invalidReply('content', 'invalid_shape');
  return { title: translatedField(value.title, original.title, TRANSLATION.replyTitleBytes, 'translation_title'),
    description: translatedField(value.description, original.description, TRANSLATION.replyDescriptionBytes, 'translation_description') };
}
