import { finiteGroundingWitness, type GroundingWitness } from './grounding-witness.js';
import { finiteLanguageRejection, type LanguageRejection } from './language-rejection.js';
import { carryOpenAiHttp, openAiHttpHeaders } from './openai-http-diagnostic.js';

// Only factory-bound finite diagnostics may reach headers. No upstream messages, payloads or errno text.
export const FAILURE_PHASES = ['request', 'connect', 'tls', 'dispatch_guard', 'headers', 'body', 'json', 'model',
  'envelope', 'finish', 'content', 'usage', 'accounting', 'deadline', 'caller_abort', 'language', 'grounding',
  'translation_title', 'translation_description'] as const;
export const FAILURE_REASONS = ['invalid_request', 'rejected', 'io_error', 'timeout', 'aborted', 'http_error',
  'invalid_type', 'limit', 'invalid_json', 'mismatch', 'invalid_shape', 'invalid_finish', 'invalid_content', 'invalid_receipt',
  'observation_failed', 'not_russian', 'unknown_identifier', 'finish_length', 'finish_content_filter',
  'finish_tool_calls', 'finish_error', 'finish_unknown', 'null_mismatch', 'unsafe_text', 'invalid_markup',
  'identifier_mismatch', 'nonprose_changed', 'not_normalized', 'invalid_link'] as const;
export type FailurePhase = typeof FAILURE_PHASES[number];
export type FailureReason = typeof FAILURE_REASONS[number];
export type FailureDiagnostic = Readonly<{ phase: FailurePhase; reason: FailureReason }>;
export const GROUNDING_PREDICATES = Object.freeze(['cvss_version', 'package_label', 'version_label', 'update_target',
  'score_parentheses', 'score_value', 'score_boundary', 'unmasked_tilde', 'unmasked_dotted_number', 'advisory_identifier'] as const);
export type GroundingPredicate = typeof GROUNDING_PREDICATES[number];
// Index is a zero-based summary paragraph (0..11); chat has one text at index 0.
export type GroundingDiagnostic = Readonly<{ predicate: GroundingPredicate; index: number; witness?: GroundingWitness }>;
export type LanguageDiagnostic = Readonly<{ index: number; rejection: LanguageRejection }>;
// Only normalized, explicitly known finish values are classified. Never echo native/provider strings.
export function rejectedFinishReason(value: unknown): FailureReason {
  switch (value) {
    case 'length': return 'finish_length';
    case 'content_filter': return 'finish_content_filter';
    case 'tool_calls':
    case 'function_call': return 'finish_tool_calls';
    case 'error': return 'finish_error';
    default: return 'finish_unknown';
  }
}
const diagnostics = new WeakMap<object, FailureDiagnostic>();
const groundingDiagnostics = new WeakMap<object, GroundingDiagnostic>();
const languageDiagnostics = new WeakMap<object, LanguageDiagnostic>();
export function diagnose<T extends object>(target: T, phase: FailurePhase, reason: FailureReason): T {
  if (!diagnostics.has(target) && FAILURE_PHASES.includes(phase) && FAILURE_REASONS.includes(reason))
    diagnostics.set(target, Object.freeze({ phase, reason }));
  return target;
}
export function diagnostic(value: unknown): FailureDiagnostic | undefined {
  return value !== null && typeof value === 'object' ? diagnostics.get(value) : undefined;
}
export function diagnoseGrounding<T extends object>(target: T, predicate: GroundingPredicate, index: number, witness?: GroundingWitness): T {
  // Never enrich or overwrite another failure, even an earlier generic grounding failure.
  if (diagnostics.has(target)) return target;
  diagnose(target, 'grounding', 'unknown_identifier');
  if (GROUNDING_PREDICATES.includes(predicate) && Number.isInteger(index) && index >= 0 && index <= 11) {
    const finite = finiteGroundingWitness(witness);
    groundingDiagnostics.set(target, Object.freeze({ predicate, index, ...(finite ? { witness: finite } : {}) }));
  }
  return target;
}
export function groundingDiagnostic(value: unknown): GroundingDiagnostic | undefined {
  return value !== null && typeof value === 'object' ? groundingDiagnostics.get(value) : undefined;
}
export function diagnoseLanguage<T extends object>(target: T, rejection: LanguageRejection, index: number): T {
  if (diagnostics.has(target)) return target;
  diagnose(target, 'language', 'not_russian');
  if (Number.isInteger(index) && index >= 0 && index <= 11) {
    const finite = finiteLanguageRejection(rejection);
    if (finite) languageDiagnostics.set(target, Object.freeze({ index, rejection: finite }));
  }
  return target;
}
export function languageDiagnostic(value: unknown): LanguageDiagnostic | undefined {
  return value !== null && typeof value === 'object' ? languageDiagnostics.get(value) : undefined;
}
export function carryDiagnostic<T extends object>(from: unknown, to: T): T {
  const value = diagnostic(from);
  if (!value || diagnostics.has(to)) return to;
  carryOpenAiHttp(from, to);
  const grounding = groundingDiagnostic(from);
  if (grounding) return diagnoseGrounding(to, grounding.predicate, grounding.index, grounding.witness);
  const language = languageDiagnostic(from);
  return language ? diagnoseLanguage(to, language.rejection, language.index) : diagnose(to, value.phase, value.reason);
}
export function diagnosticHeaders(value: unknown): Record<string, string> {
  const detail = diagnostic(value);
  if (!detail) return {};
  const grounding = groundingDiagnostic(value);
  const language = languageDiagnostic(value);
  return { 'X-LLM-Failure-Phase': detail.phase, 'X-LLM-Failure-Reason': detail.reason,
      ...openAiHttpHeaders(value),
    ...(grounding ? { 'X-LLM-Grounding-Predicate': grounding.predicate, 'X-LLM-Grounding-Index': String(grounding.index) } : {}),
    ...(grounding?.witness ? {
      'X-LLM-Grounding-Source-Relation': grounding.witness.sourceRelation,
      'X-LLM-Grounding-Lexical-Class': grounding.witness.lexicalClass,
      'X-LLM-Grounding-Boundary-Class': grounding.witness.boundaryClass,
    } : {}),
    ...(language ? {
      'X-LLM-Language-Reason': language.rejection.reason,
      'X-LLM-Language-Index': String(language.index),
      'X-LLM-Language-Token-Class': language.rejection.tokenClass,
    } : {}) };
}
export function abortDiagnostic(controller: AbortController, phase: 'deadline' | 'caller_abort'): void {
  if (!controller.signal.aborted) controller.abort(diagnose(new Error('LLM operation stopped'), phase, phase === 'deadline' ? 'timeout' : 'aborted'));
}
export function stoppedDiagnostic(signal: AbortSignal, target: object): void {
  const detail = diagnostic(signal.reason);
  if (detail) diagnose(target, detail.phase, detail.reason);
  else diagnose(target, 'caller_abort', 'aborted');
}
