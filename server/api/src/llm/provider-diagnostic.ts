// Only factory-bound finite diagnostics may reach headers. No upstream messages, payloads or errno text.
export const FAILURE_PHASES = ['request', 'connect', 'tls', 'dispatch_guard', 'headers', 'body', 'json', 'model',
  'envelope', 'finish', 'content', 'usage', 'accounting', 'deadline', 'caller_abort', 'language', 'grounding'] as const;
export const FAILURE_REASONS = ['invalid_request', 'rejected', 'io_error', 'timeout', 'aborted', 'http_error',
  'invalid_type', 'limit', 'invalid_json', 'mismatch', 'invalid_shape', 'invalid_finish', 'invalid_content', 'invalid_receipt',
  'observation_failed', 'not_russian', 'unknown_identifier', 'finish_length', 'finish_content_filter',
  'finish_tool_calls', 'finish_error', 'finish_unknown'] as const;
export type FailurePhase = typeof FAILURE_PHASES[number];
export type FailureReason = typeof FAILURE_REASONS[number];
export type FailureDiagnostic = Readonly<{ phase: FailurePhase; reason: FailureReason }>;
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
export function diagnose<T extends object>(target: T, phase: FailurePhase, reason: FailureReason): T {
  if (!diagnostics.has(target) && FAILURE_PHASES.includes(phase) && FAILURE_REASONS.includes(reason))
    diagnostics.set(target, Object.freeze({ phase, reason }));
  return target;
}
export function diagnostic(value: unknown): FailureDiagnostic | undefined {
  return value !== null && typeof value === 'object' ? diagnostics.get(value) : undefined;
}
export function carryDiagnostic<T extends object>(from: unknown, to: T): T {
  const value = diagnostic(from);
  return value ? diagnose(to, value.phase, value.reason) : to;
}
export function diagnosticHeaders(value: unknown): Record<string, string> {
  const detail = diagnostic(value);
  return detail ? { 'X-LLM-Failure-Phase': detail.phase, 'X-LLM-Failure-Reason': detail.reason } : {};
}
export function abortDiagnostic(controller: AbortController, phase: 'deadline' | 'caller_abort'): void {
  if (!controller.signal.aborted) controller.abort(diagnose(new Error('LLM operation stopped'), phase, phase === 'deadline' ? 'timeout' : 'aborted'));
}
export function stoppedDiagnostic(signal: AbortSignal, target: object): void {
  const detail = diagnostic(signal.reason);
  if (detail) diagnose(target, detail.phase, detail.reason);
  else diagnose(target, 'caller_abort', 'aborted');
}
