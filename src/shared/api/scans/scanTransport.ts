import { z } from 'zod';

const state = z.enum(['queued', 'running', 'cancelling', 'completed', 'partial', 'failed', 'cancelled']);
const coverageState = z.enum(['checked', 'unsupported', 'not_authorized', 'failed', 'skipped']);
const coverage = z.object({ check: z.string(), status: coverageState, reason: z.string().optional(), scannerVersion: z.string().optional(), dbVersion: z.string().optional() });
const finding = z.object({ findingId: z.string(), category: z.string(), ruleId: z.string(), severity: z.string(), location: z.string().optional(), evidenceRef: z.string().optional() });
const status = z.object({ scanId: z.string(), state, stage: z.string().optional(), percent: z.number().min(0).max(100).nullable().optional(), imageReference: z.string().optional(), digest: z.string().optional(), platform: z.string().optional(), updatedAt: z.string().optional() });
const results = z.object({ findings: z.array(finding), nextCursor: z.string().nullable(), coverage: z.array(coverage) });
const receipt = z.object({ scanId: z.string(), statusUrl: z.string(), eventsUrl: z.string() });
export type ScanStatus = z.infer<typeof status>;
export type ScanResults = z.infer<typeof results>;
export type ScanFinding = z.infer<typeof finding>;
export type ScanCoverage = z.infer<typeof coverage>;
export type ScanReceipt = z.infer<typeof receipt>;
export type ScanSummary = ScanStatus & { targetLabel: string };
export type ScanIntent = { imageReference: string; scope: 'image'; checks: ['secret']; idempotencyKey: string };
export type ScanCapabilities = { list: boolean; create: boolean; cancel: boolean; events: boolean };
export type ScanTransport = {
  kind: 'fixture' | 'live';
  capabilities: ScanCapabilities;
  list(signal?: AbortSignal): Promise<ScanSummary[]>;
  get(scanId: string, signal?: AbortSignal): Promise<ScanStatus>;
  results(scanId: string, cursor?: string, signal?: AbortSignal): Promise<ScanResults>;
  create(intent: ScanIntent): Promise<ScanReceipt>;
  cancel(scanId: string): Promise<void>;
};
export const parseScanStatus = (value: unknown): ScanStatus => status.parse(value);
export const parseScanResults = (value: unknown): ScanResults => results.parse(value);
export const parseScanReceipt = (value: unknown): ScanReceipt => receipt.parse(value);

// Current internal API wire shape; future fields must be explicitly reviewed before enabling browser transport.
const wireOutcome = z.enum(['checked', 'failed', 'unsupported', 'skipped', 'not_authorized']);
const wireCoverage = z.object({ findingCount: z.number().int().nonnegative(), check: z.literal('secret'), coverage: z.literal('image'), outcome: wireOutcome, errorCode: z.string().nullable(), scannerVersion: z.string().nullable() });
const wireStatus = z.object({ scanId: z.string(), state: z.enum(['queued', 'running', 'completed', 'failed', 'cancelled']), result: wireCoverage.nullable() });
const wireResults = z.object({ findings: z.array(z.object({ findingId: z.string(), ruleId: z.string(), line: z.number().nullable(), evidenceRef: z.string() })), nextCursor: z.number().int().nonnegative().nullable(), coverage: wireCoverage.nullable() });
export function parseCurrentStatus(value: unknown): ScanStatus {
  const current = wireStatus.parse(value);
  return { scanId: current.scanId, state: current.state, percent: null };
}
export function parseCurrentResults(value: unknown): ScanResults {
  const current = wireResults.parse(value);
  const secret = current.coverage;
  return {
    findings: current.findings.map(({ findingId, ruleId }) => ({ findingId, ruleId, category: 'secret', severity: 'unknown' })),
    nextCursor: current.nextCursor === null ? null : String(current.nextCursor),
    coverage: [
      { check: 'Secrets', status: secret?.outcome ?? 'skipped', reason: secret?.errorCode ?? (secret ? undefined : 'Результат ещё не получен'), scannerVersion: secret?.scannerVersion ?? undefined },
      { check: 'CVE', status: 'unsupported', reason: 'В текущем API проверка недоступна' },
      { check: 'SBOM', status: 'unsupported', reason: 'В текущем API проверка недоступна' },
    ],
  };
}
export function sameOriginScanUrl(raw: string, scanId: string, suffix = ''): string {
  const expected = `/api/v1/scans/${encodeURIComponent(scanId)}${suffix}`;
  const url = new URL(raw, window.location.origin);
  if (raw !== expected || url.origin !== window.location.origin || url.pathname !== expected || url.search || url.hash) {
    throw new Error('Недопустимый адрес скана');
  }
  return expected;
}
export function reconcileSnapshot(current: ScanStatus, incoming: ScanStatus): ScanStatus {
  if (incoming.scanId !== current.scanId) return current;
  const terminal = ['completed', 'partial', 'failed', 'cancelled'];
  if (terminal.includes(current.state) && !terminal.includes(incoming.state)) return current;
  // No comparable server revision: only the subsequent GET snapshot can be authoritative.
  return incoming;
}
