import { HISTORY, bytes, contextLimit, hashValue, type HistoryHead } from './history-contract.js';
import type { LlmPolicy } from './policy.js';
import { prepareHistory, type PreparedRequest } from './prepared-request.js';
import type { ReportContext, SafeFinding } from './report-context.js';
import { compareFindings, mandatoryFinding } from './summary-context.js';

export type HistoryContext = { version: string; report: ReportContext; history: {
  epoch: string; revision: number; userTurns: unknown[]; decisions: unknown[]; optionalExplanations: unknown[] };
  question: string; omission: { findings: number; explanations: number; selectedFindingIds: string[] } };
const mandatory = mandatoryFinding;
export function selectHistoryContext(report: ReportContext, head: HistoryHead, question: string, policy: LlmPolicy, inputCeiling: number) {
  const required = report.findings.filter(mandatory);
  if (required.length > policy.findings) return contextLimit();
  const words = question.toLowerCase().split(/[^\p{L}\p{N}_-]+/u).filter(w => w.length > 2).slice(0, 64);
  const score = (f: SafeFinding) => words.reduce((n, w) => n + Number(JSON.stringify(f).toLowerCase().includes(w)), 0);
  const optional = report.findings.filter(f => !mandatory(f)).sort((a, b) => score(b) - score(a) || compareFindings(a, b));
  let count = Math.min(16, optional.length, policy.findings - required.length), recent = Math.min(4, head.turns.length);
  for (;;) {
    const findings = [...required, ...optional.slice(0, count)].sort((a, b) => a.findingId.localeCompare(b.findingId));
        if (!findings.length) return contextLimit();
    const context: HistoryContext = { version: HISTORY.version, report: { ...report, findings }, question,
      history: { epoch: head.epoch, revision: head.revision,
        // All user content is conservatively decision-bearing. Age never excludes it.
        userTurns: head.turns.map(t => ({ id: t.id, text: t.question, report: t.report,
          sources: t.reply?.sources ?? [], sourceState: t.report.reportVersion === report.reportVersion ? 'same-report' : 'historical-unresolved' })),
        decisions: head.decisions.map(d => ({ ...d, sourceState: d.report.reportVersion === report.reportVersion ? 'same-report' : 'historical-unresolved' })),
        optionalExplanations: head.turns.slice(-recent || head.turns.length).filter(t => t.reply).map(t => ({ id: t.id, text: t.reply!.text, kind: 'hypothesis' })) },
      omission: { findings: report.findings.length - findings.length, explanations: head.turns.filter(t => t.reply).length -
        head.turns.slice(-recent || head.turns.length).filter(t => t.reply).length, selectedFindingIds: findings.map(f => f.findingId) } };
    let prepared: PreparedRequest | undefined;
    try { prepared = prepareHistory(context, policy); } catch { /* Remove optional data only. */ }
    if (prepared && prepared.reserve.input <= inputCeiling) return { context, prepared };
    if (recent > 0) { recent = 0; continue; }
    if (count > 0) { count--; continue; }
    return contextLimit();
  }
}
function freeze<T>(value: T): T {
  if (value && typeof value === 'object') { Object.freeze(value); for (const child of Object.values(value)) freeze(child); }
  return value;
}
// Cache contains context only, never response, consent or authorization decisions.
export class PreparedContextCache {
  private readonly entries = new Map<string, { context: HistoryContext; bytes: number; expires: number; hash: string }>();
  private size = 0;
  lookups = 0;
  constructor(private readonly clock = Date.now) {}
  get(key: string, authoritative: HistoryContext): HistoryContext {
    this.lookups++;
    const existing = this.entries.get(key);
    if (existing && existing.expires > this.clock() && existing.hash === hashValue(existing.context) &&
      existing.hash === hashValue(authoritative)) {
      this.entries.delete(key); this.entries.set(key, existing); return existing.context;
    }
    if (existing) { this.entries.delete(key); this.size -= existing.bytes; }
    const context = freeze(JSON.parse(JSON.stringify(authoritative)) as HistoryContext), length = bytes(context) + key.length;
    if (length > HISTORY.cacheBytes) return contextLimit();
    for (const [id, entry] of this.entries) {
      if (this.entries.size < HISTORY.cacheEntries && this.size + length <= HISTORY.cacheBytes) break;
      this.entries.delete(id); this.size -= entry.bytes;
    }
    this.entries.set(key, { context, bytes: length, expires: this.clock() + HISTORY.cacheMs, hash: hashValue(context) }); this.size += length;
    return context;
  }
  clear() { this.entries.clear(); this.size = 0; }
}
