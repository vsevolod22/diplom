import type { ReportContext } from './report-context.js';
import type { validateReply } from './response.js';

export type SummaryResponse = ReturnType<typeof validateReply> & Partial<Pick<ReportContext,
  'findingCount' | 'identifierCounts' | 'findingCounts' | 'coverage' | 'contextSelection'>>;
export type SummaryPublication = { value: SummaryResponse; write(action: () => void): void };
export const SUMMARY_CACHE = Object.freeze({ entries: 64, bytes: 2 * 1024 * 1024, entryBytes: 65536, busyMs: 100 });
type Binding = Pick<ReportContext, 'scanId' | 'digest' | 'platform' | 'reportVersion'>;

// One LlmService instance only. Serialized validated results, never prompts,
// credentials, authorization decisions, DB rows, or process-global user state.
export class SummaryResultCache {
  private readonly entries = new Map<string, { scope: string; body: string; bytes: number }>();
  private bytes = 0;
  private scope(owner: string, report: Binding) { return JSON.stringify([owner, report.scanId]); }
  private key(owner: string, report: Binding, policy: string) {
    return JSON.stringify([owner, report.scanId, report.digest, report.platform, report.reportVersion, policy]);
  }
  private remove(key: string) {
    const entry = this.entries.get(key);
    if (entry) { this.bytes -= entry.bytes; this.entries.delete(key); }
  }
  private current(owner: string, report: Binding, policy: string | null) {
    const scope = this.scope(owner, report), key = policy === null ? null : this.key(owner, report, policy);
    for (const [oldKey, entry] of this.entries) if (entry.scope === scope && oldKey !== key) this.remove(oldKey);
    return key;
  }
  get(owner: string, report: Binding, policy: string | null): SummaryResponse | undefined {
    const key = this.current(owner, report, policy), entry = key === null ? undefined : this.entries.get(key);
    if (!entry || key === null) return undefined;
    this.entries.delete(key); this.entries.set(key, entry);
    return JSON.parse(entry.body) as SummaryResponse;
  }
  put(owner: string, report: Binding, policy: string, body: string): void {
    const key = this.current(owner, report, policy)!;
    this.remove(key);
    const bytes = Buffer.byteLength(body) + Buffer.byteLength(key) + Buffer.byteLength(this.scope(owner, report));
    if (Buffer.byteLength(body) > SUMMARY_CACHE.entryBytes || bytes > SUMMARY_CACHE.bytes) return;
    while (this.entries.size >= SUMMARY_CACHE.entries || this.bytes + bytes > SUMMARY_CACHE.bytes)
      this.remove(this.entries.keys().next().value!);
    this.entries.set(key, { scope: this.scope(owner, report), body, bytes }); this.bytes += bytes;
  }
  clear() { this.entries.clear(); this.bytes = 0; }
}
