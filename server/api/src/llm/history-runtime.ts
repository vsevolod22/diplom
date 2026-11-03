import { HttpException } from '@nestjs/common';
import { HistoryStore } from './history-store.js';
import { HISTORY, historyUnavailable } from './history-contract.js';

export const HISTORY_AUTHORITY = 'single-api-quiesced-terminal-v1';
export function historyEnabled(): boolean {
  return process.env.LLM_HISTORY_ENABLED === 'true' && process.env.LLM_HISTORY_REVISION === HISTORY.version &&
    process.env.LLM_HISTORY_AUTHORITY === HISTORY_AUTHORITY;
}
export class HistoryRuntime {
  private handle?: HistoryStore;
  // Composition/test seam only; production keeps the existing auth-volume path.
  constructor(private readonly path = '/auth/llm-history.sqlite') {}
  private open(): HistoryStore {
    if (!historyEnabled()) return historyUnavailable();
    if (!this.handle) this.handle = new HistoryStore(this.path);
    return this.handle;
  }
  // Open the existing v3/v4/v5 authority without recovery or schema changes.
  // Callers must use a guarded read (readSnapshot/guardHead) for fresh store checks.
  readStore(): HistoryStore { return this.open(); }
  // Readiness must freshly validate even a cached handle, without expiry recovery.
  assertHealthy(): void { this.open().assertHealthy(); }
  store(): HistoryStore {
    const store = this.open();
    store.recoverExpired(); return store;
  }
  summaryStore(): HistoryStore {
    try {
      const store = this.open();
      // No chat-head creation, expiry recovery, initialization or migration on GET.
      store.requireSummarySchema(); return store;
    } catch (error) {
      if (error instanceof HttpException) throw error;
      return historyUnavailable();
    }
  }
  close() { this.handle?.close(); this.handle = undefined; }
}
