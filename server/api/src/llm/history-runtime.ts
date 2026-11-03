import { HistoryStore } from './history-store.js';
import { HISTORY, historyUnavailable } from './history-contract.js';

export const HISTORY_AUTHORITY = 'single-api-quiesced-terminal-v1';
export function historyEnabled(): boolean {
  return process.env.LLM_HISTORY_ENABLED === 'true' && process.env.LLM_HISTORY_REVISION === HISTORY.version &&
    process.env.LLM_HISTORY_AUTHORITY === HISTORY_AUTHORITY;
}
export class HistoryRuntime {
  private handle?: HistoryStore;
  private open(): HistoryStore {
    if (!historyEnabled()) return historyUnavailable();
    if (!this.handle) this.handle = new HistoryStore('/auth/llm-history.sqlite');
    return this.handle;
  }
  // Readiness must freshly validate even a cached handle, without expiry recovery.
  assertHealthy(): void { this.open().assertHealthy(); }
  store(): HistoryStore {
    const store = this.open();
    store.recoverExpired(); return store;
  }
  close() { this.handle?.close(); this.handle = undefined; }
}
