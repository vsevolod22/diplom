import { Injectable, type OnModuleDestroy } from '@nestjs/common';
import { QuotaLedger } from './quota-ledger.js';
import { quotaPolicyFromEnvironment, quotaUnavailable } from './quota-policy.js';

@Injectable()
export class LlmQuotaRuntime implements OnModuleDestroy {
  private readonly stores = new Map<string, QuotaLedger>();
  ledger(): QuotaLedger {
    // Named non-secret configuration only; no env-file loading or serialization.
    const policy = quotaPolicyFromEnvironment();
    if (!policy) throw quotaUnavailable();
    let store = this.stores.get(policy.version);
    if (store) return store;
    // Keep old handles alive for receipts already bound to their original policy.
    // Unbounded hot policy rotation is refused rather than leaking connections.
    if (this.stores.size >= 4) throw quotaUnavailable();
    try { store = new QuotaLedger('/auth/llm-usage.sqlite', policy); }
    catch { throw quotaUnavailable(); }
    this.stores.set(policy.version, store);
    return store;
  }
  onModuleDestroy() { for (const store of this.stores.values()) store.close(); this.stores.clear(); }
}
