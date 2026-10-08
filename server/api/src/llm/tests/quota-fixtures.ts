import { quotaPolicyFromEnvironment, type QuotaPolicy } from '../quota-policy.js';
import { QuotaLedger } from '../quota-ledger.js';
// Explicit disposable fixture initialization; production constructor never bootstraps.
export class FixtureQuotaLedger extends QuotaLedger {
  constructor(path: string, policy: QuotaPolicy, clock: () => number = Date.now) { super(path, policy, clock, true); }
}
export const quotaEnv = {
  LLM_QUOTA_ENABLED: 'true', LLM_QUOTA_REVISION: 'fixture-v1', LLM_QUOTA_WINDOW: 'utc-day',
  LLM_QUOTA_USER_INPUT: '262144', LLM_QUOTA_USER_OUTPUT: '16384', LLM_QUOTA_USER_COST_USD: '0',
  LLM_QUOTA_SCAN_INPUT: '65536', LLM_QUOTA_SCAN_OUTPUT: '8192', LLM_QUOTA_SCAN_COST_USD: '0',
  LLM_QUOTA_WARNING_PERCENT: '80', LLM_QUOTA_REQUEST_INPUT: '65536',
  LLM_QUOTA_OBSERVATION_TOKENS: '1048576', LLM_QUOTA_OBSERVATION_COST_USD: '1',
  LLM_QUOTA_RECEIPT_MS: '300000', LLM_QUOTA_REPLAY_DAYS: '7', LLM_QUOTA_MAX_ROWS: '100000',
  LLM_QUOTA_DB_BYTES: '67108864', LLM_QUOTA_DISK_HEADROOM_BYTES: '134217728',
  LLM_QUOTA_BUSY_MS: '1000', LLM_QUOTA_CLEANUP_BATCH: '256',
};
export const quotaPolicy = quotaPolicyFromEnvironment(quotaEnv)!;
