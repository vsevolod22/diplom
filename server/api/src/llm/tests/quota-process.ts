import { QuotaLedger } from '../quota-ledger.js';
import { quotaPolicy } from './quota-fixtures.js';
const ledger = new QuotaLedger(process.argv[2], { ...quotaPolicy, user: { ...quotaPolicy.user, input: 1500 }, scan: { ...quotaPolicy.scan, input: 1500 } });
process.send?.({ ready: true });
process.once('message', (message: { action: string; id?: string; scan?: string }) => {
  try {
    const result = message.action === 'dispatch' ? ledger.dispatch(message.id!) : message.action === 'release' ? ledger.release(message.id!) :
      ledger.reserve({ subject: 'shared-user', scanId: message.scan ?? 'same-scan', reportVersion: 'a'.repeat(64), policyVersion: 'b'.repeat(64), requestHash: 'c'.repeat(64) }, { input: 1000, output: 200, costMicros: 0 });
    process.send?.({ result });
  } catch { process.send?.({ denied: true }); }
  finally { ledger.close(); process.disconnect(); }
});
