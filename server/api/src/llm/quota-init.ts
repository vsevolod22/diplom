import { existsSync } from 'node:fs';
import { QuotaLedger } from './quota-ledger.js';
import { quotaPolicyFromEnvironment } from './quota-policy.js';

// Operator-only bootstrap, never imported by Nest or run during startup/recovery.
// It neither reads nor migrates auth/scans DBs and refuses an existing quota file.
if (process.argv.length !== 3 || process.argv[2] !== '--initialize') {
  process.stderr.write('Explicit --initialize and a complete approved non-secret quota policy are required.\n');
  process.exitCode = 1;
} else {
  try {
    const policy = quotaPolicyFromEnvironment();
    if (!policy || existsSync('/auth/llm-usage.sqlite')) throw new Error();
    new QuotaLedger('/auth/llm-usage.sqlite', policy, Date.now, true).close();
    process.stdout.write('Quota ledger initialized. No provider call or service activation performed.\n');
  } catch {
    process.stderr.write('Quota initialization refused; no existing ledger was reset.\n');
    process.exitCode = 1;
  }
}
