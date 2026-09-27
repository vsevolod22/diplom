import type { Job, ScanLedger } from '../ledger/ledger.js';
import { scanPinned, type ScanResult } from './scan-worker.js';
import { scannerFailure } from './scanner-errors.js';

// Called only by a separately isolated worker process. Not registered in AppModule.
// At-least-once: an expired lease may start another attempt; fencing prevents stale ack.
export async function consumeOne(ledger: ScanLedger, options: { timeoutMs: number; dbDir: string },
  runner: (job: Job, options: { timeoutMs: number; dbDir: string }) => Promise<ScanResult> = scanPinned,
  now = Date.now()): Promise<boolean> {
  const job = ledger.claim(now, options.timeoutMs + 30_000);
  if (!job) return false;
  let result: ScanResult;
  try { result = await runner(job, options); }
  catch { result = { ok: false, failure: scannerFailure(null) }; }
  // A finding count alone is not a durable scan result. Until result persistence and
  // coverage are implemented, a successful subprocess must not advertise completion.
  // Never persist arbitrary runner output or diagnostics.
  void result;
  ledger.finish(job.scanId, job.attempts, 'failed');
  return true;
}
