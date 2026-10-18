import { isDeepStrictEqual } from 'node:util';
import { createImageConfigModule } from '../image-config/index.js';
import type { ImageConfigResult } from '../image-config/contract.js';
import { sanitizeConfigReport } from '../image-config/report-contract.js';
import type { Job, ScanLedger } from '../ledger/ledger.js';
import { admittedConfigTarget, CONFIG_LOAD_MS, createPinnedConfigLoader, loadPinnedConfig, type ConfigLoader } from '../oci/pinned-image-config.js';

/** The handle exists only in this attempt's composition, never in a job or HTTP DTO. */
export async function runImageConfig(ledger: ScanLedger, suppliedJob: Job, signal: AbortSignal,
  loader: ConfigLoader | undefined = undefined, publicImagePolicy = false): Promise<ImageConfigResult> {
  const job = Object.freeze({ ...suppliedJob });
  const load = loader ?? (publicImagePolicy === true ? createPinnedConfigLoader(undefined, true) : loadPinnedConfig);
  let enabled = false;
  try { const checks: unknown = JSON.parse(job.checks); enabled = Array.isArray(checks) && checks.includes('config'); } catch { /* Unsupported legacy job is finalized by its existing failure path. */ }
  const handles = new WeakMap<object, ReturnType<ScanLedger['configAttemptContext']>>();
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) abort();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const module = createImageConfigModule({
    async resolveAuthorizedTarget(handle) {
      if (typeof handle !== 'object' || handle === null || controller.signal.aborted) return undefined;
      const issued = handles.get(handle);
      const current = ledger.configAttemptContext(job.scanId, job.attempts);
      if (!issued || !ledger.checkpointActive(job) || !isDeepStrictEqual(issued, current) || !admittedConfigTarget(job, publicImagePolicy) ||
          !isDeepStrictEqual(issued.job, job)) return undefined;
      const input = await load(job, controller.signal);
      if (controller.signal.aborted || !ledger.checkpointActive(job) || !isDeepStrictEqual(issued, ledger.configAttemptContext(job.scanId, job.attempts))) return undefined;
      if (input.identity.registry !== job.registry || input.identity.repository !== job.repository ||
          input.identity.manifestDigest !== job.digest ||
          [input.identity.platform.os, input.identity.platform.architecture, input.identity.platform.variant].filter(Boolean).join('/') !== job.platform) return undefined;
      return input;
    },
  });
  const handle = Object.freeze(Object.create(null) as object);
  try {
    // Off never issues authority or reads the loader/bytes.
    if (!enabled) return await module.analyze({ enabled: false });
    const context = ledger.configAttemptContext(job.scanId, job.attempts);
    if (context && ledger.checkpointActive(job)) handles.set(handle, context);
    const timedOut = new Promise<ImageConfigResult>(resolve => {
      const fail = () => { controller.abort(); resolve(sanitizeConfigReport(null, job, true)); };
      timer = setTimeout(fail, CONFIG_LOAD_MS);
      controller.signal.addEventListener('abort', () => resolve(sanitizeConfigReport(null, job, true)), { once: true });
    });
    return sanitizeConfigReport(await Promise.race([module.analyze({ enabled: true, target: handle }), timedOut]), job, true);
  } finally {
    handles.delete(handle);
    clearTimeout(timer);
    signal.removeEventListener('abort', abort);
    controller.abort();
  }
}
