#!/usr/bin/env node
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPublicCveBridge } from './public-cve-bridge.mjs';
import { createCveScheduler, INTERVAL_SECONDS } from './schedule-local-cve.mjs';
import {
  publicPaths,
  loadPublicBinding,
  requirePublicIntegration,
  refreshPublicCve,
  publicCveFailure,
} from './refresh-public-cve.mjs';

export const LABEL = 'io.diplom.public-images.cve-refresh';
export { INTERVAL_SECONDS };
const refuse = () =>
  new Error(
    'PUBLIC CVE schedule refused; check public profile, shared HOLD and scheduler configuration. No automatic recovery.',
  );
// Do not print arbitrary retained JSON, even if it is small and owned. This
// renderer selects fixed enums and bounded nonsecret timestamp/digest fields.
export function publicStatus(raw) {
  const s = JSON.parse(raw);
  if (
    s?.version !== 1 ||
    !['running', 'completed', 'failed'].includes(s.state) ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(s.startedAt)
  )
    throw refuse();
  const result = { version: 1, state: s.state, startedAt: s.startedAt };
  if (s.state !== 'running') {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(s.finishedAt)) throw refuse();
    result.finishedAt = s.finishedAt;
  }
  if (s.state === 'completed') {
    if (
      !['unchanged', 'activated', 'deferred-busy', 'deferred-stopped'].includes(s.outcome) ||
      !/^sha256:[a-f0-9]{64}(?![\s\S])/.test(s.manifest)
    )
      throw refuse();
    result.outcome = s.outcome;
    result.manifest = s.manifest;
  }
  if (s.state === 'failed') {
    const allowed = [
      'preflight',
      'discovery',
      'verify-current',
      'staging',
      'download',
      'prepare',
      'sign',
      'verify',
      'namespace',
      'fence',
      'drain',
      'preservation',
      'activate',
      'readiness',
      'cleanup',
    ];
    if (!allowed.includes(s.phase) || typeof s.hold !== 'boolean') throw refuse();
    result.phase = s.phase;
    result.hold = s.hold;
  }
  return JSON.stringify(result);
}
export function publicCveScheduler({ integration = createPublicCveBridge() } = {}) {
  return createCveScheduler({
    label: LABEL,
    script: 'schedule-public-cve.mjs',
    paths: publicPaths,
    scope: 'PUBLIC',
    refreshFailure: publicCveFailure,
    readStatus: publicStatus,
    strictLoadedEnvironment: true,
    loadedEnvironmentMetadata: Object.freeze({ XPC_SERVICE_NAME: LABEL, OSLogRateLimit: '64' }),
    validateRecord: (record) => JSON.parse(publicStatus(JSON.stringify(record))),
    beforeCommand: async (_command, root) => {
      requirePublicIntegration(integration);
      await integration.assertCompatible(root);
      loadPublicBinding(root); // Do not install a job against an unmigrated v1 binding.
    },
    loadRefresh: async () => (argv, options) => refreshPublicCve(argv, { ...options, integration }),
  });
}
// The same concrete bridge is used by manual CLI and launchd. Installation is
// explicit; no import-time launchctl, refresh, key provisioning or state change.
export const {
  agentPlist,
  validateLoadedAgent,
  scheduledRun,
  scheduleCve: schedulePublicCve,
} = publicCveScheduler();
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  schedulePublicCve(process.argv.slice(2)).catch(() => {
    console.error(refuse().message);
    process.exitCode = 1;
  });
}
