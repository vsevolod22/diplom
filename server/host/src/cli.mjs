import { pathToFileURL } from 'node:url';
import { COMMANDS, HostCollector } from './collector.mjs';
import { PLAN_ID, EXCLUSIONS, canonical } from './contract.mjs';
import { supervise, INVOCATION_MS, SHUTDOWN_MS, SUPERVISOR_ID } from './supervisor.mjs';
import { CLEANUP_GRACE_MS } from './collector.mjs';

export const SAFETY_PLAN = Object.freeze({
  planId: PLAN_ID,
  supervisorId: SUPERVISOR_ID,
  approval: 'parent_review_required_before_capture',
  platform: 'native-macos-only',
  commands: COMMANDS,
  limits: {
    commandCount: 5,
    active: 1,
    queue: 0,
    commandMs: 750,
    totalMs: 5000,
    combinedOutputBytesPerCommand: 1024,
    intakeBytes: 8192,
    childCleanupGraceMs: CLEANUP_GRACE_MS,
    invocationMs: INVOCATION_MS,
    supervisorShutdownMs: SHUTDOWN_MS,
  },
  captureAuthority: 'single-use-before-observation; module-process-local-only',
  supervisor: 'SIGINT/SIGTERM-to-AbortSignal; finite cleanup; sticky blocked on uncertainty',
  processTreeQualification: 'not_established; fixed-command leaf-only constraint requires independent review',
  actualCapture: 'blocked_pending_independent_supervisor_review_and_separate_single_invocation_consent',
  authority: 'separate_explicit_host_consent_and_parent_review_assertion',
  sourceQualification: 'not_established',
  output: 'sanitized_unsigned_local_evidence_stdout_only',
  exclusions: EXCLUSIONS,
});

export async function main(args, collector = new HostCollector(), now = Date.now(), { signal } = {}) {
  if (args.length === 1 && args[0] === '--plan') return SAFETY_PLAN;
  if (args.length === 0) return { host: 'not_authorized', engineQueried: false };
  const fields = [
    '--parent-reviewed-plan',
    '--parent-reviewed-supervisor',
    '--subject',
    '--target',
    '--version',
    '--consent',
    '--nonce',
    '--issued-at',
    '--expires-at',
  ];
  if (
    args[0] !== '--capture' ||
    args[1] !== '--host-opt-in' ||
    args[2] !== '--single-invocation' ||
    args.length !== 21
  ) {
    return { host: 'not_authorized', engineQueried: false };
  }
  const options = {};
  for (let i = 3; i < args.length; i += 2) {
    if (!fields.includes(args[i]) || Object.hasOwn(options, args[i])) {
      return { host: 'not_authorized', engineQueried: false };
    }
    options[args[i]] = args[i + 1];
  }
  if (
    options['--parent-reviewed-plan'] !== PLAN_ID ||
    !/^[1-9][0-9]{0,8}$/.test(options['--version'] ?? '')
  ) {
    return { host: 'not_authorized', engineQueried: false };
  }
  if (options['--parent-reviewed-supervisor'] !== SUPERVISOR_ID) {
    return { host: 'blocked', reason: 'supervisor_review_required', engineQueried: false };
  }
  const consent = {
    binding: {
      subject: options['--subject'],
      targetId: options['--target'],
      targetVersion: Number(options['--version']),
      consentId: options['--consent'],
      nonce: options['--nonce'],
    },
    confirmed: true,
    reviewed: true,
    planId: options['--parent-reviewed-plan'],
    issuedAt: options['--issued-at'],
    expiresAt: options['--expires-at'],
  };
  // now is not a platform/clock override for actual collection; the collector rechecks actual time.
  if (!Number.isSafeInteger(now)) return { host: 'not_authorized', engineQueried: false };
  return collector.collect(consent, { signal });
}

export async function runCli(
  args,
  { processLike = process, collector = new HostCollector(), now = Date.now(), timers } = {},
) {
  const outcome = await supervise((signal) => main(args, collector, now, { signal }), {
    processLike,
    timers,
  });
  processLike.exitCode = outcome.exitCode;
  processLike.stdout.write(`${canonical(outcome.result)}\n`);
  return outcome;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli(process.argv.slice(2)).catch(() => {
    process.stderr.write('HOST_CAPTURE_REJECTED\n');
    process.exitCode = 1;
  });
}
