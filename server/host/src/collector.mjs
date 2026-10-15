import { spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { processCaptureAuthority } from './capture-authority.mjs';
import {
  PLAN_ID,
  SOURCE_VERSION,
  EXCLUSIONS,
  authorization,
  canonical,
  payload,
  validFact,
} from './contract.mjs';

// No discovery, caller-provided executable/arguments, shell, sudo, Engine or socket facility.
export const COMMANDS = Object.freeze(
  [
    { fact: 'productVersion', file: '/usr/bin/sw_vers', args: ['-productVersion'] },
    { fact: 'kernelRelease', file: '/usr/bin/uname', args: ['-r'] },
    { fact: 'architecture', file: '/usr/bin/uname', args: ['-m'] },
    { fact: 'physicalMemoryBytes', file: '/usr/sbin/sysctl', args: ['-n', 'hw.memsize'] },
    { fact: 'logicalCpuCount', file: '/usr/sbin/sysctl', args: ['-n', 'hw.logicalcpu'] },
  ].map((command) => Object.freeze({ ...command, args: Object.freeze(command.args) })),
);
const unavailable = (reason) => ({ status: 'unavailable', reason });
const cleanupBlocked = () => ({ status: 'blocked', reason: 'cleanup_unconfirmed' });
export const CLEANUP_GRACE_MS = 100;

export function projectOutput(name, output) {
  if (typeof output !== 'string' || Buffer.byteLength(output) > 1024 || !/^[A-Za-z0-9_.]+\n?$/.test(output))
    return unavailable('invalid_output');
  const text = output.endsWith('\n') ? output.slice(0, -1) : output;
  const numeric = name === 'physicalMemoryBytes' || name === 'logicalCpuCount';
  if (numeric && !/^[1-9][0-9]{0,15}$/.test(text)) return unavailable('invalid_output');
  const value = numeric ? Number(text) : text;
  return validFact(name, value) ? { status: 'observed', value } : unavailable('invalid_output');
}

// This function is reachable only through explicit collection; importing the module does no I/O.
// Fixed absolute commands use no inherited environment, stdin, shell or raw diagnostic logging.
export function createCommandRunner(spawnChild = spawn, timers = { setTimeout, clearTimeout }) {
  let active = false,
    blocked = false;
  return function runPublicCommand(command, { timeoutMs, signal }) {
    if (!COMMANDS.includes(command) || !Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 750) {
      return Promise.resolve(unavailable('command_failed'));
    }
    if (blocked || active) return Promise.resolve(cleanupBlocked());
    return new Promise((resolve) => {
      if (signal?.aborted) {
        resolve(unavailable('command_failed'));
        return;
      }
      active = true;
      let child;
      try {
        child = spawnChild(command.file, command.args, {
          shell: false,
          env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LC_ALL: 'C', LANG: 'C' },
          stdio: ['ignore', 'pipe', 'pipe'],
        });
      } catch {
        active = false;
        resolve(unavailable('command_failed'));
        return;
      }
      let bytes = 0,
        chunks = [],
        reason,
        settled = false,
        cleanupTimer;
      const finish = (result) => {
        if (settled) return;
        settled = true;
        timers.clearTimeout(timer);
        timers.clearTimeout(cleanupTimer);
        signal?.removeEventListener('abort', abort);
        child.stdout.removeListener('data', stdout);
        child.stderr.removeListener('data', stderr);
        chunks = [];
        if (result.status === 'blocked') {
          // Resolve finitely but NEVER release uncertain cleanup into new observations.
          // These affect only our owned handles, not process settings or arbitrary PID/groups.
          blocked = true;
          for (const stream of [child.stdout, child.stderr]) {
            try {
              stream.destroy?.();
            } catch {
              /* cleanup remains unconfirmed */
            }
          }
          try {
            child.unref?.();
          } catch {
            /* cleanup remains unconfirmed */
          }
        }
        active = false;
        resolve(result);
      };
      const stop = (value) => {
        if (settled || reason) return;
        reason = value;
        chunks = [];
        timers.clearTimeout(timer);
        // Install the finite close budget BEFORE kill: fake/real kill may synchronously fail.
        cleanupTimer = timers.setTimeout(() => finish(cleanupBlocked()), CLEANUP_GRACE_MS);
        try {
          if (child.kill('SIGKILL') !== true) blocked = true;
        } catch {
          blocked = true; /* no raw errors; finite close deadline still fires */
        }
      };
      const timer = timers.setTimeout(() => stop('timeout'), timeoutMs);
      const abort = () => stop('command_failed');
      const consume = (chunk, retain) => {
        if (settled || reason) return;
        bytes += chunk.length;
        if (bytes > 1024) stop('output_limit');
        else if (retain) chunks.push(chunk);
      };
      const stdout = (chunk) => consume(chunk, true),
        stderr = (chunk) => consume(chunk, false);
      child.stdout.on('data', stdout);
      child.stderr.on('data', stderr);
      child.stdout.on('error', () => stop('command_failed'));
      child.stderr.on('error', () => stop('command_failed'));
      // Keep a safe error handler for late errors while an unconfirmed child may still exist.
      child.on('error', () => stop('command_failed'));
      child.on('close', (code) => {
        if (settled) return; // Late close never clears the sticky blocked state.
        if (reason || code !== 0)
          finish(blocked ? cleanupBlocked() : unavailable(reason ?? 'command_failed'));
        else {
          try {
            const output = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(
              Buffer.concat(chunks),
            );
            finish(projectOutput(command.fact, output));
          } catch {
            finish(unavailable('invalid_output'));
          }
        }
      });
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) abort();
    });
  };
}
export const runPublicCommand = createCommandRunner();

export class HostCollector {
  #busy = false;
  #runner;
  #platform;
  #now;
  #monotonic;
  #authority;
  #cleanupUnconfirmed = false;
  constructor({
    runner = runPublicCommand,
    platform = process.platform,
    now = Date.now,
    monotonic = () => performance.now(),
    authority = processCaptureAuthority,
  } = {}) {
    // Injection is for controlled pure tests; substituted runners/platforms never qualify a source.
    this.#runner = runner;
    this.#platform = platform;
    this.#now = now;
    this.#monotonic = monotonic;
    this.#authority = authority;
  }
  async collect(consent, { signal } = {}) {
    // Missing independent opt-in wins even over unsupported platform. Zero commands are sent.
    if (consent?.confirmed !== true) return { host: 'not_authorized', engineQueried: false };
    let auth;
    try {
      auth = structuredClone(authorization(consent, this.#now()));
    } catch {
      return { host: 'not_authorized', engineQueried: false };
    }
    if (this.#platform !== 'darwin')
      return { host: 'unsupported', reason: 'native_macos_only', engineQueried: false };
    if (this.#authority.used(auth.binding)) return { host: 'not_authorized', engineQueried: false };
    if (this.#cleanupUnconfirmed)
      return { host: 'blocked', reason: 'cleanup_unconfirmed', engineQueried: false };
    if (this.#busy) return { host: 'skipped', reason: 'busy', engineQueried: false };
    if (signal?.aborted) return { host: 'not_authorized', engineQueried: false };
    this.#busy = true;
    const started = this.#now(),
      monotonicStart = this.#monotonic();
    try {
      const facts = {};
      for (const command of COMMANDS) {
        const current = this.#now();
        if (signal?.aborted || current >= Date.parse(auth.expiresAt) || current < started) {
          return { host: 'not_authorized', engineQueried: false };
        }
        const elapsed = this.#monotonic() - monotonicStart;
        if (!Number.isFinite(elapsed) || elapsed < 0)
          return { host: 'skipped', reason: 'budget_exhausted', engineQueried: false };
        const remaining = Math.min(
          750,
          5000 - elapsed,
          5000 - (current - started),
          Date.parse(auth.expiresAt) - current,
        );
        if (remaining <= 0) return { host: 'skipped', reason: 'budget_exhausted', engineQueried: false };
        if (command === COMMANDS[0] && !this.#authority.consume(auth.binding)) {
          return { host: 'not_authorized', engineQueried: false };
        }
        try {
          const result = await this.#runner(command, { timeoutMs: remaining, signal });
          if (result?.status === 'blocked') {
            this.#cleanupUnconfirmed = true;
            return { host: 'blocked', reason: 'cleanup_unconfirmed', engineQueried: false };
          }
          facts[command.fact] = result;
        } catch {
          // Unexpected runner failure has unknown cleanup, never continue to another command.
          this.#cleanupUnconfirmed = true;
          return { host: 'blocked', reason: 'cleanup_unconfirmed', engineQueried: false };
        }
      }
      const ended = this.#now();
      if (signal?.aborted || ended >= Date.parse(auth.expiresAt))
        return { host: 'not_authorized', engineQueried: false };
      if (ended < started || ended - started > 5000 || this.#monotonic() - monotonicStart > 5000)
        return { host: 'skipped', reason: 'budget_exhausted', engineQueried: false };
      const evidence = payload({
        schema: 'host-evidence-v1',
        sourceVersion: SOURCE_VERSION,
        platform: 'native-macos',
        scope: PLAN_ID,
        binding: auth.binding,
        startedAt: new Date(started).toISOString(),
        endedAt: new Date(ended).toISOString(),
        facts,
      });
      return {
        host: 'captured',
        provenance: 'local_capture_unsigned',
        liveQualified: false,
        engineQueried: false,
        exclusions: [...EXCLUSIONS],
        evidence: JSON.parse(canonical(evidence)),
      };
    } finally {
      this.#busy = false;
    }
  }
}
