#!/usr/bin/env node
import * as fs from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { childEnvironment, readBounded, runChild, writeExclusive, syncDirectory, localPaths } from './setup-local-cve.mjs';
import { publicRefreshFailure } from './refresh-local-cve.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
export const LABEL = 'io.diplom.local-full.cve-refresh';
export const INTERVAL_SECONDS = 6 * 60 * 60;
// Shared inert scheduler mechanics; profile-specific paths/errors/loader are explicit.
export function createCveScheduler({ label = LABEL, script = 'schedule-local-cve.mjs', paths = localPaths,
  scope = 'LOCAL', refreshFailure = publicRefreshFailure, beforeCommand = () => {}, readStatus = raw => raw.trimEnd(),
    validateRecord = record => record, strictLoadedEnvironment = false, loadedEnvironmentMetadata = Object.freeze({}),
  loadRefresh = async () => (await import('./refresh-local-cve.mjs')).refreshLocalCve } = {}) {
const failure = () => new Error(scope + ' CVE schedule refused; inspect its public status and existing LaunchAgent. No automatic replacement or recovery.');
function requireSafe(ok) { if (!ok) throw failure(); }
// Opt-in, source-defined launchd metadata only; never optional user credentials
// or overrides for HOME/PATH/LANG/TZ. Capture data descriptors without getters.
requireSafe(loadedEnvironmentMetadata && typeof loadedEnvironmentMetadata === 'object' &&
  [Object.prototype, null].includes(Object.getPrototypeOf(loadedEnvironmentMetadata)));
const optionalEnvironment = new Map();
for (const key of Reflect.ownKeys(loadedEnvironmentMetadata)) {
  const descriptor = Object.getOwnPropertyDescriptor(loadedEnvironmentMetadata, key);
  const expected = key === 'XPC_SERVICE_NAME' ? label : key === 'OSLogRateLimit' ? '64' : null;
  requireSafe(strictLoadedEnvironment === true && expected !== null && descriptor &&
    Object.hasOwn(descriptor, 'value') && descriptor.value === expected);
  optionalEnvironment.set(key, expected);
}
const xml = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&apos;');

function agentPlist({ root = ROOT, node = process.execPath, home = homedir() } = {}) {
  requireSafe([root, node, home].every(p => typeof p === 'string' && resolve(p) === p && !/[\x00-\x1f]/.test(p)));
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${label}</string>
<key>ProgramArguments</key><array><string>${xml(node)}</string><string>${xml(join(root, 'scripts', script))}</string><string>run</string></array>
<key>WorkingDirectory</key><string>${xml(root)}</string>
<key>EnvironmentVariables</key><dict><key>HOME</key><string>${xml(home)}</string><key>PATH</key><string>${childEnvironment().PATH}</string><key>LANG</key><string>C</string><key>TZ</key><string>UTC</string></dict>
<key>StartInterval</key><integer>${INTERVAL_SECONDS}</integer>
<key>RunAtLoad</key><false/>
<key>KeepAlive</key><false/>
<key>ProcessType</key><string>Background</string>
<key>LowPriorityIO</key><true/>
<key>Nice</key><integer>10</integer>
<key>Umask</key><integer>63</integer>
</dict></plist>
`;
}

function validateLoadedAgent(output, { root, node, path, home }) {
  requireSafe(typeof output === 'string' && Buffer.byteLength(output) <= 65536);
  if (strictLoadedEnvironment) requireSafe(!/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(output));
  const fields = new Map(), blocks = new Map(), stack = [];
  for (const raw of output.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    if (line.endsWith(' = {')) {
      if (strictLoadedEnvironment) requireSafe(!(stack.length === 2 && stack[1] === 'environment'));
      const key = line.slice(0, -4);
      if (stack.length === 1) { requireSafe(!blocks.has(key)); blocks.set(key, []); }
      stack.push(key); continue;
    }
    if (line === '}') { requireSafe(stack.length > 0); stack.pop(); continue; }
    requireSafe(stack.length > 0 && !/[{}]/.test(line));
    if (stack.length === 1) {
      const split = line.indexOf(' = ');
      if (split >= 0) { const key = line.slice(0, split); requireSafe(!fields.has(key)); fields.set(key, line.slice(split + 3)); }
    } else if (stack.length === 2) blocks.get(stack[1]).push(line);
    if (stack.some(key => key.endsWith('environment'))) {
      requireSafe(!/^(DYLD_[A-Z_]+|NODE_OPTIONS|NODE_PATH|DOCKER_HOST|DOCKER_CONTEXT|DOCKER_CONFIG|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY)\s*=>/.test(line));
    }
  }
  requireSafe(stack.length === 0);
  for (const [key, expected] of Object.entries({ path, program: node, 'working directory': root, 'run interval': `${INTERVAL_SECONDS} seconds` })) {
    requireSafe(fields.get(key) === expected);
  }
  requireSafe(JSON.stringify(blocks.get('arguments')) === JSON.stringify([node, join(root, 'scripts', script), 'run']));
  const environment = new Map();
  for (const line of blocks.get('environment') ?? []) {
    const split = line.indexOf(' => '); requireSafe(split > 0);
    const key = line.slice(0, split); requireSafe(!environment.has(key)); environment.set(key, line.slice(split + 4));
  }
  const requiredEnvironment = { ...childEnvironment(), HOME: home };
  for (const [key, value] of Object.entries(requiredEnvironment)) requireSafe(environment.get(key) === value);
  if (strictLoadedEnvironment) {
    let metadataCount = 0;
    for (const [key, value] of optionalEnvironment) if (environment.has(key)) {
      requireSafe(environment.get(key) === value); metadataCount++;
    }
    requireSafe(environment.size === Object.keys(requiredEnvironment).length + metadataCount);
  }
}

function ownedDirectory(path) {
  const stat = fs.lstatSync(path);
  requireSafe(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === process.getuid() && !(stat.mode & 0o022));
}

// One atomic, bounded public record, not an unbounded launchd stdout/stderr log.
function recordRun(root, record) {
  const { stand } = paths(root);
  const path = join(stand, 'cve-refresh-status.json');
  if (fs.lstatSync(path, { throwIfNoEntry: false })) readBounded(path, 4096, 0o600);
  const body = JSON.stringify(validateRecord(record)) + '\n';
  requireSafe(Buffer.byteLength(body) <= 4096);
  const pending = join(stand, '.cve-refresh-status.pending');
  writeExclusive(pending, body, 0o600);
  fs.renameSync(pending, path); syncDirectory(stand);
}

async function scheduledRun({ root = ROOT, refresh, clock = () => new Date().toISOString() } = {}) {
  const startedAt = clock();
  // Refuse overlapping wrappers before replacing the status of an active run.
  const { stand } = paths(root), lock = join(stand, '.cve-schedule.lock');
  fs.mkdirSync(lock, { mode: 0o700 });
  const identity = fs.lstatSync(lock);
  const assertLock = () => {
    const current = fs.lstatSync(lock);
    requireSafe(current.isDirectory() && !current.isSymbolicLink() &&
      current.dev === identity.dev && current.ino === identity.ino);
  };
  let started = false;
  try {
    syncDirectory(stand);
    const update = refresh ?? await loadRefresh();
    const result = await update([], { root, log: () => {}, onLocked: () => {
      assertLock(); requireSafe(!started);
      recordRun(root, { version: 1, startedAt, state: 'running' });
      started = true;
    } });
    assertLock();
    requireSafe(started && ['unchanged', 'activated', 'deferred-busy', 'deferred-stopped'].includes(result.outcome) &&
      /^sha256:[a-f0-9]{64}$/.test(result.manifest));
    recordRun(root, { version: 1, startedAt, finishedAt: clock(), state: 'completed', outcome: result.outcome, manifest: result.manifest });
    return result;
  } catch (error) {
    // Until the updater owns the shared lock, the previous owner's record is immutable.
    if (started) {
      assertLock();
      recordRun(root, { version: 1, startedAt, finishedAt: clock(), state: 'failed', ...refreshFailure(error) });
    }
    throw failure();
  } finally {
    try { assertLock(); fs.rmdirSync(lock); syncDirectory(stand); }
    catch { throw failure(); }
  }
}

async function scheduleCve(argv, { root = ROOT, home = homedir(), node = process.execPath,
  platform = process.platform, run = runChild, log = console.log, uid = process.getuid() } = {}) {
  requireSafe(argv.length === 1 && ['install', 'status', 'run'].includes(argv[0]) && platform === 'darwin');
  await beforeCommand(argv[0], root);
  if (argv[0] === 'run') return scheduledRun({ root });
  paths(root);
  requireSafe(fs.realpathSync(home) === home && fs.realpathSync(node) === node && fs.statSync(node).isFile());
  const agents = join(home, 'Library/LaunchAgents');
  ownedDirectory(home); ownedDirectory(join(home, 'Library')); ownedDirectory(agents);
  const path = join(agents, `${label}.plist`), target = `gui/${uid}/${label}`;
  const env = { ...childEnvironment(), HOME: home };
  const call = args => run('/bin/launchctl', args, { cwd: root, env, timeout: 15_000 });
  const plist = agentPlist({ root, home, node });
  const checkLoaded = async () => validateLoadedAgent(await call(['print', target]), { root, node, path, home });
  if (argv[0] === 'status') {
    requireSafe(readBounded(path, 16384, 0o600) === plist);
    await checkLoaded();
    log(`${scope} CVE schedule loaded: ${label}, every ${INTERVAL_SECONDS / 3600} hours.`);
    const status = join(paths(root).stand, 'cve-refresh-status.json');
    if (fs.lstatSync(status, { throwIfNoEntry: false })) log(readStatus(readBounded(status, 4096, 0o600)));
    return;
  }
  // Never overwrite/adopt a foreign plist, or silently restart an existing job.
  if (fs.existsSync(path)) {
    requireSafe(readBounded(path, 16384, 0o600) === plist);
    await checkLoaded();
    log(scope + ' CVE schedule already installed and loaded; unchanged.');
    return;
  }
  writeExclusive(path, plist, 0o600); syncDirectory(agents);
  await call(['bootstrap', `gui/${uid}`, path]);
  await checkLoaded();
  log(`Installed ${label}: every 6 hours while logged in; no daemon/stopped-stack startup or retries of ambiguous mutations.`);
}

  return { agentPlist, validateLoadedAgent, recordRun, scheduledRun, scheduleCve };
}
export const { agentPlist, validateLoadedAgent, recordRun, scheduledRun, scheduleCve: scheduleLocalCve } = createCveScheduler();

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  scheduleLocalCve(process.argv.slice(2)).catch(() => { console.error('LOCAL CVE schedule refused; inspect its public status and existing LaunchAgent. No automatic replacement or recovery.'); process.exitCode = 1; });
}
