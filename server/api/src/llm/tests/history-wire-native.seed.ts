import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readFileSync, readSync, realpathSync, readdirSync, statfsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import Database from 'better-sqlite3';
import { ServiceUnavailableException } from '@nestjs/common';
import { AuthStore } from '../../auth/auth.store.js';
import { LedgerStore } from '../../ledger/ledger-store.js';
import { NginxLocalScansService } from '../../oci/nginx-local-profile.js';
import { NGINX_LOCAL_BINDING, NGINX_LOCAL_POLICY as local } from '../../oci/nginx-local-policy.js';
import { ReportReader } from '../report-context.js';
import { HistoryRuntime } from '../history-runtime.js';
import { HISTORY, hashValue, mutationInputHash, reportBinding } from '../history-contract.js';
import { policyFromEnvironment } from '../policy.js';
import type { ArchiveScanReport } from '../../worker/archive-scan-worker.js';
import { OciResolver } from '../../oci/oci-resolver.js';

// BEGIN PURE SEED DIAGNOSTICS — no IO, messages, stacks, paths or input values.
export const SEED_ENTRY_STEPS = ['entry_read', 'entry_parse', 'entry_argv', 'entry_mode'] as const;
export const SEED_COMMON_STEPS = ['input_schema', 'environment_uid', 'environment_gid', 'environment_auth_path',
  'environment_scan_path', 'environment_flags', 'environment_private_names', 'environment_volume_stat',
  'environment_volume_mode', 'environment_volume_canonical', 'environment_volume_distinct', 'quota_absent',
  'source_fixture_shape', 'source_fixture_stat', 'source_fixture_hash', 'source_map_read', 'source_map_identity',
  'source_embedded_path', 'source_embedded_stat', 'source_embedded_hash', 'source_tree', 'receipt_encode',
  'metadata_file', 'metadata_headroom', 'metadata_other_files', 'metadata_sidecars', 'metadata_schema', 'metadata_counts', 'metadata_close',
  'access_open', 'access_read', 'access_close', 'state_schema', 'state_uuids', 'state_ids', 'state_hashes', 'state_binding', 'state_inode'] as const;
export const SEED_SETUP_STEPS = ['fresh_auth_empty', 'fresh_scan_empty', 'history_runtime_construct',
  'history_missing_open', 'history_missing_close', 'history_missing_assert', 'initialize_spawn', 'initialize_status',
  'initialize_error_signal', 'initialize_stderr', 'initialize_stdout', 'initialize_identity', 'existing_spawn',
  'existing_status', 'existing_error_signal', 'existing_stdout', 'existing_stderr', 'existing_hash', 'existing_inode',
  'auth_register_open', 'auth_register_owner', 'auth_register_foreign', 'auth_register_assert', 'auth_register_close',
  'auth_allowlist_finalize', 'auth_login_open', 'auth_login_owner', 'auth_login_close', 'ledger_open', 'history_open',
  'history_writer', 'report_construct', 'report_enqueue', 'report_claim', 'report_finish', 'report_pending',
  'report_projection', 'history_original_head', 'history_descriptor', 'history_access_incarnation', 'history_begin',
  'history_begin_revision', 'history_fail', 'history_failed_head', 'history_metadata', 'state_construct', 'state_validate',
  'setup_close_history', 'setup_close_ledger'] as const;
export const SEED_AUDIT_STEPS = ['audit_state', 'audit_allowlist', 'audit_ledger', 'audit_history_open', 'audit_head',
  'audit_metadata', 'audit_writer', 'audit_identity', 'audit_shape', 'audit_turn', 'audit_fingerprints',
  'audit_original_request', 'audit_projection', 'audit_report', 'audit_decision', 'audit_close_history', 'audit_close_ledger'] as const;
export const SEED_ERROR_CLASSES = ['Error', 'AssertionError', 'TypeError', 'RangeError', 'SyntaxError', 'SqliteError',
  'ServiceUnavailableException', 'UnauthorizedException', 'ForbiddenException', 'ConflictException',
  'BadRequestException', 'InternalServerErrorException', 'other_error', 'non_error'] as const;
export const SEED_ERROR_CODES = ['none', 'other', 'ERR_ASSERTION', 'ERR_MODULE_NOT_FOUND', 'MODULE_NOT_FOUND',
  'ERR_DLOPEN_FAILED', 'ERR_UNKNOWN_FILE_EXTENSION', 'ERR_INVALID_ARG_TYPE', 'SQLITE_ERROR', 'SQLITE_CANTOPEN',
  'SQLITE_READONLY', 'SQLITE_FULL', 'SQLITE_BUSY', 'SQLITE_CORRUPT', 'EPERM', 'EACCES', 'ENOENT', 'ETIMEDOUT', 'ENOBUFS', 'EAGAIN', 'ENOMEM'] as const;
type SeedPhase = 'entry' | 'setup' | 'audit';
type SeedStep = typeof SEED_ENTRY_STEPS[number] | typeof SEED_COMMON_STEPS[number] |
  typeof SEED_SETUP_STEPS[number] | typeof SEED_AUDIT_STEPS[number];
type SeedError = { errorClass: typeof SEED_ERROR_CLASSES[number]; errorCode: typeof SEED_ERROR_CODES[number] };
export function seedError(error: unknown): SeedError {
  if (!(error instanceof Error)) return { errorClass: 'non_error', errorCode: 'none' };
  let errorClass: SeedError['errorClass'] = 'other_error', errorCode: SeedError['errorCode'] = 'other';
  try {
    const constructor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(error), 'constructor')?.value;
    const name: unknown = typeof constructor === 'function' ? Object.getOwnPropertyDescriptor(constructor, 'name')?.value : undefined;
    for (const allowed of SEED_ERROR_CLASSES) if (name === allowed) errorClass = allowed;
    const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
    const code: unknown = descriptor && 'value' in descriptor ? descriptor.value : undefined;
    if (!descriptor || 'value' in descriptor && code === undefined) errorCode = 'none';
    else for (const allowed of SEED_ERROR_CODES) if (code === allowed) errorCode = allowed;
  } catch { /* Only fixed fallback enums survive hostile descriptors. */ }
  return { errorClass, errorCode };
}
export const INITIALIZER_CAPTURE_BYTES = 32768;
export const SEED_DIAGNOSTIC_BYTES = 2048;
export const SEED_NODE_FLAGS = ['loader', 'transform', 'spawn_eagain', 'worker_init', 'uv_thread', 'go_thread',
  'esbuild_stopped', 'esbuild_binary'] as const;
export const OWN_PIDS_FILES = ['max', 'current', 'peak', 'events'] as const;
export const OWN_PIDS_COUNTER_MAX = 1000000;
type PidsCounter = [present: boolean, bounded: boolean, value: number | 'max' | null];
type PidsSample = Record<typeof OWN_PIDS_FILES[number], PidsCounter>;
type PidsProbe = { kind: 'initialize' | 'existing_refusal'; before: PidsSample; after: PidsSample };
export function unavailablePids(): PidsSample {
  return { max: [false, false, null], current: [false, false, null], peak: [false, false, null], events: [false, false, null] };
}
export function pidsCounter(kind: typeof OWN_PIDS_FILES[number], raw: unknown, present: boolean): PidsCounter {
  if (!present) return [false, false, null];
  if (!Buffer.isBuffer(raw) || raw.length > 256) return [true, false, null];
  const text = raw.toString('ascii');
  // Reject high-bit bytes instead of silently interpreting ASCII aliases.
  if (!Buffer.from(text, 'ascii').equals(raw)) return [true, false, null];
  if (kind === 'max' && (text === 'max\n' || text === 'max')) return [true, true, 'max'];
  const match = (kind === 'events' ? /^max (0|[1-9][0-9]{0,6})\n?$/ : /^(0|[1-9][0-9]{0,6})\n?$/).exec(text);
  if (!match || match[0].length !== text.length) return [true, false, null];
  const n = Number(match[1]);
  return Number.isSafeInteger(n) && n <= OWN_PIDS_COUNTER_MAX ? [true, true, n] : [true, false, null];
}
export const SEED_NODE_CLASSES = ['Error', 'AssertionError', 'TypeError', 'RangeError', 'SyntaxError', 'ReferenceError',
  'SqliteError', 'TransformError', 'TSError', 'ServiceUnavailableException'] as const;
export const SEED_NODE_CODES = ['ERR_ASSERTION', 'ERR_MODULE_NOT_FOUND', 'MODULE_NOT_FOUND', 'ERR_DLOPEN_FAILED',
  'ERR_UNKNOWN_FILE_EXTENSION', 'ERR_INVALID_ARG_TYPE', 'ERR_REQUIRE_ESM', 'ERR_REQUIRE_CYCLE_MODULE',
  'ERR_PACKAGE_PATH_NOT_EXPORTED', 'ERR_UNSUPPORTED_DIR_IMPORT', 'ERR_INVALID_MODULE_SPECIFIER',
  'SQLITE_ERROR', 'SQLITE_CANTOPEN', 'SQLITE_READONLY', 'SQLITE_FULL', 'SQLITE_BUSY', 'SQLITE_CORRUPT',
  'EPERM', 'EACCES', 'ENOENT', 'EAGAIN', 'ENOMEM', 'ERR_WORKER_INIT_FAILED'] as const;
// IDs map only to public files pinned by the existing fixture/embedded receipts.
export const SEED_NODE_FRAME_PATHS = {
  fixture_seed: 'server/api/src/llm/tests/history-wire-native.seed.ts',
  fixture_api: 'server/api/src/llm/tests/history-wire-native.api.ts',
  fixture_client: 'server/api/src/llm/tests/history-wire-native.client.mjs',
  fixture_runner: 'server/deploy/proof/history-wire-native.py',
  fixture_tests: 'server/deploy/proof/test_history_wire_native.py',
  history_init: 'server/api/src/llm/history-init.ts',
  history_runtime: 'server/api/src/llm/history-runtime.ts',
  history_store: 'server/api/src/llm/history-store.ts',
} as const;
type NodeDiagnostic = { class: typeof SEED_NODE_CLASSES[number] | 'none' | 'ambiguous';
  code: typeof SEED_NODE_CODES[number] | 'none' | 'ambiguous'; frame: [keyof typeof SEED_NODE_FRAME_PATHS, number] | null;
    flags: Record<typeof SEED_NODE_FLAGS[number], boolean> };
  export function emptyNodeDiagnostic(): NodeDiagnostic {
    return { class: 'none', code: 'none', frame: null, flags: { loader: false, transform: false, spawn_eagain: false,
      worker_init: false, uv_thread: false, go_thread: false, esbuild_stopped: false, esbuild_binary: false } };
  }
export function initializerNodeDiagnostic(stderr: unknown): NodeDiagnostic {
  const result = emptyNodeDiagnostic();
  if (!Buffer.isBuffer(stderr) || stderr.length > INITIALIZER_CAPTURE_BYTES) return result;
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(stderr); } catch { return result; }
  const classes = new Set<typeof SEED_NODE_CLASSES[number]>(), codes = new Set<typeof SEED_NODE_CODES[number]>();
  const escaped = (literal: string) => literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Prefix-only observation, never a completeness or root-cause claim.
  for (const line of text.split('\n', 257).slice(0, 256)) {
    if (line.length > 2048) continue;
    // Match only fixed public signature fragments; never retain matched text.
    if (/^Error: spawn [^\r\n]{1,512} EAGAIN$/.test(line)) result.flags.spawn_eagain = true;
    if (/^node\[[0-9]{1,10}\]: pthread_create: Resource temporarily unavailable$/.test(line) ||
        line.includes('Assertion') && line.includes('uv_thread_create')) result.flags.uv_thread = true;
    if (/^fatal error: newosproc$/.test(line) || /^runtime: failed to create new OS thread /.test(line)) result.flags.go_thread = true;
    if (/^Error: The service (?:was stopped|is no longer running)(?::.*)?$/.test(line)) result.flags.esbuild_stopped = true;
    if (line === "You installed esbuild for another platform than the one you're currently using." ||
        /^Error: The package "@esbuild\/linux-(?:x64|arm64)" could not be found, and is needed by esbuild\.$/.test(line)) result.flags.esbuild_binary = true;
    for (const name of SEED_NODE_CLASSES) {
      if (new RegExp('^' + escaped(name) + '(?: \\[(?:' + SEED_NODE_CODES.map(escaped).join('|') + ')\\])?:').test(line) ||
          name === 'TransformError' && /^Error \[TransformError\]:/.test(line)) classes.add(name);
    }
    for (const code of SEED_NODE_CODES) {
      if (new RegExp('^(?:' + SEED_NODE_CLASSES.map(escaped).join('|') + ') \\[' + escaped(code) + '\\]:').test(line) ||
          new RegExp("^ {0,8}code: '" + escaped(code) + "',?$").test(line)) codes.add(code);
    }
    if (result.frame === null) for (const [id, path] of Object.entries(SEED_NODE_FRAME_PATHS)) {
      const location = '(?:file://)?' + escaped('/app/' + path) + ':([1-9][0-9]{0,3}):[1-9][0-9]{0,4}';
      const match = new RegExp('^(?: {0,16}at ' + location + '| {0,16}at [^()\\r\\n]{1,128} \\(' + location + '\\)|' + location + ')$').exec(line);
      if (match) {
        const n = Number(match[1] ?? match[2] ?? match[3]);
        if (Number.isInteger(n) && n <= 4096) { result.frame = [id as keyof typeof SEED_NODE_FRAME_PATHS, n]; break; }
      }
    }
  }
  result.class = classes.size === 1 ? [...classes][0] : classes.size ? 'ambiguous' : 'none';
  result.code = codes.size === 1 ? [...codes][0] : codes.size ? 'ambiguous' : 'none';
  result.flags.loader = ['ERR_MODULE_NOT_FOUND', 'MODULE_NOT_FOUND', 'ERR_UNKNOWN_FILE_EXTENSION', 'ERR_REQUIRE_ESM',
    'ERR_PACKAGE_PATH_NOT_EXPORTED', 'ERR_UNSUPPORTED_DIR_IMPORT', 'ERR_INVALID_MODULE_SPECIFIER'].some(code => codes.has(code as typeof SEED_NODE_CODES[number]));
  result.flags.transform = classes.has('TransformError') || classes.has('TSError');
  result.flags.spawn_eagain ||= codes.has('EAGAIN');
  result.flags.worker_init = codes.has('ERR_WORKER_INIT_FAILED');
  return result;
}
type InitializerKind = 'initialize' | 'existing_refusal';
export type InitializerDiagnostic = {
  kind: InitializerKind; exit: 'zero' | 'one' | 'other' | 'none' | 'invalid';
  signal: 'none' | 'sigterm' | 'sigkill' | 'other'; error: 'none' | 'ETIMEDOUT' | 'ENOBUFS' | 'EPERM' | 'EACCES' | 'ENOENT' | 'EAGAIN' | 'ENOMEM' | 'other';
  stdoutExpectedMatch: boolean; stderrExpectedMatch: boolean; stdoutEmpty: boolean; stderrEmpty: boolean;
  stdoutBounded: boolean; stderrBounded: boolean; node: NodeDiagnostic;
};
export function initializerDiagnostic(kind: InitializerKind, result: {
  status: unknown; signal: unknown; error?: unknown; stdout: unknown; stderr: unknown;
}): InitializerDiagnostic {
  const code = result.error === undefined ? 'none' : seedError(result.error).errorCode;
  const error: InitializerDiagnostic['error'] = code === 'none' && result.error !== undefined ? 'other' :
    code === 'none' || code === 'ETIMEDOUT' || code === 'ENOBUFS' || code === 'EPERM' || code === 'EACCES' || code === 'ENOENT' || code === 'EAGAIN' || code === 'ENOMEM' ? code : 'other';
  const expectedOut = kind === 'initialize' ? 'History operator action complete. No provider call or runtime activation performed.\n' : '';
  const expectedErr = kind === 'existing_refusal' ? 'History operator action refused; no quota reset or automatic repair.\n' : '';
  return { kind, exit: result.status === null ? 'none' : typeof result.status !== 'number' || !Number.isInteger(result.status) ? 'invalid' :
    result.status === 0 ? 'zero' : result.status === 1 ? 'one' : 'other',
    signal: result.signal === null ? 'none' : result.signal === 'SIGTERM' ? 'sigterm' : result.signal === 'SIGKILL' ? 'sigkill' : 'other', error,
    stdoutExpectedMatch: Buffer.isBuffer(result.stdout) && result.stdout.equals(Buffer.from(expectedOut)),
    stderrExpectedMatch: Buffer.isBuffer(result.stderr) && result.stderr.equals(Buffer.from(expectedErr)),
    stdoutEmpty: Buffer.isBuffer(result.stdout) && result.stdout.length === 0,
    stderrEmpty: Buffer.isBuffer(result.stderr) && result.stderr.length === 0,
    stdoutBounded: Buffer.isBuffer(result.stdout) && result.stdout.length <= INITIALIZER_CAPTURE_BYTES,
    stderrBounded: Buffer.isBuffer(result.stderr) && result.stderr.length <= INITIALIZER_CAPTURE_BYTES,
    node: initializerNodeDiagnostic(result.stderr) };
}
export type SeedDiagnostic = SeedError & { kind: 'history-wire-seed-refusal'; passed: false; phase: SeedPhase;
  step: SeedStep; initializers: InitializerDiagnostic[]; initializerPids: PidsProbe | null; cleanupFailed: boolean; rawValuesIncluded: false };
let seedPhase: SeedPhase = 'entry', seedStep: SeedStep = 'entry_read';
const initializerResults: InitializerDiagnostic[] = [];
let initializerPids: PidsProbe | null = null;
export function initializerExpected(kind: InitializerKind, row: InitializerDiagnostic): boolean {
  return row.exit === (kind === 'initialize' ? 'zero' : 'one') && row.signal === 'none' && row.error === 'none' &&
    row.stdoutExpectedMatch && row.stderrExpectedMatch;
}
let firstSeedFailure: SeedDiagnostic | undefined;
function checkpoint(step: SeedStep) { seedStep = step; }
export function seedDiagnostic(error: unknown): SeedDiagnostic {
  const result: SeedDiagnostic = { kind: 'history-wire-seed-refusal', passed: false, phase: seedPhase, step: seedStep,
    ...seedError(error), initializers: initializerResults.slice(), initializerPids, cleanupFailed: false, rawValuesIncluded: false };
  assert(Buffer.byteLength(JSON.stringify(result)) <= SEED_DIAGNOSTIC_BYTES); return result;
}
function rememberSeedFailure(error: unknown) { firstSeedFailure ??= seedDiagnostic(error); }
function diagnosticCleanup(step: SeedStep, close: () => void) {
  const previous = seedStep; checkpoint(step);
  try { close(); }
  catch (error) {
    rememberSeedFailure(error);
    firstSeedFailure!.cleanupFailed = true;
    throw error;
  } finally { seedStep = previous; }
}
// END PURE SEED DIAGNOSTICS

// Runtime-only, after OWN/private-cgroup and fixture qualification. No host,
// cgroup-v1, parent traversal or arbitrary-path fallback. Diagnostics never throw.
function ownPidsSnapshot(): PidsSample {
  const result = unavailablePids();
  if (process.platform !== 'linux') return result;
  try {
    const root = '/sys/fs/cgroup', s = lstatSync(root);
    if (!s.isDirectory() || s.isSymbolicLink() || realpathSync(root) !== root) return result;
    for (const kind of OWN_PIDS_FILES) {
      let fd: number | undefined, present = false;
      try {
        const path = root + '/pids.' + kind, stat = lstatSync(path); present = true;
        if (!stat.isFile() || stat.isSymbolicLink()) { result[kind] = [true, false, null]; continue; }
        fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
        if (!fstatSync(fd).isFile()) { result[kind] = [true, false, null]; continue; }
        const raw = Buffer.alloc(257), n = readSync(fd, raw, 0, raw.length, null);
        result[kind] = pidsCounter(kind, raw.subarray(0, n), true);
      } catch { result[kind] = [present, false, null]; }
      finally { if (fd !== undefined) try { closeSync(fd); } catch { result[kind] = [true, false, null]; } }
    }
  } catch { /* Missing/unqualified virtual files remain unavailable, never primary. */ }
  return result;
}

export const accounts = Object.freeze([
  Object.freeze({ email: 'history-wire-a@qualification.invalid', password: 'history-wire-public-password-a-123' }),
  Object.freeze({ email: 'history-wire-b@qualification.invalid', password: 'history-wire-public-password-b-123' }),
]);
export const question = 'Explain the reported finding.';
export const decisionText = 'Investigate this finding before accepting the image.';
export function replayPolicy() {
  const policy = policyFromEnvironment(Object.freeze({
    LLM_ENABLED: 'true', LLM_FREE_ONLY: 'true', LLM_MODEL: 'apodex/apodex-1.1-mini:free',
    LLM_PROVIDER_ALLOWLIST: 'novita/bf16', LLM_POLICY_REVISION: 'history-wire-replay-fixture-v1',
    LLM_ROUTING_APPROVED: 'true', LLM_REGION: 'global', LLM_RETENTION: 'no-storage',
    LLM_TIMEOUT_MS: '1000', LLM_REQUEST_BYTES: '262144', LLM_RESPONSE_BYTES: '65536',
    LLM_MAX_FINDINGS: '1000', LLM_OUTPUT_TOKENS: '256', LLM_REQUEST_BUDGET_USD: '0',
    LLM_INPUT_PRICE_PER_MILLION_USD: '0', LLM_OUTPUT_PRICE_PER_MILLION_USD: '0', LLM_REQUEST_PRICE_USD: '0',
  }));
  assert(policy?.freeOnly && Object.isFrozen(policy) && Object.isFrozen(policy.providers));
  assert.deepEqual(policy.providers, ['novita/bf16']);
  return policy;
}
export const consentVersion = () => hashValue([replayPolicy().version, HISTORY.version, 'question-history-decisions-retained-no-output-cache']);
export function quotaAbsent() {
  checkpoint('quota_absent');
  for (const suffix of ['', '-journal', '-wal', '-shm']) assert(!existsSync('/auth/llm-usage.sqlite' + suffix));
  return true;
}
export function fixtureEnvironment() {
  checkpoint('environment_uid'); assert.equal(process.getuid?.(), 65532);
  checkpoint('environment_gid'); assert.equal(process.getgid?.(), 65532);
  checkpoint('environment_auth_path'); assert.equal(process.env.AUTH_DB_PATH, '/auth/auth.sqlite');
  checkpoint('environment_scan_path'); assert.equal(process.env.SCAN_LEDGER_PATH, '/data/scans.sqlite');
  checkpoint('environment_flags');
  for (const [key, value] of Object.entries({ LLM_ENABLED: 'false', LLM_ROUTING_APPROVED: 'false',
    LLM_QUOTA_ENABLED: 'false', LLM_HISTORY_ENABLED: 'true', LLM_HISTORY_REVISION: HISTORY.version,
    LLM_HISTORY_AUTHORITY: 'single-api-quiesced-terminal-v1' })) assert.equal(process.env[key], value);
  checkpoint('environment_private_names');
  for (const key of Object.keys(process.env)) assert(!/^(?:OPENROUTER_|RUNTIME_DB_PATH$|NODE_OPTIONS$|NODE_TLS_|NODE_EXTRA_CA|HTTP_PROXY$|HTTPS_PROXY$|ALL_PROXY$)/i.test(key));
  for (const path of ['/auth', '/data']) {
    checkpoint('environment_volume_stat'); const s = lstatSync(path); assert(s.isDirectory() && !s.isSymbolicLink() && s.uid === 65532 && s.gid === 65532);
    checkpoint('environment_volume_mode'); assert.equal(s.mode & 0o7777, 0o700);
    checkpoint('environment_volume_canonical'); assert.equal(realpathSync(path), path);
  }
  checkpoint('environment_volume_distinct'); const authRoot = lstatSync('/auth'), scanRoot = lstatSync('/data');
  assert(authRoot.dev !== scanRoot.dev || authRoot.ino !== scanRoot.ino);
  quotaAbsent();
}
const digest = (raw: Buffer) => createHash('sha256').update(raw).digest('hex');
export function qualify(files: Record<string, string>, fixtures: Record<string, string>, serving = false) {
  const bound = ['server/api/src/llm/tests/history-wire-native.seed.ts',
    ...(serving ? ['server/api/src/llm/tests/history-wire-native.api.ts'] : [])];
  checkpoint('source_fixture_shape'); assert.deepEqual(Object.keys(fixtures).sort(), bound.sort());
  for (const [name, expected] of Object.entries(fixtures)) {
    checkpoint('source_fixture_stat'); assert(/^[a-f0-9]{64}$/.test(expected)); const path = '/app/' + name, s = lstatSync(path);
    assert(s.isFile() && !s.isSymbolicLink() && s.nlink === 1 && s.size <= 262144 && realpathSync(path) === path);
    checkpoint('source_fixture_hash'); assert.equal(digest(readFileSync(path)), expected);
  }
  checkpoint('source_map_read');
  const map = JSON.parse(readFileSync('/proof/source-map.json', 'utf8'));
  checkpoint('source_map_identity'); assert.equal(map.sourceSnapshotSha256, 'e4efad5ff9ef56040e1d341311599d8bb19da874af94b5bf1eaffa97b7ed6334');
  assert.deepEqual(map.files, files); assert.equal(Object.keys(files).length, 238);
  for (const [name, expected] of Object.entries(files)) {
    checkpoint('source_embedded_path'); assert(/^[A-Za-z0-9_./-]+$/.test(name) && !name.split('/').some(p => p.startsWith('.')));
    assert(/^[a-f0-9]{64}$/.test(expected));
    checkpoint('source_embedded_stat'); const path = '/app/' + name, s = lstatSync(path);
    assert(s.isFile() && !s.isSymbolicLink() && s.size <= 4194304 && realpathSync(path) === path);
    checkpoint('source_embedded_hash'); assert.equal(digest(readFileSync(path)), expected);
  }
  checkpoint('source_tree');
  const added = new Set(bound);
  const walk = (directory: string): string[] => readdirSync(directory, { withFileTypes: true }).flatMap(e => {
    assert(!e.isSymbolicLink()); const path = directory + '/' + e.name;
    assert(!e.name.startsWith('.'));
    if (e.isDirectory()) return walk(path);
    assert(e.isFile());
    if (!/\.(?:ts|tsx|mts|cts|js|mjs|cjs|json)$/.test(e.name)) return [];
    return added.has(path.slice(5)) ? [] : [path.slice(5)];
  });
  for (const tree of ['server/api/src', 'server/runtime/src', 'server/broker/src'])
    assert.deepEqual(walk('/app/' + tree).sort(), Object.keys(files).filter(p => p.startsWith(tree + '/')).sort());
}
export type FixtureState = {
  owner: string; foreign: string; scanId: string; epoch: string; turnId: string; mutationId: string; decisionId: string;
  digest: string; platform: string; reportVersion: string; consentPolicyVersion: string;
  incarnation: string; fingerprintDigest: string; reportDigest: string; accessIncarnation: string;
  historyInode: number; historyDevice: number;
};
export function validateState(s: FixtureState) {
  checkpoint('state_schema'); assert.deepEqual(Object.keys(s).sort(), ['owner', 'foreign', 'scanId', 'epoch', 'turnId', 'mutationId', 'decisionId',
    'digest', 'platform', 'reportVersion', 'consentPolicyVersion', 'incarnation', 'fingerprintDigest', 'reportDigest',
    'accessIncarnation', 'historyInode', 'historyDevice'].sort());
  checkpoint('state_uuids');
  for (const key of ['scanId', 'epoch', 'turnId', 'mutationId', 'decisionId', 'incarnation'] as const)
    assert(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(s[key]));
  checkpoint('state_ids');
  for (const key of ['owner', 'foreign', 'accessIncarnation'] as const) assert(/^[a-f0-9]{32}$/.test(s[key]));
  checkpoint('state_hashes');
  for (const key of ['reportVersion', 'consentPolicyVersion', 'fingerprintDigest', 'reportDigest'] as const) assert(/^[a-f0-9]{64}$/.test(s[key]));
  checkpoint('state_binding'); assert.equal(s.digest, local.digest); assert.equal(s.platform, 'linux/amd64'); assert.notEqual(s.owner, s.foreign);
  checkpoint('state_inode'); assert(Number.isSafeInteger(s.historyInode) && Number.isSafeInteger(s.historyDevice));
}
function metadata() {
  checkpoint('metadata_file'); const s = lstatSync('/auth/llm-history.sqlite');
  assert(s.isFile() && !s.isSymbolicLink() && s.nlink === 1 && s.uid === 65532 && s.gid === 65532);
  assert.equal(s.mode & 0o7777, 0o600); assert(s.size <= HISTORY.dbBytes);
  assert.equal(realpathSync('/auth/llm-history.sqlite'), '/auth/llm-history.sqlite');
  checkpoint('metadata_headroom'); const fs = statfsSync('/auth', { bigint: true }); assert(fs.bavail * fs.bsize >= BigInt(HISTORY.diskHeadroom));
  checkpoint('metadata_other_files');
  for (const path of ['/auth/auth.sqlite', '/data/scans.sqlite']) {
    const other = lstatSync(path); assert(other.isFile() && !other.isSymbolicLink() && other.nlink === 1);
    assert.equal(other.mode & 0o7777, 0o600); assert.equal(other.uid, 65532); assert.equal(other.gid, 65532);
    assert(other.dev !== s.dev || other.ino !== s.ino);
  }
  checkpoint('metadata_sidecars'); let sidecarBytes = 0;
  for (const suffix of ['-journal', '-wal', '-shm']) if (existsSync('/auth/llm-history.sqlite' + suffix)) {
    assert.equal(suffix, '-journal'); const side = lstatSync('/auth/llm-history.sqlite' + suffix);
    assert(side.isFile() && !side.isSymbolicLink() && side.nlink === 1 && side.uid === 65532);
    assert.equal(side.mode & 0o7777, 0o600); sidecarBytes += side.size;
  }
  assert(sidecarBytes <= HISTORY.sidecarBytes);
  checkpoint('metadata_schema'); const db = new Database('/auth/llm-history.sqlite', { readonly: true, fileMustExist: true });
  try {
    assert.equal(db.pragma('application_id', { simple: true }), 1145655602);
    assert.equal(db.pragma('user_version', { simple: true }), 3);
    assert.equal(db.pragma('page_size', { simple: true }), 4096);
    assert.equal(db.pragma('journal_mode', { simple: true }), 'delete');
    checkpoint('metadata_counts'); assert.equal((db.prepare('SELECT count(*) n FROM history_completion_space').get() as { n: number }).n, 0);
    assert.equal((db.prepare('SELECT count(*) n FROM history_head').get() as { n: number }).n, 1);
  } catch (error) { rememberSeedFailure(error); throw error; }
  finally { diagnosticCleanup('metadata_close', () => db.close()); }
  return { inode: s.ino, device: s.dev };
}
function accessIncarnation() {
  checkpoint('access_open'); const db = new Database('/auth/auth.sqlite', { readonly: true, fileMustExist: true });
  try { checkpoint('access_read'); return (db.prepare('SELECT incarnation FROM browser_access WHERE id=1').get() as { incarnation: string }).incarnation; }
  catch (error) { rememberSeedFailure(error); throw error; }
  finally { diagnosticCleanup('access_close', () => db.close()); }
}
function reader(store: LedgerStore) {
  const service = new NginxLocalScansService(store, new OciResolver());
  return new ReportReader(service);
}
async function setup(files: Record<string, string>, fixtures: Record<string, string>) {
  fixtureEnvironment(); qualify(files, fixtures); process.umask(0o077);
  checkpoint('fresh_auth_empty'); assert.deepEqual(readdirSync('/auth'), []);
  checkpoint('fresh_scan_empty'); assert.deepEqual(readdirSync('/data'), []);
  checkpoint('history_runtime_construct'); const runtime = new HistoryRuntime(); let missing = false;
  checkpoint('history_missing_open');
  try { runtime.store(); } catch (error) {
      missing = error instanceof ServiceUnavailableException &&
        (error.getResponse() as { errorCode?: string }).errorCode === 'LLM_HISTORY_UNAVAILABLE';
      if (!missing) rememberSeedFailure(error);
    } finally { diagnosticCleanup('history_missing_close', () => runtime.close()); }
  checkpoint('history_missing_assert'); assert(missing && !existsSync('/auth/llm-history.sqlite'));
  const initialize = (kind: InitializerKind) => {
    const before = ownPidsSnapshot();
    try {
      const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/llm/history-init.ts', '--initialize'],
        { cwd: '/app/server/api', timeout: 10000, maxBuffer: INITIALIZER_CAPTURE_BYTES, stdio: ['ignore', 'pipe', 'pipe'] });
      const summary = initializerDiagnostic(kind, result);
      assert(initializerResults.length < 2); initializerResults.push(summary);
      if (!initializerExpected(kind, summary)) initializerPids = { kind, before, after: ownPidsSnapshot() };
      return result;
    } catch (error) {
      initializerPids ??= { kind, before, after: ownPidsSnapshot() }; throw error;
    }
  };
  checkpoint('initialize_spawn'); const initialized = initialize('initialize');
  checkpoint('initialize_status'); assert.equal(initialized.status, 0);
  checkpoint('initialize_error_signal'); assert(!initialized.error && !initialized.signal);
  checkpoint('initialize_stderr'); assert.equal(initialized.stderr.toString(), '');
  checkpoint('initialize_stdout'); assert.equal(initialized.stdout.toString(), 'History operator action complete. No provider call or runtime activation performed.\n');
  checkpoint('initialize_identity'); const before = digest(readFileSync('/auth/llm-history.sqlite'));
  const originalInode = lstatSync('/auth/llm-history.sqlite').ino;
  checkpoint('existing_spawn'); const negative = initialize('existing_refusal');
  checkpoint('existing_status'); assert.equal(negative.status, 1);
  checkpoint('existing_error_signal'); assert(!negative.error && !negative.signal);
  checkpoint('existing_stdout'); assert.equal(negative.stdout.toString(), '');
  checkpoint('existing_stderr'); assert.equal(negative.stderr.toString(), 'History operator action refused; no quota reset or automatic repair.\n');
  checkpoint('existing_hash'); assert.equal(digest(readFileSync('/auth/llm-history.sqlite')), before);
  checkpoint('existing_inode'); assert.equal(lstatSync('/auth/llm-history.sqlite').ino, originalInode);
  checkpoint('auth_register_open'); let auth = new AuthStore();
  checkpoint('auth_register_owner'); const a = await auth.register(accounts[0].email, accounts[0].password);
  checkpoint('auth_register_foreign'); const b = await auth.register(accounts[1].email, accounts[1].password);
  checkpoint('auth_register_assert'); assert(a && b);
  checkpoint('auth_register_close'); auth.onModuleDestroy();
  // Exactly one offline finalization, before any serving bootstrap captures policy.
  checkpoint('auth_allowlist_finalize'); process.env.SCAN_BROWSER_ALLOWED_USER_IDS = a.id + ',' + b.id;
  checkpoint('auth_login_open'); auth = new AuthStore();
  try {
    checkpoint('auth_login_owner'); assert.equal((await auth.login(accounts[0].email, accounts[0].password))?.id, a.id);
  } catch (error) { rememberSeedFailure(error); throw error; }
  finally { diagnosticCleanup('auth_login_close', () => auth.onModuleDestroy()); }
  checkpoint('ledger_open'); const ledgerStore = new LedgerStore(), ledger = ledgerStore.ledger; assert(ledger);
  checkpoint('history_open'); const history = runtime.store();
  checkpoint('history_writer'); assert.equal(Reflect.get(history, 'db').pragma('synchronous', { simple: true }), 2);
  try {
    checkpoint('report_construct'); const report: ArchiveScanReport = { receipt: {
      registry: local.registry, repository: local.repository, digest: local.digest, configDigest: local.configDigest,
      platform: local.platform, layerDigests: [`sha256:${'a'.repeat(64)}`], diffIds: [`sha256:${'b'.repeat(64)}`],
      archiveSha256: `sha256:${'c'.repeat(64)}`, profileVersion: local.profileVersion,
      checksVersion: local.checksVersion, resourcePolicyVersion: local.resourcePolicyVersion,
    }, scannerVersion: '0.69.3', checkedAt: Date.now(), metrics: { wireBytes: 100, requests: 5, compressedBytes: 50,
      expandedBytes: 2048, entries: 1, archiveBytes: 4096, reservationPeak: 4096, scratchPeak: 4096 },
      secret: { outcome: 'checked', findings: [{ findingId: 'secret-0-0', ruleId: 'rule-0123456789abcdef',
        evidenceRef: 'result-0-secret-0', line: 1 }] } };
    checkpoint('report_enqueue'); const scanId = ledger.enqueue({ ...report.receipt, executionProfile: NGINX_LOCAL_BINDING, subject: a.id,
      idempotencyKey: 'history-wire-synthetic-report-v1', scope: 'image', checks: '["secret"]' }).scanId;
    checkpoint('report_claim'); const job = ledger.claim(); assert(job);
    checkpoint('report_finish'); assert(ledger.finishArchive(scanId, job.attempts, report, undefined, job.leaseToken));
    checkpoint('report_pending'); assert.equal(ledger.pending().length, 0);
    checkpoint('report_projection'); const projected = reader(ledgerStore).read({ subject: a.id, scope: ['scan:read'] }, scanId);
    checkpoint('history_original_head'); const head = history.snapshot(a.id, scanId); assert.equal(head.revision, 0);
    checkpoint('history_descriptor'); const turnId = randomUUID(), mutationId = randomUUID(), policyVersion = consentVersion();
    const inputHash = mutationInputHash(scanId, { epoch: head.epoch, revision: 0, mutationId, reportVersion: projected.reportVersion }, question, policyVersion);
    const requestHash = hashValue(['explicit-synthetic-descriptor-NOT-prepared-provider-wire', inputHash]);
    checkpoint('history_access_incarnation'); const access = accessIncarnation();
    checkpoint('history_begin'); const begun = history.begin(a.id, scanId, head.epoch, 0, { id: turnId, mutationId, state: 'pending', question,
      report: reportBinding(projected), createdAt: Date.now(), inputHash, consentPolicyVersion: policyVersion, requestHash },
      { id: turnId, sessionId: randomBytes(16).toString('hex'), generation: 1, accessIncarnation: access,
        policyVersion, deadline: Date.now() + 60000, requestHash });
    checkpoint('history_begin_revision'); assert.equal(begun.revision, 1);
    checkpoint('history_fail'); assert(history.fail(a.id, scanId, head.epoch, turnId, 'failed'));
    checkpoint('history_failed_head'); const final = history.snapshot(a.id, scanId); assert.equal(final.revision, 2); assert.equal(final.pending, null);
    checkpoint('history_metadata'); const info = metadata();
    checkpoint('state_construct'); const state: FixtureState = { owner: a.id, foreign: b.id, scanId, epoch: head.epoch, turnId, mutationId,
      decisionId: randomUUID(), digest: projected.digest, platform: projected.platform, reportVersion: projected.reportVersion,
      consentPolicyVersion: policyVersion, incarnation: history.incarnation, fingerprintDigest: hashValue([inputHash, policyVersion, requestHash]),
      reportDigest: hashValue(projected), accessIncarnation: accessIncarnation(), historyInode: info.inode, historyDevice: info.device };
    checkpoint('state_validate'); validateState(state); quotaAbsent(); return { kind: 'history-wire-setup', state, missingHistoryRefused: true,
      initializerSucceeded: true, existingInitializerRefusedUnchanged: true, embeddedSourceQualified: true,
            mountedFixtureBytesQualified: true, fullSynchronous: true,
      syntheticTerminalReport: true, syntheticFailedTurn: true, quotaAbsent: true, revisions: [0, 1, 2] };
  } catch (error) { rememberSeedFailure(error); throw error; }
  finally {
    diagnosticCleanup('setup_close_history', () => runtime.close());
    diagnosticCleanup('setup_close_ledger', () => ledgerStore.onModuleDestroy());
  }
}
function audit(state: FixtureState, files: Record<string, string>, fixtures: Record<string, string>) {
  fixtureEnvironment(); qualify(files, fixtures);
  checkpoint('audit_state'); validateState(state);
  checkpoint('audit_allowlist'); assert.equal(process.env.SCAN_BROWSER_ALLOWED_USER_IDS, state.owner + ',' + state.foreign);
  checkpoint('audit_ledger'); const ledgerStore = new LedgerStore(), ledger = ledgerStore.ledger, runtime = new HistoryRuntime(); assert(ledger);
  try {
    checkpoint('audit_history_open'); const store = runtime.store();
    checkpoint('audit_head'); const head = store.snapshot(state.owner, state.scanId);
    checkpoint('audit_metadata'); const info = metadata();
    checkpoint('audit_writer'); assert.equal(Reflect.get(store, 'db').pragma('synchronous', { simple: true }), 2);
    checkpoint('audit_identity'); assert.equal(store.incarnation, state.incarnation); assert.equal(head.epoch, state.epoch); assert.equal(head.revision, 3);
    assert.equal(info.inode, state.historyInode); assert.equal(info.device, state.historyDevice);
    assert.equal(accessIncarnation(), state.accessIncarnation);
    checkpoint('audit_shape'); assert.equal(head.pending, null); assert.equal(head.turns.length, 1); assert.equal(head.decisions.length, 1);
    checkpoint('audit_turn'); const turn = head.turns[0]; assert.equal(turn.id, state.turnId); assert.equal(turn.mutationId, state.mutationId);
    assert.equal(turn.state, 'failed'); assert.equal(turn.question, question); assert.equal(turn.reply, undefined);
    checkpoint('audit_fingerprints'); assert.equal(hashValue([turn.inputHash, turn.consentPolicyVersion, turn.requestHash]), state.fingerprintDigest);
    checkpoint('audit_original_request'); const original = mutationInputHash(state.scanId, { epoch: state.epoch, revision: 0, mutationId: state.mutationId,
      reportVersion: state.reportVersion }, question, state.consentPolicyVersion); assert.equal(turn.inputHash, original);
    checkpoint('audit_projection'); const projected = reader(ledgerStore).read({ subject: state.owner, scope: ['scan:read'] }, state.scanId);
    checkpoint('audit_report'); assert.equal(hashValue(projected), state.reportDigest); assert.equal(ledger.pending().length, 0);
    checkpoint('audit_decision'); const decision = head.decisions[0]; assert.equal(decision.mutationId, state.decisionId); assert.equal(decision.text, decisionText);
    assert.deepEqual(decision.report, reportBinding(projected)); assert.deepEqual(decision.sources,
      [{ ...reportBinding(projected), finding: projected.findings[0] }]);
    quotaAbsent(); return { kind: 'history-wire-audit', preserved: true, mountedFixtureBytesQualified: true, revision: 3, turns: 1, decisions: 1,
      quotaAbsent: true, pendingAbsent: true, fingerprintsPreserved: true, incarnationAndInodePreserved: true,
      originalRequestPreserved: true, reportAndDecisionSourcesPreserved: true, schema: 3, application: 1145655602,
      pageSize: 4096, deleteJournal: true, fullSynchronous: true,
            privateRegularFile: true, nonalias: true, headroom: true };
  } catch (error) { rememberSeedFailure(error); throw error; }
  finally {
    diagnosticCleanup('audit_close_history', () => runtime.close());
    diagnosticCleanup('audit_close_ledger', () => ledgerStore.onModuleDestroy());
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    checkpoint('entry_read'); process.umask(0o077); const parts: Buffer[] = []; let size = 0;
        while (true) { const b = Buffer.alloc(4096), n = readSync(0, b, 0, b.length, null);
          if (!n) break; size += n; assert(size <= 65536); parts.push(b.subarray(0, n)); }
        const raw = Buffer.concat(parts);
    checkpoint('entry_parse'); const input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
    checkpoint('entry_argv'); assert.equal(process.argv.length, 3);
    checkpoint('entry_mode'); const mode = process.argv[2]; assert(mode === 'setup' || mode === 'audit'); seedPhase = mode;
    checkpoint('input_schema'); assert.deepEqual(Object.keys(input).sort(), (mode === 'setup' ? ['files', 'fixtures'] : ['files', 'fixtures', 'state']).sort());
    const result = mode === 'setup' ? await setup(input.files, input.fixtures) : audit(input.state, input.files, input.fixtures);
    checkpoint('receipt_encode'); const encoded = JSON.stringify(result); assert(Buffer.byteLength(encoded) <= 16384); process.stdout.write(encoded + '\n');
  } catch (error) {
    rememberSeedFailure(error);
    const encoded = JSON.stringify(firstSeedFailure); assert(Buffer.byteLength(encoded) <= SEED_DIAGNOSTIC_BYTES);
    process.stdout.write(encoded + '\n'); process.exitCode = 1;
  }
}
