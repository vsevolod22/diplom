// Current-only export diagnostics. No import-time I/O, journal, retries or recovery authority.
import * as fs from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { validateExportManifest, isolatedDockerDiagnostic } from './public-image-stand.mjs';

const failures = new WeakMap(), responses = new WeakMap(), assertions = new WeakMap();
const FILE_LIMIT = 256 * 1024 ** 2, CHUNK = 1024 ** 2;
const STAGES = ['manifest', 'destination', 'open', 'guard', 'read-guard', 'dispatch-guard', 'dispatch',
  'post-dispatch-guard', 'json', 'protocol', 'decode', 'write', 'final-guard', 'hash', 'fsync',
  'identity', 'publish', 'unlink-partial', 'directory-open', 'directory-fsync', 'directory-close', 'close'];
const CAUSES = ['VALIDATION', 'GUARD', 'JSON', 'PROTOCOL', 'ENCODING', 'HOST_WRITE', 'HASH',
  'FILESYSTEM_IO', 'OUTPUT_LIMIT', 'TIMEOUT', 'SPAWN', 'EXIT_NONZERO', 'DOCKER_FAILURE', 'UNKNOWN'];
const choose = (value, values) => values.includes(value) ? value : null;
const count = (value, max = FILE_LIMIT) => Number.isSafeInteger(value) && value >= 0 && value <= max ? value : null;
const own = (value, key) => {
  try { return value && typeof value === 'object' ? Object.getOwnPropertyDescriptor(value, key)?.value : undefined; }
  catch { return undefined; }
};
function check(ok, cause = 'VALIDATION') {
  if (!ok) { const error = Error('Current backup validation refused; details withheld.'); assertions.set(error, cause); throw error; }
}
const clock = now => { try { const value = now(); return Number.isFinite(value) ? value : null; } catch { return null; } };
const elapsed = (now, start) => { const end = clock(now); return start !== null && end !== null ? count(Math.floor(end - start), 2147483647) : null; };
function record(value) {
  // Explicit projection: never spread foreign errors, paths, arguments or response bodies.
  return Object.freeze({
    version: 1,
    phase: choose(value.phase, ['fenced', 'post-migration', 'before-api', 'after-api']),
    group: choose(value.group, ['core', 'llm']), role: choose(value.role, ['auth', 'ledger']),
    stage: choose(value.stage, STAGES), cause: choose(value.cause, CAUSES) ?? 'UNKNOWN',
    requestedOffset: count(value.requestedOffset), requestedBytes: count(value.requestedBytes, CHUNK),
    validatedBytes: count(value.validatedBytes), writtenBytes: count(value.writtenBytes),
    fileFsyncCompleted: value.fileFsyncCompleted === true, published: value.published === true,
    partialRemoved: value.partialRemoved === true, directoryFsyncCompleted: value.directoryFsyncCompleted === true,
    closeFailed: value.closeFailed === true,
    transferElapsedMs: count(value.transferElapsedMs, 2147483647), readElapsedMs: count(value.readElapsedMs, 2147483647),
    stdoutBytes: count(value.stdoutBytes, 64 * 1024 ** 2), stderrBytes: count(value.stderrBytes, 64 * 1024 ** 2),
    exitCode: count(value.exitCode, 255),
    signal: choose(value.signal, ['SIGKILL', 'SIGTERM', 'SIGABRT', 'SIGPIPE', 'SIGSEGV', 'SIGINT']),
  });
}
export function currentBackupDiagnostic(error) { return failures.get(error) ?? null; }
export function carryCurrentBackupDiagnostic(error, replacement) {
  const diagnostic = failures.get(error);
  if (diagnostic) failures.set(replacement, diagnostic);
  return replacement;
}
function failure(error, state, progress = null) {
  const prior = failures.get(error), docker = isolatedDockerDiagnostic(error);
  const code = own(error, 'code');
  const io = ['EIO', 'ENOSPC', 'EACCES', 'EPERM', 'ENOENT', 'EEXIST', 'ELOOP', 'EROFS', 'EMFILE', 'ENFILE'].includes(code);
  const cause = assertions.get(error) ?? docker?.cause ?? (io ? 'FILESYSTEM_IO' :
    state.stage?.endsWith('guard') ? 'GUARD' : state.stage === 'json' ? 'JSON' : state.stage === 'manifest' ? 'VALIDATION' : 'UNKNOWN');
  const result = Error('Current backup export refused; details withheld. No automatic recovery.');
  failures.set(result, record({ ...state, cause, ...docker, ...prior, ...progress }));
  return result;
}
// These guards are synchronous. Do not insert an await between validation and
// dispatch, and keep the original error for non-export callers/diagnostic owners.
export function currentBackupStep(stage, work, output) {
  check(['dispatch-guard', 'post-dispatch-guard'].includes(stage));
  try { return work(); } catch (error) {
    if (error && (typeof error === 'object' || typeof error === 'function')) {
      failures.set(error, record({ stage, cause: 'GUARD',
        stdoutBytes: typeof output === 'string' ? Math.min(Buffer.byteLength(output), 64 * 1024 ** 2) : null }));
    }
    throw error;
  }
}
export async function readCurrentBackupExport({ request, check: verify, dispatch, phase, group, now = () => performance.now() }) {
  const started = clock(now);
  const state = { phase, group, role: request.role, requestedOffset: request.offset, requestedBytes: request.bytes, stage: 'read-guard' };
  try {
    await verify();
    state.stage = 'dispatch';
    const text = await dispatch(request);
    state.stdoutBytes = typeof text === 'string' ? Math.min(Buffer.byteLength(text), 64 * 1024 ** 2) : null;
    state.stage = 'json';
    const value = JSON.parse(text);
    if (value && typeof value === 'object') responses.set(value, { stdoutBytes: state.stdoutBytes, readElapsedMs: elapsed(now, started) });
    return value;
  } catch (error) {
    const result = failure(error, state);
    // Dispatch failures know the substage, but not the caller's scope/request.
    failures.set(result, record({ ...failures.get(result), phase, group, role: request.role,
      requestedOffset: request.offset, requestedBytes: request.bytes, readElapsedMs: elapsed(now, started) }));
    throw result;
  }
}
const keys = (value, expected) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...expected].sort().join(',');

// Same transfer/publication protocol as the frozen transferBackupSnapshot.
// Counters describe validated/written bytes, NOT durability before fsync returns.
export async function transferCurrentBackupSnapshot({ io = fs, crypto = { createHash }, dir, role, manifest,
  readChunk, verify, phase, group, now = () => performance.now() }) {
  const started = clock(now);
  const state = { phase, group, role, stage: 'manifest', requestedOffset: 0, requestedBytes: 0,
    validatedBytes: 0, writtenBytes: 0, fileFsyncCompleted: false, published: false,
    partialRemoved: false, directoryFsyncCompleted: false, closeFailed: false };
  let fd, caught;
  const progress = () => ({ phase, group, role, requestedOffset: state.requestedOffset, requestedBytes: state.requestedBytes,
    validatedBytes: state.validatedBytes, writtenBytes: state.writtenBytes, fileFsyncCompleted: state.fileFsyncCompleted,
    published: state.published, partialRemoved: state.partialRemoved, directoryFsyncCompleted: state.directoryFsyncCompleted,
    transferElapsedMs: elapsed(now, started) });
  try {
    validateExportManifest(manifest); check(['auth', 'ledger'].includes(role));
    const b = manifest.receipt[role], path = join(dir, role + '.sqlite'), partial = join(dir, '.' + role + '.sqlite.exporting');
    state.stage = 'destination';
    check(!io.existsSync(path) && !io.existsSync(partial));
    const identity = io.lstatSync(dir);
    check(identity.isDirectory() && !identity.isSymbolicLink() && (identity.mode & 0o7777) === 0o700 && identity.uid === process.getuid());
    state.stage = 'open';
    fd = io.openSync(partial, io.constants.O_CREAT | io.constants.O_EXCL | io.constants.O_WRONLY | io.constants.O_NOFOLLOW, 0o600);
    const h = crypto.createHash('sha256');
    for (let offset = 0; offset < b.bytes;) {
      const bytesRequested = Math.min(CHUNK, b.bytes - offset);
      state.requestedOffset = offset; state.requestedBytes = bytesRequested;
      state.stdoutBytes = null; state.stderrBytes = null; state.readElapsedMs = null;
      state.stage = 'guard'; await verify();
      state.stage = 'dispatch';
      const v = await readChunk({ action: 'chunk', role, offset, bytes: bytesRequested, stamp: manifest.files[role] });
      const response = responses.get(v);
      state.stdoutBytes = response?.stdoutBytes ?? null; state.readElapsedMs = response?.readElapsedMs ?? null;
      state.stage = 'protocol';
      check(keys(v, ['version', 'role', 'offset', 'data']) && v.version === 1 && v.role === role && v.offset === offset &&
        typeof v.data === 'string' && v.data.length === 4 * Math.ceil(bytesRequested / 3) && /^[A-Za-z0-9+/]*={0,2}$/.test(v.data), 'PROTOCOL');
      state.stage = 'decode';
      const bytes = Buffer.from(v.data, 'base64');
      check(bytes.length === bytesRequested && bytes.toString('base64') === v.data, 'ENCODING');
      state.validatedBytes += bytes.length;
      state.stage = 'write';
      let written = 0;
      while (written < bytes.length) {
        const n = io.writeSync(fd, bytes, written, bytes.length - written, null);
        check(n > 0, 'HOST_WRITE'); written += n; state.writtenBytes += n;
      }
      h.update(bytes); offset += bytes.length;
    }
    state.requestedOffset = b.bytes; state.requestedBytes = 0;
    state.stage = 'final-guard'; await verify();
    state.stage = 'hash'; check(h.digest('hex') === b.sha256, 'HASH');
    state.stage = 'fsync'; io.fsyncSync(fd); state.fileFsyncCompleted = true;
    state.stage = 'identity';
    const s = io.fstatSync(fd), p = io.lstatSync(partial), d = io.lstatSync(dir);
    check(s.isFile() && s.nlink === 1 && (s.mode & 0o7777) === 0o600 && s.uid === process.getuid() && s.size === b.bytes &&
      s.ino === p.ino && s.dev === p.dev && identity.ino === d.ino && identity.dev === d.dev);
    state.stage = 'publish'; io.linkSync(partial, path); state.published = true;
    state.stage = 'unlink-partial'; io.unlinkSync(partial); state.partialRemoved = true;
    state.stage = 'directory-open'; const directory = io.openSync(dir, 'r');
    let directoryFailure;
    try { state.stage = 'directory-fsync'; io.fsyncSync(directory); state.directoryFsyncCompleted = true; }
    catch (error) { directoryFailure = failure(error, state); }
    try { state.stage = 'directory-close'; io.closeSync(directory); }
    catch (error) {
      if (!directoryFailure) directoryFailure = failure(error, state);
      failures.set(directoryFailure, record({ ...failures.get(directoryFailure), closeFailed: true }));
    }
    if (directoryFailure) throw directoryFailure;
  } catch (error) { caught = failure(error, state, progress()); }
  finally {
    if (fd !== undefined) try { io.closeSync(fd); }
    catch (error) {
      if (!caught) caught = failure(error, { ...state, stage: 'close' }, progress());
      failures.set(caught, record({ ...failures.get(caught), closeFailed: true }));
    }
  }
  if (caught) throw caught;
}
