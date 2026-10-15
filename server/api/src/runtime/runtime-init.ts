import { readFileSync, lstatSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseRuntimeJson } from './runtime-json.js';
import { initializeRuntimeStore, RuntimeStore, type Enrollment } from './runtime-store.js';

export function runtimeInit(args: string[]): void {
  const [action, path, authorization, enrollmentPath] = args;
  if (
    !['init', 'enroll'].includes(action) ||
    authorization !== '--authorize-runtime-store' ||
    !path ||
    !isAbsolute(path)
  )
    throw new Error('EXPLICIT_RUNTIME_AUTHORIZATION_REQUIRED');
  const others = [process.env.AUTH_DB_PATH ?? '', process.env.SCAN_LEDGER_PATH ?? ''];
  if (action === 'init') {
    if (args.length !== 3) throw new Error('INVALID_RUNTIME_INPUT');
    initializeRuntimeStore(path, others);
    return;
  }
  if (
    args.length !== 4 ||
    !enrollmentPath ||
    !isAbsolute(enrollmentPath) ||
    realpathSync(enrollmentPath) !== enrollmentPath
  )
    throw new Error('INVALID_RUNTIME_INPUT');
  const file = lstatSync(enrollmentPath);
  const parent = lstatSync(dirname(enrollmentPath));
  if (
    file.isSymbolicLink() ||
    !file.isFile() ||
    file.size > 65536 ||
    file.uid !== process.getuid?.() ||
    parent.uid !== file.uid ||
    (file.mode & 0o777) !== 0o600 ||
    (parent.mode & 0o777) !== 0o700
  )
    throw new Error('INVALID_RUNTIME_INPUT');
  const input = parseRuntimeJson(readFileSync(enrollmentPath));
  const store = new RuntimeStore(path, Date.now, others);
  try {
    store.enroll(input as Enrollment);
  } finally {
    store.close();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    runtimeInit(process.argv.slice(2));
    process.stdout.write('runtime_operator_action_complete\n');
  } catch {
    process.stderr.write('runtime_operator_action_failed\n');
    process.exitCode = 1;
  }
}
