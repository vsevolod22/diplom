import { isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { initializeCallerJournal } from './runtime-caller-journal.js';

// Offline operator action only. All exclusions are explicit; never consult ambient private config.
export function runtimeCallerInit(args: string[]): void {
  const [action, path, authorization, ...forbidden] = args;
  if (
    action !== 'init' ||
    authorization !== '--authorize-runtime-caller-journal' ||
    args.length !== 6 ||
    [path, ...forbidden].some((p) => !p || !isAbsolute(p) || resolve(p) !== p)
  )
    throw new Error('EXPLICIT_CALLER_JOURNAL_AUTHORIZATION_REQUIRED');
  // API runtime, auth and image-ledger paths must be separately identified, including when absent.
  if (new Set([path, ...forbidden]).size !== 4) throw new Error('RUNTIME_UNAVAILABLE');
  initializeCallerJournal(path, forbidden);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    runtimeCallerInit(process.argv.slice(2));
    process.stdout.write('runtime_caller_journal_initialized\n');
  } catch {
    process.stderr.write('runtime_caller_journal_initialization_failed\n');
    process.exitCode = 1;
  }
}
