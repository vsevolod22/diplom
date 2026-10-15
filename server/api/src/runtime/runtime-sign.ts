import { createPrivateKey } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { canonical } from '../../../runtime/src/contract.js';
import { createHistoricalPackage } from '../../../runtime/src/operator-package.js';
import { parseRuntimeJson } from './runtime-json.js';

function ownedFile(path: string, cap: number): Buffer {
  if (!isAbsolute(path) || realpathSync(path) !== path) throw new Error('INVALID_RUNTIME_INPUT');
  const file = lstatSync(path);
  const parent = lstatSync(dirname(path));
  if (
    !file.isFile() ||
    file.nlink !== 1 ||
    file.uid !== process.getuid?.() ||
    parent.uid !== file.uid ||
    !parent.isDirectory() ||
    realpathSync(dirname(path)) !== dirname(path) ||
    (file.mode & 0o777) !== 0o600 ||
    (parent.mode & 0o777) !== 0o700 ||
    file.size > cap
  ) {
    throw new Error('INVALID_RUNTIME_INPUT');
  }
  const bytes = readFileSync(path);
  if (bytes.length > cap) throw new Error('INVALID_RUNTIME_INPUT');
  return bytes;
}

// Offline operator CLI. No server import, secret environment, Engine call or implicit signing.
export function runtimeSign(args: string[]): string {
  const [authorization, inputPath, keyPath] = args;
  if (args.length !== 3 || authorization !== '--authorize-runtime-sign') {
    throw new Error('EXPLICIT_RUNTIME_AUTHORIZATION_REQUIRED');
  }
  const input = parseRuntimeJson(ownedFile(inputPath, 65536));
  const keyBytes = ownedFile(keyPath, 8192);
  try {
    return canonical(createHistoricalPackage(input, createPrivateKey(keyBytes)));
  } finally {
    keyBytes.fill(0);
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.stdout.write(`${runtimeSign(process.argv.slice(2))}\n`);
  } catch {
    process.stderr.write('runtime_operator_sign_failed\n');
    process.exitCode = 1;
  }
}
