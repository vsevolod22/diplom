import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readdirSync } from 'node:fs';

// Resolve only already-installed tooling; never download or import the API application.
const require = createRequire(new URL('../api/package.json', import.meta.url));
const root = fileURLToPath(new URL('.', import.meta.url));
const mode = process.argv[2];
let command;
let args;
try {
  if (mode === 'test') {
    command = process.execPath;
    args = [
      require.resolve('tsx/cli'),
      '--test',
      ...readdirSync(`${root}tests`)
        .filter((name) => name.endsWith('.test.ts'))
        .sort()
        .map((name) => `${root}tests/${name}`),
    ];
  } else if (mode === 'typecheck') {
    command = process.execPath;
    args = [
      require.resolve('typescript/bin/tsc'),
      '--project',
      `${root}tsconfig.json`,
      '--noEmit',
      '--typeRoots',
      fileURLToPath(new URL('../api/node_modules/@types', import.meta.url)),
    ];
  } else if (mode === 'start') {
    command = process.execPath;
    args = [require.resolve('tsx/cli'), `${root}src/main.ts`];
  } else {
    throw new Error();
  }
} catch {
  process.stderr.write('broker_toolchain_or_command_unavailable\n');
  process.exit(1);
}
const result = spawnSync(command, args, { cwd: root, stdio: 'inherit', timeout: 120_000 });
if (result.error) process.stderr.write('broker_process_failed\n');
process.exit(result.status ?? 1);
