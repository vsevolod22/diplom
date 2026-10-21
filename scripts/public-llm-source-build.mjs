// Offline COPY-closure qualification. No Docker, dotenv, dependency install or network.
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';

export function checkPublicLlmSourceBuild(root) {
  if (resolve(root) !== root || fs.realpathSync(root) !== root) throw Error('PUBLIC_SOURCE_ROOT_REJECTED');
  const temp = fs.mkdtempSync(join(tmpdir(), 'public-llm-copy-'));
  const refuse = reason => { const error = Error(reason); error.reason = reason; throw error; };
  try {
    for (const path of ['package.json', 'pnpm-workspace.yaml', 'pnpm-lock.yaml', 'server/api/package.json',
      'index.html', 'admin.html', 'vite.config.ts', 'tsconfig.json', 'src', 'public',
      'server/runtime/src/contract.ts', 'server/runtime/src/runtime-json.ts']) {
      fs.mkdirSync(dirname(join(temp, path)), { recursive: true });
      fs.cpSync(join(root, path), join(temp, path), { recursive: true, dereference: false });
    }
    const require = createRequire(join(root, 'package.json'));
    fs.symlinkSync(join(root, 'node_modules'), join(temp, 'node_modules'), 'dir');
    fs.writeFileSync(join(temp, 'tsconfig.public.json'), JSON.stringify({ extends: './tsconfig.json', include: ['src', 'vite.config.ts'] }));
    const run = args => spawnSync(process.execPath, args, { cwd: temp, env: { PATH: process.env.PATH },
      encoding: 'utf8', timeout: 90000, maxBuffer: 2 * 1024 ** 2 });
    if (run([require.resolve('typescript/bin/tsc'), '--project', 'tsconfig.public.json']).status !== 0) refuse('PUBLIC_SOURCE_TYPESCRIPT_REJECTED');
    const code = "import {build} from 'vite';try{await build({configLoader:'runner',envFile:false,logLevel:'silent',build:{outDir:'dist',emptyOutDir:true}});}catch{process.exitCode=1;}";
    if (run(['--input-type=module', '-e', code]).status !== 0) refuse('PUBLIC_SOURCE_BUNDLE_REJECTED');
    return { typescript: true, bundle: true, docker: false };
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
}
